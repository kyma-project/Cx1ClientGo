package main

import (
	"crypto/tls"
	"log"
	"net/http"
	"net/url"
	"os"

	"github.com/cxpsemea/Cx1ClientGo"
	"github.com/sirupsen/logrus"
	easy "github.com/t-tomalak/logrus-easy-formatter"
)

func main() {
	logger := logrus.New()
	logger.SetLevel(logrus.InfoLevel)
	myformatter := &easy.Formatter{}
	myformatter.TimestampFormat = "2006-01-02 15:04:05.000"
	myformatter.LogFormat = "[%lvl%][%time%] %msg%\n"
	logger.SetFormatter(myformatter)
	logger.SetOutput(os.Stdout)

	if len(os.Args) < 5 {
		log.Fatalf("Usage: go run . <cx1 url> <iam url> <tenant> <api key>")
	}

	logger.Info("Starting")

	base_url := os.Args[1]
	iam_url := os.Args[2]
	tenant := os.Args[3]
	api_key := os.Args[4]

	proxyURL, _ := url.Parse("http://127.0.0.1:8080")
	transport := &http.Transport{}
	transport.Proxy = http.ProxyURL(proxyURL)
	transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}

	httpClient := &http.Client{}
	httpClient.Transport = transport

	cx1client, err := Cx1ClientGo.NewAPIKeyClient(httpClient, base_url, iam_url, tenant, api_key, logger)
	if err != nil {
		logger.Fatalf("Error creating client: %s", err)
	}

	logger.Info("Retrieving or creating test-project inside application test-application")

	project, _, err := cx1client.GetOrCreateProjectInApplicationByName("test-project", "test-application")
	if err != nil {
		logger.Fatalf("Error getting or creating project 'test-project' under application 'test-application': %s", err)
	}

	logger.Infof("Retrieving last successful scan for %v", project.String())
	lastscans, err := cx1client.GetLastScansByStatusAndID(project.ProjectID, 1, []string{"Completed"})
	var lastscan Cx1ClientGo.Scan

	if err == nil && len(lastscans) > 0 {
		lastscan = lastscans[0]
	} else {
		if err != nil {
			logger.Warnf("Error getting last completed scan: %s", err)
		} else {
			logger.Warnf("No successfully completed scans have been run for this project")
		}
		logger.Infof("Running a new scan")

		sastScanConfig := Cx1ClientGo.ScanConfiguration{
			ScanType: "sast",
		}
		lastscan, err = cx1client.ScanProjectGitByID(project.ProjectID, "https://github.com/michaelkubiaczyk/ssba", "master", []Cx1ClientGo.ScanConfiguration{sastScanConfig}, map[string]string{})
		if err != nil {
			logger.Fatalf("Failed to run a new scan: %s", err)
		}
		lastscan, err = cx1client.ScanPollingDetailed(&lastscan)
		if err != nil {
			logger.Fatalf("Scan failed with error: %s", err)
		}
		if lastscan.Status != "Completed" {
			logger.Fatalf("Scan did not complete successfully.")
		}
	}

	logger.Infof("Starting Web-Audit session for last successful scan %v", lastscan.String())

	session, err := cx1client.GetAuditSessionByID("sast", project.ProjectID, lastscan.ScanID)
	if err != nil {
		logger.Fatalf("Error getting an audit session: %s", err)
	}

	defer func() {
		logger.Infof("Terminating audit session %v", session.ID)
		err = cx1client.AuditDeleteSession(&session)
		if err != nil {
			logger.Errorf("Failed to terminate audit session: %s", err)
		}
	}()

	qc, err := cx1client.GetQueries()
	if err != nil {
		logger.Fatalf("Error getting the query collection: %s", err)
	}

	aq, err := cx1client.GetAuditQueriesByLevelID(&session, cx1client.QueryTypeProject(), project.ProjectID)
	if err != nil {
		logger.Fatalf("Error getting queries: %s", err)
	}

	qc.AddQueries(&aq)
	cqc := qc.GetCustomQueryCollection()

	logger.Infof("The following custom (not Cx-level) queries exist for project Id %v", project.ProjectID)

	for lid := range cqc.QueryLanguages {
		for gid := range cqc.QueryLanguages[lid].QueryGroups {
			for _, q := range cqc.QueryLanguages[lid].QueryGroups[gid].Queries {
				logger.Info(q.StringDetailed())
			}
		}
	}

	corpOverride := newCorpOverride(cx1client, logger, &qc, &session)
	if err = cx1client.AuditSessionKeepAlive(&session); err != nil {
		logger.Errorf("Audit session may have expired: %s", err)
	}
	defer DeleteQuery(cx1client, logger, &session, corpOverride)

	appOverride := newApplicationOverride(cx1client, logger, &qc, &session)
	if err = cx1client.AuditSessionKeepAlive(&session); err != nil {
		logger.Errorf("Audit session may have expired: %s", err)
	}
	defer DeleteQuery(cx1client, logger, &session, appOverride)

	projOverride := newProjectOverride(cx1client, logger, &qc, &session)
	if err = cx1client.AuditSessionKeepAlive(&session); err != nil {
		logger.Errorf("Audit session may have expired: %s", err)
	}
	defer DeleteQuery(cx1client, logger, &session, projOverride)

	corpQuery := newCorpQuery(cx1client, logger, &qc, &session)
	if err = cx1client.AuditSessionKeepAlive(&session); err != nil {
		logger.Errorf("Audit session may have expired: %s", err)
	}
	defer DeleteQuery(cx1client, logger, &session, corpQuery)

	logger.Info("Retrieving an updated list of queries")
	qc, err = cx1client.GetQueries()
	if err != nil {
		logger.Errorf("Error getting the query collection: %s", err)
	}

	aq, err = cx1client.GetAuditQueriesByLevelID(&session, Cx1ClientGo.AUDIT_QUERY_PROJECT, project.ProjectID)
	if err != nil {
		logger.Errorf("Error getting queries: %s", err)
	}

	qc.AddQueries(&aq)
	if corpQuery != nil {
		qc.UpdateNewQuery(corpQuery) // fill in the missing QueryID for this new query
	}

	cqc = qc.GetCustomQueryCollection()

	logger.Infof("The following custom (not Cx-level) queries exist for project Id %v", project.ProjectID)

	for lid := range cqc.QueryLanguages {
		for gid := range cqc.QueryLanguages[lid].QueryGroups {
			for _, q := range cqc.QueryLanguages[lid].QueryGroups[gid].Queries {
				logger.Info(q.StringDetailed())
			}
		}
	}
}

func newCorpOverride(cx1client *Cx1ClientGo.Cx1Client, logger *logrus.Logger, qc *Cx1ClientGo.QueryCollection, session *Cx1ClientGo.AuditSession) *Cx1ClientGo.Query {
	logger.Infof("Creating corp override under session %v", session.ID)
	baseQuery := qc.GetQueryByName("Java", "Java_Spring", "Spring_Missing_Expect_CT_Header")

	if baseQuery == nil {
		logger.Errorf("Unable to find query Java - Java_Spring - Spring_Missing_Expect_CT_Header")
		return nil
	}

	newCorpOverride, err := cx1client.CreateQueryOverride(session, Cx1ClientGo.AUDIT_QUERY_TENANT, baseQuery)
	if err != nil {
		logger.Errorf("Failed to create override: %s", err)
		return nil
	}

	updatedQuery, err := cx1client.UpdateQuerySourceByKey(session, newCorpOverride.EditorKey, "result = base.Spring_Missing_Expect_CT_Header(); // corp override")
	if err != nil {
		logger.Errorf("Error updating query source: %s", err)
	} else {
		newCorpOverride = updatedQuery
	}

	metadata := newCorpOverride.GetMetadata()
	metadata.Severity = "Low"
	updatedQuery, err = cx1client.UpdateQueryMetadataByKey(session, newCorpOverride.EditorKey, metadata)
	if err != nil {
		logger.Errorf("Error updating query metadata: %s", err)
	} else {
		newCorpOverride = updatedQuery
	}

	if err = qc.UpdateNewQuery(&newCorpOverride); err != nil {
		logger.Errorf("Unable to update query %v from collection: %s", newCorpOverride.String(), err)
	}

	logger.Infof("Created new corp override: %v", newCorpOverride.StringDetailed())
	return &newCorpOverride
}

func newApplicationOverride(cx1client *Cx1ClientGo.Cx1Client, logger *logrus.Logger, qc *Cx1ClientGo.QueryCollection, session *Cx1ClientGo.AuditSession) *Cx1ClientGo.Query {
	logger.Infof("Creating application-level override under session %v", session.ID)
	baseQuery := qc.GetQueryByName("Java", "Java_Spring", "Spring_Missing_Expect_CT_Header")

	if baseQuery == nil {
		logger.Errorf("Unable to find query Java - Java_Spring - Spring_Missing_Expect_CT_Header")
		return nil
	}

	cx1client.AuditSessionKeepAlive(session)
	newApplicationOverride, err := cx1client.CreateQueryOverride(session, Cx1ClientGo.AUDIT_QUERY_APPLICATION, baseQuery)
	if err != nil {
		logger.Errorf("Failed to create override: %s", err)
		return nil
	}

	updatedQuery, err := cx1client.UpdateQuerySourceByKey(session, newApplicationOverride.EditorKey, "result = base.Spring_Missing_Expect_CT_Header(); // application override")
	if err != nil {
		logger.Errorf("Error updating query source: %s", err)
	} else {
		newApplicationOverride = updatedQuery
	}

	metadata := newApplicationOverride.GetMetadata()
	metadata.Severity = "Medium"
	updatedQuery, err = cx1client.UpdateQueryMetadataByKey(session, newApplicationOverride.EditorKey, metadata)
	if err != nil {
		logger.Errorf("Error updating query metadata: %s", err)
	} else {
		newApplicationOverride = updatedQuery
	}

	qc.UpdateNewQuery(&newApplicationOverride)

	logger.Infof("Created new application override: %v", newApplicationOverride.StringDetailed())
	return &newApplicationOverride
}

func newProjectOverride(cx1client *Cx1ClientGo.Cx1Client, logger *logrus.Logger, qc *Cx1ClientGo.QueryCollection, session *Cx1ClientGo.AuditSession) *Cx1ClientGo.Query {
	logger.Infof("Creating project override under session %v", session.ID)
	baseQuery := qc.GetQueryByName("Java", "Java_Spring", "Spring_Missing_Expect_CT_Header")

	if baseQuery == nil {
		logger.Errorf("Unable to find query Java - Java_Spring - Spring_Missing_Expect_CT_Header")
		return nil
	}

	cx1client.AuditSessionKeepAlive(session)
	newProjectOverride, err := cx1client.CreateQueryOverride(session, Cx1ClientGo.AUDIT_QUERY_PROJECT, baseQuery)
	if err != nil {
		logger.Errorf("Failed to create override: %s", err)
		return nil
	}

	updatedQuery, err := cx1client.UpdateQuerySourceByKey(session, newProjectOverride.EditorKey, "result = base.Spring_Missing_Expect_CT_Header(); // project override")
	if err != nil {
		logger.Errorf("Error updating query source: %s", err)
	} else {
		newProjectOverride = updatedQuery
	}

	metadata := newProjectOverride.GetMetadata()
	metadata.Severity = "High"
	updatedQuery, err = cx1client.UpdateQueryMetadataByKey(session, newProjectOverride.EditorKey, metadata)
	if err != nil {
		logger.Errorf("Error updating query metadata: %s", err)
	} else {
		newProjectOverride = updatedQuery
	}

	qc.UpdateNewQuery(&newProjectOverride)

	logger.Infof("Created new project override: %v", newProjectOverride.StringDetailed())
	return &newProjectOverride
}

func newCorpQuery(cx1client *Cx1ClientGo.Cx1Client, logger *logrus.Logger, qc *Cx1ClientGo.QueryCollection, session *Cx1ClientGo.AuditSession) *Cx1ClientGo.Query {
	logger.Infof("Creating corp query under session %v", session.ID)
	NewQuery := Cx1ClientGo.Query{
		Source:             "result = Find_Strings().FindByName(\"test\"); // new corp query",
		Name:               "Test_String",
		Group:              "Java_Spring",
		Language:           "Java",
		Severity:           "Low",
		CweID:              123,
		IsExecutable:       true,
		QueryDescriptionId: 123,
	}

	cx1client.AuditSessionKeepAlive(session)
	newCorpQuery, err := cx1client.CreateNewQuery(session, NewQuery)
	if err != nil {
		logger.Errorf("Failed to create new corp query: %s", err)
		return nil
	}

	qc.UpdateNewQuery(&newCorpQuery)

	logger.Infof("Created new corp query: %v", newCorpQuery.StringDetailed())
	logger.Info(" - Query IDs for brand-new queries are unknown until the full query collection is refreshed via client.GetQueries()")
	return &newCorpQuery
}

func DeleteQuery(cx1client *Cx1ClientGo.Cx1Client, logger *logrus.Logger, session *Cx1ClientGo.AuditSession, query *Cx1ClientGo.Query) {
	if query != nil {
		logger.Infof("Deleting custom query: %v", query.StringDetailed())
		err := cx1client.DeleteQueryOverrideByKey(session, query.EditorKey)
		if err != nil {
			logger.Errorf("Failed to delete custom query %v: %s", query.StringDetailed(), err)
		}
	}
}
