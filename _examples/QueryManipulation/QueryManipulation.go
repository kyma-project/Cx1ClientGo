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
	logger.SetLevel(logrus.TraceLevel)
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

	qc, err := cx1client.GetQueries()
	if err != nil {
		logger.Fatalf("Error getting the query collection: %s", err)
	}

	aq, err := cx1client.GetAuditQueriesByLevelID(session.ID, cx1client.QueryTypeProject(), project.ProjectID)
	if err != nil {
		logger.Fatalf("Error getting queries: %s", err)
	}

	qc.AddAuditQueries(&aq)

	corpOverride := newCorpOverride(cx1client, logger, &qc, session.ID)
	appOverride := newApplicationOverride(cx1client, logger, &qc, session.ID)
	projOverride := newProjectOverride(cx1client, logger, &qc, session.ID)
	//corpQuery := newCorpQuery(cx1client, logger, &qc, session.ID)

	err = cx1client.AuditDeleteSessionByID(session.ID)
	if err != nil {
		logger.Errorf("Failed to delete audit session: %s", err)
	}

	logger.Infof("The following custom (not Cx-level) queries exist for project Id %v", project.ProjectID)
	queries, err := cx1client.GetAuditQueriesByLevelID(session.ID, cx1client.QueryTypeProject(), project.ProjectID)
	if err != nil {
		logger.Errorf("Failed to get queries for project: %s", err)
	} else {
		for _, q := range queries {
			if q.Level != cx1client.QueryTypeProduct() {
				logger.Infof(" - %v", q.String())
			}
		}
	}

	err = cx1client.DeleteQueryOverrideByKey(session.ID, projOverride.EditorKey)
	if err != nil {
		logger.Errorf("Failed to delete project query %v: %s", projOverride.String(), err)
	}
	err = cx1client.DeleteQueryOverrideByKey(session.ID, appOverride.EditorKey)
	if err != nil {
		logger.Errorf("Failed to delete application query %v: %s", appOverride.String(), err)
	}
	err = cx1client.DeleteQueryOverrideByKey(session.ID, corpOverride.EditorKey)
	if err != nil {
		logger.Errorf("Failed to delete corp query %v: %s", corpOverride.String(), err)
	}

	/*
		err = cx1client.DeleteQueryOverrideByKey(session.ID, corpQuery)
		if err != nil {
			logger.Errorf("Failed to delete corp query %v: %s", corpQuery.String(), err)
		}
	*/
}

func newCorpOverride(cx1client *Cx1ClientGo.Cx1Client, logger *logrus.Logger, qc *Cx1ClientGo.QueryCollection, session string) Cx1ClientGo.Query {
	logger.Infof("Creating corp override under session %v", session)
	baseQuery := qc.GetQueryByName("Java", "Java_Spring", "Spring_Missing_Expect_CT_Header")

	if baseQuery == nil {
		logger.Fatalf("Unable to find query Java - Java_Spring - Spring_Missing_Expect_CT_Header")
	}

	newCorpOverride, err := cx1client.CreateQueryOverrideByKey(session, baseQuery.EditorKey, cx1client.QueryTypeTenant())
	if err != nil {
		logger.Fatalf("Failed to create override: %s", err)
	}

	newCorpOverride, err = cx1client.UpdateQuerySourceByKey(session, newCorpOverride.EditorKey, "result = base.Spring_Missing_Expect_CT_Header(); // corp override")
	if err != nil {
		logger.Fatalf("Error updating query source: %s", err)
	}

	logger.Infof("Created new corp override: %v", newCorpOverride)
	return newCorpOverride
}

func newApplicationOverride(cx1client *Cx1ClientGo.Cx1Client, logger *logrus.Logger, qc *Cx1ClientGo.QueryCollection, session string) Cx1ClientGo.Query {
	logger.Infof("Creating application-level override under session %v", session)
	baseQuery := qc.GetQueryByName("Java", "Java_Spring", "Spring_Missing_Expect_CT_Header")

	if baseQuery == nil {
		logger.Fatalf("Unable to find query Java - Java_Spring - Spring_Missing_Expect_CT_Header")
	}

	cx1client.AuditSessionKeepAlive(session)
	newApplicationOverride, err := cx1client.CreateQueryOverrideByKey(session, baseQuery.EditorKey, cx1client.QueryTypeApplication())
	if err != nil {
		logger.Fatalf("Failed to create override: %s", err)
	}

	newApplicationOverride, err = cx1client.UpdateQuerySourceByKey(session, newApplicationOverride.EditorKey, "result = base.Spring_Missing_Expect_CT_Header(); // application override")
	if err != nil {
		logger.Fatalf("Error updating query source: %s", err)
	}

	logger.Infof("Created new application override: %v", newApplicationOverride)
	return newApplicationOverride
}

func newProjectOverride(cx1client *Cx1ClientGo.Cx1Client, logger *logrus.Logger, qc *Cx1ClientGo.QueryCollection, session string) Cx1ClientGo.Query {
	logger.Infof("Creating project override under session %v", session)
	baseQuery := qc.GetQueryByName("Java", "Java_Spring", "Spring_Missing_Expect_CT_Header")

	if baseQuery == nil {
		logger.Fatalf("Unable to find query Java - Java_Spring - Spring_Missing_Expect_CT_Header")
	}

	cx1client.AuditSessionKeepAlive(session)
	newProjectOverride, err := cx1client.CreateQueryOverrideByKey(session, baseQuery.EditorKey, cx1client.QueryTypeProject())
	if err != nil {
		logger.Fatalf("Failed to create override: %s", err)
	}

	newProjectOverride, err = cx1client.UpdateQuerySourceByKey(session, newProjectOverride.EditorKey, "result = base.Spring_Missing_Expect_CT_Header(); // project override")
	if err != nil {
		logger.Fatalf("Error updating query source: %s", err)
	}

	logger.Infof("Created new project override: %v", newProjectOverride)
	return newProjectOverride
}

/*
func newCorpQuery(cx1client *Cx1ClientGo.Cx1Client, logger *logrus.Logger, qc *Cx1ClientGo.QueryCollection, session string) Cx1ClientGo.AuditQuery {
	logger.Infof("Creating new corp query under session %v", session)
	// Third query: create new corp/tenant query
	cx1client.AuditSessionKeepAlive(session)
	newQuery, err := cx1client.AuditNewQuery("Java", "Java_Spring", "TestQuery")
	if err != nil {
		logger.Fatalf("Error creating query: %s", err)
	}

	newQuery.Source = "result = All.NewCxList(); // TestQuery"
	newQuery.IsExecutable = true
	newQuery, err = cx1client.AuditCreateCorpQuery(session, newQuery)
	if err != nil {
		logger.Fatalf("Error creating new corp-level query: %s", err)
	}

	err = cx1client.AuditCompileQuery(session, newQuery)
	if err != nil {
		logger.Fatalf("Error triggering query compile: %s", err)
	}

	err = cx1client.AuditCompilePollingByID(session)
	if err != nil {
		logger.Fatalf("Error while polling compiler: %s", err)
	}

	err = cx1client.UpdateAuditQuery(session, newQuery)
	if err != nil {
		logger.Fatalf("Error creating new corp query: %s", err)
	} else {
		logger.Infof("Saved override %v", newQuery.String())
	}

	nq, err := cx1client.GetQueryByName(cx1client.QueryTypeTenant(), "Java", "Java_Spring", "TestQuery")
	if err != nil {
		logger.Fatalf("Failed to get new corp query: %s", err)
	}

	logger.Infof("Created new corp query: %v", nq)
	return nq
}
*/
