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
	//httpClient.Transport = transport

	cx1client, err := Cx1ClientGo.NewAPIKeyClient(httpClient, base_url, iam_url, tenant, api_key, logger)
	if err != nil {
		logger.Fatalf("Error creating client: %s", err)
	}

	logger.Info("Retrieving or creating test-project inside application test-application")

	project, application, err := cx1client.GetOrCreateProjectInApplicationByName("test-project", "test-application")
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

	session, err := cx1client.GetAuditSessionByID(project.ProjectID, lastscan.ScanID, false)
	if err != nil {
		logger.Fatalf("Error getting an audit session: %s", err)
	}

	corpOverride := newCorpOverride(cx1client, logger, session)
	appOverride := newApplicationOverride(cx1client, logger, session, application.ApplicationID)
	projOverride := newProjectOverride(cx1client, logger, session, project.ProjectID)
	corpQuery := newCorpQuery(cx1client, logger, session)

	err = cx1client.AuditDeleteSessionByID(session)
	if err != nil {
		logger.Errorf("Failed to delete audit session: %s", err)
	}

	logger.Infof("The following custom (not Cx-level) queries exist for project Id %v", project.ProjectID)
	queries, err := cx1client.GetQueriesByLevelID("Project", project.ProjectID)
	if err != nil {
		logger.Errorf("Failed to get queries for project: %s", err)
	} else {
		for _, q := range queries {
			if q.Level != "Cx" {
				logger.Infof(" - %v", q.String())
			}
		}
	}

	err = cx1client.DeleteQuery(projOverride)
	if err != nil {
		logger.Errorf("Failed to delete project query %v: %s", projOverride.String(), err)
	}
	err = cx1client.DeleteQuery(appOverride)
	if err != nil {
		logger.Errorf("Failed to delete application query %v: %s", appOverride.String(), err)
	}
	err = cx1client.DeleteQuery(corpOverride)
	if err != nil {
		logger.Errorf("Failed to delete corp query %v: %s", corpOverride.String(), err)
	}
	err = cx1client.DeleteQuery(corpQuery)
	if err != nil {
		logger.Errorf("Failed to delete corp query %v: %s", corpQuery.String(), err)
	}
}

func newCorpOverride(cx1client *Cx1ClientGo.Cx1Client, logger *logrus.Logger, session string) Cx1ClientGo.AuditQuery {
	logger.Infof("Creating corp override under session %v", session)
	// First query: Tenant-level override of an existing query
	baseQuery, err := cx1client.GetQueryByName("Cx", "Java", "Java_Spring", "Spring_Missing_Expect_CT_Header")
	if err != nil {
		logger.Fatalf("Error getting query: %s", err)
	}

	newCorpOverride := baseQuery.CreateTenantOverride()
	newCorpOverride.Source = "result = base.Spring_Missing_Expect_CT_Header(); // corp override"

	err = cx1client.AuditCompileQuery(session, newCorpOverride)
	if err != nil {
		logger.Fatalf("Error triggering query compile: %s", err)
	}

	err = cx1client.AuditCompilePollingByID(session)
	if err != nil {
		logger.Fatalf("Error while polling compiler: %s", err)
	}

	err = cx1client.AuditUpdateQuery(session, newCorpOverride)
	if err != nil {
		logger.Fatalf("Error saving new query: %s", err)
	} else {
		logger.Infof("Saved new query %v", newCorpOverride.String())
	}

	nq, err := cx1client.GetQueryByName("Corp", "Java", "Java_Spring", "Spring_Missing_Expect_CT_Header")
	if err != nil {
		logger.Fatalf("Failed to get new corp query: %s", err)
	}

	logger.Infof("Created new corp override: %v", nq)
	return nq
}

func newApplicationOverride(cx1client *Cx1ClientGo.Cx1Client, logger *logrus.Logger, session, applicationId string) Cx1ClientGo.AuditQuery {
	logger.Infof("Creating application-level override under session %v", session)
	// First query: Tenant-level override of an existing query
	baseQuery, err := cx1client.GetQueryByName("Cx", "Java", "Java_Spring", "Spring_Missing_Expect_CT_Header")
	if err != nil {
		logger.Fatalf("Error getting query: %s", err)
	}
	// Second query: app-level override of existing query
	cx1client.AuditSessionKeepAlive(session)
	newApplicationOverride := baseQuery.CreateProjectOverrideByID(applicationId)
	newApplicationOverride.Source = "result = base.Spring_Missing_Expect_CT_Header(); // project override"

	err = cx1client.AuditCompileQuery(session, newApplicationOverride)
	if err != nil {
		logger.Fatalf("Error triggering query compile: %s", err)
	}

	err = cx1client.AuditCompilePollingByID(session)
	if err != nil {
		logger.Fatalf("Error while polling compiler: %s", err)
	}

	err = cx1client.AuditUpdateQuery(session, newApplicationOverride)
	if err != nil {
		logger.Fatalf("Error saving new query: %s", err)
	} else {
		logger.Infof("Saved new query %v", newApplicationOverride.String())
	}

	nq, err := cx1client.GetQueryByName(applicationId, "Java", "Java_Spring", "Spring_Missing_Expect_CT_Header")
	if err != nil {
		logger.Fatalf("Failed to get new project override: %s", err)
	}

	logger.Infof("Created new application override: %v", nq)
	return nq
}

func newProjectOverride(cx1client *Cx1ClientGo.Cx1Client, logger *logrus.Logger, session, projectId string) Cx1ClientGo.AuditQuery {
	logger.Infof("Creating project override under session %v", session)
	// First query: Tenant-level override of an existing query
	baseQuery, err := cx1client.GetQueryByName("Cx", "Java", "Java_Spring", "Spring_Missing_Expect_CT_Header")
	if err != nil {
		logger.Fatalf("Error getting query: %s", err)
	}
	// Second query: project-level override of existing query
	cx1client.AuditSessionKeepAlive(session)
	newProjectOverride := baseQuery.CreateProjectOverrideByID(projectId)
	newProjectOverride.Source = "result = base.Spring_Missing_Expect_CT_Header(); // project override"

	err = cx1client.AuditCompileQuery(session, newProjectOverride)
	if err != nil {
		logger.Fatalf("Error triggering query compile: %s", err)
	}

	err = cx1client.AuditCompilePollingByID(session)
	if err != nil {
		logger.Fatalf("Error while polling compiler: %s", err)
	}

	err = cx1client.AuditUpdateQuery(session, newProjectOverride)
	if err != nil {
		logger.Fatalf("Error saving new query: %s", err)
	} else {
		logger.Infof("Saved new query %v", newProjectOverride.String())
	}

	nq, err := cx1client.GetQueryByName(projectId, "Java", "Java_Spring", "Spring_Missing_Expect_CT_Header")
	if err != nil {
		logger.Fatalf("Failed to get new project override: %s", err)
	}

	logger.Infof("Created new project override: %v", nq)
	return nq
}

func newCorpQuery(cx1client *Cx1ClientGo.Cx1Client, logger *logrus.Logger, session string) Cx1ClientGo.AuditQuery {
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

	err = cx1client.AuditUpdateQuery(session, newQuery)
	if err != nil {
		logger.Fatalf("Error creating new corp query: %s", err)
	} else {
		logger.Infof("Saved override %v", newQuery.String())
	}

	nq, err := cx1client.GetQueryByName("Corp", "Java", "Java_Spring", "TestQuery")
	if err != nil {
		logger.Fatalf("Failed to get new corp query: %s", err)
	}

	logger.Infof("Created new corp query: %v", nq)
	return nq
}
