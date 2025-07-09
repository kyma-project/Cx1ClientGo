package main

import (
	"os"

	"github.com/cxpsemea/Cx1ClientGo"
	log "github.com/sirupsen/logrus"

	//	"time"

	"fmt"
	"net/http"

	easy "github.com/t-tomalak/logrus-easy-formatter"
)

func main() {
	logger := log.New()
	logger.SetLevel(log.InfoLevel)
	myformatter := &easy.Formatter{}
	myformatter.TimestampFormat = "2006-01-02 15:04:05.000"
	myformatter.LogFormat = "[%lvl%][%time%] %msg%\n"
	logger.SetFormatter(myformatter)
	logger.SetOutput(os.Stdout)

	if len(os.Args) < 5 {
		log.Fatalf("Usage: go run . <cx1 url> <iam url> <tenant> <api key>")
	}

	logger.Infof("Starting")

	base_url := os.Args[1]
	iam_url := os.Args[2]
	tenant := os.Args[3]
	api_key := os.Args[4]
	//	project_name := os.Args[5]
	//	group_name := os.Args[6]
	//	project_repo := os.Args[7]
	//	branch_name := os.Args[8]

	//proxyURL, _ := url.Parse("http://127.0.0.1:8080")
	//transport := &http.Transport{}
	//transport.Proxy = http.ProxyURL(proxyURL)
	//transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}

	httpClient := &http.Client{}
	//httpClient.Transport = transport

	cx1client, err := Cx1ClientGo.NewAPIKeyClient(httpClient, base_url, iam_url, tenant, api_key, logger)
	if err != nil {
		log.Fatalf("Error creating client: %s", err)
		return
	}

	// no err means that the client is initialized
	logger.Infof("Client initialized: " + cx1client.String())

	var scanConfig Cx1ClientGo.ScanConfiguration
	scanConfig.ScanType = "sast"
	scanConfig.Values = map[string]string{"incremental": "false", "presetName": "All"}

	var i uint64
	for i = 1; i <= 100; i++ {
		group, gerr := cx1client.GetOrCreateGroupByName(fmt.Sprintf("Testgroup%d", i))
		if gerr != nil {
			logger.Errorf("Failed to get Testgroup%d", i)
			continue
		}
		app, aerr := cx1client.GetOrCreateApplicationByName(fmt.Sprintf("Testapp%d", i))
		if aerr != nil {
			logger.Errorf("Failed to get Testapp%d", i)
			continue
		}
		project, perr := cx1client.GetOrCreateProjectByName(fmt.Sprintf("Testproject%d", i))
		if perr != nil {
			logger.Errorf("Failed to get Testproject%d: %v", i, perr)
			continue
		}
		app.AssignProject(&project)
		err = cx1client.UpdateApplication(&app)
		if err != nil {
			logger.Errorf("Failed to Update application: %s", err)
		}

		project.AssignGroup(&group)
		err = cx1client.UpdateProject(&project)

		if err != nil {
			logger.Errorf("Failed to Update project: %s", err)
		}

		scan, serr := cx1client.ScanProjectGitByID(project.ProjectID, "https://github.com/michaelkubiaczyk/ssba/", "master", []Cx1ClientGo.ScanConfiguration{scanConfig}, map[string]string{})
		if serr != nil {
			logger.Errorf("Error starting scan: %s", err)
		} else {
			logger.Infof("Started scan %v", scan.String())
		}
	}

}
