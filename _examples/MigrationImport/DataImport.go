package main

import (
	"crypto/tls"
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

	logger.Infof("Starting")

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
		logger.Fatalf("Error creating client: %s", err.Error())
	}

	encryptionKey := "Uo9B+aCL4Z1rhemrUzUEQLCj3hX15yHxx99FQ9+vyc8="
	fileContents, err := os.ReadFile("importData.zip")
	if err != nil {
		logger.Fatalf("Failed to read importData.zip: %s", err)
	}

	importID, err := cx1client.StartMigration(fileContents, []byte{}, encryptionKey) // no project-to-app mapping
	if err != nil {
		logger.Fatalf("Failed to start migration: %s", err)
	}

	result, err := cx1client.ImportPollingByID(importID)
	if err != nil {
		logger.Fatalf("Failed during polling: %s", err)
	}

	logger.Infof("Migration data import finished with status: %v", result)
}
