package Cx1ClientGo

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// Reports

func (c Cx1Client) RequestNewReportByID(scanID, projectID, branch, reportType string) (string, error) {
	jsonData := map[string]interface{}{
		"fileFormat": reportType,
		"reportType": "ui",
		"reportName": "scan-report",
		"data": map[string]interface{}{
			"scanId":     scanID,
			"projectId":  projectID,
			"branchName": branch,
			"sections": []string{
				"ScanSummary",
				"ExecutiveSummary",
				"ScanResults",
			},
			"scanners": []string{"SAST"},
			"host":     "",
		},
	}

	jsonBody, err := json.Marshal(jsonData)
	if err != nil {
		return "", err
	}

	data, err := c.sendRequest(http.MethodPost, "/reports", bytes.NewReader(jsonBody), nil)
	if err != nil {
		return "", fmt.Errorf("failed to trigger report generation for scan %v: %s", scanID, err)
	}

	var reportResponse struct {
		ReportId string
	}
	err = json.Unmarshal([]byte(data), &reportResponse)

	return reportResponse.ReportId, err
}

// the v2 report is the "improved scan report" which can be used the same as the existing RequestNewReportByID
// returns the report ID which can be passed to GetReportStatusByID or ReportPollingByID
// supports pdf, csv, and json format (not xml)
func (c Cx1Client) RequestNewReportByIDv2(scanID string, engines []string, format string) (string, error) {
	jsonData := map[string]interface{}{
		"reportName": "improved-scan-report",
		"entities": []map[string]interface{}{
			{
				"entity": "scan",
				"ids":    []string{scanID},
				"tags":   []string{},
			},
		},
		"filters": map[string][]string{
			"scanners": engines,
		},
		"reportType": "ui",
		"fileFormat": format,
	}

	jsonValue, _ := json.Marshal(jsonData)

	data, err := c.sendRequest(http.MethodPost, "/reports/v2", bytes.NewReader(jsonValue), nil)
	if err != nil {
		return "", fmt.Errorf("failed to trigger report v2 generation for scan %v: %s", scanID, err)
	} else {
		c.logger.Infof("Generating report %v", string(data))
	}

	var reportResponse struct {
		ReportId string
	}
	err = json.Unmarshal(data, &reportResponse)

	return reportResponse.ReportId, err
}

func (c Cx1Client) GetReportStatusByID(reportID string) (ReportStatus, error) {
	var response ReportStatus

	data, err := c.sendRequest(http.MethodGet, fmt.Sprintf("/reports/%v?returnUrl=true", reportID), nil, nil)
	if err != nil {
		c.logger.Tracef("Failed to fetch report status for reportID %v: %s", reportID, err)
		return response, fmt.Errorf("failed to fetch report status for reportID %v: %s", reportID, err)
	}

	err = json.Unmarshal([]byte(data), &response)
	return response, err
}

func (c Cx1Client) DownloadReport(reportUrl string) ([]byte, error) {
	data, err := c.sendRequestInternal(http.MethodGet, reportUrl, nil, nil)
	if err != nil {
		return []byte{}, fmt.Errorf("failed to download report from url %v: %s", reportUrl, err)
	}
	return data, nil
}

// convenience
func (c Cx1Client) ReportPollingByID(reportID string) (string, error) {
	for {
		status, err := c.GetReportStatusByID(reportID)
		if err != nil {
			return "", err
		}

		if status.Status == "completed" {
			return status.ReportURL, nil
		} else if status.Status == "failed" {
			return "", fmt.Errorf("report generation failed")
		}
		time.Sleep(10 * time.Second)
	}
}
