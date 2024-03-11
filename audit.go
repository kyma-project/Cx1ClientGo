package Cx1ClientGo

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

/*
	This is separate from queries.go to split the functions that require a Web-Audit Session from those that do not.
	This file contains the query-related functions that require an audit session (compiling queries, updating queries, creating overrides)
*/

func (c Cx1Client) AuditCreateSessionByID(projectId, scanId string) (string, error) {
	c.logger.Debugf("Trying to create audit session for project %v scan %v", projectId, scanId)
	available, _, err := c.AuditFindSessionsByID(projectId, scanId)
	if err != nil {
		return "", err
	}

	if !available {
		return "", fmt.Errorf("audit session not available")
	}

	body := map[string]interface{}{
		"projectId": projectId,
		"scanId":    scanId,
		"time":      30,
		"fromZip":   false,
	}

	jsonBody, _ := json.Marshal(body)

	response, err := c.sendRequest(http.MethodPost, "/cx-audit/sessions", bytes.NewReader(jsonBody), nil)
	if err != nil {
		return "", err
	}

	var responseStruct struct {
		Id     string `json:"id"`
		Status string `json:"status"`
		ScanId string `json:"scanId"`
	}

	err = json.Unmarshal(response, &responseStruct)
	if err != nil {
		return "", err
	}

	if responseStruct.Status == "ALLOCATED" {
		return responseStruct.Id, nil
	}

	return "", fmt.Errorf("failed to allocate audit session: %v", responseStruct)
}

func (c Cx1Client) AuditDeleteSessionByID(sessionId string) error {
	_, err := c.sendRequest(http.MethodDelete, fmt.Sprintf("/cx-audit/sessions/%v", sessionId), nil, nil)
	if err != nil {
		return err
	}

	return nil
}

func (c Cx1Client) AuditFindSessionsByID(projectId, scanId string) (bool, []string, error) {
	c.logger.Tracef("Checking for audit session for project %v scan %v", projectId, scanId)

	response, err := c.sendRequest(http.MethodGet, fmt.Sprintf("/cx-audit/sessions?projectId=%v&scanId=%v", projectId, scanId), nil, nil)
	if err != nil {
		return false, []string{}, err
	}

	var responseStruct struct {
		Available bool `json:"available"`
		Metadata  []struct {
			Session string `json:"session_id"`
		} `json:"metadata"`
	}

	err = json.Unmarshal(response, &responseStruct)
	if err != nil {
		return false, []string{}, err
	}

	sessions := []string{}
	for _, s := range responseStruct.Metadata {
		err = c.AuditSessionKeepAlive(s.Session)
		if err != nil {
			c.logger.Tracef("Found an expired session %v, deleting", s.Session)
			err = c.AuditDeleteSessionByID(s.Session)
			if err != nil {
				c.logger.Errorf("Failed to delete expired session %v: %s", s.Session, err)
			} else {
				responseStruct.Available = true
			}
		} else {
			sessions = append(sessions, s.Session)
		}
	}

	return responseStruct.Available, sessions, nil
}

func (c Cx1Client) AuditGetEngineStatusByID(auditSessionId string) (bool, error) {
	response, err := c.sendRequest(http.MethodGet, fmt.Sprintf("/cx-audit/sessions/%v/sast-status", auditSessionId), nil, nil)
	if err != nil {
		return false, err
	}

	var engineResponse struct {
		Ready   bool   `json:"ready"`
		Message string `json:"message"`
	}

	err = json.Unmarshal(response, &engineResponse)
	if err != nil {
		return false, err
	}

	if engineResponse.Ready {
		return true, nil
	}

	if engineResponse.Message == "the SAST Engine is not ready yet" {
		return false, nil
	}

	return false, fmt.Errorf("unknown cx-audit sast status response: %v", engineResponse.Message)
}

func (c Cx1Client) AuditEnginePollingByID(auditSessionId string) error {
	return c.AuditEnginePollingByIDWithTimeout(auditSessionId, c.consts.AuditEnginePollingDelaySeconds, c.consts.AuditEnginePollingMaxSeconds)
}

func (c Cx1Client) AuditEnginePollingByIDWithTimeout(auditSessionId string, delaySeconds, maxSeconds int) error {
	c.logger.Debugf("Polling status of cx-audit engine for session %v", auditSessionId)
	status := false
	var err error
	pollingCounter := 0

	for !status {
		status, err = c.AuditGetEngineStatusByID(auditSessionId)
		if err != nil {
			return err
		}
		if maxSeconds != 0 && pollingCounter >= maxSeconds {
			return fmt.Errorf("audit engine polled %d seconds without success: session may no longer be valid - use cx1client.get/setclientvars to change timeout", pollingCounter)
		}

		if status {
			return nil
		}
		time.Sleep(time.Duration(delaySeconds) * time.Second)
		pollingCounter += delaySeconds
	}

	return nil
}

func (c Cx1Client) AuditCheckLanguagesByID(auditSessionId string) error {
	c.logger.Infof("Triggering language check under audit session %v", auditSessionId)
	response, err := c.sendRequest(http.MethodGet, fmt.Sprintf("/cx-audit/sessions/%v/project/languages", auditSessionId), nil, nil)
	if err != nil {
		return err
	}
	if string(response) == "0" {
		return nil
	}

	var responseStruct struct {
		Message string `json:"message"`
	}

	err = json.Unmarshal(response, &responseStruct)
	if err != nil {
		return err
	}

	return fmt.Errorf("error: %v", responseStruct.Message)
}

func (c Cx1Client) AuditGetLanguagesByID(auditSessionId string) ([]string, error) {
	var languageResponse struct {
		Completed bool     `json:"completed"`
		Value     []string `json:"value"`
		Message   string   `json:"message"`
	}

	response, err := c.sendRequest(http.MethodGet, fmt.Sprintf("/cx-audit/sessions/%v/request-status?type=%d", auditSessionId, 0), nil, nil)
	if err != nil {
		return []string{}, err
	}
	err = json.Unmarshal(response, &languageResponse)
	if err != nil {
		return []string{}, err
	}

	if languageResponse.Completed {
		return languageResponse.Value, nil
	}

	if languageResponse.Message != "" {
		return []string{}, fmt.Errorf("error: %v", languageResponse.Message)
	}
	return languageResponse.Value, nil
}

func (c Cx1Client) AuditLanguagePollingByID(auditSessionId string) ([]string, error) {
	return c.AuditLanguagePollingByIDWithTimeout(auditSessionId, c.consts.AuditLanguagePollingDelaySeconds, c.consts.AuditLanguagePollingMaxSeconds)
}

func (c Cx1Client) AuditLanguagePollingByIDWithTimeout(auditSessionId string, delaySeconds, maxSeconds int) ([]string, error) {
	c.logger.Debugf("Polling status of language check for audit session %v", auditSessionId)
	languages := []string{}
	var err error
	pollingCounter := 0
	for len(languages) == 0 {
		languages, err = c.AuditGetLanguagesByID(auditSessionId)
		if err != nil {
			return languages, err
		}

		if maxSeconds != 0 && pollingCounter >= maxSeconds {
			return languages, fmt.Errorf("audit languages polled %d seconds without success: session may no longer be valid - use cx1client.get/setclientvars to change timeout", pollingCounter)
		}

		if len(languages) > 0 {
			return languages, nil
		}

		time.Sleep(time.Duration(delaySeconds) * time.Second)
		pollingCounter += delaySeconds
	}

	return languages, fmt.Errorf("unknown error")
}

func (c Cx1Client) AuditRunScanByID(auditSessionId string) error {
	c.logger.Infof("Triggering scan under audit session %v", auditSessionId)
	response, err := c.sendRequest(http.MethodGet, fmt.Sprintf("/cx-audit/sessions/%v/project/scan", auditSessionId), nil, nil)
	if err != nil {
		return err
	}

	if string(response) == "1" {
		return nil
	}

	var responseStruct struct {
		Message string `json:"message"`
	}

	err = json.Unmarshal(response, &responseStruct)
	if err != nil {
		return err
	}
	return fmt.Errorf("error: %v", responseStruct.Message)
}

func (c Cx1Client) AuditGetScanStatusByID(auditSessionId string) (bool, error) {
	var scanResponse struct {
		Completed bool     `json:"completed"`
		Value     []string `json:"value"`
		Message   string   `json:"message"`
	}

	response, err := c.sendRequest(http.MethodGet, fmt.Sprintf("/cx-audit/sessions/%v/request-status?type=%d", auditSessionId, 1), nil, nil)
	if err != nil {
		return false, err
	}
	err = json.Unmarshal(response, &scanResponse)
	if err != nil {
		return false, err
	}

	if scanResponse.Completed {
		return true, nil
	}

	if scanResponse.Message != "" {
		return false, fmt.Errorf("error: %v", scanResponse.Message)
	}
	return scanResponse.Completed, nil
}

func (c Cx1Client) AuditScanPollingByID(auditSessionId string) error {
	return c.AuditScanPollingByIDWithTimeout(auditSessionId, c.consts.AuditScanPollingDelaySeconds, c.consts.AuditScanPollingMaxSeconds)
}

func (c Cx1Client) AuditScanPollingByIDWithTimeout(auditSessionId string, delaySeconds, maxSeconds int) error {
	c.logger.Debugf("Polling status of scan for audit session %v", auditSessionId)
	status := false
	var err error
	pollingCounter := 0
	for !status {
		status, err = c.AuditGetScanStatusByID(auditSessionId)
		if err != nil {
			return err
		}
		if maxSeconds != 0 && pollingCounter >= maxSeconds {
			return fmt.Errorf("audit scan polled %d seconds without success: session may no longer be valid - use cx1client.get/setclientvars to change timeout", pollingCounter)
		}
		if status {
			return nil
		}

		time.Sleep(time.Duration(delaySeconds) * time.Second)
		pollingCounter += delaySeconds
	}

	return fmt.Errorf("unknown error")
}

func (c Cx1Client) AuditSessionKeepAlive(auditSessionId string) error {
	_, err := c.sendRequest(http.MethodPost, fmt.Sprintf("/cx-audit/sessions/%v", auditSessionId), nil, nil)
	if err != nil {
		return err
	}
	return nil
}

// Convenience function
func (c Cx1Client) GetAuditSessionByID(projectId, scanId string, fastInit bool) (string, error) {
	// TODO: convert the audit session to an object that also does the polling/keepalive
	c.logger.Infof("Creating an audit session for project %v scan %v", projectId, scanId)

	available, sessions, err := c.AuditFindSessionsByID(projectId, scanId)
	if err != nil {
		c.logger.Errorf("Failed to retrieve sessions: %s", err)
		return "", err
	}
	session := ""
	reusedSession := false
	if len(sessions) > 0 && (fastInit || !available) {
		lastSession := len(sessions) - 1
		if fastInit { // reuse existing
			c.logger.Debugf("FastInit: re-using the last session %v", sessions[lastSession])
		} else { // !available
			c.logger.Debugf("No additional audit sessions are available, but %d matching sessions exist. Re-using the last session %v", len(sessions), sessions[lastSession])
		}
		session = sessions[lastSession]
		reusedSession = true
	} else {
		session, err = c.AuditCreateSessionByID(projectId, scanId)
		if err != nil {
			c.logger.Errorf("Error creating cxaudit session: %s", err)
			return "", err
		}
	}

	err = c.AuditSessionKeepAlive(session)
	if err != nil {
		return "", err
	}

	err = c.AuditEnginePollingByID(session)
	if err != nil {
		c.logger.Errorf("Error while creating audit engine: %s", err)
		return "", err
	}

	if !fastInit || !reusedSession {
		err = c.AuditCheckLanguagesByID(session)
		if err != nil {
			c.logger.Errorf("Error while checking languages: %s", err)
			return "", err
		}
	}

	languages, err := c.AuditLanguagePollingByID(session)
	if err != nil {
		c.logger.Errorf("Error while getting languages: %s", err)
		return "", err
	}

	c.logger.Infof("Languages present: %v", languages)

	if !fastInit || !reusedSession {
		err = c.AuditRunScanByID(session)
		if err != nil {
			c.logger.Errorf("Error while triggering audit scan: %s", err)
			return "", err
		}
	}

	err = c.AuditScanPollingByID(session)
	if err != nil {
		c.logger.Errorf("Error while polling audit scan: %s", err)
		return "", err
	}

	c.AuditSessionKeepAlive(session) // one for the road

	return session, nil
}

func (c Cx1Client) AuditCompileQuery(auditSessionId string, query AuditQuery) error {
	// this wraps "compileQueryFull" and omits parameters that seem to be specific to the CxAudit UI
	return c.compileQueryFull(auditSessionId, query, false, "cxclientgo", "cxclientgo", "cxclientgo")
}
func (c Cx1Client) compileQueryFull(auditSessionId string, query AuditQuery, newquery bool, clientUniqID, fullEditorId, editorId string) error {
	// returns error if failed, else compiled successfully
	c.logger.Infof("Triggering compile for query %v under audit session %v", query.String(), auditSessionId)

	queryIdStr := strconv.FormatUint(query.QueryID, 10)
	type descriptionInfo struct {
		Cwe                int64  `json:"Cwe"`
		CxDescriptionID    int64  `json:"CxDescriptionID"`
		QueryDescriptionID string `json:"QueryDescriptionID"`
	}

	type queryInfo struct {
		Id           string          `json:"Id"`
		Name         string          `json:"name"`
		Group        string          `json:"group"`
		Lang         string          `json:"lang"`
		Path         string          `json:"path"`
		Level        string          `json:"level"` // Tenant, ProjectID, or later AppId?
		NewQuery     bool            `json:"newQuery"`
		IsExecutable bool            `json:"isExecutable"`
		ClientUniqId string          `json:"clientUniqId"`
		OriginalCode string          `json:"originalCode"`
		Code         string          `json:"code"`
		FullEditorId string          `json:"fullEditorId"`
		EditorId     string          `json:"editorId"`
		Id2          string          `json:"id"`     // no clue why this is duplicated
		Source       string          `json:"source"` // same as code?
		Data         descriptionInfo `json:"data"`
	}

	queryBody := make([]queryInfo, 1)
	queryBody[0] = queryInfo{
		Id:           queryIdStr,
		Name:         query.Name,
		Group:        query.Group,
		Lang:         query.Language,
		Path:         query.Path,
		Level:        query.Level,
		IsExecutable: query.IsExecutable,
		ClientUniqId: clientUniqID,
		OriginalCode: "",
		Code:         query.Source,
		FullEditorId: fullEditorId,
		EditorId:     editorId,
		Id2:          queryIdStr,
		Source:       query.Source,
		NewQuery:     newquery,
		Data:         descriptionInfo{Cwe: query.Cwe, CxDescriptionID: query.CxDescriptionId, QueryDescriptionID: query.QueryDescriptionId},
	}

	jsonBody, _ := json.Marshal(queryBody)
	response, err := c.sendRequest(http.MethodPost, fmt.Sprintf("/cx-audit/sessions/%v/queries/compile", auditSessionId), bytes.NewReader(jsonBody), nil)
	if err != nil {
		return err
	}

	if string(response) == "2" {
		return nil
	}

	var responseStruct struct {
		Message string `json:"message"`
	}

	err = json.Unmarshal(response, &responseStruct)
	if err != nil {
		return err
	}

	return fmt.Errorf("error while compiling: %v", responseStruct.Message)
}

func (c Cx1Client) auditGetCompileStatusByID(sessionId string) (bool, error) {
	response, err := c.sendRequest(http.MethodGet, fmt.Sprintf("/cx-audit/sessions/%v/request-status?type=%d", sessionId, 2), nil, nil)
	if err != nil {
		return false, err
	}

	var compileResponse struct {
		Completed bool `json:"completed"`
		Value     struct {
			FailedQueries []struct {
				QueryId string `json:"query_id"`
				Errors  []struct {
					Column  int    `json:"column"`
					Line    int    `json:"line"`
					Message string `json:"message"`
				} `json:"errors"`
			} `json:"failed_queries"`
			Success bool `json:"success"`
		} `json:"value"`
	}

	err = json.Unmarshal(response, &compileResponse)
	if err != nil {
		return false, err
	}

	if !compileResponse.Completed {
		return false, nil
	}

	if compileResponse.Value.Success {
		return true, nil
	}

	return false, fmt.Errorf("error compiling: %v", compileResponse.Value.FailedQueries)
}

func (c Cx1Client) AuditCompilePollingByID(auditSessionId string) error {
	return c.AuditCompilePollingByIDWithTimeout(auditSessionId, c.consts.AuditCompilePollingDelaySeconds, c.consts.AuditCompilePollingMaxSeconds)
}

func (c Cx1Client) AuditCompilePollingByIDWithTimeout(auditSessionId string, delaySeconds, maxSeconds int) error {
	c.logger.Infof("Polling status of compilation for audit session %v", auditSessionId)
	status := false
	var err error

	pollingCounter := 0
	for !status {
		status, err = c.auditGetCompileStatusByID(auditSessionId)
		if err != nil {
			return err
		}
		if status {
			return nil
		}

		if maxSeconds != 0 && pollingCounter >= maxSeconds {
			return fmt.Errorf("audit query compilation polled %d seconds without success: session may no longer be valid - use cx1client.get/setclientvars to change timeout", pollingCounter)
		}
		if status {
			return nil
		}

		time.Sleep(time.Duration(delaySeconds) * time.Second)
		pollingCounter += delaySeconds
	}
	return fmt.Errorf("unknown error")
}

func (c Cx1Client) AuditCreateCorpQuery(auditSessionId string, query AuditQuery) (AuditQuery, error) {
	folder := fmt.Sprintf("queries/%v/%v/", query.Language, query.Group)
	var qc struct {
		Name     string `json:"name"`
		Path     string `json:"path"`
		Source   string `json:"source"`
		Metadata struct {
			IsExecutable       bool
			Path               string
			QueryDescriptionID string
			Severity           uint
		} `json:"metadata"`
	}
	qc.Name = query.Name
	qc.Source = query.Source
	qc.Path = folder
	qc.Metadata.IsExecutable = query.IsExecutable
	qc.Metadata.Path = query.Path
	qc.Metadata.Severity = query.Severity

	jsonBody, _ := json.Marshal(qc)

	response, err := c.sendRequest(http.MethodPost, fmt.Sprintf("/cx-audit/queries/%v", auditSessionId), bytes.NewReader(jsonBody), nil)
	if err != nil {
		return AuditQuery{}, err
	}

	if string(response) != "" {
		return AuditQuery{}, fmt.Errorf("creating query returned error: %v", string(response))
	}
	return c.GetQueryByName("Corp", query.Language, query.Group, query.Name)
}

// updating queries via PUT is possible, but only allows changing the source code, not metadata around each query.
// this will be fixed in the future
// PUT is the only option to create an override on the project-level (and maybe in the future on application-level)
func (c Cx1Client) AuditUpdateQuery(auditSessionId string, query AuditQuery) error { // level = projectId or "Corp"
	c.logger.Debugf("Saving query %v on level %v", query.Path, query.Level)

	q := QueryUpdate{
		Name:   query.Name,
		Path:   query.Path,
		Source: query.Source,
		Metadata: QueryUpdateMetadata{
			Severity: query.Severity,
		},
	}

	return c.AuditUpdateQueries(auditSessionId, query.LevelID, []QueryUpdate{q})
}

func (c Cx1Client) AuditUpdateQueries(auditSessionId, level string, queries []QueryUpdate) error {
	jsonBody, _ := json.Marshal(queries)
	response, err := c.sendRequest(http.MethodPut, fmt.Sprintf("/cx-audit/queries/%v/%v", auditSessionId, level), bytes.NewReader(jsonBody), nil)
	if err != nil {
		// Workaround to fix issue in CX1: sometimes the query is saved but still throws a 500 error
		c.logger.Warnf("Query update failed with %s but it's buggy, checking if the query was updated anyway", err)
		for _, q := range queries {
			aq, err2 := c.GetQueryByPath(level, q.Path)
			if err2 != nil {
				return fmt.Errorf("retrieving the query %v on %v to check status failed with: %s", q.Path, level, err2)
			}
			if aq.Source != q.Source {
				return fmt.Errorf("query %v on %v source was not updated", q.Path, level)
			}
			c.logger.Warnf("Query %v on %v was successfully updated despite the error", q.Path, level)
		}
		return nil
	}
	if string(response) == "" {
		return nil
	}

	var responseStruct struct {
		Message string `json:"message"`
		Type    string `json:"type"`
	}

	err = json.Unmarshal(response, &responseStruct)
	if err != nil {
		return err
	}

	if responseStruct.Type == "ERROR" {
		return fmt.Errorf("error while saving queries: %v", responseStruct.Message)
	} else {
		return nil
	}
}

func (q AuditQuery) String() string {
	return fmt.Sprintf("[%d] %v: %v", q.QueryID, q.Level, q.Path)
}
func (q *AuditQuery) ParsePath() {
	s := strings.Split(q.Path, "/")
	q.Language = s[1]
	q.Group = s[2]
	q.Name = s[3]
}
