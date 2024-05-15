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

func (c Cx1Client) AuditCreateSessionByID(engine, projectId, scanId string) (AuditSession, error) {
	c.logger.Debugf("Trying to create audit session for project %v scan %v", projectId, scanId)
	/*available, _, err := c.AuditFindSessionsByID(projectId, scanId)
	if err != nil {
		return "", err
	}

	if !available {
		return "", fmt.Errorf("audit session not available")
	}*/

	var session AuditSession

	body := map[string]interface{}{
		"projectId": projectId,
		"scanId":    scanId,
		"scanner":   engine,
	}

	jsonBody, _ := json.Marshal(body)

	response, err := c.sendRequest(http.MethodPost, "/query-editor/sessions", bytes.NewReader(jsonBody), nil)
	if err != nil {
		return session, err
	}

	err = json.Unmarshal(response, &session)
	if err != nil {
		return session, err
	}

	if session.Data.Status == "ALLOCATED" {
		return session, nil
	}

	return session, fmt.Errorf("failed to allocate audit session: %v", session.Data.Status)
}

func (c Cx1Client) AuditDeleteSessionByID(sessionId string) error {
	_, err := c.sendRequest(http.MethodDelete, fmt.Sprintf("/query-editor/sessions/%v", sessionId), nil, nil)
	if err != nil {
		return err
	}

	return nil
}

/*
// no longer available as of 2024-05-13

func (c Cx1Client) AuditFindSessionsByID(projectId, scanId string) (bool, []string, error) {
	c.logger.Tracef("Checking for audit session for project %v scan %v", projectId, scanId)

	response, err := c.sendRequest(http.MethodGet, fmt.Sprintf("/query-editor/sessions?projectId=%v&scanId=%v", projectId, scanId), nil, nil)
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
*/

func (c Cx1Client) AuditGetRequestStatusByID(auditSessionId, requestId string) (AuditRequestStatus, error) {
	response, err := c.sendRequest(http.MethodGet, fmt.Sprintf("/query-editor/sessions/%v/requests/%v", auditSessionId, requestId), nil, nil)
	var status AuditRequestStatus
	if err != nil {
		return status, err
	}

	err = json.Unmarshal(response, &status)
	if err != nil {
		return status, err
	}

	if status.ErrorCode != 0 && status.ErrorMessage != "" {
		return status, fmt.Errorf("query editor returned error code %d: %v", status.ErrorCode, status.ErrorMessage)
	}
	return status, nil
}

func (c Cx1Client) AuditRequestStatusPollingByID(auditSessionId, requestId string) (AuditRequestStatus, error) {
	return c.AuditRequestStatusByIDWithTimeout(auditSessionId, requestId, c.consts.AuditEnginePollingDelaySeconds, c.consts.AuditEnginePollingMaxSeconds)
}

func (c Cx1Client) AuditRequestStatusByIDWithTimeout(auditSessionId, requestId string, delaySeconds, maxSeconds int) (AuditRequestStatus, error) {
	c.logger.Debugf("Polling status of request %v for audit session %v", requestId, auditSessionId)
	var status AuditRequestStatus
	var err error
	pollingCounter := 0
	for !status.Completed {
		status, err = c.AuditGetRequestStatusByID(auditSessionId, requestId)
		if err != nil {
			return status, err
		}

		if maxSeconds != 0 && pollingCounter >= maxSeconds {
			return status, fmt.Errorf("audit request %v polled %d seconds without success: session may no longer be valid - use cx1client.get/setclientvars to change timeout", requestId, pollingCounter)
		}

		if status.Completed {
			break
		}

		time.Sleep(time.Duration(delaySeconds) * time.Second)
		pollingCounter += delaySeconds
	}

	return status, nil
}

/*
func (c Cx1Client) AuditGetEngineStatusByID(auditSessionId string) (bool, error) {
	response, err := c.sendRequest(http.MethodGet, fmt.Sprintf("/query-editor/sessions/%v/sast-status", auditSessionId), nil, nil)
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

	return false, fmt.Errorf("unknown query-editor sast status response: %v", engineResponse.Message)
}

func (c Cx1Client) AuditEnginePollingByID(auditSessionId string) error {
	return c.AuditEnginePollingByIDWithTimeout(auditSessionId, c.consts.AuditEnginePollingDelaySeconds, c.consts.AuditEnginePollingMaxSeconds)
}

func (c Cx1Client) AuditEnginePollingByIDWithTimeout(auditSessionId string, delaySeconds, maxSeconds int) error {
	c.logger.Debugf("Polling status of query-editor engine for session %v", auditSessionId)
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
	response, err := c.sendRequest(http.MethodGet, fmt.Sprintf("/query-editor/sessions/%v/project/languages", auditSessionId), nil, nil)
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

	response, err := c.sendRequest(http.MethodGet, fmt.Sprintf("/query-editor/sessions/%v/request-status?type=%d", auditSessionId, 0), nil, nil)
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
*/

func (c Cx1Client) AuditRunScanByID(auditSessionId string) (string, error) {
	c.logger.Infof("Triggering scan under audit session %v", auditSessionId)
	response, err := c.sendRequest(http.MethodPost, fmt.Sprintf("/query-editor/sessions/%v/sources/scan", auditSessionId), nil, nil)
	if err != nil {
		return "", err
	}

	var responseStruct struct {
		Message string `json:"message"`
		Code    int    `json:"code"`
		Id      string `json:"id"`
	}

	err = json.Unmarshal(response, &responseStruct)
	if err != nil {
		return "", err
	}

	if responseStruct.Code != 0 && responseStruct.Message != "" {
		return "", fmt.Errorf("audit scan returned error %d: %v", responseStruct.Code, responseStruct.Message)
	}

	return responseStruct.Id, nil
}

func (c Cx1Client) AuditGetScanStatusByID(auditSessionId string) (bool, error) {
	var scanResponse struct {
		Completed bool     `json:"completed"`
		Value     []string `json:"value"`
		Message   string   `json:"message"`
	}

	response, err := c.sendRequest(http.MethodGet, fmt.Sprintf("/query-editor/sessions/%v/request-status?type=%d", auditSessionId, 1), nil, nil)
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

/*
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
*/

func (c Cx1Client) AuditSessionKeepAlive(auditSessionId string) error {
	_, err := c.sendRequest(http.MethodPatch, fmt.Sprintf("/query-editor/sessions/%v", auditSessionId), nil, nil)
	if err != nil {
		return err
	}
	return nil
}

// Convenience function
func (c Cx1Client) GetAuditSessionByID(engine, projectId, scanId string) (AuditSession, error) {
	// TODO: convert the audit session to an object that also does the polling/keepalive
	c.logger.Infof("Creating an audit session for project %v scan %v", projectId, scanId)

	session, err := c.AuditCreateSessionByID(engine, projectId, scanId)
	if err != nil {
		c.logger.Errorf("Error creating cxaudit session: %s", err)
		return session, err
	}
	//}

	err = c.AuditSessionKeepAlive(session.ID)
	if err != nil {
		return session, err
	}

	// check engine status
	_, err = c.AuditRequestStatusPollingByID(session.ID, session.Data.RequestID)

	if err != nil {
		c.logger.Errorf("Error while creating audit engine: %s", err)
		return session, err
	}

	//c.logger.Infof("Languages present: %v", status.Value.([]string))

	_, err = c.AuditGetScanSourcesByID(session.ID)
	if err != nil {
		return session, fmt.Errorf("error while getting scan sources: %v", session.ID)
	}

	//if !fastInit { // || !reusedSession {
	requestID, err := c.AuditRunScanByID(session.ID)
	if err != nil {
		c.logger.Errorf("Error while triggering audit scan: %s", err)
		return session, err
	}
	//}

	_, err = c.AuditRequestStatusPollingByID(session.ID, requestID)
	if err != nil {
		c.logger.Errorf("Error while polling audit scan: %s", err)
		return session, err
	}

	c.AuditSessionKeepAlive(session.ID) // one for the road

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
	response, err := c.sendRequest(http.MethodPost, fmt.Sprintf("/query-editor/sessions/%v/queries/compile", auditSessionId), bytes.NewReader(jsonBody), nil)
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
	response, err := c.sendRequest(http.MethodGet, fmt.Sprintf("/query-editor/sessions/%v/request-status?type=%d", sessionId, 2), nil, nil)
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

	response, err := c.sendRequest(http.MethodPost, fmt.Sprintf("/query-editor/sessions/%v/queries/", auditSessionId), bytes.NewReader(jsonBody), nil)
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
func (c Cx1Client) UpdateAuditQuery(auditSessionId string, query AuditQuery) error { // level = projectId or "Corp"
	c.logger.Debugf("Saving query %v on level %v", query.Path, query.Level)

	q := QueryUpdate{
		Name:   query.Name,
		Path:   query.Path,
		Source: query.Source,
		Metadata: QueryUpdateMetadata{
			Severity: query.Severity,
		},
	}

	return c.UpdateAuditQueries(auditSessionId, query.LevelID, []QueryUpdate{q})
}

func (c Cx1Client) UpdateAuditQueries(auditSessionId, level string, queries []QueryUpdate) error {
	jsonBody, _ := json.Marshal(queries)
	response, err := c.sendRequest(http.MethodPut, fmt.Sprintf("/query-editor/sessions/%v/queries/%v", auditSessionId, level), bytes.NewReader(jsonBody), nil)
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

func (c Cx1Client) AuditGetScanSourcesByID(auditSessionId string) ([]AuditScanSourceFile, error) {
	c.logger.Debugf("Get %v audit scan sources", auditSessionId)

	var sourcefiles []AuditScanSourceFile

	response, err := c.sendRequest(http.MethodGet, fmt.Sprintf("/query-editor/sessions/%v/sources", auditSessionId), nil, nil)
	if err != nil {
		return sourcefiles, err
	}

	err = json.Unmarshal(response, &sourcefiles)
	return sourcefiles, err
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

func (c Cx1Client) GetAuditQueryByName(auditSessionId, level, language, group, query string) (AuditQuery, error) {
	c.logger.Debugf("Get %v audit query by name: %v -> %v -> %v", level, language, group, query)
	path := fmt.Sprintf("queries%%2F%v%%2F%v%%2F%v%%2F%v", language, group, query, query)

	response, err := c.sendRequest(http.MethodGet, fmt.Sprintf("/query-editor/sessions/%v/queries/%v/%v.cs", auditSessionId, level, path), nil, nil)
	if err != nil {
		return AuditQuery{}, err
	}

	var q AuditQuery
	err = json.Unmarshal(response, &q)
	if err != nil {
		return q, err
	}
	q.ParsePath()

	q.LevelID = level

	return q, nil
}

func (c Cx1Client) GetAuditQueryByPath(auditSessionId, level, path string) (AuditQuery, error) {
	c.logger.Debugf("Get %v query by path: %v", level, path)

	response, err := c.sendRequest(http.MethodGet, fmt.Sprintf("/query-editor/sessions/%v/queries/%v/%v", auditSessionId, level, strings.Replace(path, "/", "%2f", -1)), nil, nil)
	if err != nil {
		return AuditQuery{}, err
	}

	var q AuditQuery
	err = json.Unmarshal(response, &q)
	if err != nil {
		return q, err
	}
	q.ParsePath()

	if strings.EqualFold(q.Level, "corp") || strings.EqualFold(q.Level, "cx") {
		q.LevelID = q.Level
	} else { // team or project-level override, so store the ID
		q.LevelID = level
	}
	return q, nil
}

func (c Cx1Client) GetAuditQueriesByLevelID(auditSessionId, level, levelId string) ([]AuditQuery, error) {
	c.logger.Debugf("Get all queries for %v", level)

	var url string
	var queries []AuditQuery
	switch level {
	case "Corp":
		url = "/query-editor/queries"
	case "Project":
		url = fmt.Sprintf("/query-editor/sessions/%v/queries?projectId=%v", auditSessionId, levelId)
	default:
		return queries, fmt.Errorf("invalid level %v, options are currently: Corp or Project", level)
	}

	response, err := c.sendRequest(http.MethodGet, url, nil, nil)
	if err != nil {
		return queries, err
	}

	err = json.Unmarshal(response, &queries)
	if err != nil {
		return queries, err
	}

	for id := range queries {
		queries[id].ParsePath()
	}

	return queries, nil
}

func (c Cx1Client) DeleteAuditQuery(auditSessionId string, query AuditQuery) error {
	return c.DeleteAuditQueryByName(auditSessionId, query.Level, query.LevelID, query.Language, query.Group, query.Name)
}

func (c Cx1Client) DeleteAuditQueryByName(auditSessionId, level, levelID, language, group, query string) error {
	c.logger.Debugf("Delete %v query by name: %v -> %v -> %v", level, language, group, query)
	path := fmt.Sprintf("queries%%2F%v%%2F%v%%2F%v%%2F%v", language, group, query, query)

	_, err := c.sendRequest(http.MethodDelete, fmt.Sprintf("/query-editor/sessions/%v/queries/%v/%v.cs", auditSessionId, levelID, path), nil, nil)
	if err != nil {
		// currently there's a bug where the response can be error 500 even if it succeeded.

		q, err2 := c.GetQueryByName(levelID, language, group, query)
		if err2 != nil {
			c.logger.Warnf("error while deleting query (%s) followed by error while checking if the query was deleted (%s) - assuming the query was deleted", err, err2)
			return nil
		}

		if q.Level != level {
			c.logger.Warnf("While deleting the query an error was returned (%s) but the query was deleted", err)
			return nil
		} else {
			return fmt.Errorf("error while deleting query (%s) and the query %v still exists", err, q)
		}
	}

	return nil
}

func (q AuditQuery) CreateTenantOverride() AuditQuery {
	new_query := q
	new_query.Level = "Corp"
	new_query.LevelID = "Corp"
	return new_query
}
func (q AuditQuery) CreateProjectOverrideByID(projectId string) AuditQuery {
	new_query := q
	new_query.Level = "Project"
	new_query.LevelID = projectId
	return new_query
}
func (q AuditQuery) CreateApplicationOverrideByID(applicationId string) AuditQuery {
	new_query := q
	new_query.Level = "Team"
	new_query.LevelID = applicationId
	return new_query
}
