package Cx1ClientGo

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

/*
	This is separate from queries.go to split the functions that require a Web-Audit Session from those that do not.
	This file contains the query-related functions that require an audit session (compiling queries, updating queries, creating overrides)
*/

var AUDIT_QUERY_PRODUCT = "Cx"
var AUDIT_QUERY_TENANT = "Corp"
var AUDIT_QUERY_APPLICATION = "Team"
var AUDIT_QUERY_PROJECT = "Project"

type requestIDBody struct {
	Message string `json:"message"`
	Code    int    `json:"code"`
	Id      string `json:"id"`
}

type requestQueryStatus struct {
	AlreadyExists bool   `json:"alreadyExists"`
	EditorKey     string `json:"id"`
}

func (c Cx1Client) QueryTypeProduct() string {
	return AUDIT_QUERY_PRODUCT
}
func (c Cx1Client) QueryTypeTenant() string {
	return AUDIT_QUERY_TENANT
}
func (c Cx1Client) QueryTypeApplication() string {
	return AUDIT_QUERY_APPLICATION
}
func (c Cx1Client) QueryTypeProject() string {
	return AUDIT_QUERY_PROJECT
}

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

	if session.Data.Status != "ALLOCATED" {
		return session, fmt.Errorf("failed to allocate audit session: %v", session.Data.Status)
	}

	_, err = c.AuditRequestStatusPollingByID(session.ID, session.Data.RequestID)

	if err != nil {
		c.logger.Errorf("Error while creating audit engine: %s", err)
		return session, err
	}

	return session, nil
}

func (c Cx1Client) AuditDeleteSessionByID(sessionId string) error {
	_, err := c.sendRequest(http.MethodDelete, fmt.Sprintf("/query-editor/sessions/%v", sessionId), nil, nil)
	if err != nil {
		return err
	}

	return nil
}

func (c Cx1Client) AuditGetRequestStatusByID(auditSessionId, requestId string) (bool, interface{}, error) {
	response, err := c.sendRequest(http.MethodGet, fmt.Sprintf("/query-editor/sessions/%v/requests/%v", auditSessionId, requestId), nil, nil)
	type AuditRequestStatus struct {
		Completed    bool        `json:"completed"`
		Value        interface{} `json:"value"`
		ErrorCode    int         `json:"code"`
		ErrorMessage string      `json:"message"`
	}

	var status AuditRequestStatus
	if err != nil {
		return false, status.Value, err
	}

	err = json.Unmarshal(response, &status)
	if err != nil {
		return false, status.Value, err
	}

	if status.ErrorCode != 0 && status.ErrorMessage != "" {
		return false, status.Value, fmt.Errorf("query editor returned error code %d: %v", status.ErrorCode, status.ErrorMessage)
	}
	return status.Completed, status.Value, nil
}

func (c Cx1Client) AuditRequestStatusPollingByID(auditSessionId, requestId string) (interface{}, error) {
	return c.AuditRequestStatusByIDWithTimeout(auditSessionId, requestId, c.consts.AuditEnginePollingDelaySeconds, c.consts.AuditEnginePollingMaxSeconds)
}

func (c Cx1Client) AuditRequestStatusByIDWithTimeout(auditSessionId, requestId string, delaySeconds, maxSeconds int) (interface{}, error) {
	c.logger.Debugf("Polling status of request %v for audit session %v", requestId, auditSessionId)
	var status interface{}
	var err error
	var completed bool
	pollingCounter := 0
	for err != nil {
		completed, status, err = c.AuditGetRequestStatusByID(auditSessionId, requestId)
		if err != nil {
			return status, err
		}

		if maxSeconds != 0 && pollingCounter >= maxSeconds {
			return status, fmt.Errorf("audit request %v polled %d seconds without success: session may no longer be valid - use cx1client.get/setclientvars to change timeout", requestId, pollingCounter)
		}

		if completed {
			break
		}

		time.Sleep(time.Duration(delaySeconds) * time.Second)
		pollingCounter += delaySeconds
	}

	return status, nil
}

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

	//c.logger.Infof("Languages present: %v", status.Value.([]string))

	_, err = c.AuditGetScanSourcesByID(session.ID)
	if err != nil {
		return session, fmt.Errorf("error while getting scan sources: %v", session.ID)
	}

	err = c.AuditRunScanByID(session.ID)
	if err != nil {
		c.logger.Errorf("Error while triggering audit scan: %s", err)
		return session, err
	}

	c.AuditSessionKeepAlive(session.ID) // one for the road
	return session, nil
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

func (c Cx1Client) AuditRunScanByID(auditSessionId string) error {
	c.logger.Infof("Triggering scan under audit session %v", auditSessionId)
	response, err := c.sendRequest(http.MethodPost, fmt.Sprintf("/query-editor/sessions/%v/sources/scan", auditSessionId), nil, nil)
	if err != nil {
		return err
	}

	var responseBody requestIDBody

	err = json.Unmarshal(response, &responseBody)
	if err != nil {
		return err
	}

	if responseBody.Code != 0 && responseBody.Message != "" {
		return fmt.Errorf("audit scan returned error %d: %v", responseBody.Code, responseBody.Message)
	}

	_, err = c.AuditRequestStatusPollingByID(auditSessionId, responseBody.Id)
	if err != nil {
		c.logger.Errorf("Error while polling audit scan: %s", err)
		return err
	}

	return nil
}

func (q AuditQuery) String() string {
	return fmt.Sprintf("[%d] %v: %v", q.QueryID, q.Level, q.Path)
}

func (c Cx1Client) GetAuditQueryByKey(auditSessionId, key string) (Query, error) {
	c.logger.Debugf("Get audit query by key: %v", key)

	response, err := c.sendRequest(http.MethodGet, fmt.Sprintf("/query-editor/sessions/%v/queries/%v", auditSessionId, key), nil, nil)
	if err != nil {
		return Query{}, err
	}

	var q AuditQuery
	err = json.Unmarshal(response, &q)
	if err != nil {
		return Query{}, err
	}

	return q.ToQuery(), nil
}

func (c Cx1Client) GetAuditQueriesByLevelID(auditSessionId, level, levelId string) ([]AuditQuery, error) {
	c.logger.Debugf("Get all queries for %v", level)

	var url string
	var queries []AuditQuery
	var querytree []AuditQueryTree
	switch level {
	case AUDIT_QUERY_TENANT:
		url = "/query-editor/queries"
	case AUDIT_QUERY_PROJECT:
		url = fmt.Sprintf("/query-editor/sessions/%v/queries?projectId=%v", auditSessionId, levelId)
	default:
		return queries, fmt.Errorf("invalid level %v, options are currently: Corp or Project", level)
	}

	response, err := c.sendRequest(http.MethodGet, url, nil, nil)
	if err != nil {
		return queries, err
	}

	err = json.Unmarshal(response, &querytree)
	if err != nil {
		return queries, err
	}

	for _, lang := range querytree {
		for _, level := range lang.Children {
			for _, group := range level.Children {
				for _, query := range group.Children {
					queries = append(queries, AuditQuery{
						QueryID:            0,
						Level:              level.Title,
						LevelID:            levelId,
						Path:               fmt.Sprintf("queries/%v/%v/%v/%v.cs", lang.Title, group.Title, query.Title, query.Title),
						Modified:           "",
						Source:             "",
						Name:               query.Title,
						Group:              group.Title,
						Language:           lang.Title,
						Severity:           GetSeverity(GetSeverityID(query.Data.Severity)), // easy way to make the severity consistent since this endpoint returns lowercase.
						Cwe:                0,
						IsExecutable:       false,
						CxDescriptionId:    0,
						QueryDescriptionId: "",
						Key:                query.Key,
						Title:              query.Title,
					})
				}
			}
		}
	}

	return queries, nil
}

func (c Cx1Client) DeleteQueryOverrideByKey(sessionId, queryKey string) error {
	response, err := c.sendRequest(http.MethodDelete, fmt.Sprintf("/query-editor/sessions/%v/queries/%v", sessionId, queryKey), nil, nil)
	if err != nil {
		return err
	}

	var responseBody requestIDBody
	err = json.Unmarshal(response, &responseBody)
	if err != nil {
		return err
	}

	_, err = c.AuditRequestStatusPollingByID(sessionId, responseBody.Id)

	return err
}

func (c Cx1Client) CreateQueryOverrideByKey(sessionId, queryKey, level string) (Query, error) {
	var newQuery Query
	if strings.EqualFold(level, AUDIT_QUERY_APPLICATION) {
		level = AUDIT_QUERY_APPLICATION
	} else if strings.EqualFold(level, AUDIT_QUERY_PROJECT) {
		level = AUDIT_QUERY_PROJECT
	} else if strings.EqualFold(level, AUDIT_QUERY_TENANT) {
		level = AUDIT_QUERY_TENANT
	} else {
		return newQuery, fmt.Errorf("invalid query override level specified ('%v'), use functions cx1client.QueryTypeTenant, QueryTypeApplication, and QueryTypeProduct", level)
	}

	oq, err := c.GetAuditQueryByKey(sessionId, queryKey)
	if err != nil {
		return newQuery, err
	}

	type NewQuery struct {
		CWE         int64
		Executable  bool
		Description int64
		Language    string
		Group       string
		Severity    string
		SastID      uint64
		ID          string
		Name        string
		Level       string
		Path        string
	}

	newQueryData := NewQuery{
		CWE:         oq.CweID,
		Executable:  oq.IsExecutable,
		Description: oq.QueryDescriptionId,
		Language:    oq.Language,
		Group:       oq.Group,
		Severity:    oq.Severity,
		SastID:      oq.SastID,
		ID:          oq.EditorKey,
		Name:        oq.Name,
		Level:       strings.ToLower(level), // seems to be in lowercase in the post
		Path:        oq.Path,
	}

	jsonBody, _ := json.Marshal(newQueryData)

	response, err := c.sendRequest(http.MethodPost, fmt.Sprintf("/query-editor/sessions/%v/queries", sessionId), bytes.NewReader(jsonBody), nil)
	if err != nil {
		return newQuery, err
	}
	var responseBody requestIDBody
	err = json.Unmarshal(response, &responseBody)
	if err != nil {
		return newQuery, fmt.Errorf("failed to unmarshal response: %s", err)
	}

	data, err := c.AuditRequestStatusPollingByID(sessionId, responseBody.Id)
	if err != nil {
		return newQuery, fmt.Errorf("failed to create query: %s", err)
	}

	return c.GetAuditQueryByKey(sessionId, data.(requestQueryStatus).EditorKey)
}

func (c Cx1Client) UpdateQuerySourceByKey(sessionId, queryKey, source string) (Query, error) {
	var newQuery Query
	var postbody struct {
		ID     string `json:"id"`
		Source string `json:"source"`
	}
	postbody.ID = queryKey
	postbody.Source = source

	jsonBody, err := json.Marshal(postbody)
	if err != nil {
		return newQuery, fmt.Errorf("failed to marshal query source: %s", err)
	}

	response, err := c.sendRequest(http.MethodPut, fmt.Sprintf("/query-editor/sessions/%v/queries/source", sessionId), bytes.NewReader(jsonBody), nil)
	if err != nil {
		return newQuery, fmt.Errorf("failed to save source: %s", err)
	}

	var responseBody requestIDBody
	err = json.Unmarshal(response, &responseBody)
	if err != nil {
		return newQuery, fmt.Errorf("failed to unmarshal response: %s", err)
	}

	type QueryStatus struct {
		AlreadyExists bool   `json:"alreadyExists"`
		EditorKey     string `json:"id"`
	}

	status, err := c.AuditRequestStatusPollingByID(sessionId, responseBody.Id)
	if err != nil {
		return newQuery, err
	}

	newAuditQuery, err := c.GetAuditQueryByKey(sessionId, status.(QueryStatus).EditorKey)
	if err != nil {
		return newQuery, err
	}

	return newAuditQuery, nil

}

func (q AuditQuery) ToQuery() Query {
	return Query{
		QueryID:            q.QueryID,
		Level:              q.Level,
		LevelID:            q.LevelID,
		Path:               q.Path,
		Modified:           q.Modified,
		Source:             q.Source,
		Name:               q.Name,
		Group:              q.Group,
		Language:           q.Language,
		Severity:           q.Severity,
		CweID:              q.Cwe,
		IsExecutable:       q.IsExecutable,
		QueryDescriptionId: q.CxDescriptionId,
		Custom:             q.Level != AUDIT_QUERY_PRODUCT,
		EditorKey:          q.Key,
		SastID:             q.SastID,
	}
}
