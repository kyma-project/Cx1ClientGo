package Cx1ClientGo

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

/*
	This is separate from audit.go to split the functions that require a Web-Audit Session from those that do not.
	This file contains the generic query-related functions that do not need a valid audit session.
*/

func (c Cx1Client) GetQueryByName_v310(level, language, group, query string) (AuditQuery_v310, error) {
	c.depwarn("GetQueryByName", "GetAuditQueryByName")
	c.logger.Debugf("Get %v query by name: %v -> %v -> %v", level, language, group, query)
	path := fmt.Sprintf("queries%%2F%v%%2F%v%%2F%v%%2F%v", language, group, query, query)

	response, err := c.sendRequest(http.MethodGet, fmt.Sprintf("/cx-audit/queries/%v/%v.cs", level, path), nil, nil)
	if err != nil {
		return AuditQuery_v310{}, err
	}

	var q_v310 AuditQuery_v310
	var q AuditQuery_v310
	err = json.Unmarshal(response, &q_v310)
	if err != nil {
		return q, err
	}
	q_v310.ParsePath()

	q_v310.LevelID = level

	return q_v310, nil
}

func (c Cx1Client) GetQueryByPath_v310(level, path string) (AuditQuery_v310, error) {
	c.depwarn("GetQueryByPath", "GetAuditQueryByPath")
	c.logger.Debugf("Get %v query by path: %v", level, path)

	response, err := c.sendRequest(http.MethodGet, fmt.Sprintf("/cx-audit/queries/%v/%v", level, strings.Replace(path, "/", "%2f", -1)), nil, nil)
	if err != nil {
		return AuditQuery_v310{}, err
	}

	var q_v310 AuditQuery_v310
	err = json.Unmarshal(response, &q_v310)
	if err != nil {
		return q_v310, err
	}
	q_v310.ParsePath()

	if strings.EqualFold(q_v310.Level, AUDIT_QUERY_TENANT) || strings.EqualFold(q_v310.Level, AUDIT_QUERY_PRODUCT) {
		q_v310.LevelID = q_v310.Level
	} else { // team or project-level override, so store the ID
		q_v310.LevelID = level
	}
	return q_v310, nil
}

func (c Cx1Client) GetQueriesByLevelID_v310(level, levelId string) ([]AuditQuery_v310, error) {
	c.depwarn("GetQueryByLevelID", "GetAuditQueryByLevelID")
	c.logger.Debugf("Get all queries for %v", level)

	var url string

	var queries_v310 []AuditQuery_v310

	switch level {
	case AUDIT_QUERY_TENANT:
		url = "/cx-audit/queries"
	case AUDIT_QUERY_PROJECT:
		url = fmt.Sprintf("/cx-audit/queries?projectId=%v", levelId)
	default:
		return queries_v310, fmt.Errorf("invalid level %v, options are currently: Corp or Project", level)
	}

	response, err := c.sendRequest(http.MethodGet, url, nil, nil)
	if err != nil {
		return queries_v310, err
	}

	err = json.Unmarshal(response, &queries_v310)
	if err != nil {
		return queries_v310, err
	}

	applicationId := ""

	for id := range queries_v310 {
		queries_v310[id].ParsePath()
		switch queries_v310[id].Level {
		case AUDIT_QUERY_TENANT:
			queries_v310[id].LevelID = AUDIT_QUERY_TENANT
		case AUDIT_QUERY_PROJECT:
			queries_v310[id].LevelID = levelId
		case AUDIT_QUERY_APPLICATION:
			if applicationId == "" {
				project, err := c.GetProjectByID(levelId)
				if err != nil {
					return queries_v310, fmt.Errorf("failed to retrieve project with ID %v", levelId)
				}
				if len(project.Applications) == 0 {
					return queries_v310, fmt.Errorf("project %v has an application-level query defined, but has no application associated", project.String())
				}
				applicationId = project.Applications[0]
			}
			queries_v310[id].LevelID = applicationId
		case AUDIT_QUERY_PRODUCT:
			queries_v310[id].LevelID = AUDIT_QUERY_PRODUCT
		}
	}

	return queries_v310, nil
}

func FindQueryByName_v310(queries []AuditQuery_v310, level, language, group, name string) (AuditQuery_v310, error) {
	for _, q := range queries {
		if q.Level == level && q.Language == language && q.Group == group && q.Name == name {
			return q, nil
		}
	}

	return AuditQuery_v310{}, fmt.Errorf("no query found matching [%v] %v -> %v -> %v", level, language, group, name)
}

func (c Cx1Client) DeleteQuery_v310(query AuditQuery_v310) error {
	return c.DeleteQueryByName_v310(query.Level, query.LevelID, query.Language, query.Group, query.Name)
}

func (c Cx1Client) DeleteQueryByName_v310(level, levelID, language, group, query string) error {
	c.depwarn("DeleteQueryByName", "DeleteAuditQueryByName")
	c.logger.Debugf("Delete %v query by name: %v -> %v -> %v", level, language, group, query)
	path := fmt.Sprintf("queries%%2F%v%%2F%v%%2F%v%%2F%v", language, group, query, query)

	_, err := c.sendRequest(http.MethodDelete, fmt.Sprintf("/cx-audit/queries/%v/%v.cs", levelID, path), nil, nil)
	if err != nil {
		// currently there's a bug where the response can be error 500 even if it succeeded.

		q, err2 := c.GetQueryByName_v310(levelID, language, group, query)
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

func (c Cx1Client) AuditNewQuery_v310(language, group, name string) (AuditQuery_v310, error) {
	c.depwarn("AuditNewQuery", "CreateAuditQuery")
	newQuery, err := c.GetQueryByName_v310(AUDIT_QUERY_TENANT, language, "CxDefaultQueryGroup", "CxDefaultQuery")
	if err != nil {
		return newQuery, err
	}

	newQuery.Group = group
	newQuery.Name = name
	return newQuery, nil
}

// updating queries via PUT is possible, but only allows changing the source code, not metadata around each query.
// this will be fixed in the future
// PUT is the only option to create an override on the project-level (and maybe in the future on application-level)
func (c Cx1Client) UpdateQuery_v310(query AuditQuery_v310) error {
	c.depwarn("UpdateQuery", "UpdateAuditQuery")
	c.logger.Debugf("Saving query %v on level %v", query.Path, query.Level)

	q := QueryUpdate{
		Name:   query.Name,
		Path:   query.Path,
		Source: query.Source,
		Metadata: QueryUpdateMetadata{
			Severity: query.Severity,
		},
	}

	return c.UpdateQueries_v310(query.LevelID, []QueryUpdate{q})
}

func (c Cx1Client) UpdateQueries_v310(level string, queries []QueryUpdate) error {
	c.depwarn("UpdateQuery/UpdateQueries", "UpdateAuditQuery/UpdateAuditQueries")
	jsonBody, _ := json.Marshal(queries)
	response, err := c.sendRequest(http.MethodPut, fmt.Sprintf("/cx-audit/queries/%v", level), bytes.NewReader(jsonBody), nil)
	if err != nil {
		if err.Error()[0:8] == "HTTP 405" {
			return fmt.Errorf("this endpoint is no longer available - please use UpdateAuditQuery/UpdateAuditQueries instead")
		} else {
			// Workaround to fix issue in CX1: sometimes the query is saved but still throws a 500 error
			c.logger.Warnf("Query update failed with %s but it's buggy, checking if the query was updated anyway", err)
			for _, q := range queries {
				aq, err2 := c.GetQueryByPath_v310(level, q.Path)
				if err2 != nil {
					return fmt.Errorf("retrieving the query %v on %v to check status failed with: %s", q.Path, level, err2)
				}
				if aq.Source != q.Source {
					return fmt.Errorf("query %v on %v source was not updated", q.Path, level)
				}
				c.logger.Warnf("Query %v on %v was successfully updated despite the error", q.Path, level)
			}
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

func (c Cx1Client) GetQueries_v310() (QueryCollection, error) {
	c.depwarn("GetQueries", "GetAuditQueries")
	var qc QueryCollection
	q, err := c.GetPresetQueries()
	if err != nil {
		return qc, err
	}
	qc.AddQueries(&q)

	aq, err := c.GetQueriesByLevelID_v310(AUDIT_QUERY_TENANT, "")
	if err != nil {
		return qc, err
	}

	qc.AddAuditQueries_v310(&aq)

	return qc, nil
}

func (qc *QueryCollection) AddAuditQueries_v310(queries *[]AuditQuery_v310) {
	for _, q := range *queries {
		ql := qc.GetQueryLanguageByName(q.Language)

		if ql == nil {
			qc.QueryLanguages = append(qc.QueryLanguages, QueryLanguage{q.Language, []QueryGroup{}})
			ql = &qc.QueryLanguages[len(qc.QueryLanguages)-1]
		}

		qg := ql.GetQueryGroupByName(q.Group)
		if qg == nil {
			ql.QueryGroups = append(ql.QueryGroups, QueryGroup{q.Group, q.Language, []Query{q.ToQuery()}})
		} else {
			if qgq := qg.GetQueryByLevelAndName(q.Level, q.LevelID, q.Name); qgq == nil {
				qg.Queries = append(qg.Queries, q.ToQuery())
			} else {
				qgq.MergeQuery(q.ToQuery())
			}
		}
	}
}
