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

func (c Cx1Client) GetQueryByID(qid uint64) (Query, error) {
	return Query{}, fmt.Errorf("this API call no longer exists")
	/*
		var q Query
		// Note: this list includes API Key/service account users from Cx1, remove the /admin/ for regular users only.
		response, err := c.sendRequest(http.MethodGet, fmt.Sprintf("/queries/%d", qid), nil, nil)
		if err != nil {
			return q, err
		}
		err = json.Unmarshal(response, &q)
		if err != nil {
			c.logger.Tracef("Failed to parse %v", string(response))
		}
		return q, err*/
}

func (c Cx1Client) GetQueryByName(level, language, group, query string) (AuditQuery, error) {
	c.logger.Debugf("Get %v query by name: %v -> %v -> %v", level, language, group, query)
	path := fmt.Sprintf("queries%%2F%v%%2F%v%%2F%v%%2F%v", language, group, query, query)

	response, err := c.sendRequest(http.MethodGet, fmt.Sprintf("/cx-audit/queries/%v/%v.cs", level, path), nil, nil)
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

func (c Cx1Client) GetQueryByPath(level, path string) (AuditQuery, error) {
	c.logger.Debugf("Get %v query by path: %v", level, path)

	response, err := c.sendRequest(http.MethodGet, fmt.Sprintf("/cx-audit/queries/%v/%v", level, strings.Replace(path, "/", "%2f", -1)), nil, nil)
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

func (c Cx1Client) GetQueriesByLevelID(level, levelId string) ([]AuditQuery, error) {
	c.logger.Debugf("Get all queries for %v", level)

	var url string
	var queries []AuditQuery
	switch level {
	case "Corp":
		url = "/cx-audit/queries"
	case "Project":
		url = fmt.Sprintf("/cx-audit/queries?projectId=%v", levelId)
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

func FindQueryByName(queries []AuditQuery, level, language, group, name string) (AuditQuery, error) {
	for _, q := range queries {
		if q.Level == level && q.Language == language && q.Group == group && q.Name == name {
			return q, nil
		}
	}

	return AuditQuery{}, fmt.Errorf("no query found matching [%v] %v -> %v -> %v", level, language, group, name)
}

func (c Cx1Client) DeleteQuery(query AuditQuery) error {
	return c.DeleteQueryByName(query.Level, query.LevelID, query.Language, query.Group, query.Name)
}

func (c Cx1Client) DeleteQueryByName(level, levelID, language, group, query string) error {
	c.logger.Debugf("Delete %v query by name: %v -> %v -> %v", level, language, group, query)
	path := fmt.Sprintf("queries%%2F%v%%2F%v%%2F%v%%2F%v", language, group, query, query)

	_, err := c.sendRequest(http.MethodDelete, fmt.Sprintf("/cx-audit/queries/%v/%v.cs", levelID, path), nil, nil)
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

/*

	WebAudit use cases:
		1. Create new Corp/Tenant-level query with no existing Cx (product default) query: AuditNewQuery function + AuditCreateCorpQuery (POST to /cx-audit/queries/:session)
		2. Create new Corp/Tenant-level over an existing Cx (product default) query: UpdateQuery function (PUT to /cx-audit/queries/Corp)
		3. Create new override on Project or Application level, where a Corp/Tenant or Cx-level base query already exists: UpdateQuery function (PUT to /cx-audit/queries/ProjectID or AppID)
		4. Update an existing override on Corp/Tenant, Project, or Application level: UpdateQuery function (PUT to /cx-audit/queries/:level

	Note: Application-level queries are not yet implemented in Cx1.

*/

func (c Cx1Client) AuditNewQuery(language, group, name string) (AuditQuery, error) {
	newQuery, err := c.GetQueryByName("Corp", language, "CxDefaultQueryGroup", "CxDefaultQuery")
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
func (c Cx1Client) UpdateQuery(query AuditQuery) error { // level = projectId or "Corp"
	c.logger.Debugf("Saving query %v on level %v", query.Path, query.Level)

	q := QueryUpdate{
		Name:   query.Name,
		Path:   query.Path,
		Source: query.Source,
		Metadata: QueryUpdateMetadata{
			Severity: query.Severity,
		},
	}

	return c.UpdateQueries(query.LevelID, []QueryUpdate{q})
}

func (c Cx1Client) UpdateQueries(level string, queries []QueryUpdate) error {
	c.depwarn("UpdateQuery/UpdateQueries", "AuditUpdateQuery/AuditUpdateQueries")
	jsonBody, _ := json.Marshal(queries)
	response, err := c.sendRequest(http.MethodPut, fmt.Sprintf("/cx-audit/queries/%v", level), bytes.NewReader(jsonBody), nil)
	if err != nil {
		if err.Error()[0:8] == "HTTP 405" {
			return fmt.Errorf("this endpoint is no longer available - please use AuditUpdateQuery/AuditUpdateQueries instead")
		} else {
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

func (c Cx1Client) GetQueries() (QueryCollection, error) {
	c.logger.Debug("Get Cx1 Queries Collection")
	var qc QueryCollection

	response, err := c.sendRequest(http.MethodGet, "/presets/queries", nil, nil)
	if err != nil {
		return qc, err
	}

	queries := []Query{}

	err = json.Unmarshal(response, &queries)
	if err != nil {
		c.logger.Tracef("Failed to parse %v", string(response))
	}

	for _, q := range queries {
		ql := qc.GetQueryLanguageByName(q.Language)

		if ql == nil {
			qc.QueryLanguages = append(qc.QueryLanguages, QueryLanguage{q.Language, []QueryGroup{}})
			ql = &qc.QueryLanguages[len(qc.QueryLanguages)-1]
		}

		qg := ql.GetQueryGroupByName(q.Group)
		if qg == nil {
			ql.QueryGroups = append(ql.QueryGroups, QueryGroup{q.Group, q.Language, []Query{q}})
		} else {
			qg.Queries = append(qg.Queries, q)
		}
	}

	return qc, err
}

func (c Cx1Client) GetQueryMappings() (map[uint64]uint64, error) {
	var mapping map[uint64]uint64 = make(map[uint64]uint64)
	var responsemap struct {
		Mappings []struct {
			AstId  uint64 `json:"astId,string"`
			SastId uint64 `json:"sastId,string"`
		} `json:"mappings"`
	}

	response, err := c.sendRequest(http.MethodGet, "/queries/mappings", nil, nil)
	if err != nil {
		return mapping, err
	}

	err = json.Unmarshal(response, &responsemap)
	if err != nil {
		return mapping, err
	}

	for _, qm := range responsemap.Mappings {
		mapping[qm.SastId] = qm.AstId
	}

	return mapping, nil

}

// convenience
func (c Cx1Client) GetSeverityID(severity string) uint {
	switch strings.ToUpper(severity) {
	case "INFO":
		return 0
	case "INFORMATION":
		return 0
	case "LOW":
		return 1
	case "MEDIUM":
		return 2
	case "HIGH":
		return 3
	}
	return 0
}

func (qg QueryGroup) GetQueryByName(name string) *Query {
	for id, q := range qg.Queries {
		if strings.EqualFold(q.Name, name) {
			return &qg.Queries[id]
		}
	}
	return nil
}

func (ql QueryLanguage) GetQueryGroupByName(name string) *QueryGroup {
	for id, qg := range ql.QueryGroups {
		if strings.EqualFold(qg.Name, name) {
			return &ql.QueryGroups[id]
		}
	}
	return nil
}
func (qc QueryCollection) GetQueryLanguageByName(language string) *QueryLanguage {
	for id, ql := range qc.QueryLanguages {
		if strings.EqualFold(ql.Name, language) {
			return &qc.QueryLanguages[id]
		}
	}
	return nil
}
func (qc QueryCollection) GetQueryByName(language, group, query string) *Query {
	ql := qc.GetQueryLanguageByName(language)
	if ql == nil {
		return nil
	}
	qg := ql.GetQueryGroupByName(group)
	if qg == nil {
		return nil
	}
	return qg.GetQueryByName(query)
}

func (qc QueryCollection) GetQueryByID(qid uint64) *Query {
	for _, ql := range qc.QueryLanguages {
		for _, qg := range ql.QueryGroups {
			for id, q := range qg.Queries {
				if q.QueryID == qid {
					return &qg.Queries[id]
				}
			}
		}
	}
	return nil
}
func (q Query) String() string {
	return fmt.Sprintf("[%d] %v -> %v -> %v", q.QueryID, q.Language, q.Group, q.Name)
}
func (q QueryGroup) String() string {
	return fmt.Sprintf("%v -> %v", q.Language, q.Name)
}
func (q QueryLanguage) String() string {
	return q.Name
}

func (c Cx1Client) QueryLink(q *Query) string {
	return fmt.Sprintf("%v/audit/?queryid=%d", c.baseUrl, q.QueryID)
}

func (c Cx1Client) QueryGroupLink(q *QueryGroup) string {
	return fmt.Sprintf("%v/audit/?language=%v&group=%v", c.baseUrl, q.Language, q.Name)
}

func (c Cx1Client) QueryLanguageLink(q *QueryLanguage) string {
	return fmt.Sprintf("%v/audit/?language=%v", c.baseUrl, q.Name)
}
