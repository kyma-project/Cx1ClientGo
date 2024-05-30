package Cx1ClientGo

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

/*
	This is separate from audit.go to split the functions that require a Web-Audit Session from those that do not.
	This file contains the generic query-related functions that do not need a valid audit session.
*/

// this struct is used specifically for the to-be-deprecated /cx-audit/queries endpoint
type AuditQuery_v312 struct {
	QueryID            uint64 `json:"Id,string"`
	Level              string
	LevelID            string `json:"-"`
	Path               string
	Modified           string
	Source             string
	Name               string
	Group              string
	Language           string `json:"lang"`
	Severity           string
	Cwe                int64
	IsExecutable       bool
	CxDescriptionId    int64
	QueryDescriptionId string
	Key                string
	Title              string
}

func (q AuditQuery_v312) ToQuery() Query {
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
		SastID:             0,
	}
}

func (c Cx1Client) GetQueryByName(level, language, group, query string) (AuditQuery, error) {
	c.depwarn("GetQueryByName", "GetAuditQueryByName")
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

	q.LevelID = level

	return q, nil
}

func (c Cx1Client) GetQueryByPath(level, path string) (AuditQuery, error) {
	c.depwarn("GetQueryByPath", "GetAuditQueryByPath")
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

	if strings.EqualFold(q.Level, AUDIT_QUERY_TENANT) || strings.EqualFold(q.Level, AUDIT_QUERY_PRODUCT) {
		q.LevelID = q.Level
	} else { // team or project-level override, so store the ID
		q.LevelID = level
	}
	return q, nil
}

func (c Cx1Client) GetQueriesByLevelID(level, levelId string) ([]Query, error) {
	c.depwarn("GetQueriesByLevelID", "GetAuditQueriesByLevelID")
	c.logger.Debugf("Get all queries for %v", level)

	var url string

	var queries_v312 []AuditQuery_v312
	var queries []Query
	switch level {
	case AUDIT_QUERY_TENANT:
		url = "/cx-audit/queries"
	case AUDIT_QUERY_PROJECT:
		url = fmt.Sprintf("/cx-audit/queries?projectId=%v", levelId)
	default:
		return queries, fmt.Errorf("invalid level %v, options are currently: Corp or Project", level)
	}

	response, err := c.sendRequest(http.MethodGet, url, nil, nil)
	if err != nil {
		return queries, err
	}

	err = json.Unmarshal(response, &queries_v312)
	if err != nil {
		return queries, err
	}

	applicationId := ""

	for id := range queries_v312 {
		switch queries_v312[id].Level {
		case AUDIT_QUERY_TENANT:
			queries_v312[id].LevelID = AUDIT_QUERY_TENANT
		case AUDIT_QUERY_PROJECT:
			queries_v312[id].LevelID = levelId
		case AUDIT_QUERY_APPLICATION:
			if applicationId == "" {
				project, err := c.GetProjectByID(levelId)
				if err != nil {
					return queries, fmt.Errorf("failed to retrieve project with ID %v", levelId)
				}
				if len(project.Applications) == 0 {
					return queries, fmt.Errorf("project %v has an application-level query defined, but has no application associated", project.String())
				} else if len(project.Applications) > 1 {
					return queries, fmt.Errorf("project %v has an application-level query defined, but has multiple application associated", project.String())
				}
				applicationId = project.Applications[0]
			}
			queries_v312[id].LevelID = applicationId
		case AUDIT_QUERY_PRODUCT:
			queries_v312[id].LevelID = AUDIT_QUERY_PRODUCT
		}

		queries = append(queries, queries_v312[id].ToQuery())
	}

	return queries, nil
}

/*
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
	c.depwarn("DeleteQueryByName", "DeleteAuditQueryByName")
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
} */

func (c Cx1Client) GetQueries() (QueryCollection, error) {
	c.depwarn("GetQueries", "GetAuditQueries")
	var qc QueryCollection
	q, err := c.GetPresetQueries()
	if err != nil {
		return qc, err
	}
	qc.AddQueries(&q)

	aq, err := c.GetQueriesByLevelID(AUDIT_QUERY_TENANT, "")
	if err != nil {
		return qc, err
	}

	qc.AddQueries(&aq)

	return qc, nil
}

func (c Cx1Client) GetPresetQueries() ([]Query, error) {
	queries := []Query{}

	response, err := c.sendRequest(http.MethodGet, "/presets/queries", nil, nil)
	if err != nil {
		return queries, err
	}

	err = json.Unmarshal(response, &queries)
	if err != nil {
		c.logger.Tracef("Failed to parse %v", string(response))
	}

	for i := range queries {
		queries[i].IsExecutable = true // all queries in the preset are executable

		if queries[i].Custom {
			queries[i].Level = AUDIT_QUERY_TENANT
			queries[i].LevelID = AUDIT_QUERY_TENANT
		} else {
			queries[i].Level = AUDIT_QUERY_PRODUCT
			queries[i].LevelID = AUDIT_QUERY_PRODUCT
		}
	}

	return queries, err
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
	return GetSeverityID(severity)
}

func GetSeverityID(severity string) uint {
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
	case "CRITICAL":
		return 4
	}
	return 0
}

func (c Cx1Client) GetSeverity(severity uint) string {
	return GetSeverity(severity)
}

func GetSeverity(severity uint) string {
	switch severity {
	case 0:
		return "Info"
	case 1:
		return "Low"
	case 2:
		return "Medium"
	case 3:
		return "High"
	case 4:
		return "Critical"
	}
	return "Unknown"
}

func (qg QueryGroup) GetQueryByName(name string) *Query {
	for id, q := range qg.Queries {
		if strings.EqualFold(q.Name, name) {
			return &qg.Queries[id]
		}
	}
	return nil
}

func (qg QueryGroup) GetQueryByID(qid uint64) *Query {
	for id, q := range qg.Queries {
		if q.QueryID == qid {
			return &qg.Queries[id]
		}
	}
	return nil
}

func (qg QueryGroup) GetQueryByLevelAndName(level, levelID, name string) *Query {
	for id, q := range qg.Queries {
		if q.Name == name && q.Level == level && q.LevelID == levelID {
			return &qg.Queries[id]
		}
	}
	return nil
}

func (qg QueryGroup) GetQueryByLevelAndID(level, levelID string, qid uint64) *Query {
	for id, q := range qg.Queries {
		if q.QueryID == qid && q.LevelID == levelID && q.Level == level {
			return &qg.Queries[id]
		}
	}
	return nil
}

func (ql QueryLanguage) GetQueryByID(qid uint64) *Query {
	for id := range ql.QueryGroups {
		if q := ql.QueryGroups[id].GetQueryByID(qid); q != nil {
			return q
		}
	}
	return nil
}
func (ql QueryLanguage) GetQueryByLevelAndID(level, levelID string, qid uint64) *Query {
	for id := range ql.QueryGroups {
		if q := ql.QueryGroups[id].GetQueryByLevelAndID(level, levelID, qid); q != nil {
			return q
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

func (qc QueryCollection) GetQueryByLevelAndName(level, levelID, language, group, query string) *Query {
	ql := qc.GetQueryLanguageByName(language)
	if ql == nil {
		return nil
	}
	qg := ql.GetQueryGroupByName(group)
	if qg == nil {
		return nil
	}
	return qg.GetQueryByLevelAndName(level, levelID, query)
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
	for id := range qc.QueryLanguages {
		if q := qc.QueryLanguages[id].GetQueryByID(qid); q != nil {
			return q
		}
	}
	return nil
}

func (qc QueryCollection) GetQueryByLevelAndID(level, levelID string, qid uint64) *Query {
	for id := range qc.QueryLanguages {
		if q := qc.QueryLanguages[id].GetQueryByLevelAndID(level, levelID, qid); q != nil {
			return q
		}
	}
	return nil
}

func (qc *QueryCollection) GetQueryCount() uint {
	var total uint = 0
	for lid := range qc.QueryLanguages {
		for gid := range qc.QueryLanguages[lid].QueryGroups {
			total += uint(len(qc.QueryLanguages[lid].QueryGroups[gid].Queries))
		}
	}
	return total
}

/*
func (qc *QueryCollection) AddAuditQueries(queries *[]AuditQuery) {
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
			if qgq := qg.GetQueryByLevelAndName(q.Level, q.Name); qgq == nil {
				qg.Queries = append(qg.Queries, q.ToQuery())
			} else {
				qgq.MergeQuery(q.ToQuery())
			}
		}
	}
}
*/

func (qc *QueryCollection) AddQuery(q Query) {
	ql := qc.GetQueryLanguageByName(q.Language)

	if ql == nil {
		qc.QueryLanguages = append(qc.QueryLanguages, QueryLanguage{q.Language, []QueryGroup{}})
		ql = &qc.QueryLanguages[len(qc.QueryLanguages)-1]
	}

	qg := ql.GetQueryGroupByName(q.Group)
	if qg == nil {
		ql.QueryGroups = append(ql.QueryGroups, QueryGroup{q.Group, q.Language, []Query{q}})
	} else {
		var qgq *Query = nil
		if q.QueryID == 0 {
			tq := qg.GetQueryByName(q.Name)
			if tq != nil {
				q.QueryID = tq.QueryID
			}
		}
		if q.QueryID != 0 {
			qgq = qg.GetQueryByLevelAndID(q.Level, q.LevelID, q.QueryID)
		}
		if qgq == nil {
			qgq = qg.GetQueryByLevelAndName(q.Level, q.LevelID, q.Name)
		}

		if qgq == nil {
			qg.Queries = append(qg.Queries, q)
		} else {
			qgq.MergeQuery(q)
		}
	}
}

func (qc *QueryCollection) UpdateNewQuery(query *Query) error {
	ql := qc.GetQueryLanguageByName(query.Language)
	if ql == nil {
		return fmt.Errorf("query language '%v' is not included in this query collection, refresh the collection", query.Language)
	}
	qg := ql.GetQueryGroupByName(query.Group)
	if qg == nil {
		return fmt.Errorf("query group '%v' is not included in this query collection, refresh the collection", query.Group)
	}
	qgq := qg.GetQueryByLevelAndName(query.Level, query.LevelID, query.Name)
	if qgq != nil {
		query.MergeQuery(*qgq)
		return nil
	}

	qgq = qg.GetQueryByLevelAndName(AUDIT_QUERY_TENANT, AUDIT_QUERY_TENANT, query.Name)
	if qgq != nil {
		query.MergeQuery(*qgq)
		return nil
	}

	qgq = qg.GetQueryByLevelAndName(AUDIT_QUERY_PRODUCT, AUDIT_QUERY_PRODUCT, query.Name)
	if qgq != nil {
		query.MergeQuery(*qgq)
		return nil
	}

	return fmt.Errorf("query '%v' inherits from an unknown query, refresh the collection", query.Name)
}

func (qc *QueryCollection) AddQueries(queries *[]Query) {
	for _, q := range *queries {
		qc.AddQuery(q)
	}
}

func (qc *QueryCollection) GetCustomQueryCollection() QueryCollection {
	var cqc QueryCollection

	for _, ql := range qc.QueryLanguages {
		for _, qg := range ql.QueryGroups {
			for _, qq := range qg.Queries {
				if qq.Custom {
					cqc.AddQuery(qq)
				}
			}
		}
	}

	return cqc
}

func (q *Query) MergeQuery(nq Query) {
	if q.QueryID == 0 && nq.QueryID != 0 {
		q.QueryID = nq.QueryID
	}
	if q.Path == "" && nq.Path != "" {
		q.Path = nq.Path
	}
	if q.EditorKey == "" && nq.EditorKey != "" {
		q.EditorKey = nq.EditorKey
	}
	if q.Level == "" && nq.Level != "" {
		q.Level = nq.Level
	}
	if q.LevelID == "" && nq.LevelID != "" {
		q.LevelID = nq.LevelID
	}
}

func (q Query) StringDetailed() string {
	switch q.Level {
	case AUDIT_QUERY_PRODUCT:
		return fmt.Sprintf("Cx: %v -> %v -> %v [ID %v, Key %v]", q.Language, q.Group, q.Name, q.QueryID, q.EditorKey)
	case AUDIT_QUERY_TENANT:
		return fmt.Sprintf("Tenant: %v -> %v -> %v [ID %v, Key %v]", q.Language, q.Group, q.Name, q.QueryID, q.EditorKey)
	}
	return fmt.Sprintf("%v %v: %v -> %v -> %v [ID %v, Key %v]", q.Level, ShortenGUID(q.LevelID), q.Language, q.Group, q.Name, q.QueryID, q.EditorKey)
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
