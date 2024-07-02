package Cx1ClientGo

import (
	"fmt"
	"strings"
)

/*
	This is separate from queries.go to split the functions that require a Web-Audit Session from those that do not.
	This file contains the query-related functions that require an audit session (compiling queries, updating queries, creating overrides)
*/

type AuditQuery_v310 struct {
	QueryID            uint64 `json:"Id,string"`
	Level              string
	LevelID            string `json:"-"`
	Path               string
	Modified           string
	Source             string
	Name               string
	Group              string
	Language           string `json:"lang"`
	Severity           uint
	Cwe                int64
	IsExecutable       bool
	CxDescriptionId    int64
	QueryDescriptionId string
	Key                string
	Title              string
}

func (q *AuditQuery_v310) ParsePath() {
	s := strings.Split(q.Path, "/")
	q.Language = s[1]
	q.Group = s[2]
	q.Name = s[3]
}

func (q Query) ToAuditQuery_v310() AuditQuery_v310 {
	return AuditQuery_v310{
		QueryID:            q.QueryID,
		Level:              q.Level,
		LevelID:            q.LevelID,
		Path:               q.Path,
		Modified:           q.Modified,
		Source:             q.Source,
		Name:               q.Name,
		Group:              q.Group,
		Language:           q.Language,
		Severity:           GetSeverityID(q.Severity),
		Cwe:                q.CweID,
		IsExecutable:       q.IsExecutable,
		CxDescriptionId:    q.GetMetadata().CxDescriptionID,
		QueryDescriptionId: "",
		Key:                q.EditorKey,
		Title:              q.Name,
	}
}

func (q AuditQuery_v310) String() string {
	return fmt.Sprintf("[%d] %v: %v", q.QueryID, q.Level, q.Path)
}

func (q AuditQuery_v310) ToQuery() Query {
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
		Severity:           GetSeverity(q.Severity),
		CweID:              q.Cwe,
		IsExecutable:       q.IsExecutable,
		QueryDescriptionId: q.CxDescriptionId,
		Custom:             q.Level != AUDIT_QUERY_PRODUCT,
		EditorKey:          q.Key,
		SastID:             0,
	}
}

func (q AuditQuery_v310) CreateTenantOverride() AuditQuery_v310 {
	new_query := q
	new_query.Level = "Corp"
	new_query.LevelID = "Corp"
	return new_query
}
func (q AuditQuery_v310) CreateProjectOverrideByID(projectId string) AuditQuery_v310 {
	new_query := q
	new_query.Level = "Project"
	new_query.LevelID = projectId
	return new_query
}
func (q AuditQuery_v310) CreateApplicationOverrideByID(applicationId string) AuditQuery_v310 {
	new_query := q
	new_query.Level = "Team"
	new_query.LevelID = applicationId
	return new_query
}
