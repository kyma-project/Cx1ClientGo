package Cx1ClientGo

import (
	"fmt"
	"strings"

	"github.com/sirupsen/logrus"
)

func (c Cx1Client) GetSASTQueryCollection() (SASTQueryCollection, error) {
	var qc SASTQueryCollection
	q, err := c.GetPresetQueries()
	if err != nil {
		return qc, err
	}
	qc.AddQueries(&q)

	aq, err := c.GetQueriesByLevelID(c.QueryTypeTenant(), c.QueryTypeTenant())
	if err != nil {
		return qc, err
	}

	qc.AddQueries(&aq)

	return qc, nil
}

func (qg SASTQueryGroup) GetQueryByName(name string) *SASTQuery {
	for id, q := range qg.Queries {
		if strings.EqualFold(q.Name, name) {
			return &qg.Queries[id]
		}
	}
	return nil
}

func (qg SASTQueryGroup) GetQueryByID(qid uint64) *SASTQuery {
	for id, q := range qg.Queries {
		if q.QueryID == qid {
			return &qg.Queries[id]
		}
	}
	return nil
}

func (qg SASTQueryGroup) GetQueryByLevelAndName(level, levelID, name string) *SASTQuery {
	for id, q := range qg.Queries {
		if q.Name == name && q.Level == level && q.LevelID == levelID {
			return &qg.Queries[id]
		}
	}
	return nil
}

func (qg SASTQueryGroup) GetQueryByLevelAndID(level, levelID string, qid uint64) *SASTQuery {
	if qid == 0 {
		return nil
	}

	for id, q := range qg.Queries {
		if q.QueryID == qid && q.LevelID == levelID && q.Level == level {
			return &qg.Queries[id]
		}
	}
	return nil
}

func (qg SASTQueryGroup) findQuery(level, levelID, name string, qid uint64) *SASTQuery {
	var qgq *SASTQuery = nil

	if qid == 0 {
		qgq = qg.GetQueryByLevelAndID(level, levelID, qid)
	} else {
		qgq = qg.GetQueryByLevelAndID(level, levelID, qid)
	}

	if qgq == nil {
		qgq = qg.GetQueryByName(name)
	}

	return qgq
}

func (ql SASTQueryLanguage) GetQueryByID(qid uint64) *SASTQuery {
	for id := range ql.QueryGroups {
		if q := ql.QueryGroups[id].GetQueryByID(qid); q != nil {
			return q
		}
	}
	return nil
}
func (ql SASTQueryLanguage) GetQueryByLevelAndID(level, levelID string, qid uint64) *SASTQuery {
	for id := range ql.QueryGroups {
		if q := ql.QueryGroups[id].GetQueryByLevelAndID(level, levelID, qid); q != nil {
			return q
		}
	}
	return nil
}
func (ql SASTQueryLanguage) GetQueryGroupByName(name string) *SASTQueryGroup {
	for id, qg := range ql.QueryGroups {
		if strings.EqualFold(qg.Name, name) {
			return &ql.QueryGroups[id]
		}
	}
	return nil
}
func (qc SASTQueryCollection) GetQueryLanguageByName(language string) *SASTQueryLanguage {
	for id, ql := range qc.QueryLanguages {
		if strings.EqualFold(ql.Name, language) {
			return &qc.QueryLanguages[id]
		}
	}
	return nil
}

func (qc SASTQueryCollection) GetQueryByLevelAndName(level, levelID, language, group, query string) *SASTQuery {
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

func (qc SASTQueryCollection) GetQueryByName(language, group, query string) *SASTQuery {
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

func (qc SASTQueryCollection) GetQueryByID(qid uint64) *SASTQuery {
	if qid == 0 {
		return nil
	}

	for id := range qc.QueryLanguages {
		if q := qc.QueryLanguages[id].GetQueryByID(qid); q != nil {
			return q
		}
	}
	return nil
}

func (qc SASTQueryCollection) GetQueryByLevelAndID(level, levelID string, qid uint64) *SASTQuery {
	if qid == 0 {
		return nil
	}

	for id := range qc.QueryLanguages {
		if q := qc.QueryLanguages[id].GetQueryByLevelAndID(level, levelID, qid); q != nil {
			return q
		}
	}
	return nil
}

func (qc *SASTQueryCollection) GetQueryCount() uint {
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

func (qc *SASTQueryCollection) AddQuery(q SASTQuery) {
	ql := qc.GetQueryLanguageByName(q.Language)

	if ql == nil {
		qc.QueryLanguages = append(qc.QueryLanguages, SASTQueryLanguage{q.Language, []SASTQueryGroup{}})
		ql = &qc.QueryLanguages[len(qc.QueryLanguages)-1]
	}
	qg := ql.GetQueryGroupByName(q.Group)
	if qg == nil {
		ql.QueryGroups = append(ql.QueryGroups, SASTQueryGroup{q.Group, q.Language, []SASTQuery{q}})
	} else {
		qgq := qg.findQuery(q.Level, q.LevelID, q.Name, q.QueryID)
		if qgq == nil {
			qg.Queries = append(qg.Queries, q)
		} else {
			qgq.MergeQuery(q)
		}
	}
}

/*
This function may not be necessary in the future, it is used to fill in missing fields when creating new queries
*/
func (qc *SASTQueryCollection) UpdateNewQuery(query *SASTQuery) error {
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

func (qc *SASTQueryCollection) AddQueries(queries *[]SASTQuery) {
	for _, q := range *queries {
		qc.AddQuery(q)
	}
}

func (qc *SASTQueryCollection) AddQueryTree(t *[]AuditQueryTree) {
	queries := treeToSASTQueries(t)
	for _, q := range queries {
		qc.AddQuery(q)
	}
}

func (qc *SASTQueryCollection) GetCustomQueryCollection() SASTQueryCollection {
	var cqc SASTQueryCollection

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

func (qc SASTQueryCollection) GetQueries() []SASTQuery {
	queries := []SASTQuery{}

	for lid := range qc.QueryLanguages {
		for gid := range qc.QueryLanguages[lid].QueryGroups {
			queries = append(queries, qc.QueryLanguages[lid].QueryGroups[gid].Queries...)
		}
	}

	return queries
}

func (c Cx1Client) QueryGroupLink(q *SASTQueryGroup) string {
	return fmt.Sprintf("%v/audit/?language=%v&group=%v", c.baseUrl, q.Language, q.Name)
}

func (c Cx1Client) QueryLanguageLink(q *SASTQueryLanguage) string {
	return fmt.Sprintf("%v/audit/?language=%v", c.baseUrl, q.Name)
}

func (q SASTQueryGroup) String() string {
	return fmt.Sprintf("%v -> %v", q.Language, q.Name)
}
func (q SASTQueryLanguage) String() string {
	return q.Name
}

// convenience functions for debugging
func (qg SASTQueryGroup) Print(logger *logrus.Logger) {
	logger.Infof("Language %v group: %v", qg.Language, qg.Name)
	for _, q := range qg.Queries {
		logger.Infof(" - %v", q.String())
	}
}
func (ql SASTQueryLanguage) Print(logger *logrus.Logger) {
	logger.Infof("Language: %v", ql.Name)
	for _, g := range ql.QueryGroups {
		g.Print(logger)
	}
}

func (qc *SASTQueryCollection) Print(logger *logrus.Logger) {
	logger.Infof("Printing query collection")
	for _, l := range qc.QueryLanguages {
		l.Print(logger)
	}
}
