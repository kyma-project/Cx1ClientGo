package Cx1ClientGo

import (
	"net/url"

	"github.com/google/go-querystring/query"
)

// miscellaneous functions (ClientVars & Pagination)

func (c Cx1Client) GetClientVars() ClientVars {
	return c.consts
}

func (c *Cx1Client) SetClientVars(clientvars ClientVars) {
	c.consts = clientvars
}

func (c *Cx1Client) InitializeClientVars() {
	c.consts = ClientVars{
		MigrationPollingMaxSeconds:                300, // 5 min
		MigrationPollingDelaySeconds:              30,
		AuditEnginePollingMaxSeconds:              300,
		AuditEnginePollingDelaySeconds:            30,
		AuditScanPollingMaxSeconds:                600,
		AuditScanPollingDelaySeconds:              30,
		AuditCompilePollingMaxSeconds:             600,
		AuditCompilePollingDelaySeconds:           30,
		AuditLanguagePollingMaxSeconds:            300,
		AuditLanguagePollingDelaySeconds:          30,
		ScanPollingMaxSeconds:                     0,
		ScanPollingDelaySeconds:                   30,
		ProjectApplicationLinkPollingMaxSeconds:   300,
		ProjectApplicationLinkPollingDelaySeconds: 15,
	}
}

func (c Cx1Client) GetPaginationSettings() PaginationSettings {
	c.logger.Debug("Retrieving client vars - polling limits set in seconds")
	return c.pagination
}

func (c *Cx1Client) SetPaginationSettings(pagination PaginationSettings) {
	c.pagination = pagination
}

func (c *Cx1Client) InitializePaginationSettings() {
	c.pagination = PaginationSettings{
		Applications: 20,
		Branches:     20,
		Groups:       50,
		Projects:     20,
		Results:      20,
		Scans:        20,
		Users:        50,
	}
}

func (f *BaseFilter) Bump() {
	f.Offset += f.Limit
}

func (f BaseFilter) UrlParams() url.Values {
	params, _ := query.Values(f)
	return params
}

func (f *BaseIAMFilter) Bump() {
	f.First += f.Max
}

func (f BaseIAMFilter) UrlParams() url.Values {
	params, _ := query.Values(f)
	return params
}
