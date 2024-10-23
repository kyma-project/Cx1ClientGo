package Cx1ClientGo

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
		Applications:  50,
		Branches:      100,
		Groups:        100,
		Projects:      50,
		Results:       100,
		Scans:         50,
		SASTAggregate: 10000,
		Users:         100,
	}
}

func (f *BaseFilter) Bump() {
	f.Offset += f.Limit
}

func (f *BaseIAMFilter) Bump() {
	f.First += f.Max
}
