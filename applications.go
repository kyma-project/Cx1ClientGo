package Cx1ClientGo

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// Get the first count Applications
// uses the pagination behind the scenes
func (c Cx1Client) GetApplications(count uint64) ([]Application, error) {
	c.logger.Debug("Get Cx1 Applications")

	_, applications, err := c.GetXApplicationsFiltered(ApplicationFilter{
		BaseFilter: BaseFilter{Limit: c.pagination.Applications},
	}, count)

	return applications, err
}

func (c Cx1Client) GetAllApplications() ([]Application, error) {
	c.logger.Debug("Get Cx1 Applications")

	_, applications, err := c.GetAllApplicationsFiltered(ApplicationFilter{
		BaseFilter: BaseFilter{Limit: c.pagination.Applications},
	})

	return applications, err
}

func (c Cx1Client) GetApplicationByID(id string) (Application, error) {
	c.logger.Debugf("Get Cx1 Applications by id: %v", id)
	var application Application
	response, err := c.sendRequest(http.MethodGet, fmt.Sprintf("/applications/%v", id), nil, nil)
	if err != nil {
		return application, err
	}

	err = json.Unmarshal(response, &application)
	return application, err
}

// Get all applications matching 'name'
// As of 2024-10-17, this function no longer takes a specific limit as a parameter
// To set limits, offsets, and other parameters directly, use GetApplicationsFiltered
func (c Cx1Client) GetApplicationsByName(name string) ([]Application, error) {
	c.logger.Debugf("Get Cx1 Applications by name: %v", name)

	_, applications, err := c.GetAllApplicationsFiltered(ApplicationFilter{
		BaseFilter: BaseFilter{Limit: c.pagination.Applications},
		Name:       name,
	})

	return applications, err
}

// returns the application matching exactly (case sensitive) the name
func (c Cx1Client) GetApplicationByName(name string) (Application, error) {
	apps, err := c.GetApplicationsByName(name)
	if err != nil {
		return Application{}, err
	}

	for _, a := range apps {
		if a.Name == name {
			return a, nil
		}
	}

	return Application{}, fmt.Errorf("no application found named %v", name)
}

// Underlying function used by many GetApplications* calls
// Returns the number of applications matching the filter and the array of matching applications
// with one page (filter.Offset to filter.Offset+filter.Limit) of results
func (c Cx1Client) GetApplicationsFiltered(filter ApplicationFilter) (uint64, []Application, error) {
	params := filter.UrlParams()

	var ApplicationResponse struct {
		BaseFilteredResponse
		Applications []Application
	}

	response, err := c.sendRequest(http.MethodGet, fmt.Sprintf("/applications?%v", params.Encode()), nil, nil)

	if err != nil {
		return ApplicationResponse.FilteredTotalCount, ApplicationResponse.Applications, err
	}

	err = json.Unmarshal(response, &ApplicationResponse)
	return ApplicationResponse.FilteredTotalCount, ApplicationResponse.Applications, err
}

// retrieves all applications matching the filter
// using pagination set via filter.Limit or Get/SetPaginationSettings
func (c Cx1Client) GetAllApplicationsFiltered(filter ApplicationFilter) (uint64, []Application, error) {
	var applications []Application

	count, err := c.GetApplicationCountFiltered(filter)
	if err != nil {
		return count, applications, err
	}

	return c.GetXApplicationsFiltered(filter, count)
}

// retrieves the first X applications matching the filter
// using pagination set via filter.Limit or Get/SetPaginationSettings
func (c Cx1Client) GetXApplicationsFiltered(filter ApplicationFilter, count uint64) (uint64, []Application, error) {
	var applications []Application

	_, apps, err := c.GetApplicationsFiltered(filter)
	applications = apps

	for err == nil && count > filter.Offset+filter.Limit && filter.Limit > 0 && uint64(len(applications)) < count {
		filter.Bump()
		_, apps, err = c.GetApplicationsFiltered(filter)
		applications = append(applications, apps...)
	}

	if uint64(len(applications)) > count {
		return count, applications[:count], err
	}

	return count, applications, err
}

func (c Cx1Client) CreateApplication(appname string) (Application, error) {
	c.logger.Debugf("Create Application: %v", appname)
	data := map[string]interface{}{
		"name":        appname,
		"description": "",
		"criticality": 3,
		"rules":       []ApplicationRule{},
		"tags":        map[string]string{},
	}

	var app Application

	jsonBody, err := json.Marshal(data)
	if err != nil {
		return app, err
	}

	response, err := c.sendRequest(http.MethodPost, "/applications", bytes.NewReader(jsonBody), nil)
	if err != nil {
		c.logger.Tracef("Error while creating application: %s", err)
		return app, err
	}

	err = json.Unmarshal(response, &app)

	return app, err
}

func (c Cx1Client) DeleteApplication(application *Application) error {
	return c.DeleteApplicationByID(application.ApplicationID)
}
func (c Cx1Client) DeleteApplicationByID(applicationId string) error {
	c.logger.Debugf("Delete Application: %v", applicationId)

	_, err := c.sendRequest(http.MethodDelete, fmt.Sprintf("/applications/%v", applicationId), nil, nil)
	if err != nil {
		c.logger.Tracef("Error while deleting application: %s", err)
		return err
	}

	return nil
}

// convenience
func (c Cx1Client) GetApplicationCount() (uint64, error) {
	c.logger.Debug("Get Cx1 Project count")

	count, _, err := c.GetApplicationsFiltered(ApplicationFilter{
		BaseFilter: BaseFilter{Limit: 1},
	})

	return count, err
}

func (c Cx1Client) GetApplicationCountByName(name string) (uint64, error) {
	c.logger.Debugf("Get Cx1 Application count by name: %v", name)

	count, _, err := c.GetApplicationsFiltered(ApplicationFilter{
		BaseFilter: BaseFilter{Limit: 1},
		Name:       name,
	})

	return count, err
}

func (c Cx1Client) GetApplicationCountFiltered(filter ApplicationFilter) (uint64, error) {
	filter.Limit = 1
	c.logger.Debugf("Get Cx1 Application count matching filter: %v", filter.UrlParams().Encode())

	count, _, err := c.GetApplicationsFiltered(filter)

	return count, err
}

func (a *Application) String() string {
	return fmt.Sprintf("[%v] %v", ShortenGUID(a.ApplicationID), a.Name)
}

func (c Cx1Client) GetOrCreateApplicationByName(name string) (Application, error) {
	app, err := c.GetApplicationByName(name)
	if err == nil {
		return app, nil
	}

	return c.CreateApplication(name)
}

func (c Cx1Client) UpdateApplication(app *Application) error {
	c.logger.Debugf("Update application: %v", app.String())
	jsonBody, err := json.Marshal(*app)
	if err != nil {
		return err
	}

	_, err = c.sendRequest(http.MethodPut, fmt.Sprintf("/applications/%v", app.ApplicationID), bytes.NewReader(jsonBody), nil)
	if err != nil {
		c.logger.Tracef("Error while updating application: %s", err)
		return err
	}

	return nil
}

func (a *Application) GetRuleByType(ruletype string) *ApplicationRule {
	for id := range a.Rules {
		if a.Rules[id].Type == ruletype {
			return &(a.Rules[id])
		}
	}
	return nil
}

func (a *Application) AddRule(ruletype, value string) {
	rule := a.GetRuleByType(ruletype)
	if rule == nil {
		var newrule ApplicationRule
		newrule.Type = ruletype
		newrule.Value = value
		a.Rules = append(a.Rules, newrule)
	} else {
		if rule.Value == value || strings.Contains(fmt.Sprintf(";%v;", rule.Value), fmt.Sprintf(";%v;", value)) {
			return // rule value already contains this value
		}
		rule.Value = fmt.Sprintf("%v;%v", rule.Value, value)
	}
}

func (a *Application) RemoveRule(rule *ApplicationRule) {
	for i := 0; i < len(a.Rules); i++ {
		if rule == &a.Rules[i] {
			a.Rules = append(a.Rules[:i], a.Rules[i+1:]...)
			return
		}
	}
}

// AssignProject will create or update a "project.name.in" type rule to assign the project to the app
func (a *Application) AssignProject(project *Project) {
	a.AddRule("project.name.in", project.Name)
}

// UnassignProject will remove the project from the "project.name.in" rule if it's there, and if the rule ends up empty it will remove the rule
func (a *Application) UnassignProject(project *Project) {
	rule := a.GetRuleByType("project.name.in")
	if rule == nil {
		return
	}

	rule.RemoveItem(project.Name)
	if rule.Value == "" {
		a.RemoveRule(rule)
	}
}

func (ar *ApplicationRule) RemoveItem(item string) {
	rulestr := ";" + ar.Value + ";"
	itemstr := ";" + item + ";"
	if strings.Contains(rulestr, item) {
		rulestr = strings.Replace(rulestr, itemstr, ";", 1)
		rulestr = rulestr[1:] // chop out starting ;
		if len(rulestr) > 0 {
			rulestr = rulestr[:len(rulestr)-1]
		}
	}
	ar.Value = rulestr
}
