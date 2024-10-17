package Cx1ClientGo

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"golang.org/x/exp/slices"
)

// Projects
func (c Cx1Client) CreateProject(projectname string, cx1_group_ids []string, tags map[string]string) (Project, error) {
	c.logger.Debugf("Create Project: %v", projectname)
	data := map[string]interface{}{
		"name":        projectname,
		"groups":      []string{},
		"tags":        map[string]string{},
		"criticality": 3,
		"origin":      cxOrigin,
	}

	if len(tags) > 0 {
		data["tags"] = tags
	}
	if len(cx1_group_ids) > 0 {
		data["groups"] = cx1_group_ids
	}

	jsonBody, err := json.Marshal(data)
	if err != nil {
		return Project{}, err
	}

	var project Project
	response, err := c.sendRequest(http.MethodPost, "/projects", bytes.NewReader(jsonBody), nil)
	if err != nil {
		c.logger.Tracef("Error while creating project %v: %s", projectname, err)
		return project, err
	}

	err = json.Unmarshal(response, &project)

	return project, err
}

func (c Cx1Client) CreateProjectInApplication(projectname string, cx1_group_ids []string, tags map[string]string, applicationId string) (Project, error) {
	c.logger.Debugf("Create Project %v in applicationId %v", projectname, applicationId)
	data := map[string]interface{}{
		"name":        projectname,
		"groups":      []string{},
		"tags":        map[string]string{},
		"criticality": 3,
		"origin":      cxOrigin,
	}

	if len(tags) > 0 {
		data["tags"] = tags
	}
	if len(cx1_group_ids) > 0 {
		data["groups"] = cx1_group_ids
	}

	jsonBody, err := json.Marshal(data)
	if err != nil {
		return Project{}, err
	}

	var project Project
	var response []byte
	if c.version.CheckCxOne("3.16.0") >= 0 {
		data["applicationIds"] = []string{applicationId}
		jsonBody, err = json.Marshal(data)
		if err != nil {
			return Project{}, err
		}
		response, err = c.sendRequest(http.MethodPost, "/projects", bytes.NewReader(jsonBody), nil)
	} else {
		response, err = c.sendRequest(http.MethodPost, fmt.Sprintf("/projects/application/%v", applicationId), bytes.NewReader(jsonBody), nil)

		if err != nil && err.Error()[0:8] == "HTTP 404" { // At some point, the api /projects/applications will be removed and instead the normal /projects API will do the job.
			data["applicationIds"] = []string{applicationId}
			jsonBody, err = json.Marshal(data)
			if err != nil {
				return Project{}, err
			}
			response, err = c.sendRequest(http.MethodPost, "/projects", bytes.NewReader(jsonBody), nil)
		}
	}

	if err != nil {
		c.logger.Tracef("Error while creating project %v: %s", projectname, err)
		return project, err
	}

	err = json.Unmarshal(response, &project)
	if err != nil {
		return Project{}, err
	}

	return c.ProjectInApplicationPollingByID(project.ProjectID, applicationId)
}

func (c Cx1Client) ProjectInApplicationPollingByID(projectId, applicationId string) (Project, error) {
	return c.ProjectInApplicationPollingByIDWithTimeout(projectId, applicationId, c.consts.ProjectApplicationLinkPollingDelaySeconds, c.consts.ProjectApplicationLinkPollingMaxSeconds)
}

func (c Cx1Client) ProjectInApplicationPollingByIDWithTimeout(projectId, applicationId string, delaySeconds, maxSeconds int) (Project, error) {
	project, err := c.GetProjectByID(projectId)
	pollingCounter := 0
	for err != nil || !slices.Contains(project.Applications, applicationId) {
		if pollingCounter > maxSeconds {
			return project, fmt.Errorf("project %v is not assigned to application ID %v after %d seconds, aborting", projectId, applicationId, maxSeconds)
		}
		c.logger.Debugf("Project is not yet assigned to the application, polling")
		time.Sleep(time.Duration(delaySeconds) * time.Second)
		project, err = c.GetProjectByID(projectId)
		pollingCounter += delaySeconds
	}
	return project, nil
}

func (p *Project) String() string {
	return fmt.Sprintf("[%v] %v", ShortenGUID(p.ProjectID), p.Name)
}

func (p *Project) GetTags() string {
	str := ""
	for key, val := range p.Tags {
		if str == "" {
			str = key + " = " + val
		} else {
			str = str + ", " + key + " = " + val
		}
	}
	return str
}

// Get all projects
// As of 2024-10-17 this function no longer takes a specific limit as a parameter
// To set limits, offsets, and other parameters directly, use GetProjectsFiltered
func (c Cx1Client) GetProjects() ([]Project, error) {
	c.logger.Debug("Get Cx1 Projects")
	_, projects, err := c.GetAllProjectsFiltered(ProjectFilter{
		BaseFilter: BaseFilter{Limit: c.pagination.Projects},
	})

	return projects, err
}

func (c Cx1Client) GetProjectByID(projectID string) (Project, error) {
	c.logger.Debugf("Getting Project with ID %v...", projectID)
	var project Project

	data, err := c.sendRequest(http.MethodGet, fmt.Sprintf("/projects/%v", projectID), nil, nil)
	if err != nil {
		return project, fmt.Errorf("failed to fetch project %v: %s", projectID, err)
	}

	err = json.Unmarshal([]byte(data), &project)
	if err != nil {
		return project, err
	}

	err = c.GetProjectConfiguration(&project)
	return project, err
}

func (c Cx1Client) GetProjectByName(projectname string) (Project, error) {
	projects, err := c.GetProjectsByName(projectname)
	if err != nil {
		return Project{}, err
	}

	for _, p := range projects {
		if p.Name == projectname {
			err = c.GetProjectConfiguration(&p)
			return p, err
		}
	}

	return Project{}, fmt.Errorf("no project matching %v found", projectname)
}

// Get all projects matching the name 'name'
// As of 2024-10-17 this function no longer takes a specific limit as a parameter
// To set limits, offsets, and other parameters directly, use GetProjectsFiltered
func (c Cx1Client) GetProjectsByName(name string) ([]Project, error) {
	c.logger.Debugf("Get Cx1 Projects By Name: %v", name)

	_, projects, err := c.GetAllProjectsFiltered(ProjectFilter{
		BaseFilter: BaseFilter{Limit: c.pagination.Projects},
		Name:       name,
	})

	return projects, err
}

func (c Cx1Client) GetProjectsByNameAndGroupID(projectName string, groupID string) ([]Project, error) {
	c.logger.Debugf("Getting projects with name %v of group ID %v...", projectName, groupID)

	_, projects, err := c.GetAllProjectsFiltered(ProjectFilter{
		BaseFilter: BaseFilter{Limit: c.pagination.Projects},
		Name:       projectName,
		Groups:     []string{groupID},
	})

	return projects, err
}

// Underlying function used by many GetApplications* calls
// Returns the number of applications matching the filter and the array of matching applications
func (c Cx1Client) GetProjectsFiltered(filter ProjectFilter) (uint64, []Project, error) {
	params := filter.UrlParams()

	var ProjectResponse struct {
		BaseFilteredResponse
		Projects []Project
	}

	response, err := c.sendRequest(http.MethodGet, fmt.Sprintf("/projects?%v", params.Encode()), nil, nil)

	if err != nil {
		return ProjectResponse.FilteredTotalCount, ProjectResponse.Projects, err
	}

	err = json.Unmarshal(response, &ProjectResponse)
	return ProjectResponse.FilteredTotalCount, ProjectResponse.Projects, err
}

func (c Cx1Client) GetAllProjectsFiltered(filter ProjectFilter) (uint64, []Project, error) {
	var projects []Project

	count, projs, err := c.GetProjectsFiltered(filter)
	projects = projs

	for err == nil && count > filter.Offset+filter.Limit && filter.Limit > 0 {
		filter.Bump()
		_, projs, err = c.GetProjectsFiltered(filter)
		projects = append(projects, projs...)
	}

	return count, projects, err
}

// convenience
func (p *Project) IsInGroupID(groupId string) bool {
	for _, g := range p.Groups {
		if g == groupId {
			return true
		}
	}
	return false
}

func (p *Project) IsInGroup(group *Group) bool {
	return p.IsInGroupID(group.GroupID)
}

func (c Cx1Client) GetProjectConfiguration(project *Project) error {
	configurations, err := c.GetProjectConfigurationByID(project.ProjectID)
	project.Configuration = configurations
	return err
}

func (c Cx1Client) GetProjectConfigurationByID(projectID string) ([]ConfigurationSetting, error) {
	c.logger.Debugf("Getting project configuration for project %v", projectID)
	var projectConfigurations []ConfigurationSetting
	params := url.Values{
		"project-id": {projectID},
	}
	data, err := c.sendRequest(http.MethodGet, fmt.Sprintf("/configuration/project?%v", params.Encode()), nil, nil)

	if err != nil {
		c.logger.Tracef("Failed to get project configuration for project ID %v: %s", projectID, err)
		return projectConfigurations, err
	}

	err = json.Unmarshal([]byte(data), &projectConfigurations)
	return projectConfigurations, err
}

// UpdateProjectConfiguration updates the configuration of the project addressed by projectID
func (c Cx1Client) UpdateProjectConfiguration(project *Project, settings []ConfigurationSetting) error {
	project.Configuration = settings
	return c.UpdateProjectConfigurationByID(project.ProjectID, settings)
}

func (c Cx1Client) UpdateProjectConfigurationByID(projectID string, settings []ConfigurationSetting) error {
	if len(settings) == 0 {
		return fmt.Errorf("empty list of settings provided")
	}

	params := url.Values{
		"project-id": {projectID},
	}

	jsonBody, err := json.Marshal(settings)
	if err != nil {
		return err
	}

	_, err = c.sendRequest(http.MethodPatch, fmt.Sprintf("/configuration/project?%v", params.Encode()), bytes.NewReader(jsonBody), nil)
	if err != nil {
		c.logger.Tracef("Failed to update project %v configuration: %s", projectID, err)
		return err
	}

	return nil
}

func (c Cx1Client) SetProjectBranchByID(projectID, branch string, allowOverride bool) error {
	var setting ConfigurationSetting
	setting.Key = "scan.handler.git.branch"
	setting.Value = branch
	setting.AllowOverride = allowOverride

	return c.UpdateProjectConfigurationByID(projectID, []ConfigurationSetting{setting})
}

func (c Cx1Client) GetProjectBranchesByID(projectID string) ([]string, error) {
	return c.GetAllProjectBranchesFiltered(ProjectBranchFilter{
		BaseFilter: BaseFilter{Limit: c.pagination.Branches},
		ProjectID:  projectID,
	})
}

func (c Cx1Client) GetProjectBranchesFiltered(filter ProjectBranchFilter) ([]string, error) {
	params := filter.UrlParams()
	branches := []string{}

	data, err := c.sendRequest(http.MethodGet, fmt.Sprintf("/projects/branches?%v", params.Encode()), nil, nil)
	if err != nil {
		err = fmt.Errorf("failed to fetch branches matching filter %v: %s", params, err)
		c.logger.Tracef("Error: %s", err)
		return branches, err
	}

	err = json.Unmarshal(data, &branches)
	return branches, err
}

func (c Cx1Client) GetAllProjectBranchesFiltered(filter ProjectBranchFilter) ([]string, error) {
	var branches []string

	bs, err := c.GetProjectBranchesFiltered(filter)
	branches = bs

	for err == nil && filter.Limit == uint64(len(bs)) && filter.Limit > 0 {
		filter.Bump()
		bs, err = c.GetProjectBranchesFiltered(filter)
		branches = append(branches, bs...)
	}

	return branches, err
}

func (c Cx1Client) SetProjectRepositoryByID(projectID, repository string, allowOverride bool) error {
	var setting ConfigurationSetting
	setting.Key = "scan.handler.git.repository"
	setting.Value = repository
	setting.AllowOverride = allowOverride

	return c.UpdateProjectConfigurationByID(projectID, []ConfigurationSetting{setting})
}

func (c Cx1Client) SetProjectPresetByID(projectID, presetName string, allowOverride bool) error {
	var setting ConfigurationSetting
	setting.Key = "scan.config.sast.presetName"
	setting.Value = presetName
	setting.AllowOverride = allowOverride

	return c.UpdateProjectConfigurationByID(projectID, []ConfigurationSetting{setting})
}

func (c Cx1Client) SetProjectLanguageModeByID(projectID, languageMode string, allowOverride bool) error {
	var setting ConfigurationSetting
	setting.Key = "scan.config.sast.languageMode"
	setting.Value = languageMode
	setting.AllowOverride = allowOverride

	return c.UpdateProjectConfigurationByID(projectID, []ConfigurationSetting{setting})
}

func (c Cx1Client) SetProjectFileFilterByID(projectID, filter string, allowOverride bool) error {
	var setting ConfigurationSetting
	setting.Key = "scan.config.sast.filter"
	setting.Value = filter
	setting.AllowOverride = allowOverride

	// TODO - apply the filter across all languages? set up separate calls per engine? engine as param?

	return c.UpdateProjectConfigurationByID(projectID, []ConfigurationSetting{setting})
}

func (c Cx1Client) GetLastScansByID(projectID string, limit uint64) ([]Scan, error) {
	scanFilter := ScanFilter{
		BaseFilter: BaseFilter{Limit: limit},
		ProjectID:  projectID,
		Sort:       "+created_at",
	}
	_, scans, err := c.GetScansFiltered(scanFilter)
	return scans, err
}

func (c Cx1Client) GetLastScansByIDFiltered(projectID string, filter ScanFilter) ([]Scan, error) {
	filter.ProjectID = projectID
	return c.GetLastScansFiltered(filter)
}

func (c Cx1Client) GetLastScansByStatusAndID(projectID string, limit uint64, status []string) ([]Scan, error) {
	scanFilter := ScanFilter{
		BaseFilter: BaseFilter{Limit: limit},
		ProjectID:  projectID,
		Statuses:   status,
	}
	return c.GetLastScansFiltered(scanFilter)
}

// convenience
func (c Cx1Client) GetProjectCount() (uint64, error) {
	c.logger.Debug("Get Cx1 Projects Count")
	count, _, err := c.GetProjectsFiltered(ProjectFilter{BaseFilter: BaseFilter{Limit: 1}})
	return count, err
}

func (c Cx1Client) GetProjectCountByName(name string) (uint64, error) {
	c.logger.Debugf("Get Cx1 Project count by name: %v", name)
	count, _, err := c.GetProjectsFiltered(ProjectFilter{
		BaseFilter: BaseFilter{Limit: 1},
		Name:       name,
	})
	return count, err
}

func (c Cx1Client) ProjectLink(p *Project) string {
	return fmt.Sprintf("%v/projects/%v/overview", c.baseUrl, p.ProjectID)
}

func (c Cx1Client) UpdateProject(project *Project) error {
	c.logger.Debugf("Updating project %v", project.String())

	jsonBody, err := json.Marshal(project)
	if err != nil {
		return err
	}

	_, err = c.sendRequest(http.MethodPut, fmt.Sprintf("/projects/%v", project.ProjectID), bytes.NewReader(jsonBody), nil)
	return err
}

func (c Cx1Client) DeleteProject(p *Project) error {
	c.logger.Debugf("Deleting Project %v", p.String())

	_, err := c.sendRequest(http.MethodDelete, fmt.Sprintf("/projects/%v", p.ProjectID), nil, nil)
	if err != nil {
		return fmt.Errorf("deleting project %v failed: %s", p.String(), err)
	}

	return nil
}

func (p *Project) AssignGroup(group *Group) {
	if p.IsInGroup(group) {
		return
	}
	p.Groups = append(p.Groups, group.GroupID)
}

func (c Cx1Client) GetOrCreateProjectByName(name string) (Project, error) {
	project, err := c.GetProjectByName(name)
	if err == nil {
		return project, nil
	}

	return c.CreateProject(name, []string{}, map[string]string{})
}

func (c Cx1Client) GetOrCreateProjectInApplicationByName(projectName, applicationName string) (Project, Application, error) {
	var application Application
	var project Project
	var err error
	application, err = c.GetApplicationByName(applicationName)
	if err != nil {
		application, err = c.CreateApplication(applicationName)
		if err != nil {
			return project, application, fmt.Errorf("attempt to create project %v in application %v failed, application did not exist and could not be created due to error: %s", projectName, applicationName, err)
		}
	}

	project, err = c.GetProjectByName(projectName)
	if err != nil {
		if err.Error()[:19] == "no project matching" {
			project, err = c.CreateProjectInApplication(projectName, []string{}, map[string]string{}, application.ApplicationID)
			if err != nil {
				return project, application, fmt.Errorf("attempt to create project %v in application %v failed due to error: %s", projectName, applicationName, err)
			}
			return project, application, nil
		} else {
			return project, application, err
		}
	}

	return project, application, nil
}

func (p Project) GetConfigurationByName(configKey string) *ConfigurationSetting {
	return getConfigurationByName(&p.Configuration, configKey)
}

func (c Cx1Client) GetConfigurationByName(config *[]ConfigurationSetting, configKey string) *ConfigurationSetting {
	return getConfigurationByName(config, configKey)
}

func getConfigurationByName(config *[]ConfigurationSetting, configKey string) *ConfigurationSetting {
	for id := range *config {
		if (*config)[id].Key == configKey || (*config)[id].Name == configKey {
			return &((*config)[id])
		}
	}
	return nil
}

/* misc future stuff

Listing of files in a scan:
	https://deu.ast.checkmarx.net/api/repostore/project-tree/74328f1f-94ec-452f-8f1a-047d76f6764e
*/
