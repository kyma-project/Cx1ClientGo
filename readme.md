This is a basic CheckmarxOne REST API client written in GoLang. It already covers much of the CheckmarxOne API allowing Read operations on Applications, Clients, Groups, Presets, Projects, Queries, Reports, Results, Roles, Scans, and Users. Many of these include full CRUD support but this is still a work in progress.

Feel free to use or modify this code, open issues, or submit pull requests. Please submit pull requests against the Dev branch - I will try to keep the main branch clean with only tagged versions. Since this code is changing regularly, consider using a specific tag of Cx1ClientGo until you can test against a newer release.

Basic usage:

```golang
package main

import (
	"github.com/cxpsemea/Cx1ClientGo"
	log "github.com/sirupsen/logrus"
	"os"
    "net/http"
)

func main() {
	logger := log.New()
	logger.Infof( "Starting" )

	base_url := os.Args[1]
	iam_url := os.Args[2]
	tenant := os.Args[3]
	api_key := os.Args[4]

	cx1client, err := Cx1ClientGo.NewAPIKeyClient( &http.Client{}, base_url, iam_url, tenant, api_key, logger )
	if err != nil {
		log.Error( "Error creating client: " + err.Error() )
		return 
	}

	// no err means that the client is initialized
	logger.Infof( "Client initialized: " + cx1client.ToString() )
}
```



More complete workflow example:

```golang
package main

import (
	"github.com/cxpsemea/Cx1ClientGo"
	log "github.com/sirupsen/logrus"
	"os"
	"time"
	"net/http"
	"net/url"
	"crypto/tls"
)

func main() {
	logger := log.New()
	logger.Infof( "Starting" )
	//logger.SetLevel( log.TraceLevel ) 

	base_url := os.Args[1]
	iam_url := os.Args[2]
	tenant := os.Args[3]
	api_key := os.Args[4]
	project_name := os.Args[5]
	group_name := os.Args[6]
	project_repo := os.Args[7]
	branch_name := os.Args[8]
	
	proxyURL, err := url.Parse( "http://127.0.0.1:8080" )
	transport := &http.Transport{}
	transport.Proxy = http.ProxyURL(proxyURL)
	transport.TLSClientConfig = &tls.Config{ InsecureSkipVerify: true, }
	
	httpClient := &http.Client{}
	//httpClient.Transport = transport
	
	
	cx1client, err := Cx1ClientGo.NewAPIKeyClient( httpClient, base_url, iam_url, tenant, api_key, logger )
	if err != nil {
		log.Error( "Error creating client: " + err.Error() )
		return 
	}

	// no err means that the client is initialized
	logger.Infof( "Client initialized: " + cx1client.ToString() )
	
	group, err := cx1client.GetGroupByName( group_name )
	if err != nil {
		if err.Error() != "No matching group found" {
			logger.Infof( "Failed to retrieve group named %s: %v", group_name, err )
			return
		}
		
		logger.Infof( "No group named %s exists - it will now be created", group_name )
		group, err = cx1client.CreateGroup( group_name )
		if err != nil {
			logger.Errorf( "Failed to create group %s: %v", group_name, err )
			return
		}
		
		logger.Infof( "Created group named '%v' with ID %v", group.Name, group.GroupID )
	} else {	
		logger.Infof( "Found group named %v with ID %v", group.Name, group.GroupID )
	}
	
	projects, err := cx1client.GetProjectsByNameAndGroup( project_name, group.GroupID )
	if err != nil {
		logger.Errorf( "Failed to retrieve project named %s: %v", project_name, err )
		return
	}	
	
	var project Cx1ClientGo.Project
	if len(projects) == 0 {
		logger.Infof( "No project named %s found under group %s - it will now be created", project_name, group_name )
		project, err = cx1client.CreateProject( project_name, group.GroupID, map[string]string{ "CreatedBy" : "Cx1ClientGo" } )
		if err != nil {
			logger.Errorf( "Failed to create project %s: %v", project_name, err )
			return
		}
		logger.Infof( "Created project named '%v' with ID %v", project.Name, project.ProjectID )
	} else {
		project = projects[0]
		logger.Infof( "First project matching '%v' in group '%v' is named '%v' with ID %v", project_name, group_name, project.Name, project.ProjectID )
	}
	
	scanConfig := Cx1ClientGo.ScanConfiguration{}
	scanConfig.ScanType = "sast"
	scanConfig.Values = map[string]string{ "incremental" : "false" }
	
	scan, err := cx1client.ScanProjectGitByID( project.ProjectID, project_repo, branch_name, []Cx1ClientGo.ScanConfiguration{scanConfig}, map[string]string{ "CreatedBy" : "Cx1ClientGo" } )
	
	if err != nil {
		logger.Errorf( "Failed to trigger scan with repository '%v' branch '%v': %s", project_repo, branch_name, err )
		return
	}
	
	logger.Infof( "Triggered scan %v, polling status", scan.ScanID )
	for scan.Status == "Running" {
		time.Sleep( 10 * time.Second )
		scan, err = cx1client.GetScanByID( scan.ScanID )
		if err != nil {
			logger.Errorf( "Failed to get scan status: %v", err )
			return
		}
		logger.Infof( " - %v", scan.Status )
	}
	
	reportID, err := cx1client.RequestNewReportByID( scan.ScanID, project.ProjectID, branch_name, "pdf" )
	if err != nil {
		logger.Errorf( "Failed to trigger new report generation for scan ID %v, project ID %v: %s", scan.ScanID, project.ProjectID, err )
		return
	}
	
	logger.Infof( "Generating report %v, polling status", reportID )
	var status Cx1ClientGo.ReportStatus
	
	for status.Status != "completed" {
		time.Sleep( 10 * time.Second )
		status, err = cx1client.GetReportStatusByID( reportID )
		if err != nil {
			logger.Errorf( "Failed to get report status: %v", err )
			return
		}
		
		logger.Infof( " - %v", status.Status )
	}
	
	logger.Infof( "Downloading report from %v", status.ReportURL )
	reportData, err := cx1client.DownloadReport( status.ReportURL )
	if err != nil {
		logger.Errorf( "Failed to download report: %s", err )
		return
	}
	
	err = os.WriteFile( "report.pdf", reportData, 0o700 )
	if err != nil {
		logger.Errorf( "Failed to Update report: %s", err )
		return
	}
	logger.Infof( "Report Updated to report.pdf" )
	
	scanresults, err := cx1client.GetScanResultsByID( scan.ScanID )
	if err != nil && len(scanresults) == 0 {
		logger.Errorf( "Failed to retrieve scan results: %s", err )
		return
	}
	
	if err != nil {
		logger.Infof( "Results retrieved but error thrown: %s", err ) // can be "remote error: tls: user canceled" but still returns results
	} else {
		logger.Infof( "%d results retrieved", len(scanresults) )
	}
	
	for _, result := range scanresults {
		logger.Infof( "Finding with similarity ID: %v", result.SimilarityID )
	}
}
```

Invocation for the more complicated example:
go run . "https://eu.ast.checkmarx.net" "https://eu.iam.checkmarx.net" "tenant" "API Key" "Project Name" "Group Name" "https://my.github/project/repo" "branch"


Current API coverage:
```
Cx1: Delete /api/applications/%v
Cx1: Delete /api/presets/%d
Cx1: Delete /api/projects/%v
Cx1: Get /api/applications?%v
Cx1: Get /api/applications?%v
Cx1: Get /api/applications?%v
Cx1: Get /api/applications?%v
Cx1: Get /api/configuration/project?%v
Cx1: Get /api/presets/%d
Cx1: Get /api/presets/queries
Cx1: Get /api/projects/
Cx1: Get /api/projects/%v
Cx1: Get /api/projects/?%v
Cx1: Get /api/projects/?%v
Cx1: Get /api/projects?%v
Cx1: Get /api/projects?%v
Cx1: Get /api/projects?%v
Cx1: Get /api/queries/%d
Cx1: Get /api/queries/presets
Cx1: Get /api/reports/%v
Cx1: Get /api/results/?%v
Cx1: Get /api/results/?%v
Cx1: Get /api/sast-metadata/%v
Cx1: Get /api/sast-results-predicates/%d?project-ids=%v
Cx1: Get /api/scans/%v
Cx1: Get /api/scans?%v
Cx1: Get /api/scans?%v
Cx1: Get /api/scan-summary/?%v
Cx1: Patch /api/configuration/project?%v
Cx1: Post /api/applications
Cx1: Post /api/presets
Cx1: Post /api/projects
Cx1: Post /api/reports
Cx1: Post /api/sast-results-predicates
Cx1: Post /api/scans
Cx1: Post /api/uploads
Cx1: Put /api/applications/%v
Cx1: Put /api/presets/%d
Cx1: Put /api/projects/%v
IAM: Delete /auth/admin/tenant/groups/%v
IAM: Delete /auth/admin/tenant/groups/%v/role-mappings/clients/%v
IAM: Delete /auth/admin/tenant/roles-by-id/%v
IAM: Delete /auth/admin/tenant/roles-by-id/%v/composites
IAM: Delete /auth/admin/tenant/users/%v
IAM: Delete /auth/admin/tenant/users/%v/groups/%v
IAM: Delete /auth/admin/tenant/users/%v/role-mappings/clients/%v
IAM: Delete /auth/admin/tenant/users/%v/role-mappings/realm
IAM: Get /auth/admin/tenant
IAM: Get /auth/admin/tenant/clients/%v/roles/%v
IAM: Get /auth/admin/tenant/clients/%v/roles?briefRepresentation=true
IAM: Get /auth/admin/tenant/clients?briefRepresentation=true
IAM: Get /auth/admin/tenant/groups/%v?%v
IAM: Get /auth/admin/tenant/groups?briefRepresentation=true
IAM: Get /auth/admin/tenant/groups?briefRepresentation=true&search=%v
IAM: Get /auth/admin/tenant/groups?briefRepresentation=true&search=%v
IAM: Get /auth/admin/tenant/roles/%v
IAM: Get /auth/admin/tenant/roles?briefRepresentation=true
IAM: Get /auth/admin/tenant/roles-by-id/%v
IAM: Get /auth/admin/tenant/roles-by-id/%v/composites
IAM: Get /auth/admin/tenant/users
IAM: Get /auth/admin/tenant/users/%v
IAM: Get /auth/admin/tenant/users/%v/groups
IAM: Get /auth/admin/tenant/users/%v/role-mappings/clients/%v
IAM: Get /auth/admin/tenant/users/%v/role-mappings/realm
IAM: Get /auth/admin/tenant/users/?exact=true&email=%v
IAM: Get /auth/admin/tenant/users/?exact=true&username=%v
IAM: Get /auth/tenant/pip/groups
IAM: Post /auth/admin/tenant/children
IAM: Post /auth/admin/tenant/clients/%v/roles
IAM: Post /auth/admin/tenant/groups
IAM: Post /auth/admin/tenant/groups/%v/children
IAM: Post /auth/admin/tenant/groups/%v/role-mappings/clients/%v
IAM: Post /auth/admin/tenant/roles-by-id/%v/composites
IAM: Post /auth/admin/tenant/users/%v/role-mappings/clients/%v
IAM: Post /auth/admin/tenant/users/%v/role-mappings/realm
IAM: Put /auth/admin/tenant/groups/%v
IAM: Put /auth/admin/tenant/users/%v
IAM: Put /auth/admin/tenant/users/%v/groups/%v
```