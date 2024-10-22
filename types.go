package Cx1ClientGo

import (
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/sirupsen/logrus"
)

type Cx1Client struct {
	httpClient *http.Client
	//authToken  string
	baseUrl    string
	iamUrl     string
	tenant     string
	logger     *logrus.Logger
	flags      map[string]bool // initial implementation ignoring "payload" part of the flag
	consts     ClientVars
	pagination PaginationSettings
	claims     Cx1Claims
	user       *User
	version    *VersionInfo
}

type Cx1Claims struct {
	jwt.RegisteredClaims
	Cx1License    ASTLicense `json:"ast-license"`
	IsServiceUser string     `json:"is-service-user"`
	UserID        string     `json:"sub"`
}
type ASTLicense struct {
	ID          int
	TenantID    string
	PackageName string
	LicenseData struct {
		AllowedEngines     []string
		APISecurityEnabled bool
		CodebashingEnabled bool
		DASTEnabled        bool
		MaxConcurrentScans int
		SCSEnabled         bool
		ServiceType        string
		Services           []string
		UsersCount         int
	}
}

type TenantOwner struct {
	Username  string
	Firstname string
	Lastname  string
	Email     string
	UserID    string `json:"id"`
}

type ClientVars struct {
	MigrationPollingMaxSeconds                int
	MigrationPollingDelaySeconds              int
	AuditEnginePollingMaxSeconds              int
	AuditEnginePollingDelaySeconds            int
	AuditScanPollingMaxSeconds                int
	AuditScanPollingDelaySeconds              int
	AuditCompilePollingMaxSeconds             int
	AuditCompilePollingDelaySeconds           int
	AuditLanguagePollingMaxSeconds            int
	AuditLanguagePollingDelaySeconds          int
	ScanPollingMaxSeconds                     int
	ScanPollingDelaySeconds                   int
	ProjectApplicationLinkPollingMaxSeconds   int
	ProjectApplicationLinkPollingDelaySeconds int
}

// Related to pagination and filtering
type PaginationSettings struct {
	Applications uint64
	Branches     uint64
	Groups       uint64
	Projects     uint64
	Results      uint64
	Scans        uint64
	Users        uint64
}

type BaseFilter struct {
	Offset uint64 `url:"offset"` // offset is set automatically for pagination
	Limit  uint64 `url:"limit"`  // limit is set automatically for pagination, should generally not be 0
}

type BaseIAMFilter struct {
	First uint64 `url:"first"` // offset is set automatically for pagination
	Max   uint64 `url:"max"`   // limit is set automatically for pagination, should generally not be 0
}

type BaseFilteredResponse struct {
	TotalCount         uint64 `json:"totalCount"`
	FilteredTotalCount uint64 `json:"filteredTotalCount"`
}

type AccessAssignment struct {
	TenantID     string               `json:"tenantID"`
	EntityID     string               `json:"entityID"`
	EntityType   string               `json:"entityType"`
	EntityName   string               `json:"entityName"`
	EntityRoles  []AccessAssignedRole `json:"entityRoles"`
	ResourceID   string               `json:"resourceID"`
	ResourceType string               `json:"resourceType"`
	ResourceName string               `json:"resourceName"`
	CreatedAt    string               `json:"createdAt"`
}

type AccessAssignedRole struct {
	Id   string `json:"id"`
	Name string `json:"name"`
}

type AccessibleResource struct {
	ResourceID   string   `json:"resourceId"`
	ResourceType string   `json:"resourceType"`
	Roles        []string `json:"roles"`
}

type Application struct {
	ApplicationID string            `json:"id"`
	Name          string            `json:"name"`
	Description   string            `json:"description"`
	Criticality   uint              `json:"criticality"`
	Rules         []ApplicationRule `json:"rules"`
	Tags          map[string]string `json:"tags"`
	ProjectIds    []string          `json:"projectIds"`
	CreatedAt     string            `json:"createdAt"`
	UpdatedAt     string            `json:"updatedAt"`
}

type ApplicationFilter struct {
	BaseFilter
	Name       string   `url:"name,omitempty"`
	TagsKeys   []string `url:"tags-keys,omitempty"`
	TagsValues []string `url:"tags-values,omitempty"`
}

type ApplicationRule struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

type AuditQuery struct {
	Key      string `json:"id"`
	Name     string
	Level    string
	LevelID  string
	Path     string
	Source   string
	Metadata AuditQueryMetadata
}

type AuditQueryTree struct {
	IsLeaf bool
	Title  string
	Key    string
	Data   struct {
		Level    string
		Severity string
	}
	Children []AuditQueryTree
}

type AuditQueryMetadata struct {
	Cwe             int64  `json:"cwe,omitempty"`
	IsExecutable    bool   `json:"executable"`
	CxDescriptionID int64  `json:"description,omitempty"`
	Language        string `json:"language"`
	Group           string `json:"group"`
	Severity        string `json:"severity"`
	SastID          uint64 `json:"sastId,omitempty"`
	Name            string `json:"name"`
}

type AuditPermissions struct {
	View   bool `json:"view"`
	Update bool `json:"update"`
	Create bool `json:"create"`
	Delete bool `json:"delete"`
}

type AuditSession struct {
	ID   string `json:"id"`
	Data struct {
		Status      string `json:"status"`
		RequestID   string `json:"requestId"`
		Permissions struct {
			Tenant      AuditPermissions `json:"tenant"`
			Project     AuditPermissions `json:"project"`
			Application AuditPermissions `json:"application"`
		} `json:"permissions"`
	} `json:"data"`
	ProjectName            string   `json:"projectName"`
	QueryBuilder           bool     `json:"queryBuilder"`
	ApplicationAssociation bool     `json:"applicationAssociation"`
	Status                 string   `json:"status"`
	Value                  []string `json:"value"`
	ProjectID              string   `json:"-"`
	ApplicationID          string   `json:"-"`
	ScanID                 string   `json:"-"`
	Languages              []string `json:"-"`
}

type AuditSessionFilters map[string]AuditSessionLanguageFilters

type AuditSessionLanguageFilters struct {
	Description string
	Filters     []AuditSessionLanguage
}

type AuditSessionLanguage struct {
	Key   string
	Title string
	Icon  string
}

type AuditScanSourceFile struct {
	IsLeaf   bool                  `json:"isLeaf"`
	Title    string                `json:"title"`
	Key      string                `json:"key"`
	Children []AuditScanSourceFile `json:"children"`
}

type AuthenticationProvider struct {
	Alias      string `json:"alias"`
	ID         string `json:"internalId,omitempty"`
	ProviderID string `json:"providerId"`
}

type AuthenticationProviderMapper struct {
	ID     string                             `json:"id,omitempty"`
	Name   string                             `json:"name"`
	Alias  string                             `json:"identityProviderAlias"`
	Mapper string                             `json:"identityProviderMapper"`
	Config AuthenticationProviderMapperConfig `json:"config"`
}

type AuthenticationProviderMapperConfig struct {
	SyncMode      string `json:"syncMode"`
	UserAttribute string `json:"user.attribute,omitempty"`
	FriendlyName  string `json:"attribute.friendly.name,omitempty"`
	Format        string `json:"attribute.name.format,omitempty"`
	Name          string `json:"attribute.name,omitempty"`
	Role          string `json:"attribute.role,omitempty"`
	Value         string `json:"attribute.value,omitempty"`
	Target        string `json:"target,omitempty"`
	Template      string `json:"template,omitempty"`
}

type DataImport struct {
	MigrationId string             `json:"migrationId"`
	Status      string             `json:"status"`
	CreatedAt   string             `json:"createdAt"`
	Logs        []DataImportStatus `json:"logs"`
}

type DataImportStatus struct {
	Level   string `json:"level"`
	Message string `json:"msg"`
	Error   string `json:"error"`
	Worker  string `json:"worker"`
	RawLog  string `json:"raw_log"`
}

type Group struct {
	GroupID         string              `json:"id"`
	Name            string              `json:"name"`
	Path            string              `json:"path"`
	SubGroups       []Group             `json:"subGroups"`
	SubGroupCount   uint64              `json:"subGroupCount"`
	DescendentCount uint64              `json:"-"`
	ClientRoles     map[string][]string `json:"clientRoles"`
	Filled          bool                `json:"-"`
}

type GroupFilter struct {
	BaseIAMFilter
	BriefRepresentation bool   `url:"briefRepresentation,omitempty"`
	Exact               bool   `url:"exact,omitempty"`
	PopulateHierarchy   bool   `url:"populateHierarchy,omitempty"`
	Q                   bool   `url:"q,omitempty"`
	Search              string `url:"search,omitempty"` // used in both GetGroup and GetGroupCount
	Top                 bool   `url:"-"`                // used only in GetGroupCount
}

type OIDCClient struct {
	ID                 string                 `json:"id"`
	ClientID           string                 `json:"clientId"`
	Enabled            bool                   `json:"enabled"`
	ClientSecret       string                 `json:"secret"`
	ClientSecretExpiry uint64                 `json:"-"`
	Creator            string                 `json:"-"`
	OIDCClientRaw      map[string]interface{} `json:"-"`
}

type OIDCClientScope struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Protocol    string `json:"protocol"`
}

type Preset struct {
	PresetID    uint64 `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Custom      bool   `json:"custom"`
	QueryIDs    []uint64
	Filled      bool
	Queries     []Query `json:"-"`
}

type Project struct {
	ProjectID     string                 `json:"id"`
	Name          string                 `json:"name"`
	CreatedAt     string                 `json:"createdAt"`
	UpdatedAt     string                 `json:"updatedAt"`
	Groups        []string               `json:"groups"`
	Applications  []string               `json:"applicationIds"`
	Tags          map[string]string      `json:"tags"`
	RepoUrl       string                 `json:"repoUrl"`
	MainBranch    string                 `json:"mainBranch"`
	Origin        string                 `json:"origin"`
	Criticality   uint                   `json:"criticality"`
	Configuration []ConfigurationSetting `json:"-"`
}

type ProjectFilter struct {
	BaseFilter
	ProjectIDs []string `url:"ids,omitempty"`
	Names      []string `url:"names,omitempty"`
	Name       string   `url:"name,omitempty"`
	NameRegex  string   `url:"name-regex,omitempty"`
	Groups     []string `url:"groups,omitempty"`
	Origins    []string `url:"origins,omitempty"`
	TagsKeys   []string `url:"tags-keys,omitempty"`
	TagsValues []string `url:"tags-values,omitempty"`
	EmptyTags  bool     `url:"empty-tags,omitempty"`
	RepoURL    string   `url:"repo-url,omitempty"`
}

type ProjectBranchFilter struct {
	BaseFilter
	ProjectID string `url:"project-id,omitempty"`
	Name      string `url:"branch-name,omitempty"`
}

type ConfigurationSetting struct {
	Key             string `json:"key"`
	Name            string `json:"name"`
	Category        string `json:"category"`
	OriginLevel     string `json:"originLevel"`
	Value           string `json:"value"`
	ValueType       string `json:"valuetype"`
	ValueTypeParams string `json:"valuetypeparams"`
	AllowOverride   bool   `json:"allowOverride"`
}

type Query struct {
	QueryID            uint64 `json:"queryID,string"`
	Level              string `json:"level"`
	LevelID            string `json:"levelId"`
	Path               string `json:"path"`
	Modified           string `json:"-"`
	Source             string `json:"-"`
	Name               string `json:"queryName"`
	Group              string `json:"group"`
	Language           string `json:"language"`
	Severity           string `json:"severity"`
	CweID              int64  `json:"cweID"`
	IsExecutable       bool   `json:"isExecutable"`
	QueryDescriptionId int64  `json:"queryDescriptionId"`
	Custom             bool   `json:"custom"`
	EditorKey          string `json:"key"`
	SastID             uint64 `json:"sastId"`
}

type QueryGroup struct {
	Name     string
	Language string
	Queries  []Query
}

type QueryLanguage struct {
	Name        string
	QueryGroups []QueryGroup
}

type QueryCollection struct {
	QueryLanguages []QueryLanguage
}

type QueryUpdate_v310 struct { // used when saving queries in Cx1
	Name     string `json:"name"`
	Path     string `json:"path"`
	Source   string `json:"source"`
	Language string `json:"-"`
	Group    string `json:"-"`

	Metadata QueryUpdateMetadata_v310 `json:"metadata"`
}
type QueryUpdateMetadata_v310 struct {
	Severity uint `json:"severity"`
}

type ReportStatus struct {
	ReportID  string `json:"reportId"`
	Status    string `json:"status"`
	ReportURL string `json:"url"`
}

type RunningScan struct {
	ScanID    string
	Status    string
	ProjectID string
	CreatedAt time.Time
	UpdatedAt time.Time
}

type ResultsPredicatesBase struct {
	PredicateID  string `json:"ID"`
	SimilarityID string `json:"similarityId"`
	ProjectID    string `json:"projectId"`
	State        string `json:"state"`
	Comment      string `json:"comment"`
	Severity     string `json:"severity"`
	CreatedBy    string `json:"createdBy"`
	CreatedAt    string `json:"createdAt"`
}

type SASTResultsPredicates struct {
	ResultsPredicatesBase // actually the same structure but different endpoint
}
type KICSResultsPredicates struct {
	ResultsPredicatesBase // actually the same structure but different endpoint
}

/*
type KeyCloakClient struct {
	ClientID string `json:"id"`
	Name     string `json:"clientId"`
	Enabled  bool
}*/

type Role struct {
	ClientID    string `json:"containerId"` // the 'client' in Keycloak - AST roles with have the "ast-app" client ID
	RoleID      string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Attributes  struct {
		Creator    []string
		Type       []string
		Category   []string
		LastUpdate []string // it is returned as [ "uint",... ]
	} `json:"attributes"`
	Composite  bool   `json:"composite"`
	ClientRole bool   `json:"clientRole"`
	SubRoles   []Role `json:"-"`
}

type Scan struct {
	ScanID        string              `json:"id"`
	Status        string              `json:"status"`
	StatusDetails []ScanStatusDetails `json:"statusDetails"`
	Branch        string              `json:"branch"`
	CreatedAt     string              `json:"createdAt"`
	UpdatedAt     string              `json:"updatedAt"`
	ProjectID     string              `json:"projectId"`
	ProjectName   string              `json:"projectName"`
	UserAgent     string              `json:"userAgent"`
	Initiator     string              `json:"initiator"`
	Tags          map[string]string   `json:"tags"`
	Metadata      struct {
		Type    string              `json:"type"`
		Configs []ScanConfiguration `json:"configs"`
	} `json:"metadata"`
	Engines      []string `json:"engines"`
	SourceType   string   `json:"sourceType"`
	SourceOrigin string   `json:"sourceOrigin"`
}

type ScanFilter struct {
	BaseFilter
	ProjectID string    `url:"project-id"`
	Sort      []string  `url:"sort,omitempty"` // Available values : -created_at, +created_at, -status, +status, +branch, -branch, +initiator, -initiator, +user_agent, -user_agent, +name, -name
	TagKeys   []string  `url:"tags-keys,omitempty"`
	TagValues []string  `url:"tags-values,omitempty"`
	Statuses  []string  `url:"statuses,omitempty"`
	Branches  []string  `url:"branches,omitempty"`
	FromDate  time.Time `url:"from-date,omitempty"`
	ToDate    time.Time `url:"to-date,omitempty"`
}

type ScanConfiguration struct {
	ScanType string            `json:"type"`
	Values   map[string]string `json:"value"`
}

type ScanMetadata struct {
	ScanID                string
	ProjectID             string
	LOC                   uint64
	FileCount             uint64
	IsIncremental         bool
	IsIncrementalCanceled bool
	PresetName            string `json:"queryPreset"`
}

type ScanResultSet struct {
	SAST         []ScanSASTResult
	SCA          []ScanSCAResult
	SCAContainer []ScanSCAContainerResult
	KICS         []ScanKICSResult
	Containers   []ScanContainersResult
}

type ScanResultsFilter struct {
	BaseFilter
	ScanID             string   `url:"scan-id"`
	Severity           []string `url:"severity"`
	State              []string `url:"state"`
	Status             []string `url:"status"`
	ExcludeResultTypes []string `url:"exclude-result-types"` // Available values : DEV_AND_TEST, NONE
	Sort               []string `url:"sort"`                 //Available values : -severity, +severity, -status, +status, -state, +state, -type, +type, -firstfoundat, +firstfoundat, -foundat, +foundat, -firstscanid, +firstscanid
}

// generic data common to all
type ScanResultBase struct {
	Type            string
	ResultID        string `json:"id"`
	SimilarityID    string `json:"similarityId"`
	Status          string
	State           string
	Severity        string
	ConfidenceLevel int    `json:"confidenceLevel"`
	CreatedAt       string `json:"created"`
	FirstFoundAt    string
	FoundAt         string
	FirstScanId     string
	Description     string
	// Comments			// currently doesn't do anything?
}

type ScanContainersResult struct {
	ScanResultBase
	Data                 ScanContainersResultData
	VulnerabilityDetails ScanContainersResultDetails
}

type ScanContainersResultData struct {
	PackageName    string
	PackageVersion string
	ImageName      string
	ImageTag       string
	ImageFilePath  string
	ImageOrigin    string
}

type ScanContainersResultDetails struct {
	CVSSScore float64
	CveName   string
	CweID     string
	Cvss      struct {
		Scope                 string
		Score                 string
		Severity              string
		AttackVector          string `json:"attack_vector"`
		IntegrityImpact       string `json:"integrity_impact"`
		UserInteraction       string `json:"user_interaction"`
		AttackComplexity      string `json:"attack_complexity"`
		AvailabilityImpact    string `json:"availability_impact"`
		PrivilegesRequired    string `json:"privileges_required"`
		ConfidentialityImpact string `json:"confidentiality_impact"`
	}
}

type ScanKICSResult struct {
	ScanResultBase
	Data ScanKICSResultData
	//VulnerabilityDetails ScanKICSResultDetails // currently {}
}
type ScanKICSResultData struct {
	QueryID       string
	QueryName     string
	Group         string
	QueryURL      string
	FileName      string
	Line          int
	Platform      string
	IssueType     string
	ExpectedValue string
	Value         string
}

type ScanSASTResult struct {
	ScanResultBase
	Data                 ScanSASTResultData
	VulnerabilityDetails ScanSASTResultDetails
}
type ScanSASTResultData struct {
	QueryID      uint64
	QueryName    string
	Group        string
	ResultHash   string
	LanguageName string
	Nodes        []ScanSASTResultNodes
}
type ScanSASTResultNodes struct {
	ID          string
	Line        uint64
	Name        string
	Column      uint64
	Length      uint64
	Method      string
	NodeID      uint64
	DOMType     string
	FileName    string
	FullName    string
	TypeName    string
	MethodLine  uint64
	Definitions string
}
type ScanSASTResultDetails struct {
	CweId       int
	Compliances []string
}

type ScanSCAResult struct {
	ScanResultBase
	Data                 ScanSCAResultData `json:"data"`
	VulnerabilityDetails ScanSCAResultDetails
}
type ScanSCAResultData struct {
	PackageIdentifier  string
	PublishedAt        string
	Recommendation     string
	RecommendedVersion string
	//ExploitableMethods // TODO
	PackageData []ScanSCAResultPackageData
}
type ScanSCAResultDetails struct {
	CweId     string
	CVSSScore float64
	CveName   string
	Cvss      ScanSCAResultCVSS
}
type ScanSCAResultCVSS struct {
	Version          int
	AttackVector     string
	Availability     string
	Confidentiality  string
	AttackComplexity string
}
type ScanSCAResultPackageData struct {
	URL     string
	Type    string
	Comment string
}

type ScanSCAContainerResult struct {
	ScanResultBase
	Data                 ScanSCAContainerResultData `json:"data"`
	VulnerabilityDetails ScanSCAResultDetails
}

type ScanSCAContainerResultData struct {
	Metadata struct {
		Enrichers []string `json:"enrichers"`
	} `json:"metadata"`
	PackageName    string `json:"packageName"`
	PackageVersion string `json:"packageVersion"`
	PublishedAt    string `json:"publishedAt"`
}

type ScanStatusDetails struct {
	Name    string `json:"name"`
	Status  string `json:"status"`
	Details string `json:"details"`
}

type ScanResultStatusSummary struct {
	ToVerify               uint64
	NotExploitable         uint64
	Confirmed              uint64
	ProposedNotExploitable uint64
	Urgent                 uint64
}

type ScanResultSummary struct {
	High        ScanResultStatusSummary
	Medium      ScanResultStatusSummary
	Low         ScanResultStatusSummary
	Information ScanResultStatusSummary
}

type ScanStatusSummary struct {
	Canceled  uint64
	Completed uint64
	Partial   uint64
	Queued    uint64
	Failed    uint64
	Running   uint64
}

// Very simplified for now
type ScanSummary struct {
	TenantID     string
	ScanID       string
	SASTCounters struct {
		QueriesCounters        []ScanSummaryQueriesCounter
		SinkFileCounters       []ScanSummaryFileCounter
		LanguageCounters       []ScanSummaryLanguageCounter
		ComplianceCounters     []ScanSummaryComplianceCounter
		SeverityCounters       []ScanSummarySeverityCounter
		StatusCounters         []ScanSummaryStatusCounter
		StateCounters          []ScanSummaryStateCounter
		SeverityStatusCounters []ScanSummarySeverityStatusCounter
		SourceFileCounters     []ScanSummaryFileCounter
		AgeCounters            []ScanSummaryAgeCounter

		TotalCounter        uint64
		FilesScannedCounter uint64
	}

	KICSCounters struct {
		SeverityCounters       []ScanSummarySeverityCounter
		StatusCounters         []ScanSummaryStatusCounter
		StateCounters          []ScanSummaryStateCounter
		SeverityStatusCounters []ScanSummarySeverityStatusCounter
		SourceFileCounters     []ScanSummaryFileCounter
		AgeCounters            []ScanSummaryAgeCounter

		TotalCounter        uint64
		FilesScannedCounter uint64

		PlatformSummary []ScanSummaryPlatformCounter
		CategorySummary []ScanSummaryCategoryCounter
	}

	SCACounters struct {
		SeverityCounters       []ScanSummarySeverityCounter
		StatusCounters         []ScanSummaryStatusCounter
		StateCounters          []ScanSummaryStateCounter
		SeverityStatusCounters []ScanSummarySeverityStatusCounter
		SourceFileCounters     []ScanSummaryFileCounter
		AgeCounters            []ScanSummaryAgeCounter

		TotalCounter        uint64
		FilesScannedCounter uint64
	}

	SCAPackagesCounters struct {
		SeverityCounters       []ScanSummarySeverityCounter
		StatusCounters         []ScanSummaryStatusCounter
		StateCounters          []ScanSummaryStateCounter
		SeverityStatusCounters []ScanSummarySeverityStatusCounter
		SourceFileCounters     []ScanSummaryFileCounter
		AgeCounters            []ScanSummaryAgeCounter

		TotalCounter        uint64
		FilesScannedCounter uint64
		OutdatedCounter     uint64
		RiskLevelCounters   []ScanSummaryRiskLevelCounter
		LicenseCounters     []ScanSummaryLicenseCounter
		PackageCounters     []ScanSummaryPackageCounter
	}

	SCAContainersCounters struct {
		TotalPackagesCounters           uint64
		TotalVulnerabilitiesCounter     uint64
		SeverityVulnerabilitiesCounters []ScanSummarySeverityCounter
		StateVulnerabilityCounters      []ScanSummaryStateCounter
		StatusVulnerabilityCounters     []ScanSummaryStatusCounter
		AgeVulnerabilityCounters        []ScanSummaryAgeCounter
		PackageVulnerabilitiesCounters  []ScanSummaryPackageCounter
	}

	APISecCounters struct {
		SeverityCounters       []ScanSummarySeverityCounter
		StatusCounters         []ScanSummaryStatusCounter
		StateCounters          []ScanSummaryStateCounter
		SeverityStatusCounters []ScanSummarySeverityStatusCounter
		SourceFileCounters     []ScanSummaryFileCounter
		AgeCounters            []ScanSummaryAgeCounter

		TotalCounter        uint64
		FilesScannedCounter uint64
		RiskLevel           string
		APISecTotal         uint64
	}

	MicroEnginesCounters struct {
		SeverityCounters       []ScanSummarySeverityCounter
		StatusCounters         []ScanSummaryStatusCounter
		StateCounters          []ScanSummaryStateCounter
		SeverityStatusCounters []ScanSummarySeverityStatusCounter
		SourceFileCounters     []ScanSummaryFileCounter
		AgeCounters            []ScanSummaryAgeCounter

		TotalCounter        uint64
		FilesScannedCounter uint64
	}

	ContainersCounters struct {
		TotalPackagesCounter   uint64
		TotalCounter           uint64
		SeverityCounters       []ScanSummarySeverityCounter
		StatusCounters         []ScanSummaryStatusCounter
		StateCounters          []ScanSummaryStateCounter
		AgeCounters            []ScanSummaryAgeCounter
		PackageCounters        []ScanSummaryContainerPackageCounter
		SeverityStatusCounters []ScanSummarySeverityStatusCounter
	}
}

type ScanSummaryAgeCounter struct {
	Age              string
	SeverityCounters []ScanSummarySeverityCounter
	Counter          uint64
}
type ScanSummaryComplianceCounter struct {
	Compliance string
	Counter    uint64
}
type ScanSummaryFileCounter struct {
	File    string
	Counter uint64
}
type ScanSummaryLanguageCounter struct {
	Language string
	Counter  uint64
}
type ScanSummaryLicenseCounter struct {
	License string
	Counter uint64
}
type ScanSummaryPackageCounter struct {
	Package string
	Counter uint64
}
type ScanSummaryContainerPackageCounter struct {
	Package     string
	Counter     uint64
	IsMalicious bool
}
type ScanSummaryQueriesCounter struct {
	QueryID        uint64                     `json:"queryID"`
	Name           uint64                     `json:"queryName"`
	Severity       string                     `json:"severity"`
	StatusCounters []ScanSummaryStatusCounter `json:"statusCounters"`
	Counter        uint64                     `json:"counter"`
}
type ScanSummaryRiskLevelCounter struct {
	RiskLevel string
	Counter   uint64
}
type ScanSummarySeverityCounter struct {
	Severity string
	Counter  uint64
}
type ScanSummarySeverityStatusCounter struct {
	Severity string
	Status   string
	Counter  uint64
}
type ScanSummaryStateCounter struct {
	State   string
	Counter uint64
}
type ScanSummaryStatusCounter struct {
	Status  string
	Counter uint64
}

type ScanSummaryPlatformCounter struct {
	Platform string
	Counter  uint64
}
type ScanSummaryCategoryCounter struct {
	Category string
	Counter  uint64
}

type ScanSummaryFilter struct {
	BaseFilter
	ScanIDs        string   `url:"scan-ids"` // comma-separated list of scan ids
	SeverityStatus bool     `url:"include-severity-status"`
	Status         bool     `url:"include-status-counters"`
	Queries        bool     `url:"include-queries"`
	Files          bool     `url:"include-files"`
	Predicates     bool     `url:"apply-predicates"`
	Language       string   `url:"language"`
	ExcludeTypes   []string `url:"exclude-result-types"` // DEV_AND_TEST, NONE
}

type Status struct {
	ID      int               `json:"id"`
	Name    string            `json:"name"`
	Details ScanStatusDetails `json:"details"`
}

type Cx1LongTime struct {
	time.Time
}

type User struct {
	Enabled      bool        `json:"enabled"`
	UserID       string      `json:"id,omitempty"`
	FirstName    string      `json:"firstName"`
	LastName     string      `json:"lastName"`
	UserName     string      `json:"username"`
	Email        string      `json:"email"`
	LastLogin    Cx1LongTime `json:"-"`
	Groups       []Group     `json:"-"` // only returned from /users/{id}/groups. Use GetUserGroups to fill.
	FilledGroups bool        `json:"-"` // indicates if the user object has had the Groups array filled.
	Roles        []Role      `json:"-"` // only returned from /users/{id}/role-mappings. Use GetUserRoles to fill.
	FilledRoles  bool        `json:"-"` // indicates if the user object has had the Roles array filled.
}

type UserFilter struct {
	BaseIAMFilter
	BriefRepresentation bool   `url:"briefRepresentation,omitempty"` // only used by GetUser* (not GetUserCount)
	Email               string `url:"email,omitempty"`
	EmailVerified       bool   `url:"emailVerified,omitempty"`
	Enabled             bool   `url:"enabled,omitempty"`
	Exact               bool   `url:"exact,omitempty"` // only used by GetUser* (not GetUserCount)
	FirstName           string `url:"firstName,omitempty"`
	IDPAlias            string `url:"idpAlias,omitempty"`  // only used by GetUser* (not GetUserCount)
	IDPUserId           string `url:"idpUserId,omitempty"` // only used by GetUser* (not GetUserCount)
	Q                   string `url:"q,omitempty"`
	Search              string `url:"search,omitempty"`
	Username            string `url:"username,omitempty"`
	Realm               string `url:"realm"`
}

type UserWithAttributes struct {
	User
	Attributes struct {
		LastLogin []Cx1LongTime `json:"lastLogin"`
	} `json:"attributes"`
}

type VersionInfo struct {
	CxOne string
	KICS  string
	SAST  string
}

type WhoAmI struct {
	UserID string `json:"userId"`
	Name   string `json:"displayName"`
}

type WorkflowLog struct {
	Source    string `json:"Source"`
	Info      string `json:"Info"`
	Timestamp string `json:"Timestamp"`
}
