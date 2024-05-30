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
	baseUrl string
	iamUrl  string
	tenant  string
	logger  *logrus.Logger
	flags   map[string]bool // initial implementation ignoring "payload" part of the flag
	consts  ClientVars
	claims  Cx1Claims
	user    *User
}

type Cx1Claims struct {
	jwt.RegisteredClaims
	Cx1License    ASTLicense `json:"ast-license"`
	IsServiceUser string     `json:"is-service-user"`
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
	Cwe             int64
	IsExecutable    bool  `json:"executable"`
	CxDescriptionID int64 `json:"description"`
	Language        string
	Group           string
	Severity        string
	SastID          uint64
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
	GroupID     string              `json:"id"`
	Name        string              `json:"name"`
	Path        string              `json:"path"`
	SubGroups   []Group             `json:"subGroups"`
	ClientRoles map[string][]string `json:"clientRoles"`
	Filled      bool                `json:"-"`
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
	LevelID            string `json:"-"`
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

type QueryUpdate struct { // used when saving queries in Cx1
	Name     string              `json:"name"`
	Path     string              `json:"path"`
	Source   string              `json:"source"`
	Metadata QueryUpdateMetadata `json:"metadata"`
}
type QueryUpdateMetadata struct {
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
	ProjectID string   `json:"project-id"`
	Limit     int      `json:"limit"`
	Offset    int      `json:"offset"`
	Sort      string   `json:"sort"`
	TagKeys   []string `json:"tags-keys"`
	TagValues []string `json:"tags-values"`
	Statuses  []string `json:"statuses"`
	Branches  []string `json:"branches"`
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
		//QueriesCounters           []?
		//SinkFileCounters          []?
		LanguageCounters []struct {
			Language string
			Counter  uint64
		}
		ComplianceCounters []struct {
			Compliance string
			Counter    uint64
		}
		SeverityCounters []struct {
			Severity string
			Counter  uint64
		}
		StatusCounters []struct {
			Status  string
			Counter uint64
		}
		StateCounters []struct {
			State   string
			Counter uint64
		}
		TotalCounter        uint64
		FilesScannedCounter uint64
	}
	// ignoring the other counters
	// KICSCounters
	// SCACounters
	// SCAPackagesCounters
	// SCAContainerCounters
	// APISecCounters
}

type Status struct {
	ID      int               `json:"id"`
	Name    string            `json:"name"`
	Details ScanStatusDetails `json:"details"`
}

type User struct {
	Enabled      bool    `json:"enabled"`
	UserID       string  `json:"id,omitempty"`
	FirstName    string  `json:"firstName"`
	LastName     string  `json:"lastName"`
	UserName     string  `json:"username"`
	Email        string  `json:"email"`
	Groups       []Group `json:"-"` // only returned from /users/{id}/groups. Use GetUserGroups to fill.
	FilledGroups bool    `json:"-"` // indicates if the user object has had the Groups array filled.
	Roles        []Role  `json:"-"` // only returned from /users/{id}/role-mappings. Use GetUserRoles to fill.
	FilledRoles  bool    `json:"-"` // indicates if the user object has had the Roles array filled.
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
