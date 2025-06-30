package salesforce

import (
	"sync"
)

const (
	ResourceTypeProject     = "Project"
	ResourceTypeBoard       = "Board"
	ResourceTypeGroup       = "Group"
	ResourceTypeIssue       = "Issue"
	ResourceTypeUser        = "User"
	ResourceTypeAuditRecord = "AuditRecord"
)

var ResourcePermissions = map[string][]Permission{
	ResourceTypeProject: {
		Profile,
	},
}

type SecretInfo struct {
	mu sync.RWMutex

	UserInfo    SalesforceUser
	Permissions []string
	Resources   []SalesforceResource
}

type SalesforceUser struct {
	Sub                         string `json:"sub"`
	UserID                      string `json:"user_id"`
	OrganizationID              string `json:"organization_id"`
	PreferredUsername           string `json:"preferred_username"`
	Nickname                    string `json:"nickname"`
	Name                        string `json:"name"`
	Email                       string `json:"email"`
	EmailVerified               bool   `json:"email_verified"`
	GivenName                   string `json:"given_name"`
	FamilyName                  string `json:"family_name"`
	Zoneinfo                    string `json:"zoneinfo"`
	Profile                     string `json:"profile"`
	Picture                     string `json:"picture"`
	IsSalesforceIntegrationUser bool   `json:"is_salesforce_integration_user"`
	Active                      bool   `json:"active"`
	UserType                    string `json:"user_type"`
	Language                    string `json:"language"`
	Locale                      string `json:"locale"`
	UpdatedAt                   string `json:"updated_at"`
}

type SalesforceResource struct {
	ID          string
	Name        string
	Type        string
	Metadata    map[string]string
	Parent      *SalesforceResource
	Permissions []string
}

func (s *SecretInfo) appendResource(resource SalesforceResource, resourceType string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if perms, ok := ResourcePermissions[resourceType]; ok {
		for _, p := range perms {
			if userPerms[p] {
				resource.Permissions = append(resource.Permissions, PermissionStrings[p])
			}
		}
	}

	s.Resources = append(s.Resources, resource)
}

type SalesforcePermissionsResponse struct {
	Permissions map[string]SalesforcePermission `json:"permissions"`
}

type SalesforcePermission struct {
	ID             string `json:"id"`
	Key            string `json:"key"`
	Name           string `json:"name"`
	Type           string `json:"type"`
	Description    string `json:"description"`
	HavePermission bool   `json:"havePermission"`
}

type ProjectSearchResponse struct {
	MaxResults int           `json:"maxResults"`
	Total      int           `json:"total"`
	IsLast     bool          `json:"isLast"`
	Values     []Project `json:"values"`
}

type Project struct {
	ID             string `json:"id"`
	Key            string `json:"key"`
	Name           string `json:"name"`
	ProjectTypeKey string `json:"projectTypeKey"`
	IsPrivate      bool   `json:"isPrivate"`
	UUID           string `json:"uuid"`
}

type Issue struct {
	Issues []struct {
		ID     string `json:"id"`
		Key    string `json:"key"`
		Fields struct {
			Summary string `json:"summary"`
			Status  struct {
				Name string `json:"name"`
			} `json:"status"`
			IssueType struct {
				Name string `json:"name"`
			} `json:"issuetype"`
		} `json:"fields"`
	} `json:"issues"`
}

type Board struct {
	Values []struct {
		ID        int    `json:"id"`
		Name      string `json:"name"`
		Type      string `json:"type"`
		Self      string `json:"self"`
		IsPrivate bool   `json:"isPrivate"`
		Location  struct {
			ProjectID      int    `json:"projectId"`
			DisplayName    string `json:"displayName"`
			ProjectName    string `json:"projectName"`
			ProjectKey     string `json:"projectKey"`
			ProjectTypeKey string `json:"projectTypeKey"`
			AvatarURI      string `json:"avatarURI"`
			Name           string `json:"name"`
		} `json:"location"`
	} `json:"values"`
}

type Group struct {
	Total  int `json:"total"`
	Groups []struct {
		Name    string `json:"name"`
		HTML    string `json:"html"`
		GroupID string `json:"groupId"`
		Labels  []struct {
			Text  string `json:"text"`
			Title string `json:"title"`
			Type  string `json:"type"`
		} `json:"labels"`
	} `json:"groups"`
}

type AuditRecord struct {
	Offset  int `json:"offset"`
	Limit   int `json:"limit"`
	Total   int `json:"total"`
	Records []struct {
		ID            int    `json:"id"`
		Summary       string `json:"summary"`
		Created       string `json:"created"`
		Category      string `json:"category"`
		EventSource   string `json:"eventSource"`
		RemoteAddress string `json:"remoteAddress,omitempty"`
		AuthorKey     string `json:"authorKey,omitempty"`
		AuthorAccount string `json:"authorAccountId,omitempty"`

		ObjectItem struct {
			ID         string `json:"id,omitempty"`
			Name       string `json:"name"`
			TypeName   string `json:"typeName"`
			ParentID   string `json:"parentId,omitempty"`
			ParentName string `json:"parentName,omitempty"`
		} `json:"objectItem"`

		AssociatedItems []struct {
			ID         string `json:"id"`
			Name       string `json:"name"`
			TypeName   string `json:"typeName"`
			ParentID   string `json:"parentId"`
			ParentName string `json:"parentName"`
		} `json:"associatedItems"`

		ChangedValues []struct {
			FieldName string `json:"fieldName"`
			ChangedTo string `json:"changedTo"`
		} `json:"changedValues"`
	} `json:"records"`
}
