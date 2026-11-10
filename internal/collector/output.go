package collector

// SchemaVersion is the version of docs/schema/v1.0.0.json, which describes
// Output. It stays 1.0.0 until the collector itself reaches v1.0.0.
const SchemaVersion = "1.0.0"

// Output is the artifact the collector emits at artifactPath. A part whose
// read failed is left out, with a gap in the collector result. The
// inventories are left out below the audit level.
type Output struct {
	SchemaVersion    string           `json:"schema_version"`
	CollectedAt      string           `json:"collected_at"`
	CollectedAtLevel string           `json:"collected_at_level"`
	Workspace        Workspace        `json:"workspace"`
	Members          *Members         `json:"members,omitempty"`
	Environments     *Environments    `json:"environments,omitempty"`
	ServiceUsers     *ServiceUsers    `json:"service_users,omitempty"`
	ProxyAuthTokens  *ProxyAuthTokens `json:"proxy_auth_tokens,omitempty"`
	Secrets          *Secrets         `json:"secrets,omitempty"`
	Apps             *Apps            `json:"apps,omitempty"`
}

// Workspace is the workspace the token belongs to. Its ID is left out below
// the audit level.
type Workspace struct {
	ID   string `json:"id,omitempty"`
	Name string `json:"name"`
}

// Members rolls up the workspace's members.
type Members struct {
	TotalCount   int `json:"total_count"`
	OwnerCount   int `json:"owner_count"`
	ManagerCount int `json:"manager_count"`
	MemberCount  int `json:"member_count"`
	// SignIn counts members by how they sign in.
	SignIn SignInCounts `json:"sign_in"`
	// InactiveCount counts members with no activity in the last
	// inactiveDays days, including members never active.
	InactiveCount int      `json:"inactive_count"`
	Inventory     []Member `json:"inventory,omitzero"`
}

// SignInCounts counts members by the identity provider they sign in with.
type SignInCounts struct {
	GitHubCount int `json:"github_count"`
	GoogleCount int `json:"google_count"`
	SAMLCount   int `json:"saml_count"`
	OtherCount  int `json:"other_count"`
}

// Member is one row of the members inventory.
type Member struct {
	Name         string  `json:"name"`
	Email        string  `json:"email"`
	Role         string  `json:"role"`
	SignIn       string  `json:"sign_in"`
	JoinedAt     *string `json:"joined_at"`
	LastActiveAt *string `json:"last_active_at"`
	Inactive     bool    `json:"inactive"`
}

// Environments rolls up the environments the token can see.
type Environments struct {
	TotalCount      int           `json:"total_count"`
	RestrictedCount int           `json:"restricted_count"`
	Inventory       []Environment `json:"inventory,omitzero"`
}

// Environment is one row of the environments inventory.
type Environment struct {
	Name       string  `json:"name"`
	Default    bool    `json:"default"`
	Restricted bool    `json:"restricted"`
	CreatedAt  *string `json:"created_at"`
	// DefaultMemberRole is the role a Member gets in a restricted
	// environment without a role of their own. Null when Modal sends none.
	DefaultMemberRole *string `json:"default_member_role"`
	// BlocksUnauthenticated is whether the environment refuses new web
	// endpoints that anyone can call. Null when the environment inherits
	// the workspace's setting, which the API does not report.
	BlocksUnauthenticated *bool `json:"blocks_unauthenticated"`
	// Roles lists who holds a role of their own in a restricted
	// environment. Null for an environment that isn't restricted.
	Roles []RoleGrant `json:"roles"`
}

// RoleGrant is a member's or a service user's role in an environment.
type RoleGrant struct {
	Principal string `json:"principal"`
	Kind      string `json:"kind"`
	Role      string `json:"role"`
}

// ServiceUsers rolls up the workspace's service users, which only the Team
// and Enterprise plans have.
type ServiceUsers struct {
	TotalCount     int           `json:"total_count"`
	NeverUsedCount int           `json:"never_used_count"`
	Inventory      []ServiceUser `json:"inventory,omitzero"`
}

// ServiceUser is one row of the service users inventory.
type ServiceUser struct {
	Name       string  `json:"name"`
	CreatedBy  *string `json:"created_by"`
	CreatedAt  *string `json:"created_at"`
	LastUsedAt *string `json:"last_used_at"`
	NeverUsed  bool    `json:"never_used"`
}

// ProxyAuthTokens rolls up the tokens that callers of a proxy-auth web
// endpoint present.
type ProxyAuthTokens struct {
	TotalCount int `json:"total_count"`
	// UnscopedCount counts tokens that work for proxy-auth endpoints in
	// every environment.
	UnscopedCount int              `json:"unscoped_count"`
	Inventory     []ProxyAuthToken `json:"inventory,omitzero"`
}

// ProxyAuthToken is one row of the proxy auth tokens inventory.
type ProxyAuthToken struct {
	Name      string  `json:"name"`
	CreatedBy *string `json:"created_by"`
	CreatedAt *string `json:"created_at"`
	Scoped    bool    `json:"scoped"`
	// Environments lists the environments a scoped token works in. Null
	// for an unscoped token.
	Environments []string `json:"environments"`
}

// Secrets rolls up the secrets in every environment the token can see.
type Secrets struct {
	TotalCount     int      `json:"total_count"`
	NeverUsedCount int      `json:"never_used_count"`
	Inventory      []Secret `json:"inventory,omitzero"`
}

// Secret is one row of the secrets inventory, without its values.
type Secret struct {
	Name        string   `json:"name"`
	Environment string   `json:"environment"`
	CreatedBy   *string  `json:"created_by"`
	CreatedAt   *string  `json:"created_at"`
	LastUsedAt  *string  `json:"last_used_at"`
	NeverUsed   bool     `json:"never_used"`
	Keys        []string `json:"keys"`
}

// Apps rolls up the apps in every environment the token can see. The
// counts cover deployed apps.
type Apps struct {
	DeployedCount int `json:"deployed_count"`
	// WebEndpointCount counts deployed apps' functions that serve web
	// requests.
	WebEndpointCount int `json:"web_endpoint_count"`
	// UnauthenticatedEndpointCount counts those that anyone with the URL
	// can call, with no proxy auth token.
	UnauthenticatedEndpointCount int   `json:"unauthenticated_endpoint_count"`
	ScheduledFunctionCount       int   `json:"scheduled_function_count"`
	Inventory                    []App `json:"inventory,omitzero"`
}

// App is one row of the apps inventory. Its function counts are null for
// an app that isn't deployed, since the collector reads functions of
// deployed apps only.
type App struct {
	Name                     string  `json:"name"`
	Environment              string  `json:"environment"`
	State                    string  `json:"state"`
	CreatedAt                *string `json:"created_at"`
	WebEndpoints             *int    `json:"web_endpoints"`
	UnauthenticatedEndpoints *int    `json:"unauthenticated_endpoints"`
	ScheduledFunctions       *int    `json:"scheduled_functions"`
}
