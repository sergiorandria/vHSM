package internal

import (
	"crypto/tls"
	"fmt"

	"github.com/go-ldap/ldap/v3"
)

// LDAPConfig holds everything needed to talk to one organization's
// OpenLDAP directory (see generate-network.sh / README.md for the
// directory layout this expects — one LDAP per org, pre-populated with
// the same identities as the Fabric-CA registry).
type LDAPConfig struct {
	URL          string // e.g. "ldap://ldap.misa.university.com:1389"
	BindDN       string // service account used to search the directory, e.g. "cn=admin,dc=misa,dc=university,dc=com"
	BindPassword string
	UserBaseDN   string // e.g. "ou=users,dc=misa,dc=university,dc=com"
	UserFilter   string // e.g. "(uid=%s)" — %s is replaced with the submitted username
	GroupBaseDN  string // e.g. "ou=groups,dc=misa,dc=university,dc=com"
	GroupFilter  string // e.g. "(member=%s)" — %s is replaced with the user's DN
	RoleAttr     string // attribute on the group entry that names the role, e.g. "cn"
	UseTLS       bool
	InsecureSkip bool // skip TLS cert verification — dev only
}

// AuthenticatedUser is what the rest of the API needs once LDAP has
// confirmed a username/password pair and resolved group membership.
type AuthenticatedUser struct {
	Username string
	DN       string
	Roles    []string
}

type LDAPAuthService struct {
	cfg LDAPConfig
}

func NewLDAPAuthService(cfg LDAPConfig) *LDAPAuthService {
	return &LDAPAuthService{cfg: cfg}
}

func (s *LDAPAuthService) dial() (*ldap.Conn, error) {
	if s.cfg.UseTLS {
		tlsCfg := &tls.Config{InsecureSkipVerify: s.cfg.InsecureSkip}
		return ldap.DialURL(s.cfg.URL, ldap.DialWithTLSConfig(tlsCfg))
	}
	return ldap.DialURL(s.cfg.URL)
}

// Authenticate implements the standard "search then bind" LDAP login
// pattern:
//  1. bind as a service account and search for the user's DN by uid
//  2. open a *second* connection and bind as that DN with the password the
//     caller supplied — this is the actual credential check
//  3. search for the groups the user belongs to, to resolve roles
func (s *LDAPAuthService) Authenticate(username, password string) (*AuthenticatedUser, error) {
	if username == "" || password == "" {
		return nil, fmt.Errorf("username and password are required")
	}

	conn, err := s.dial()
	if err != nil {
		return nil, fmt.Errorf("ldap dial failed: %w", err)
	}
	defer conn.Close()

	if err := conn.Bind(s.cfg.BindDN, s.cfg.BindPassword); err != nil {
		return nil, fmt.Errorf("service account bind failed: %w", err)
	}

	searchReq := ldap.NewSearchRequest(
		s.cfg.UserBaseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		fmt.Sprintf(s.cfg.UserFilter, ldap.EscapeFilter(username)),
		[]string{"dn", "uid", "cn"},
		nil,
	)

	result, err := conn.Search(searchReq)
	if err != nil {
		return nil, fmt.Errorf("user search failed: %w", err)
	}
	if len(result.Entries) != 1 {
		return nil, fmt.Errorf("user %q not found or ambiguous", username)
	}
	userDN := result.Entries[0].DN

	// Second connection: verify the password by binding as the user itself.
	// Never reuse the service-account connection for this — a failed bind
	// can leave a connection in a bad state, and mixing the two identities
	// on one connection is a classic LDAP-auth foot-gun.
	userConn, err := s.dial()
	if err != nil {
		return nil, fmt.Errorf("ldap dial failed: %w", err)
	}
	defer userConn.Close()

	if err := userConn.Bind(userDN, password); err != nil {
		return nil, fmt.Errorf("invalid credentials")
	}

	roles, err := s.lookupRoles(conn, userDN)
	if err != nil {
		return nil, fmt.Errorf("role lookup failed: %w", err)
	}

	return &AuthenticatedUser{Username: username, DN: userDN, Roles: roles}, nil
}

func (s *LDAPAuthService) lookupRoles(conn *ldap.Conn, userDN string) ([]string, error) {
	searchReq := ldap.NewSearchRequest(
		s.cfg.GroupBaseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		fmt.Sprintf(s.cfg.GroupFilter, ldap.EscapeFilter(userDN)),
		[]string{s.cfg.RoleAttr},
		nil,
	)

	result, err := conn.Search(searchReq)
	if err != nil {
		return nil, err
	}

	roles := make([]string, 0, len(result.Entries))
	for _, entry := range result.Entries {
		if v := entry.GetAttributeValue(s.cfg.RoleAttr); v != "" {
			roles = append(roles, v)
		}
	}
	return roles, nil
}
