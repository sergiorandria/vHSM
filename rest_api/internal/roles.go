package internal

// Role names as they should appear as LDAP group CNs. Adjust these to
// match whatever your LDIF bootstrap in generate-network.sh actually
// names the groups — these are placeholders.
const (
	RoleAdmin     = "admin"
	RoleProfessor = "professeurs"
	RoleStudent   = "etudiants"
)

// actionPermissions maps an application-level action (usually 1:1 with a
// chaincode function, but it doesn't have to be) to the roles allowed to
// perform it. Add one entry here per protected action — anything not
// listed is denied by default (fail closed).
var actionPermissions = map[string][]string{
	"CreateThesis":   {RoleAdmin, RoleProfessor},
	"SubmitDocument": {RoleAdmin, RoleProfessor},
	"ReadThesis":     {RoleAdmin, RoleProfessor, RoleStudent},
}

// HasPermission reports whether any of the user's roles is allowed to
// perform the given action.
func HasPermission(userRoles []string, action string) bool {
	allowed, ok := actionPermissions[action]
	if !ok {
		return false
	}
	for _, r := range userRoles {
		for _, a := range allowed {
			if r == a {
				return true
			}
		}
	}
	return false
}