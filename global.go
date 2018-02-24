package rbac

import "context"

var globalRbac = New(nil)

func SetStorage(s IStorage) {
	globalRbac.storage = s
}

func RegisterRole(ctx context.Context, caption string) (interface{}, error) {
	return globalRbac.RegisterRole(ctx, caption)
}

func GetRoles(ctx context.Context, ids ...interface{}) ([]*Role, error) {
	return globalRbac.GetRoles(ctx, ids...)
}

func GetRole(ctx context.Context, id interface{}) (*Role, error) {
	return globalRbac.GetRole(ctx, id)
}

func NewPermission(id, caption string) *Permission {
	return globalRbac.NewPermission(id, caption)
}

func RegisterPermissionsGroup(id, caption string, permissions ...*Permission) error {
	return globalRbac.RegisterPermissionsGroup(id, caption, permissions...)
}

func GetPermissionsGroup(id string) *PermissionsGroup {
	return globalRbac.GetPermissionsGroup(id)
}

func GetPermission(id string) *Permission {
	return globalRbac.GetPermission(id)
}

func GetAllPermissionsGroups() []*PermissionsGroup {
	return globalRbac.GetAllPermissionsGroups()
}

func AddRolePermissions(ctx context.Context, roleId interface{}, permissionsIds ...string) error {
	return globalRbac.AddRolePermissions(ctx, roleId, permissionsIds...)
}

func RevokeRolePermissions(ctx context.Context, roleId interface{}, permissionsIds ...string) error {
	return globalRbac.RevokeRolePermissions(ctx, roleId, permissionsIds...)
}

func GetRolesPermissions(ctx context.Context, roleIds ...interface{}) ([]string, error) {
	return globalRbac.GetRolesPermissions(ctx, roleIds...)
}

func AddUserRoles(ctx context.Context, userId interface{}, rolesIds ...interface{}) error {
	return globalRbac.AddUserRoles(ctx, userId, rolesIds...)
}

func RevokeUserRoles(ctx context.Context, userId interface{}, rolesIds ...interface{}) error {
	return globalRbac.RevokeUserRoles(ctx, userId, rolesIds...)
}

func GetUserRolesIds(ctx context.Context, userId interface{}) ([]interface{}, error) {
	return globalRbac.GetUserRolesIds(ctx, userId)
}

func ContextWithPermissions(ctx context.Context, user_id interface{}) (context.Context, error) {
	return globalRbac.ContextWithPermissions(ctx, user_id)
}

func HasPermission(ctx context.Context, permission *Permission) bool {
	return globalRbac.HasPermission(ctx, permission)
}

func HasAnyPermissions(ctx context.Context, permissions ...*Permission) bool {
	return globalRbac.HasAnyPermissions(ctx, permissions...)
}

func HasAllPermissions(ctx context.Context, permissions ...*Permission) bool {
	return globalRbac.HasAllPermissions(ctx, permissions...)
}
