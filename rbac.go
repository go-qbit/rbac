package rbac

import (
	"context"
	"strings"
	"sync"

	"github.com/go-qbit/qerror"
)

type keyType string

var userPermissionsKey = keyType("permissions")

type userPermissions struct {
	permissions map[string]struct{}
}

type RBAC struct {
	roles             map[string]*Role
	permissionsGroups map[string]*PermissionsGroup
	mtx               sync.RWMutex
	storage           IStorage
}

func New(storage IStorage) *RBAC {
	return &RBAC{
		roles:             make(map[string]*Role),
		permissionsGroups: make(map[string]*PermissionsGroup),
		storage:           storage,
	}
}

func (r *RBAC) RegisterRole(ctx context.Context, caption string) (interface{}, error) {
	return r.storage.AddRole(ctx, caption)
}

func (r *RBAC) GetRoles(ctx context.Context, ids ...interface{}) ([]*Role, error) {
	roles, err := r.storage.GetRoles(ctx, ids...)
	if err != nil {
		return nil, err
	}

	res := make([]*Role, len(roles))

	for i := range roles {
		res[i] = &Role{roles[i].Id, roles[i].Caption}
	}

	return res, nil
}

func (r *RBAC) GetRole(ctx context.Context, id interface{}) (*Role, error) {
	roles, err := r.GetRoles(ctx, id)
	if err != nil {
		return nil, err
	}

	if len(roles) == 0 {
		return nil, nil
	}

	return roles[0], nil
}

func (r *RBAC) NewPermission(id, caption string) *Permission {
	return &Permission{
		id:      id,
		caption: caption,
	}
}

func (r *RBAC) RegisterPermissionsGroup(id, caption string, permissions ...*Permission) error {
	pg := &PermissionsGroup{
		id:      id,
		caption: caption,
	}

	for _, p := range permissions {
		if err := pg.RegisterPermission(p); err != nil {
			return nil
		}
	}

	r.mtx.Lock()
	defer r.mtx.Unlock()

	if _, exists := r.permissionsGroups[id]; exists {
		return qerror.Errorf("Permissions group with id '%s' exists")
	}

	r.permissionsGroups[id] = pg

	return nil
}

func (r *RBAC) GetPermissionsGroup(id string) *PermissionsGroup {
	r.mtx.RLock()
	defer r.mtx.RUnlock()

	return r.permissionsGroups[id]
}

func (r *RBAC) GetPermission(id string) *Permission {
	splitted := strings.SplitN(id, ".", 2)

	group := r.GetPermissionsGroup(splitted[0])
	if group == nil {
		return nil
	}

	return group.GetPermission(splitted[1])
}

func (r *RBAC) GetAllPermissionsGroups() []*PermissionsGroup {
	r.mtx.RLock()
	defer r.mtx.RUnlock()

	res := make([]*PermissionsGroup, 0, len(r.permissionsGroups))

	for _, g := range r.permissionsGroups {
		res = append(res, g)
	}

	return res
}

func (r *RBAC) AddRolePermissions(ctx context.Context, roleId interface{}, permissionsIds ...string) error {
	for _, id := range permissionsIds {
		if r.GetPermission(id) == nil {
			return qerror.Errorf("Permission with id `%s` does not exists", id)
		}
	}

	rolesPermissions := make([]RolePermission, len(permissionsIds))
	for i, permissionId := range permissionsIds {
		rolesPermissions[i].RoleId = roleId
		rolesPermissions[i].PermissionId = permissionId
	}

	return r.storage.AddRolesPermissions(ctx, rolesPermissions...)
}

func (r *RBAC) RevokeRolePermissions(ctx context.Context, roleId interface{}, permissionsIds ...string) error {
	rolesPermissions := make([]RolePermission, len(permissionsIds))
	for i, permissionId := range permissionsIds {
		rolesPermissions[i].RoleId = roleId
		rolesPermissions[i].PermissionId = permissionId
	}

	return r.storage.RevokeRolesPermissions(ctx, rolesPermissions...)
}

func (r *RBAC) GetRolesPermissions(ctx context.Context, roleIds ...interface{}) ([]string, error) {
	return r.storage.GetRolesPermissions(ctx, roleIds...)
}

func (r *RBAC) AddUserRoles(ctx context.Context, userId interface{}, rolesIds ...interface{}) error {
	userRoles := make([]UserRole, len(rolesIds))
	for i, roleId := range rolesIds {
		userRoles[i] = UserRole{userId, roleId}
	}

	return r.storage.AddUserRoles(ctx, userRoles...)
}

func (r *RBAC) RevokeUserRoles(ctx context.Context, userId interface{}, rolesIds ...interface{}) error {
	userRoles := make([]UserRole, len(rolesIds))
	for i, roleId := range rolesIds {
		userRoles[i] = UserRole{userId, roleId}
	}

	return r.storage.RevokeUserRoles(ctx, userRoles...)
}

func (r *RBAC) GetUserRolesIds(ctx context.Context, userId interface{}) ([]interface{}, error) {
	return r.storage.GetUserRoles(ctx, userId)
}

func (r *RBAC) ContextWithPermissions(ctx context.Context, user_id interface{}) (context.Context, error) {
	roles, err := r.storage.GetUserRoles(ctx, user_id)
	if err != nil {
		return ctx, err
	}

	rolesPermissions, err := r.storage.GetRolesPermissions(ctx, roles...)
	if err != nil {
		return ctx, err
	}

	up := &userPermissions{
		permissions: make(map[string]struct{}, len(rolesPermissions)),
	}

	for _, permissionId := range rolesPermissions {
		up.permissions[permissionId] = struct{}{}
	}

	return context.WithValue(ctx, userPermissionsKey, up), nil
}

func (r *RBAC) CheckPermission(ctx context.Context, id string) (bool, error) {
	ctxUp := ctx.Value(userPermissionsKey)
	if ctxUp == nil {
		return false, qerror.Errorf("Context does not have user permission info")
	}

	up := ctxUp.(*userPermissions)

	_, exists := up.permissions[id]

	return exists, nil
}
