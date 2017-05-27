package rbac_test

import (
	"context"
	"sync"
	"testing"

	"github.com/go-qbit/rbac"
	"github.com/stretchr/testify/assert"
)

type storage struct {
	roleId          int
	roles           map[int]string
	rolePermissions map[int]map[string]struct{}
	userRoles       map[int]map[int]struct{}
	mtx             sync.RWMutex
}

func newStorage() *storage {
	return &storage{
		roleId:          0,
		roles:           make(map[int]string),
		rolePermissions: make(map[int]map[string]struct{}),
		userRoles:       make(map[int]map[int]struct{}),
	}
}

func (s *storage) AddRole(ctx context.Context, caption string) (interface{}, error) {
	s.mtx.Lock()
	defer s.mtx.Unlock()

	s.roles[s.roleId] = caption

	s.roleId++

	return s.roleId - 1, nil
}

func (s *storage) GetRoles(ctx context.Context, ids ...interface{}) ([]rbac.RoleDescription, error) {
	s.mtx.RLock()
	defer s.mtx.RUnlock()

	resLen := len(ids)
	if resLen == 0 {
		resLen = len(s.roles)
	}

	res := make([]rbac.RoleDescription, 0, resLen)

	if resLen == 0 {
		for id, caption := range s.roles {
			res = append(res, rbac.RoleDescription{id, caption})
		}
	} else {
		for _, id := range ids {
			if caption, exists := s.roles[id.(int)]; exists {
				res = append(res, rbac.RoleDescription{id, caption})
			}
		}
	}

	return res, nil
}

func (s *storage) AddRolesPermissions(ctx context.Context, rolesPermissions ...rbac.RolePermission) error {
	s.mtx.Lock()
	defer s.mtx.Unlock()

	for i := range rolesPermissions {
		rolePermissions, exist := s.rolePermissions[rolesPermissions[i].RoleId.(int)]
		if !exist {
			rolePermissions = make(map[string]struct{})
			s.rolePermissions[rolesPermissions[i].RoleId.(int)] = rolePermissions
		}

		rolePermissions[rolesPermissions[i].PermissionId] = struct{}{}
	}

	return nil
}

func (s *storage) RevokeRolesPermissions(ctx context.Context, rolesPermissions ...rbac.RolePermission) error {
	s.mtx.Lock()
	defer s.mtx.Unlock()

	for i := range rolesPermissions {
		delete(s.rolePermissions[rolesPermissions[i].RoleId.(int)], rolesPermissions[i].PermissionId)
	}

	return nil
}

func (s *storage) GetRolesPermissions(ctx context.Context, rolesIds ...interface{}) ([]string, error) {
	s.mtx.RLock()
	defer s.mtx.RUnlock()

	res := make([]string, 0)
	for _, id := range rolesIds {
		for permissionId, _ := range s.rolePermissions[id.(int)] {
			res = append(res, permissionId)
		}
	}

	return res, nil
}

func (s *storage) AddUserRoles(ctx context.Context, usersRoles ...rbac.UserRole) error {
	s.mtx.Lock()
	defer s.mtx.Unlock()

	for i := range usersRoles {
		userRoles, exist := s.userRoles[usersRoles[i].RoleId.(int)]
		if !exist {
			userRoles = make(map[int]struct{})
			s.userRoles[usersRoles[i].RoleId.(int)] = userRoles
		}

		userRoles[usersRoles[i].RoleId.(int)] = struct{}{}
	}

	return nil
}

func (s *storage) RevokeUserRoles(ctx context.Context, usersRoles ...rbac.UserRole) error {
	s.mtx.Lock()
	defer s.mtx.Unlock()

	for i := range usersRoles {
		delete(s.userRoles[usersRoles[i].UserId.(int)], usersRoles[i].RoleId.(int))
	}

	return nil
}

func (s *storage) GetUserRoles(ctx context.Context, userId interface{}) ([]interface{}, error) {
	s.mtx.RLock()
	defer s.mtx.RUnlock()

	res := make([]interface{}, 0)
	for roleId, _ := range s.userRoles[userId.(int)] {
		res = append(res, roleId)
	}

	return res, nil
}

var role1, role2 interface{}

func init() {
	rbac.SetStorage(newStorage())

	role1, _ = rbac.RegisterRole(context.Background(), "Role 1")
	role2, _ = rbac.RegisterRole(context.Background(), "Role 2")

	rbac.RegisterPermissionsGroup("test", "Test group",
		rbac.NewPermission("perm1", "Permission1"),
		rbac.NewPermission("perm2", "Permission2"),
		rbac.NewPermission("perm3", "Permission3"),
	)
}

func TestRBAC_GetRole(t *testing.T) {
	role, err := rbac.GetRole(context.Background(), role1)
	if !(assert.NoError(t, err) && assert.NotNil(t, role)) {
		return
	}

	assert.EqualValues(t, role1, role.GetId())
	assert.Equal(t, "Role 1", role.GetCaption())
}

func TestRBAC_GetPermissionsGroup(t *testing.T) {
	pg := rbac.GetPermissionsGroup("test")
	if !assert.NotNil(t, pg) {
		return
	}

	assert.Equal(t, "test", pg.GetId())
	assert.Equal(t, "Test group", pg.GetCaption())
	assert.NotNil(t, pg.GetAllPermissions())
}

func TestRBAC_GetPermission(t *testing.T) {
	p := rbac.GetPermission("test.perm1")
	if !assert.NotNil(t, p) {
		return
	}

	assert.Equal(t, "perm1", p.GetId())
	assert.Equal(t, "Permission1", p.GetCaption())
	assert.Equal(t, "test", p.GetGroupId())
}

func TestRBAC_SetRolePermissions(t *testing.T) {
	assert.NoError(t, rbac.AddRolePermissions(context.Background(), role1, "test.perm1"))
	assert.NoError(t, rbac.AddRolePermissions(context.Background(), role2, "test.perm1", "test.perm3"))
}

func TestRBAC_SetUserRoles(t *testing.T) {
	TestRBAC_SetRolePermissions(t)

	assert.NoError(t, rbac.AddUserRoles(context.Background(), 1, role1, role2))
	assert.NoError(t, rbac.AddUserRoles(context.Background(), 2, role1))
}

func TestRBAC_CheckPermission(t *testing.T) {
	TestRBAC_SetUserRoles(t)

	ctx, err := rbac.ContextWithPermissions(context.Background(), 1)
	assert.NoError(t, err)

	res, err := rbac.CheckPermission(ctx, "test.perm1")
	assert.NoError(t, err)
	assert.True(t, res)

	res, err = rbac.CheckPermission(ctx, "test.perm2")
	assert.NoError(t, err)
	assert.False(t, res)
}
