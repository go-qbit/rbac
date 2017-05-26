package rbac

import "context"

type RoleDescription struct {
	Id      interface{}
	Caption string
}

type RolePermission struct {
	RoleId       interface{}
	PermissionId string
}

type UserRole struct {
	UserId interface{}
	RoleId interface{}
}

type IStorage interface {
	AddRole(ctx context.Context, caption string) (interface{}, error)
	GetRoles(ctx context.Context, ids ...interface{}) ([]RoleDescription, error)

	AddRolesPermissions(ctx context.Context, rolesPermissions ...RolePermission) error
	RevokeRolesPermissions(ctx context.Context, rolesPermissions ...RolePermission) error
	GetRolesPermissions(ctx context.Context, rolesIds ...interface{}) ([]string, error)

	AddUserRoles(ctx context.Context, usersRoles ...UserRole) error
	RevokeUserRoles(ctx context.Context, usersRoles ...UserRole) error
	GetUserRoles(ctx context.Context, userIds ...interface{}) ([]interface{}, error)
}
