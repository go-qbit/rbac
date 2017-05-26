package rbac

import (
	"sync"

	"github.com/go-qbit/qerror"
)

type PermissionsGroup struct {
	id          string
	caption     string
	permissions map[string]*Permission
	mtx         sync.RWMutex
}

func (g *PermissionsGroup) GetId() string {
	return g.id
}

func (g *PermissionsGroup) GetCaption() string {
	return g.caption
}

func (g *PermissionsGroup) RegisterPermission(p *Permission) error {
	g.mtx.Lock()
	defer g.mtx.Unlock()

	if g.permissions == nil {
		g.permissions = make(map[string]*Permission)
	}

	if _, exists := g.permissions[p.id]; exists {
		return qerror.Errorf("Permission with id '%s' exists")
	}

	p.groupId = g.id

	g.permissions[p.id] = p

	return nil
}

func (g *PermissionsGroup) GetPermission(id string) *Permission {
	g.mtx.RLock()
	defer g.mtx.RUnlock()

	return g.permissions[id]
}

func (g *PermissionsGroup) GetAllPermissions() []*Permission {
	g.mtx.RLock()
	defer g.mtx.RUnlock()

	res := make([]*Permission, 0, len(g.permissions))

	for _, p := range g.permissions {
		res = append(res, p)
	}

	return res
}
