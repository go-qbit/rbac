package rbac

type Permission struct {
	id      string
	caption string
	groupId string
}

func (p *Permission) GetId() string {
	return p.id
}

func (p *Permission) GetCaption() string {
	return p.caption
}

func (p *Permission) GetGroupId() string {
	return p.groupId
}
