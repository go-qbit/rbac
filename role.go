package rbac

type Role struct {
	id      interface{}
	caption string
}

func (r *Role) GetId() interface{} {
	return r.id
}

func (r *Role) GetCaption() string {
	return r.caption
}
