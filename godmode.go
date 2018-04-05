package rbac

import "context"

type godModeKeyType uint8

var godModeKey = 0

func SetGodMode(ctx context.Context) context.Context {
	return context.WithValue(ctx, godModeKey, true)
}

func isGodMode(ctx context.Context) bool {
	ctxData := ctx.Value(godModeKey)
	return ctxData != nil && ctxData.(bool)
}
