//go:build go1.7
// +build go1.7

package csrf

import (
	"context"
	"fmt"
	"net/http"
)

func contextGet(r *http.Request, key string) (interface{}, error) {
	return valueFromContext(r.Context(), key)
}

func valueFromContext(ctx context.Context, key string) (interface{}, error) {
	val := ctx.Value(key)
	if val == nil {
		return nil, fmt.Errorf("no value exists in the context for key %q", key)
	}
	return val, nil
}

func contextSave(r *http.Request, key string, val interface{}) *http.Request {
	ctx := r.Context()
	ctx = context.WithValue(ctx, key, val) // nolint:staticcheck
	return r.WithContext(ctx)
}

func contextClear(r *http.Request) {
	// no-op for go1.7+
}
