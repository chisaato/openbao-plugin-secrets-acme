package cmd

import (
	"errors"
	"fmt"
	"net/http"
	"testing"

	baoapi "github.com/openbao/openbao/api/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestForbiddenHint(t *testing.T) {
	tests := []struct {
		name   string
		err    error
		wantOK bool
	}{
		{
			name:   "nil 不命中",
			err:    nil,
			wantOK: false,
		},
		{
			name:   "403 命中",
			err:    &baoapi.ResponseError{StatusCode: http.StatusForbidden},
			wantOK: true,
		},
		{
			name:   "403 经包装仍命中",
			err:    fmt.Errorf("列出账户失败: %w", &baoapi.ResponseError{StatusCode: http.StatusForbidden}),
			wantOK: true,
		},
		{
			name:   "400 不命中",
			err:    &baoapi.ResponseError{StatusCode: http.StatusBadRequest},
			wantOK: false,
		},
		{
			name:   "500 不命中",
			err:    &baoapi.ResponseError{StatusCode: http.StatusInternalServerError},
			wantOK: false,
		},
		{
			name:   "网络错误不命中",
			err:    errors.New("connection refused"),
			wantOK: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hint, ok := ForbiddenHint(tt.err)
			assert.Equal(t, tt.wantOK, ok)
			if !tt.wantOK {
				assert.Empty(t, hint)
				return
			}
			require.NotEmpty(t, hint)
			assert.Contains(t, hint, "403")
			assert.Contains(t, hint, "permission denied")
			assert.Contains(t, hint, "bao CLI")
			assert.Contains(t, hint, "policy")
		})
	}
}
