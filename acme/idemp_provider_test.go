package acme

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

type mockChallengeProvider struct {
	presentErr error
	cleanedUp  bool
}

func (m *mockChallengeProvider) Present(ctx context.Context, domain, token, keyAuth string) error {
	return m.presentErr
}

func (m *mockChallengeProvider) CleanUp(ctx context.Context, domain, token, keyAuth string) error {
	m.cleanedUp = true
	return nil
}

func (m *mockChallengeProvider) Timeout() (time.Duration, time.Duration) {
	return 10 * time.Second, 1 * time.Second
}

func TestIdempProviderSuppressesAlreadyExists(t *testing.T) {
	ctx := context.Background()

	// 1. 普通错误仍报错
	mock := &mockChallengeProvider{presentErr: errors.New("auth failed")}
	idemp := &idempProvider{inner: mock}
	err := idemp.Present(ctx, "example.com", "token", "keyAuth")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "auth failed")

	// 2. 81058 / identical record already exists 视为成功
	mockCF := &mockChallengeProvider{
		presentErr: errors.New("cloudflare: failed to create TXT record: [status code 400] 81058: An identical record already exists."),
	}
	idempCF := &idempProvider{inner: mockCF}
	errCF := idempCF.Present(ctx, "example.com", "token", "keyAuth")
	assert.NoError(t, errCF, "应被静默容错为成功")

	// 3. CleanUp 正常透传
	assert.NoError(t, idempCF.CleanUp(ctx, "example.com", "token", "keyAuth"))
	assert.True(t, mockCF.cleanedUp)
}
