package acme

import (
	"context"
)

// fakeCredentialLoader 返回预置凭据，供签发/路径测试使用。
type fakeCredentialLoader struct {
	data map[string]string
}

func NewFakeCredentialLoader(data map[string]string) *fakeCredentialLoader {
	return &fakeCredentialLoader{data: data}
}

func (f *fakeCredentialLoader) Load(ctx context.Context, clientToken string, ref credentialsRef) (map[string]string, error) {
	// 与 brief 意图一致：断言调用方必须透传 clientToken。
	// brief 原写法 require.NotEmpty(ctx, ...) 无法编译（首参需 testing.TB），
	// 在无 *testing.T 的 fake 方法内以 panic 保持等价的响亮失败语义。
	if clientToken == "" {
		panic("clientToken 必须传递")
	}
	return f.data, nil
}
