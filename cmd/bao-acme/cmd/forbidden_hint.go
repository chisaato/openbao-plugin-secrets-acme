package cmd

import (
	"errors"
	"net/http"

	baoapi "github.com/openbao/openbao/api/v2"
)

// forbiddenHintText 是 403 时打印到 stderr 的分类指引。
// OpenBao 对 token 失效与策略不足均返回 permission denied，无法从单次响应区分，故同时覆盖两种可能。
const forbiddenHintText = `提示：收到 403 (permission denied)。若较久未登录，请先用 bao CLI 完成登录（任意认证方式，token 会被自动读取）后重试；若刚登录过，则是当前身份策略缺少对该路径/操作的权限，请检查对应 policy。`

// ForbiddenHint 若 err 链包含 OpenBao 的 403 ResponseError，返回应打印到 stderr 的分类指引。
// 不修改原错误；调用方应在既有错误输出之后将指引写入 stderr。
func ForbiddenHint(err error) (string, bool) {
	if err == nil {
		return "", false
	}
	var re *baoapi.ResponseError
	if errors.As(err, &re) && re.StatusCode == http.StatusForbidden {
		return forbiddenHintText, true
	}
	return "", false
}
