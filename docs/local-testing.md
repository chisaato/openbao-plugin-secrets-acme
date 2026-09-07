# 本地 OpenBao 测试环境（Docker Compose）

用 Docker Compose 在本地跑一个真实形态的 OpenBao（raft 持久化 + `plugin_directory` +
声明式插件注册），加载本插件并走通签发链路。与生产部署的差异只在 TLS 与运行用户。

## 前置条件

- Docker + Docker Compose v2（`docker compose version` 可用）
- Go（`just build` 用）
- 镜像：`openbao/openbao:2.6.2`（声明式插件块需 OpenBao ≥ 2.5.0）

## 快速开始

```bash
# 0. 生成本地配置（bao-config.hcl 已被 gitignore，token 随便填不会被提交）
cp bao-config.hcl.example bao-config.hcl

# 1. 构建插件（linux 本机二进制，ldflags 注入版本 = git describe，当前 v0.1.0）
just build

# 2. 把二进制的 sha256 填入 bao-config.hcl 的 plugin 块 sha256sum
sha256sum bin/openbao-plugin-secrets-acme

# 3. 拷贝插件到挂载目录（compose 映射为 /openbao/plugins）
cp bin/openbao-plugin-secrets-acme data/plugins/

# 4. 启动
docker compose up -d

# 5. 初始化（脚本自动完成：operator init + 凭据保存到 data/credentials.json +
#    root token 回填 bao-config.hcl 并重启生效；已初始化时只校验 token 有效性）
just init
#    彻底重置（销毁 data/data 重新 init，数据不可恢复）：
just init --reset

# 8. 验证插件已声明式注册并挂载引擎
export BAO_TOKEN=<root token> # bao CLI 的所有操作都需要它
docker compose exec -T -e BAO_ADDR -e BAO_TOKEN bao bao plugin list secret   # 应看到 acme v0.1.0
docker compose exec -T -e BAO_ADDR -e BAO_TOKEN bao bao secrets enable -path=acme acme
```

> **坑位提醒（实测踩过）**
> - 容器内 bao CLI 默认 `BAO_ADDR=https://127.0.0.1:8200`，而本地 listener 是 HTTP，
>   所以容器内执行 CLI 必须带 `-e BAO_ADDR=http://127.0.0.1:8200`。
> - `bao` 的读写类命令都需要 `BAO_TOKEN`（init/unseal 除外）；漏掉会得到误导性的
>   `permission denied` 或 `data from server response is empty`。
> - static seal 下 `operator init` 不能带 `-key-shares/-key-threshold`（报
>   `parameters not applicable`），且 `data/data/unseal.key` 必须预先存在，bao 不会自动生成。
> - `compose restart` 后 static seal 会自动解封（无需手动 `operator unseal`）。
> - root token / recovery keys 每次重置都会更换，以 `data/credentials.json` 里保存的为准；
>   丢了 token 只能 `just init --reset` 重来。

## 配置测试资源

凭据放在 KV v2（插件实时读取，改 KV 即轮换、无须重启）：

```bash
# 挂一个 KV v2 引擎当凭据库（本地没有现成的）
docker compose exec -T -e BAO_ADDR -e BAO_TOKEN bao bao secrets enable -path=secret kv-v2

# 放入 Cloudflare 凭据（键名 = lego 环境变量名）
docker compose exec -T -e BAO_ADDR -e BAO_TOKEN bao bao kv put secret/dns/cf \
  CLOUDFLARE_DNS_API_TOKEN=<your-token>
```

你可以直接使用项目内置的快捷 CLI 工具 `bin/bao-acme`（详细使用指南与字段参数见 [docs/cli.md](cli.md)），也可继续使用原生 `curl`。

### 方式 A：使用快捷 CLI (`bin/bao-acme`)

```bash
# 0. 编译插件与 CLI (生成 bin/openbao-plugin-secrets-acme 与 bin/bao-acme)
just build

# 1. 配置 DNS Provider
bin/bao-acme provider set cf --type cloudflare --cred-mount secret --cred-path dns/cf

# 2. 注册 ACME 账户并绑定 DNS Provider
bin/bao-acme account register le-staging \
  --server-url https://acme-staging-v02.api.letsencrypt.org/directory \
  --contact you@example.com \
  --provider cf

# 3. 配置 Role 策略
bin/bao-acme role set web \
  --account le-staging \
  --allowed-domains example.com \
  --allow-bare --allow-sub

# 4. 签发证书 (默认异步提交并在终端自动轮询等待结果，可直存本地文件)
bin/bao-acme cert issue web --cn example.com --alt "*.example.com" \
  --out-cert cert.pem --out-key key.pem

# 查看任务列表与详情
bin/bao-acme job list
bin/bao-acme job get <job_id>
```

---

### 方式 B：使用原生 curl

```bash
# DNS provider（指向上面的 KV）
curl -s -H "X-Vault-Token: $BAO_TOKEN" -X POST \
  -d '{"type":"cloudflare","credentials_ref":{"mount":"secret","path":"dns/cf"}}' \
  $BAO_ADDR/v1/acme/dns-providers/cf

# ACME 账户（本地无公网 CA 时可先用 pebble 或 LE staging 的 server_url）
curl -s -H "X-Vault-Token: $BAO_TOKEN" -X POST \
  -d '{"server_url":"https://acme-staging-v02.api.letsencrypt.org/directory","contact":"you@example.com","terms_of_service_agreed":true,"key_type":"EC256","dns_providers":[{"name":"cf"}]}' \
  $BAO_ADDR/v1/acme/accounts/le-staging

# Role
curl -s -H "X-Vault-Token: $BAO_TOKEN" -X POST \
  -d '{"account":"le-staging","allowed_domains":"example.com","allow_bare_domains":true}' \
  $BAO_ADDR/v1/acme/roles/web

# 签发（默认异步：立即返回 job_id，插件后台完成 DNS01 + 签发）
curl -s -H "X-Vault-Token: $BAO_TOKEN" -X POST \
  -d '{"common_name":"example.com"}' \
  $BAO_ADDR/v1/acme/certs/web | python3 -m json.tool
# → {"job_id":"...","status":"pending","poll_path":"jobs/...",...}

# 轮询任务状态；completed 时响应含 certificate/private_key/issuer_cert/
# not_before/not_after/output_path（无 lease，不参与续期/撤销生命周期）
curl -s -H "X-Vault-Token: $BAO_TOKEN" \
  $BAO_ADDR/v1/acme/jobs/<job_id> | python3 -m json.tool

# 列出 / 清理任务（仅 completed/failed 可删）
curl -s -H "X-Vault-Token: $BAO_TOKEN" $BAO_ADDR/v1/acme/jobs/ | python3 -m json.tool
curl -s -H "X-Vault-Token: $BAO_TOKEN" -X DELETE $BAO_ADDR/v1/acme/jobs/<job_id>

# 旧同步行为（阻塞至签发完成、响应带 lease，可用于快速验证）
curl -s -H "X-Vault-Token: $BAO_TOKEN" -X POST \
  -d '{"common_name":"example.com","sync":true}' \
  $BAO_ADDR/v1/acme/certs/web | python3 -m json.tool
```

进程重启（compose restart）后，未完成的 job 会被插件自动重新驱动并收敛；
已签发的泛域名证书会直接服务同 account 后续的单域名请求（响应带
`reused: true`），详见 `README.md`。

字段含义、KV 键映射（`keys`）、多 provider zones 路由、缓存与 revoke 语义见 `README.md`。

## 日常操作

```bash
docker compose stop        # 停止（数据保留）
docker compose up -d       # 再启动（unseal 后可用）
docker compose down        # 停止并删容器（数据保留在 data/data）
docker compose down && sudo rm -rf data/data   # 彻底重置（插件副本在 data/plugins，不动）
just init --reset                              # 同上 + 自动重新 init 并回填 token
```

## 与生产部署的差异

| 项 | 本地 compose | 生产（README §2/§3） |
|---|---|---|
| 存储 | raft 单节点（同构） | raft 集群或集成存储 |
| TLS | 关闭（`tls_disable = 1`） | 必须启用 |
| 运行用户 | 容器内 root（`compose.yaml` 注释说明，绕开镜像 entrypoint 的用户切换以简化 bind mount 权限） | 专用低权限用户 |
| BAO_TOKEN | root token | 最小权限服务身份（凭据 read + 输出 create/update） |

## 附：dev 模式速记（不推荐用于本插件）

```bash
docker run --rm -d --name bao-dev -p 8200:8200 \
  -v "$(pwd)/bin:/openbao-plugins" --cap-add IPC_LOCK \
  openbao/openbao:2.6.2 server -dev -dev-root-token-id=root -dev-plugin-dir=/openbao-plugins
```

dev 模式跳过 sha256 校验、内存存储（重启即丢），且**不走声明式 `env` 注入链路**——
无法验证本插件依赖的 BAO_TOKEN 服务身份注入，仅适合临时把玩其他引擎。
