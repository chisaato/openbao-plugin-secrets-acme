# ACL 和挂载路径的关系

> 虽然我更推荐你先学习 OpenBao 的概念

为了方便如何构造 ACL,以下面这一段举例,此处我们假定

- KV 引擎挂载于 `secret`
- 你的条目存放于 `dns/*`

```hcl
# 读取所有配置在 dns-providers 中的 KV 凭据路径（KVv2 路径包含 data/ 前缀）
path "secret/data/dns/*" {
  capabilities = ["read"]
}

# 若配置了 role 的 output_kv_mount 输出到 certs，需具备写权限
path "certs/data/*" {
  capabilities = ["create", "update"]
}

# 插件自身 Token 自动续期
path "auth/token/renew-self" {
  capabilities = ["update"]
}
```

就是因为 OpenBao 会为 KVv2 引擎自动添加 `data/` 前缀.  
所以存放于名为 `secret` 挂载路径下的 `dns/cred` 就会命中 `dns/*` 这个路径.

当然如果你不想再拆那么干净,让我们思考一个更简单的模式

- KV 引擎挂载于 `dns`
- 你的条目直接按照供应商名字写

那我要记录一条名为 cloudflare 的条目,那我的 ACL 可以改为

```hcl
# 下面的所有都可以读
path "dns/data/*" {
    capabilities = ["read"]
}
# 或者,你要具体锁定
path "certs/data/cloudflare" {
    capabilities = ["read"]
}
```

