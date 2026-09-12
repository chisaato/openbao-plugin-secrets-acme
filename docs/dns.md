# DNS 配置

这篇文章告诉你你需要在 KV 引擎里配置什么来适配对应的 DNS 提供商. 假设

- KV 引擎挂载于 `dns`
- 条目名称为 `dns-cred`

## Cloudflare

按照官方推荐使用 `CLOUDFLARE_DNS_API_TOKEN` 即可.

```bash
bao kv patch -mount=dns dns-cred CLOUDFLARE_DNS_API_TOKEN=你的 Token
```

你要想用其他模式,或者古老的邮箱+全局 Key 也可以,参考 [LEGO-Cloudflare](https://go-acme.github.io/lego/dns/cloudflare/).
