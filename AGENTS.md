# openbao-plugin-secrets-acme

这是一个专为 OpenBao 设计的,用于自动化签发并保存证书的插件.

主要实现 DNS01 挑战,这是最方便 headless 的.

ACME 协议使用 LEGO 库实现.

## Cloned Dependency Source

Read-only dependency source repositories are available under
`.slim/clonedeps/repos/` for inspection. Do not edit these clones.

- `.slim/clonedeps/repos/openbao__openbao/` - `openbao/openbao` at `v2.6.2`; OpenBao 核心源码,研究原生凭据标识与 accessor 存储机制时查阅。
