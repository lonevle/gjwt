# Changelog

## [0.1.0](https://github.com/lonevle/gjwt/compare/v0.0.1...v0.1.0) (2026-10-22)


### 🚀 Features

* 优化 WithRefreshClaims 函数，增加对 nil 函数的处理，确保默认行为一致；更新示例代码中的时间格式 ([a53b528](https://github.com/lonevle/gjwt/commit/a53b528333ef8a99c635b93e2057008552e2c332))
* 增强 JWT 认证，支持刷新令牌声明最小化和错误处理 ([03e247e](https://github.com/lonevle/gjwt/commit/03e247ed7164acafb413fe1034bcf536454a4471))
* 更新文档和代码，优化 WithRefreshClaims 的类型检查，确保初始化阶段即暴露类型不匹配错误 ([8a32bc5](https://github.com/lonevle/gjwt/commit/8a32bc59d822125fc0865ec19af8fcfe98a4c98a))
* 添加带有全面测试的 JWT 认证包 ([3b3df37](https://github.com/lonevle/gjwt/commit/3b3df378f6d4801a96e860cc2ad2b8731106a916))
