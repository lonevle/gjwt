# gjwt

基于 [golang-jwt/v5](https://github.com/golang-jwt/jwt) + HS256 的 [GoFrame](https://goframe.org) 轻量认证库。

设计哲学：**初始化可复杂、调用保持简单**——泛型 `Auth[C]` 在编译期定死 claims 类型，验签逻辑全部委托给 golang-jwt，业务侧三五行完成签发/解析。

## 特性

- **泛型类型安全**：`Parse` 直接返回 `*MyClaims`，无需类型断言
- **双密钥隔离**：access / refresh token 用不同密钥签名，密钥即身份——拿错用途的 token 验签直接失败
- **claims 最小化续签**：`WithRefreshClaims` 让长效 refresh token 只携带标识字段，续签时查库重建
- **大数精度安全**：签发链路开启 `UseNumber`，雪花 ID 等超过 2^53 的 int64 往返无损
- **错误可定制**：三场景错误（missing / invalid / expired）可整体替换为业务错误码，错误链保留原始原因供排障
- **算法白名单**：锁定 HS256，防 alg 混淆攻击；`WWW-Authenticate` 响应头遵循 RFC 6750
- **中间件一行接入**：claims 与原始 token 注入 ctx，handler 泛型取出即用

## 安装

```bash
go get github.com/lonevle/gjwt
```

## 快速开始

### 1. 定义 claims 与初始化

```go
type MyClaims struct {
    jwt.RegisteredClaims              // 嵌入以满足 jwt.Claims 约束
    UserID int64  `json:"userId"`
    Name   string `json:"name"`
    Role   string `json:"role"`
}

auth, err := gjwt.New(
    "至少32字节的HS256密钥",                  // 生产环境从配置中心/环境变量读取
    func() *MyClaims { return &MyClaims{} }, // claims 工厂，定死解析类型
    gjwt.WithIssuer("my-app"),
)
```

### 2. 登录：签发双令牌

```go
func (c *LoginCtrl) Login(r *ghttp.Request) {
    // ...校验用户名密码...
    pair, err := auth.GenerateTokenPair(&MyClaims{UserID: user.ID, Name: user.Name, Role: user.Role})
    // pair.AccessToken / pair.RefreshToken / pair.ExpiresAt / pair.RefreshExpiresAt
    r.Response.WriteJson(g.Map{"data": pair})
}
```

`iat` / `exp` / `jti` / `iss` 等注册字段由库统一写入，无需手动构造 `NumericDate`。

### 3. 挂载鉴权中间件

```go
s.Group("/", func(group *ghttp.RouterGroup) {
    group.Middleware(ghttp.MiddlewareHandlerResponse) // gf 标准响应中间件
    group.Bind(loginCtrl, refreshCtrl)                // 公开路由
    group.Group("/", func(group *ghttp.RouterGroup) {
        group.Middleware(auth.Middleware())           // 受保护路由
        group.Bind(userCtrl)
    })
})
```

### 4. handler 中取出用户信息

```go
func (c *UserCtrl) Profile(r *ghttp.Request) {
    claims, ok := auth.ClaimsFromContext(r.Context())
    if !ok {
        r.SetError(gerror.New("claims not found"))
        return
    }
    r.Response.WriteJson(g.Map{"data": claims})
}
```

> **CORS 预检**：OPTIONS 预检请求不携带 Authorization 头。鉴权中间件不要挂在包含跨域路由的分组上——预检会被 401 拒绝，浏览器端表现为跨域失败且难以排查。预检应由挂在更外层、先于鉴权执行的 CORS 中间件处理。

token 提取兼容 `Authorization: Bearer xxx`（大小写不敏感）、裸 token、`?token=xxx`（仅建议用于下载/WebSocket 等无法带 header 的场景）。

## 续签：三步式（推荐）

无状态的 `RefreshTokenPair` 原样回签 claims，**对外业务建议用三步式**——续签前必须有机会确认用户状态：

```go
func (c *RefreshCtrl) Refresh(r *ghttp.Request) {
    var req struct{ RefreshToken string `json:"refreshToken"` }
    r.Parse(&req)

    claims, err := auth.ParseRefresh(req.RefreshToken) // 1. refresh 密钥验签
    if err != nil {
        r.SetError(gerror.NewCode(gcode.New(10041, "", nil), "登录已过期"))
        return
    }
    user := userDao.GetById(claims.UserID)             // 2. 查库：确认未禁用、取最新数据
    if user == nil || user.Disabled {
        r.SetError(gerror.NewCode(gcode.New(1003, "", nil), "账号已被禁用"))
        return
    }
    pair, err := auth.GenerateTokenPair(&MyClaims{     // 3. 最新数据重建 claims 签发
        UserID: user.ID, Name: user.Name, Role: user.Role,
    })
    r.Response.WriteJson(g.Map{"data": pair})
}
```

### refresh token 最小化

默认 refresh token 与 access token 携带同一份 claims。配置 `WithRefreshClaims` 后只携带标识字段——长效令牌泄漏时暴露面最小，且用户资料变更后不会把陈旧数据带进新一轮签发：

```go
auth, err := gjwt.New(secret, func() *MyClaims { return &MyClaims{} },
    gjwt.WithRefreshClaims(func(c *MyClaims) jwt.Claims {
        return jwt.MapClaims{"userId": c.UserID} // 只保留续签所需标识
    }),
)
```

注意：返回 claims 的 JSON 字段名需与 C 中同名字段对齐（如 `userId`），`ParseRefresh` 才能把值还原进 C。

注意与 `RefreshTokenPair` 的组合：最小化配置下，`RefreshTokenPair`（原样回签）续出的新 access token 同样只携带最小字段（Name/Role 等为零值）——handler 依赖这些字段时必须用三步式续签；handler 本来就只取标识字段（业务数据每次查库）时，`RefreshTokenPair` 仍可安全使用。

## 配置项

| Option | 默认值 | 说明 |
|---|---|---|
| `WithIssuer` | 空（不校验） | 配置后签发 `iss` 并在验签时强制校验 |
| `WithAccessTTL` | 2h | access token 有效期，须为正 |
| `WithRefreshTTL` | 7×24h | refresh token 有效期，须 ≥ accessTTL |
| `WithLeeway` | 1m | 过期校验的时钟偏移容忍 |
| `WithRefreshSecret` | 从 accessSecret 派生 | 显式指定续签密钥（不得与主密钥相同） |
| `WithRefreshClaims` | 不启用（同份 claims） | refresh token 的 claims 抽取函数（最小化） |
| `WithErrors` | 库默认（码 401） | 覆盖三场景错误实例 |
| `WithHTTPStatus` | 401 | 鉴权失败的 HTTP 状态码（可设 200 走业务码判错） |
| `WithTimeFunc` | `time.Now` | 替换内部时间源，测试注入假时钟用 |

## 错误定制

```go
auth, _ := gjwt.New(secret, newClaims,
    gjwt.WithErrors(gjwt.Errors{
        TokenExpired: gerror.NewCode(gcode.New(10041, "", nil), "登录已过期"),
    }),
    gjwt.WithHTTPStatus(200), // 前端约定 HTTP 200 + 业务码判错时
)
```

- 三场景：`TokenMissing`（未携带）、`TokenInvalid`（验签失败/格式非法/issuer 不符）、`TokenExpired`（已过期）
- **传入普通错误（如 `errors.New`）同样安全**：`New` 会自动补上 401 码，提示语与错误链（`errors.Is` 匹配原实例）保持不变；需要自定义错误码时才用 `gerror.NewCode`
- 错误链保留原始验签原因：`errors.As` / `%+v` 可查真实失败原因（签名不符、issuer 不符等），对外提示语不泄漏 JWT 内部细节
- 鉴权失败（401）时自动携带 `WWW-Authenticate: Bearer` 或 `Bearer error="invalid_token"`（RFC 6750）

## 安全注意事项

1. **密钥长度**：HS256 密钥至少 32 字节（RFC 7518 要求），`New` 会拒绝过短密钥；生产环境勿硬编码，建议用 `crypto/rand` 生成（如 32 字节随机数再 base64 编码）。注意长度校验不识别强度——全同字符、可预测的字符串虽能通过校验但安全性不足
2. **算法锁定**：验签 Parser 锁定 HS256 白名单，杜绝 `alg: none` / 算法混淆攻击
3. **exp 必填**：验签强制要求 `exp` 存在，共享同一密钥的其他签发方产出的无过期 token 会被直接拒绝
4. **吊销**：本库无状态、不内置黑名单。每个 token 均有唯一 `jti`（`claims.ID`），需要吊销能力时由业务层用它自建黑名单/白名单
5. **续签轮换（rotation）**：无状态 JWT 无法单点作废旧 refresh token；高安全场景建议业务层记录每用户最近一次续签的 jti，检测到旧 token 复用即强制下线
6. **query 传 token**：会进入访问日志与浏览器历史，仅用于无法携带 header 的场景
7. **假时钟仅用于测试**：`WithTimeFunc` 生产环境不要配置

## 测试

```bash
go test ./... -race -count=1
```
