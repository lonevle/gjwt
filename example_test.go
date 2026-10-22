// Package gjwt 示例：完整演示"签发 → 鉴权 → 续签"全链路。
// 示例不带 Output 断言（token 内含随机 jti，输出不固定），仅保证可编译、逻辑真实可用。
package gjwt_test

import (
	"fmt"

	"github.com/golang-jwt/jwt/v5"

	"github.com/lonevle/gjwt"
)

// MyClaims 是业务自定义的用户结构：嵌入 RegisteredClaims 满足 jwt.Claims 约束，
// 其余字段随意定义——json tag 即 token payload 中的字段名。
type MyClaims struct {
	jwt.RegisteredClaims
	UserID int64  `json:"userId"`
	Name   string `json:"name"`
	Role   string `json:"role"`
}

// ExampleNew 演示初始化 + 双令牌签发 + 解析。
// 初始化可复杂（一次性配置全部行为），调用保持简单（业务侧三五行完成签发/解析）。
func ExampleNew() {
	auth, err := gjwt.New(
		"0123456789abcdef0123456789abcdef", // 至少 32 字节的 HS256 密钥
		func() *MyClaims { return &MyClaims{} }, // claims 工厂：定死解析返回的类型
		gjwt.WithIssuer("my-app"),
		gjwt.WithAccessTTL(2*60*60*1e9), // 2 小时（time.Duration）
	)
	if err != nil {
		panic(err)
	}

	// 登录成功后签发双令牌：注册字段（iat/exp/jti/iss）由库统一写入
	pair, err := auth.GenerateTokenPair(&MyClaims{UserID: 1001, Name: "alice", Role: "admin"})
	if err != nil {
		panic(err)
	}
	_ = pair.ExpiresAt // 前端静默刷新的依据（值为动态时间戳，示例不打印）

	// 业务接口验签：直接返回 *MyClaims，无需类型断言
	claims, err := auth.Parse(pair.AccessToken)
	if err != nil {
		panic(err) // 鉴权失败：errors.Is(err, gjwt.ErrTokenExpired) 等可精确判断
	}
	fmt.Println(claims.UserID, claims.Name, claims.Role)
	// Output:
	// 1001 alice admin
}

// ExampleAuth_ParseRefresh 演示主流安全续签模式（三步式）：
// 验签 → 查库确认用户状态并取最新数据 → 重建 claims 重新签发。
// 配合 WithRefreshClaims 把 refresh token 最小化为只携带标识字段。
func ExampleAuth_ParseRefresh() {
	auth, err := gjwt.New(
		"0123456789abcdef0123456789abcdef",
		func() *MyClaims { return &MyClaims{} },
		// refresh token 只携带 userId，角色/昵称等业务字段不进长效令牌：
		// 泄漏暴露面最小，续签时强制查库取最新数据
		gjwt.WithRefreshClaims(func(c *MyClaims) jwt.Claims {
			return jwt.MapClaims{"userId": c.UserID}
		}),
	)
	if err != nil {
		panic(err)
	}

	pair, err := auth.GenerateTokenPair(&MyClaims{UserID: 1001, Name: "alice", Role: "admin"})
	if err != nil {
		panic(err)
	}

	// 续签 handler 的写法（db 查询以注释代替）：
	claims, err := auth.ParseRefresh(pair.RefreshToken) // 1. 用 refresh 密钥验签
	if err != nil {
		panic(err) // 失败则让用户重新登录
	}
	_ = claims // 2. 用 claims.UserID 查库：确认未被禁用、取最新角色等数据
	// 3. 用最新数据重建 claims 签发新对（而非信任 token 里的陈旧字段）
	pair2, err := auth.GenerateTokenPair(&MyClaims{UserID: 1001, Name: "alice", Role: "user"})
	if err != nil {
		panic(err)
	}
	refreshed, err := auth.Parse(pair2.AccessToken)
	if err != nil {
		panic(err)
	}
	fmt.Println(refreshed.Role)
	// Output:
	// user
}
