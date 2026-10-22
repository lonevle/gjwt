package gjwt

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/gogf/gf/v2/errors/gcode"
	"github.com/gogf/gf/v2/errors/gerror"
	"github.com/gogf/gf/v2/net/ghttp"
)

const (
	defaultHeaderKey = "Authorization"
	defaultQueryKey  = "token"
	bearerPrefix     = "bearer"
)

// ExtractToken 从 header 值或 query 值中提取纯 token 字符串（独立纯函数，便于单元测试）。
// 兼容三种写法："Bearer xxx"（标准，前缀大小写不敏感）、裸 token（无前缀）、"?token=xxx"。
// 注意：query 传 token 会进入访问日志与浏览器历史，仅建议用于文件下载、
// WebSocket 等无法携带 header 的场景，常规接口请优先使用 header。
func ExtractToken(headerValue, queryValue string) (string, error) {
	headerValue = strings.TrimSpace(headerValue)
	if headerValue != "" {
		// 只有 "Bearer" 单词本身（前缀后无 token）同样视为无法识别的格式：
		// 不修复的话它会走下方裸 token 分支被原样返回，碰巧在验签处失败，语义路径不干净
		if strings.EqualFold(headerValue, bearerPrefix) {
			return "", ErrTokenInvalid
		}
		if strings.Contains(headerValue, " ") {
			parts := strings.SplitN(headerValue, " ", 2)
			if strings.EqualFold(parts[0], bearerPrefix) && strings.TrimSpace(parts[1]) != "" {
				return strings.TrimSpace(parts[1]), nil
			}
			// header 有值但格式无法识别，视为无效而非静默忽略
			return "", ErrTokenInvalid
		}
		return headerValue, nil
	}
	queryValue = strings.TrimSpace(queryValue)
	if queryValue != "" {
		return queryValue, nil
	}
	return "", ErrTokenMissing
}

// GetRequestToken 从 GoFrame 请求中提取 token。
func GetRequestToken(r *ghttp.Request) (string, error) {
	return ExtractToken(r.Header.Get(defaultHeaderKey), r.URL.Query().Get(defaultQueryKey))
}

// 包级默认错误：包内唯一实例，defaultConfig 引用同一实例，
// 业务侧用 errors.Is(err, gjwt.ErrTokenExpired) 即可精确判断（覆盖自定义错误后同理）。
var (
	ErrTokenMissing = gerror.NewCode(gcode.New(401, "", nil), "token is missing")
	ErrTokenInvalid = gerror.NewCode(gcode.New(401, "", nil), "token is invalid")
	ErrTokenExpired = gerror.NewCode(gcode.New(401, "", nil), "token is expired")
)

// ctx 的 key 用私有空结构体类型：避免与其他包冲突，且无法被外部构造伪造。
type claimsKey struct{}
type tokenKey struct{}

// WithClaims 把解析后的自定义结构体 C 写入 ctx，供中间件向下游 handler 注入。
func WithClaims[C any](ctx context.Context, claims C) context.Context {
	return context.WithValue(ctx, claimsKey{}, claims)
}

// ClaimsFromContext 从 ctx 中取回自定义结构体（由 Middleware 注入）。
// 取出的类型必须与注入时一致，否则 ok 为 false——类型安全由泛型保证。
func ClaimsFromContext[C any](ctx context.Context) (C, bool) {
	claims, ok := ctx.Value(claimsKey{}).(C)
	return claims, ok
}

// ClaimsFromContext 实例方法版：C 已由 Auth 实例在初始化时定死，
// 业务 handler 拿着 auth 实例调用时无需重复书写类型参数（编译器自动推断）。
//
//	claims, ok := auth.ClaimsFromContext(r.Context())
func (a *Auth[C]) ClaimsFromContext(ctx context.Context) (C, bool) {
	return ClaimsFromContext[C](ctx)
}

// WithToken 把原始 token 字符串写入 ctx。
func WithToken(ctx context.Context, tokenString string) context.Context {
	return context.WithValue(ctx, tokenKey{}, tokenString)
}

// TokenFromContext 从 ctx 中取回原始 token 字符串（由 Middleware 放入）。
func TokenFromContext(ctx context.Context) (string, bool) {
	tokenString, ok := ctx.Value(tokenKey{}).(string)
	return tokenString, ok
}

// Middleware 返回 GoFrame 鉴权中间件：从请求提取 token → 工厂构造 claims →
// 验签 + 过期校验 → 成功则把 C 注入 ctx 放行，失败则返回配置的错误（默认或用户覆盖后）。
//
// 挂载方式：
//
//	s.Group("/", func(group *ghttp.RouterGroup) {
//	    group.Middleware(ghttp.MiddlewareHandlerResponse)
//	    group.Bind(loginCtrl, refreshCtrl)              // 公开路由
//	    group.Group("/", func(group *ghttp.RouterGroup) {
//	        group.Middleware(auth.Middleware())         // 受保护路由
//	        group.Bind(userCtrl)
//	    })
//	})
//
// 业务 handler 中取自定义结构体：
//
//	claims, ok := gjwt.ClaimsFromContext[*MyClaims](r.Context())
func (a *Auth[C]) Middleware() ghttp.HandlerFunc {
	return func(r *ghttp.Request) {
		tokenString, err := GetRequestToken(r)
		if err != nil {
			a.reject(r, a.mapExtractError(err))
			return
		}
		claims, err := a.Parse(tokenString)
		if err != nil {
			a.reject(r, err)
			return
		}
		r.SetCtx(WithToken(WithClaims(r.Context(), claims), tokenString))
		r.Middleware.Next()
	}
}

// mapExtractError 把 token 提取阶段的错误翻译为配置中的错误（统一包装成 mappedError，
// 语义类别打上 missing 标记）：header 有值但格式非法（如 "Basic xxx"）应报 invalid 而非 missing，
// 语义才准确；错误链保留提取阶段的原始错误，与验签路径的行为一致。
func (a *Auth[C]) mapExtractError(err error) error {
	if errors.Is(err, ErrTokenInvalid) {
		return &mappedError{
			configured: a.cfg.errors.TokenInvalid,
			cause:      err,
			msg:        a.cfg.errors.TokenInvalid.Error(),
		}
	}
	return &mappedError{
		configured: a.cfg.errors.TokenMissing,
		cause:      err,
		msg:        a.cfg.errors.TokenMissing.Error(),
		missing:    true,
	}
}

// reject 中止请求并把鉴权错误交由外层响应中间件统一包装（gf 标准流程）。
// 错误携带 gerror 错误码（用户可用 gerror.NewCode 自定义），
// 响应体格式（如 SoybeanAdmin 的 msg 字段）由业务侧自定义的响应中间件控制。
// 不调用 r.Middleware.Next() 且直接 return 即为 GoFrame 中间件的中止方式。
//
// RFC 6750：状态码为 401 时必须携带 WWW-Authenticate: Bearer 响应头，
// 标准 HTTP 客户端据此区分"未携带凭证"与"携带了但无效"：
//   - 未携带 token（missing）→ "Bearer"（无 error 参数）
//   - 携带了但无效/过期      → `Bearer error="invalid_token"`（RFC 6750 未定义 expired，统一归入 invalid_token）
//
// httpStatus 被配置为 200 等非 401 值时不携带该头（该头只在 401 语境下有意义）。
func (a *Auth[C]) reject(r *ghttp.Request, err error) {
	if a.cfg.httpStatus == http.StatusUnauthorized {
		var me *mappedError
		if errors.As(err, &me) && !me.missing {
			r.Response.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
		} else {
			r.Response.Header().Set("WWW-Authenticate", "Bearer")
		}
	}
	r.Response.WriteHeader(a.cfg.httpStatus)
	r.SetError(err)
}
