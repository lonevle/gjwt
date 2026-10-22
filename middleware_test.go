package gjwt

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/gogf/gf/v2/errors/gcode"
	"github.com/gogf/gf/v2/errors/gerror"
	"github.com/gogf/gf/v2/frame/g"
	"github.com/gogf/gf/v2/net/ghttp"
	"github.com/gogf/gf/v2/util/guid"
)

// startAuthServer 启动一个挂载了鉴权中间件的真实 gf server，返回受保护路由 URL。
// 用真实 server 而非手工构造 Request 的原因：Middleware 的行为依赖 gf 完整的
// 中间件链（Middleware.Next / SetError / 缓冲式 WriteHeader），脱离链路模拟会失真。
func startAuthServer(t *testing.T, a *Auth[*testClaims]) string {
	t.Helper()
	s := g.Server(guid.S()) // 唯一实例名，多测试并行起 server 互不冲突
	s.Group("/", func(group *ghttp.RouterGroup) {
		// gf 标准响应中间件：读取 r.GetError() 并包装为统一 JSON 响应，模拟业务真实挂载方式
		group.Middleware(ghttp.MiddlewareHandlerResponse)
		group.Group("/", func(group *ghttp.RouterGroup) {
			group.Middleware(a.Middleware())
			group.ALL("/user", func(r *ghttp.Request) {
				claims, ok := a.ClaimsFromContext(r.Context())
				if !ok {
					r.SetError(fmt.Errorf("claims not found in ctx"))
					return
				}
				token, _ := TokenFromContext(r.Context())
				r.Response.WriteJson(map[string]any{
					"userId": claims.UserID,
					"name":   claims.Name,
					"token":  token,
				})
			})
		})
	})
	s.SetDumpRouterMap(false)
	s.Start()
	t.Cleanup(func() { _ = s.Shutdown() })
	return fmt.Sprintf("http://127.0.0.1:%d/user", s.GetListenedPort())
}

// httpGet 发 GET 请求并返回状态码、WWW-Authenticate 头与响应体。
// server 启动是异步的，带上限重试以等待就绪。
func httpGet(t *testing.T, url, authorization string) (status int, wwwAuth, body string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatalf("构造请求失败: %v", err)
	}
	if authorization != "" {
		req.Header.Set("Authorization", authorization)
	}
	var resp *http.Response
	for i := 0; i < 5; i++ {
		resp, err = http.DefaultClient.Do(req)
		if err == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("请求 %s 失败: %v", url, err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("读取响应体失败: %v", err)
	}
	return resp.StatusCode, resp.Header.Get("WWW-Authenticate"), string(b)
}

// decodeBody 把 gf DefaultHandlerResponse 格式的响应体解析为 map（code/message/data）。
func decodeBody(t *testing.T, body string) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(body), &m); err != nil {
		t.Fatalf("响应体不是合法 JSON: %q (%v)", body, err)
	}
	return m
}

// TestMiddleware_HappyPath 验证受保护路由的完整链路：
// Bearer token 验签通过 → claims 与原始 token 注入 ctx → handler 正常取用。
func TestMiddleware_HappyPath(t *testing.T) {
	a := newTestAuth(t)
	url := startAuthServer(t, a)
	pair, err := a.GenerateTokenPair(&testClaims{UserID: 42, Name: "alice"})
	if err != nil {
		t.Fatalf("GenerateTokenPair() error = %v", err)
	}
	status, _, body := httpGet(t, url, "Bearer "+pair.AccessToken)
	if status != http.StatusOK {
		t.Fatalf("携带有效 token 应返回 200，got %d, body %s", status, body)
	}
	m := decodeBody(t, body)
	if m["userId"] != float64(42) || m["name"] != "alice" {
		t.Fatalf("handler 应从 ctx 取到完整 claims: %v", m)
	}
	if m["token"] != pair.AccessToken {
		t.Fatalf("TokenFromContext 应取到原始 token: %v", m["token"])
	}
}

// TestMiddleware_MissingToken 验证未携带 token 的拒绝路径：
// 401 + WWW-Authenticate: Bearer（无 error 参数，RFC 6750 语义）+ 响应中间件输出配置的错误。
func TestMiddleware_MissingToken(t *testing.T) {
	a := newTestAuth(t)
	url := startAuthServer(t, a)
	status, wwwAuth, body := httpGet(t, url, "")
	if status != http.StatusUnauthorized {
		t.Fatalf("未携带 token 应返回 401，got %d", status)
	}
	if wwwAuth != "Bearer" {
		t.Fatalf("未携带 token 时 WWW-Authenticate 应为无参数的 Bearer，got %q", wwwAuth)
	}
	m := decodeBody(t, body)
	if m["code"] != float64(401) || m["message"] != "token is missing" {
		t.Fatalf("响应体应包含 missing 错误: %v", m)
	}
}

// TestMiddleware_InvalidHeader 验证无法识别的 Authorization 格式（如 Basic）：
// 401 + WWW-Authenticate 携带 error="invalid_token"（与 missing 区分）。
func TestMiddleware_InvalidHeader(t *testing.T) {
	a := newTestAuth(t)
	url := startAuthServer(t, a)
	status, wwwAuth, body := httpGet(t, url, "Basic dXNlcjpwYXNz")
	if status != http.StatusUnauthorized {
		t.Fatalf("Basic 凭证应返回 401，got %d", status)
	}
	if wwwAuth != `Bearer error="invalid_token"` {
		t.Fatalf("携带无效凭证时 WWW-Authenticate 应带 error 参数，got %q", wwwAuth)
	}
	m := decodeBody(t, body)
	if m["code"] != float64(401) || m["message"] != "token is invalid" {
		t.Fatalf("响应体应包含 invalid 错误: %v", m)
	}
}

// TestMiddleware_ExpiredToken 验证过期 token 的拒绝路径：401 + error="invalid_token"（RFC 6750 未定义 expired）。
func TestMiddleware_ExpiredToken(t *testing.T) {
	base := time.Unix(1700000000, 0)
	now := base
	a := newTestAuth(t,
		WithAccessTTL(time.Hour),
		WithTimeFunc(func() time.Time { return now }),
	)
	url := startAuthServer(t, a)
	pair, err := a.GenerateTokenPair(&testClaims{UserID: 1})
	if err != nil {
		t.Fatalf("GenerateTokenPair() error = %v", err)
	}
	now = base.Add(2 * time.Hour) // 时钟拨到过期之后
	status, wwwAuth, body := httpGet(t, url, "Bearer "+pair.AccessToken)
	if status != http.StatusUnauthorized {
		t.Fatalf("过期 token 应返回 401，got %d", status)
	}
	if wwwAuth != `Bearer error="invalid_token"` {
		t.Fatalf("过期 token 的 WWW-Authenticate 应带 error 参数，got %q", wwwAuth)
	}
	m := decodeBody(t, body)
	if m["message"] != "token is expired" {
		t.Fatalf("响应体应包含 expired 错误: %v", m)
	}
}

// TestMiddleware_CustomHTTPStatus 验证 WithHTTPStatus(200) 场景：
// HTTP 200 + body 携带错误码（适配"HTTP 200 + 业务码判错"的前端约定），且不带 WWW-Authenticate。
func TestMiddleware_CustomHTTPStatus(t *testing.T) {
	a := newTestAuth(t, WithHTTPStatus(http.StatusOK))
	url := startAuthServer(t, a)
	status, wwwAuth, body := httpGet(t, url, "")
	if status != http.StatusOK {
		t.Fatalf("配置 httpStatus=200 后应返回 200，got %d", status)
	}
	if wwwAuth != "" {
		t.Fatalf("非 401 状态码不应携带 WWW-Authenticate，got %q", wwwAuth)
	}
	m := decodeBody(t, body)
	if m["code"] != float64(401) {
		t.Fatalf("body 中的业务错误码应保持 401: %v", m)
	}
}

// errCode 是测试用的自定义错误构造器（业务侧适配前端错误码的标准写法）。
func errCode(code int, msg string) error {
	return gerror.NewCode(gcode.New(code, "", nil), msg)
}

// TestMiddleware_CustomErrors 验证用户覆盖错误后的完整输出链路：
// 自定义提示语与错误码经响应中间件原样透出（适配前端错误码约定）。
func TestMiddleware_CustomErrors(t *testing.T) {
	a := newTestAuth(t, WithErrors(Errors{
		TokenMissing: errCode(10041, "登录已过期，请重新登录"),
	}))
	url := startAuthServer(t, a)
	status, _, body := httpGet(t, url, "")
	if status != http.StatusUnauthorized {
		t.Fatalf("应返回 401，got %d", status)
	}
	m := decodeBody(t, body)
	if m["code"] != float64(10041) || m["message"] != "登录已过期，请重新登录" {
		t.Fatalf("响应体应透出自定义错误码与提示语: %v", m)
	}
}
