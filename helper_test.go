package gjwt

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gogf/gf/v2/net/ghttp"
)

func TestExtractToken(t *testing.T) {
	tests := []struct {
		name        string
		headerValue string
		queryValue  string
		want        string
		wantErr     error
	}{
		{"标准 Bearer", "Bearer abc", "", "abc", nil},
		{"小写 bearer", "bearer abc", "", "abc", nil},
		{"大写 BEARER", "BEARER abc", "", "abc", nil},
		{"前缀与 token 间多个空格", "Bearer   abc", "", "abc", nil},
		{"裸 token 无前缀", "abc", "", "abc", nil},
		{"query 传值", "", "abc", "abc", nil},
		{"header 优先于 query", "Bearer abc", "xyz", "abc", nil},
		{"非 Bearer 协议视为无效", "Basic abc", "", "", ErrTokenInvalid},
		{"Bearer 单词无 token 视为无效", "Bearer", "", "", ErrTokenInvalid},
		{"小写 bearer 单词无 token", "bearer", "", "", ErrTokenInvalid},
		{"Bearer 后只有空格视为无效", "Bearer   ", "", "", ErrTokenInvalid},
		{"header 与 query 均为空", "", "", "", ErrTokenMissing},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ExtractToken(tt.headerValue, tt.queryValue)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("err = %v, want %v", err, tt.wantErr)
			}
			if got != tt.want {
				t.Fatalf("token = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestGetRequestToken 验证从 GoFrame 请求对象提取 token 的取值路径。
func TestGetRequestToken(t *testing.T) {
	// 从 query 提取
	r := &ghttp.Request{}
	r.Request = httptest.NewRequest(http.MethodGet, "/api/user?token=abc", nil)
	if token, err := GetRequestToken(r); err != nil || token != "abc" {
		t.Fatalf("query 提取失败: token=%q, err=%v", token, err)
	}
	// 从 header 提取
	r2 := &ghttp.Request{}
	r2.Request = httptest.NewRequest(http.MethodGet, "/", nil)
	r2.Request.Header.Set("Authorization", "Bearer xyz")
	if token, err := GetRequestToken(r2); err != nil || token != "xyz" {
		t.Fatalf("header 提取失败: token=%q, err=%v", token, err)
	}
	// 均未携带
	r3 := &ghttp.Request{}
	r3.Request = httptest.NewRequest(http.MethodGet, "/", nil)
	if _, err := GetRequestToken(r3); !errors.Is(err, ErrTokenMissing) {
		t.Fatalf("应报 missing，got %v", err)
	}
}

// TestTokenContext 验证原始 token 字符串的 ctx 存取。
func TestTokenContext(t *testing.T) {
	// 模拟其他包注入的无关 ctx 值：key 类型不同则取不到（ctx 的类型隔离由编译器保证）
	type foreignKey struct{}
	ctx := context.WithValue(context.Background(), foreignKey{}, "sentinel")
	if _, ok := TokenFromContext(ctx); ok {
		t.Fatal("无关的 ctx 值不应被 TokenFromContext 取到")
	}
	ctx = WithToken(context.Background(), "raw-token")
	got, ok := TokenFromContext(ctx)
	if !ok || got != "raw-token" {
		t.Fatalf("TokenFromContext() = %q, %v; want raw-token, true", got, ok)
	}
}

// TestClaimsContext 验证泛型 claims 的 ctx 存取，包括类型不匹配时 ok=false（不 panic）。
func TestClaimsContext(t *testing.T) {
	claims := &testClaims{UserID: 5}
	ctx := WithClaims(context.Background(), claims)
	got, ok := ClaimsFromContext[*testClaims](ctx)
	if !ok || got.UserID != 5 {
		t.Fatalf("ClaimsFromContext() = %+v, %v; want UserID=5, true", got, ok)
	}
	// 类型不匹配：注入 *testClaims、按其他类型取出 → ok=false 而非 panic
	if _, ok := ClaimsFromContext[*otherClaims](ctx); ok {
		t.Fatal("类型不匹配时 ok 应为 false")
	}
	// 未注入的 ctx → ok=false
	if _, ok := ClaimsFromContext[*testClaims](context.Background()); ok {
		t.Fatal("未注入的 ctx 不应取到 claims")
	}
}
