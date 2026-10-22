package gjwt

import (
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
