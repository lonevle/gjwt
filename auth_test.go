package gjwt

import (
	"errors"
	"testing"
	"time"

	"github.com/gogf/gf/v2/errors/gcode"
	"github.com/gogf/gf/v2/errors/gerror"
	"github.com/golang-jwt/jwt/v5"
)

// testSecret 恰好 32 字节，满足 HS256 最低密钥长度要求。
const testSecret = "0123456789abcdef0123456789abcdef"

// testClaims 模拟业务自定义 claims：嵌入 RegisteredClaims 满足 jwt.Claims 约束，
// UserID 故意用 int64 以覆盖大数（雪花 ID 场景）的精度行为。
type testClaims struct {
	jwt.RegisteredClaims
	UserID int64  `json:"userId"`
	Name   string `json:"name"`
}

func newTestClaims() *testClaims { return &testClaims{} }

func newTestAuth(t *testing.T, opts ...Option) *Auth[*testClaims] {
	t.Helper()
	a, err := New(testSecret, newTestClaims, opts...)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return a
}

func TestNew_InvalidConfig(t *testing.T) {
	tests := []struct {
		name   string
		secret string
		opts   []Option
	}{
		{"空密钥", "", nil},
		{"空白密钥", "   ", nil},
		{"密钥过短", "short-secret", nil},
		{"claims 工厂为 nil", testSecret, nil},
		{"续签密钥与业务密钥相同", testSecret, []Option{WithRefreshSecret(testSecret)}},
		{"续签密钥过短", testSecret, []Option{WithRefreshSecret("short")}},
		{"accessTTL 为负", testSecret, []Option{WithAccessTTL(-time.Hour)}},
		{"refreshTTL 为负", testSecret, []Option{WithRefreshTTL(-time.Hour)}},
		{"refreshTTL 短于 accessTTL", testSecret, []Option{WithAccessTTL(2 * time.Hour), WithRefreshTTL(time.Hour)}},
		{"leeway 为负", testSecret, []Option{WithLeeway(-time.Second)}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.name == "claims 工厂为 nil" {
				if _, err := New[*testClaims](tt.secret, nil, tt.opts...); err == nil {
					t.Fatal("New() 应返回错误，实际为 nil")
				}
				return
			}
			if _, err := New(tt.secret, newTestClaims, tt.opts...); err == nil {
				t.Fatal("New() 应返回错误，实际为 nil")
			}
		})
	}
}

// TestSignClaimsPrecision 验证 int64 大数（超过 float64 安全整数范围 2^53）在签发/解析往返后不丢精度。
func TestSignClaimsPrecision(t *testing.T) {
	a := newTestAuth(t)
	// 2^53 + 1：历史上 map 中转用 float64 承接会把它舍入为 9007199254740992
	want := int64(9007199254740993)
	token, err := a.GenerateToken(&testClaims{UserID: want, Name: "u1"})
	if err != nil {
		t.Fatalf("GenerateToken() error = %v", err)
	}
	claims, err := a.Parse(token)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if claims.UserID != want {
		t.Fatalf("UserID 精度丢失：want %d, got %d", want, claims.UserID)
	}
	if claims.Name != "u1" {
		t.Fatalf("Name 往返不一致：want u1, got %s", claims.Name)
	}
}

func TestIssuerValidation(t *testing.T) {
	a := newTestAuth(t, WithIssuer("gjwt-test"))
	token, err := a.GenerateToken(&testClaims{UserID: 1})
	if err != nil {
		t.Fatalf("GenerateToken() error = %v", err)
	}
	if _, err := a.Parse(token); err != nil {
		t.Fatalf("同 issuer 的 token 应解析成功: %v", err)
	}

	// 用同一密钥伪造不同 iss 的 token，issuer 校验开启后必须拒绝
	makeToken := func(iss string) string {
		mc := jwt.MapClaims{"exp": time.Now().Add(time.Hour).Unix()}
		if iss != "" {
			mc["iss"] = iss
		}
		token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, mc).SignedString([]byte(testSecret))
		if err != nil {
			t.Fatalf("构造伪造 token 失败: %v", err)
		}
		return token
	}
	if _, err := a.Parse(makeToken("evil")); !errors.Is(err, ErrTokenInvalid) {
		t.Fatalf("伪造 iss 的 token 应报 invalid，got %v", err)
	}
	// 缺失 iss 的 token 同样应拒绝
	if _, err := a.Parse(makeToken("")); !errors.Is(err, ErrTokenInvalid) {
		t.Fatalf("缺失 iss 的 token 应报 invalid，got %v", err)
	}

	// 未配置 issuer 时不校验 iss（未配置即不启用该约束）
	a2 := newTestAuth(t)
	if _, err := a2.Parse(makeToken("evil")); err != nil {
		t.Fatalf("未配置 issuer 时不校验 iss，应解析成功: %v", err)
	}
}

func TestKeyIsolation(t *testing.T) {
	a := newTestAuth(t)
	pair, err := a.GenerateTokenPair(&testClaims{UserID: 1})
	if err != nil {
		t.Fatalf("GenerateTokenPair() error = %v", err)
	}
	// refresh token 不能通过业务验签
	if _, err := a.Parse(pair.RefreshToken); err == nil {
		t.Fatal("refresh token 不应通过 Parse 验签")
	}
	// access token 不能通过续签验签
	if _, err := a.RefreshTokenPair(pair.AccessToken); err == nil {
		t.Fatal("access token 不应通过 RefreshTokenPair 验签")
	}
	// 各自的正常路径可用，且业务字段完整保留
	if _, err := a.Parse(pair.AccessToken); err != nil {
		t.Fatalf("access token 应通过 Parse: %v", err)
	}
	pair2, err := a.RefreshTokenPair(pair.RefreshToken)
	if err != nil {
		t.Fatalf("RefreshTokenPair() error = %v", err)
	}
	claims2, err := a.Parse(pair2.AccessToken)
	if err != nil {
		t.Fatalf("续签后的 access token 应通过 Parse: %v", err)
	}
	if claims2.UserID != 1 {
		t.Fatalf("续签后业务字段丢失：want 1, got %d", claims2.UserID)
	}
}

func TestExpiry(t *testing.T) {
	base := time.Unix(1700000000, 0)
	now := base
	a := newTestAuth(t,
		WithAccessTTL(time.Hour),
		WithLeeway(time.Minute),
		WithTimeFunc(func() time.Time { return now }),
	)
	token, err := a.GenerateToken(&testClaims{UserID: 1})
	if err != nil {
		t.Fatalf("GenerateToken() error = %v", err)
	}
	// 未过期：解析成功
	now = base.Add(59 * time.Minute)
	if _, err := a.Parse(token); err != nil {
		t.Fatalf("未过期 token 应解析成功: %v", err)
	}
	// 过期但在 leeway 内：仍视为有效
	now = base.Add(time.Hour + 30*time.Second)
	if _, err := a.Parse(token); err != nil {
		t.Fatalf("leeway 内应仍有效: %v", err)
	}
	// 过期超过 leeway：报 expired
	now = base.Add(2 * time.Hour)
	_, err = a.Parse(token)
	if !errors.Is(err, ErrTokenExpired) {
		t.Fatalf("过期 token 应报 expired，got %v", err)
	}
}

func TestCustomErrors(t *testing.T) {
	base := time.Unix(1700000000, 0)
	now := base
	customExpired := gerror.NewCode(gcode.New(10041, "", nil), "登录已过期")
	a := newTestAuth(t,
		WithAccessTTL(time.Hour),
		WithErrors(Errors{TokenExpired: customExpired}),
		WithTimeFunc(func() time.Time { return now }),
	)
	token, err := a.GenerateToken(&testClaims{UserID: 1})
	if err != nil {
		t.Fatalf("GenerateToken() error = %v", err)
	}
	now = base.Add(2 * time.Hour)
	_, err = a.Parse(token)
	if err == nil {
		t.Fatal("过期 token 应返回错误")
	}
	if !errors.Is(err, customExpired) {
		t.Fatalf("应 errors.Is 匹配自定义错误，got %v", err)
	}
	if errors.Is(err, ErrTokenExpired) {
		t.Fatal("覆盖后不应再匹配默认错误实例")
	}
	if got := gerror.Code(err).Code(); got != 10041 {
		t.Fatalf("错误码应为自定义码 10041，got %d", got)
	}
	if err.Error() != "登录已过期" {
		t.Fatalf("提示语应为自定义内容，got %q", err.Error())
	}
}

// TestTokenPairConsistency 验证 TokenPair 中的过期时间与 token 内的 exp 严格一致（固定时钟下可精确断言）。
func TestTokenPairConsistency(t *testing.T) {
	base := time.Unix(1700000000, 0)
	a := newTestAuth(t,
		WithAccessTTL(time.Hour),
		WithRefreshTTL(24*time.Hour),
		WithTimeFunc(func() time.Time { return base }),
	)
	pair, err := a.GenerateTokenPair(&testClaims{UserID: 1})
	if err != nil {
		t.Fatalf("GenerateTokenPair() error = %v", err)
	}
	if pair.ExpiresAt != base.Add(time.Hour).Unix() {
		t.Fatalf("ExpiresAt = %d, want %d", pair.ExpiresAt, base.Add(time.Hour).Unix())
	}
	if pair.RefreshExpiresAt != base.Add(24*time.Hour).Unix() {
		t.Fatalf("RefreshExpiresAt = %d, want %d", pair.RefreshExpiresAt, base.Add(24*time.Hour).Unix())
	}
	claims, err := a.Parse(pair.AccessToken)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if claims.ExpiresAt.Unix() != pair.ExpiresAt {
		t.Fatalf("token 内 exp 与对外 ExpiresAt 不一致: %d vs %d", claims.ExpiresAt.Unix(), pair.ExpiresAt)
	}
}

// TestMapErrorKeepsOriginalCause 验证错误链中保留了 golang-jwt 的原始错误，便于线上排障。
func TestMapErrorKeepsOriginalCause(t *testing.T) {
	a := newTestAuth(t)
	token, err := a.GenerateToken(&testClaims{UserID: 1})
	if err != nil {
		t.Fatalf("GenerateToken() error = %v", err)
	}
	// 篡改签名末尾两个字符
	tampered := token[:len(token)-2] + "xx"
	_, err = a.Parse(tampered)
	if err == nil {
		t.Fatal("篡改签名的 token 应返回错误")
	}
	if !errors.Is(err, ErrTokenInvalid) {
		t.Fatalf("应报 invalid，got %v", err)
	}
	if !errors.Is(err, jwt.ErrTokenSignatureInvalid) {
		t.Fatalf("错误链应保留原始验签错误，got %v", err)
	}
}
