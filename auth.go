// Package gjwt 是一个基于 golang-jwt/v5 + HS256 的轻量认证库：
// 泛型 Auth[C] + 工厂函数定死解析类型，双密钥隔离 access/refresh token，
// 验签逻辑全部委托给第三方库，初始化可复杂、调用保持简单。
package gjwt

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/gogf/gf/v2/errors/gcode"
	"github.com/gogf/gf/v2/errors/gerror"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// minSecretLen 是 HS256 密钥的最低字节数：RFC 7518 要求 HMAC-SHA256 密钥
// 至少与哈希输出等长（256 位 = 32 字节），过短密钥会显著降低签名强度。
const minSecretLen = 32

// Errors 是可被业务覆盖的错误集合：三个场景各一个错误，
// 用 gerror.NewCode(gcode.New(自定义码, "", nil), "提示语") 传入即可适配任意前端的错误码约定。
// 只覆盖需要的字段，未设置的保持库默认值（统一为 401）。
//
// 重要：字段虽然声明为 error，但必须传入 gerror.NewCode 构造的错误实例。
// 若传入普通错误（如 errors.New），mappedError.Code() 会得到 CodeNil，
// gf 的 MiddlewareHandlerResponse 随即把它替换为 CodeInternalError（码 50），
// 出现"HTTP 401 + body code 50"的自相矛盾响应。
type Errors struct {
	TokenMissing error // 请求中未携带 token
	TokenInvalid error // 验签失败 / 格式非法 / 算法不在白名单
	TokenExpired error // token 已过期
}

func defaultErrors() Errors {
	return Errors{
		TokenMissing: ErrTokenMissing,
		TokenInvalid: ErrTokenInvalid,
		TokenExpired: ErrTokenExpired,
	}
}

// config 是非泛型的配置结构，Option 操作它——
// 这样 Option 无需携带类型参数（否则 WithIssuer 这类不接触 C 的选项无法推断 C）。
// refreshClaims 字段例外：它必须感知 C，因此存 any 原值、调用处断言回具体函数类型
// （见 New 与 refreshClaimsFor），类型不匹配在 New 时即报错。
type config struct {
	issuer        string
	accessTTL     time.Duration
	refreshTTL    time.Duration
	leeway        time.Duration
	refreshSecret string
	httpStatus    int
	nowFunc       func() time.Time
	errors        Errors
	refreshClaims any // func(C) jwt.Claims：refresh token 的 claims 抽取函数，nil 表示不启用最小化
}

func defaultConfig() config {
	return config{
		accessTTL:  2 * time.Hour,
		refreshTTL: 7 * 24 * time.Hour,
		leeway:     time.Minute,
		httpStatus: 401,
		nowFunc:    time.Now,
		errors:     defaultErrors(),
	}
}

type Option func(*config)

func WithIssuer(issuer string) Option {
	return func(c *config) { c.issuer = issuer }
}

func WithAccessTTL(d time.Duration) Option {
	return func(c *config) { c.accessTTL = d }
}

func WithRefreshTTL(d time.Duration) Option {
	return func(c *config) { c.refreshTTL = d }
}

// WithLeeway 设置过期校验的时钟偏移容忍时长，容忍范围内的"过期"仍视为有效。
func WithLeeway(d time.Duration) Option {
	return func(c *config) { c.leeway = d }
}

// WithRefreshSecret 显式指定续签密钥；不设置时自动从 accessSecret 派生，
// 密钥即身份：access token 拿去调续签接口、refresh token 拿去访问业务接口，验签都会直接失败。
func WithRefreshSecret(secret string) Option {
	return func(c *config) { c.refreshSecret = secret }
}

// WithRefreshClaims 配置 refresh token 的 claims 抽取函数（claims 最小化，least privilege 主流实践）。
// 未配置时 refresh token 与 access token 携带同一份业务 claims（默认行为）；
// 配置后 refresh token 只携带 fn 的返回值——长效令牌泄漏时暴露面最小，
// 用户资料变更后也不会把陈旧数据带进新一轮签发。
//
//	// refresh token 只装 userId，其余业务字段一律不进长效令牌
//	gjwt.WithRefreshClaims(func(c *MyClaims) jwt.Claims {
//	    return jwt.MapClaims{"userId": c.UserID}
//	})
//
// 配套的续签模式（主流安全实践，见 ParseRefresh 文档）：
//
//	ParseRefresh 验签 → 用 userId 查库确认用户状态并取最新数据 → 重建完整 claims → GenerateTokenPair。
//
// 注意三点：
//   - fn 返回 claims 的 JSON 字段名需与 C 中同名字段对齐，ParseRefresh 才能把值还原进 C（其余字段为零值）；
//   - fn 的参数类型必须与 Auth 的 C 一致，编译期无法拦截，类型不匹配会在 New 时返回错误；
//   - fn 传 nil 视为不启用（与未配置一致）：typed-nil 装箱进 any 后 != nil，
//     若不拦截会绕过判空并在首次签发时触发 nil 函数调用 panic。
func WithRefreshClaims[C jwt.Claims](fn func(C) jwt.Claims) Option {
	return func(c *config) {
		if fn == nil {
			return
		}
		c.refreshClaims = fn
	}
}

// WithErrors 覆盖库的默认错误（逐字段生效），
// 例如适配前端自定义错误码：gjwt.WithErrors(gjwt.Errors{TokenExpired: gerror.NewCode(gcode.New(10041, "", nil), "登录已过期")})
// 注意：传入的错误必须用 gerror.NewCode 构造（详见 Errors 类型说明），
// 传 errors.New 等普通错误会导致响应中间件输出内部错误码 50。
func WithErrors(e Errors) Option {
	return func(c *config) {
		if e.TokenMissing != nil {
			c.errors.TokenMissing = e.TokenMissing
		}
		if e.TokenInvalid != nil {
			c.errors.TokenInvalid = e.TokenInvalid
		}
		if e.TokenExpired != nil {
			c.errors.TokenExpired = e.TokenExpired
		}
	}
}

// WithHTTPStatus 设置鉴权失败时的 HTTP 状态码，默认 401。
// 部分前端约定 HTTP 200 + 业务码判错，可设为 200。
func WithHTTPStatus(status int) Option {
	return func(c *config) { c.httpStatus = status }
}

// WithTimeFunc 替换库内部使用的"当前时间"来源，默认 time.Now。
// 主要用于测试：注入可控的假时钟后，把时间拨到过期之后即可验证过期逻辑，
// 不需要真实等待；生产环境一般无需配置。
func WithTimeFunc(f func() time.Time) Option {
	return func(c *config) {
		if f != nil {
			c.nowFunc = f
		}
	}
}

// Auth 持有签发/验签的全部状态，一个服务按一种 claims 类型创建一个实例。
// 类型参数 C 即"解析返回的用户结构体指针类型"（如 *MyClaims），
// 由工厂函数在编译期定死，Parse 直接返回 C，无需断言。
// 实例创建后字段不再变更，可安全地并发使用。
type Auth[C jwt.Claims] struct {
	cfg        config
	accessKey  []byte
	refreshKey []byte
	newClaims  func() C
	parser     *jwt.Parser // 验签 Parser 本身无状态，初始化时构建一次复用
}

// now 返回库内部统一的时间源：所有"当前时间"都必须从这里取，
// WithTimeFunc 注入假时钟后整条签发/验签链路的时间行为都可控。
func (a *Auth[C]) now() time.Time {
	return a.cfg.nowFunc()
}

// New 创建 Auth。
// accessSecret：业务 token 的 HS256 密钥，长度至少 32 字节（低于该长度签名强度不足）；
// newClaims：工厂函数，每次解析调用一次，返回新实例供 golang-jwt 写入，
// 也是 C 类型的定义处，如 func() *MyClaims { return &MyClaims{} }。
func New[C jwt.Claims](accessSecret string, newClaims func() C, opts ...Option) (*Auth[C], error) {
	if err := validateSecret(accessSecret); err != nil {
		return nil, err
	}
	if newClaims == nil {
		return nil, gerror.New("claims factory must not be nil")
	}
	cfg := defaultConfig()
	for _, opt := range opts {
		opt(&cfg)
	}
	// TTL 配置静态校验：负值/过短会签出"出生即过期"的 token，提前报错而非静默产出坏数据
	if cfg.accessTTL <= 0 {
		return nil, gerror.Newf("access ttl must be positive, got %v", cfg.accessTTL)
	}
	if cfg.refreshTTL <= 0 {
		return nil, gerror.Newf("refresh ttl must be positive, got %v", cfg.refreshTTL)
	}
	if cfg.refreshTTL < cfg.accessTTL {
		return nil, gerror.Newf("refresh ttl (%v) must not be shorter than access ttl (%v)", cfg.refreshTTL, cfg.accessTTL)
	}
	if cfg.leeway < 0 {
		return nil, gerror.Newf("leeway must not be negative, got %v", cfg.leeway)
	}
	// HTTP 状态码静态校验：越界值（如 0）会被 gf 缓冲式 Response 静默回退为 200，
	// 与调用方意图相悖且难以排查，提前报错
	if cfg.httpStatus < 100 || cfg.httpStatus > 599 {
		return nil, gerror.Newf("http status must be in [100, 599], got %d", cfg.httpStatus)
	}
	// WithRefreshClaims 的抽取函数类型在初始化即校验：config 非泛型存的是 any，
	// 这里有 C 的完整上下文，可把原本延迟到首次签发的类型错误提前到启动阶段
	if cfg.refreshClaims != nil {
		if _, ok := cfg.refreshClaims.(func(C) jwt.Claims); !ok {
			return nil, gerror.New("WithRefreshClaims: fn must be of type func(C) jwt.Claims matching this Auth instance")
		}
	}
	a := &Auth[C]{
		cfg:       cfg,
		accessKey: []byte(accessSecret),
		newClaims: newClaims,
	}
	if strings.TrimSpace(cfg.refreshSecret) != "" {
		if err := validateSecret(cfg.refreshSecret); err != nil {
			return nil, gerror.Wrap(err, "refresh secret")
		}
		// 显式指定的续签密钥不能与业务密钥相同，否则 access token 可直接通过续签验签，
		// "双密钥隔离"的设计会静默失效
		if cfg.refreshSecret == accessSecret {
			return nil, gerror.New("refresh secret must differ from access secret")
		}
		a.refreshKey = []byte(cfg.refreshSecret)
	} else {
		a.refreshKey = deriveKey(a.accessKey)
	}
	a.parser = a.newParser()
	return a, nil
}

// validateSecret 校验密钥非空且长度不低于 HS256 的最低要求。
func validateSecret(secret string) error {
	if strings.TrimSpace(secret) == "" {
		return gerror.New("secret must not be empty")
	}
	if len(secret) < minSecretLen {
		return gerror.Newf("secret must be at least %d bytes for HS256, got %d", minSecretLen, len(secret))
	}
	return nil
}

// newParser 构建验签 Parser：算法白名单 + 时钟偏移容忍 + 注入时间源，
// 配置了 issuer 时同步开启校验（否则该配置只写不验、形同虚设）。
func (a *Auth[C]) newParser() *jwt.Parser {
	opts := []jwt.ParserOption{
		// 锁定算法白名单，防止攻击者把 header 的 alg 改成 none/RS256 伪造签名
		jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}),
		jwt.WithLeeway(a.cfg.leeway),
		// 验签侧同样使用注入的时间源，WithTimeFunc 后签发/验签的时钟行为完全可控
		jwt.WithTimeFunc(a.now),
	}
	if a.cfg.issuer != "" {
		opts = append(opts, jwt.WithIssuer(a.cfg.issuer))
	}
	return jwt.NewParser(opts...)
}

// deriveKey 从主密钥确定性派生子密钥：同一根密钥域分离出独立用途，
// 等价于配置了两个无关联的 secret，但初始化方只需提供一个。
func deriveKey(secret []byte) []byte {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte("gjwt:refresh-key"))
	return mac.Sum(nil)
}

// TokenPair 一次签发的双令牌。ExpiresAt 给前端用于在过期前静默刷新（SoybeanAdmin 内置该流程）。
type TokenPair struct {
	AccessToken      string `json:"accessToken"`
	RefreshToken     string `json:"refreshToken"`
	ExpiresAt        int64  `json:"expiresAt"`
	RefreshExpiresAt int64  `json:"refreshExpiresAt"`
}

// GenerateToken 签发单个业务 token（无续签需求的内部服务可用）。
func (a *Auth[C]) GenerateToken(claims C) (string, error) {
	return a.sign(claims, a.accessKey, a.cfg.accessTTL, a.now())
}

// GenerateTokenPair 签发双令牌：access token 携带完整业务 claims（短寿命），
// refresh token 默认携带同一份 claims；配置 WithRefreshClaims 后只携带抽取出的最小 claims（长寿命）。
func (a *Auth[C]) GenerateTokenPair(claims C) (*TokenPair, error) {
	// 时间源只取一次：保证 token 内的 exp 与返回给前端的 ExpiresAt 严格一致，
	// 避免两次取时跨秒导致前端按 ExpiresAt 做静默刷新时出现偏差
	now := a.now()
	access, err := a.sign(claims, a.accessKey, a.cfg.accessTTL, now)
	if err != nil {
		return nil, err
	}
	refreshClaims, err := a.refreshClaimsFor(claims)
	if err != nil {
		return nil, err
	}
	refresh, err := a.sign(refreshClaims, a.refreshKey, a.cfg.refreshTTL, now)
	if err != nil {
		return nil, err
	}
	return &TokenPair{
		AccessToken:      access,
		RefreshToken:     refresh,
		ExpiresAt:        now.Add(a.cfg.accessTTL).Unix(),
		RefreshExpiresAt: now.Add(a.cfg.refreshTTL).Unix(),
	}, nil
}

// refreshClaimsFor 返回 refresh token 实际携带的 claims：
// 未配置 WithRefreshClaims 时与 access claims 相同（默认行为）；
// 配置后为抽取函数的返回值。config 非泛型所以存 any，在这里断言回具体类型——
// New 已做过同样的校验，此处是运行时兜底，正常路径不会走到失败分支。
func (a *Auth[C]) refreshClaimsFor(claims C) (jwt.Claims, error) {
	if a.cfg.refreshClaims == nil {
		return claims, nil
	}
	fn, ok := a.cfg.refreshClaims.(func(C) jwt.Claims)
	if !ok {
		return nil, gerror.New("WithRefreshClaims: fn must be of type func(C) jwt.Claims matching this Auth instance")
	}
	return fn(claims), nil
}

// parseWithKey 是 Parse/ParseRefresh 的共用实现：验签、过期校验、issuer 校验、
// 算法白名单校验全部由 parser 完成，两个方法唯一的区别是用哪把密钥（密钥即身份）。
func (a *Auth[C]) parseWithKey(tokenString string, key []byte) (C, error) {
	var zero C
	claims := a.newClaims()
	_, err := a.parser.ParseWithClaims(tokenString, claims, func(*jwt.Token) (interface{}, error) {
		return key, nil
	})
	if err != nil {
		return zero, a.mapError(err)
	}
	return claims, nil
}

// Parse 用 access 密钥验签并解析为 C（初始化时工厂函数定死的类型），单次原生解析。
// 验签、过期校验、issuer 校验、算法白名单校验全部由 golang-jwt 完成，本库只做错误翻译。
func (a *Auth[C]) Parse(tokenString string) (C, error) {
	return a.parseWithKey(tokenString, a.accessKey)
}

// ParseRefresh 用 refresh 密钥验签续签 token 并解析为 C，与 Parse 对称。
// 拿 access token 调本方法会在 refresh 密钥处验签失败，无需类型字段判断。
//
// 它存在的意义是把"验签"与"重新签发"解耦（RefreshTokenPair 把两者绑死），
// 解锁主流的安全续签模式——续签时服务端必须有机会介入校验：
//
//	claims, err := auth.ParseRefresh(refreshToken)   // 1. 验签续签 token
//	if err != nil { /* 让用户重新登录 */ }
//	user := db.GetUser(claims.UserID)                // 2. 查库：确认未被禁用 + 取最新数据
//	if user.Disabled { /* 拒绝续签 */ }
//	pair, err := auth.GenerateTokenPair(&MyClaims{   // 3. 用最新数据重建 claims 重新签发
//	    UserID: user.ID, Role: user.Role,
//	})
//
// 若配置了 WithRefreshClaims，claims 中通常只有标识字段（如 UserID）有值，
// 其余字段为零值——这正好强制业务走"查库重建"而不是信任 token 里的陈旧数据。
// 封禁的用户因此在 refresh token 过期前无法继续续签。
func (a *Auth[C]) ParseRefresh(tokenString string) (C, error) {
	return a.parseWithKey(tokenString, a.refreshKey)
}

// RefreshTokenPair 用 refresh 密钥验签续签 token 并原样签发新令牌对（claims 不经服务端介入）。
// 适用于无状态、无吊销需求的内部服务；对外业务建议使用 ParseRefresh + 查库重建的
// 三步式续签（见 ParseRefresh 文档），在续签前确认用户状态。
//
// 注意与 WithRefreshClaims 的组合：最小化配置下 refresh token 只携带标识字段，
// 本方法续出的新 access token 同样只含这些字段（Name/Role 等业务字段为零值）。
// handler 依赖这些字段时必须改用三步式续签；handler 本来就只取标识字段（业务数据
// 每次查库）时，本方法仍可安全使用。
func (a *Auth[C]) RefreshTokenPair(refreshToken string) (*TokenPair, error) {
	claims, err := a.ParseRefresh(refreshToken)
	if err != nil {
		return nil, err
	}
	return a.GenerateTokenPair(claims)
}

// sign 把 claims 序列化为 map 后签名（C 与 jwt.Claims 均可传入）。
// 走 map 中转的原因：exp/iat/jti/iss 这些注册字段由库统一写入并覆盖，
// 用户构造 claims 时完全不用手动填 NumericDate（教程里最啰嗦的部分）。
func (a *Auth[C]) sign(claims jwt.Claims, key []byte, ttl time.Duration, now time.Time) (string, error) {
	data, err := json.Marshal(claims)
	if err != nil {
		return "", gerror.Wrap(err, "marshal claims failed")
	}
	mc := jwt.MapClaims{}
	// 解码开启 UseNumber：数字保留为 json.Number 而非 float64，
	// 否则超过 2^53 的 int64（如雪花 ID）会在 map 中转时精度丢失
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if err := dec.Decode(&mc); err != nil {
		return "", gerror.Wrap(err, "unmarshal claims failed")
	}
	mc["iat"] = now.Unix()
	mc["exp"] = now.Add(ttl).Unix()
	mc["jti"] = uuid.NewString()
	if a.cfg.issuer != "" {
		mc["iss"] = a.cfg.issuer
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, mc)
	signed, err := token.SignedString(key)
	if err != nil {
		return "", gerror.Wrap(err, "sign token failed")
	}
	return signed, nil
}

// mappedError 是验签失败的统一错误载体：
// Error() 与错误码始终为用户配置的值（响应中间件只会输出干净的提示语，不泄漏 jwt 内部细节），
// 错误链同时保留配置错误实例（errors.Is(err, gjwt.ErrTokenExpired) 照常可用）
// 与失败的原始原因（errors.As / %+v 可查真实原因，如签名不符 / issuer 不符，供排障）。
type mappedError struct {
	configured error  // 用户配置或库默认的错误实例（含 gcode 错误码）
	cause      error  // 原始错误：golang-jwt 验签错误，或 token 提取阶段的错误
	msg        string // 对外提示语，与 configured.Error() 一致
	missing    bool   // 语义类别：请求未携带 token 为 true（供 reject 决定 WWW-Authenticate 格式）
}

func (e *mappedError) Error() string    { return e.msg }
func (e *mappedError) Code() gcode.Code { return gerror.Code(e.configured) }
func (e *mappedError) Unwrap() []error  { return []error{e.configured, e.cause} }

// mapError 把 golang-jwt 的错误翻译为配置中的错误（默认或用户覆盖后的 gerror.NewCode 错误），
// 调用方无需 import jwt 包。
func (a *Auth[C]) mapError(err error) error {
	configured := a.cfg.errors.TokenInvalid
	if errors.Is(err, jwt.ErrTokenExpired) {
		configured = a.cfg.errors.TokenExpired
	}
	return &mappedError{configured: configured, cause: err, msg: configured.Error()}
}
