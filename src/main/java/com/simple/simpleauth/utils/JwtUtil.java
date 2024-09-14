package com.simple.simpleauth.utils;

import com.simple.simpleauth.config.propertoes.JwtConfiguration;
import com.simple.simpleauth.model.LoginResult;
import com.simple.simpleauth.model.RefreshToken;
import com.simple.simpleauth.model.UserInfoDetail;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import jakarta.annotation.PostConstruct;
import jakarta.servlet.http.HttpServletRequest;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Component;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

/**
 * @Author:benxiong.hu
 * @CreateAt:2024/8/12
 * @ModifyAt:2024/8/12
 * @Version:1.0
 */
@Component
@RequiredArgsConstructor
public class JwtUtil {

    public static final String USER_TOKEN_CACHE_PREFIX = "USER:TOKEN:";

    public static final String USER_PERMISSIONS_CACHE_PREFIX = "USER:PERMISSIONS:";

    public static final String WEBSOCKET = "websocket";
    private static final Logger log = LoggerFactory.getLogger(JwtUtil.class);

    private static final String USER_NAME = "username";
    private static final String USER_ID = "userId";
    private static final String DEPT_ID = "deptId";
    private static final String DATA_SCOPE = "dataScope";
    private final static String TENANT_ID = "tenantId";
    private static final String ROLE = "role";
    private final RedisUtil redisUtil;
    private final JwtConfiguration jwtConfiguration;

    @Getter
    private SecretKey secretKey;

    @PostConstruct
    private void init() {
        try {
            SecureRandom secureRandom = SecureRandom.getInstance("SHA1PRNG");
            // 使用固定的种子
            secureRandom.setSeed(jwtConfiguration.getSecretKey().getBytes());
            KeyGenerator keyGen = KeyGenerator.getInstance("HmacSHA256");
            // 使用 256 位的密钥和固定的随机数生成器
            keyGen.init(256, secureRandom);
            secretKey = keyGen.generateKey();
            log.info("init secretKey：{}", secretKey);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("生成 JWT SecretKey 失败" + e.getMessage());
        }
    }


    /**
     * 获取登录用户对象
     *
     * @param authenticate 认证信息
     * @return 登录结果
     */
    public LoginResult getLoginResult(Authentication authenticate) {
        if (authenticate == null || authenticate.getPrincipal() == null) {
            return null;
        }
        UserInfoDetail principal = (UserInfoDetail) authenticate.getPrincipal();
        // 1. 构建对应参数
        // 1.1 特殊说明一下过期时间 , 会有短暂误差
        Duration accessTokenExpirationTime = jwtConfiguration.getAccessTokenExpirationTime();
        Duration refreshTokenExpirationTime = jwtConfiguration.getRefreshTokenExpirationTime();
        String accessToken = generateAccessToken(authenticate);
        String refreshToken = generateRefreshToken(authenticate);
        // 2. 构建 LoginResult 对象
        LoginResult result = LoginResult.builder().accessToken(accessToken).refreshToken(refreshToken).expires(Date.from(Instant.now().plus(accessTokenExpirationTime)).getTime()).build();
        // 3. 数据存入 redis ( 做一人一号认证，以及退出登录 )
        redisUtil.setCacheObject(USER_TOKEN_CACHE_PREFIX + principal.getUserId(), result, refreshTokenExpirationTime.toMillis(), TimeUnit.MILLISECONDS);
        // 4. 写入 权限信息
        redisUtil.setCacheObject(USER_PERMISSIONS_CACHE_PREFIX + principal.getUserId(), principal.getPermissions(), refreshTokenExpirationTime.toMillis(), TimeUnit.MILLISECONDS);
        return result;
    }


    /**
     * 生成 AccessToken
     *
     * @param authentication 授权参数信息
     * @return
     */
    private String generateAccessToken(Authentication authentication) {
        // 从认证信息中获取用户详细信息
        UserInfoDetail principal = (UserInfoDetail) authentication.getPrincipal();

        // 解析角色信息并插入到声明中  收集角色信息
        Set<String> roles = principal.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.toSet());
        return Jwts.builder().issuer(jwtConfiguration.getIssuer()).issuedAt(new Date())
                // 用户id
                .claim(USER_ID, principal.getUserId())
                // 用户名
                .claim(USER_NAME, principal.getUsername())
                // 租户id
                .claim(TENANT_ID, Optional.ofNullable(principal.getTenantId()).orElse(0L))
                // 部门名
                .claim(DEPT_ID, principal.getDeptId())
                // 数据权限
                .claim(DATA_SCOPE, principal.getDataScope())
                // 角色
                .claim(ROLE, roles)
                // 过期时间
                .signWith(getSecretKey()).expiration(Date.from(Instant.now().plus(jwtConfiguration.getAccessTokenExpirationTime())))
                .compact();

    }


    /**
     * 去除 Token 前缀
     *
     * @param request 原始 Token
     * @return 去除前缀后的 Token
     */
    public String removeTokenPrefix(HttpServletRequest request) {
        // 1. http 请求处理
        String authorization = jwtConfiguration.getRequestHeaderKey();
        String token = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (token == null) {
            // 2. websocket => sec-websocket-protocol ( 该系统支持自定义协议 JWT_PROTOCOL )
            if (WEBSOCKET.equals(request.getHeader(HttpHeaders.UPGRADE))) {
                token = request.getParameter(authorization);
            }
        }
        if (token != null && token.startsWith(jwtConfiguration.getTokenPrefix())) {
            return token.substring(jwtConfiguration.getTokenPrefix().length());
        }
        return null;
    }

    /**
     * 解析 JWT Token 获取声明
     *
     * @param token JWT Token
     * @return 解析后的声明对象
     */
    private Claims parseTokenClaims(String token) {
        try {
            return Jwts.parser().verifyWith(getSecretKey()).build().parseSignedClaims(token).getPayload();
        } catch (Exception e) {
            // 解析失败返回 null
            return null;
        }
    }

    /**
     * 判断 token 是否过期
     *
     * @param token 令牌
     * @return 是否过期
     */
    public boolean isJwtExpired(String token) {
        try {
            Jwts.parser().verifyWith(getSecretKey()).build().parseSignedClaims(token).getPayload();
            return false;
        } catch (ExpiredJwtException e) {
            return true;
        } catch (Exception e) {
            // 需要根据自己系统决定解析错误的 token 为 true 还是 false
            // 目前表示无法判断是否过期 , 无法解析
            return false;
        }
    }


    /**
     * 生成 RefreshToken
     *
     * @param authentication 权限信息
     * @return RefreshToken
     */
    private String generateRefreshToken(Authentication authentication) {
        UserInfoDetail principal = (UserInfoDetail) authentication.getPrincipal();
        return Jwts.builder()
                // 签发公司名
                .issuer(jwtConfiguration.getIssuer())
                // 签发日期
                .issuedAt(new Date())
                // USER_ID
                .claim(USER_ID, principal.getUserId())
                // 租户id
                .claim(TENANT_ID, Optional.ofNullable(principal.getTenantId()).orElse(0L))
                // SecretKey
                .signWith(getSecretKey())
                // jwt过期时间
                .expiration(Date.from(Instant.now().plus(jwtConfiguration.getRefreshTokenExpirationTime())))
                .compact();
    }


    /**
     * 实行方案二
     * 方案一 : 每次使用同一个 refreshToken , 达到 refreshToken 过期，则无法刷新，需要重新登录的效果
     * 方案二 : 每次刷新将 refreshToken 一并刷新 ， 达到永久登录的效果
     *
     * @param refreshTokenForm 刷新 token 表单信息
     * @return LoginResult
     */
    public LoginResult refreshToken(RefreshToken refreshTokenForm) {
        Duration tokenSkewTime = jwtConfiguration.getRefreshTokenExpirationTime().minus(jwtConfiguration.getAccessTokenExpirationTime());
        Duration accessTokenExpirationTime = jwtConfiguration.getAccessTokenExpirationTime();
        Duration refreshTokenExpirationTime = jwtConfiguration.getRefreshTokenExpirationTime();
        String accessToken = refreshTokenForm.getAccessToken();
        try {
            // 1. 解析 claims
            Claims claims = Jwts.parser()
                    .verifyWith(getSecretKey())
                    .clockSkewSeconds(tokenSkewTime.getSeconds())
                    .build()
                    .parseSignedClaims(accessToken)
                    .getPayload();
            Long userId = claims.get(USER_ID, Long.class);
            Long tenantId = claims.get(TENANT_ID, Long.class);
            // 2. 生成 accessToken
            String newAccessToken = Jwts.builder().claims(claims)
//                    .issuedAt(new Date())       // 去掉 issuedAt 可以通过jwt获取到第一次登录的时间
                    .expiration(Date.from(Instant.now().plus(accessTokenExpirationTime)))
                    .signWith(getSecretKey())
                    .compact();
            // 3. 生成 refreshToken
            String newRefreshToken = Jwts.builder()
                    .issuer(claims.getIssuer())
                    .issuedAt(new Date())
                    .claim(USER_ID, userId)
                    .claim(TENANT_ID, tenantId)
                    .expiration(Date.from(Instant.now().plus(refreshTokenExpirationTime))).signWith(getSecretKey()).compact();
            // 4. 构建 loginResult
            LoginResult result = LoginResult.builder().accessToken(newAccessToken).refreshToken(newRefreshToken).expires(Date.from(Instant.now().plus(accessTokenExpirationTime)).getTime()).build();
            // 5. 存入 redis ( 防止旧的 refreshToken 能使用 )
            redisUtil.setCacheObject(USER_TOKEN_CACHE_PREFIX + userId, result, refreshTokenExpirationTime.toMillis(), TimeUnit.MILLISECONDS);
            // 6. 刷新 redis 权限缓存时间
            redisUtil.expire(USER_PERMISSIONS_CACHE_PREFIX + userId, refreshTokenExpirationTime.toMillis(), TimeUnit.MILLISECONDS);
            // 7. 返回 LoginResult
            return result;
        } catch (Exception e) {
            log.error("JwtUtil.refreshToken() 错误信息 : ", e);
            return null;
        }
    }

    /**
     * 解析用户id
     *
     * @param refreshToken 刷新 token
     * @return refreshToken中的用户id
     */
    public Long getUserId(String refreshToken) {
        Claims claims = this.parseTokenClaims(refreshToken);
        if (claims == null) {
            return null;
        }
        return claims.get(USER_ID, Long.class);
    }

    /**
     * 解析租户Id
     *
     * @param refreshToken 刷新 token
     * @return refreshToken中的用户id
     */
    public Long getTenantId(String refreshToken) {
        Claims claims = this.parseTokenClaims(refreshToken);
        if (claims == null) {
            return null;
        }
        return claims.get(TENANT_ID, Long.class);
    }

}
