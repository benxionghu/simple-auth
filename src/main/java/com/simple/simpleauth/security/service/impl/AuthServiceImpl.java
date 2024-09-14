package com.simple.simpleauth.security.service.impl;

import com.simple.simpleauth.model.LoginForm;
import com.simple.simpleauth.model.LoginResult;
import com.simple.simpleauth.model.RefreshToken;
import com.simple.simpleauth.model.enums.LoginTypeEnum;
import com.simple.simpleauth.security.service.IAuthService;
import com.simple.simpleauth.utils.JwtUtil;
import com.simple.simpleauth.utils.RedisUtil;
import lombok.RequiredArgsConstructor;
import org.apache.tomcat.websocket.AuthenticationException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;

/**
 * @Author:benxiong.hu
 * @CreateAt:2024/9/3
 * @ModifyAt:2024/9/3
 * @Version:1.0
 */

@RequiredArgsConstructor
public class AuthServiceImpl implements IAuthService {

    private final JwtUtil jwtUtil;
    private final RedisUtil redisUtil;
    private final AuthenticationManager authenticationManager;

    /**
     * 本地登陆
     *
     * @param loginForm 登陆表单
     * @param type      登陆类型
     * @return LoginResult
     */
    @Override
    public LoginResult login(LoginForm loginForm, LoginTypeEnum type) {
        // 参数说明 : principal 主体 ，credentials 凭据
        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(loginForm, type);
        // 1. 获取到 UserDetails 对象
        Authentication authenticate = authenticationManager.authenticate(authenticationToken);
        // 2. 生成 Jwt Token;
        return jwtUtil.getLoginResult(authenticate);
    }

    /**
     * 刷新token
     *
     * @param refreshToken 刷新token表单
     * @return LoginResult
     */
    @Override
    public LoginResult refreshToken(RefreshToken refreshToken) throws AuthenticationException {
        if (!jwtUtil.isJwtExpired(refreshToken.getAccessToken())) {
            // 1.1 未过期刷新 token 未恶意刷新
            throw new AuthenticationException("token not out of date");
        }
        Long userId = jwtUtil.getUserId(refreshToken.getRefreshToken());
        if (userId == null) {
            // 2.1 userId 等于 null 表示 refreshToken 错误
            if (jwtUtil.isJwtExpired(refreshToken.getRefreshToken())) {
                // 2.1.1 RefreshToken 过期
                throw new AuthenticationException("token expires");
            } else {
                // 2.1.2 错误的 RefreshToken
                throw new AuthenticationException("token error");
            }
        }
        LoginResult loginResult = redisUtil.getCacheObject(jwtUtil.USER_TOKEN_CACHE_PREFIX + userId);
        if (loginResult == null) {
            // 3.1 表示 refreshToken 过期
            throw new AuthenticationException("token is null");
        }
        if (!refreshToken.getAccessToken().equals(loginResult.getAccessToken()) ||
                !refreshToken.getRefreshToken().equals(loginResult.getRefreshToken())) {
            // 3.2 如果 accessToken 和 refreshToken 有一个不一致 ， 表示恶意刷新 Token
            throw new AuthenticationException("malicious refresh");
        }
        // 4. 返回 刷新后的token
        return jwtUtil.refreshToken(refreshToken);
    }

    /**
     * 退出登陆
     *
     * @return 是否退出登陆成功
     */
    @Override
    public boolean logout() {
//        Long userId = SecurityUtil.getUserId();
//        // 删除 token
//        boolean deletedToken = redisUtil.deleteObject(jwtUtil.USER_TOKEN_CACHE_PREFIX + userId);
//        // 删除 权限
//        boolean deletedPermission = redisUtil.deleteObject(jwtUtil.USER_PERMISSIONS_CACHE_PREFIX + userId);
//        // 删除用户信息
//        redisUtil.deleteObject(RedisKeyConstants.SYSTEM_ME_CACHE_PREFIX + userId);
//        return deletedToken && deletedPermission;
        return false;
    }
}
