package com.simple.simpleauth.security.service;

import com.simple.simpleauth.model.LoginForm;
import com.simple.simpleauth.model.LoginResult;
import com.simple.simpleauth.model.RefreshToken;
import com.simple.simpleauth.model.enums.LoginTypeEnum;
import org.apache.tomcat.websocket.AuthenticationException;

/**
 * @Author:benxiong.hu
 * @CreateAt:2024/9/3
 * @ModifyAt:2024/9/3
 * @Version:1.0
 */
public interface IAuthService {
    /**
     * 本地登陆
     *
     * @param loginForm 登陆表单
     * @param type      登陆类型
     * @return LoginResult
     */
    LoginResult login(LoginForm loginForm, LoginTypeEnum type);

    /**
     * 刷新token
     *
     * @param refreshToken 刷新token表单
     * @return LoginResult
     */
    LoginResult refreshToken(RefreshToken refreshToken) throws AuthenticationException;

    /**
     * 退出登陆
     *
     * @return 是否退出登陆成功
     */
    boolean logout();
}
