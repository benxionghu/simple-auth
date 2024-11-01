package com.simple.simpleauth.security.authentication.impl;

import com.simple.simpleauth.model.LoginForm;
import com.simple.simpleauth.model.UserAuthInfo;
import com.simple.simpleauth.model.UserInfoDetail;
import com.simple.simpleauth.model.enums.LoginTypeEnum;
import com.simple.simpleauth.security.authentication.ILoginProcessStrategy;
import com.simple.simpleauth.security.service.IAuthenticationService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

/**
 * 用户名和密码登录
 *
 * @Author:benxiong.hu
 * @CreateAt:2024/9/3
 * @ModifyAt:2024/9/3
 * @Version:1.0
 */
@Component
@RequiredArgsConstructor
public class UsernamePasswordStrategy implements ILoginProcessStrategy {

    private final PasswordEncoder passwordEncoder;

    private final IAuthenticationService authenticationService;

    /**
     * 获取登录类型
     */
    @Override
    public LoginTypeEnum getLoginTypeSupport() {
        return LoginTypeEnum.USERNAME_PASSWORD;
    }

    /**
     * 自动注册用户 : 默认已注册
     *
     * @param principal
     */
    @Override
    public boolean registeredUsers(LoginForm principal) {
        // todo 需要确认系统是否需要自动注册
        // 如果需要则提前设置
        //authenticationService.registeredUsers(principal, LoginTypeEnum.USERNAME_PASSWORD);
        return false;
    }

    /**
     * 校验登录参数
     *
     * @param principal 主体
     */
    @Override
    public boolean validateParameters(LoginForm principal) {
        String username = principal.getUsername();
        String password = principal.getPassword();
        if (username == null) {
            throw new AuthenticationServiceException("invalid username format");
        }
        // 2. 校验密码
        if (password == null) {
            throw new AuthenticationServiceException("invalid password format");
        }
        return true;
    }

    /**
     * 获取用户信息
     *
     * @param principal
     */
    @Override
    public UserDetails getUserDetailsByPrincipal(LoginForm principal) {
        UserAuthInfo userAuthInfo = authenticationService.getUserDetailsByPrincipal(principal, LoginTypeEnum.USERNAME_PASSWORD);
        return new UserInfoDetail(userAuthInfo);
    }

    /**
     * 后置校验用户信息 : 默认校验成功
     *
     * @param principal
     * @param userDetails
     */
    @Override
    public boolean validatePostParameters(LoginForm principal, UserDetails userDetails) {
        return passwordEncoder.matches(principal.getPassword(), userDetails.getPassword());
    }
}
