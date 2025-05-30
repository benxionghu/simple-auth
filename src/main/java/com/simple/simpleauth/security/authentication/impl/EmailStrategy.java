package com.simple.simpleauth.security.authentication.impl;

import cn.hutool.core.lang.Validator;
import com.simple.simpleauth.model.LoginForm;
import com.simple.simpleauth.model.UserAuthInfo;
import com.simple.simpleauth.model.UserInfoDetail;
import com.simple.simpleauth.model.enums.LoginTypeEnum;
import com.simple.simpleauth.security.authentication.ILoginProcessStrategy;
import com.simple.simpleauth.security.service.IAuthenticationService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;


/**
 * 邮件登录
 *
 * @Author:benxiong.hu
 * @CreateAt:2024/9/5
 * @ModifyAt:2024/9/5
 * @Version:1.0
 */
@Component
@RequiredArgsConstructor
public class EmailStrategy implements ILoginProcessStrategy {

    private final IAuthenticationService authenticationService;

    /**
     * 获取登录类型
     */
    @Override
    public LoginTypeEnum getLoginTypeSupport() {
        return LoginTypeEnum.EMAIL;
    }

    /**
     * 自动注册用户 : 默认已注册
     *
     * @param principal
     */
    @Override
    public boolean registeredUsers(LoginForm principal) {
        String email = principal.getEmail();
        if (!Validator.isEmail(email)) {
            throw new AuthenticationServiceException("invalid email format");
        }
        Boolean checkUserExist = authenticationService.checkUserExist(principal, LoginTypeEnum.EMAIL);
        if (checkUserExist) {
            return true;
        }
        return authenticationService.registeredUsers(principal, LoginTypeEnum.EMAIL);
    }

    /**
     * 校验登录参数
     *
     * @param principal 主体
     */
    @Override
    public boolean validateParameters(LoginForm principal) {
        String email = principal.getEmail();
        String emailCode = principal.getEmailCode();
        // 1. 校验邮箱合法性
        if (!Validator.isEmail(email)) {
            throw new AuthenticationServiceException("invalid email format");
        }
        // 2. 校验验证码合法性
        if (!authenticationService.getEmailLength().equals(emailCode.length())) {
            throw new AuthenticationServiceException("invalid email length format");
        }
        // 3. 验证验证码是否正确
        if (!authenticationService.checkEmailCode(principal.getEmail(), principal.getEmailCode())) {
            throw new AuthenticationServiceException("invalid email code format");
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
        UserAuthInfo userAuthInfo = authenticationService.getUserDetailsByPrincipal(principal, LoginTypeEnum.EMAIL);
        return new UserInfoDetail(userAuthInfo);
    }
}
