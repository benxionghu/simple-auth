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
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

/**
 * 手机号登录
 *
 * @version 1.0
 * @author: benxiong.hu
 * @createAt: 2024/11/01 15:54:43
 * @modifyAt: 2024/11/01 15:54:43
 */
@Service
@RequiredArgsConstructor
public class PhoneStrategy implements ILoginProcessStrategy {

    private final IAuthenticationService authenticationService;

    /**
     * 获取登录类型
     */
    @Override
    public LoginTypeEnum getLoginTypeSupport() {
        return LoginTypeEnum.PHONE;
    }

    /**
     * 自动注册用户 : 默认已注册
     *
     * @param principal
     */
    @Override
    public boolean registeredUsers(LoginForm principal) {
        if (!Validator.isMobile(principal.getPhoneNumber())) {
            throw new AuthenticationServiceException("invalid phone number format");
        }
        if (StringUtils.isEmpty(principal.getSmsCode())) {
            throw new AuthenticationServiceException("sms code is empty");
        }
        if (!authenticationService.checkPhoneCode(principal.getPhoneNumber(), principal.getSmsCode())) {
            throw new AuthenticationServiceException("sms code is error");
        }
        if (authenticationService.checkUserExist(principal, LoginTypeEnum.PHONE)) {
            return true;
        }
        return authenticationService.registeredUsers(principal, LoginTypeEnum.PHONE);
    }

    /**
     * 校验登录参数
     *
     * @param principal 主体
     */
    @Override
    public boolean validateParameters(LoginForm principal) {
        if (!Validator.isMobile(principal.getPhoneNumber())) {
            throw new AuthenticationServiceException("invalid phone number format");
        }
        if (StringUtils.isEmpty(principal.getSmsCode())) {
            throw new AuthenticationServiceException("sms code is empty");
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
        UserAuthInfo userAuthInfo = authenticationService.getUserDetailsByPrincipal(principal, LoginTypeEnum.PHONE);
        return new UserInfoDetail(userAuthInfo);
    }
}
