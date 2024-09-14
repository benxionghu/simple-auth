package com.simple.simpleauth.security.authentication.impl;

import com.simple.simpleauth.model.LoginForm;
import com.simple.simpleauth.model.enums.LoginTypeEnum;
import com.simple.simpleauth.security.authentication.ILoginProcessStrategy;
import com.simple.simpleauth.security.service.IAuthenticationService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * @Author:benxiong.hu
 * @CreateAt:2024/9/5
 * @ModifyAt:2024/9/5
 * @Version:1.0
 */
@Component
@RequiredArgsConstructor
public class EmailStrategy implements ILoginProcessStrategy {

    private static final String EMAIL_REGEX = "^[A-Za-z0-9+_.-]+@[A-Za-z0-9.-]+$";

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
        // todo 验证邮箱是否正确

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
        Pattern pattern = Pattern.compile(EMAIL_REGEX);
        // 创建 matcher 对象
        Matcher matcher = pattern.matcher(principal.getEmail());
        return matcher.matches();
    }

    /**
     * 获取用户信息
     *
     * @param principal
     */
    @Override
    public UserDetails getUserDetailsByPrincipal(LoginForm principal) {
        return authenticationService.getUserDetailsByPrincipal(principal, LoginTypeEnum.EMAIL);
    }

    /**
     * 后置校验用户信息 : 默认校验成功
     *
     * @param principal
     * @param userDetails
     */
    @Override
    public boolean validatePostParameters(LoginForm principal, UserDetails userDetails) {
        return true;
    }
}
