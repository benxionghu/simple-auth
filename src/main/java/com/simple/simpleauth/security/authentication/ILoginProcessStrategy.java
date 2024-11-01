package com.simple.simpleauth.security.authentication;

import com.simple.simpleauth.model.LoginForm;
import com.simple.simpleauth.model.enums.LoginTypeEnum;
import org.springframework.security.core.userdetails.UserDetails;

/**
 * @Author:benxiong.hu
 * @CreateAt:2024/9/3
 * @ModifyAt:2024/9/3
 * @Version:1.0
 */
public interface ILoginProcessStrategy {

    /**
     * 获取登录类型
     */
    LoginTypeEnum getLoginTypeSupport();

    /**
     * 自动注册用户 : 默认已注册
     */
    boolean registeredUsers(LoginForm principal);

    /**
     * 校验登录参数
     *
     * @param principal 主体
     */
    boolean validateParameters(LoginForm principal);

    /**
     * 获取用户信息
     */
    UserDetails getUserDetailsByPrincipal(LoginForm principal);

    /**
     * 后置校验用户信息 : 默认校验成功
     */
    default boolean validatePostParameters(LoginForm principal, UserDetails userDetails) {
        return true;
    }

}
