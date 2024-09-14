package com.simple.simpleauth.security.service;

import com.simple.simpleauth.model.LoginForm;
import com.simple.simpleauth.model.enums.LoginTypeEnum;
import org.springframework.security.core.userdetails.UserDetails;

/**
 * 获取用户相关信息
 * 需要手动集成并且实现
 *
 * @Author:benxiong.hu
 * @CreateAt:2024/9/3
 * @ModifyAt:2024/9/3
 * @Version:1.0
 */
public interface IAuthenticationService {

    /**
     * 验证用户是否存在
     *
     * @param principal
     * @param loginTypeEnum
     * @return
     */
    Boolean checkUserExist(LoginForm principal, LoginTypeEnum loginTypeEnum);

    /**
     * 获取用户信息
     *
     * @param principal     登录信息
     * @param loginTypeEnum 登录类型
     * @return
     */
    UserDetails getUserDetailsByPrincipal(LoginForm principal, LoginTypeEnum loginTypeEnum);

    /**
     * 注册用户信息
     *
     * @param principal     登录信息
     * @param loginTypeEnum 登录类型
     * @return
     */
    Boolean registeredUsers(LoginForm principal, LoginTypeEnum loginTypeEnum);

}
