package com.simple.simpleauth.security.service;

import com.simple.simpleauth.model.LoginForm;
import com.simple.simpleauth.model.UserAuthInfo;
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
     * @param principal     登录信息
     * @param loginTypeEnum 登录类型
     * @return 用户是否登录存在
     */
    Boolean checkUserExist(LoginForm principal, LoginTypeEnum loginTypeEnum);

    /**
     * 获取用户信息
     *
     * @param principal     登录信息
     * @param loginTypeEnum 登录类型
     * @return 用户信息
     */
    UserAuthInfo getUserDetailsByPrincipal(LoginForm principal, LoginTypeEnum loginTypeEnum);

    /**
     * 注册用户信息
     *
     * @param principal     登录信息
     * @param loginTypeEnum 登录类型
     * @return 用户是否注册成功
     */
    Boolean registeredUsers(LoginForm principal, LoginTypeEnum loginTypeEnum);

    /**
     * 校验邮箱验证码是否正确
     *
     * @param email     邮箱
     * @param emailCode 邮箱验证码
     * @return
     */
    default Boolean checkEmailCode(String email, String emailCode) {
        return false;
    }

    /**
     * 校验手机验证码是否正确
     *
     * @param phone     手机号
     * @param phoneCode 手机验证码
     * @return
     */
    default Boolean checkPhoneCode(String phone, String phoneCode) {
        return false;
    }


    /**
     * 获取email验证码长度 支持自定义
     *
     * @return
     */
    default Integer getEmailLength() {
        return 6;
    }

}
