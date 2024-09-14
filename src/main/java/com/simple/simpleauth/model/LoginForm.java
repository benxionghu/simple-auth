package com.simple.simpleauth.model;

import lombok.Data;
import lombok.ToString;
import me.zhyd.oauth.model.AuthCallback;

/**
 * 登录请求参数
 *
 * @Author:benxiong.hu
 * @CreateAt:2024/9/3
 * @ModifyAt:2024/9/3
 * @Version:1.0
 */
@Data
@ToString
public class LoginForm {

    /**
     * 用户Id
     */
    private String userId;

    /**
     * 用户名
     */
    private String username;

    /**
     * 手机号
     */
    private String phoneNumber;

    /**
     * 邮箱
     */
    private String email;

    /**
     * 密码
     */
    private String password;

    /**
     * 验证码
     */
    private String verifyCode;

    /**
     * 验证码标识 key
     */
    private String verifyCodeKey;

    /**
     * 短信验证码
     */
    private String smsCode;

    /**
     * 邮箱验证码
     */
    private String emailCode;

    /**
     * 第三方登录 Oauth 授权对象
     */
    private AuthCallback oauth;

    /**
     * 租户Id 可为空
     */
    private Long tenantId;
}
