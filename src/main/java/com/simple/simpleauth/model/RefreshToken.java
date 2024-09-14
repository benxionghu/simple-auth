package com.simple.simpleauth.model;

import lombok.Data;
import lombok.ToString;

/**
 * @Author:benxiong.hu
 * @CreateAt:2024/9/3
 * @ModifyAt:2024/9/3
 * @Version:1.0
 */
@Data
@ToString
public class RefreshToken {

    /**
     * 访问Token
     */
    private String accessToken;

    /**
     * 刷新Token
     */
    private String refreshToken;
}
