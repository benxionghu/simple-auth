package com.simple.simpleauth.config.propertoes;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.time.Duration;

/**
 * @Author:benxiong.hu
 * @CreateAt:2024/8/12
 * @ModifyAt:2024/8/12
 * @Version:1.0
 */
@Data
@Component
@ConfigurationProperties(prefix = "jwt")
public class JwtConfiguration {

    /**
     * 生成 token 的前缀
     */
    private String tokenPrefix = "Bearer ";

    /**
     * 请求头存储 token 的 key
     */
    private String requestHeaderKey;
    /**
     * JWT 密匙
     */
    private String secretKey;
    /**
     * 默认 Token 过期时间（小时为单位）
     */
    private Duration accessTokenExpirationTime = Duration.ofDays(8);
    /**
     * 刷新 Token 过期时间（小时为单位）
     */
    private Duration refreshTokenExpirationTime = Duration.ofDays(3);

    /**
     * 签发者
     */
    private String issuer;

}
