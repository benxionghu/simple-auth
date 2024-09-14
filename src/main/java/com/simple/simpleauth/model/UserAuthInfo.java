package com.simple.simpleauth.model;

import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.experimental.Accessors;

import java.util.Set;

/**
 * @Author:benxiong.hu
 * @CreateAt:2024/8/12
 * @ModifyAt:2024/8/12
 * @Version:1.0
 */
@Data
@Accessors(chain = true)
@NoArgsConstructor
public class UserAuthInfo {

    /**
     * 用户ID
     */
    private Long userId;
    /**
     * 用户名
     */
    private String username;
    /**
     * 部门ID
     */
    private Long deptId;

    /**
     * 数据范围
     */
    private Integer dataScope;

    /**
     * 密码
     */
    private String password;

    /**
     * 状态
     */
    private Integer status;

    /**
     * 角色集合
     */
    private Set<String> roles;

    /**
     * 权限集合
     */
    private Set<String> permissions;
}
