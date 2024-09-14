package com.simple.simpleauth.model;

import com.simple.simpleauth.model.enums.EnableStatusEnum;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.util.CollectionUtils;

import java.util.Collection;
import java.util.Collections;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * @Author:benxiong.hu
 * @CreateAt:2024/8/12
 * @ModifyAt:2024/8/12
 * @Version:1.0
 */
@Data
@Builder
@AllArgsConstructor
public class UserInfoDetail implements UserDetails {

    /**
     * 用户 ID
     */
    private Long userId;
    /**
     * 用户名
     */
    private String username;
    /**
     * 密码
     */
    private String password;
    /**
     * 是否启用
     */
    private Boolean enabled;
    /**
     * 权限
     */
    private Set<String> permissions;
    /**
     * 部门Id
     */
    private Long deptId;
    /**
     * 数据权限范围
     */
    private Integer dataScope;
    /**
     * 租户ID
     */
    private Long tenantId;

    /**
     * 角色
     */
    private Collection<SimpleGrantedAuthority> roles;

    /**
     * 初始化
     *
     * @param userAuthInfo
     */
    public UserInfoDetail(UserAuthInfo userAuthInfo) {
        this.userId = userAuthInfo.getUserId();
        this.username = userAuthInfo.getUsername();

        Set<String> roles = userAuthInfo.getRoles();
        if (!CollectionUtils.isEmpty(roles)) {
            // 处理角色信息
            this.roles = roles.stream()
                    // 在Spring Security中，所有角色前缀需要为 ROLE_
                    .map(role -> new SimpleGrantedAuthority("ROLE_" + role))
                    .collect(Collectors.toSet());
        } else {
            // 如果没有角色信息，赋值为空集合
            this.roles = Collections.emptySet();
        }
        this.password = userAuthInfo.getPassword();

        // 根据用户状态设置是否可用
        this.enabled = userAuthInfo.getStatus().equals(EnableStatusEnum.ENABLE.getValue());
        this.permissions = userAuthInfo.getPermissions();
        this.deptId = userAuthInfo.getDeptId();
        this.dataScope = userAuthInfo.getDataScope();
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return this.roles;
    }
}
