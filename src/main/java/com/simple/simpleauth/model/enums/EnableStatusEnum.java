package com.simple.simpleauth.model.enums;

import com.fasterxml.jackson.annotation.JsonValue;
import lombok.Getter;

/**
 * @Author:benxiong.hu
 * @CreateAt:2024/8/12
 * @ModifyAt:2024/8/12
 * @Version:1.0
 */
@Getter
public enum EnableStatusEnum {

    DIS_ENABLE(0, "禁用"),
    ENABLE(1, "正常");

//    @EnumValue //  Mybatis-Plus 提供注解表示插入数据库时插入该值
    @JsonValue //  表示对枚举序列化时返回此字段
    private final Integer value;

    private final String label;

    EnableStatusEnum(Integer value, String label) {
        this.value = value;
        this.label = label;
    }
}
