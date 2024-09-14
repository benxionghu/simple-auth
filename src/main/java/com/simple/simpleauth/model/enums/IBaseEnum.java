package com.simple.simpleauth.model.enums;

import java.util.EnumSet;
import java.util.Objects;

/**
 * @Author:benxiong.hu
 * @CreateAt:2024/8/12
 * @ModifyAt:2024/8/12
 * @Version:1.0
 */
public interface IBaseEnum<T> {

    T getValue();

    String getLabel();

    /**
     * 根据值获取枚举
     *
     * @param value 枚举值
     * @param clazz 类名
     * @param <E>   <E extends Enum<E> & IBaseEnum> E
     * @return 枚举值
     */
    static <E extends Enum<E> & IBaseEnum> E getEnumByValue(Object value, Class<E> clazz) {
        Objects.requireNonNull(value);
        // 获取类型下的所有枚举
        EnumSet<E> allEnums = EnumSet.allOf(clazz);
        return allEnums.stream()
                .filter(e -> e.getValue().equals(value))
                .findFirst()
                .orElse(null);
    }

    /**
     * 根据文本标签获取值
     *
     * @param value 枚举内容
     * @param clazz 类名
     * @param <E>   <E extends Enum<E> & IBaseEnum>
     * @return 枚举内容
     */
    static <E extends Enum<E> & IBaseEnum> String getLabelByValue(Object value, Class<E> clazz) {
        Objects.requireNonNull(value);
        // 获取类型下的所有枚举
        EnumSet<E> allEnums = EnumSet.allOf(clazz);
        E matchEnum = allEnums.stream()
                .filter(e -> e.getValue().equals(value))
                .findFirst()
                .orElse(null);

        String label = null;
        if (matchEnum != null) {
            label = matchEnum.getLabel();
        }
        return label;
    }


    /**
     * 根据文本标签获取值
     *
     * @param label 枚举内容
     * @param clazz 类名
     * @param <E>   <E extends Enum<E> & IBaseEnum>
     * @return 枚举值
     */
    static <E extends Enum<E> & IBaseEnum> Object getValueByLabel(String label, Class<E> clazz) {
        Objects.requireNonNull(label);
        // 获取类型下的所有枚举
        EnumSet<E> allEnums = EnumSet.allOf(clazz);
        E matchEnum = allEnums.stream()
                .filter(e -> e.getValue().equals(label))
                .findFirst()
                .orElse(null);

        Object value = null;
        if (matchEnum != null) {
            value = matchEnum.getValue();
        }
        return value;
    }
}
