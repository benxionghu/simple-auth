package com.simple.simpleauth.utils;

import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.BoundSetOperations;
import org.springframework.data.redis.core.HashOperations;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.ValueOperations;
import org.springframework.data.redis.core.script.RedisScript;
import org.springframework.stereotype.Component;

import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.TimeUnit;

/**
 * Redis 帮助类
 *
 * @Author:benxiong.hu
 * @CreateAt:2024/8/12
 * @ModifyAt:2024/8/12
 * @Version:1.0
 */
@SuppressWarnings(value = {"unchecked", "rawtypes"})
@Component
@RequiredArgsConstructor
public class RedisUtil {

    private final RedisTemplate redisTemplate;


    /**
     * 缓存基本的对象，Integer、String、实体类等
     *
     * @param key   缓存的键值
     * @param value 缓存的值
     */
    public <T> void setCacheObject(final String key, final T value) {
        redisTemplate.opsForValue().set(key, value);
    }

    /**
     * 缓存基本的对象，Integer、String、实体类等
     *
     * @param key      缓存的键值
     * @param value    缓存的值
     * @param timeout  时间
     * @param timeUnit 时间颗粒度
     */
    public <T> void setCacheObject(final String key, final T value, final Integer timeout, final TimeUnit timeUnit) {
        redisTemplate.opsForValue().set(key, value, timeout, timeUnit);
    }

    /**
     * 缓存基本的对象，Integer、String、实体类等
     *
     * @param key      缓存的键值
     * @param value    缓存的值
     * @param timeout  时间
     * @param timeUnit 时间颗粒度
     */
    public <T> void setCacheObject(final String key, final T value, long timeout, final TimeUnit timeUnit) {
        redisTemplate.opsForValue().set(key, value, timeout, timeUnit);
    }

    /**
     * 设置有效时间
     *
     * @param key     Redis键
     * @param timeout 超时时间
     * @return true=设置成功；false=设置失败
     */
    public boolean expire(final String key, final long timeout) {
        return expire(key, timeout, TimeUnit.SECONDS);
    }

    /**
     * 设置有效时间
     *
     * @param key     Redis键
     * @param timeout 超时时间
     * @param unit    时间单位
     * @return true=设置成功；false=设置失败
     */
    public boolean expire(final String key, final long timeout, final TimeUnit unit) {
        return Boolean.TRUE.equals(redisTemplate.expire(key, timeout, unit));
    }

    /**
     * 获得缓存的基本对象。
     *
     * @param key 缓存键值
     * @return 缓存键值对应的数据
     */
    public <T> T getCacheObject(final String key) {
        ValueOperations<String, T> operation = redisTemplate.opsForValue();
        return operation.get(key);
    }

    /**
     * 删除单个对象
     */
    public boolean deleteObject(final String key) {
        return Boolean.TRUE.equals(redisTemplate.delete(key));
    }

    /**
     * 删除多个对象
     */
    public boolean deleteObject(final Collection<String> keys) {
        Long deletedCount = redisTemplate.delete(keys);
        return deletedCount != null && deletedCount > 0;
    }

    /**
     * 缓存List数据
     *
     * @param key      缓存的键值
     * @param dataList 待缓存的List数据
     * @return 缓存的对象
     */
    public <T> long pushToList(final String key, final List<T> dataList) {
        Long count = redisTemplate.opsForList().rightPushAll(key, dataList);
        return count == null ? 0 : count;
    }

    /**
     * 向缓存的List数据中推送单个元素
     *
     * @param key    缓存的键值
     * @param entity 待推送到List的元素
     * @return 推送后列表的长度
     */
    public <T> long pushToList(final String key, final T entity) {
        Long count = redisTemplate.opsForList().rightPush(key, entity);
        return count == null ? 0 : count;
    }

    /**
     * 获得缓存的list对象
     *
     * @param key 缓存的键值
     * @return 缓存键值对应的数据
     */
    public <T> List<T> getCacheList(final String key) {
        return redisTemplate.opsForList().range(key, 0, -1);
    }

    /**
     * 缓存Set
     *
     * @param key     缓存键值
     * @param dataSet 缓存的数据
     * @return 缓存数据的对象
     */
    public <T> BoundSetOperations<String, T> addToCacheSet(final String key, final Set<T> dataSet) {
        BoundSetOperations<String, T> setOperation = redisTemplate.boundSetOps(key);
        for (T t : dataSet) {
            setOperation.add(t);
        }
        return setOperation;
    }

    /**
     * 缓存Set
     *
     * @param key  缓存键值
     * @param data 要添加到缓存的数据
     * @return 缓存数据的对象
     */
    public <T> BoundSetOperations<String, T> addToCacheSet(final String key, T data) {
        BoundSetOperations<String, T> setOperation = redisTemplate.boundSetOps(key);
        setOperation.add(data);
        return setOperation;
    }

    /**
     * 获得缓存的set
     */
    public <T> Set<T> getCacheSet(final String key) {
        return redisTemplate.opsForSet().members(key);
    }

    /**
     * 缓存Map
     */
    public <T> void putMapToCache(final String key, final Map<String, T> dataMap) {
        if (dataMap != null) {
            redisTemplate.opsForHash().putAll(key, dataMap);
        }
    }

    /**
     * 获得缓存的Map
     */
    public <T> Map<String, T> getCacheMap(final String key) {
        return redisTemplate.opsForHash().entries(key);
    }

    /**
     * 往Hash中存入数据
     *
     * @param key   Redis键
     * @param hKey  Hash键
     * @param value 值
     */
    public <T> void putHashValueToCache(final String key, final String hKey, final T value) {
        redisTemplate.opsForHash().put(key, hKey, value);
    }

    /**
     * 获取Hash中的数据
     *
     * @param key  Redis键
     * @param hKey Hash键
     * @return Hash中的对象
     */
    public <T> T getCacheMapValue(final String key, final String hKey) {
        HashOperations<String, String, T> opsForHash = redisTemplate.opsForHash();
        return opsForHash.get(key, hKey);
    }

    /**
     * 删除Hash中的数据
     */
    public void delCacheMapValue(final String key, final String hkey) {
        HashOperations hashOperations = redisTemplate.opsForHash();
        hashOperations.delete(key, hkey);
    }

    /**
     * 获取多个Hash中的数据
     *
     * @param key   Redis键
     * @param hKeys Hash键集合
     * @return Hash对象集合
     */
    public <T> List<T> getMultiCacheMapValue(final String key, final Collection<String> hKeys) {
        return redisTemplate.opsForHash().multiGet(key, hKeys);
    }

    /**
     * 获得缓存的基本对象列表
     *
     * @param pattern 字符串前缀
     * @return 对象列表
     */
    public Collection<String> keys(final String pattern) {
        return redisTemplate.keys(pattern);
    }

    /**
     * 是否含有 key
     *
     * @param key 键
     * @return 是否含有
     */
    public boolean hasKey(String key) {
        return Boolean.TRUE.equals(redisTemplate.hasKey(key));
    }

    /**
     * 缓存有序集合（ZSet）类型的数据到Redis
     *
     * @param key   缓存的键值
     * @param value 缓存的值
     * @param score 有序集合中的分数
     */
    public <T> void addCacheZSetValue(final String key, final T value, double score) {
        // 将值和分数存储到有序集合中
        redisTemplate.opsForZSet().add(key, value, score);
    }

    /**
     * 缓存有序集合（ZSet）类型的数据到Redis，并设置过期时间
     *
     * @param key      缓存的键值
     * @param value    缓存的值
     * @param score    有序集合中的分数
     * @param timeout  过期时间
     * @param timeUnit 时间单位
     */
    public <T> void addCacheZSetValue(final String key, final T value, double score, final Integer timeout, final TimeUnit timeUnit) {
        // 将值和分数存储到有序集合中，并设置过期时间
        redisTemplate.opsForZSet().add(key, value, score);
        redisTemplate.expire(key, timeout, timeUnit);
    }

    /**
     * 从Redis中获取有序集合（ZSet）类型的数据
     *
     * @param key   缓存的键值
     * @param start 起始索引
     * @param end   结束索引
     * @return 有序集合中指定范围的值的列表
     */
    public <T> Set<T> getCacheZSet(final String key, long start, long end) {
        // 获取有序集合中指定范围的值
        return redisTemplate.opsForZSet().range(key, start, end);
    }

    /**
     * 从Redis中获取有序集合（ZSet）类型的数据，并按分数降序排序
     *
     * @param key   缓存的键值
     * @param start 起始索引 (注: 不是分数)
     * @param end   结束索引 (注: 不是分数)
     * @return 有序集合中指定范围的值的列表
     */
    public <T> Set<T> getCacheZSetWithScoresDesc(final String key, long start, long end) {
        // 获取有序集合中指定范围的值，并按分数降序排序
        return redisTemplate.opsForZSet().reverseRangeWithScores(key, start, end);
    }

    /**
     * 从Redis中获取有序集合（ZSet）类型的数据，并按分数降序排序
     *
     * @param key   缓存的键值
     * @param start 起始索引 (注: 不是分数)
     * @param end   结束索引 (注: 不是分数)
     * @return 有序集合中指定范围的值的列表
     */
    public <T> Set<T> getCacheZSetWithScores(final String key, long start, long end) {
        // 获取有序集合中指定范围的值，并按分数降序排序
        return redisTemplate.opsForZSet().rangeWithScores(key, start, end);
    }

    /**
     * 从Redis中获取有序集合（ZSet）类型的数据，并按分数降序排序
     *
     * @param key        缓存的键值
     * @param startScore 起始分数
     * @param endScore   结束分数
     * @param offset     结果集偏移量
     * @param count      结果集大小
     * @return 有序集合中指定范围的值的列表
     */
    public <T> Set<T> getCacheZSetByScoreDesc(final String key, double startScore, double endScore, long offset, long count) {
        // 获取有序集合中指定范围的值，并按分数降序排序
        return redisTemplate.opsForZSet().reverseRangeByScore(key, startScore, endScore, offset, count);
    }

    /**
     * 从Redis中获取有序集合（ZSet）类型的数据，根据分数范围获取，不进行排序
     *
     * @param key      缓存的键值
     * @param minScore 最小分数
     * @param maxScore 最大分数
     * @param offset   结果集偏移量
     * @param count    结果集大小
     * @return 有序集合中指定范围的值的列表
     */
    public <T> Set<T> getCacheZSetByScore(final String key, double minScore, double maxScore, long offset, long count) {
        // 根据分数范围获取有序集合中的值，不进行排序
        return redisTemplate.opsForZSet().rangeByScore(key, minScore, maxScore, offset, count);
    }

    /**
     * 从Redis中删除有序集合（ZSet）中指定分数范围的元素
     *
     * @param key        缓存的键值
     * @param startScore 起始分数
     * @param endScore   结束分数
     * @return 删除的元素数量
     */
    public Long removeZSetRangeByScore(final String key, double startScore, double endScore) {
        return redisTemplate.opsForZSet().removeRangeByScore(key, startScore, endScore);
    }

    /**
     * 从Redis中删除有序集合（ZSet）中指定的成员
     *
     * @param key    缓存的键值
     * @param member 要删除的成员
     * @return 是否删除成功
     */
    public Long removeZSetMember(final String key, Object member) {
        return redisTemplate.opsForZSet().remove(key, member);
    }

    /**
     * 执行 Lua 脚本
     *
     * @param script Lua 脚本
     * @param keys   Redis 键列表
     * @param args   Lua 脚本参数
     * @param <T>    返回类型
     * @return 脚本执行结果
     */
    public <T> T executeLuaScript(final RedisScript<T> script, final List<String> keys, final List<?> args) {
        return (T) redisTemplate.execute(script, keys, args.toArray());
    }
}
