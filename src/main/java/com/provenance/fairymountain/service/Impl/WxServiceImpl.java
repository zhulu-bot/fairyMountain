package com.provenance.fairymountain.service.Impl;

import cn.hutool.core.codec.Base64;
import cn.hutool.core.lang.UUID;
import cn.hutool.http.HttpUtil;
import cn.hutool.json.JSONObject;
import cn.hutool.json.JSONUtil;
import com.baomidou.mybatisplus.core.assist.ISqlRunner;
import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import com.provenance.fairymountain.mapper.UserMapper;
import com.provenance.fairymountain.mapper.WxUserInfoMapper;
import com.provenance.fairymountain.model.User;
import com.provenance.fairymountain.model.WXAuth;
import com.provenance.fairymountain.model.WxUserInfo;
import com.provenance.fairymountain.redisMapper.RedisUserMapper;
import com.provenance.fairymountain.response.RespBean;
import com.provenance.fairymountain.response.ResultCode;
import com.provenance.fairymountain.service.WxService;
import com.provenance.fairymountain.utils.TokenUtil;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.context.ApplicationContext;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Isolation;
import org.springframework.transaction.annotation.Transactional;

import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.Cipher;
import java.security.spec.AlgorithmParameterSpec;
import java.util.HashMap;
import java.util.Random;
import java.util.concurrent.TimeUnit;

@Service
@Slf4j
public class WxServiceImpl implements WxService {
    @Autowired
    private WxUserInfoMapper wxUserInfoMapper;
    @Value("${wxmini.secret}")
    private String secret;
    @Value("${wxmini.appid}")
    private String appid;
    @Autowired
    private WxService wxService;
    @Autowired
    private RedisTemplate redisTemplate;
    @Autowired
    private RedisUserMapper redisUserMapper;
    @Autowired
    private UserMapper userMapper;
    private ApplicationContext applicationContext = null;

    /**
     * 用于解决一个类两个事物方法，并且互相调用，无法开启事务的问题
     *
     * @param applicationContext
     * @throws BeansException
     */
    @Override
    public void setApplicationContext(ApplicationContext applicationContext) throws BeansException {

        this.applicationContext = applicationContext;
    }


    @Override
    public String wxDecrypt(String encryptedData, String sessionId, String vi) {
        // 开始解密
        String jsons = (String) redisTemplate.opsForValue().get(sessionId);
        if ("".equals(jsons) || null == jsons) {
            //说明超时了
            return "";
        }
        JSONObject jsonObject = JSONUtil.parseObj(jsons);
        String sessionKey = (String) jsonObject.get("session_key");
        log.info("\"wxSerciceImpl\",\"wxDecrypt\",\"解密时拿到的sessionKey\"+sessionKey");
        byte[] encData = cn.hutool.core.codec.Base64.decode(encryptedData);
        byte[] iv = cn.hutool.core.codec.Base64.decode(vi);
        byte[] key = Base64.decode(sessionKey);
        AlgorithmParameterSpec ivSpec = new IvParameterSpec(iv);
        String res = "";
        try {
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
            cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
            res = new String(cipher.doFinal(encData), "UTF-8");
            log.info("wxserviceImpl", "wxDecrypt", "解密到原始数据" + res);
        } catch (Exception e) {
        }
        return res;
    }

    @Override
    public String getStringRandom(int length) {

        StringBuilder val = new StringBuilder();
        Random random = new Random();
        //参数length，表示生成几位随机数
        for (int i = 0; i < length; i++) {
            String charOrNum = random.nextInt(2) % 2 == 0 ? "char" : "num";
            //输出字母还是数字
            if ("char".equalsIgnoreCase(charOrNum)) {
                //输出是大写字母还是小写字母
                int temp = random.nextInt(2) % 2 == 0 ? 65 : 97;
                val.append((char) (random.nextInt(26) + temp));
            } else {
                val.append(random.nextInt(10));
            }
        }
        return val.toString();
    }

    public String getSessionId(String code) {
        String url = "https://api.weixin.qq.com/sns/jscode2session?appid={0}&secret={1}&js_code={2}&grant_type=authorization_code";
        url = url.replace("{0}", appid).replace("{1}", secret).replace("{2}", code);
        String res = HttpUtil.get(url);
        System.out.println("直接在服务器拿到的sessionKEY" + res);
        String uuid = UUID.randomUUID().toString();
        //res放在redis，并且设置过期时间15分钟，15分钟内用户不点授权就超时了
        redisTemplate.opsForValue().set(uuid, res, 15L, TimeUnit.MINUTES);
        //uuid给前端，用户同意一键登录后返回回来
        return uuid;
    }

    /**
     * 微信小程序一键登录，如果之前没有登录过自动注册
     *
     * @param wxAuth
     * @return
     */
    @Override
    @Transactional(isolation = Isolation.READ_COMMITTED)
    public RespBean authLogin(WXAuth wxAuth) {
        //将加密信息解密成字符串，调用了另一个service
        String wxRes = wxService.wxDecrypt(wxAuth.getEncryptedData(), wxAuth.getSessionId(), wxAuth.getIv());
        //判断如果解密出来的消息为空说明登陆超时,解密不为空则登录成功
        if ("".equals(wxRes)) {
            return RespBean.error("登陆超时", ResultCode.USER_ACCOUNT_USE_BY_OTHERS);
        }
        //使用hutool工具将字符串转换为对象
        WxUserInfo wxUserInfo = JSONUtil.toBean(wxRes, WxUserInfo.class);

        // User user = userMapper.selectOne(Wrappers.<User>lambdaQuery().eq(User::getOpenId, wxUserInfo.getOpenId()));hutool工具的使用，暂时不会
        //根据openid查看数据库，看看用户是否为第一次登录
        //这个可能会有bug，我直接把openid传进去了，没有加解密

        //Openid要自己给进去
        String jsons = (String) redisTemplate.opsForValue().get(wxAuth.getSessionId());
        JSONObject jsonObject = JSONUtil.parseObj(jsons);
        String sessionKey = (String) jsonObject.get("session_key");
        String openId = (String) jsonObject.get("openid");
        wxUserInfo.setOpenId(openId);
        HashMap<String, Object> res = null;
        //查看数据库中是否有Openid对应的用户
        WxUserInfo wxUserIndataBase = wxService.getWxUserByOpenId(openId);
        User user = null;
        if (wxUserIndataBase == null) {
            //这里说明用户没有登陆过，就注册用户将用户写入数据库
            //写入两个表，一个wx_user 一个user
            WxService wxService = applicationContext.getBean(WxService.class);
            //通过容器获取service，为了织入aop
            wxService.saveWxUser(wxUserInfo);
            //更新userid
            user = wxService.saveWxUser(wxUserInfo);
        } else {
            //之前注册过,通过OpenId获取user，返回一个token，还要返回user的数据
            QueryWrapper<User> userQueryWrapper = new QueryWrapper<User>();
            userQueryWrapper.eq("uid", wxUserIndataBase.getUserId());
            user = userMapper.selectOne(userQueryWrapper);
        }
        res = new HashMap<String, Object>();
        //然后构造出token，优化，将构造JWT放到方法
        String jwt = TokenUtil.getJwtByUser(user);
        log.info("UserserviceImpl", "authlogin", jwt);
        //登录成功将user放入redis
        redisUserMapper.redisUpdataUser(user);
        res.put("token", jwt);
        res.put("user", user);

        if (res != null) {
            return RespBean.ok(ResultCode.SUCCESS.getMessage(), res);
        } else return RespBean.error(ResultCode.COMMON_FAIL);
    }
    /**
     * @param wxUserInfo
     * @return
     */
    @Override
    @Transactional(isolation = Isolation.READ_COMMITTED)
    //小项目，避免脏读就好，不用开事物传播，同一个类中的方法互相调用会出问题，原因是aop的实现基于动态代理
    public User saveWxUser(WxUserInfo wxUserInfo) {
        /**
         * 微信小程序用户第一次登录自动注册，写两个表user和wxUserInfo
         */
        User user = new User();
        userMapper.insert(user);
        //插入后会把数据回填给user对象
        wxUserInfo.setUserId(user.getUserId());
        wxUserInfoMapper.insert(wxUserInfo);
        return user;
    }

    public WxUserInfo getWxUserByOpenId(String OpenId) {
        QueryWrapper<WxUserInfo> WxqueryWrapper = new QueryWrapper<WxUserInfo>();
        WxqueryWrapper.eq("open_id", OpenId);
        WxUserInfo wxUserIndataBase = wxUserInfoMapper.selectOne(WxqueryWrapper);
        return wxUserIndataBase;
    }
}

