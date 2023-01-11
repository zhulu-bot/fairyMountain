package com.provenance.fairymountain.service;

import com.provenance.fairymountain.model.User;
import com.provenance.fairymountain.model.WXAuth;
import com.provenance.fairymountain.model.WxUserInfo;
import com.provenance.fairymountain.response.RespBean;
import org.springframework.beans.BeansException;
import org.springframework.context.ApplicationContext;
import org.springframework.stereotype.Service;

import javax.servlet.http.HttpSession;

/**
 * 用于微信登录相关操作的服务层
 */
public interface WxService {
    /**
     * 用户一键登录时调用，获取所有的用户信息并写入数据库
     *
     * @param encryptedData
     * @param sessionId
     * @param vi
     * @return
     */
    public String wxDecrypt(String encryptedData, String sessionId, String vi);

    public String getStringRandom(int length);

    /**
     * 当微信小程序调用wx.login时调用此方法，通过code向微信服务器换取信息并保存
     *
     * @param code
     * @return
     */
    public String getSessionId(String code);

    /**
     * 微信小程序一键授权
     *
     * @param wxAuth
     * @return
     */
    public RespBean authLogin(WXAuth wxAuth);
    public void setApplicationContext(ApplicationContext applicationContext) throws BeansException;
    public User saveWxUser(WxUserInfo wxUserInfo);
    public WxUserInfo getWxUserByOpenId(String OpenId);

}
