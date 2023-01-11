package com.provenance.fairymountain.model;

import lombok.Data;

/**
 * 解密出来的微信给的信息，用这个来构建user实现注册
 * 微信小程序用户独有的用户实体
 */
@Data
public class WxUserInfo {

    //微信平台下标识用户身份的唯一id
    private String openId;

    private String nickName;

    private Long userId;

    private String gender;

    private String city;

    private String province;

    private String country;

    private String avatarUrl;

    private String unionId;

}
