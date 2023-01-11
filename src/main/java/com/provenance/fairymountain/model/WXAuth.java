package com.provenance.fairymountain.model;

import lombok.Data;

/**
 * 用于接收前端的参数，加密信息，和初始向量
 * 微信登录的认证实体
 */
@Data
public class WXAuth {
    private String encryptedData;
    private String iv;
    private String sessionId;
}