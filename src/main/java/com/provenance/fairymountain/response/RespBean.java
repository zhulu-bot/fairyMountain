package com.provenance.fairymountain.response;

import lombok.Data;

/**
 * json 返回的对象
 */
@Data
public class RespBean {
    private Integer status;
    private String msg;
    private Object obj;

    public static RespBean build() {
        return new RespBean();
    }

    public static RespBean ok(String msg) {
        return new RespBean(200, msg, null);
    }

    public static RespBean ok(String msg, Object obj) {
        return new RespBean(200, msg, obj);
    }

    public static RespBean error(String msg) {
        return new RespBean(500, msg, null);
    }

    public static RespBean error(String msg, Object obj) {
        return new RespBean(500, msg, obj);
    }

    /**
     * 根据result code返回一个respBean
     *
     * @param resultCode
     * @return
     */
    public static RespBean error(ResultCode resultCode) {
        RespBean result = new RespBean();
        result.setStatus(resultCode.getCode());
        result.setMsg(resultCode.getMessage());
        return result;
    }

    /**
     * 构造器为什么是privata 先放着
     */
    private RespBean() {
    }

    private RespBean(Integer status, String msg, Object obj) {
        this.status = status;
        this.msg = msg;
        this.obj = obj;
    }


}
