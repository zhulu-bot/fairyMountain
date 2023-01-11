package com.provenance.fairymountain.model;

import com.baomidou.mybatisplus.annotation.IdType;
import com.baomidou.mybatisplus.annotation.TableId;
import lombok.Data;

@Data
public class User {

    @TableId(type = IdType.ID_WORKER)
    //使用雪花算法生成唯一id
    private Long uid;

    private String UserName;

    private String Password;

    private Integer RoleId;

    private Boolean locked;
}
