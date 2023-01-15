package com.provenance.fairymountain.model;


import com.baomidou.mybatisplus.annotation.IdType;
import com.baomidou.mybatisplus.annotation.TableId;
import lombok.Data;
import lombok.EqualsAndHashCode;

import java.io.Serializable;

@Data
@EqualsAndHashCode(callSuper = false)
public class User implements Serializable {

    //为了序列化，随便写
    private static final long serialVersionUID =  -111l;
    @TableId(type = IdType.ID_WORKER)
    //使用雪花算法生成唯一id
    private Long userId;

    private String UserName;

    private String Password;

    private Integer RoleId;

    private Boolean locked;
}
