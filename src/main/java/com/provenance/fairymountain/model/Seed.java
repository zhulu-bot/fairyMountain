package com.provenance.fairymountain.model;

import com.baomidou.mybatisplus.annotation.IdType;
import com.baomidou.mybatisplus.annotation.TableId;
import lombok.Data;

@Data
public class Seed {

    @TableId(type = IdType.AUTO)
    Integer seedId;

    Long userId;

    String category;

    String quality;

    Integer count;

}
