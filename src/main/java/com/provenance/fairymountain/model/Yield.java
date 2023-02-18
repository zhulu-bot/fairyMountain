package com.provenance.fairymountain.model;

import com.baomidou.mybatisplus.annotation.IdType;
import com.baomidou.mybatisplus.annotation.TableId;
import lombok.Data;

// 记录产量与种子的关系
@Data
public class Yield {
    @TableId(type = IdType.AUTO)
    Integer yieldId;

    String Category;

    String quality;

    Integer yield;
}
