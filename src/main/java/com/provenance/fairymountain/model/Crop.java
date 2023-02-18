package com.provenance.fairymountain.model;

import com.baomidou.mybatisplus.annotation.IdType;
import com.baomidou.mybatisplus.annotation.TableId;
import lombok.Data;

import java.sql.Timestamp;
@Data
public class Crop {

    @TableId(type = IdType.AUTO)
    Integer cropId;

    Long userId;

    String Category;

    String quality;

    String position;

    Integer yield;

    Timestamp plantTime;

    String state;

}
