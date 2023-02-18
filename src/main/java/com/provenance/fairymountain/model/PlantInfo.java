package com.provenance.fairymountain.model;

import lombok.Data;

//当种下植物前端需要传来的数据
@Data
public class PlantInfo {
    //种植的植物的ID
    Integer seedId;
    //种植的位置
    String position;
}
