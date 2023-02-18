package com.provenance.fairymountain.controller;

import com.provenance.fairymountain.model.Crop;
import com.provenance.fairymountain.model.PlantInfo;
import com.provenance.fairymountain.model.Seed;
import com.provenance.fairymountain.response.RespBean;
import com.provenance.fairymountain.service.PlantService;
import com.provenance.fairymountain.service.SeedService;
import com.provenance.fairymountain.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.AfterDomainEventPublication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;

import java.util.List;

//关于种植植物的接口
public class CropController {

    @Autowired
    SeedService seedService;
    @Autowired
    PlantService plantService;
    @Autowired
    UserService userService;


    /**
     * 种植植物的方法，前端需要传位置与种子Id参数
     * 后端先查询数据库获取种子的详细信息，然后更新种子数据，更新作物数据
     * TODO 加事物
     * @param plantInfo
     * @return
     */
    @PostMapping("/plant")
    public RespBean updateSeeds(@RequestBody PlantInfo plantInfo) {
        //根据seedId 查找Crop
        Crop crop = plantService.getCropInfo(plantInfo.getSeedId());
        crop.setPosition(plantInfo.getPosition());
        //更新userId
        crop.setUserId(userService.getUserId());
        //种植Crop
        plantService.plantCrop(crop);
        seedService.delSeeds(plantInfo.getSeedId());
        return RespBean.ok("成功获取sessionid");
    }

    /**
     *
     * 获取用户所有的农作物
     * @param plantInfo
     * @return
     */
    @GetMapping("/getAllPlants")
    public RespBean getAllPlants() {
        //根据seedId 查找Crop
       Long userId = userService.getUserId();
       List<Crop> cropList = plantService.getAllCrops(userId);
        return RespBean.ok("成功获取sessionid",cropList);
    }
}
