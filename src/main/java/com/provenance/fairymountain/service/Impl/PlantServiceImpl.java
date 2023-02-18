package com.provenance.fairymountain.service.Impl;


import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import com.provenance.fairymountain.mapper.CropMapper;
import com.provenance.fairymountain.mapper.SeedMapper;
import com.provenance.fairymountain.mapper.YieldMapper;
import com.provenance.fairymountain.model.Crop;
import com.provenance.fairymountain.model.Seed;
import com.provenance.fairymountain.model.Yield;
import com.provenance.fairymountain.service.PlantService;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.List;


public class PlantServiceImpl implements PlantService {

    @Autowired
    SeedMapper seedMapper;
    @Autowired
    YieldMapper yieldMapper;
    @Autowired
    CropMapper cropMapper;


    @Override
    public Crop getCropInfo(Integer seedId) {
        //根据seedId 获取种子
        Seed seed = seedMapper.selectById(seedId);
        //根据种子的种类与品质 查看产量
        QueryWrapper<Yield>  yieldQueryWrapper= new QueryWrapper<Yield>();
        yieldQueryWrapper.eq("quality",seed.getQuality());
        yieldQueryWrapper.eq("categroy",seed.getCategory());
        Yield yield = yieldMapper.selectOne(yieldQueryWrapper);
        Crop crop= new Crop();
        crop.setCategory(seed.getCategory());
        crop.setQuality(seed.getQuality());
        crop.setYield(yield.getYield());
        return crop;
    }

    @Override
    public Integer plantCrop(Crop crop) {
        return cropMapper.insert(crop);
    }

    @Override
    public List<Crop> getAllCrops(Long userId) {
        QueryWrapper<Crop> queryWrap = new QueryWrapper<Crop>();
        queryWrap.eq("user_id",userId);
        return cropMapper.selectList(queryWrap);
    }


}
