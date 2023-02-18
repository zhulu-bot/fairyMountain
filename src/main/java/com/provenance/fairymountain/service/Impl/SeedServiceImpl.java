package com.provenance.fairymountain.service.Impl;

import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import com.provenance.fairymountain.mapper.SeedMapper;
import com.provenance.fairymountain.model.Seed;
import com.provenance.fairymountain.service.SeedService;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class SeedServiceImpl implements SeedService {
    @Autowired
    SeedMapper seedMapper;

    @Override
    public Seed getSeed(String category, String quality) {
        QueryWrapper<Seed> select = new QueryWrapper<Seed>();
        select.eq("category",category);
        select.eq("quality",quality);
        return seedMapper.selectOne(select);
    }

    @Override
    public Seed updateSeed(Seed seed) {
        Seed userSeed = getSeed(seed.getCategory(), seed.getQuality());
        if(userSeed == null){
            seedMapper.insert(seed);
        }else {
            seed.setCount(userSeed.getCount()+seed.getCount());
            QueryWrapper<Seed> update = new QueryWrapper<Seed>();
            update.eq("seed_id", userSeed.getSeedId());
            seedMapper.update(seed,update);
        }
        return seed;
    }

    public List<Seed> getSeeds(Long userid) {
        QueryWrapper<Seed> select = new QueryWrapper<Seed>();
        select.eq("user_id",userid);
        return seedMapper.selectList(select);
    }

    public Integer delSeeds(Integer seedid) {
        QueryWrapper<Seed> select = new QueryWrapper<Seed>();
        select.eq("seed_id",seedid);
        return seedMapper.delete(select);
    }
}
