package com.provenance.fairymountain.mapper;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import com.provenance.fairymountain.model.Yield;
import org.apache.ibatis.annotations.Mapper;

import javax.annotation.ManagedBean;

@Mapper
public interface YieldMapper extends BaseMapper<Yield> {
}
