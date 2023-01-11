package com.provenance.fairymountain.mapper;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import com.provenance.fairymountain.model.User;
import com.provenance.fairymountain.model.WxUserInfo;
import org.apache.ibatis.annotations.Mapper;

import javax.annotation.ManagedBean;

@Mapper
public interface UserMapper extends BaseMapper<User> {
}
