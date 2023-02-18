package com.provenance.fairymountain;


import com.provenance.fairymountain.mapper.SeedMapper;
import com.provenance.fairymountain.model.Seed;
import com.provenance.fairymountain.model.Yield;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.List;

@SpringBootTest
class FairyMountainApplicationTests {


    @Autowired
    SeedMapper seedMapper;
    @Test
    void contextLoads() {
        System.out.println("a");
    }




}
