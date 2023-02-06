package com.provenance.fairymountain.service;

import com.provenance.fairymountain.model.Seed;

import java.util.List;

public interface SeedService {
    public Seed getSeed(String category, String quality);
    public Seed updateSeed(Seed seed);
    public List<Seed> getSeeds(Long userid);
}
