package com.provenance.fairymountain.service;

import com.provenance.fairymountain.model.Crop;

import java.util.HashMap;
import java.util.List;

public interface PlantService {
    public Crop getCropInfo(Integer seedId);
    public Integer plantCrop(Crop crop);
    public List<Crop> getAllCrops(Long userId);
}
