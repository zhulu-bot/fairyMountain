package com.provenance.fairymountain.controller;

import com.provenance.fairymountain.response.RespBean;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.validation.Errors;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import javax.validation.Valid;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;



@RestController
public class AdminController {
    @Autowired
    private PasswordEncoder passwordEncoder;


    @GetMapping("/hello")
    public Object hello() {
        return SecurityContextHolder.getContext().getAuthentication().getPrincipal();
    }


    @GetMapping("/world")
    public Object world() {
        return SecurityContextHolder.getContext().getAuthentication().getPrincipal();
    }

}
