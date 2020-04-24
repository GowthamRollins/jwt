package com.security.jwt.controller;

import com.security.jwt.models.AuthRequest;
import com.security.jwt.repo.UserRepo;
import com.security.jwt.utils.JwtUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class AuthController {

    @Autowired
    private UserRepo userRepo;

    @PostMapping("/authenticate")
    public ResponseEntity authenticate(@RequestBody AuthRequest authRequest) throws Exception {
        if (userRepo.findByUserNameAndPassword(authRequest.getUsername(), authRequest.getPassword()) != null) {
            return ResponseEntity.ok(JwtUtil.generateToken(authRequest));
        } else {
            throw new Exception("Bad Credentials");
        }
    }


}
