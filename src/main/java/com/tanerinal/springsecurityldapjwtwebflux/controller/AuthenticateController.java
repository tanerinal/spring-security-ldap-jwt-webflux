package com.tanerinal.springsecurityldapjwtwebflux.controller;

import com.tanerinal.springsecurityldapjwtwebflux.model.dto.AuthRequest;
import com.tanerinal.springsecurityldapjwtwebflux.model.dto.AuthResponse;
import com.tanerinal.springsecurityldapjwtwebflux.service.PortalUserService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.lang.NonNull;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/authenticate")
@RequiredArgsConstructor
@Slf4j
public class AuthenticateController {
    private final PortalUserService portalUserService;

    @PostMapping
    public AuthResponse authenticate(@RequestBody @NonNull AuthRequest authRequest) {
        log.info("Authentication request for user {} received!", authRequest.getUsername());
        return portalUserService.authenticateUser(authRequest.getUsername(), authRequest.getPassword());
    }
}
