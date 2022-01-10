package com.tanerinal.springsecurityldapjwtwebflux.controller;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/finance-zone")
public class FinanceController {
    @GetMapping
    public ResponseEntity<String> get() {
        return ResponseEntity.ok("If your see this, you have FINANCE role!");
    }
}
