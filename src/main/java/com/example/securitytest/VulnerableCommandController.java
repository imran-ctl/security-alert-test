package com.example.securitytest;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class VulnerableCommandController {

    @GetMapping("/vuln/ping")
    public String ping(@RequestParam("host") String host) throws Exception {
        // Command injection: user-controlled input reaches OS command execution
        Process p = Runtime.getRuntime().exec("ping -c 1 " + host);
        return "started: " + p.pid();
    }
}