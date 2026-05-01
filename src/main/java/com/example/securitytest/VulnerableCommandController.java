package com.example.securitytest;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.regex.Pattern;

@RestController
public class VulnerableCommandController {

    private static final Pattern SAFE_HOST_PATTERN = Pattern.compile("^[a-zA-Z0-9._-]{1,253}$");

    @GetMapping("/vuln/ping")
    public String ping(@RequestParam("host") String host) throws Exception {
        if (!SAFE_HOST_PATTERN.matcher(host).matches()) {
            throw new IllegalArgumentException("Invalid host parameter");
        }
        // Pass command as a string array to prevent shell injection
        Process p = Runtime.getRuntime().exec(new String[]{"ping", "-c", "1", host});
        return "started: " + p.pid();
    }
}