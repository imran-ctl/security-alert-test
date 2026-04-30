package com.example.securitytest;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class VulnerableCommandController {

    // Allowlist pattern: valid hostname/IP characters only (alphanumeric, dots, hyphens)
    private static final java.util.regex.Pattern VALID_HOST =
            java.util.regex.Pattern.compile("^[a-zA-Z0-9.-]{1,253}$");

    @GetMapping("/vuln/ping")
    public String ping(@RequestParam("host") String host) throws Exception {
        if (!VALID_HOST.matcher(host).matches()) {
            return "Invalid host";
        }
        // Use array form to prevent shell injection; host is validated by allowlist
        Process p = Runtime.getRuntime().exec(new String[]{"ping", "-c", "1", host});
        return "started: " + p.pid();
    }
}
