package com.centurylink.github;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.net.InetAddress;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.Set;

@RestController
public class MyController {

    private static final Set<String> ALLOWED_HOSTS = Set.of(
            "api.centurylink.com",
            "service.centurylink.com"
    );

    private static final Set<String> BLOCKED_IP_PREFIXES = Set.of(
            "127.", "10.", "169.254.", "192.168."
    );

    private static final Set<String> BLOCKED_IPV6_PREFIXES = Set.of(
            "::1",           // loopback
            "0:0:0:0:0:0:0:1" // loopback expanded
    );

    @GetMapping("/fetch")
    public ResponseEntity<String> fetchUrl(@RequestParam String url) {
        URI safeUri;
        try {
            safeUri = validateAndBuildSafeUri(url);
        } catch (SecurityException e) {
            return ResponseEntity.badRequest().body("Request blocked");
        }

        try {
            HttpClient client = HttpClient.newHttpClient();
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(safeUri)
                    .GET()
                    .build();
            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
            return ResponseEntity.ok(response.body());
        } catch (Exception e) {
            return ResponseEntity.internalServerError().body("Error fetching URL");
        }
    }

    /**
     * Validates the user-supplied URL and returns a safe URI constructed entirely
     * from allowlisted, trusted components to prevent SSRF.
     */
    URI validateAndBuildSafeUri(String url) {
        if (url == null || url.isBlank()) {
            throw new SecurityException("URL must not be empty");
        }

        URI uri;
        try {
            uri = new URI(url);
        } catch (URISyntaxException e) {
            throw new SecurityException("Invalid URL format");
        }

        if (!"https".equals(uri.getScheme())) {
            throw new SecurityException("Only HTTPS scheme is allowed");
        }

        String host = uri.getHost();
        if (host == null || host.isBlank()) {
            throw new SecurityException("URL must contain a valid host");
        }

        // Validate host against the allowlist; use the allowlisted value, not user input
        String allowedHost = ALLOWED_HOSTS.stream()
                .filter(h -> h.equals(host.toLowerCase()))
                .findFirst()
                .orElseThrow(() -> new SecurityException("Host is not in the allowlist"));

        // Verify the resolved IP is not an internal address to guard against DNS rebinding
        try {
            InetAddress address = InetAddress.getByName(allowedHost);
            String resolvedIp = address.getHostAddress();
            if (isBlockedIpAddress(resolvedIp)) {
                throw new SecurityException("Resolved IP address is not allowed");
            }
        } catch (java.net.UnknownHostException e) {
            throw new SecurityException("Unable to resolve host");
        }

        // Reconstruct URI from trusted, allowlisted components to break the taint chain
        try {
            return new URI("https", allowedHost, uri.getPath(), uri.getQuery(), null);
        } catch (URISyntaxException e) {
            throw new SecurityException("Invalid URL path or query");
        }
    }

    boolean isBlockedIpAddress(String ip) {
        if (ip == null) {
            return true;
        }
        // Block IPv4 private/reserved ranges
        for (String prefix : BLOCKED_IP_PREFIXES) {
            if (ip.startsWith(prefix)) {
                return true;
            }
        }
        // Block 172.16.0.0/12 range (172.16.x.x - 172.31.x.x)
        if (ip.startsWith("172.")) {
            String[] parts = ip.split("\\.");
            if (parts.length == 4) {
                try {
                    int second = Integer.parseInt(parts[1]);
                    if (second >= 16 && second <= 31) {
                        return true;
                    }
                } catch (NumberFormatException ignored) {
                    // Treat unparseable 172.x octets as blocked for safety
                    return true;
                }
            }
        }
        // Block IPv6 loopback (::1)
        if (BLOCKED_IPV6_PREFIXES.contains(ip.toLowerCase())) {
            return true;
        }
        // Block IPv6 link-local (fe80::/10) and unique-local (fc00::/7)
        String lowerIp = ip.toLowerCase();
        if (lowerIp.startsWith("fe80") || lowerIp.startsWith("fc") || lowerIp.startsWith("fd")) {
            return true;
        }
        return false;
    }
}
