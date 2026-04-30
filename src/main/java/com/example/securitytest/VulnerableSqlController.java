package com.example.securitytest;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;

@RestController
public class VulnerableSqlController {

    @GetMapping("/vuln/users")
    public String users(@RequestParam("name") String name) throws Exception {
        StringBuilder result = new StringBuilder();

        // Fix: use a parameterized PreparedStatement to prevent SQL injection
        // Resources are closed automatically via try-with-resources
        try (Connection conn = DriverManager.getConnection("jdbc:h2:mem:testdb", "sa", "");
             PreparedStatement stmt = conn.prepareStatement("SELECT * FROM users WHERE name = ?")) {
            stmt.setString(1, name);
            try (ResultSet rs = stmt.executeQuery()) {
                while (rs.next()) {
                    result.append(rs.getString(1)).append("\n");
                }
            }
        }

        return result.toString();
    }
}
