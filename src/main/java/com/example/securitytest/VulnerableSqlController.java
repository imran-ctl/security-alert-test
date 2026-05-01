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
        Connection conn = DriverManager.getConnection("jdbc:h2:mem:testdb", "sa", "");

        // Use PreparedStatement to prevent SQL injection
        PreparedStatement stmt = conn.prepareStatement("SELECT * FROM users WHERE name = ?");
        stmt.setString(1, name);
        ResultSet rs = stmt.executeQuery();

        return rs.toString();
    }
}