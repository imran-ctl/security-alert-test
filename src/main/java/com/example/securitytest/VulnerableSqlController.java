package com.example.securitytest;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;

@RestController
public class VulnerableSqlController {

    // Intentionally vulnerable endpoint for CodeQL testing
    @GetMapping("/vuln/users")
    public String users(@RequestParam("name") String name) throws Exception {
        Connection conn = DriverManager.getConnection("jdbc:h2:mem:testdb", "sa", "");
        Statement stmt = conn.createStatement();

        // SQL Injection: user-controlled input concatenated into SQL
        ResultSet rs = stmt.executeQuery("SELECT * FROM users WHERE name = '" + name + "'");

        return rs.toString();
    }
}
