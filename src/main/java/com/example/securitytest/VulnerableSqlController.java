package com.example.securitytest;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.ResultSetMetaData;
import java.util.ArrayList;
import java.util.List;

@RestController
public class VulnerableSqlController {

    @GetMapping("/vuln/users")
    public String users(@RequestParam("name") String name) throws Exception {
        try (Connection conn = DriverManager.getConnection("jdbc:h2:mem:testdb", "sa", "");
             // Use PreparedStatement to prevent SQL injection
             PreparedStatement stmt = conn.prepareStatement("SELECT * FROM users WHERE name = ?")) {

            stmt.setString(1, name);

            try (ResultSet rs = stmt.executeQuery()) {
                ResultSetMetaData meta = rs.getMetaData();
                int cols = meta.getColumnCount();
                List<String> rows = new ArrayList<>();
                while (rs.next()) {
                    List<String> row = new ArrayList<>();
                    for (int i = 1; i <= cols; i++) {
                        row.add(meta.getColumnName(i) + "=" + rs.getString(i));
                    }
                    rows.add(String.join(", ", row));
                }
                return rows.isEmpty() ? "no results" : String.join("\n", rows);
            }
        }
    }
}