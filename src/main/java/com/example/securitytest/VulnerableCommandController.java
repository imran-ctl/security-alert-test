package com.example.securitytest;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.Map;
import java.util.concurrent.TimeUnit;

@RestController
public class VulnerableCommandController {

    // Allowlist of permitted commands mapped to their safe, fixed argument lists.
    // User input is never interpolated into the command; only the command key is
    // accepted and validated against this map before execution.
    private static final Map<String, String[]> ALLOWED_COMMANDS = Map.of(
            "date",    new String[]{"date"},
            "uptime",  new String[]{"uptime"},
            "whoami",  new String[]{"whoami"}
    );

    @GetMapping("/execute")
    public ResponseEntity<String> execute(@RequestParam String command)
            throws IOException, InterruptedException {
        if (!ALLOWED_COMMANDS.containsKey(command)) {
            return ResponseEntity.badRequest().body("Error: command not permitted.");
        }

        // Arguments are supplied as a fixed array — never constructed from user input —
        // so the OS receives no shell-interpretable input from the caller.
        String[] cmd = ALLOWED_COMMANDS.get(command);
        ProcessBuilder pb = new ProcessBuilder(cmd);
        pb.redirectErrorStream(true);
        Process process = pb.start();

        StringBuilder output = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream()))) {
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\n");
            }
        }

        boolean finished = process.waitFor(10, TimeUnit.SECONDS);
        if (!finished) {
            process.destroyForcibly();
            return ResponseEntity.internalServerError().body("Error: command timed out.");
        }
        if (process.exitValue() != 0) {
            return ResponseEntity.internalServerError()
                    .body("Error: command exited with status " + process.exitValue() + ".");
        }
        return ResponseEntity.ok(output.toString());
    }
}
