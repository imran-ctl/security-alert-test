package com.example.securitytest;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(VulnerableCommandController.class)
class VulnerableCommandControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    void disallowedCommandReturnsError() throws Exception {
        mockMvc.perform(get("/execute").param("command", "rm -rf /"))
                .andExpect(status().isOk())
                .andExpect(content().string("Error: command not permitted."));
    }

    @Test
    void shellInjectionAttemptIsRejected() throws Exception {
        mockMvc.perform(get("/execute").param("command", "date; cat /etc/passwd"))
                .andExpect(status().isOk())
                .andExpect(content().string("Error: command not permitted."));
    }

    @Test
    void allowedCommandReturnsOutput() throws Exception {
        mockMvc.perform(get("/execute").param("command", "whoami"))
                .andExpect(status().isOk());
    }
}
