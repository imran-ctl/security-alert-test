package com.example.securitytest;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

class VulnerableCommandControllerTest {

    private final VulnerableCommandController controller = new VulnerableCommandController();

    @Test
    void validHostIsAccepted() throws Exception {
        // A valid hostname should not return "Invalid host"
        String result = controller.ping("localhost");
        // Should not be rejected (result will be "started: <pid>" or similar)
        assertNotEquals("Invalid host", result);
    }

    @Test
    void injectionAttemptIsRejected() throws Exception {
        // A malicious host containing shell metacharacters must be rejected
        String result = controller.ping("127.0.0.1; rm -rf /");
        assertEquals("Invalid host", result);
    }

    @Test
    void hostWithPipeIsRejected() throws Exception {
        String result = controller.ping("host | cat /etc/passwd");
        assertEquals("Invalid host", result);
    }

    @Test
    void hostWithBackticksIsRejected() throws Exception {
        String result = controller.ping("`id`");
        assertEquals("Invalid host", result);
    }

    @Test
    void hostWithAmpersandIsRejected() throws Exception {
        String result = controller.ping("host && evil");
        assertEquals("Invalid host", result);
    }

    @Test
    void emptyHostIsRejected() throws Exception {
        String result = controller.ping("");
        assertEquals("Invalid host", result);
    }
}
