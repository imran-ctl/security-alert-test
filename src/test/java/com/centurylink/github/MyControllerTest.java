package com.centurylink.github;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.net.URI;

import static org.junit.jupiter.api.Assertions.*;

class MyControllerTest {

    private MyController controller;

    @BeforeEach
    void setUp() {
        controller = new MyController();
    }

    @Test
    void validateAndBuildSafeUri_rejectsNullUrl() {
        assertThrows(SecurityException.class, () -> controller.validateAndBuildSafeUri(null));
    }

    @Test
    void validateAndBuildSafeUri_rejectsBlankUrl() {
        assertThrows(SecurityException.class, () -> controller.validateAndBuildSafeUri("   "));
    }

    @Test
    void validateAndBuildSafeUri_rejectsHttpScheme() {
        assertThrows(SecurityException.class,
                () -> controller.validateAndBuildSafeUri("http://api.centurylink.com/data"));
    }

    @Test
    void validateAndBuildSafeUri_rejectsFtpScheme() {
        assertThrows(SecurityException.class,
                () -> controller.validateAndBuildSafeUri("ftp://api.centurylink.com/data"));
    }

    @Test
    void validateAndBuildSafeUri_rejectsHostNotInAllowlist() {
        assertThrows(SecurityException.class,
                () -> controller.validateAndBuildSafeUri("https://attacker.example.com/data"));
    }

    @Test
    void validateAndBuildSafeUri_rejectsLocalhostUrl() {
        assertThrows(SecurityException.class,
                () -> controller.validateAndBuildSafeUri("https://localhost/admin"));
    }

    @Test
    void validateAndBuildSafeUri_rejectsInvalidUrlFormat() {
        assertThrows(SecurityException.class,
                () -> controller.validateAndBuildSafeUri("not-a-url"));
    }

    @Test
    void validateAndBuildSafeUri_rejectsMissingHost() {
        assertThrows(SecurityException.class,
                () -> controller.validateAndBuildSafeUri("https:///path"));
    }

    @Test
    void validateAndBuildSafeUri_rejectsInternalMetadataServiceUrl() {
        assertThrows(SecurityException.class,
                () -> controller.validateAndBuildSafeUri("https://169.254.169.254/latest/meta-data/"));
    }

    @Test
    void isBlockedIpAddress_blocks10Range() {
        MyController c = new MyController();
        assertTrue(invokeIsBlockedIp(c, "10.0.0.1"));
        assertTrue(invokeIsBlockedIp(c, "10.255.255.255"));
    }

    @Test
    void isBlockedIpAddress_blocks192168Range() {
        MyController c = new MyController();
        assertTrue(invokeIsBlockedIp(c, "192.168.0.1"));
        assertTrue(invokeIsBlockedIp(c, "192.168.100.200"));
    }

    @Test
    void isBlockedIpAddress_blocks172PrivateRange() {
        MyController c = new MyController();
        assertTrue(invokeIsBlockedIp(c, "172.16.0.1"));
        assertTrue(invokeIsBlockedIp(c, "172.31.255.255"));
        assertFalse(invokeIsBlockedIp(c, "172.32.0.1"));
        assertFalse(invokeIsBlockedIp(c, "172.15.0.1"));
    }

    @Test
    void isBlockedIpAddress_blocks127Loopback() {
        MyController c = new MyController();
        assertTrue(invokeIsBlockedIp(c, "127.0.0.1"));
        assertTrue(invokeIsBlockedIp(c, "127.255.255.255"));
    }

    @Test
    void isBlockedIpAddress_blocksLinkLocal() {
        MyController c = new MyController();
        assertTrue(invokeIsBlockedIp(c, "169.254.169.254"));
        assertTrue(invokeIsBlockedIp(c, "169.254.0.1"));
    }

    @Test
    void isBlockedIpAddress_allowsPublicIp() {
        MyController c = new MyController();
        assertFalse(invokeIsBlockedIp(c, "8.8.8.8"));
        assertFalse(invokeIsBlockedIp(c, "172.32.0.1"));
    }

    private boolean invokeIsBlockedIp(MyController c, String ip) {
        try {
            var method = MyController.class.getDeclaredMethod("isBlockedIpAddress", String.class);
            method.setAccessible(true);
            return (boolean) method.invoke(c, ip);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
