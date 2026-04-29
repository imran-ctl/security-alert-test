package com.centurylink.github;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

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
        assertTrue(controller.isBlockedIpAddress("10.0.0.1"));
        assertTrue(controller.isBlockedIpAddress("10.255.255.255"));
    }

    @Test
    void isBlockedIpAddress_blocks192168Range() {
        assertTrue(controller.isBlockedIpAddress("192.168.0.1"));
        assertTrue(controller.isBlockedIpAddress("192.168.100.200"));
    }

    @Test
    void isBlockedIpAddress_blocks172PrivateRange() {
        assertTrue(controller.isBlockedIpAddress("172.16.0.1"));
        assertTrue(controller.isBlockedIpAddress("172.31.255.255"));
        assertFalse(controller.isBlockedIpAddress("172.32.0.1"));
        assertFalse(controller.isBlockedIpAddress("172.15.0.1"));
    }

    @Test
    void isBlockedIpAddress_blocks127Loopback() {
        assertTrue(controller.isBlockedIpAddress("127.0.0.1"));
        assertTrue(controller.isBlockedIpAddress("127.255.255.255"));
    }

    @Test
    void isBlockedIpAddress_blocksLinkLocal() {
        assertTrue(controller.isBlockedIpAddress("169.254.169.254"));
        assertTrue(controller.isBlockedIpAddress("169.254.0.1"));
    }

    @Test
    void isBlockedIpAddress_blocksIPv6Loopback() {
        assertTrue(controller.isBlockedIpAddress("::1"));
        assertTrue(controller.isBlockedIpAddress("0:0:0:0:0:0:0:1"));
    }

    @Test
    void isBlockedIpAddress_blocksIPv6LinkLocal() {
        assertTrue(controller.isBlockedIpAddress("fe80::1"));
        assertTrue(controller.isBlockedIpAddress("FE80::1"));
    }

    @Test
    void isBlockedIpAddress_blocksIPv6UniqueLocal() {
        assertTrue(controller.isBlockedIpAddress("fc00::1"));
        assertTrue(controller.isBlockedIpAddress("fd12:3456:789a::1"));
    }

    @Test
    void isBlockedIpAddress_allowsPublicIp() {
        assertFalse(controller.isBlockedIpAddress("8.8.8.8"));
        assertFalse(controller.isBlockedIpAddress("172.32.0.1"));
    }

    @Test
    void isBlockedIpAddress_blocksNull() {
        assertTrue(controller.isBlockedIpAddress(null));
    }
}
