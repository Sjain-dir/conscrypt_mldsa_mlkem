package org.conscrypt.java.security;

import static org.junit.Assert.assertNotNull;

import java.security.KeyPair;
import java.security.KeyPairGenerator;

import org.junit.Test;

public class PqcKeyGenerationTest {

    @Test
    public void testGenerateMlKemKeyPair() throws Exception {
        KeyPairGenerator kpg =
                KeyPairGenerator.getInstance("ML-KEM");

        KeyPair kp = kpg.generateKeyPair();

        assertNotNull(kp.getPrivate());
        assertNotNull(kp.getPublic());
    }

    @Test
    public void testGenerateMlDsaKeyPair() throws Exception {
        KeyPairGenerator kpg =
                KeyPairGenerator.getInstance("ML-DSA");

        KeyPair kp = kpg.generateKeyPair();

        assertNotNull(kp.getPrivate());
        assertNotNull(kp.getPublic());
    }
}