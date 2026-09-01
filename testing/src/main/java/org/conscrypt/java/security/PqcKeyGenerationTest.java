package org.conscrypt.java.security;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.Signature;

import org.bouncycastle.jcajce.spec.MLDSAParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
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

    @Test
    public void testMlDsaExplicitProviderDetection() throws Exception {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }

        byte[] message = "hello".getBytes(StandardCharsets.UTF_8);

        // Two-argument getInstance(algorithm, provider) call.
        KeyPairGenerator generator = KeyPairGenerator.getInstance(
                "ML-DSA", BouncyCastleProvider.PROVIDER_NAME);
        generator.initialize(MLDSAParameterSpec.ml_dsa_65);

        KeyPair keyPair = generator.generateKeyPair();

        assertNotNull(keyPair);
        assertNotNull(keyPair.getPrivate());
        assertNotNull(keyPair.getPublic());

        // Two-argument getInstance(algorithm, provider) call.
        Signature signer = Signature.getInstance(
                "ML-DSA", BouncyCastleProvider.PROVIDER_NAME);
        signer.initSign(keyPair.getPrivate());
        signer.update(message);
        byte[] signatureBytes = signer.sign();

        assertNotNull(signatureBytes);

        // Two-argument getInstance(algorithm, provider) call.
        Signature verifier = Signature.getInstance(
                "ML-DSA", BouncyCastleProvider.PROVIDER_NAME);
        verifier.initVerify(keyPair.getPublic());
        verifier.update(message);

        assertTrue(verifier.verify(signatureBytes));
    }

    public static void main(String[] args) throws Exception {
        PqcKeyGenerationTest program = new PqcKeyGenerationTest();
        program.testMlDsaExplicitProviderDetection();

        System.out.println(
                "testMlDsaExplicitProviderDetection completed successfully");
    }
}