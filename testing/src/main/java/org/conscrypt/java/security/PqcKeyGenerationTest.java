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

    private static void registerBouncyCastleProvider() {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

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
    public void controlSingleArgument() throws Exception {
        KeyPairGenerator generator =
                KeyPairGenerator.getInstance("ML-DSA");

        KeyPair keyPair = generator.generateKeyPair();

        assertNotNull(keyPair.getPrivate());
        assertNotNull(keyPair.getPublic());
    }

    @Test
    public void controlLiteralProvider() throws Exception {
        registerBouncyCastleProvider();

        KeyPairGenerator generator =
                KeyPairGenerator.getInstance("ML-DSA", "BC");

        KeyPair keyPair = generator.generateKeyPair();

        assertNotNull(keyPair.getPrivate());
        assertNotNull(keyPair.getPublic());
    }

    @Test
    public void controlProviderConstant() throws Exception {
        registerBouncyCastleProvider();

        System.out.println(
        "Bouncy Castle provider name: "
                + BouncyCastleProvider.PROVIDER_NAME);

        KeyPairGenerator generator = KeyPairGenerator.getInstance(
                "ML-DSA", BouncyCastleProvider.PROVIDER_NAME);

        KeyPair keyPair = generator.generateKeyPair();

        assertNotNull(keyPair.getPrivate());
        assertNotNull(keyPair.getPublic());
    }

    private static final String LOCAL_PROVIDER_NAME = "BC";

    @Test
    public void controlLocalProviderConstant() throws Exception {
        registerBouncyCastleProvider();

        KeyPairGenerator generator = KeyPairGenerator.getInstance(
                "ML-DSA", LOCAL_PROVIDER_NAME);

        KeyPair keyPair = generator.generateKeyPair();

        assertNotNull(keyPair.getPrivate());
        assertNotNull(keyPair.getPublic());
    }

    @Test
    public void controlProviderConstantAES() throws Exception {
        registerBouncyCastleProvider();

        System.out.println(
        "Bouncy Castle provider name: "
                + BouncyCastleProvider.PROVIDER_NAME);

        KeyPairGenerator generator = KeyPairGenerator.getInstance(
                "AES", BouncyCastleProvider.PROVIDER_NAME);

        KeyPair keyPair = generator.generateKeyPair();

        assertNotNull(keyPair.getPrivate());
        assertNotNull(keyPair.getPublic());
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

        program.controlProviderConstant();

        System.out.println("controlProviderConstant completed successfully");
    }
}