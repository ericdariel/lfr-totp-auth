package com.monapp.totp.integration;

import com.liferay.arquillian.extension.junit.bridge.junit.Arquillian;
import com.monapp.totp.service.TOTPService;
import com.warrenstrange.googleauth.GoogleAuthenticator;
import org.jboss.arquillian.container.test.api.Deployment;
import org.jboss.shrinkwrap.api.ShrinkWrap;
import org.jboss.shrinkwrap.api.asset.StringAsset;
import org.jboss.shrinkwrap.api.spec.JavaArchive;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.osgi.framework.BundleContext;
import org.osgi.framework.ServiceReference;

import javax.inject.Inject;
import java.util.Base64;
import java.util.HashSet;
import java.util.List;

import static org.junit.Assert.*;

/**
 * Arquillian integration tests for {@link TOTPService} inside a Liferay OSGi
 * runtime.
 */
@RunWith(Arquillian.class)
public class TOTPServiceIntegrationTest {

    @Deployment
    public static JavaArchive createDeployment() {
        return ShrinkWrap.create(JavaArchive.class, "totp-integration-test.jar")
            .addClasses(TOTPService.class)
            .addAsManifestResource(
                new StringAsset(
                    "Bundle-SymbolicName: com.monapp.totp.integration.test\n" +
                    "Bundle-Version: 1.0.0\n" +
                    "Import-Package: com.warrenstrange.googleauth,*\n"
                ), "MANIFEST.MF"
            );
    }

    @Inject
    private BundleContext _bundleContext;

    private TOTPService _totpService;

    @Before
    public void setUp() {
        ServiceReference<TOTPService> ref =
            _bundleContext.getServiceReference(TOTPService.class);
        assertNotNull("TOTPService non enregistré dans OSGi", ref);
        _totpService = _bundleContext.getService(ref);
    }

    @Test
    public void totpService_shouldBeRegisteredInOSGi() {
        assertNotNull(_bundleContext.getServiceReference(TOTPService.class));
    }

    @Test
    public void generateSecret_shouldProduceValidBase32Key() {
        String secret = _totpService.generateSecret();
        assertNotNull(secret);
        assertTrue(secret.matches("[A-Z2-7]+=*"));
    }

    @Test
    public void fullTOTPCycle_generateAndVerify_shouldSucceed() {
        String secret = _totpService.generateSecret();
        int currentCode = new GoogleAuthenticator().getTotpPassword(secret);
        assertTrue(_totpService.verifyCode(secret, currentCode));
    }

    @Test
    public void fullTOTPCycle_withWrongCode_shouldFail() {
        String secret = _totpService.generateSecret();
        assertFalse(_totpService.verifyCode(secret, 000000));
    }

    @Test
    public void generateQRCode_shouldProduceDecodableBase64PNG() throws Exception {
        String base64 = _totpService.generateQRCodeBase64(
            "otpauth://totp/MonApp:admin@test.com?secret=JBSWY3DPEHPK3PXP&issuer=MonApp");
        assertNotNull(base64);
        byte[] imageBytes = Base64.getDecoder().decode(base64);
        assertTrue(imageBytes.length > 0);
        assertEquals((byte) 0x89, imageBytes[0]);
        assertEquals((byte) 0x50, imageBytes[1]);
        assertEquals((byte) 0x4E, imageBytes[2]);
        assertEquals((byte) 0x47, imageBytes[3]);
    }

    @Test
    public void generateBackupCodes_shouldReturnUniqueFormattedCodes() {
        List<String> codes = _totpService.generateBackupCodes();
        assertEquals(5, codes.size());
        assertEquals(5, new HashSet<>(codes).size());
        codes.forEach(code ->
            assertTrue(
                "Invalid format: " + code,
                code.matches(
                    "[A-Z2-9]{4}-[A-Z2-9]{4}-[A-Z2-9]{4}-[A-Z2-9]{4}")));
    }
}
