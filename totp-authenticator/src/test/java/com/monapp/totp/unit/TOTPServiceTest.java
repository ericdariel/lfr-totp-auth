package com.monapp.totp.unit;

import com.liferay.expando.kernel.model.ExpandoTableConstants;
import com.liferay.expando.kernel.service.ExpandoColumnLocalService;
import com.liferay.expando.kernel.service.ExpandoTableLocalService;
import com.liferay.expando.kernel.service.ExpandoValueLocalService;
import com.liferay.portal.kernel.model.User;
import com.monapp.totp.service.TOTPService;
import com.warrenstrange.googleauth.GoogleAuthenticator;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Base64;
import java.util.HashSet;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/**
 * Unit tests for {@link TOTPService} using Mockito.
 */
@ExtendWith(MockitoExtension.class)
class TOTPServiceTest {

    @InjectMocks
    private TOTPService _totpService;

    @Mock
    private ExpandoValueLocalService _expandoValueLocalService;

    @Mock
    private ExpandoTableLocalService _expandoTableLocalService;

    @Mock
    private ExpandoColumnLocalService _expandoColumnLocalService;

    @Mock
    private User _user;

    @Test
    void generateSecret_shouldReturnValidKey() {
        String secret = _totpService.generateSecret();
        assertNotNull(secret);
        assertFalse(secret.isEmpty());
    }

    @Test
    void verifyCode_withValidCode_shouldReturnTrue() {
        String secret = _totpService.generateSecret();
        GoogleAuthenticator gAuth = new GoogleAuthenticator();
        int validCode = gAuth.getTotpPassword(secret);
        assertTrue(_totpService.verifyCode(secret, validCode));
    }

    @Test
    void verifyCode_withInvalidCode_shouldReturnFalse() {
        String secret = _totpService.generateSecret();
        assertFalse(_totpService.verifyCode(secret, 000000));
    }

    @Test
    void getTotpSecret_whenExists_shouldReturnSecret() throws Exception {
        when(_user.getCompanyId()).thenReturn(1L);
        when(_user.getUserId()).thenReturn(100L);
        when(_expandoValueLocalService.getData(
            eq(1L), eq(User.class.getName()),
            eq(ExpandoTableConstants.DEFAULT_TABLE_NAME),
            eq("totpSecret"), eq(100L)
        )).thenReturn("MYSECRETBASE32");

        assertEquals("MYSECRETBASE32", _totpService.getTotpSecret(_user));
    }

    @Test
    void getTotpSecret_whenNotExists_shouldReturnNull() throws Exception {
        when(_user.getCompanyId()).thenReturn(1L);
        when(_user.getUserId()).thenReturn(100L);
        when(_expandoValueLocalService.getData(
            anyLong(), anyString(), anyString(),
            eq("totpSecret"), anyLong()
        )).thenReturn(null);

        assertNull(_totpService.getTotpSecret(_user));
    }

    @Test
    void generateBackupCodes_shouldReturnConfiguredCount() {
        assertEquals(5, _totpService.generateBackupCodes().size());
    }

    @Test
    void generateBackupCodes_shouldMatchFormat() {
        _totpService.generateBackupCodes().forEach(code ->
            assertTrue(
                code.matches("[A-Z2-9]{4}-[A-Z2-9]{4}-[A-Z2-9]{4}-[A-Z2-9]{4}"),
                "Invalid format: " + code));
    }

    @Test
    void generateBackupCodes_shouldBeUnique() {
        List<String> codes = _totpService.generateBackupCodes();
        assertEquals(codes.size(), new HashSet<>(codes).size());
    }

    @Test
    void generateQRCodeBase64_shouldReturnValidBase64() throws Exception {
        String base64 = _totpService.generateQRCodeBase64(
            "otpauth://totp/Test:user@test.com?secret=ABC&issuer=Test");
        assertNotNull(base64);
        assertDoesNotThrow(() -> Base64.getDecoder().decode(base64));
    }
}
