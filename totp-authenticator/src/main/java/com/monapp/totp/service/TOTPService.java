package com.monapp.totp.service;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.client.j2se.MatrixToImageWriter;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.qrcode.QRCodeWriter;
import com.liferay.expando.kernel.model.ExpandoColumnConstants;
import com.liferay.expando.kernel.model.ExpandoTable;
import com.liferay.expando.kernel.model.ExpandoTableConstants;
import com.liferay.expando.kernel.service.ExpandoColumnLocalService;
import com.liferay.expando.kernel.service.ExpandoTableLocalService;
import com.liferay.expando.kernel.service.ExpandoValueLocalService;
import com.liferay.expando.kernel.exception.NoSuchColumnException;
import com.liferay.portal.kernel.exception.PortalException;
import com.liferay.portal.kernel.json.JSONArray;
import com.liferay.portal.kernel.json.JSONFactoryUtil;
import com.liferay.portal.kernel.log.Log;
import com.liferay.portal.kernel.log.LogFactoryUtil;
import com.liferay.portal.kernel.model.User;
import com.liferay.portal.kernel.util.Validator;
import com.warrenstrange.googleauth.GoogleAuthenticator;
import com.warrenstrange.googleauth.GoogleAuthenticatorKey;
import com.warrenstrange.googleauth.GoogleAuthenticatorQRGenerator;
import org.mindrot.jbcrypt.BCrypt;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;

import java.io.ByteArrayOutputStream;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.stream.Collectors;

/**
 * OSGi service providing TOTP secret management, verification, backup codes,
 * and QR code generation.
 *
 * <p>User secrets and backup codes are persisted in Liferay Expando custom
 * fields.</p>
 *
 * @author monapp
 */
@Component(
    immediate = true,
    service = TOTPService.class
)
public class TOTPService {

    private static final Log _log = LogFactoryUtil.getLog(TOTPService.class);

    /** Number of single-use backup codes generated during setup. */
    private static final int BACKUP_CODE_COUNT = 5;

    /** Characters per hyphen-separated backup code group. */
    private static final int BACKUP_CODE_GROUP_LENGTH = 4;

    /** Number of groups in each backup code. */
    private static final int BACKUP_CODE_GROUP_COUNT = 4;

    /** Alphabet excluding ambiguous characters (0/O, 1/I/L). */
    private static final String BACKUP_CODE_ALPHABET =
        "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

    private final GoogleAuthenticator _gAuth = new GoogleAuthenticator();

    /**
     * Generates a new Base32 TOTP secret.
     *
     * @return new secret key
     */
    public String generateSecret() {
        return _gAuth.createCredentials().getKey();
    }

    /**
     * Builds an {@code otpauth://} URL suitable for authenticator apps.
     *
     * @param issuer application or company name
     * @param account user account label (typically email)
     * @param secret TOTP secret
     * @return otpauth URI
     */
    public String generateOtpAuthUrl(String issuer, String account, String secret) {
        GoogleAuthenticatorKey key = new GoogleAuthenticatorKey.Builder(secret).build();
        return GoogleAuthenticatorQRGenerator.getOtpAuthTotpURL(issuer, account, key);
    }

    /**
     * Verifies a six-digit TOTP code against the given secret.
     *
     * @param secret stored TOTP secret
     * @param code six-digit code from the authenticator app
     * @return {@code true} if the code is valid
     */
    public boolean verifyCode(String secret, int code) {
        return _gAuth.authorize(secret, code);
    }

    /**
     * Returns the persisted TOTP secret for the user, if any.
     *
     * @param user target user
     * @return secret or {@code null}
     */
    public String getTotpSecret(User user) {
        try {
            return (String) _expandoValueLocalService.getData(
                user.getCompanyId(), User.class.getName(),
                ExpandoTableConstants.DEFAULT_TABLE_NAME,
                "totpSecret", user.getUserId());
        } catch (Exception e) {
            _log.error("Erreur lecture secret TOTP", e);
            return null;
        }
    }

    /**
     * Persists a TOTP secret for the user.
     *
     * @param user target user
     * @param secret secret to store
     * @throws PortalException if Expando update fails
     */
    public void saveTotpSecret(User user, String secret) throws PortalException {
        _ensureExpandoColumn(user.getCompanyId(), "totpSecret");
        _expandoValueLocalService.addValue(
            user.getCompanyId(), User.class.getName(),
            ExpandoTableConstants.DEFAULT_TABLE_NAME,
            "totpSecret", user.getUserId(), secret
        );
    }

    /**
     * Deletes the TOTP secret for the user.
     *
     * @param user target user
     */
    public void deleteTotpSecret(User user) {
        try {
            _expandoValueLocalService.deleteValue(
                user.getCompanyId(), User.class.getName(),
                ExpandoTableConstants.DEFAULT_TABLE_NAME,
                "totpSecret", user.getUserId()
            );
        } catch (Exception e) {
            _log.warn("Impossible de supprimer le secret TOTP : " + user.getEmailAddress());
        }
    }

    /**
     * Persists BCrypt-hashed backup codes for the user.
     *
     * @param user target user
     * @param codes plain-text backup codes
     * @throws PortalException if Expando update fails
     */
    public void saveBackupCodes(User user, List<String> codes) throws PortalException {
        _ensureExpandoColumn(user.getCompanyId(), "totpBackupCodes");
        List<String> hashedCodes = codes.stream()
            .map(code -> BCrypt.hashpw(code, BCrypt.gensalt()))
            .collect(Collectors.toList());
        String codesJson = JSONFactoryUtil.createJSONArray(hashedCodes).toString();
        _expandoValueLocalService.addValue(
            user.getCompanyId(), User.class.getName(),
            ExpandoTableConstants.DEFAULT_TABLE_NAME,
            "totpBackupCodes", user.getUserId(), codesJson
        );
    }

    /**
     * Deletes all backup codes for the user.
     *
     * @param user target user
     */
    public void deleteBackupCodes(User user) {
        try {
            _expandoValueLocalService.deleteValue(
                user.getCompanyId(), User.class.getName(),
                ExpandoTableConstants.DEFAULT_TABLE_NAME,
                "totpBackupCodes", user.getUserId()
            );
        } catch (Exception e) {
            _log.warn("Impossible de supprimer les codes de secours : " + user.getEmailAddress());
        }
    }

    /**
     * Verifies a backup code and removes it on success (single use).
     *
     * <p>Input is normalized to support legacy numeric codes and the current
     * alphanumeric format with optional hyphens.</p>
     *
     * @param user target user
     * @param inputCode user-supplied backup code
     * @return {@code true} if valid and consumed
     * @throws PortalException if Expando update fails after consumption
     */
    public boolean verifyBackupCode(User user, String inputCode)
        throws PortalException {

        String normalizedCode = _normalizeBackupCode(inputCode);

        if (Validator.isNull(normalizedCode)) {
            return false;
        }

        String codesJson = (String)_expandoValueLocalService.getData(
            user.getCompanyId(), User.class.getName(),
            ExpandoTableConstants.DEFAULT_TABLE_NAME,
            "totpBackupCodes", user.getUserId());

        if (Validator.isNull(codesJson)) {
            return false;
        }

        JSONArray jsonArray = JSONFactoryUtil.createJSONArray(codesJson);

        for (int i = 0; i < jsonArray.length(); i++) {
            String hashedCode = jsonArray.getString(i);

            if (BCrypt.checkpw(normalizedCode, hashedCode)) {
                _removeBackupCode(user, codesJson, i);

                return true;
            }
        }

        return false;
    }

    /**
     * Generates unique single-use backup codes.
     *
     * @return list of {@value #BACKUP_CODE_COUNT} codes in
     *         {@code XXXX-XXXX-XXXX-XXXX} format
     */
    public List<String> generateBackupCodes() {
        List<String> codes = new ArrayList<>();
        SecureRandom random = new SecureRandom();

        while (codes.size() < BACKUP_CODE_COUNT) {
            String code = _generateBackupCode(random);

            if (!codes.contains(code)) {
                codes.add(code);
            }
        }

        return codes;
    }

    /**
     * Encodes an otpauth URL as a Base64 PNG QR code image.
     *
     * @param otpAuthUrl otpauth URI
     * @return Base64-encoded PNG data
     * @throws Exception if QR encoding fails
     */
    public String generateQRCodeBase64(String otpAuthUrl) throws Exception {
        QRCodeWriter writer = new QRCodeWriter();
        BitMatrix matrix = writer.encode(otpAuthUrl, BarcodeFormat.QR_CODE, 250, 250);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        MatrixToImageWriter.writeToStream(matrix, "PNG", baos);
        return Base64.getEncoder().encodeToString(baos.toByteArray());
    }

    private String _generateBackupCode(SecureRandom random) {
        StringBuilder builder = new StringBuilder();

        for (int group = 0; group < BACKUP_CODE_GROUP_COUNT; group++) {
            if (group > 0) {
                builder.append('-');
            }

            for (int i = 0; i < BACKUP_CODE_GROUP_LENGTH; i++) {
                int index = random.nextInt(BACKUP_CODE_ALPHABET.length());

                builder.append(BACKUP_CODE_ALPHABET.charAt(index));
            }
        }

        return builder.toString();
    }

    private String _normalizeBackupCode(String code) {
        if (Validator.isNull(code)) {
            return null;
        }

        String normalized = code.trim().toUpperCase().replaceAll("[\\s-]", "");

        if (normalized.matches("\\d{8}")) {
            return normalized.substring(0, 4) + "-" + normalized.substring(4);
        }

        if (normalized.matches(
                "[" + BACKUP_CODE_ALPHABET + "]{" +
                    (BACKUP_CODE_GROUP_LENGTH * BACKUP_CODE_GROUP_COUNT) + "}")) {

            StringBuilder builder = new StringBuilder();

            for (int group = 0; group < BACKUP_CODE_GROUP_COUNT; group++) {
                if (group > 0) {
                    builder.append('-');
                }

                int start = group * BACKUP_CODE_GROUP_LENGTH;

                builder.append(
                    normalized, start, start + BACKUP_CODE_GROUP_LENGTH);
            }

            return builder.toString();
        }

        return code.trim().toUpperCase();
    }

    private void _ensureExpandoColumn(long companyId, String columnName) throws PortalException {
        try {
            ExpandoTable table = _expandoTableLocalService.getDefaultTable(
                companyId, User.class.getName());
            _expandoColumnLocalService.getColumn(table.getTableId(), columnName);
        } catch (NoSuchColumnException e) {
            ExpandoTable table = _expandoTableLocalService.getDefaultTable(
                companyId, User.class.getName());
            _expandoColumnLocalService.addColumn(
                table.getTableId(), columnName, ExpandoColumnConstants.STRING);
        }
    }

    private void _removeBackupCode(User user, String codesJson, int usedIndex) throws PortalException {
        JSONArray jsonArray = JSONFactoryUtil.createJSONArray(codesJson);
        JSONArray updatedCodes = JSONFactoryUtil.createJSONArray();
        for (int i = 0; i < jsonArray.length(); i++) {
            if (i != usedIndex) updatedCodes.put(jsonArray.getString(i));
        }
        _expandoValueLocalService.addValue(
            user.getCompanyId(), User.class.getName(),
            ExpandoTableConstants.DEFAULT_TABLE_NAME,
            "totpBackupCodes", user.getUserId(), updatedCodes.toString()
        );
    }

    @Reference
    private ExpandoValueLocalService _expandoValueLocalService;

    @Reference
    private ExpandoTableLocalService _expandoTableLocalService;

    @Reference
    private ExpandoColumnLocalService _expandoColumnLocalService;
}
