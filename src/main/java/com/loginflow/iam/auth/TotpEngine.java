package com.loginflow.iam.auth;

import com.warrenstrange.googleauth.GoogleAuthenticator;
import com.warrenstrange.googleauth.GoogleAuthenticatorKey;
import com.google.zxing.BarcodeFormat;
import com.google.zxing.client.j2se.MatrixToImageWriter;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.qrcode.QRCodeWriter;
import org.springframework.stereotype.Component;

import java.io.ByteArrayOutputStream;
import java.util.Base64;

@Component
public class TotpEngine {

    private final GoogleAuthenticator gAuth = new GoogleAuthenticator();

    public String generateSecretKey() {
        GoogleAuthenticatorKey credentials = gAuth.createCredentials();
        return credentials.getKey();
    }

    public boolean verifyCode(String secret, int code) {
        if (secret == null || secret.isBlank()) return false;
        return gAuth.authorize(secret, code);
    }

    /**
     * Natively converts an OTP Auth URL text configuration path into an industry standard 
     * Base64 Encoded PNG Image Data URL.
     */
    public String generateQrCodeBase64(String username, String secret) {
        try {
            // Standard format syntax required by Google Authenticator and Authy apps
            String formatUri = String.format("otpauth://totp/Umapathi'sIAM:%s?secret=%s&issuer=SecureIdentityGrid", username, secret);
            
            QRCodeWriter qrCodeWriter = new QRCodeWriter();
            BitMatrix bitMatrix = qrCodeWriter.encode(formatUri, BarcodeFormat.QR_CODE, 200, 200);
            
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            MatrixToImageWriter.writeToStream(bitMatrix, "PNG", outputStream);
            byte[] imageBytes = outputStream.toByteArray();
            
            return "data:image/png;base64," + Base64.getEncoder().encodeToString(imageBytes);
        } catch (Exception e) {
            throw new RuntimeException("CRITICAL_MFA_MATRIX_RENDER_ERROR", e);
        }
    }
}