package com.loginflow.iam.user.dto;

public class MfaSetupResponse {
	private String secret;
	private String manualConfigString;
	private String qrCodeDataUrl;

	public MfaSetupResponse(String secret, String manualConfigString, String qrCodeDataUrl) {
		this.secret = secret;
		this.manualConfigString = manualConfigString;
		this.qrCodeDataUrl = qrCodeDataUrl;
	}

	public String getSecret() {
		return secret;
	}

	public String getManualConfigString() {
		return manualConfigString;
	}

	public String getQrCodeDataUrl() {
		return qrCodeDataUrl;
	}
}
