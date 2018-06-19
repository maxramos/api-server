package com.maxaramos.apiserver.security;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Base64.Decoder;
import java.util.Base64.Encoder;

import javax.annotation.PostConstruct;
import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Scope;

@Configuration
public class CryptoConfig {

	private SecretKey secretKey;

	@Value("${as.security.token.secret-key}")
	private String encodedSecretKey;

	@PostConstruct
	void init() {
		byte[] decodedSecretKey = base64Decoder().decode(encodedSecretKey);
		secretKey = new SecretKeySpec(decodedSecretKey, "AES");
	}

	@Bean
	public Encoder base64Encoder() {
		return Base64.getEncoder();
	}

	@Bean
	public Decoder base64Decoder() {
		return Base64.getDecoder();
	}

	@Bean
	@Scope("prototype")
	public Cipher aesEncryptor() {
		Cipher cipher = null;

		try {
			cipher = Cipher.getInstance("AES");
			cipher.init(Cipher.ENCRYPT_MODE, secretKey);
		} catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException e) {
			new RuntimeException("Cannot create encryptor cipher.", e);
		}

		return cipher;
	}

	@Bean
	@Scope("prototype")
	public Cipher aesDecryptor() {
		Cipher cipher = null;

		try {
			cipher = Cipher.getInstance("AES");
			cipher.init(Cipher.DECRYPT_MODE, secretKey);
		} catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException e) {
			new RuntimeException("Cannot create decryptor cipher.", e);
		}

		return cipher;
	}

}
