package com.maxaramos.apiserver.service;

import java.time.Instant;
import java.util.Base64.Decoder;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;

import org.json.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import com.maxaramos.apiserver.dao.AuthTokenDao;
import com.maxaramos.apiserver.dao.UserDao;

@Service
public class UserService {

	@Autowired
	private Decoder base64Decoder;

	@Autowired
	private ApplicationContext applicationContext;

	@Autowired
	private UserDao userDao;

	@Autowired
	private AuthTokenDao authTokenDao;


	public UserDetails findUserByNonExpiredAuthToken(String encodedEncryptedToken) {
		String token = decryptToken(encodedEncryptedToken);

		if (token == null) {
			return null;
		}

		JSONObject jsonObj = new JSONObject(token);
		String username = jsonObj.getString("username");
		String tokenId = jsonObj.getString("tokenId");
		Instant expiry = Instant.ofEpochMilli(jsonObj.getLong("expiry"));

		if (!expiry.isAfter(Instant.now()) && authTokenDao.isExpired(tokenId)) {
			return null;
		}

		authTokenDao.refreshExpiry(tokenId);
		UserDetails user = userDao.findByUsername(username);
		return user;
	}

	private String decryptToken(String encodedEncryptedToken) {
		try {
			byte[] decodedEncryptedToken = base64Decoder.decode(encodedEncryptedToken);
			byte[] decryptedToken = applicationContext.getBean("aesDecryptor", Cipher.class).doFinal(decodedEncryptedToken);
			return new String(decryptedToken);
		} catch (IllegalArgumentException | IllegalBlockSizeException | BadPaddingException e) {
			throw new RuntimeException(e);
		}
	}

}
