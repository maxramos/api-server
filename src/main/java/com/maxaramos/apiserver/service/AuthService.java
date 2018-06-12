package com.maxaramos.apiserver.service;

import java.util.Base64.Encoder;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;

import org.json.JSONException;
import org.json.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import com.maxaramos.apiserver.dao.AuthTokenDao;
import com.maxaramos.apiserver.dao.UserDao;
import com.maxaramos.apiserver.model.security.AuthToken;

@Service
public class AuthService {

	@Autowired
	private Encoder base64Encoder;

	@Autowired
	private UserDao userDao;

	@Autowired
	private AuthTokenDao authTokenDao;

	@Autowired
	private ApplicationContext applicationContext;

	public String generateToken(String username) {
		UserDetails user = userDao.findByUsername(username);

		if (user == null) {
			throw new AuthException();
		}

		return generateToken(user);
	}

	private String generateToken(UserDetails user) {
		AuthToken authToken = authTokenDao.generate(user);

		try {
			JSONObject jsonObj = new JSONObject();
			jsonObj.put("username", user.getUsername());
			jsonObj.put("tokenId", authToken.getTokenId());
			jsonObj.put("expiry", authToken.getExpiry().toEpochMilli());
			String token = jsonObj.toString();
			byte[] encryptedToken = applicationContext.getBean("aesEncryptor", Cipher.class).doFinal(token.getBytes());
			String encodedEncryptedToken = base64Encoder.encodeToString(encryptedToken);
			return encodedEncryptedToken;
		} catch (JSONException | IllegalBlockSizeException | BadPaddingException e) {
			throw new RuntimeException("Error in generating auth token.", e);
		}
	}

}
