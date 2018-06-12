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

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Scope;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.client.web.OAuth2LoginAuthenticationFilter;
import org.springframework.security.web.authentication.Http403ForbiddenEntryPoint;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;

import com.maxaramos.apiserver.service.AuthService;

@EnableWebSecurity(debug = true)
public class WebSecurityConfig {

	@Value("${as.security.login.success-url}")
	private String loginSuccessUrl;

	@Value("${as.security.token.secret-key}")
	private String encodedSecretKey;

	private SecretKey secretKey;

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

	@Bean
	public OAuth2LoginSuccessHandler loginSuccessHandlerBean(AuthService authService) {
		OAuth2LoginSuccessHandler loginSuccessHandler = new OAuth2LoginSuccessHandler(loginSuccessUrl, authService);
		loginSuccessHandler.setAlwaysUseDefaultTargetUrl(true);
		return loginSuccessHandler;
	}

	@Configuration
	public static class OAuth2LoginSecurityConfig extends WebSecurityConfigurerAdapter {

		@Autowired
		private ConcurrentHashMapOAuth2AuthorizationRequestRepository concurrentHashMapOAuth2AuthorizationRequestRepository;

		@Autowired
		private ApiServerPreLoginAuthenticationFilter apiServerPreLoginAuthenticationFilter;

		@Autowired
		private OAuth2LoginSuccessHandler oauth2LoginSuccessHandler;

		@Override
		protected void configure(HttpSecurity http) throws Exception {
	//		OAuth2AuthorizationRequestRedirectFilter = /oauth2/authorization/{registrationId}
	//		OAuth2LoginAuthenticationFilter = /login/oauth2/code/*
			http
				.requestMatchers()
					.antMatchers("/oauth2/authorization/*", "/login/oauth2/code/*")
					.and()
				.authorizeRequests()
					.anyRequest().authenticated()
					.and()
				.oauth2Login()
					.authorizationEndpoint()
						.authorizationRequestRepository(concurrentHashMapOAuth2AuthorizationRequestRepository)
						.and()
					.successHandler(oauth2LoginSuccessHandler)
					.and()
				.addFilterBefore(apiServerPreLoginAuthenticationFilter,  OAuth2LoginAuthenticationFilter.class)
				.exceptionHandling()
					.authenticationEntryPoint(new Http403ForbiddenEntryPoint())
					.and()
				.csrf().disable();
		}
	}

	@Configuration
	@Order(Ordered.HIGHEST_PRECEDENCE)
	public static class ApiSecurityConfig extends WebSecurityConfigurerAdapter {

		@Autowired
		private AuthTokenProcessingFilter authTokenProcessingFilter;

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			http
				.requestMatchers()
					.antMatchers("/api/**")
					.and()
				.authorizeRequests()
					.anyRequest().authenticated()
					.and()
				.addFilterAt(authTokenProcessingFilter, AbstractPreAuthenticatedProcessingFilter.class)
				.exceptionHandling()
					.authenticationEntryPoint(new Http403ForbiddenEntryPoint())
					.and()
				.sessionManagement()
					.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
					.and()
				.csrf().disable();

		}
	}

}
