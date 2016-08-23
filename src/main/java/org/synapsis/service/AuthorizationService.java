package org.synapsis.service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.spec.SecretKeySpec;

import org.springframework.stereotype.Component;

import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

@Component
public class AuthorizationService implements IAuthorizationService {
	private static final String ISSUER = "org.ipc.synapsis";
	private static final long TTL = 3600L;
	private static final String SECRET = "UnRvktIJzP9tWsZZGZ8LSqcu1TphQ26dTDvxH1YRBmQSwFqoOZtq9aOViHdWr1Um2694kGg5ChmgK1nUdgmZgma3QUwTB6Hrip3c9kWE9FwrErVCTO4d8VknnImGmyNt";

	public String createJWT(String subject, String profile) {
		SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.HS256;
		
		long nowMillis = System.currentTimeMillis();
		Date now = new Date(nowMillis);
		Date expiration = new Date(nowMillis + TTL);
		
		byte[] secretBytes = SECRET.getBytes();
		Key signinKey = new SecretKeySpec(secretBytes, signatureAlgorithm.getJcaName());
		
		JwtBuilder builder = Jwts.builder().setIssuer(ISSUER)
										.setIssuedAt(now)
										.setSubject(subject)
										.setExpiration(expiration);
		Map<String, Object> claims = new HashMap<String, Object>();
		claims.put("ipc-profile", profile);
		builder.setClaims(claims);
		
		builder.signWith(signatureAlgorithm, signinKey);

		return builder.compact();
	}
	
}
