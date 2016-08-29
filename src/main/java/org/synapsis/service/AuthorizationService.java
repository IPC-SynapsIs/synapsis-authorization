package org.synapsis.service;

import java.security.Key;
import java.util.Date;

import javax.crypto.spec.SecretKeySpec;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.SignatureException;

@Component
public class AuthorizationService implements IAuthorizationService {
	private static final Logger LOG = LoggerFactory.getLogger(AuthorizationService.class);
	
	private static final String ISSUER = "org.ipc.synapsis";
	private static final long TTL = 3600L;
	private static final String SECRET = "UnRvktIJzP9tWsZZGZ8LSqcu1TphQ26dTDvxH1YRBmQSwFqoOZtq9aOViHdWr1Um2694kGg5ChmgK1nUdgmZgma3QUwTB6Hrip3c9kWE9FwrErVCTO4d8VknnImGmyNt";

	// Creation du jeton JWT pour le sujet et le profile passés en paramètres
	public String createJWT(String subject, String profile) {
		long nowMillis = System.currentTimeMillis();
		Date now = new Date(nowMillis);
		Date expiration = new Date(nowMillis + TTL*1000);
		
		JwtBuilder builder = Jwts.builder().setIssuer(ISSUER)
										.setIssuedAt(now)
										.setSubject(subject)
										.setExpiration(expiration)
										.claim("ipc-profile", profile);
		/**
		Map<String, Object> claims = new HashMap<String, Object>();
		claims.put("ipc-profile", profile);
		builder.setClaims(claims);
		*/
		
		builder.signWith(getSignatureAlgorithm(), getSigninKey());

		return builder.compact();
	}

	// V�rification de la validité du jeton
	public boolean verifyJWT(String jwt) {
		boolean status = true;

		try {
			Jws<Claims> token = Jwts.parser().setSigningKey(getSigninKey()).parseClaimsJws(jwt);
			Claims claims = token.getBody();
			LOG.debug("issuer : " + claims.get("issuer", String.class));
			LOG.debug("issuedAt : " + claims.get("issuer", Date.class));			
			LOG.debug("subject : " + claims.get("subject", String.class));
			LOG.debug("expiration : " + claims.get("subject", Date.class));
			LOG.debug("profile : " + claims.get("subject", String.class));
			
		} catch (SignatureException se) {
			LOG.error("Erreur de validation du jeton JWT", se);
			status=false;
		} catch (ExpiredJwtException es) {
			LOG.error("Erreur de validation du jeton JWT", es);
			status=false;
		} catch (MalformedJwtException me) {
			LOG.error("Erreur de validation du jeton JWT", me);
			status=false;			
		} 
		
		return status;
	}

	// L'algorithme de cryptage utilisé
	private SignatureAlgorithm getSignatureAlgorithm() {
		return SignatureAlgorithm.HS256;
	}
	
	// La clef de cryptage
	private Key getSigninKey() {
		byte[] secretBytes = SECRET.getBytes();
		return new SecretKeySpec(secretBytes, getSignatureAlgorithm().getJcaName());
	}
}
