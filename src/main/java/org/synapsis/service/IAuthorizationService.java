package org.synapsis.service;

public interface IAuthorizationService {
	public  String createJWT(String subject, String profile);
}