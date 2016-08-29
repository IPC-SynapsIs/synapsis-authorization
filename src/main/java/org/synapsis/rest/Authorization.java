package org.synapsis.rest;

import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.synapsis.service.IAuthorizationService;



@Component
@Path("/authorization")
public class Authorization {
	
	@Autowired
	private IAuthorizationService authorizationService;
	
	@Path("/jwt")
	@GET
	@Produces(MediaType.TEXT_PLAIN)
	public Response getJwt(@QueryParam("subject") String subject, @QueryParam("profile") String profile) {
		String jwt = authorizationService.createJWT(subject, profile);
		return Response.ok().entity(jwt).build();
	}
	
	@Path("/jwt/validation")
	@GET
	@Produces(MediaType.TEXT_PLAIN)
	public Response verifyJwt(@QueryParam("jwt") String jwt) {
		boolean status = authorizationService.verifyJWT(jwt);
		return Response.ok().entity("Status : " + status).build();
	}
}
