package com.appdeveloperblog.app.ws.security;

import java.io.IOException;
import java.util.ArrayList;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import io.jsonwebtoken.Jwts;

public class AuthorizationFilter extends BasicAuthenticationFilter{

	public AuthorizationFilter(AuthenticationManager authManager) {
		super(authManager);
		// TODO Auto-generated constructor stub
	}

	@Override
	protected void doFilterInternal(HttpServletRequest req, HttpServletResponse res, FilterChain chain)
			throws IOException, ServletException {
		String header = req.getHeader(SecurityContants.HEADER_STRING);
		System.out.println("doFilterInternal. header : " + header);
		System.out.println(header.startsWith(SecurityContants.TOKEN_PREFIX));
		if(header == null || !header.startsWith(SecurityContants.TOKEN_PREFIX)) {
			chain.doFilter(req, res);
			System.out.println("if문 걸림 ㅠ");
			return;
		}
		System.out.println("if문 안걸림!");
		UsernamePasswordAuthenticationToken authentication = getAuthentication(req);
		SecurityContextHolder.getContext().setAuthentication(authentication);
		chain.doFilter(req, res);
	}
	
	private UsernamePasswordAuthenticationToken getAuthentication(HttpServletRequest request) {
		String token = request.getHeader(SecurityContants.HEADER_STRING);
		System.out.println("@@@ getAuthentication token : " + token);
		if(token != null) {
			token = token.replace(SecurityContants.TOKEN_PREFIX, "");
			
			String user = Jwts.parser()
					.setSigningKey(SecurityContants.getTokenSecret())
					.parseClaimsJws(token)
					.getBody()
					.getSubject();
			
			if(user != null) {
				return new UsernamePasswordAuthenticationToken(user, null, new ArrayList<>());
			}
			
			return null;
		}
		return null;
	}
	
	
	
}
