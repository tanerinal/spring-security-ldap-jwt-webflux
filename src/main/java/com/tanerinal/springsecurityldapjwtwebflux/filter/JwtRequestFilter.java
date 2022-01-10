package com.tanerinal.springsecurityldapjwtwebflux.filter;

import com.tanerinal.springsecurityldapjwtwebflux.exception.UnauthenticatedException;
import com.tanerinal.springsecurityldapjwtwebflux.handler.AuthenticationSuccessHandler;
import com.tanerinal.springsecurityldapjwtwebflux.service.PortalUserService;
import com.tanerinal.springsecurityldapjwtwebflux.util.JwtUtils;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureException;
import io.jsonwebtoken.UnsupportedJwtException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.server.WebFilterExchange;
import org.springframework.security.web.server.context.ServerSecurityContextRepository;
import org.springframework.security.web.server.context.WebSessionServerSecurityContextRepository;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

import java.util.Optional;

@Slf4j
@RequiredArgsConstructor
public class JwtRequestFilter implements WebFilter {
	private final String jwtSecret;
	private final PortalUserService portalUserService;
	private final AuthenticationSuccessHandler authenticationSuccessHandler;

	@Override
	public Mono<Void> filter(ServerWebExchange serverWebExchange, WebFilterChain webFilterChain) {
		Optional<String> token = JwtUtils.getTokenWithoutBearer(serverWebExchange);

		return token.map(s -> verifyAndAuthenticatePortalUser(s)
				.switchIfEmpty(webFilterChain.filter(serverWebExchange).then(Mono.empty()))
				.flatMap(authentication -> onAuthSuccess(authentication, serverWebExchange, webFilterChain))).orElseGet(() -> webFilterChain.filter(serverWebExchange));
	}
	
	private Mono<Authentication> verifyAndAuthenticatePortalUser(String token) {
		try {
			JwtUtils.verifyToken(token, jwtSecret);
			String username = JwtUtils.extractUsername(token, jwtSecret);
			return portalUserService.findByUsername(username)
					.flatMap(principal -> Mono.just(new UsernamePasswordAuthenticationToken(principal, null, principal.getAuthorities())));
		} catch (UsernameNotFoundException | ExpiredJwtException |
				MalformedJwtException | SignatureException | UnsupportedJwtException  | IllegalArgumentException e) {
			log.error("Exception occured while evaluating token: {}", token, e);
			return Mono.error(new UnauthenticatedException("Invalid token. Please authenticate again!", e));
		}
	}

	private Mono<Void> onAuthSuccess(Authentication authentication, ServerWebExchange exchange, WebFilterChain webFilterChain) {
		ServerSecurityContextRepository securityContextRepository = new WebSessionServerSecurityContextRepository();
		WebFilterExchange webFilterExchange = new WebFilterExchange(exchange, webFilterChain);
		SecurityContextImpl securityContext = new SecurityContextImpl();
		securityContext.setAuthentication(authentication);

		return securityContextRepository.save(exchange, securityContext)
				.then(authenticationSuccessHandler.onAuthenticationSuccess(webFilterExchange, authentication))
				.contextWrite(ReactiveSecurityContextHolder.withAuthentication(authentication));
	}
}
