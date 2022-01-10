package com.tanerinal.springsecurityldapjwtwebflux.handler;

import com.tanerinal.springsecurityldapjwtwebflux.Constants;
import com.tanerinal.springsecurityldapjwtwebflux.exception.UnauthorizedException;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.server.authorization.ServerAccessDeniedHandler;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.Collections;
import java.util.Optional;

@Configuration
@Slf4j
public class AccessDeniedHandler implements ServerAccessDeniedHandler {

    @Override
    public Mono<Void> handle(ServerWebExchange serverWebExchange, AccessDeniedException e) {
        log.info("Access Denied. Unauthorized access attempt to resource {} from {} with HttpMethod of {} Authorization header: {}",
                serverWebExchange.getRequest().getPath(),
                Optional.ofNullable(serverWebExchange.getRequest().getHeaders().get(Constants.HEADER_X_FORWARDED_FOR))
                        .orElse(Collections.singletonList(serverWebExchange.getRequest().getRemoteAddress().getHostName())),
                StringUtils.defaultString(serverWebExchange.getRequest().getMethod().name(), StringUtils.EMPTY),
                serverWebExchange.getRequest().getHeaders().get(Constants.HEADER_AUTHORIZATION));

        return Mono.error(new UnauthorizedException("You are trying to access to a resource that you're not allowed to."));
    }
}
