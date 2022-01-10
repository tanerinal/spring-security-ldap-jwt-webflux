package com.tanerinal.springsecurityldapjwtwebflux.configuration;

import com.tanerinal.springsecurityldapjwtwebflux.Constants;
import com.tanerinal.springsecurityldapjwtwebflux.entrypoint.AuthenticationEntryPoint;
import com.tanerinal.springsecurityldapjwtwebflux.filter.JwtRequestFilter;
import com.tanerinal.springsecurityldapjwtwebflux.handler.AccessDeniedHandler;
import com.tanerinal.springsecurityldapjwtwebflux.handler.AuthenticationSuccessHandler;
import com.tanerinal.springsecurityldapjwtwebflux.service.PortalUserService;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.UserDetailsRepositoryReactiveAuthenticationManager;
import org.springframework.security.config.annotation.method.configuration.EnableReactiveMethodSecurity;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.authentication.AuthenticationWebFilter;
import org.springframework.security.web.server.context.NoOpServerSecurityContextRepository;

@Configuration
@EnableWebFluxSecurity
@EnableReactiveMethodSecurity
@RequiredArgsConstructor
public class WebSecurityConfiguration {
    private final AuthenticationSuccessHandler authenticationSuccessHandler;
    private final AuthenticationEntryPoint authenticationEntryPoint;
    private final AccessDeniedHandler accessDeniedHandler;
    private final PortalUserService portalUserService;

    @Value("${autz.permitted.paths.all}")
    private String[] permittedPaths;
    @Value("${autz.permitted.paths.finance}")
    private String[] financeRolePermittedPaths;
    @Value("${autz.permitted.paths.business}")
    private String[] businessRolePermittedPaths;

    @Value("${jwt.secret}")
    private String jwtSecret;

    @Bean
    SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {
        AuthenticationWebFilter authenticationWebFilter = new AuthenticationWebFilter(new UserDetailsRepositoryReactiveAuthenticationManager(portalUserService));
        authenticationWebFilter.setAuthenticationSuccessHandler(authenticationSuccessHandler);

        http
                .cors()
                .and()
                .csrf()
                    .disable()
                .addFilterAt(authenticationWebFilter, SecurityWebFiltersOrder.FIRST)
                .authorizeExchange()
                    .pathMatchers(permittedPaths).permitAll()
                    .pathMatchers(financeRolePermittedPaths).hasAuthority(Constants.LDAP_ROLE_FINANCE)
                    .pathMatchers(businessRolePermittedPaths).hasAuthority(Constants.LDAP_ROLE_BUSINESS)
                    .anyExchange().denyAll()
                .and()
                    .exceptionHandling()
                    .authenticationEntryPoint(this.authenticationEntryPoint)
                    .accessDeniedHandler(this.accessDeniedHandler)
                .and()
                    .securityContextRepository(NoOpServerSecurityContextRepository.getInstance())
                    .logout()
                        .disable()
                    .formLogin()
                        .disable();

        http.addFilterAt(new JwtRequestFilter(jwtSecret, portalUserService, authenticationSuccessHandler), SecurityWebFiltersOrder.FIRST);

        return http.build();
    }
}
