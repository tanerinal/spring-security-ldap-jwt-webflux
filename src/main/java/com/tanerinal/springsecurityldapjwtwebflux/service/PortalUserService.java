package com.tanerinal.springsecurityldapjwtwebflux.service;

import com.tanerinal.springsecurityldapjwtwebflux.Constants;
import com.tanerinal.springsecurityldapjwtwebflux.exception.UnauthenticatedException;
import com.tanerinal.springsecurityldapjwtwebflux.model.PortalUser;
import com.tanerinal.springsecurityldapjwtwebflux.model.dto.AuthResponse;
import com.tanerinal.springsecurityldapjwtwebflux.principal.PortalUserPrincipal;
import com.tanerinal.springsecurityldapjwtwebflux.util.JwtUtils;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.dao.IncorrectResultSizeDataAccessException;
import org.springframework.ldap.core.DirContextOperations;
import org.springframework.ldap.core.support.BaseLdapPathContextSource;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.ReactiveUserDetailsService;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.LdapShaPasswordEncoder;
import org.springframework.security.ldap.DefaultSpringSecurityContextSource;
import org.springframework.security.ldap.SpringSecurityLdapTemplate;
import org.springframework.security.ldap.authentication.PasswordComparisonAuthenticator;
import org.springframework.stereotype.Service;
import org.springframework.util.Assert;
import reactor.core.publisher.Mono;

import javax.annotation.PostConstruct;
import javax.naming.directory.SearchControls;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

@Service
@Slf4j
@RequiredArgsConstructor
public class PortalUserService implements ReactiveUserDetailsService {
    private static final String LDAP_ATTRIBUTE_USERPASSWORD = "userpassword";

    @Value("${jwt.secret}")
    private String jwtSecret;
    @Value("${jwt.timeout:18000}")
    private long jwtTimeout;

    @Value("${ldap.url}")
    private String ldapUrl;
    @Value("${ldap.port}")
    private String ldapPort;
    @Value("${ldap.directory.root}")
    private String ldapRoot;
    @Value("${ldap.managerDN}")
    private String ldapManagerDn;
    @Value("${ldap.managerPassword}")
    private String ldapManagerPassword;
    @Value("${ldap.user.base}")
    private String ldapUserSearchBase;
    @Value("${ldap.user.filter}")
    private String ldapUserSearchFilter;
    @Value("${ldap.group.base}")
    private String groupBase;

    private BaseLdapPathContextSource contextSource;

    @PostConstruct
    private void prepareLdapContext() {
        String ldapFullUrl = new StringBuilder(this.ldapUrl)
                .append(":")
                .append(this.ldapPort)
                .append("/")
                .append(this.ldapRoot)
                .toString();
        DefaultSpringSecurityContextSource localContextSource = new DefaultSpringSecurityContextSource(ldapFullUrl);
        localContextSource.setUserDn(this.ldapManagerDn);
        localContextSource.setPassword(this.ldapManagerPassword);
        localContextSource.afterPropertiesSet();
        this.contextSource = localContextSource;
    }

    @Override
    public Mono<UserDetails> findByUsername(String username) {
        try {
            log.info("Searching LDAP for user {}", username);
            SearchControls searchControls = new SearchControls();
            searchControls.setReturningAttributes(new String[]{Constants.LDAP_ATTRIBUTE_ISMEMBEROF, Constants.LDAP_ATTRIBUTE_UID});
            SpringSecurityLdapTemplate template = new SpringSecurityLdapTemplate(this.contextSource);
            template.setSearchControls(searchControls);

            DirContextOperations searchResult = template.searchForSingleEntry(this.ldapUserSearchBase, this.ldapUserSearchFilter, new String[]{username});

            List<String> grantedAuthorities = new ArrayList<>(this.getGrantedAuthorities(searchResult));
            log.info("User {} retrieved. User's roles are: {}", username, grantedAuthorities);

            return Mono.just(new PortalUserPrincipal(PortalUser.builder()
                    .username(username)
                    .grantedAuthorities(grantedAuthorities)
                    .build()));
        } catch (IncorrectResultSizeDataAccessException ex) {
            log.error("Unexpected result size returned from LDAP for search for user {}", username);

            if (ex.getActualSize() == 0) {
                throw new UsernameNotFoundException("User " + username + " not found in LDAP.");
            } else {
                throw ex;
            }
        }
    }

    public AuthResponse authenticateUser(String username, String password) {
        Assert.isTrue(StringUtils.isNotBlank(username), "Username should not left blank!");
        Assert.isTrue(StringUtils.isNotBlank(password), "Password should not left blank!");

        List<String> grantedAuthorities = this.doLdapSearch(username, password);
        log.info("Authentication of {} successfull! Users groups are: {}", username, grantedAuthorities);

        PortalUserPrincipal portalUserPrincipal = new PortalUserPrincipal(PortalUser.builder()
                .username(username)
                .grantedAuthorities(grantedAuthorities)
                .build());
        Authentication authentication = new UsernamePasswordAuthenticationToken(portalUserPrincipal, null, portalUserPrincipal.getAuthorities());
        SecurityContextHolder.getContext().setAuthentication(authentication);

        List<String> userRoles = portalUserPrincipal.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toList());

        String jwtToken = JwtUtils.createJWTToken(username, this.jwtSecret, this.jwtTimeout, userRoles);

        return AuthResponse.builder()
                .username(username)
                .userRoles(userRoles)
                .token(jwtToken)
                .build();
    }

    private List<String> doLdapSearch (String username, String password) {
        try {
            PortalUserPrincipal portalUserPrincipal = new PortalUserPrincipal(PortalUser.builder().username(username).build());
            Authentication authentication = new UsernamePasswordAuthenticationToken(portalUserPrincipal, password);
            PasswordComparisonAuthenticator passwordComparisonAuthenticator = new PasswordComparisonAuthenticator(this.contextSource);
            passwordComparisonAuthenticator.setPasswordEncoder(new LdapShaPasswordEncoder());
            passwordComparisonAuthenticator.setUserDnPatterns(new String[]{this.ldapUserSearchFilter + "," + ldapUserSearchBase});
            passwordComparisonAuthenticator.setUserAttributes(new String[]{Constants.LDAP_ATTRIBUTE_ISMEMBEROF, LDAP_ATTRIBUTE_USERPASSWORD});

            DirContextOperations authenticationResult = passwordComparisonAuthenticator.authenticate(authentication);

            return this.getGrantedAuthorities(authenticationResult);
        } catch (BadCredentialsException |  UsernameNotFoundException e) {
            log.error("LDAP authentication failed for {}. {}", username, e.getMessage());
            throw new UnauthenticatedException(Constants.MESSAGE_AUTHENTICATION_FAILED, e);
        }
    }

    private List<String> getGrantedAuthorities(DirContextOperations ldapResult) {
        if (ArrayUtils.isEmpty(ldapResult.getStringAttributes(Constants.LDAP_ATTRIBUTE_ISMEMBEROF))) {
            log.info("No roles found for user: {}. Returning empty granted authorities list.", ldapResult.getStringAttribute(Constants.LDAP_ATTRIBUTE_UID));
            return  new ArrayList<>();
        }

        return Arrays.asList(ldapResult.getStringAttributes(Constants.LDAP_ATTRIBUTE_ISMEMBEROF)).stream()
                .filter(groupDn -> StringUtils.endsWith(groupDn, this.groupBase))
                .map(groupDn -> StringUtils.substringBetween(StringUtils.upperCase(groupDn), "CN=", ","))
                .collect(Collectors.toList());
    }
}