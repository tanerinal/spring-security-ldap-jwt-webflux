package com.tanerinal.springsecurityldapjwtwebflux;

public class Constants {
    private Constants() {
        //Hidden from external initializations.
    }

    public static final String LDAP_ROLE_BUSINESS = "BUSINESS";
    public static final String LDAP_ROLE_FINANCE = "FINANCE";

    public static final String MESSAGE_AUTHENTICATION_FAILED = "Login failed! Wrong username of password.";

    public static final String JWT_CLAIM_USER_ROLES = "grantedAuthorities";

    public static final String HEADER_AUTHORIZATION = "Authorization";
    public static final String HEADER_AUTHORIZATION_PREFIX_BEARER = "Bearer ";
    public static final String HEADER_X_FORWARDED_FOR = "X-FORWARDED-FOR";

    public static final String LDAP_ATTRIBUTE_ISMEMBEROF = "ismemberof";
    public static final String LDAP_ATTRIBUTE_UID = "uid";
}
