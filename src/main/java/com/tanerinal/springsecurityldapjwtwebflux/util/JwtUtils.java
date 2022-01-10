package com.tanerinal.springsecurityldapjwtwebflux.util;

import com.tanerinal.springsecurityldapjwtwebflux.Constants;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.web.server.ServerWebExchange;

import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;
import java.time.ZonedDateTime;
import java.util.Date;
import java.util.List;
import java.util.Optional;

@Slf4j
public class JwtUtils {
    private static final SignatureAlgorithm HS256 = SignatureAlgorithm.HS256;
    private static final String ALG_NAME = HS256.getJcaName();
    private static final int BEARER_INDEX = Constants.HEADER_AUTHORIZATION_PREFIX_BEARER.length();

    private JwtUtils() {
    }

    public static String createJWTToken(String username, String secret, long expiration, List<String> grantedAuthorities) {
        ZonedDateTime now = ZonedDateTime.now();

        return Jwts.builder()
                .setSubject(username)
                .setIssuedAt(Date.from(now.toInstant()))
                .setExpiration(Date.from(now.plusSeconds(expiration).toInstant()))
                .signWith(HS256, new SecretKeySpec(DatatypeConverter.parseBase64Binary(secret), ALG_NAME))
                .claim(Constants.JWT_CLAIM_USER_ROLES, grantedAuthorities)
                .compact();
    }

    public static Optional<String> getTokenWithoutBearer(ServerWebExchange serverWebExchange) {
        Optional<String> token = Optional.ofNullable(serverWebExchange.getRequest().getHeaders().getFirst(Constants.HEADER_AUTHORIZATION));
        return getTokenWithoutBearer(token);
    }

    public static Optional<String> getTokenWithoutBearer(Optional<String> tokenWithBearerPrefix) {
        return tokenWithBearerPrefix.map(s -> StringUtils.substring(s, BEARER_INDEX));
    }

    public static void verifyToken(String token, String secret) {
        extractAllClaims(token, secret);
    }

    public static String extractUsername(String token, String secret) {
        final Claims claims = extractAllClaims(token, secret);
        return claims.getSubject();
    }

    public static Claims extractAllClaims(String token, String secret) {
        return Jwts
                .parser()
                .setSigningKey(new SecretKeySpec(DatatypeConverter.parseBase64Binary(secret), ALG_NAME))
                .parseClaimsJws(token)
                .getBody();
    }
}
