package com.spring_security.Security.utils;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.GrantedAuthority;

import javax.crypto.SecretKey;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;

public class JwtUtils {
    public static String getAcessToken(String issuer, String userName, List<String> grantedAuthorityList, String jwtSecret) {
        SecretKey secretKey = getSecretKey(jwtSecret);
        String accessToken = Jwts.builder().issuer(issuer)
                .subject("JWT Access Token")
                .claim("username", userName)
                .claim("authorities", grantedAuthorityList.stream().collect(Collectors.joining(",")))
                .issuedAt(new Date())
                .expiration(new Date((new Date()).getTime() + 60 * 60 * 1000))
                .signWith(secretKey).compact();
        return accessToken;
    }

    public static SecretKey getSecretKey(String jwtSecret) {
        SecretKey secretKey = Keys.hmacShaKeyFor(jwtSecret.getBytes());
        return secretKey;
    }
}
