package com.spring_security.Security.filter;

import com.spring_security.Security.constants.ApplicationConstants;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.core.env.Environment;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

public class JwtValidatorFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String jwtToken = request.getHeader(ApplicationConstants.JWT_HEADER);
        Environment env = getEnvironment();
        if (jwtToken.startsWith("Bearer ") && jwtToken != null && env != null) {
            jwtToken = jwtToken.substring("Bearer ".length());
            try {
                String secret = env.getProperty(ApplicationConstants.JWT_SECRET, ApplicationConstants.JWT_SECRET_DEFAULT_KEY);
                SecretKey secretKey = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
                if (secretKey != null) {
                    Claims claims = Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(jwtToken).getPayload();
                    String userName = String.valueOf(claims.get("username"));
                    String authority = String.valueOf(claims.get("authorities"));
                    List<String> authorityList = Arrays.asList(authority.split(","));
                    List<GrantedAuthority> grantedAuthorityList = authorityList.stream()
                            .map(authorityStr -> new SimpleGrantedAuthority(authorityStr))
                            .collect(Collectors.toList());
                    Authentication authentication = new UsernamePasswordAuthenticationToken(userName, null, grantedAuthorityList);
                    SecurityContextHolder.getContext().setAuthentication(authentication);
                }
            } catch (Exception e) {
                throw new BadCredentialsException("Invalid JWT token");
            }
        }
        filterChain.doFilter(request, response);
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {
        return request.getServletPath().equalsIgnoreCase("/loginUser") || request.getServletPath().equalsIgnoreCase("/user/save")
                || request.getServletPath().equalsIgnoreCase("/getTokens") || request.getServletPath().equalsIgnoreCase("/getTokensUsingBody");
    }
}
