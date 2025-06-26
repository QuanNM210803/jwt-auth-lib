package com.jwtauthlib.jwt;

import com.jwtauthlib.entity.JwtUser;
import com.jwtauthlib.exception.InvalidTokenException;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Date;
import java.util.List;

@Component
public class JwtValidator {

    private Key getSignInKey(String secretKey) {
        byte[] bytes = Decoders.BASE64.decode(secretKey);
        return Keys.hmacShaKeyFor(bytes);
    }

    public JwtUser validate(String token, String secretKey) {
        try{
            Claims claims = Jwts.parserBuilder()
                    .setSigningKey(getSignInKey(secretKey))
                    .build()
                    .parseClaimsJws(token)
                    .getBody();

            String userId = claims.getSubject();
            List<String> roles = claims.get("roles", List.class);
            String name = claims.get("username", String.class);
            String email = claims.get("email", String.class);
            String fullName = claims.get("fullName", String.class);
            Date exp = claims.getExpiration();

            return JwtUser.builder()
                    .userId(userId)
                    .roles(roles)
                    .username(name)
                    .email(email)
                    .fullName(fullName)
                    .expiresAt(exp.toInstant())
                    .build();
        }catch (JwtException e) {
            throw new InvalidTokenException("Invalid JWT token" + e.getMessage());
        }
    }

}
