package quannm.jwtauthlib.jwt;

import quannm.jwtauthlib.entity.JwtUser;
import quannm.jwtauthlib.exception.InvalidTokenException;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

import java.security.Key;
import java.util.List;

public class JwtValidator {

    private static Key getSignInKey(String secretKey) {
        byte[] bytes = Decoders.BASE64.decode(secretKey);
        return Keys.hmacShaKeyFor(bytes);
    }

    public static JwtUser validate(String token, String secretKey) {
        try{
            Claims claims = Jwts.parserBuilder()
                    .setSigningKey(getSignInKey(secretKey))
                    .build()
                    .parseClaimsJws(token)
                    .getBody();

            String username = claims.getSubject();
            List<String> roles = claims.get("roles", List.class);
            Integer userId = claims.get("userId", Integer.class);
            String email = claims.get("email", String.class);
            String fullName = claims.get("fullName", String.class);

            return JwtUser.builder()
                    .userId(userId)
                    .roles(roles)
                    .username(username)
                    .email(email)
                    .fullName(fullName)
                    .payload(claims)
                    .build();
        }catch (JwtException e) {
            throw new InvalidTokenException("Invalid JWT token" + e.getMessage());
        }
    }

}
