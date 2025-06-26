package quannm.jwtauthlib.entity;

import io.jsonwebtoken.Claims;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;

import java.util.List;

@Data
@AllArgsConstructor
@Builder
public class JwtUser {
    private Integer userId;
    private List<String> roles;
    private String username;
    private String email;
    private String fullName;
    private Claims payload;
}
