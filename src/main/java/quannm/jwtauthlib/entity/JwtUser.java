package quannm.jwtauthlib.entity;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;

import java.time.Instant;
import java.util.List;

@Data
@AllArgsConstructor
@Builder
public class JwtUser {
    private String userId;
    private List<String> roles;
    private String username;
    private String email;
    private String fullName;
    private Instant expiresAt;

}
