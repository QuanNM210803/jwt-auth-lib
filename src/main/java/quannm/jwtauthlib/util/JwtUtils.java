package quannm.jwtauthlib.util;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.util.StringUtils;

public class JwtUtils {
    public static String getToken(HttpServletRequest request) {
        String headerAuth = (request.getHeader("Authorization") == null || request.getHeader("Authorization").isEmpty())
                ? request.getParameter("token") : request.getHeader("Authorization");

        if (!StringUtils.hasText(headerAuth)) {
            return null;
        }

        if (headerAuth.startsWith("Bearer ")) {
            return headerAuth.substring(7);
        }

        return headerAuth;
    }
}
