package utils;

import auth.service.LoginController;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.security.Keys;
import java.security.Key;
import java.util.Date;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class JWTUtil {

    // ✅ This will log messages to the console using Log4j
    private static final Logger logger = LogManager.getLogger(LoginController.class);

    // This is a secret code that we use like a password.
    // It helps protect the user's login token and make sure it can't be faked.
    // It must be exactly 32 characters long and should never change.
    private static final String SECRET_KEY = "12345678901234567890123456789012";

    // This line turns the secret code into a special format that the system needs
    // to create and check secure login tokens.
    // If someone tries to change the token, the system will know because this key won’t match.
    private static final Key key = Keys.hmacShaKeyFor(SECRET_KEY.getBytes());


    // ✅ Token expiration set to 30 minutes (in milliseconds)
    private static final long EXPIRATION_TIME = 1000 * 60 * 30; // 30 minutes

    /**
     * ✅ This method creates a new JWT token with the given username.
     * The token is valid for 30 minutes.
     * @param username The user's username
     * @return JWT token as a string
     */
    public static String generateToken(String username) {
        try {
            // Build the token with subject (username) and expiration date
            String token = Jwts.builder()
                    .setSubject(username) // Subject is the username
                    .setExpiration(new Date(System.currentTimeMillis() + EXPIRATION_TIME)) // Set expiry
                    .signWith(key) // Sign the token with secret key
                    .compact(); // Finalize and return

            // ✅ Debug: show generated token
            System.out.println("✅ JWT token successfully generated for: " + username);
            System.out.println("🔐 Token: " + token);

            return token;
        } catch (Exception e) {
            System.out.println("❌ Failed to generate JWT token: " + e.getMessage());
            return null;
        }
    }

    /**
     * ✅ Validates a JWT token (checks if it is not expired and is correctly signed).
     * @param token The JWT token to check
     * @return true if token is valid, false if expired or invalid
     */
    public static boolean validateToken(String token) {
        try {
            // Parse and verify the token
            Jwts.parserBuilder()
                .setSigningKey(key) // Use the correct signing key
                .build()
                .parseClaimsJws(token); // Parse the token

            // ✅ Debug: token is valid
            System.out.println("✅ Token is valid.");
            return true;

        } catch (JwtException e) {
            // Token is expired, malformed, or tampered
            System.out.println("❌ Invalid or expired JWT token: " + e.getMessage());
            return false;
        } catch (Exception e) {
            System.out.println("❌ Unexpected error while validating token: " + e.getMessage());
            return false;
        }
    }

    /**
     * ✅ Extracts the username (subject) from a valid token.
     * @param token The JWT token
     * @return Username inside the token, or null if error
     */
    public static String getUsername(String token) {
        try {
            // Extract the username (subject) from the token
            String username = Jwts.parserBuilder()
                    .setSigningKey(key)
                    .build()
                    .parseClaimsJws(token)
                    .getBody()
                    .getSubject(); // Get "sub" field (username)

            // ✅ Debug: print extracted username
            System.out.println("👤 Extracted username from token: " + username);
            return username;

        } catch (Exception e) {
            System.out.println("⚠️ Failed to extract username: " + e.getMessage());
            return null;
        }
    }

    /**
     * ✅ Alternate method to extract username from token with detailed error check.
     * You can use this if you want more structured parsing.
     * @param token JWT token
     * @return Username (subject), or null if invalid
     */
    public static String getUsernameFromToken(String token) {
        try {
            Claims claims = Jwts.parserBuilder()
                    .setSigningKey(key)
                    .build()
                    .parseClaimsJws(token)
                    .getBody();

            String username = claims.getSubject(); // Extract subject
            System.out.println("👤 getUsernameFromToken() = " + username);
            return username;

        } catch (Exception e) {
            System.out.println("⚠️ getUsernameFromToken failed: " + e.getMessage());
            return null;
        }
    }
}
