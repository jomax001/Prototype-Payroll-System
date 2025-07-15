package utils;

import auth.service.LoginController;
import java.sql.*;
import utils.DBConnection;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;


public class RememberTokenUtil {
    
    private static final Logger logger = LogManager.getLogger(LoginController.class); 

    /**
     * Saves a user's remember token in the database.
     * If the username already exists, it updates the token and expiration.
     */
    public static void saveToken(String username, String token, Timestamp expiresAt) {
        try (Connection conn = DBConnection.getConnection()) {
            // SQL: Insert token, or update it if the username already exists
            String sql = "INSERT INTO remember_tokens (username, token, expires_at) " +
                         "VALUES (?, ?, ?) " +
                         "ON CONFLICT (username) DO UPDATE SET token = ?, expires_at = ?";
            PreparedStatement ps = conn.prepareStatement(sql);
            ps.setString(1, username); // Insert: username
            ps.setString(2, token);    // Insert: token
            ps.setTimestamp(3, expiresAt); // Insert: expiration timestamp
            ps.setString(4, token);    // Update: token
            ps.setTimestamp(5, expiresAt); // Update: expiration timestamp
            ps.executeUpdate(); // Execute the insert/update
        } catch (Exception e) {
            e.printStackTrace(); // Print error for debugging
        }
    }

    /**
     * Checks if a token is still valid (not expired).
     * Returns true if valid, false otherwise.
     */
    public static boolean isTokenValid(String token) {
        try (Connection conn = DBConnection.getConnection()) {
            // SQL: Get the expiration time of the token
            String sql = "SELECT expires_at FROM remember_tokens WHERE token = ?";
            PreparedStatement ps = conn.prepareStatement(sql);
            ps.setString(1, token); // Set the token to search for
            ResultSet rs = ps.executeQuery();

            if (rs.next()) {
                Timestamp expires = rs.getTimestamp("expires_at"); // Get expiration
                Timestamp now = new Timestamp(System.currentTimeMillis()); // Current time
                return now.before(expires); // True if not yet expired
            }
        } catch (Exception e) {
            e.printStackTrace(); // Print error for debugging
        }
        return false; // Return false if token not found or expired
    }

    /**
     * Deletes the remember token for the given username.
     * Called when the user logs out.
     */
public static boolean deleteToken(String username) {
    try (Connection conn = DBConnection.getConnection()) {
            // SQL: Delete the token for this username
            String sql = "DELETE FROM remember_tokens WHERE username = ?";
            PreparedStatement ps = conn.prepareStatement(sql);
            ps.setString(1, username); // Set username to delete token
            ps.executeUpdate(); // Run the delete command
        } catch (Exception e) {
            e.printStackTrace(); // Print error for debugging
        }
        return false;
    }
    
    /**
 * This method deletes all expired tokens from the 'remember_tokens' table.
 * It checks which tokens are past their 'expires_at' time and removes them from the database.
 * This helps clean up old sessions and improves security and performance.
 */
public static int cleanupExpiredTokens() {
        int deletedCount = 0; // Start with 0 deleted tokens
        try (
        // Step 1: Connect to the database
        Connection conn = DBConnection.getConnection()
    ) {
        // Step 2: SQL command to delete tokens that have already expired (past the current time)
        String sql = "DELETE FROM remember_tokens WHERE expires_at < NOW()";

        // Step 3: Prepare and execute the SQL command
        PreparedStatement ps = conn.prepareStatement(sql);
        deletedCount = ps.executeUpdate(); // Count how many tokens were deleted

    } catch (Exception e) {
        // Step 4: If something goes wrong, show the error in the console
        e.printStackTrace();
    }
    return deletedCount; // Step 5: Return the number of deleted tokens
}

}
