package utils;

import auth.service.LoginController;
import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.sql.*;
import java.util.HashMap;
import java.util.Map;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SessionManager {

    private static final Logger logger = LogManager.getLogger(LoginController.class);

    // 🔒 In-memory store for active sessions (used when not relying on DB only)
    private static Map<String, SessionInfo> activeSessions = new HashMap<>();

    // 🧠 Local variables to track current session
    private static String currentUsername;
    private static String currentRole;
    private static String token;

    // ✅ Used to store session information
    public static class SessionInfo {
        private String role;
        private String token;
        private long loginTime;

        public SessionInfo(String role, String token) {
            this.role = role;
            this.token = token;
            this.loginTime = System.currentTimeMillis(); // Time in milliseconds
        }

        public String getRole() {
            return role;
        }

        public String getToken() {
            return token;
        }

        public long getLoginTime() {
            return loginTime;
        }
    }

    // ✅ Set the current session (used after login)
    public static void setSession(String username, String role, String jwtToken) {
        currentUsername = username;
        currentRole = role;
        token = jwtToken;

        // Add to in-memory session tracker
        activeSessions.put(username, new SessionInfo(role, jwtToken));

        System.out.println("✅ [SessionManager] Session created for: " + username);
    }

    // ✅ Getters and Setters for current user data
    public static void setUsername(String username) {
        currentUsername = username;
    }

    public static String getUsername() {
        return currentUsername;
    }

    public static void setRole(String role) {
        currentRole = role;
    }

    public static String getRole() {
        return currentRole;
    }

    public static void setToken(String jwtToken) {
        token = jwtToken;
    }

    public static String getToken() {
        return token;
    }

    // ✅ Clear session variables during logout
    public static void logout() {
        if (currentUsername != null) {
            activeSessions.remove(currentUsername);
            clearSession(currentUsername);
            System.out.println("🔒 [SessionManager] Logged out user: " + currentUsername);
        }
        currentUsername = null;
        currentRole = null;
        token = null;
    }

    // ✅ Save session to database with expiration (20 minutes)
    public static void saveSessionToDatabase(String username, String token, String role) {
        try (Connection conn = DBConnection.getConnection()) {
            String sql = "INSERT INTO active_sessions (username, token, role, expires_at) VALUES (?, ?, ?, ?)";
            PreparedStatement ps = conn.prepareStatement(sql);
            ps.setString(1, username);
            ps.setString(2, token);
            ps.setString(3, role);
            ps.setTimestamp(4, Timestamp.valueOf(java.time.LocalDateTime.now().plusMinutes(20)));

            ps.executeUpdate();
            System.out.println("✅ [Database] Session saved for: " + username);
        } catch (Exception e) {
            System.err.println("❌ [Database] Failed to save session: " + e.getMessage());
            e.printStackTrace();
        }
    }

    // ✅ Save session to CSV file (used for CSV mode fallback)
    public static void saveSessionToCSV(String username, String token, String csvRole) {
        try (BufferedWriter writer = new BufferedWriter(new FileWriter("data/sessions.csv", true))) {
            String line = username + "," + token + "," + csvRole + "," + java.time.LocalDateTime.now();
            writer.write(line);
            writer.newLine();
            System.out.println("✅ [CSV] Saved session: " + line);
        } catch (IOException e) {
            System.out.println("⚠️ [CSV] Failed to save session: " + e.getMessage());
        }
    }

    // ✅ Get stored token for a user (from memory)
    public static String getTokenForUser(String username) {
        if (activeSessions.containsKey(username)) {
            return activeSessions.get(username).getToken();
        }
        return null;
    }

    // ✅ Check if a user has an active session in the database
    public static boolean hasActiveSession(String username) {
        try (Connection conn = DBConnection.getConnection()) {
            String sql = "SELECT * FROM active_sessions WHERE username = ?";
            PreparedStatement ps = conn.prepareStatement(sql);
            ps.setString(1, username);
            ResultSet rs = ps.executeQuery();
            return rs.next(); // true if session found
        } catch (Exception e) {
            System.out.println("⚠️ [Session Check] Error: " + e.getMessage());
            e.printStackTrace();
        }
        return false;
    }

    // ✅ Cleanup expired sessions (expired JWT or idle session)
    public static void cleanupExpiredSessions() {
        try (Connection conn = DBConnection.getConnection()) {
            String sql = "DELETE FROM active_sessions WHERE expires_at < NOW()";
            PreparedStatement ps = conn.prepareStatement(sql);
            int deleted = ps.executeUpdate();

            System.out.println(" [Cleanup] Expired sessions removed: " + deleted);
        } catch (Exception e) {
            System.err.println("❌ [Cleanup] Failed: " + e.getMessage());
        }
    }

    // ✅ Cleanup expired "remember me" tokens
    public static void cleanupExpiredRememberTokens() {
        try (Connection conn = DBConnection.getConnection()) {
            String sql = "DELETE FROM remember_tokens WHERE expires_at < NOW()";
            PreparedStatement ps = conn.prepareStatement(sql);
            int deleted = ps.executeUpdate();

            System.out.println(" [Cleanup] Expired remember tokens removed: " + deleted);
        } catch (Exception e) {
            System.err.println("❌ [Cleanup Remember] Failed: " + e.getMessage());
        }
    }

    // ✅ Clear session from database (used on logout)
    public static void clearSession(String username) {
        try (Connection conn = DBConnection.getConnection()) {
            String sql = "DELETE FROM active_sessions WHERE username = ?";
            PreparedStatement ps = conn.prepareStatement(sql);
            ps.setString(1, username);
            ps.executeUpdate();

            System.out.println("✅ [Logout] Cleared session from DB for: " + username);
        } catch (Exception e) {
            System.err.println("❌ [Logout] Failed to clear session: " + e.getMessage());
        }
    }

    // ✅ Updates user's last active time (used for idle timeout)
    public static void updateLastActive(String username) {
        try (Connection conn = DBConnection.getConnection()) {
            String sql = "UPDATE active_sessions SET last_active = CURRENT_TIMESTAMP WHERE username = ?";
            PreparedStatement ps = conn.prepareStatement(sql);
            ps.setString(1, username);
            ps.executeUpdate();

            System.out.println("⏰ [Activity] Updated last activity for: " + username);
        } catch (Exception e) {
            System.out.println("⚠️ [Activity] Failed to update last active: " + e.getMessage());
        }
    }

    // ✅ Check if the user has been idle for more than 10 minutes
    public static boolean isUserIdle(String username) {
        try (Connection conn = DBConnection.getConnection()) {
            String sql = "SELECT last_active FROM active_sessions WHERE username = ?";
            PreparedStatement ps = conn.prepareStatement(sql);
            ps.setString(1, username);
            ResultSet rs = ps.executeQuery();

            if (rs.next()) {
                Timestamp lastActive = rs.getTimestamp("last_active");
                long idleMillis = System.currentTimeMillis() - lastActive.getTime();

                long tenMinutes = 10 * 60 * 1000;
                if (idleMillis > tenMinutes) {
                    System.out.println("🚫 [Idle] User " + username + " has been idle for more than 10 minutes.");
                    return true;
                }
            }
        } catch (Exception e) {
            System.out.println("⚠️ [Idle Check] Failed: " + e.getMessage());
        }
        return false;
    }
}
