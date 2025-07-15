package auth.service;

import java.io.BufferedReader;
import java.io.FileReader;
import java.sql.*;
import java.time.Instant;
import java.util.List;
import javax.swing.JOptionPane;

import utils.*;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.FileWriter;
import java.io.IOException;


public class LoginController {

    private static final Logger logger = LogManager.getLogger(LoginController.class);

    // ✅ Login using CSV user file
    public static String loginFromCSV(String username, String password, String selectedRole) {
        if (LoginUI.isRememberMeCheckedStatic()) {
        List<String[]> rows = CSVUtil.readCSV("data/users.csv");

        for (int i = 1; i < rows.size(); i++) {
            String[] row = rows.get(i);
            if (row.length < 22) continue;

            String csvUsername = row[0].trim();
            String csvPassword = row[1].trim();
            String email = row[2].trim();
            String csvRole = row[3].trim();

            if (username.equals(csvUsername) && password.equals(csvPassword)) {
                if (!selectedRole.equalsIgnoreCase(csvRole)) {
                    System.out.println("❌ Role mismatch.");
                    return "wrong_role";
                }
            }

                // ✅ Check if token already exists and is valid
                String existingToken = SessionManager.getTokenForUser(username);
                if (existingToken != null && JWTUtil.validateToken(existingToken)
                        && JWTUtil.getUsername(existingToken).equals(username)) {

                    System.out.println("✅ Reusing valid token from CSV for: " + username);
                    SessionManager.setSession(username, csvRole, existingToken);
                    return csvRole;
                }

                // ✅ Generate new token if none or expired
                String token = JWTUtil.generateToken(username);
                SessionManager.setSession(username, csvRole, token);
                SessionManager.saveSessionToCSV(username, token, csvRole);
                
                // ✅ Save the token to remember_token.dat if Remember Me is selected
                if (LoginUI.isRememberMeCheckedStatic()) {
                    try (FileWriter fw = new FileWriter("remember_token.dat")) {
                fw.write(token);
                    System.out.println("✅ Token saved to remember_token.dat");
                } catch (IOException e) {
                    System.out.println("❌ Failed to save token file: " + e.getMessage());
                    }
                }

                
                

                // ✅ Generate and store OTP
                String otp = OTPUtil.generateOtpCode();
                Timestamp expiresAt = Timestamp.valueOf(java.time.LocalDateTime.now().plusMinutes(5));
                OTPUtil.storeOtp(username, otp, expiresAt);
                CSVSessionWriter.updateUserSession(username, token, otp, expiresAt.toString(), 0);
                EmailUtil.sendOtpCode(email, otp);

                System.out.println("📧 OTP sent to " + email);
                return csvRole;
            }
        }

        System.out.println("❌ Invalid credentials in CSV.");
        return "invalid";
    }
    

    // ✅ Login using database
    public static String login(String username, String password, String role) {
        if (ConfigManager.isUsingCsv()) {
            return loginFromCSV(username, password, role);
        }

        SessionManager.cleanupExpiredSessions();
        SessionManager.cleanupExpiredRememberTokens();

        try (Connection conn = DBConnection.getConnection()) {

            if (SessionManager.hasActiveSession(username)) {
                System.out.println("⚠️ User already has active session.");
                return "active_session";
            }

            String query = "SELECT * FROM users WHERE username = ? AND role = ?";
            PreparedStatement ps = conn.prepareStatement(query);
            ps.setString(1, username);
            ps.setString(2, role);
            ResultSet rs = ps.executeQuery();

            if (rs.next()) {
                boolean isLocked = rs.getBoolean("account_locked");
                int failedAttempts = rs.getInt("failed_attempts");
                Timestamp lockTime = rs.getTimestamp("lock_time");

                if (isLocked && System.currentTimeMillis() - lockTime.getTime() < 86400000) {
                    System.out.println("🚫 Account is locked for 24 hours.");
                    return "locked";
                } else if (isLocked) {
                    resetLock(conn, username);
                }

                String dbPassword = rs.getString("password");
                if (password.equals(dbPassword)) {
                    resetLock(conn, username);

                    // ✅ Check for existing valid token in DB
                    String savedToken = rs.getString("jwt_token");
                    if (savedToken != null && JWTUtil.validateToken(savedToken)
                            && JWTUtil.getUsername(savedToken).equals(username)) {

                        System.out.println("✅ Reusing valid DB token for " + username);
                        SessionManager.setSession(username, role, savedToken);
                        SessionManager.saveSessionToDatabase(username, savedToken, role);
                        return role;
                    }

                    // ❌ Token is missing or expired — create new one
                    String token = JWTUtil.generateToken(username);
                    PreparedStatement tokenStmt = conn.prepareStatement("UPDATE users SET jwt_token = ? WHERE username = ?");
                    tokenStmt.setString(1, token);
                    tokenStmt.setString(2, username);
                    tokenStmt.executeUpdate();

                    SessionManager.setSession(username, role, token);
                    SessionManager.saveSessionToDatabase(username, token, role);
                    
                    // ✅ Save the token to remember_token.dat if Remember Me is selected
                    if (LoginUI.isRememberMeCheckedStatic()) {
                        try (FileWriter fw = new FileWriter("remember_token.dat")) {
                    fw.write(token);
                        System.out.println("✅ Token saved to remember_token.dat");
                    } catch (IOException e) {
                        System.out.println("❌ Failed to save token file: " + e.getMessage());
                        }
                    }


                    String email = OTPUtil.getUserEmail(username);

                    // ✅ Generate new OTP only if needed
                    if (!OTPUtil.hasValidOtp(username)) {
                        String otp = OTPUtil.generateOtpCode();
                        Timestamp expiresAt = Timestamp.from(Instant.now().plusSeconds(300));
                        OTPUtil.storeOtp(username, otp, expiresAt);
                        EmailUtil.sendOtpCode(email, otp);
                        System.out.println("📧 OTP sent to: " + email);
                    } else {
                        System.out.println("✅ OTP still valid. Skipping re-send.");
                    }

                    return role;
                } else {
                    incrementFailedAttempts(conn, username, failedAttempts);
                    System.out.println("❌ Incorrect password.");
                    return "invalid";
                }
            } else {
                System.out.println("❌ User not found in database.");
                return "not_found";
            }

        } catch (Exception e) {
            logger.error("Exception during login:", e);
            return "error";
        }
    }

    // ✅ Reset lock after successful login
    private static void resetLock(Connection conn, String username) {
        try {
            PreparedStatement ps = conn.prepareStatement(
                    "UPDATE users SET failed_attempts = 0, account_locked = false, lock_time = NULL WHERE username = ?");
            ps.setString(1, username);
            ps.executeUpdate();
            System.out.println("🔓 Lock reset for user: " + username);
        } catch (SQLException e) {
            JOptionPane.showMessageDialog(null, "Failed to reset lock: " + e.getMessage());
        }
    }

    // ✅ Increase failed attempt counter and lock after 3 tries
    private static void incrementFailedAttempts(Connection conn, String username, int current) {
        try {
            current++;
            if (current >= 3) {
                Timestamp now = new Timestamp(System.currentTimeMillis());
                Timestamp lockedUntil = new Timestamp(now.getTime() + (24 * 60 * 60 * 1000));

                PreparedStatement ps = conn.prepareStatement(
                        "UPDATE users SET account_locked = true, lock_time = ?, locked_until = ?, failed_attempts = ? WHERE username = ?");
                ps.setTimestamp(1, now);
                ps.setTimestamp(2, lockedUntil);
                ps.setInt(3, current);
                ps.setString(4, username);
                ps.executeUpdate();

                PreparedStatement emailStmt = conn.prepareStatement("SELECT email FROM users WHERE username = ?");
                emailStmt.setString(1, username);
                ResultSet rs = emailStmt.executeQuery();
                if (rs.next()) {
                    String email = rs.getString("email");
                    EmailUtil.sendLockNotification(email);
                    System.out.println("📧 Lock email sent to: " + email);
                }

                JOptionPane.showMessageDialog(null, "Your account is locked due to 3 failed attempts. Please check your email.");
            } else {
                PreparedStatement ps = conn.prepareStatement("UPDATE users SET failed_attempts = ? WHERE username = ?");
                ps.setInt(1, current);
                ps.setString(2, username);
                ps.executeUpdate();
                System.out.println("⚠️ Failed attempt " + current + " for user: " + username);
            }
        } catch (SQLException e) {
            JOptionPane.showMessageDialog(null, "Error updating failed attempts: " + e.getMessage());
        }
    }

    /**
 * ✅ Checks if the system is able to connect to the database.
 * Used to test if the DB is online and accessible.
 *
 * @return true if connected, false if there's an error.
 */
public static boolean isDatabaseConnected() {
    try (Connection conn = DBConnection.getConnection()) {
        if (conn != null) {
            System.out.println("✅ [Database] Connection is successful.");
            return true;
        }
    } catch (Exception e) {
        System.out.println("❌ [Database] Failed to connect: " + e.getMessage());
        e.printStackTrace(); // Print full error for debugging
    }
    return false;
}


    /**
 * ✅ Saves the current session (JWT token) to the database.
 * This is used to track who is currently logged in.
 *
 * @param username the user logging in
 * @param token the generated JWT token for that user
 */
public static void saveSession(String username, String token) {
    try (Connection conn = DBConnection.getConnection()) {
        // SQL: Insert new session or update if user already exists
        String sql = "INSERT INTO active_sessions (username, token, login_time, last_active) " +
                     "VALUES (?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP) " +
                     "ON CONFLICT (username) DO UPDATE SET token = EXCLUDED.token, login_time = CURRENT_TIMESTAMP, last_active = CURRENT_TIMESTAMP";

        PreparedStatement ps = conn.prepareStatement(sql);
        ps.setString(1, username); // Set username
        ps.setString(2, token);    // Set token
        ps.executeUpdate();        // Execute update or insert

        System.out.println("✅ [Session] Saved session for user: " + username);
    } catch (Exception e) {
        System.out.println("❌ [Session] Failed to save session for " + username + ": " + e.getMessage());
        e.printStackTrace(); // Shows the full error stack
    }
}


    /**
 * ✅ Clears the user's session from the database.
 * Called when a user logs out or is forcefully logged out.
 *
 * @param username the user whose session should be removed
 */
public static void clearSession(String username) {
    try (Connection conn = DBConnection.getConnection()) {
        // SQL: Delete the session of the specified user
        String sql = "DELETE FROM active_sessions WHERE username = ?";
        PreparedStatement ps = conn.prepareStatement(sql);
        ps.setString(1, username); // Set username
        ps.executeUpdate();        // Execute deletion

        System.out.println("✅ [Session] Cleared session for user: " + username);
    } catch (Exception e) {
        System.out.println("❌ [Session] Failed to clear session for " + username + ": " + e.getMessage());
        e.printStackTrace(); // Print full stack trace for debugging
    }
}
}
