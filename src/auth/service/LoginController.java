package auth.service;

import java.sql.*;
import javax.swing.JOptionPane;
import utils.DBConnection;
import utils.EmailUtil;
import utils.JWTUtil;
import utils.SessionManager;
import utils.ConfigManager; 
import utils.CSVUtil;
import java.util.List;
import utils.CSVSessionWriter;
import utils.OTPUtil;

public class LoginController {
    
    // ✅ This method performs login using users.csv file
private static String loginFromCsv(String username, String password, String role) {
    List<String[]> rows = CSVUtil.readCSV("data/users.csv");

    for (int i = 1; i < rows.size(); i++) { // Skip header
        String[] row = rows.get(i);
        if (row.length < 22) continue; // Skip rows with missing data

        String fileUsername = row[0].trim();
        String filePassword = row[1].trim();
        String fileRole = row[20].trim(); // 'Department' column as role

        // Check match
    if (username.equals(fileUsername) && password.equals(filePassword) && role.equalsIgnoreCase(fileRole)) {
    // ✅ 1. Generate JWT token (fake or real, your choice)
    String token = JWTUtil.generateToken(username);

    // ✅ 2. Generate OTP (e.g., 6-digit random)
    String otp = OTPUtil.generateOtpCode(); // Create a new OTP
    String expiry = OTPUtil.getExpiryTime(5); // 5-minute expiry
    int attempts = 0; // Start with 0 attempts

    // ✅ 3. Write token and OTP to users_with_token.csv
    CSVSessionWriter.updateUserSession(username, token, otp, expiry, attempts);

    // ✅ 4. Set session in memory
    SessionManager.setSession(username, role, token);

    // ✅ 5. Send OTP via email (optional kung meron kang email)
    EmailUtil.sendOtpCode(getUserEmailFromCSV(username), otp); // You can create this helper

    System.out.println("✅ Login (CSV) successful. OTP sent.");
    return "success";
}

    // ✅ Generate JWT token
    String token = JWTUtil.generateToken(username);

    // ✅ Generate OTP and its expiry
    String generatedOtp = utils.OTPUtil.generateOtp(); // You should have OTPUtil already
    String expiryTimeStr = java.time.LocalDateTime.now().plusMinutes(5).toString(); // Expires in 5 mins
    int otpAttempts = 0; // Reset attempts

    // ✅ Save session in memory (or wherever your SessionManager stores it)
    SessionManager.setSession(username, role, token);

    // ✅ Save session info into a new CSV (token, OTP, expiry, attempts)
    utils.CSVSessionWriter.updateUserSession(
        username,
        token,
        generatedOtp,
        expiryTimeStr,
        otpAttempts
    );

    System.out.println("✅ Login successful using CSV + Token + OTP");
    return "success";
}
    

    return "invalid"; // Login failed in CSV mode
}
    
    
    // ✅ Check if the user already has an active session (used to block multi-device login)
public static boolean hasActiveSession(String username) {
    try (Connection conn = DBConnection.getConnection()) {
        // SQL query to check if a session already exists for this user
        String sql = "SELECT * FROM active_sessions WHERE username = ?";
        PreparedStatement ps = conn.prepareStatement(sql);
        ps.setString(1, username);
        ResultSet rs = ps.executeQuery();

        // If there's a result, it means the user is already logged in
        return rs.next();
    } catch (Exception e) {
        e.printStackTrace();
        return false; // Assume no active session if there's an error
    }
}

// ✅ Save the current session to the database (token and login time)
public static void saveSession(String username, String token) {
    try (Connection conn = DBConnection.getConnection()) {
        // Insert the new session or update existing one (by username)
        String sql = "INSERT INTO active_sessions (username, token, last_active) VALUES (?, ?, CURRENT_TIMESTAMP) " +
             "ON CONFLICT (username) DO UPDATE SET token = EXCLUDED.token, login_time = CURRENT_TIMESTAMP, last_active = CURRENT_TIMESTAMP";
        PreparedStatement ps = conn.prepareStatement(sql);
        ps.setString(1, username); // Set username
        ps.setString(2, token);    // Set the session token
        ps.executeUpdate();        // Save the session
    } catch (Exception e) {
        e.printStackTrace(); // Print any error
    }
}

// ✅ Remove a session from the database (used when user logs out)
public static void clearSession(String username) {
    try (Connection conn = DBConnection.getConnection()) {
        // SQL to delete the session for the given username
        String sql = "DELETE FROM active_sessions WHERE username = ?";
        PreparedStatement ps = conn.prepareStatement(sql);
        ps.setString(1, username); // Set username
        ps.executeUpdate();        // Execute deletion
    } catch (Exception e) {
        e.printStackTrace(); // Show any error
    }
}

// ✅ This method updates the 'last_active' column for a user to the current time
public static void updateLastActive(String username) {
    try (Connection conn = DBConnection.getConnection()) {
        // SQL query to update the last_active timestamp of the given user
        String sql = "UPDATE active_sessions SET last_active = CURRENT_TIMESTAMP WHERE username = ?";
        
        // Prepare the SQL statement
        PreparedStatement ps = conn.prepareStatement(sql);
        
        // Set the username in the query (where username = ?)
        ps.setString(1, username);
        
        // Execute the update (run the SQL command)
        ps.executeUpdate();
    } catch (Exception e) {
        // If there's any error (e.g., no connection), print the error
        e.printStackTrace();
    }
}


    // This method handles the login logic and returns a String result
    public static String login(String username, String password, String role) {
    // ✅ Step 1: Check if config is set to CSV mode
    if (ConfigManager.isUsingCsv()) {
        return loginFromCsv(username, password, role); // Skip SQL, go CSV
    }
        
        // ✅ Step 2: Clean up expired sessions before doing anything
        SessionManager.cleanupExpiredSessions();
        SessionManager.cleanupExpiredRememberTokens(); // Clean tokens on startup/login
        
        
        try (Connection conn = DBConnection.getConnection()) {
            
            
        // ✅ Step 3: Check if user already has an active session
        if (SessionManager.hasActiveSession(username)) {
            return "active_session"; // 🔒 Tell LoginUI this user is already logged in elsewhere
        }

            // Check if the user exists with the given username and role
            String checkUser = "SELECT * FROM users WHERE username = ? AND role = ?";
            PreparedStatement ps = conn.prepareStatement(checkUser);
            ps.setString(1, username);
            ps.setString(2, role);

            ResultSet rs = ps.executeQuery();

            if (rs.next()) {
                // Get account lock status and time
                boolean isLocked = rs.getBoolean("account_locked");
                int failedAttempts = rs.getInt("failed_attempts");
                Timestamp lockTime = rs.getTimestamp("lock_time");

                // If the account is locked
                if (isLocked) {
                    long lockDuration = System.currentTimeMillis() - lockTime.getTime();

                    // If 24 hours have passed, unlock the account
                    if (lockDuration >= 86400000) {
                        resetLock(conn, username); // reset lock status
                    } else {
                        return "locked"; // account still locked
                    }
                }                          

                // Check if password matches
                String dbPassword = rs.getString("password");
                if (password.equals(dbPassword)) {
                    resetLock(conn, username); // reset attempts if correct

                    // generate a token to secure the session
                    String token = JWTUtil.generateToken(username);
                    
                    System.out.println("✅ Generated JWT token: " + token); // 🖨️ Print to console

                    // store the token in the database so we can use it later
                    String updateTokenSQL = "UPDATE users SET jwt_token = ? WHERE username = ?";
                    PreparedStatement tokenStmt = conn.prepareStatement(updateTokenSQL);
                    tokenStmt.setString(1, token);
                    tokenStmt.setString(2, username);
                    tokenStmt.executeUpdate();

                    // set the session with username, role, and the token
                    SessionManager.setSession(username, role, token);
                    SessionManager.saveSessionToDatabase(username, token, role);

                    return "success"; // login passed
                } else {
                    incrementFailedAttempts(conn, username, failedAttempts); // add to failed count
                    return "invalid"; // wrong password
                }
            } else {
                return "not_found"; // no user found
            }

        } catch (Exception e) {
            e.printStackTrace();
            return "error"; // return error if exception occurs
        }
    }
    
    // Method to check if the database is connected
public static boolean isDatabaseConnected() {
    try (Connection conn = utils.DBConnection.getConnection()) {
        return conn != null;
    } catch (Exception e) {
        return false;
    }
}
    // This method resets the lock state of a user after successful login or 24 hours passed
    private static void resetLock(Connection conn, String username) {
        try {
            // Update the user record to remove lock and reset failed attempts
            String sql = "UPDATE users SET failed_attempts = 0, account_locked = false, lock_time = NULL WHERE username = ?";
            PreparedStatement ps = conn.prepareStatement(sql);
            ps.setString(1, username);
            ps.executeUpdate();
        } catch (SQLException e) {
            // If something goes wrong, show error
            JOptionPane.showMessageDialog(null, "Failed to reset user lock status: " + e.getMessage());
        }
    }

    // This method increases the failed login attempts and locks the account after 3 tries
    private static void incrementFailedAttempts(Connection conn, String username, int current) {
        try {
            current++; // adding 1 to the current failed attempts

            // If user failed 3 times already
            if (current >= 3) {
                // get the current time
                Timestamp now = new Timestamp(System.currentTimeMillis());

                // set lockedUntil to 24 hours from now
                Timestamp lockedUntil = new Timestamp(System.currentTimeMillis() + (24 * 60 * 60 * 1000));

                // lock the account and store lock time and unlock time
                String lockSQL = "UPDATE users SET account_locked = true, lock_time = ?, locked_until = ?, failed_attempts = ? WHERE username = ?";
                PreparedStatement lockStmt = conn.prepareStatement(lockSQL);
                lockStmt.setTimestamp(1, now);
                lockStmt.setTimestamp(2, lockedUntil); // ✅ This is used by the GUI timer
                lockStmt.setInt(3, current);
                lockStmt.setString(4, username);
                lockStmt.executeUpdate();

                // get the user's email so I can notify them
                PreparedStatement emailStmt = conn.prepareStatement("SELECT email FROM users WHERE username = ?");
                emailStmt.setString(1, username);
                ResultSet rs = emailStmt.executeQuery();
                if (rs.next()) {
                    String userEmail = rs.getString("email");
                    EmailUtil.sendLockNotification(userEmail); // I send the lock email here
                }

                // show a message so the user knows what happened
                JOptionPane.showMessageDialog(null, "Your account has been locked due to 3 failed login attempts.\nPlease check your email or contact your admin.");
            } else {
                // If failed attempts are less than 3, I just update the count
                String updateSQL = "UPDATE users SET failed_attempts = ? WHERE username = ?";
                PreparedStatement ps = conn.prepareStatement(updateSQL);
                ps.setInt(1, current);
                ps.setString(2, username);
                ps.executeUpdate();
            }

        } catch (SQLException e) {
            // show an error if something went wrong
            JOptionPane.showMessageDialog(null, "Error updating failed attempts: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private static String getUserEmailFromCSV(String username) {
        throw new UnsupportedOperationException("Not supported yet."); // Generated from nbfs://nbhost/SystemFileSystem/Templates/Classes/Code/GeneratedMethodBody
    }
}
