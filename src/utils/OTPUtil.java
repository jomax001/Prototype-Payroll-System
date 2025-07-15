/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package utils;


import auth.service.LoginController;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Timestamp;
import java.util.Random;
import java.util.Arrays;
import java.util.List;
import java.sql.SQLException;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class OTPUtil {
        
    private static final Logger logger = LogManager.getLogger(LoginController.class);

    
    // 🔐 Generate a random 6-digit OTP
    public static String generateOtp() {
        int otp = 100000 + new Random().nextInt(900000); // Generates 100000 to 999999
        return String.valueOf(otp);
    }

    // ⏳ Get current time + 1 minute (for OTP expiration)
    public static Timestamp getOtpExpiryTime() {
        long now = System.currentTimeMillis();
        return new Timestamp(now + 60_000); // 1 minute = 60,000 ms
    }
    
        // ✅ This method chooses CSV or SQL automatically based on config
    public static String getUserEmail(String username) {
        if (ConfigManager.isUsingCsv()) {
            return getUserEmailFromCSV(username);
        } else {
            return getUserEmailFromDatabase(username);
        }
    }

    // ✉️ Fetch user email from the database based on username
    public static String getUserEmailFromDatabase(String username) {
        try (Connection conn = DBConnection.getConnection()) {
            String query = "SELECT email FROM users WHERE username = ?";
            PreparedStatement ps = conn.prepareStatement(query);
            ps.setString(1, username);
            ResultSet rs = ps.executeQuery();
            if (rs.next()) {
                return rs.getString("email");
            }
        } catch (Exception e) {
            logger.error("Exception occurred", e);
        }
        return null; // Return null if email not found or error
    }
    
    // 💾 Save the OTP to database with expiration and reset lock
public static void storeOtp(String username, String otpCode, Timestamp expiresAt) {
    try (Connection conn = DBConnection.getConnection()) {
        String sql = "INSERT INTO otp_requests (username, otp_code, expires_at, attempts, is_verified, created_at) " +
             "VALUES (?, ?, ?, 0, false, CURRENT_TIMESTAMP) " +
             "ON CONFLICT (username) DO UPDATE SET " +
             "otp_code = EXCLUDED.otp_code, " +
             "expires_at = EXCLUDED.expires_at, " +
             "attempts = 0, " +
             "is_verified = false, " +
             "created_at = CURRENT_TIMESTAMP";

        PreparedStatement ps = conn.prepareStatement(sql);

        // INSERT values
        ps.setString(1, username);      // username
        ps.setString(2, otpCode);       // otp_code
        ps.setTimestamp(3, expiresAt);  // expires_at

        ps.executeUpdate();
        
        logger.info("✅ OTP stored for " + username + ": " + otpCode);
        
    } catch (Exception e) {
        logger.error("❌ Error storing OTP: ", e);

    }
}

public static boolean checkIfOtpExists(String username) {
    try (Connection conn = DBConnection.getConnection()) {
        String sql = "SELECT otp_code FROM otp_requests WHERE username = ? AND expires_at > NOW() AND is_verified = false";
        PreparedStatement ps = conn.prepareStatement(sql);
        ps.setString(1, username);
        ResultSet rs = ps.executeQuery();

        if (rs.next()) {
            System.out.println("⚠️ Existing OTP still valid for " + username);
            return true; // Don't regenerate
        }
    } catch (SQLException e) {
        logger.error("Exception occurred", e);

    }
    return false;
}

public static void generateAndSendOtp(String username, String email) {
    if (checkIfOtpExists(username)) return;

    String otp = generateOtp(); // tama na ito, method mo na 'to
    Timestamp expiresAt = Timestamp.valueOf(java.time.LocalDateTime.now().plusMinutes(5));

    try (Connection conn = DBConnection.getConnection()) {
        String sql = "INSERT INTO otp_requests (username, otp_code, expires_at) VALUES (?, ?, ?)";
        PreparedStatement ps = conn.prepareStatement(sql);
        ps.setString(1, username);
        ps.setString(2, otp);
        ps.setTimestamp(3, expiresAt);
        ps.executeUpdate();

        EmailUtil.sendOtpCode(email, otp); // This sends the actual email
        System.out.println("✅ New OTP stored and sent to email.");
    } catch (SQLException e) {
        logger.error("Exception occurred", e);

    }
}


    
    // ✅ Generates a new OTP code
public static String generateOtpCode() {
    return generateOtp(); // Use the existing method you already wrote
}

// ✅ Returns expiration time as a formatted String (in minutes)
public static String getExpiryTime(int minutes) {
    long now = System.currentTimeMillis();  // current time in milliseconds
    long expiryMillis = now + (minutes * 60 * 1000); // convert minutes to ms
    Timestamp expiryTime = new Timestamp(expiryMillis); // convert to SQL Timestamp
    return expiryTime.toString(); // return as string, or change as needed
}
    
// Verify the OTP code entered by the user
    public static boolean verifyOtp(String username, String inputOtp) {
    try (Connection conn = DBConnection.getConnection()) {
        String sql = "SELECT otp_code, expires_at, attempts, locked_until FROM otp_requests WHERE username = ?";
        PreparedStatement ps = conn.prepareStatement(sql);
        ps.setString(1, username);
        ResultSet rs = ps.executeQuery();

        if (rs.next()) {
            String storedOtp = rs.getString("otp_code");
            Timestamp expiresAt = rs.getTimestamp("expires_at");
            int attempts = rs.getInt("attempts");
            Timestamp lockedUntil = rs.getTimestamp("locked_until");

            // 🔒 Step 1: Check if user is locked
            if (lockedUntil != null && System.currentTimeMillis() < lockedUntil.getTime()) {
                System.out.println("🚫 User is locked until: " + lockedUntil);
                return false;
            }

            // ⏳ Step 2: Check if OTP is expired
            if (System.currentTimeMillis() > expiresAt.getTime()) {
                System.out.println("⏰ OTP expired.");
                return false;
            }

            // ✅ Step 3: Correct OTP
            if (storedOtp.equals(inputOtp)) {
                // Optional: Reset attempts and mark as verified
                PreparedStatement success = conn.prepareStatement(
                    "UPDATE otp_requests SET is_verified = true, attempts = 0, locked_until = NULL WHERE username = ?"
                );
                success.setString(1, username);
                success.executeUpdate();
                return true;
            } else {
                // ❌ Step 4: Incorrect OTP - increment attempts
                attempts++;
                if (attempts >= 3) {
                    // Lock user for 24 hours
                    long lockTime = System.currentTimeMillis() + (24 * 60 * 60 * 1000); // 24 hours
                    Timestamp lockUntil = new Timestamp(lockTime);

                    PreparedStatement lock = conn.prepareStatement(
                        "UPDATE otp_requests SET attempts = ?, locked_until = ? WHERE username = ?"
                    );
                    lock.setInt(1, attempts);
                    lock.setTimestamp(2, lockUntil);
                    lock.setString(3, username);
                    lock.executeUpdate();

                    System.out.println("🚫 User locked due to too many failed OTP attempts.");
                } else {
                    // Just update attempts
                    PreparedStatement fail = conn.prepareStatement(
                        "UPDATE otp_requests SET attempts = ? WHERE username = ?"
                    );
                    fail.setInt(1, attempts);
                    fail.setString(2, username);
                    fail.executeUpdate();

                    System.out.println("❌ Incorrect OTP. Attempt #" + attempts);
                }
            }
        }
    } catch (Exception e) {
        logger.error("Exception occurred", e);

    }

    return false;
}


public static void saveOtpToDatabase(String username, String otp, Timestamp expiration, int maxAttempts) {
    try (Connection conn = DBConnection.getConnection()) {
        String sql = "INSERT INTO otp_requests (id, username, otp_code, expires_at, attempts, is_verified, created_at, used_at, locked_until) " +
                     "VALUES (NULL, ?, ?, ?, 0, false, CURRENT_TIMESTAMP, NULL, NULL) " +
                     "ON CONFLICT (username) DO UPDATE SET " +
                     "otp_code = ?, expires_at = ?, attempts = 0, is_verified = false, created_at = CURRENT_TIMESTAMP, used_at = NULL, locked_until = NULL";

        PreparedStatement ps = conn.prepareStatement(sql);

        // INSERT values
        ps.setString(1, username);     // username
        ps.setString(2, otp);          // otp_code
        ps.setTimestamp(3, expiration); // expires_at

        // UPDATE values
        ps.setString(4, otp);          // new otp_code
        ps.setTimestamp(5, expiration); // new expiration

        ps.executeUpdate();
    } catch (Exception e) {
        logger.error("Exception occurred", e);

    }
}
// 💾 Save OTP with defaults 
public static void storeOtpInDatabase(String username, String otp, Timestamp expiresAt) {
    try (Connection conn = DBConnection.getConnection()) {
        String sql = "INSERT INTO otp_requests " +
                     "(id, username, otp_code, expires_at, attempts, is_verified, created_at, used_at, locked_until) " +
                     "VALUES (NULL, ?, ?, ?, 0, false, CURRENT_TIMESTAMP, NULL, NULL)";
        PreparedStatement ps = conn.prepareStatement(sql);
        ps.setString(1, username);     // username
        ps.setString(2, otp);          // otp_code
        ps.setTimestamp(3, expiresAt); // expires_at
        ps.executeUpdate();
    } catch (Exception e) {
        logger.error("Exception occurred", e);

    }
}



/**
 * Retrieves the user's email address from the CSV file based on their username.
 * This is used during login to send the OTP (One-Time Password) to the user's email.
 *
 * @param username The username to search for in the CSV file.
 * @return The user's email address if found and valid, otherwise null.
 */
private static String getUserEmailFromCSV(String username) {
    // Read all rows from the users.csv file
    List<String[]> rows = CSVUtil.readCSV("data/users.csv");

    // Loop through each row in the CSV
    for (String[] row : rows) {
        // Check if the username in the current row matches the input
if (row.length >= 3 && row[0].equalsIgnoreCase(username)) {
    System.out.println("✔ Found user: " + username);

            // Fetch the email from the 24th column (index 23)
            String email = row[2];

            // Print the raw email for debugging
            System.out.println("📧 Email found: " + email);

            // Check if the email is not null and contains '@' to validate format
            if (email != null && email.contains("@")) {
                return email; // ✅ Valid email, return it
            } else {
                System.out.println("❌ Invalid email format found: " + email);
                return null; // ❌ Invalid format, return null
            }
        }
    }

    // Return null if username not found in any row
    return null;
}

    public static boolean hasValidOtp(String username) {
    try (Connection conn = DBConnection.getConnection()) {
        String sql = "SELECT expires_at FROM otp_requests WHERE username = ? AND is_verified = false ORDER BY created_at DESC LIMIT 1";
        PreparedStatement ps = conn.prepareStatement(sql);
        ps.setString(1, username);
        ResultSet rs = ps.executeQuery();
        if (rs.next()) {
            Timestamp expiresAt = rs.getTimestamp("expires_at");
            return expiresAt != null && System.currentTimeMillis() < expiresAt.getTime();
        }
    } catch (Exception e) {
        logger.error("Exception occurred", e);

    }
    return false;
}
}