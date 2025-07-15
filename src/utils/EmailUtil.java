package utils;

import javax.mail.*;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeMessage;
import java.sql.*;
import java.util.Properties;

// Import Apache Commons CSV
import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVParser;
import org.apache.commons.csv.CSVRecord;

// Import standard Java IO
import java.io.FileReader;
import java.io.Reader;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class EmailUtil {
    private static final Logger logger = LogManager.getLogger(EmailUtil.class);

    /**
     * ✅ Sends an account lock email to the user.
     * This is triggered after multiple failed login attempts.
     */
    public static void sendLockNotification(String toEmail) {
        String fromEmail = null;
        String password = null;

        // Step 1: Load sender email and password from database config
        try (Connection conn = DBConnection.getConnection()) {
            String sql = "SELECT sender_email, app_password FROM email_config LIMIT 1";
            PreparedStatement stmt = conn.prepareStatement(sql);
            ResultSet rs = stmt.executeQuery();

            if (rs.next()) {
                fromEmail = rs.getString("sender_email");
                password = rs.getString("app_password");
            } else {
                System.err.println("❌ No email config found.");
                logEmail(toEmail, "Account Locked - FinMark", "FAILED", "No config");
                return;
            }
        } catch (SQLException e) {
            System.err.println("❌ Error loading email config: " + e.getMessage());
            logger.error("Exception occurred", e);
            logEmail(toEmail, "Account Locked - FinMark", "FAILED", e.getMessage());
            return;
        }

        // Step 2: Setup email properties for Gmail
        final String finalEmail = fromEmail;
        final String finalPass = password;

        Properties props = new Properties();
        props.put("mail.smtp.host", "smtp.gmail.com");
        props.put("mail.smtp.port", "587");
        props.put("mail.smtp.auth", "true");
        props.put("mail.smtp.starttls.enable", "true");
        props.put("mail.smtp.ssl.trust", "smtp.gmail.com");

        // Step 3: Create session and send email
        Session session = Session.getInstance(props, new Authenticator() {
            protected PasswordAuthentication getPasswordAuthentication() {
                return new PasswordAuthentication(finalEmail, finalPass);
            }
        });

        try {
            Message message = new MimeMessage(session);
            message.setFrom(new InternetAddress(finalEmail));
            message.setRecipients(Message.RecipientType.TO, InternetAddress.parse(toEmail));
            message.setSubject("Account Locked - FinMark Payroll System");
            message.setText("Your account is locked for 24 hours due to multiple failed login attempts.\n\n"
                    + "If this was not you, please contact your administrator.");

            Transport.send(message);
            logger.info("✅ Lock email sent to: {}", toEmail);
            logEmail(toEmail, "Account Locked - FinMark", "SENT", null);

        } catch (MessagingException e) {
            System.err.println("❌ Failed to send lock email: " + e.getMessage());
            logger.error("Exception occurred", e);
            logEmail(toEmail, "Account Locked - FinMark", "FAILED", e.getMessage());
        }
    }
    
    

    /**
     * ✅ Sends a One-Time Password (OTP) to user's email during login.
     */
    public static void sendOtpCode(String toEmail, String otpCode) {
        String fromEmail = null;
        String password = null;

           // ✅ Extract username from email
         String username = toEmail.split("@")[0]; 

        // ✅ Step 0: Check if an OTP already exists and is still valid
        try (Connection conn = DBConnection.getConnection()) {
        String checkSql = "SELECT otp_code, expires_at FROM otp_requests WHERE username = ? AND expires_at > NOW()";
        PreparedStatement checkStmt = conn.prepareStatement(checkSql);
        checkStmt.setString(1, username);
        ResultSet rs = checkStmt.executeQuery();
        
                if (rs.next()) {
            logger.warn("⚠️ OTP already exists and is still valid. Skipping regeneration.");
            return; // ✅ Skip sending duplicate
        }
    } catch (SQLException e) {
        System.err.println("❌ Error checking existing OTP: " + e.getMessage());
        logger.error("Exception occurred", e);
        return;
    }
        // ✅ Step 1: Load sender credentials from database
        try (Connection conn = DBConnection.getConnection()) {
            String sql = "SELECT sender_email, app_password FROM email_config LIMIT 1";
            PreparedStatement stmt = conn.prepareStatement(sql);
            ResultSet rs = stmt.executeQuery();

            if (rs.next()) {
                fromEmail = rs.getString("sender_email");
                password = rs.getString("app_password");
            } else {
                logger.error("❌ No email config found.");
                logEmail(toEmail, "Your OTP Code - FinMark", "FAILED", "No config");
                return;
            }
        } catch (SQLException e) {
            logger.error("❌ Error loading email config", e);
            logEmail(toEmail, "Your OTP Code - FinMark", "FAILED", e.getMessage());
            return;
        }

        // Step 2: Set email properties
        final String finalEmail = fromEmail;
        final String finalPass = password;

        Properties props = new Properties();
        props.put("mail.smtp.host", "smtp.gmail.com");
        props.put("mail.smtp.port", "587");
        props.put("mail.smtp.auth", "true");
        props.put("mail.smtp.starttls.enable", "true");
        props.put("mail.smtp.ssl.trust", "smtp.gmail.com");

        // Step 3: Send OTP email
        Session session = Session.getInstance(props, new Authenticator() {
            protected PasswordAuthentication getPasswordAuthentication() {
                return new PasswordAuthentication(finalEmail, finalPass);
            }
        });

        try {
            Message message = new MimeMessage(session);
            message.setFrom(new InternetAddress(finalEmail));
            message.setRecipients(Message.RecipientType.TO, InternetAddress.parse(toEmail));
            message.setSubject("Your OTP Code - FinMark Payroll System");
            message.setText("Your OTP code is: " + otpCode + "\n\nValid for 5 minutes. Do not share it.");

            Transport.send(message);
            logger.info("📧 OTP email sent to: {}", toEmail);
            logEmail(toEmail, "Your OTP Code - FinMark", "SENT", null);

        } catch (MessagingException e) {
            System.err.println("❌ Failed to send OTP email: " + e.getMessage());
            logger.error("Exception occurred", e);
            logEmail(toEmail, "Your OTP Code - FinMark", "FAILED", e.getMessage());
        }
    }

    /**
     * ✅ Logs email results (success or failure) into the email_logs table.
     */
    public static void logEmail(String recipient, String subject, String status, String errorMessage) {
        try (Connection conn = DBConnection.getConnection()) {
            String sql = "INSERT INTO email_logs (recipient, subject, status, error_message, sent_at) " +
                    "VALUES (?, ?, ?, ?, NOW())";
            PreparedStatement ps = conn.prepareStatement(sql);
            ps.setString(1, recipient);
            ps.setString(2, subject);
            ps.setString(3, status);
            ps.setString(4, errorMessage);
            ps.executeUpdate();
        } catch (SQLException e) {
            System.err.println("❌ Failed to log email: " + e.getMessage());
            logger.error("Exception occurred", e);
        }
    }

    /**
     * ✅ Reads user's email address from CSV file based on username.
     * @param username the user's username
     * @return email if found, null otherwise
     */
    public static String getUserEmailFromCSV(String username) {
    try {
        // Load the users.csv file
        Reader reader = new FileReader("data/users.csv");

        // Use latest CSVFormat with builder — fully supported
CSVFormat format = CSVFormat.Builder.create()
    .setHeader() // Let Apache automatically use header from CSV file
    .setSkipHeaderRecord(true) // Don't return the header row as a record
    .build();

        // ✅ Parse CSV using static method (avoids deprecated constructor)
        try (CSVParser parser = CSVParser.parse(reader, format)) {
            for (CSVRecord record : parser) {
                String user = record.get("Username");
                if (user.equalsIgnoreCase(username)) {
                    String email = record.get("Email").trim();
                    if (email.contains("@")) {
                        logger.info("📧 Found email: {}", email);
                        return email;
                    } else {
                        logger.error("❌ Invalid email format: {}", email);
                        return null;
                    }
                }
            }
        }
    } catch (Exception e) {
        System.out.println("❌ Error reading CSV: " + e.getMessage());
    }
    return null; // Not found
}


    /**
     * ✅ Gets a configuration value (like email or password) from the database.
     * @param key the config key to search
     * @return value from DB, or null if not found
     */
    public static String getConfigValue(String key) {
        String value = null;
        try (Connection conn = DBConnection.getConnection()) {
            String sql = "SELECT config_value FROM email_config WHERE config_key = ?";
            PreparedStatement ps = conn.prepareStatement(sql);
            ps.setString(1, key);
            ResultSet rs = ps.executeQuery();
            if (rs.next()) {
                value = rs.getString("config_value");
            }
        } catch (Exception e) {
            logger.error("Exception occurred", e);
        }
        return value;
    }

    /**
     * ✅ Sends a security alert email to the admin when unusual login activity is detected.
     */
    public static void sendAlert(String recipient, String messageBody) {
        String subject = "⚠️ Security Alert: Suspicious Login Activity Detected";

        try {
            String senderEmail = getConfigValue("email");
            String senderPassword = getConfigValue("password");

            Properties props = new Properties();
            props.put("mail.smtp.auth", "true");
            props.put("mail.smtp.starttls.enable", "true");
            props.put("mail.smtp.host", "smtp.gmail.com");
            props.put("mail.smtp.port", "587");

            Session session = Session.getInstance(props, new Authenticator() {
                protected PasswordAuthentication getPasswordAuthentication() {
                    return new PasswordAuthentication(senderEmail, senderPassword);
                }
            });

            Message message = new MimeMessage(session);
            message.setFrom(new InternetAddress(senderEmail));
            message.setRecipients(Message.RecipientType.TO, InternetAddress.parse(recipient));
            message.setSubject(subject);
            message.setText(messageBody);

            Transport.send(message);
            logger.info("✅ Security alert email sent to admin.");
            
            // ✅ Log success
            logEmail(recipient, subject, "SENT", null);

        } catch (Exception e) {
            logger.error("Exception occurred", e);
            logger.error("❌ Failed to send alert email.");
            
            // ✅ Log failure
            logEmail(recipient, subject, "FAILED", e.getMessage());
        }
    }
    
    
}
