package auth.service;

import auth.service.LoginController;
import java.awt.Color;
import javax.swing.JTextField;
import javax.swing.ImageIcon;
import javax.swing.JOptionPane;
import java.io.*;
import gui.AccountingHeadDashboard;
import gui.AdminDashboard;
import gui.EmployeeDashboard;
import gui.HRDashboard;
import gui.PayrollManagerDashboard;
import gui.TeamLeaderDashboard;
import utils.DBConnection;
import utils.JWTUtil;
import utils.SessionManager;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.awt.event.FocusAdapter;
import java.awt.event.FocusEvent;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Timestamp;
import java.time.Instant;
import utils.CSVLogger;
import utils.EmailUtil;
import utils.OTPUtil;
import utils.RememberTokenUtil;
import javax.swing.Timer;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 *
 * @author Jomax
 */
public class LoginUI extends javax.swing.JFrame {
    
    private static final Logger logger = LogManager.getLogger(LoginController.class);
    
    // Placeholder and password visibility flags
    private final String passwordPlaceholder = "Enter password";
    private boolean showingPasswordPlaceholder = true;
    private boolean passwordVisible = false;

     // Constants for token handling
    private final String TOKEN_FILE = "remember_token.dat";
    private final String ENCRYPTION_KEY = "1234567890123456"; // 16-char key for AES
    private String otp;
    private String recipientEmail;
    /**
     * Creates new form NewLoginUI
     */
    public LoginUI() {
        initComponents();
        setLocationRelativeTo(null); // This centers the window
        setTitle("Login - FinMark Payroll System");
        setSize(400, 350);
        setDefaultCloseOperation(EXIT_ON_CLOSE);
        setResizable(false);
        
        rememberMeCheckbox.addActionListener(new ActionListener() {
    public void actionPerformed(ActionEvent e) {
        rememberMeChecked = rememberMeCheckbox.isSelected(); // ✅ Update static variable based on checkbox
    }
});
        
       Timer timer = new Timer(1000, new ActionListener() {
    public void actionPerformed(ActionEvent evt) {
        try (Connection conn = DBConnection.getConnection()) {
            String sql = "SELECT locked_until FROM users WHERE username = ?";
            PreparedStatement ps = conn.prepareStatement(sql);
            ps.setString(1, usernameField.getText()); // get current input
            ResultSet rs = ps.executeQuery();

            if (rs.next()) {
                Timestamp lockedUntil = rs.getTimestamp("locked_until");
                if (lockedUntil != null && lockedUntil.after(new Timestamp(System.currentTimeMillis()))) {
                    long remainingMillis = lockedUntil.getTime() - System.currentTimeMillis();

                    long hours = (remainingMillis / 1000) / 3600;
                    long minutes = ((remainingMillis / 1000) % 3600) / 60;
                    long seconds = (remainingMillis / 1000) % 60;

                    loginButton.setEnabled(false);
                    loginButton.setBackground(new Color(255, 0, 0));
                    loginButton.setForeground(Color.BLACK);
                    loginButton.setText("Locked (" + hours + "h " + minutes + "m " + seconds + "s)");
                } else {
                    loginButton.setEnabled(true);
                    loginButton.setText("Login");
                    loginButton.setForeground(Color.WHITE);
                    loginButton.setBackground(new Color(0, 102, 204)); // reset color if needed
                }
            }
        } catch (Exception ignored) {
            // silently ignore
        }
    }
});
timer.start();
 

        
        // Check if DB is connected
    if (LoginController.isDatabaseConnected()) {
        lblDBStatus.setText("✅ Connected to Database");
        lblDBStatus.setForeground(Color.GREEN.darker());
    } else {
        lblDBStatus.setText("❌ DB Connection Failed");
        lblDBStatus.setForeground(Color.RED);
    } 
        
         // Hide "Remember Me" checkbox for Administrator role
        String selectedRole = roleComboBox.getSelectedItem().toString();
        rememberMeCheckbox.setVisible(!selectedRole.equals("Administrator"));
        
        
        // This listens for changes in the role dropdown
        roleComboBox.addActionListener(e -> {
         String role = roleComboBox.getSelectedItem().toString();
    
        // Show or hide the checkbox based on selected role
        rememberMeCheckbox.setVisible(!role.equals("Administrator"));
        });
        
        // Set up field placeholders
        setPlaceholder(usernameField, "Enter username");
        setupPasswordPlaceholder();
    
        
// [AUTO-LOGIN LOGIC] This checks if a saved token exists for "Remember Me"
if (Files.exists(Paths.get(TOKEN_FILE))) {
    System.out.println(" Token file found, attempting auto-login...");

    try {
        // Read the encrypted token from the file
        byte[] encrypted = Files.readAllBytes(Paths.get(TOKEN_FILE));

        if (encrypted.length % 16 != 0) {
            System.err.println("⚠️ Token file is corrupted or incomplete. Skipping auto-login.");
            Files.deleteIfExists(Paths.get(TOKEN_FILE)); // Delete the bad file
            JOptionPane.showMessageDialog(this, "Your saved login token was corrupted and has been cleared.\nPlease log in again manually.");
            return;
        }


        // Decrypt the token using AES
        String token = decryptToken(encrypted);
        System.out.println("🔓 Decrypted token: " + token);

        // Validate the JWT token's signature and expiration
        if (JWTUtil.validateToken(token)) {
            // Extract username from the token
            String username = JWTUtil.getUsername(token);

            // ✅ Step: Get user's role from the database
		String role = getUserRoleFromDatabase(username); 

		// ❗ If the role is missing (null), show error message and stop login
		if (role == null || role.isBlank()) {
    		// Show popup message that we failed to get role
   		 JOptionPane.showMessageDialog(this, "❌ Cannot find your role in the database. Please log in manually.");

    		// Stop the login process to prevent app crash
    		return;
		}

		// ✅ If the role is found, open the correct dashboard
		openDashboard(role); 



            // Store the session details in memory
            SessionManager.setSession(username, role, token);

            // Open the user’s dashboard based on their role
            openDashboard(role);

            // Close the login window since we auto-logged in
            dispose();
            return; // Exit constructor
        } else {
            System.out.println("❌ Token invalid or expired. Auto-login cancelled.");
            JOptionPane.showMessageDialog(this, "Auto-login token has expired. Please log in manually.");
        }

    } catch (javax.crypto.IllegalBlockSizeException | javax.crypto.BadPaddingException ex) {
        // ✅ Token file exists but cannot be unlocked (invalid/corrupted)
        System.err.println("❌ Token cannot be unlocked. It might be broken or changed.");
        try {
            Files.deleteIfExists(Paths.get(TOKEN_FILE)); // remove bad token
        } catch (IOException io) {
            System.err.println("⚠️ Failed to delete invalid token file.");
        }
    } catch (Exception e) {
        // Catch-all: Log errors if something else fails
        System.out.println("⚠️ Error during auto-login:");
        logger.error("Exception occurred", e);
    }

} else {
    System.out.println(" 📁 No token file found. Skipping auto-login.");
}

// For debug purposes: print current system time
System.out.println("🕒 Java time now: " + java.time.ZonedDateTime.now());
    }
    
     // Add placeholder for username input field
    private void setPlaceholder(JTextField field, String placeholder) {
        field.setForeground(Color.BLACK);
        field.setText(placeholder);

        field.addFocusListener(new FocusAdapter() {
            @Override
            public void focusGained(FocusEvent e) {
                if (field.getText().equals(placeholder)) {
                    field.setText("");
                    field.setForeground(Color.BLACK);
                }
            }

            @Override
            public void focusLost(FocusEvent e) {
                if (field.getText().isEmpty()) {
                    field.setForeground(Color.BLACK);
                    field.setText(placeholder);
                }
            }
        });
    }
    
     // Password field placeholder
    private void setupPasswordPlaceholder() {
        passwordField.setEchoChar((char) 0);
        passwordField.setForeground(Color.BLACK);
        passwordField.setText(passwordPlaceholder);

        passwordField.addFocusListener(new FocusAdapter() {
            @Override
            public void focusGained(FocusEvent e) {
                if (showingPasswordPlaceholder) {
                    passwordField.setText("");
                    passwordField.setForeground(Color.BLACK);
                    passwordField.setEchoChar('*'); // or '*'
                    showingPasswordPlaceholder = false;
                }
            }

            @Override
            public void focusLost(FocusEvent e) {
                if (passwordField.getPassword().length == 0) {
                    passwordField.setEchoChar((char) 0);
                    passwordField.setText(passwordPlaceholder);
                    passwordField.setForeground(Color.BLACK);
                    showingPasswordPlaceholder = true;
                }
            }
        });
        
    }

        // This saves whether the "Remember Me" checkbox is checked or not
    // If it's checked, the value is true. If not, it's false.
    private static boolean rememberMeChecked = false;

    // This allows other parts of the program to know if "Remember Me" was checked
    public static boolean isRememberMeCheckedStatic() {
        return rememberMeChecked;
    }

    // This changes the value of rememberMeChecked (true or false)
    // Use this when the checkbox is clicked
    public void setRememberMeChecked(boolean checked) {
        rememberMeChecked = checked;
    }
    
public static void startApp() {
    // Check if may saved token
    if (Files.exists(Paths.get("remember_token.dat"))) {
        try {
            // Decrypt the token
            byte[] encrypted = Files.readAllBytes(Paths.get("remember_token.dat"));
            String token = new LoginUI().decryptToken(encrypted);

            // Validate token (check if not expired or tampered)
            if (JWTUtil.validateToken(token)) {
                String username = JWTUtil.getUsername(token);
                String role = new LoginUI().getUserRoleFromDatabase(username);

                if (role != null) {
                    // Save the session
                    SessionManager.setSession(username, role, token);

                    // ✅ Open the dashboard based on user role
                    new LoginUI().openDashboard(role);
                    return; // STOP HERE! Don't open login window
                }
            }
        } catch (Exception e) {
            System.err.println("Auto-login failed: " + e.getMessage());
        }
    }

    // ❌ If no token or token invalid → show login window
    new LoginUI().setVisible(true);
}
    

 
    
    /**
     * This method is called from within the constructor to initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is always
     * regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        loginLabel = new javax.swing.JLabel();
        usernameField = new javax.swing.JTextField();
        roleComboBox = new javax.swing.JComboBox<>();
        loginButton = new javax.swing.JButton();
        companyLabel = new javax.swing.JLabel();
        passwordField = new javax.swing.JPasswordField();
        togglePasswordBtn = new javax.swing.JButton();
        rememberMeCheckbox = new javax.swing.JCheckBox();
        lblDBStatus = new javax.swing.JLabel();

        setDefaultCloseOperation(javax.swing.WindowConstants.DISPOSE_ON_CLOSE);
        setTitle("Login Dashboard");
        setMinimumSize(new java.awt.Dimension(400, 350));
        setPreferredSize(new java.awt.Dimension(400, 350));
        setResizable(false);
        getContentPane().setLayout(new org.netbeans.lib.awtextra.AbsoluteLayout());

        loginLabel.setFont(new java.awt.Font("Segoe UI", 1, 24)); // NOI18N
        loginLabel.setHorizontalAlignment(javax.swing.SwingConstants.CENTER);
        loginLabel.setText("LOGIN");
        loginLabel.setToolTipText("");
        loginLabel.setPreferredSize(new java.awt.Dimension(200, 30));
        getContentPane().add(loginLabel, new org.netbeans.lib.awtextra.AbsoluteConstraints(90, 30, 200, 30));

        usernameField.setFont(new java.awt.Font("Segoe UI", 0, 14)); // NOI18N
        usernameField.setToolTipText("Enter username");
        usernameField.setBorder(javax.swing.BorderFactory.createBevelBorder(javax.swing.border.BevelBorder.LOWERED));
        usernameField.setPreferredSize(new java.awt.Dimension(220, 30));
        getContentPane().add(usernameField, new org.netbeans.lib.awtextra.AbsoluteConstraints(80, 80, -1, -1));

        roleComboBox.setFont(new java.awt.Font("Segoe UI", 1, 14)); // NOI18N
        roleComboBox.setModel(new javax.swing.DefaultComboBoxModel<>(new String[] { "HR Personnel", "Team Leader", "Payroll Manager", "Accounting Head", "Employee", "Administrator" }));
        roleComboBox.setBorder(javax.swing.BorderFactory.createBevelBorder(javax.swing.border.BevelBorder.RAISED));
        roleComboBox.setPreferredSize(new java.awt.Dimension(220, 30));
        getContentPane().add(roleComboBox, new org.netbeans.lib.awtextra.AbsoluteConstraints(80, 160, -1, -1));

        loginButton.setBackground(new java.awt.Color(0, 123, 255));
        loginButton.setFont(new java.awt.Font("Segoe UI Semibold", 1, 14)); // NOI18N
        loginButton.setText("Login");
        loginButton.setToolTipText("");
        loginButton.setBorder(new javax.swing.border.SoftBevelBorder(javax.swing.border.BevelBorder.RAISED));
        loginButton.setFocusPainted(false);
        loginButton.setPreferredSize(new java.awt.Dimension(220, 30));
        loginButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                loginButtonActionPerformed(evt);
            }
        });
        getContentPane().add(loginButton, new org.netbeans.lib.awtextra.AbsoluteConstraints(80, 210, -1, -1));

        companyLabel.setFont(new java.awt.Font("Segoe UI", 0, 11)); // NOI18N
        companyLabel.setHorizontalAlignment(javax.swing.SwingConstants.CENTER);
        companyLabel.setText("© 2025 FinMark Payroll System");
        companyLabel.setMaximumSize(new java.awt.Dimension(240, 20));
        companyLabel.setMinimumSize(new java.awt.Dimension(240, 20));
        companyLabel.setPreferredSize(new java.awt.Dimension(240, 20));
        getContentPane().add(companyLabel, new org.netbeans.lib.awtextra.AbsoluteConstraints(70, 250, 240, 20));

        passwordField.setText("jPasswordField1");
        passwordField.setBorder(javax.swing.BorderFactory.createBevelBorder(javax.swing.border.BevelBorder.LOWERED));
        passwordField.setPreferredSize(new java.awt.Dimension(220, 30));
        getContentPane().add(passwordField, new org.netbeans.lib.awtextra.AbsoluteConstraints(80, 120, -1, -1));

        togglePasswordBtn.setBorder(new javax.swing.border.SoftBevelBorder(javax.swing.border.BevelBorder.RAISED));
        togglePasswordBtn.setPreferredSize(new java.awt.Dimension(30, 30));
        togglePasswordBtn.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                togglePasswordBtnActionPerformed(evt);
            }
        });
        getContentPane().add(togglePasswordBtn, new org.netbeans.lib.awtextra.AbsoluteConstraints(310, 120, -1, -1));

        rememberMeCheckbox.setText("Remember Me");
        rememberMeCheckbox.setToolTipText("Remember Me");
        rememberMeCheckbox.setBorder(javax.swing.BorderFactory.createBevelBorder(javax.swing.border.BevelBorder.LOWERED));
        getContentPane().add(rememberMeCheckbox, new org.netbeans.lib.awtextra.AbsoluteConstraints(80, 190, -1, -1));

        lblDBStatus.setHorizontalAlignment(javax.swing.SwingConstants.CENTER);
        lblDBStatus.setMaximumSize(new java.awt.Dimension(250, 20));
        lblDBStatus.setMinimumSize(new java.awt.Dimension(250, 20));
        lblDBStatus.setPreferredSize(new java.awt.Dimension(250, 20));
        getContentPane().add(lblDBStatus, new org.netbeans.lib.awtextra.AbsoluteConstraints(60, 270, 250, 20));

        pack();
    }// </editor-fold>//GEN-END:initComponents

    private void togglePasswordBtnActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_togglePasswordBtnActionPerformed
    // Handle toggle button to show or hide password
        if (!showingPasswordPlaceholder) {
        if (passwordVisible) {
            passwordField.setEchoChar('*');
            togglePasswordBtn.setIcon(new ImageIcon(getClass().getResource("/resources/eye-off.png")));
            passwordVisible = false;
        } else {
            passwordField.setEchoChar((char) 0);
            togglePasswordBtn.setIcon(new ImageIcon(getClass().getResource("/resources/eye.png")));
            passwordVisible = true;
        }
    }
    }//GEN-LAST:event_togglePasswordBtnActionPerformed

    private void loginButtonActionPerformed(java.awt.event.ActionEvent evt) {                                            
    // Step 1: Get input from login form
    String username = usernameField.getText();
    String password = new String(passwordField.getPassword());
    String role = roleComboBox.getSelectedItem().toString();

    // Step 2: Require Remember Me for non-admins
    if (!role.equals("Administrator") && !rememberMeCheckbox.isSelected()) {
        JOptionPane.showMessageDialog(this, "You must check 'Remember Me' to continue.");
        return;
    }
    
   try (Connection conn = DBConnection.getConnection()) {
    String sql = "SELECT locked_until FROM users WHERE username = ?";
    PreparedStatement ps = conn.prepareStatement(sql);
    ps.setString(1, username);
    ResultSet rs = ps.executeQuery();

    if (rs.next()) {
        Timestamp lockedUntil = rs.getTimestamp("locked_until");
        Timestamp now = new Timestamp(System.currentTimeMillis());

        if (lockedUntil != null && lockedUntil.after(now)) {
            JOptionPane.showMessageDialog(this, "Your account is locked until: " + lockedUntil);
            CSVLogger.logFailedLogin(username, "Attempted login while account locked");
            return;
        }
    }
} catch (Exception e) {
    logger.error("Exception occurred", e);

}
 

    // Step 3: Check for too many login attempts in last 5 minutes
    try (Connection conn = DBConnection.getConnection()) {
        String sql = "SELECT COUNT(*) AS attempt_count FROM login_attempts WHERE username = ? AND attempt_time >= ?";
        PreparedStatement ps = conn.prepareStatement(sql);
        ps.setString(1, username);
        Timestamp fiveMinutesAgo = Timestamp.from(Instant.now().minusSeconds(300));
        ps.setTimestamp(2, fiveMinutesAgo);
        ResultSet rs = ps.executeQuery();
        if (rs.next() && rs.getInt("attempt_count") >= 10) {
            JOptionPane.showMessageDialog(this, "Too many login attempts. Please wait a while.");
            EmailUtil.sendAlert("admin@example.com", "⚠️ High login attempts for user: " + username);
            return;
        }
    } catch (Exception e) {
        logger.error("Exception occurred", e);

    }

    // Step 4: Login using CSV or SQL
    String loginSource = "csv"; // change to "sql" if needed
    String result;
    if (loginSource.equals("csv")) {
        result = LoginController.loginFromCSV(username, password, role);
    } else {
        result = LoginController.login(username, password, role);
    }

    // Step 4.5: Log the attempt
try (Connection conn = DBConnection.getConnection()) {
    // Determine login success based on role names (returned by LoginController.login)
    boolean loginSuccess = result.equals("Administrator") || result.equals("HR Personnel") ||
                           result.equals("Team Leader") || result.equals("Payroll Manager") ||
                           result.equals("Accounting Head") || result.equals("Employee");

    String status = loginSuccess ? "success" : "failed";
    CSVLogger.logLogin(username, status, loginSuccess ? "Login successful" : "Wrong credentials");

    // Insert into login_attempts table
    String sql = "INSERT INTO login_attempts (username, attempt_time, status) VALUES (?, ?, ?)";
    PreparedStatement ps = conn.prepareStatement(sql);
    ps.setString(1, username);
    ps.setTimestamp(2, Timestamp.from(Instant.now()));
    ps.setString(3, status);
    ps.executeUpdate();

    // CSV log only for failed attempts
    if (!loginSuccess) {
        CSVLogger.logFailedLogin(username, "Wrong credentials");
    }

} catch (Exception e) {
   logger.error("Exception occurred", e); 
}
    
    
    try (Connection conn = DBConnection.getConnection()) {
    String countSql = "SELECT COUNT(*) AS failed_attempts FROM login_attempts " +
                      "WHERE username = ? AND status = 'failed' AND attempt_time >= ?";
    PreparedStatement ps = conn.prepareStatement(countSql);
    ps.setString(1, username);
    Timestamp fifteenMinutesAgo = Timestamp.from(Instant.now().minusSeconds(900)); // 15 mins
    ps.setTimestamp(2, fifteenMinutesAgo);
    ResultSet rs = ps.executeQuery();

    if (rs.next()) {
        int failedCount = rs.getInt("failed_attempts");
        if (failedCount >= 3) {
    // Lock for 24 hours
    Timestamp lockedUntil = Timestamp.from(Instant.now().plusSeconds(86400)); // 24 hrs
    PreparedStatement lockPS = conn.prepareStatement(
        "UPDATE users SET locked_until = ? WHERE username = ?"
    );
    lockPS.setTimestamp(1, lockedUntil);
    lockPS.setString(2, username);
    
    int rowsUpdated = lockPS.executeUpdate();
    System.out.println("✅ Rows updated in users table: " + rowsUpdated);
    System.out.println("🔒 Locking user: " + username + " until " + lockedUntil);

    lockPS.executeUpdate();

    CSVLogger.logFailedLogin(username, "Account locked due to 3 failed attempts");

    // ✅ Send lock email notification
    String email = OTPUtil.getUserEmail(username);
    
    logger.info("🔐 Storing OTP for " + username + ": " + otp);
    logger.info("📧 Sending OTP to: " + recipientEmail);

    if (email != null && email.contains("@")) {
        EmailUtil.sendLockNotification(email);
    }

    JOptionPane.showMessageDialog(this, "Account locked for 24 hours. We sent you a notification via email. Contact your Admin for assistance.");
    return;
}
    }
} catch (Exception e) {
    logger.error("Exception occurred", e);

}

    


    // Step 5: Process result
    switch (result) {
        case "success":
            break;
        
        case "Administrator":
        case "HR Personnel":
        case "Team Leader":
        case "Payroll Manager":
        case "Accounting Head":
        case "Employee":
            
            // Step 5.1: Generate OTP
        String recipientEmail = OTPUtil.getUserEmail(username);
        
        logger.info("🔐 Storing OTP for " + username + ": " + otp);
        logger.info("📧 Sending OTP to: " + recipientEmail);

            if (recipientEmail == null) {
        JOptionPane.showMessageDialog(this, "Email not found. Cannot send OTP.");
            return;
            }

            // ✅ Avoid regenerating OTP if one is still valid
            if (OTPUtil.hasValidOtp(username)) {
            logger.warn("⚠️ OTP already exists and is still valid. Skipping regeneration.");
                } else {
            // Generate and send new OTP
            String otp = OTPUtil.generateOtpCode();
            Timestamp expiresAt = Timestamp.from(Instant.now().plusSeconds(300));
            OTPUtil.storeOtp(username, otp, expiresAt);
            
            logger.info("🔐 Storing OTP for " + username + ": " + otp);
            logger.info("📧 Sending OTP to: " + recipientEmail);

            
            EmailUtil.sendOtpCode(recipientEmail, otp);
}


            // Step 5.4: Ask user to input OTP
            String enteredOtp = JOptionPane.showInputDialog(this, "Enter the OTP sent to your email:");

            // Step 5.5: Get OTP from database
            String dbOtp = null;
            Timestamp dbExpiry = null;
            try (Connection conn = DBConnection.getConnection()) {
                    if (conn == null) {
                JOptionPane.showMessageDialog(this, "⚠️ Database connection failed. Please try again.");
                logger.error("❌ Cannot get DB connection while fetching OTP.");
                return;
            }
                
                String sql = "SELECT otp_code, expires_at FROM otp_requests WHERE username = ?";
                PreparedStatement ps = conn.prepareStatement(sql);
                ps.setString(1, username);
                ResultSet rs = ps.executeQuery();
                if (rs.next()) {
                    dbOtp = rs.getString("otp_code");
                    dbExpiry = rs.getTimestamp("expires_at");
                }
            } catch (Exception e) {
                logger.error("Exception occurred", e);

            }

            // Step 5.6: Check OTP validity
            if (enteredOtp == null || dbOtp == null || dbExpiry == null) {
                JOptionPane.showMessageDialog(this, "Missing OTP info. Login failed.");
                return;
            }
            if (new Timestamp(System.currentTimeMillis()).after(dbExpiry)) {
                JOptionPane.showMessageDialog(this, "OTP has expired.");
                return;
            }
            if (!enteredOtp.equals(dbOtp)) {
                JOptionPane.showMessageDialog(this, "Incorrect OTP.");
                return;
            }

            // ✅ OTP matched
            JOptionPane.showMessageDialog(this, "Login successful!");
            
            

            // Step 6: Save session token
            LoginController.saveSession(username, SessionManager.getToken());

            // Step 7: Remember Me = save token
            // Step 7: Remember Me = save token
            if (rememberMeCheckbox.isSelected()) {
                String token = SessionManager.getToken();
                Timestamp tokenExpiry = Timestamp.from(Instant.now().plusSeconds(7 * 24 * 60 * 60)); // 7 days

            try {
            // 🔐 Encrypt the token before saving
            byte[] encrypted = encryptToken(token);

            // 📝 Save to file
            Files.write(Paths.get(TOKEN_FILE), encrypted);
            System.out.println("📁 Encrypted token saved to: " + TOKEN_FILE);
                } catch (Exception ex) {
            logger.error("❌ Failed to save encrypted token", ex);
            }
        }


            // Step 8: Open dashboard
            openDashboard(result); // role = result
            this.dispose();
            break;

        case "locked":
            JOptionPane.showMessageDialog(this, "Your account is locked.");
            break;

        case "invalid":
            JOptionPane.showMessageDialog(this, "Invalid credentials.");
            break;

        case "not_found":
            JOptionPane.showMessageDialog(this, "User not found.");
            break;

        case "active_session":
            JOptionPane.showMessageDialog(this, "User already logged in on another device.");
            break;

        default:
            JOptionPane.showMessageDialog(this, "An error occurred. Please try again.");
            break;
    }
}

// ✅ Opens the dashboard based on role
private void openDashboard(String role) {
    switch (role) {
        case "Administrator":
            new AdminDashboard().setVisible(true);
            break;
        case "HR Personnel":
            new HRDashboard().setVisible(true);
            break;
        case "Team Leader":
            new TeamLeaderDashboard().setVisible(true);
            break;
        case "Payroll Manager":
            new PayrollManagerDashboard().setVisible(true);
            break;
        case "Accounting Head":
            new AccountingHeadDashboard().setVisible(true);
            break;
        case "Employee":
            new EmployeeDashboard().setVisible(true);
            break;
        default:
            JOptionPane.showMessageDialog(this, "Unknown role: " + role);
            break;
    }
}

// ✅ This method tries to get the user's role from the database
// Example role: "Employee", "Admin", etc.
private String getUserRoleFromDatabase(String username) {
    try (Connection conn = DBConnection.getConnection()) {

        // 🟡 Ask the database: "What is the role of this username?"
        String sql = "SELECT role FROM users WHERE username = ?";
        PreparedStatement ps = conn.prepareStatement(sql);
        ps.setString(1, username); // Put the username into the question
        ResultSet rs = ps.executeQuery();

        // ✅ If the user exists
        if (rs.next()) {
            String role = rs.getString("role");

            // ❗ If the role is blank or missing, return null
            if (role == null || role.isBlank()) {
                System.err.println("⚠️ Role is missing for user: " + username);
                return null;
            }

            // ✅ Return the user's role (e.g., "HR Personnel")
            return role;
        } else {
            // ❌ No such user found
            System.err.println("❌ No user found with username: " + username);
        }

    } catch (Exception e) {
        // ❗ If there's an error, show it in the log
        logger.error("❌ Something went wrong when checking user role", e);
    }

    // ❌ Return null if something went wrong
    return null;
}


// ✅ This method hides (encrypts) a token string using AES encryption
private byte[] encryptToken(String token) throws Exception {
    // Imagine we are putting the token inside a secret box with a lock
    // "AES/ECB/PKCS5Padding" is the type of lock we use
    Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");

    // The secret key is like a password to lock/unlock the box
    SecretKeySpec keySpec = new SecretKeySpec(ENCRYPTION_KEY.getBytes(), "AES");

    // We tell the system that we want to lock the box (encrypt)
    cipher.init(Cipher.ENCRYPT_MODE, keySpec);

    // We lock the token inside the box and return the locked data
    return cipher.doFinal(token.getBytes("UTF-8")); // We use UTF-8 so all characters are handled properly
}

// ✅ This method opens (decrypts) the encrypted token back into a readable string
private String decryptToken(byte[] encrypted) throws Exception {
    // This is like opening the locked box using the same lock type and secret key
    Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");

    // Use the same secret key we used during encryption
    SecretKeySpec keySpec = new SecretKeySpec(ENCRYPTION_KEY.getBytes(), "AES");

    // Tell the system we want to unlock (decrypt)
    cipher.init(Cipher.DECRYPT_MODE, keySpec);

    // Unlock the encrypted data and turn it back into a string
    byte[] decrypted = cipher.doFinal(encrypted);
    return new String(decrypted, "UTF-8"); // Turn the unlocked bytes back into readable text
}

// ✅ Public getter method for rememberMeCheckbox
public javax.swing.JCheckBox getRememberMeCheckbox() {
    return rememberMeCheckbox;
}


    /**
     * @param args the command line arguments
     */
public static void main(String args[]) {
    java.awt.EventQueue.invokeLater(new Runnable() {
        public void run() {
            LoginUI.startApp(); // ✅ This will become launcher
        }
    });
}


    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JLabel companyLabel;
    private javax.swing.JLabel lblDBStatus;
    private javax.swing.JButton loginButton;
    private javax.swing.JLabel loginLabel;
    private javax.swing.JPasswordField passwordField;
    private javax.swing.JCheckBox rememberMeCheckbox;
    private javax.swing.JComboBox<String> roleComboBox;
    private javax.swing.JButton togglePasswordBtn;
    private javax.swing.JTextField usernameField;
    // End of variables declaration//GEN-END:variables
}


