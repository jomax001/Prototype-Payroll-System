package utils;

import auth.service.LoginController;
import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.text.SimpleDateFormat;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Date;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;


public class CSVLogger {
    private static final Logger logger = LogManager.getLogger(LoginController.class); // or DBConnection.class

    private static final String LOGIN_LOG_FILE = "logs/success_login.csv";
    private static final String FAILED_LOG_FILE = "logs/failed_login.csv";

    // ✅ Logs to both login_log.csv (all) and failed_login.csv (only if failed)
    public static void logLogin(String username, String status, String reason) {
        String timestamp = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date());
        String line = username + "," + timestamp + "," + status + "," + reason;

        // Log to login_log.csv (ALL attempts)
        try (FileWriter fw = new FileWriter(LOGIN_LOG_FILE, true);
             BufferedWriter bw = new BufferedWriter(fw);
             PrintWriter out = new PrintWriter(bw)) {
            out.println(line);
        } catch (IOException e) {
            e.printStackTrace();
        }

        // Log to failed_login.csv (FAILED attempts only)
        if ("failed".equalsIgnoreCase(status)) {
            try (FileWriter fw = new FileWriter(FAILED_LOG_FILE, true);
                 BufferedWriter bw = new BufferedWriter(fw);
                 PrintWriter out = new PrintWriter(bw)) {
                out.println(line);
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    // Legacy support
    public static void logFailedLogin(String username, String reason) {
        logLogin(username, "failed", reason);
    }
}
