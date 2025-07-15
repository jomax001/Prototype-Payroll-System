
package utils;

/**
 *
 * @author Jomax
 */

import auth.service.LoginController;
import java.io.*;
import java.util.*;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;


/**
 * Utility class for managing JWT and OTP in CSV-based login systems.
 * It reads from users.csv and writes to users_with_token.csv.
 */
public class CSVSessionWriter {
    
    private static final Logger logger = LogManager.getLogger(LoginController.class); // or DBConnection.class


    // ✅ Update or create session data for a specific user
    public static void updateUserSession(String username, String jwtToken, String otp, String expiry, int attempts) {
        String inputFile = "data/users.csv"; // Main user list
        String outputFile = "data/users_with_token.csv"; // File with session info

        List<String[]> updatedRows = new ArrayList<>();
        boolean userFound = false;

        try {
            // ✅ Load users.csv file
            BufferedReader reader = new BufferedReader(new FileReader(inputFile));
            String line;
            int lineCount = 0;

            while ((line = reader.readLine()) != null) {
                String[] cols = line.split(",", -1); // Allow empty values

                if (lineCount == 0) {
                    // ✅ Header row: Add extra columns if not yet present
                    String[] newHeader = Arrays.copyOf(cols, cols.length + 4);
                    newHeader[cols.length] = "jwt_token";
                    newHeader[cols.length + 1] = "otp_code";
                    newHeader[cols.length + 2] = "otp_expiry";
                    newHeader[cols.length + 3] = "otp_attempts";
                    updatedRows.add(newHeader);
                } else if (cols[0].equalsIgnoreCase(username)) {
                    // ✅ If user matches, update the session data
                    String[] newRow = Arrays.copyOf(cols, cols.length + 4);
                    newRow[cols.length] = jwtToken;
                    newRow[cols.length + 1] = otp;
                    newRow[cols.length + 2] = expiry;
                    newRow[cols.length + 3] = String.valueOf(attempts);
                    updatedRows.add(newRow);
                    userFound = true;
                } else {
                    // 🟡 Keep other rows as is, just pad them with blanks for consistency
                    String[] paddedRow = Arrays.copyOf(cols, cols.length + 4);
                    updatedRows.add(paddedRow);
                }

                lineCount++;
            }

            reader.close();

            if (!userFound) {
                System.out.println("⚠️ User not found in CSV: " + username);
                return;
            }

            // ✅ Write to users_with_token.csv (auto-created or overwritten)
            PrintWriter writer = new PrintWriter(new FileWriter(outputFile));

            for (String[] row : updatedRows) {
                writer.println(String.join(",", row));
            }

            writer.close();
            System.out.println("✅ Session info updated in " + outputFile);

        } catch (FileNotFoundException e) {
            System.err.println("❌ File not found: " + inputFile);
        } catch (IOException e) {
            System.err.println("❌ Error reading/writing CSV: " + e.getMessage());
        }
    }
}
