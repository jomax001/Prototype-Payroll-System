package utils;

import auth.service.LoginController;
import java.io.BufferedReader;
import java.io.FileReader;
import java.util.ArrayList;
import java.util.List;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;


/**
 * Utility class for reading data from CSV files.
 */
public class CSVUtil {
    
    private static final Logger logger = LogManager.getLogger(LoginController.class); 

    /**
     * Reads all rows from a CSV file and returns them as a list of String arrays.
     *
     * @param filePath the path to the CSV file (e.g., "data/users.csv")
     * @return list of rows, each row is a String array
     */
    public static List<String[]> readCSV(String filePath) {
        List<String[]> rows = new ArrayList<>();

        try (BufferedReader reader = new BufferedReader(new FileReader(filePath))) {
            String line;

            // Read each line from CSV
            while ((line = reader.readLine()) != null) {
                String[] parts = line.split(","); // Split by comma
                rows.add(parts);
            }

        } catch (Exception e) {
            System.err.println("❌ Failed to read CSV: " + e.getMessage());
            e.printStackTrace();
        }

        return rows;
    }
}
