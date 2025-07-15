package utils;

import auth.service.LoginController;
import java.io.FileInputStream;  // To read files from disk
import java.util.Properties;     // For reading key=value pairs from .properties file

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;


public class ConfigManager {
    
    private static final Logger logger = LogManager.getLogger(LoginController.class); 


    // This variable will be true if we want to use CSV instead of SQL
    private static boolean useCsv = true;

    // This block runs once when the class is first loaded
    static {
        try {
            // Create a Properties object to read key-value pairs
            Properties props = new Properties();

            // Load the config.properties file from this location
            props.load(new FileInputStream("src/config/config.properties"));

            // Get the value of "use_csv" from the file
            // If not found, use "false" as default
            useCsv = Boolean.parseBoolean(props.getProperty("use_csv", "false"));
        } catch (Exception e) {
            // If there is any error (like file not found), print a warning
            System.out.println("⚠️ Failed to load config.properties. Defaulting to SQL mode.");
        }
    }

    // This method returns true if using CSV, or false if using SQL
    public static boolean isUsingCsv() {
        return useCsv;
    }
}
