package utils;

import auth.service.LoginController;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import javax.swing.JOptionPane;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;


public class DBConnection {
    
    private static final Logger logger = LogManager.getLogger(LoginController.class); 


    // This is the connection link to my Neon PostgreSQL database
    private static final String URL = "jdbc:postgresql://ep-solitary-block-a1lz8vh0-pooler.ap-southeast-1.aws.neon.tech/neondb?sslmode=require";
    
     // These are the credentials used to connect to the database
    private static final String USER = "neondb_owner";
    private static final String PASSWORD = "npg_k4JtDmyBlb2L"; // <-- PW of my SQL DB

    public static Connection getConnection() {
        try {
        // Load the PostgreSQL driver (this helps Java talk to the database)
            Class.forName("org.postgresql.Driver"); 
         // Connect to the database using the link, username, and password
            Connection conn = DriverManager.getConnection(URL, USER, PASSWORD);
            
            // Set the time zone of the connection to Asia/Manila so the time is correct
            conn.prepareStatement("SET TIME ZONE 'Asia/Manila'").execute();

            // Return the connection so other parts of the system can use it
            return conn;

        } catch (SQLException e) {
            // Show an error message if there is a problem connecting to the database
            JOptionPane.showMessageDialog(null, "Connection error: " + e.getMessage());
            return null;

        } catch (ClassNotFoundException e) {
            // Show this if the PostgreSQL driver is not found
            JOptionPane.showMessageDialog(null, "PostgreSQL JDBC Driver not found.");
            return null;
        }
    }
}