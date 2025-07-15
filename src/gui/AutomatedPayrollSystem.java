package gui;

import auth.service.LoginController;
import auth.service.LoginUI;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;




/**
 *
 * @author Jomax
 */
public class AutomatedPayrollSystem {
    
    private static final Logger logger = LogManager.getLogger(LoginController.class);

    /**
     * @param args the command line arguments
     */
    public static void main(String args[]) {
    java.awt.EventQueue.invokeLater(new Runnable() {
        public void run() {
            new LoginUI().setVisible(true);
        }
    });
}
}