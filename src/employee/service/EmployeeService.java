package employee.service;

import auth.service.LoginController;
import utils.SessionManager;
import utils.JWTUtil;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;


public class EmployeeService {
    
    private static final Logger logger = LogManager.getLogger(LoginController.class);

    public static String viewEmployeeList() {
        String token = SessionManager.getToken();
        if (token == null || !JWTUtil.validateToken(token)) {
            return "Access denied: Please login.";
        }

        String role = SessionManager.getRole();

        if (!role.equalsIgnoreCase("HR Personnel")) {
            return "Access denied: Only HR Personnel can view the employee list.";
        }

        return "Employee list loaded successfully.";
    }

    public static String addEmployee(String newEmployeeName) {
        String token = SessionManager.getToken();
        if (token == null || !JWTUtil.validateToken(token)) {
            return "Access denied: Please login.";
        }

        String role = SessionManager.getRole();

        if (!role.equalsIgnoreCase("HR Personnel")) {
            return "Access denied: Only HR Personnel can add employees.";
        }

        return "Employee '" + newEmployeeName + "' added successfully.";
    }
}
