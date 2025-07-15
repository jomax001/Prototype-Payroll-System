/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package auth.service;

/**
 *
 * @author Jomax
 */
import javax.swing.*;
import java.awt.*;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;


public class OTPDialog extends JDialog {
    
    private static final Logger logger = LogManager.getLogger(LoginController.class);
    
    private JTextField otpField;
    private boolean submitted = false;

    public OTPDialog(Frame parent) {
        super(parent, "Enter OTP", true); // Modal dialog
        setLayout(new BorderLayout());

        // Message
        JLabel label = new JLabel("A one-time password was sent to your email. Please enter it below:");
        label.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        add(label, BorderLayout.NORTH);

        // OTP input
        otpField = new JTextField();
        otpField.setColumns(6);
        JPanel inputPanel = new JPanel();
        inputPanel.add(new JLabel("OTP: "));
        inputPanel.add(otpField);
        add(inputPanel, BorderLayout.CENTER);

        // ✅ Buttons
        JButton submitBtn = new JButton("Submit");
        JButton cancelBtn = new JButton("Cancel");

        JPanel buttonPanel = new JPanel();
        buttonPanel.add(submitBtn);
        buttonPanel.add(cancelBtn);
        add(buttonPanel, BorderLayout.SOUTH);

        // ✅ Button Actions
        submitBtn.addActionListener(e -> {
            submitted = true;
            dispose();
        });

        cancelBtn.addActionListener(e -> {
            submitted = false;
            dispose();
        });

        pack();
        setLocationRelativeTo(parent); // Center on parent
    }

    public String getOtp() {
        return otpField.getText().trim();
    }

    public boolean isSubmitted() {
        return submitted;
    }
}