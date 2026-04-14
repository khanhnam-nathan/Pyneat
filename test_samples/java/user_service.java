package com.example;

import java.util.*;
import java.sql.Connection;
import java.sql.DriverManager;

/**
 * Java service class demo
 */
public class UserService {

    // Hardcoded secrets - should trigger UNI-001
    private static final String API_KEY = "sk-live-abc123xyz789";  // TODO: use env
    private static final String DB_PASSWORD = "MySecretPass123";  // FIXME: rotate
    private static final String AUTH_TOKEN = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";
    private static final String SECRET_KEY = "AES_SECRET_KEY_12345";

    // Debug prints - should trigger UNI-002
    public void init() {
        System.out.println("Initializing UserService...");
        System.out.println("API_KEY: " + API_KEY);
        System.out.println("DB_PASSWORD: " + DB_PASSWORD);
    }

    // Empty catch - should trigger UNI-003
    public void fetchUser(String id) {
        try {
            String url = "jdbc:postgresql://localhost:5432/mydb";
            Connection conn = DriverManager.getConnection(url, "admin", DB_PASSWORD);
            // process
        } catch (Exception e) {
            // empty catch - BAD
        }
    }

    // Deep nesting - should trigger UNI-005
    public boolean validateInput(String input) {
        if (input != null) {
            if (input.length() > 0) {
                if (!input.isEmpty()) {
                    if (input != "") {
                        if (input != null) {
                            System.out.println("Valid input: " + input);
                            return true;
                        }
                    }
                }
            }
        }
        return false;
    }

    public static void main(String[] args) {
        UserService svc = new UserService();
        svc.init();
    }
}
