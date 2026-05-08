import java.io.*;
import java.util.*;
import java.security.MessageDigest;

// Phantom imports - AI hallucinations
import utils.*;
import helpers.*;
import ai.*;

// Security issues
public class Sample {
    public static void evalCode(String code) throws Exception {
        // DANGEROUS: Runtime.exec with user input
        Runtime.getRuntime().exec(code);
    }

    public static String hashPassword(String password) throws Exception {
        // WEAK: MD5 for passwords
        MessageDigest md = MessageDigest.getInstance("MD5");
        byte[] result = md.digest(password.getBytes());
        return bytesToHex(result);
    }

    public static void executeCommand(String cmd) throws Exception {
        // Command injection
        Runtime.getRuntime().exec(cmd);
    }

    // Resource leaks
    public static String readFileBad(String filename) throws Exception {
        BufferedReader f = new BufferedReader(new FileReader(filename));
        // Resource leak - not closed
        return f.readLine();
    }

    // AI bugs - identity comparison
    public static boolean checkStatus(String status) {
        if (status == "success") {  // Should use .equals()
            return true;
        }
        return false;
    }

    // Magic numbers
    public static double calculateTotal(int quantity, double price) {
        double TAX_RATE = 1.1;
        double discount = 0.05;
        double subtotal = quantity * price;
        double total = subtotal * 1.08 - subtotal * discount;  // Magic number
        return total * 0.95;
    }

    // TODO comments
    public static List<String> processItems(List<String> items) {
        // TODO: optimize this method
        // FIXME: handle null values
        List<String> result = new ArrayList<>();
        for (String item : items) {
            result.add(item.toUpperCase());
        }
        return result;
    }

    // Hardcoded secrets
    public static String getApiKey() {
        String apiKey = "sk-1234567890abcdef";  // Hardcoded secret
        return apiKey;
    }

    // Empty catch block
    public static void processFile(String filename) {
        try {
            FileInputStream f = new FileInputStream(filename);
        } catch (Exception e) {
            // Empty catch - silently ignores error
        }
    }

    // System.exit in library code
    public static void validateInput(String input) {
        if (input == null) {
            System.exit(1);  // Should throw exception instead
        }
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
