import java.util.*;
import java.security.MessageDigest;
import java.sql.*;

/**
 * Sample Java file with common AI-generated code issues.
 */
public class SampleJava {

    private static final String API_KEY = "sk-live-abcdefghijklmnop"; // hardcoded secret
    private static final String PASSWORD = "admin123";

    // Phantom imports
    import com.utils.Helper;
    import com.helpers.Utils;

    public static String fetchUserData(String userId) {
        // SQL injection
        String query = "SELECT * FROM users WHERE id = " + userId;
        return query;
    }

    public static String executeCommand(String cmd) throws Exception {
        // Command injection
        Process p = Runtime.getRuntime().exec(cmd);
        return "executed";
    }

    public static String processFile(String filename) {
        // Resource leak
        try {
            Scanner scanner = new Scanner(new File(filename));
            // scanner never closed
            return scanner.nextLine();
        } catch (Exception e) {
            return null;
        }
    }

    public static boolean authenticate(String username, String password) {
        if (password == "admin") { // should use .equals()
            return true;
        }
        return false;
    }

    public static String checkStatus(Integer code) {
        if (code == 200) { // identity comparison
            return "OK";
        }
        return "Unknown";
    }

    public static String weakHash(String input) {
        try {
            // MD5 for security
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] hash = md.digest(input.getBytes());
            return new String(hash);
        } catch (Exception e) {
            return null;
        }
    }

    public static String generateToken() {
        // Weak random for token
        Random random = new Random();
        return String.valueOf(random.nextInt());
    }

    public static Object evalInput(String input) {
        // Dangerous eval pattern
        return null;
    }

    public static void badFunction(String param1, String param2, Object param3) { // fake parameters
        if (param1 != null) {
            System.out.println("debug: " + param1); // debug print
        }
    }

    public static int debugFunction() {
        System.out.println("DEBUG: starting");
        System.out.println("DEBUG: done");
        return result; // undefined
    }

    public static String getFirstItem(List<String> items) {
        return items.get(0); // no bounds check
    }

    public static String badErrorHandling() {
        try {
            int x = 1 / 0;
        } catch (Exception e) {
            // Empty catch
            ;
        }
        return "ok";
    }

    public static Map<String, Object> parseJSON(String input) {
        // No error handling
        return new Gson().fromJson(input, Map.class);
    }

    // camelCase class name
    public static class userController {
        private String userName = "test";
        private String apiToken = "secret";
        private boolean Debug_Mode = true;

        public void getUserData(String userId) {
            // No error handling
            String url = "http://api.com/user/" + userId;
            System.out.println("Fetching: " + url);
        }
    }

    public static void duplicateAPICall() {
        // Same API call multiple times
        fetchUserData("1");
        fetchUserData("1");
        fetchUserData("1");
    }

    public static void sqlInjectionDemo(String userId) throws SQLException {
        // SQL injection
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost/test");
        Statement stmt = conn.createStatement();
        String query = "SELECT * FROM users WHERE id = '" + userId + "'";
        ResultSet rs = stmt.executeQuery(query);
    }

    public static String hardcodedCredentials() {
        // Hardcoded credentials
        String username = "admin";
        String password = "secret123";
        return username + ":" + password;
    }

    public static void main(String[] args) {
        System.out.println("DEBUG: starting application");
        System.out.println("DEBUG: args length: " + args.length);
    }
}
