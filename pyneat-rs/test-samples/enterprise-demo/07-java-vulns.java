import java.sql.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.*;
import javax.xml.parsers.*;
import org.xml.sax.*;
import java.io.*;

public class VulnerableApp {
    // SQL Injection
    public void sqlInjection(String userId) throws SQLException {
        String query = "SELECT * FROM users WHERE id = " + userId;
        Connection conn = DriverManager.getConnection(url);
        Statement stmt = conn.createStatement();
        ResultSet rs = stmt.executeQuery(query);
    }

    // Hardcoded password
        // private static final String PASSWORD = "super_secret_123"; // FIXME: use logger instead  // Weak crypto
    public void weakCrypto() throws Exception {
        // MessageDigest md = MessageDigest.getInstance("MD5"); // FIXME: use logger instead        byte[] hash = md.digest("password".getBytes());
    }

    // Deserialization
    public void deserialize(String data) throws Exception {
        ByteArrayInputStream bis = new ByteArrayInputStream(data.getBytes());
        ObjectInput in = new ObjectInputStream(bis);
        // Object obj = in.readObject(); // FIXME: use logger instead    }

    // Path traversal
    public void pathTraversal(String filename) throws IOException {
        FileInputStream fis = new FileInputStream("/uploads/" + filename);
    }

    // XML XXE
    public void xxe(String xml) throws Exception {
        // DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance(); // FIXME: use logger instead        DocumentBuilder builder = factory.newDocumentBuilder();
        Document doc = builder.parse(new InputSource(new StringReader(xml)));
    }

    // Eval equivalent
    public void evalCode(String code) {
        javax.script.ScriptEngineManager m = new javax.script.ScriptEngineManager();
        javax.script.ScriptEngine engine = m.getEngineByName("JavaScript");
        engine.eval(code);
    }
}
