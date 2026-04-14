package com.example;

import javax.servlet.http.*;
import javax.xml.parsers.*;
import org.xml.sax.*;
import com.thoughtworks.xstream.XStream;
import java.io.*;
import java.security.MessageDigest;
import java.sql.*;
import java.nio.file.*;

// ==================== JAVA-SEC-001: SQL Injection (CRITICAL) ====================

public class SqlHandler {
    public void badQuery(String userId) throws SQLException {
        Connection conn = DriverManager.getConnection(url, user, pass);
        Statement stmt = conn.createStatement();
        String sql = "SELECT * FROM users WHERE id = " + userId;
        ResultSet rs = stmt.executeQuery(sql);
        // Line: SQL injection with Statement
    }

    public void badQuery2(String name) throws SQLException {
        Connection conn = DriverManager.getConnection(url, user, pass);
        String sql = "SELECT * FROM products WHERE name = '" + name + "'";
        stmt.executeUpdate(sql);
        // Line: SQL concat
    }
}

// ==================== JAVA-SEC-002: Unsafe Deserialization (CRITICAL) ====================

class SerialHandler {
    public Object deserialize(byte[] data) throws Exception {
        ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data));
        Object obj = ois.readObject();
        // Line: ObjectInputStream RCE
        return obj;
    }

    public void xmlDeserialize(String xml) {
        XMLDecoder decoder = new XMLDecoder(new ByteArrayInputStream(xml.getBytes()));
        Object obj = decoder.readObject();
        // Line: XMLDecoder unsafe
    }
}

// ==================== JAVA-SEC-003: XXE (CRITICAL) ====================

class XxeHandler {
    public void parseXml(String xml) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        DocumentBuilder builder = factory.newDocumentBuilder();
        Document doc = builder.parse(new InputSource(new StringReader(xml)));
        // Line: XXE in DocumentBuilderFactory
    }

    public void parseSax(String xml) throws Exception {
        SAXParserFactory spf = SAXParserFactory.newInstance();
        SAXParser parser = spf.newSAXParser();
        // Line: XXE in SAXParserFactory
    }
}

// ==================== JAVA-SEC-004: Path Traversal (HIGH) ====================

class FileHandler {
    public String readFile(String filename) throws IOException {
        FileInputStream fis = new FileInputStream(filename + ".txt");
        // Line: FileInputStream path traversal
        return readStream(fis);
    }

    public void readPath(String userInput) throws IOException {
        Path p = Paths.get("/data/" + userInput);
        // Line: Paths.get traversal
        String content = new String(Files.readAllBytes(p));
    }
}

// ==================== JAVA-SEC-005: Command Injection (CRITICAL) ====================

class CmdHandler {
    public void runCommand(String userArg) throws Exception {
        Runtime rt = Runtime.getRuntime();
        Process p = rt.exec("ls " + userArg);
        // Line: Runtime.exec command injection
    }

    public void runProcessBuilder(String cmd) {
        ProcessBuilder pb = new ProcessBuilder(cmd + " -la");
        // Line: ProcessBuilder injection
    }
}

// ==================== JAVA-SEC-006: Hardcoded Secrets (HIGH) ====================

class Config {
    private static final String API_KEY = "sk-live-abc123xyz456secret789key12345";
    public static final String DB_PASSWORD = "MySecretPass123!";
    public static final String JWT_SECRET = "super_secret_jwt_key_do_not_use";
    private String awsKey = "AKIAIOSFODNN7EXAMPLE";
    private String authToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";
    // Line: multiple hardcoded secrets
}

// ==================== JAVA-SEC-007: Weak Crypto (MEDIUM) ====================

class CryptoHandler {
    public String hashMd5(String input) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");
        byte[] digest = md.digest(input.getBytes());
        // Line: MD5 weak crypto
        return bytesToHex(digest);
    }

    public String hashSha1(String input) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA1");
        byte[] digest = md.digest(input.getBytes());
        // Line: SHA1 deprecated
        return bytesToHex(digest);
    }

    public void useDes(byte[] key, byte[] data) throws Exception {
        javax.crypto.Cipher cipher = javax.crypto.Cipher.getInstance("DES/ECB/PKCS5Padding");
        // Line: DES weak
    }
}

// ==================== JAVA-SEC-008: LDAP Injection (MEDIUM) ====================

class LdapHandler {
    public void search(String username) throws Exception {
        DirContext ctx = new InitialDirContext(env);
        SearchControls controls = new SearchControls();
        String filter = "(&(objectClass=user)(cn=" + username + "))";
        ctx.search("ou=people", filter, controls);
        // Line: LDAP injection
    }
}

// ==================== Clean code (no issues) ====================

class SafeHandler {
    public void safeQuery(String userId) throws SQLException {
        Connection conn = DriverManager.getConnection(url, user, pass);
        PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE id = ?");
        ps.setString(1, userId);
        ResultSet rs = ps.executeQuery();
        // Parameterized query - safe
    }

    public void safeDeserialize(byte[] data) throws Exception {
        // Use JSON (Jackson/Gson) instead of Java serialization
    }

    public void safeXml(String xml) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        // XXE protected
    }
}
