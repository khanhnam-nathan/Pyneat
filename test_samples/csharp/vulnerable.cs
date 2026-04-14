using System;
using System.IO;
using System.Web;
using System.Web.Mvc;
using System.Security.Cryptography;
using System.Data.SqlClient;

// ==================== CSHARP-SEC-001: Unsafe Deserialization (CRITICAL) ====================

class SerialHandler {
    public object Deserialize(byte[] data) {
        var formatter = new BinaryFormatter();
        var obj = formatter.Deserialize(new MemoryStream(data));
        // Line: BinaryFormatter RCE
        return obj;
    }

    public object DeserializeXml(string xml) {
        var serializer = new System.Runtime.Serialization.DataContractSerializer(typeof(object));
        // Verify input source before deserializing
    }
}

// ==================== CSHARP-SEC-002: SQL Injection (CRITICAL) ====================

class SqlHandler {
    public void Query(string userId) {
        string sql = "SELECT * FROM users WHERE id = " + userId;
        SqlCommand cmd = new SqlCommand(sql, conn);
        cmd.ExecuteReader();
        // Line: SQL injection SqlCommand
    }

    public void Query2(string name) {
        string query = "SELECT * FROM products WHERE name = '" + name + "'";
        SqlCommand cmd = new SqlCommand(query, conn);
        cmd.ExecuteNonQuery();
        // Line: SQL concat
    }
}

// ==================== CSHARP-SEC-003: Path Traversal (HIGH) ====================

class FileHandler {
    public void ReadFile(string filename) {
        string path = "/data/" + filename;
        var content = File.ReadAllText(path);
        // Line: File.ReadAllText path traversal
    }

    public void MapPath(string page) {
        string mapped = Server.MapPath("~/" + page);
        // Line: Server.MapPath traversal
    }
}

// ==================== CSHARP-SEC-004: LDAP Injection (MEDIUM) ====================

class LdapHandler {
    public void Search(string username) {
        using (var searcher = new System.DirectoryServices.DirectorySearcher()) {
            string filter = "(&(objectClass=user)(cn=" + username + "))";
            searcher.Filter = filter;
            // Line: LDAP injection
        }
    }
}

// ==================== CSHARP-SEC-005: Hardcoded Secrets (HIGH) ====================

class Config {
    private static readonly string API_KEY = "sk-live-abc123xyz456secret789key12345";
    public const string DB_PASSWORD = "MySecretPass123!";
    private string awsKey = "AKIAIOSFODNN7EXAMPLE";
    public string ConnectionString = "Server=localhost;Database=db;User=admin;Password=secret123";
    // Line: multiple hardcoded secrets
}

// ==================== CSHARP-SEC-006: Weak Crypto (MEDIUM) ====================

class CryptoHandler {
    public string HashMd5(string input) {
        using (var md5 = new MD5CryptoServiceProvider()) {
            // Line: MD5CryptoServiceProvider
            return BitConverter.ToString(md5.ComputeHash(System.Text.Encoding.UTF8.GetBytes(input)));
        }
    }

    public void UseDes(byte[] key, byte[] data) {
        var des = new DESCryptoServiceProvider();
        // Line: DESCryptoServiceProvider weak
    }
}

// ==================== CSHARP-SEC-007: XSS (HIGH) ====================

class XssHandler : Controller {
    public void Render(string content) {
        Response.Write("<div>" + content + "</div>");
        // Line: Response.Write XSS
    }

    public IHtmlString RenderRaw(string html) {
        return Html.Raw(html);
        // Line: Html.Raw XSS
    }
}

// ==================== Clean code (no issues) ====================

class SafeHandler {
    public void SafeQuery(string userId) {
        var cmd = new SqlCommand("SELECT * FROM users WHERE id = @id", conn);
        cmd.Parameters.AddWithValue("@id", userId);
        // Parameterized query - safe
    }

    public void SafeHash(string input) {
        using (var sha = new SHA256Managed()) {
            // SHA-256 - safe
        }
    }
}
