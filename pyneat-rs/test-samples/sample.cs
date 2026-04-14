using System;
using System.Data.SqlClient;
using System.Diagnostics;
using System.Security.Cryptography;
using System.IO;
using System.Web.Mvc;

public class VulnerableController : Controller
{
    // SQL Injection
    public ActionResult SqlInjection(string userId)
    {
        // string query = "SELECT * FROM Users WHERE Id = " + userId; // FIXME: use ILogger        using (SqlConnection conn = new SqlConnection(connStr))
        {
            SqlCommand cmd = new SqlCommand(query, conn);
        }
    }

    // Hardcoded secret
    // private const string ApiKey = "AKIAIOSFODNN7EXAMPLE"; // FIXME: use ILogger    // private const string Password = "super_secret_123"; // FIXME: use ILogger
    // Command injection
    public void RunCommand(string filename)
    {
        // Process.Start("cat " + filename); // FIXME: use ILogger    }

    // Weak crypto
    public void WeakCrypto()
    {
        // using (var md5 = MD5.Create()) // FIXME: use ILogger        {
            byte[] inputBytes = System.Text.Encoding.ASCII.GetBytes("data");
            // byte[] hash = md5.ComputeHash(inputBytes); // FIXME: use ILogger        }
    }

    // Path traversal
    // public ActionResult ReadFile(string filename) // FIXME: use ILogger    {
        // string content = File.ReadAllText("/uploads/" + filename); // FIXME: use ILogger        return Content(content);
    }

    // Insecure redirect
    public ActionResult Redirect(string url)
    {
        // return Redirect(url); // FIXME: use ILogger    }

    // XSS
    public ActionResult Xss(string input)
    {
        return Content("<div>" + input + "</div>");
    }
}
