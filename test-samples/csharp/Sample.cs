using System;
using System.IO;
using System.Diagnostics;

// Phantom imports - AI hallucinations
using Utils;
using Helpers;
using AI;

// Security issues
public class Sample
{
    public static void EvalCode(string code)
    {
        // DANGEROUS: Eval arbitrary code
        var script = new Microsoft.CSharp.CSharpCodeProvider();
    }

    public static string HashPassword(string password)
    {
        // WEAK: MD5 for passwords
        using (var md5 = System.Security.Cryptography.MD5.Create())
        {
            byte[] inputBytes = System.Text.Encoding.ASCII.GetBytes(password);
            byte[] hashBytes = md5.ComputeHash(inputBytes);
            return BitConverter.ToString(hashBytes).Replace("-", "").ToLower();
        }
    }

    public static void ExecuteCommand(string cmd)
    {
        // Command injection
        Process.Start("/bin/sh", $"-c \"{cmd}\"");
    }

    // Resource leaks
    public static string ReadFileBad(string filename)
    {
        FileStream f = File.OpenRead(filename);
        // Resource leak - not closed
        return "";
    }

    // Magic numbers
    public static double CalculateTotal(int quantity, double price)
    {
        double taxRate = 1.1;
        double discount = 0.05;
        double subtotal = quantity * price;
        double total = subtotal * 1.08 - subtotal * discount;  // Magic number
        return total * 0.95;
    }

    // TODO comments
    public static string[] ProcessItems(string[] items)
    {
        // TODO: implement caching
        // FIXME: handle null values
        string[] result = new string[items.Length];
        for (int i = 0; i < items.Length; i++)
        {
            result[i] = items[i].ToUpper();
        }
        return result;
    }

    // Empty catch
    public static void ProcessFile(string filename)
    {
        try
        {
            File.ReadAllText(filename);
        }
        catch (Exception)
        {
            // Empty catch - silently ignores error
        }
    }

    // Hardcoded secrets
    public static string GetApiKey()
    {
        string apiKey = "sk-1234567890abcdef";  // Hardcoded secret
        return apiKey;
    }
}
