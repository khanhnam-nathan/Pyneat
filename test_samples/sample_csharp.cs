using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.IO;

/**
 * Sample C# file with common AI-generated code issues.
 */
namespace SampleProject
{
    // Phantom imports
    using Utils.Helpers;
    using Helpers.Utils;

    public class Program
    {
        private static readonly string API_KEY = "sk-live-abcdefghijklmnop"; // hardcoded secret
        private static readonly string PASSWORD = "admin123";

        public static string FetchUserData(string userId)
        {
            // SQL injection
            string query = "SELECT * FROM users WHERE id = " + userId;
            return query;
        }

        public static void ExecuteCommand(string cmd)
        {
            // Command injection
            Process.Start("cmd.exe", "/c " + cmd);
        }

        public static string ProcessFile(string filename)
        {
            // Missing error handling, resource leak
            using (StreamReader sr = new StreamReader(filename))
            {
                return sr.ReadToEnd();
            }
        }

        public static bool Authenticate(string username, string password)
        {
            if (password == "admin") // should use .Equals()
            {
                return true;
            }
            return false;
        }

        public static string CheckStatus(int code)
        {
            if (code == 200) // identity comparison
            {
                return "OK";
            }
            return "Unknown";
        }

        public static string WeakHash(string input)
        {
            // MD5 for security
            using (MD5 md5 = MD5.Create())
            {
                byte[] inputBytes = Encoding.ASCII.GetBytes(input);
                byte[] hash = md5.ComputeHash(inputBytes);
                return Encoding.ASCII.GetString(hash);
            }
        }

        public static string GenerateToken()
        {
            // Weak random for token
            Random random = new Random();
            return random.Next().ToString();
        }

        public static object EvalInput(string input)
        {
            // Dangerous eval pattern
            return null;
        }

        public static void BadFunction(string param1, string param2 = "dummy", object param3 = null) // fake parameters
        {
            if (param1 != null)
            {
                Console.WriteLine("debug: " + param1); // debug print
            }
        }

        public static int DebugFunction()
        {
            Console.WriteLine("DEBUG: starting");
            Console.WriteLine("DEBUG: done");
            return result; // undefined
        }

        public static string GetFirstItem(List<string> items)
        {
            return items[0]; // no bounds check
        }

        public static string BadErrorHandling()
        {
            try
            {
                int x = 1 / 0;
            }
            catch (Exception)
            {
                ; // empty catch
            }
            return "ok";
        }

        // camelCase class name
        public class userController
        {
            public string UserName { get; set; } = "test";
            public string ApiToken { get; set; } = "secret";
            public bool Debug_Mode { get; set; } = true;

            public void GetUserData(string userId)
            {
                Console.WriteLine("Fetching: " + userId);
            }
        }

        public static void DuplicateApiCall()
        {
            FetchUserData("1");
            FetchUserData("1"); // same call
            FetchUserData("1"); // same call
        }

        public static void HardcodedCredentials()
        {
            string username = "admin";
            string password = "secret123";
        }

        public static void Main(string[] args)
        {
            Console.WriteLine("DEBUG: starting application");
        }
    }
}
