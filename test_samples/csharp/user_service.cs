using System;
using System.Collections.Generic;

namespace DemoApp
{
    /// <summary>
    /// C# service class demo
    /// </summary>
    public class UserService
    {
        // Hardcoded secrets - should trigger UNI-001
        private const string API_KEY = "sk-live-abc123xyz789";
        private const string DB_PASSWORD = "MySecretPass123";  // TODO: env var
        private const string AUTH_TOKEN = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";
        private const string SECRET_KEY = "AES_SECRET_KEY_12345";

        // Debug prints - should trigger UNI-002
        public void Init()
        {
            Console.WriteLine("Initializing UserService...");
            Console.WriteLine("API_KEY: " + API_KEY);
            Debug.Print("Service started");
        }

        // Empty catch - should trigger UNI-003
        public void FetchUser(string id)
        {
            try
            {
                Console.WriteLine("Fetching user: " + id);
                // process
            }
            catch (Exception)
            {
                // empty catch - BAD
            }
        }

        // Deep nesting - should trigger UNI-005
        public bool ValidateInput(string input)
        {
            if (input != null)
            {
                if (input.Length > 0)
                {
                    if (input != "")
                    {
                        if (!string.IsNullOrEmpty(input))
                        {
                            if (input != null)
                            {
                                Console.WriteLine("Valid input: " + input);
                                return true;
                            }
                        }
                    }
                }
            }
            return false;
        }

        public static void Main(string[] args)
        {
            var svc = new UserService();
            svc.Init();
        }
    }
}
