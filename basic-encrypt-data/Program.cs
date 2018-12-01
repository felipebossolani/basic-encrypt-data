using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace basic_encrypt_data
{
    class Program
    {
        static void Main(string[] args)
        {
            try
            {
                Console.WriteLine("Starting FileEncryption Method..");
                FileEncryption();
                Console.WriteLine("FileEncryption finished...");
            }
            catch (Exception e)
            {
                Console.WriteLine($"Error on FileEncryption Method: {e}");
            }

            Console.WriteLine("\n\n\n*********************");

            try
            {
                Console.WriteLine("Starting WindowsDataProtection Method..");
                WindowsDataProtection();
                Console.WriteLine("WindowsDataProtection finished...");
            }
            catch (Exception e)
            {
                Console.WriteLine($"Error on WindowsDataProtection Method: {e}");
            }

            Console.WriteLine("\n\n\n*********************");

            try
            {
                Console.WriteLine("Starting Hashing Method..");
                Hashing();
                Console.WriteLine("Hashing finished...");
            }
            catch (Exception e)
            {
                Console.WriteLine($"Error on Hashing Method: {e}");
            }

            Console.WriteLine("\n\n\n*********************");

        }

        /*
         * Mainly used for signing and validation. A hash is a value which always is generated in the same way for the data that needs to be encrypted. Is a one-way encryption algorithm, which basically means you can't revert the transformation applied (except, maybe, by brute-force attack). 
         * It's fast depending on the algorithm. It's also useful to storing information in a shorter way. 
         * For example, you might want to store a hashed password in a database.
         */
        private static void Hashing()
        {
            Console.WriteLine("Type your password:");
            string password = Console.ReadLine();

            var passwordToArray = Encoding.UTF8.GetBytes(password);
            var passwordHash = SHA256.Create().ComputeHash(passwordToArray);

            // Convert byte array to a string   
            StringBuilder passwordSB = new StringBuilder();
            for (int i = 0; i < passwordHash.Length; i++)
            {
                passwordSB.Append(passwordHash[i].ToString("x2"));
            }

            Console.WriteLine($"Hash value for password: {passwordSB}");

            Console.WriteLine("");
            Console.WriteLine("Re-Type your password:");
            string password2 = Console.ReadLine();

            var passwordToArray2 = Encoding.UTF8.GetBytes(password2);
            var passwordHash2 = SHA256.Create().ComputeHash(passwordToArray2);

            // Convert byte array to a string   
            StringBuilder passwordSB2 = new StringBuilder();
            for (int i = 0; i < passwordHash2.Length; i++)
            {
                passwordSB2.Append(passwordHash2[i].ToString("x2"));
            }

            Console.WriteLine($"Hash value for retyped password: {passwordSB2}");

            if (passwordSB.ToString().Equals(passwordSB2.ToString()))
            {
                Console.WriteLine("Passwords are equals!");
            }
            else{
                Console.WriteLine("Passwords arent equals!");
            }
        }

        /*
         this allows you to protect data in memory you might want to save into a database or provide via some web service. 
         In the following example I'm encrypting some data defining a particular scope, which will be used to decrypt it, so it's an extra level of security.  
         */
        private static void WindowsDataProtection()
        {
            // Windows Data Protection (we can also protect for the LocalMachine too)
            // note, the null can be replaced with a byte[] for additional entropy
            const string dataToProtect = "This is a bunch of super secret content!";
            var dataToProtectAsArray = Encoding.Unicode.GetBytes(dataToProtect);
            var wdpEncryptedData = ProtectedData.Protect(
                dataToProtectAsArray, null, DataProtectionScope.CurrentUser);

            var wdpUnEncryptedData = ProtectedData.Unprotect(
                wdpEncryptedData, null, DataProtectionScope.CurrentUser);
            var wdpUnencryptedString = Encoding.Unicode.GetString(
                wdpUnEncryptedData);

            Console.WriteLine($"dataToProtect value: {dataToProtect}");
            Console.WriteLine($"uncrypted value: {wdpUnencryptedString}");
            System.Diagnostics.Debug.Assert(dataToProtect.Equals(wdpUnencryptedString));
        }

        /*
          this is the most basic encryption pattern for .net developers. 
          It's very useful because you will end encrypting your files and any windows user won't be able to read the content of your encrypted messages. 
          This method uses Windows data protection mechanism behind the scenes but this is a kind of short cut.
         */
        private static void FileEncryption()
        {
            const string dataToProtect = "This is a bunch of super secret content!";
            var dataToProtectAsArray = Encoding.Unicode.GetBytes(dataToProtect);

            var fileName = Path.Combine(Environment.GetFolderPath(
                Environment.SpecialFolder.MyDocuments),
                "MyDataFile.txt");

            // Encrypt a file in the file system
            File.WriteAllText(fileName, dataToProtect);

            // now we can encrypt it - only we can access it now
            File.Encrypt(fileName);
        }
    }
}
