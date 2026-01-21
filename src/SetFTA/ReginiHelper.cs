using System;
using System.Diagnostics;
using System.IO;
using System.Security.Principal;
using System.Text;

namespace SetFTA
{
    /// <summary>
    /// Helper class for setting UserChoice via regini.exe.
    /// This method bypasses UCPD (User Choice Protection Driver) by using
    /// the undocumented [DELETE] syntax discovered through reverse-engineering
    /// PDF-XChange Editor.
    ///
    /// Based on research from January 2026.
    /// </summary>
    public static class ReginiHelper
    {
        /// <summary>
        /// UCPD-protected file extensions that require the regini bypass.
        /// </summary>
        public static readonly string[] ProtectedExtensions = { ".pdf", ".htm", ".html" };

        /// <summary>
        /// UCPD-protected protocols that require the regini bypass.
        /// </summary>
        public static readonly string[] ProtectedProtocols = { "http", "https" };

        /// <summary>
        /// Checks if the current process is running with administrator privileges.
        /// </summary>
        public static bool IsAdmin()
        {
            using (var identity = WindowsIdentity.GetCurrent())
            {
                var principal = new WindowsPrincipal(identity);
                return principal.IsInRole(WindowsBuiltInRole.Administrator);
            }
        }

        /// <summary>
        /// Checks if an extension is UCPD-protected.
        /// </summary>
        public static bool IsProtectedExtension(string extension)
        {
            if (string.IsNullOrEmpty(extension))
                return false;

            extension = extension.ToLowerInvariant();
            if (!extension.StartsWith("."))
                extension = "." + extension;

            return Array.Exists(ProtectedExtensions, e => e.Equals(extension, StringComparison.OrdinalIgnoreCase));
        }

        /// <summary>
        /// Checks if a protocol is UCPD-protected.
        /// </summary>
        public static bool IsProtectedProtocol(string protocol)
        {
            if (string.IsNullOrEmpty(protocol))
                return false;

            return Array.Exists(ProtectedProtocols, p => p.Equals(protocol, StringComparison.OrdinalIgnoreCase));
        }

        /// <summary>
        /// Sets a file type association using the regini.exe bypass method.
        /// </summary>
        /// <param name="extension">File extension (e.g., ".pdf")</param>
        /// <param name="progId">Program identifier (e.g., "ChromePDF")</param>
        /// <param name="hash">Computed UserChoice hash</param>
        /// <returns>True if successful, false otherwise</returns>
        public static bool SetFileTypeAssociationViaRegini(string extension, string progId, string hash)
        {
            string userSid = UserChoiceHash.GetUserSid();
            string regPath = $@"\Registry\User\{userSid}\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\{extension}\UserChoice";

            return SetUserChoiceViaRegini(regPath, progId, hash);
        }

        /// <summary>
        /// Sets a protocol association using the regini.exe bypass method.
        /// </summary>
        /// <param name="protocol">Protocol (e.g., "http")</param>
        /// <param name="progId">Program identifier (e.g., "ChromeHTML")</param>
        /// <param name="hash">Computed UserChoice hash</param>
        /// <returns>True if successful, false otherwise</returns>
        public static bool SetProtocolAssociationViaRegini(string protocol, string progId, string hash)
        {
            string userSid = UserChoiceHash.GetUserSid();
            string regPath = $@"\Registry\User\{userSid}\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\{protocol}\UserChoice";

            return SetUserChoiceViaRegini(regPath, progId, hash);
        }

        /// <summary>
        /// Sets UserChoice values using regini.exe with the undocumented [DELETE] syntax.
        /// </summary>
        private static bool SetUserChoiceViaRegini(string regPath, string progId, string hash)
        {
            if (!IsAdmin())
            {
                Console.WriteLine("[INFO] regini.exe method requires Administrator privileges");
                return false;
            }

            // Create temp folder
            string tempFolder = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N"));

            try
            {
                Directory.CreateDirectory(tempFolder);

                // Create DELETE INI file
                string deleteIni = Path.Combine(tempFolder, "delete.ini");
                string deleteContent = $"{regPath} [DELETE]\r\n";
                File.WriteAllText(deleteIni, deleteContent, Encoding.ASCII);

                // Create SET INI file
                string setIni = Path.Combine(tempFolder, "set.ini");
                string setContent = $@"{regPath}
ProgId=""{progId}""
Hash=""{hash}""
0
";
                File.WriteAllText(setIni, setContent, Encoding.ASCII);

                // Execute regini.exe - DELETE
                Console.WriteLine("[INFO] Executing regini.exe DELETE...");
                int deleteExitCode = RunRegini(deleteIni);

                if (deleteExitCode != 0)
                {
                    Console.WriteLine($"[INFO] regini.exe DELETE returned exit code {deleteExitCode} (may be OK if key didn't exist)");
                }

                // Brief pause
                System.Threading.Thread.Sleep(100);

                // Execute regini.exe - SET
                Console.WriteLine("[INFO] Executing regini.exe SET...");
                int setExitCode = RunRegini(setIni);

                if (setExitCode != 0)
                {
                    Console.WriteLine($"[FAIL] regini.exe SET failed with exit code {setExitCode}");
                    return false;
                }

                Console.WriteLine("[OK] regini.exe completed successfully");
                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[FAIL] regini.exe method failed: {ex.Message}");
                return false;
            }
            finally
            {
                // Cleanup
                try
                {
                    if (Directory.Exists(tempFolder))
                    {
                        Directory.Delete(tempFolder, true);
                    }
                }
                catch { }
            }
        }

        /// <summary>
        /// Runs regini.exe with the specified INI file.
        /// </summary>
        private static int RunRegini(string iniFilePath)
        {
            var startInfo = new ProcessStartInfo
            {
                FileName = "regini.exe",
                Arguments = $"\"{iniFilePath}\"",
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true
            };

            using (var process = Process.Start(startInfo))
            {
                process.WaitForExit(10000); // 10 second timeout

                if (!process.HasExited)
                {
                    process.Kill();
                    throw new TimeoutException("regini.exe timed out");
                }

                return process.ExitCode;
            }
        }
    }
}
