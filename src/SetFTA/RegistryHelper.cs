using System;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using Microsoft.Win32;

namespace SetFTA
{
    /// <summary>
    /// Registry operations for setting file type associations.
    /// Uses direct Win32 API calls to bypass some restrictions.
    /// </summary>
    public static class RegistryHelper
    {
        #region Win32 API Imports

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern int RegOpenKeyEx(
            IntPtr hKey,
            string subKey,
            int options,
            int samDesired,
            out IntPtr phkResult);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern int RegCreateKeyEx(
            IntPtr hKey,
            string subKey,
            int reserved,
            string lpClass,
            int dwOptions,
            int samDesired,
            IntPtr lpSecurityAttributes,
            out IntPtr phkResult,
            out int lpdwDisposition);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern int RegSetValueEx(
            IntPtr hKey,
            string lpValueName,
            int reserved,
            int dwType,
            string lpData,
            int cbData);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern int RegDeleteKey(IntPtr hKey, string subKey);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern int RegCloseKey(IntPtr hKey);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern int RegDeleteTree(IntPtr hKey, string lpSubKey);

        private static readonly IntPtr HKEY_CURRENT_USER = new IntPtr(unchecked((int)0x80000001));

        private const int KEY_READ = 0x20019;
        private const int KEY_WRITE = 0x20006;
        private const int KEY_ALL_ACCESS = 0xF003F;
        private const int REG_SZ = 1;
        private const int REG_OPTION_NON_VOLATILE = 0;

        #endregion

        /// <summary>
        /// Sets a file type association (FTA).
        /// </summary>
        public static bool SetFileTypeAssociation(string extension, string progId, string hash)
        {
            string basePath = $@"Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\{extension}";
            return SetUserChoice(basePath, progId, hash);
        }

        /// <summary>
        /// Sets a protocol association (PTA).
        /// </summary>
        public static bool SetProtocolAssociation(string protocol, string progId, string hash)
        {
            string basePath = $@"Software\Microsoft\Windows\Shell\Associations\UrlAssociations\{protocol}";
            return SetUserChoice(basePath, progId, hash);
        }

        private static bool SetUserChoice(string basePath, string progId, string hash)
        {
            string userChoicePath = $@"{basePath}\UserChoice";

            try
            {
                // Method 1: Try direct Win32 API (bypasses some PowerShell restrictions)
                if (TrySetUserChoiceWin32(userChoicePath, progId, hash))
                {
                    Console.WriteLine("[OK] Set via Win32 API");
                    return true;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[INFO] Win32 API failed: {ex.Message}");
            }

            try
            {
                // Method 2: Try .NET Registry API
                if (TrySetUserChoiceDotNet(userChoicePath, progId, hash))
                {
                    Console.WriteLine("[OK] Set via .NET Registry API");
                    return true;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[INFO] .NET API failed: {ex.Message}");
            }

            try
            {
                // Method 3: Try deleting first, then creating
                if (TryDeleteAndRecreate(basePath, progId, hash))
                {
                    Console.WriteLine("[OK] Set via delete-and-recreate");
                    return true;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[INFO] Delete-recreate failed: {ex.Message}");
            }

            return false;
        }

        private static bool TrySetUserChoiceWin32(string path, string progId, string hash)
        {
            IntPtr hKey = IntPtr.Zero;

            try
            {
                // Try to delete existing UserChoice key
                int deleteResult = RegDeleteTree(HKEY_CURRENT_USER, path);
                // Ignore delete errors - key might not exist

                // Create new UserChoice key
                int disposition;
                int result = RegCreateKeyEx(
                    HKEY_CURRENT_USER,
                    path,
                    0,
                    null,
                    REG_OPTION_NON_VOLATILE,
                    KEY_ALL_ACCESS,
                    IntPtr.Zero,
                    out hKey,
                    out disposition);

                if (result != 0)
                {
                    throw new Exception($"RegCreateKeyEx failed with error {result} (0x{result:X8})");
                }

                // Set ProgId value
                string progIdData = progId + "\0";
                result = RegSetValueEx(hKey, "ProgId", 0, REG_SZ, progIdData, progIdData.Length * 2);
                if (result != 0)
                {
                    throw new Exception($"RegSetValueEx (ProgId) failed with error {result}");
                }

                // Set Hash value
                string hashData = hash + "\0";
                result = RegSetValueEx(hKey, "Hash", 0, REG_SZ, hashData, hashData.Length * 2);
                if (result != 0)
                {
                    throw new Exception($"RegSetValueEx (Hash) failed with error {result}");
                }

                return true;
            }
            finally
            {
                if (hKey != IntPtr.Zero)
                {
                    RegCloseKey(hKey);
                }
            }
        }

        private static bool TrySetUserChoiceDotNet(string path, string progId, string hash)
        {
            string fullPath = @"HKEY_CURRENT_USER\" + path;

            // Try to delete existing key
            try
            {
                using (var parentKey = Registry.CurrentUser.OpenSubKey(path.Replace("\\UserChoice", ""), true))
                {
                    if (parentKey != null)
                    {
                        try { parentKey.DeleteSubKeyTree("UserChoice", false); } catch { }
                    }
                }
            }
            catch { }

            // Set values using Registry.SetValue (creates key if needed)
            Registry.SetValue(fullPath, "ProgId", progId, RegistryValueKind.String);
            Registry.SetValue(fullPath, "Hash", hash, RegistryValueKind.String);

            return true;
        }

        private static bool TryDeleteAndRecreate(string basePath, string progId, string hash)
        {
            string userChoicePath = $@"{basePath}\UserChoice";

            // Delete using Win32 API
            RegDeleteTree(HKEY_CURRENT_USER, userChoicePath);

            // Small delay to let Windows process the deletion
            System.Threading.Thread.Sleep(50);

            // Create using .NET API
            string fullPath = @"HKEY_CURRENT_USER\" + userChoicePath;
            Registry.SetValue(fullPath, "ProgId", progId, RegistryValueKind.String);
            Registry.SetValue(fullPath, "Hash", hash, RegistryValueKind.String);

            return true;
        }

        /// <summary>
        /// Gets the current file type association.
        /// </summary>
        public static (string ProgId, string Hash) GetFileTypeAssociation(string extension)
        {
            string path = $@"Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\{extension}\UserChoice";
            return GetUserChoice(path);
        }

        /// <summary>
        /// Gets the current protocol association.
        /// </summary>
        public static (string ProgId, string Hash) GetProtocolAssociation(string protocol)
        {
            string path = $@"Software\Microsoft\Windows\Shell\Associations\UrlAssociations\{protocol}\UserChoice";
            return GetUserChoice(path);
        }

        private static (string ProgId, string Hash) GetUserChoice(string path)
        {
            try
            {
                using (var key = Registry.CurrentUser.OpenSubKey(path))
                {
                    if (key != null)
                    {
                        string progId = key.GetValue("ProgId") as string;
                        string hash = key.GetValue("Hash") as string;
                        return (progId, hash);
                    }
                }
            }
            catch { }

            return (null, null);
        }

        /// <summary>
        /// Sets the ApplicationAssociationToast entry (required for the association to work).
        /// </summary>
        public static void SetApplicationAssociationToast(string extension, string progId)
        {
            string path = @"HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts";
            string valueName = $"{progId}_{extension}";

            try
            {
                Registry.SetValue(path, valueName, 0, RegistryValueKind.DWord);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[WARN] Could not set ApplicationAssociationToast: {ex.Message}");
            }
        }
    }
}
