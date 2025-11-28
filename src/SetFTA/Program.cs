using System;
using System.Linq;

namespace SetFTA
{
    /// <summary>
    /// SetFTA - File Type Association Tool
    ///
    /// A standalone executable that sets file type and protocol associations
    /// by computing the correct UserChoice hash that Windows requires.
    ///
    /// This is an attempt to bypass UCPD restrictions by using a custom .exe
    /// that is not on the UCPD blocklist (powershell.exe, cmd.exe, etc.).
    ///
    /// Based on research from:
    /// - PS-SFTA (https://github.com/DanysysTeam/PS-SFTA)
    /// - SetUserFTA by Christoph Kolbicz (https://kolbi.cz)
    /// </summary>
    class Program
    {
        static int Main(string[] args)
        {
            if (args.Length == 0 || args.Contains("-h") || args.Contains("--help") || args.Contains("/?"))
            {
                ShowHelp();
                return 0;
            }

            try
            {
                string command = args[0].ToLowerInvariant();

                switch (command)
                {
                    case "set-fta":
                        return SetFTA(args.Skip(1).ToArray());

                    case "set-pta":
                        return SetPTA(args.Skip(1).ToArray());

                    case "get-fta":
                        return GetFTA(args.Skip(1).ToArray());

                    case "get-pta":
                        return GetPTA(args.Skip(1).ToArray());

                    case "test-hash":
                        return TestHash(args.Skip(1).ToArray());

                    default:
                        Console.WriteLine($"Unknown command: {command}");
                        ShowHelp();
                        return 1;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine();
                Console.WriteLine("╔══════════════════════════════════════════════════════════════════╗");
                Console.WriteLine("║                         ERROR                                    ║");
                Console.WriteLine("╚══════════════════════════════════════════════════════════════════╝");
                Console.WriteLine();
                Console.WriteLine($"  {ex.Message}");
                Console.WriteLine();

                if (ex.Message.Contains("access") || ex.Message.Contains("permission") || ex.Message.Contains("denied"))
                {
                    Console.WriteLine("  This is likely due to UCPD (User Choice Protection Driver).");
                    Console.WriteLine("  Protected extensions: .pdf, .htm, .html");
                    Console.WriteLine("  Protected protocols: http, https");
                    Console.WriteLine();
                    Console.WriteLine("  Options:");
                    Console.WriteLine("    1. User changes manually in Windows Settings");
                    Console.WriteLine("    2. Disable UCPD (requires Admin + Reboot)");
                    Console.WriteLine("    3. Use DISM for new user profiles");
                }

                return 1;
            }
        }

        static void ShowHelp()
        {
            Console.WriteLine(@"
╔══════════════════════════════════════════════════════════════════╗
║  SetFTA - File Type Association Tool                             ║
║  Part of FTA-Manager (https://github.com/feiglein74/FTA-Manager) ║
╚══════════════════════════════════════════════════════════════════╝

USAGE:
  SetFTA.exe <command> [arguments]

COMMANDS:
  set-fta <ProgId> <Extension>     Set file type association
  set-pta <ProgId> <Protocol>      Set protocol association
  get-fta <Extension>              Get current file type association
  get-pta <Protocol>               Get current protocol association
  test-hash <Extension> <ProgId>   Test hash computation (debug)

EXAMPLES:
  SetFTA.exe set-fta ""AcroExch.Document.DC"" "".pdf""
  SetFTA.exe set-fta ""Applications\notepad.exe"" "".txt""
  SetFTA.exe set-pta ""ChromeHTML"" ""http""
  SetFTA.exe set-pta ""ChromeHTML"" ""https""
  SetFTA.exe get-fta "".pdf""
  SetFTA.exe get-pta ""http""

COMMON PROGIDS:
  Browser:
    ChromeHTML              - Google Chrome
    MSEdgeHTM               - Microsoft Edge
    FirefoxURL-*            - Mozilla Firefox

  PDF Reader:
    AcroExch.Document.DC    - Adobe Acrobat Reader DC
    FoxitReader.Document    - Foxit Reader

  General:
    Applications\notepad.exe    - Notepad
    Applications\code.exe       - VS Code

NOTE:
  UCPD (User Choice Protection Driver) blocks changes to:
    - .pdf, .htm, .html extensions
    - http, https protocols

  This tool attempts to bypass UCPD by using direct Win32 API calls
  from a custom executable. This may or may not work depending on
  Windows version and UCPD updates.
");
        }

        static int SetFTA(string[] args)
        {
            if (args.Length < 2)
            {
                Console.WriteLine("Usage: SetFTA.exe set-fta <ProgId> <Extension>");
                Console.WriteLine("Example: SetFTA.exe set-fta \"AcroExch.Document.DC\" \".pdf\"");
                return 1;
            }

            string progId = args[0];
            string extension = args[1];

            if (!extension.StartsWith("."))
            {
                extension = "." + extension;
            }

            Console.WriteLine($"Setting file type association: {extension} -> {progId}");
            Console.WriteLine();

            // Get hash components
            string userSid = UserChoiceHash.GetUserSid();
            string timestamp = UserChoiceHash.GetHexDateTime();
            string hash = UserChoiceHash.ComputeHash(extension, userSid, progId, timestamp);

            Console.WriteLine($"  User SID:  {userSid}");
            Console.WriteLine($"  Timestamp: {timestamp}");
            Console.WriteLine($"  Hash:      {hash}");
            Console.WriteLine();

            // Set ApplicationAssociationToast
            RegistryHelper.SetApplicationAssociationToast(extension, progId);

            // Set the association
            bool success = RegistryHelper.SetFileTypeAssociation(extension, progId, hash);

            if (success)
            {
                // Verify
                var (currentProgId, currentHash) = RegistryHelper.GetFileTypeAssociation(extension);

                if (currentProgId == progId)
                {
                    Console.WriteLine();
                    Console.WriteLine("╔══════════════════════════════════════════════════════════════════╗");
                    Console.WriteLine("║                        SUCCESS                                   ║");
                    Console.WriteLine("╚══════════════════════════════════════════════════════════════════╝");
                    Console.WriteLine();
                    Console.WriteLine($"  {extension} is now associated with {progId}");
                    return 0;
                }
                else
                {
                    Console.WriteLine();
                    Console.WriteLine("[WARN] Registry write succeeded but verification failed.");
                    Console.WriteLine($"  Expected: {progId}");
                    Console.WriteLine($"  Got:      {currentProgId ?? "(null)"}");
                    Console.WriteLine();
                    Console.WriteLine("  This usually means UCPD blocked the change.");
                    return 1;
                }
            }
            else
            {
                Console.WriteLine();
                Console.WriteLine("[FAIL] Could not set file type association.");
                return 1;
            }
        }

        static int SetPTA(string[] args)
        {
            if (args.Length < 2)
            {
                Console.WriteLine("Usage: SetFTA.exe set-pta <ProgId> <Protocol>");
                Console.WriteLine("Example: SetFTA.exe set-pta \"ChromeHTML\" \"http\"");
                return 1;
            }

            string progId = args[0];
            string protocol = args[1].ToLowerInvariant();

            Console.WriteLine($"Setting protocol association: {protocol} -> {progId}");
            Console.WriteLine();

            // Get hash components
            string userSid = UserChoiceHash.GetUserSid();
            string timestamp = UserChoiceHash.GetHexDateTime();
            string hash = UserChoiceHash.ComputeHash(protocol, userSid, progId, timestamp);

            Console.WriteLine($"  User SID:  {userSid}");
            Console.WriteLine($"  Timestamp: {timestamp}");
            Console.WriteLine($"  Hash:      {hash}");
            Console.WriteLine();

            // Set ApplicationAssociationToast
            RegistryHelper.SetApplicationAssociationToast(protocol, progId);

            // Set the association
            bool success = RegistryHelper.SetProtocolAssociation(protocol, progId, hash);

            if (success)
            {
                // Verify
                var (currentProgId, currentHash) = RegistryHelper.GetProtocolAssociation(protocol);

                if (currentProgId == progId)
                {
                    Console.WriteLine();
                    Console.WriteLine("╔══════════════════════════════════════════════════════════════════╗");
                    Console.WriteLine("║                        SUCCESS                                   ║");
                    Console.WriteLine("╚══════════════════════════════════════════════════════════════════╝");
                    Console.WriteLine();
                    Console.WriteLine($"  {protocol}:// is now associated with {progId}");
                    return 0;
                }
                else
                {
                    Console.WriteLine();
                    Console.WriteLine("[WARN] Registry write succeeded but verification failed.");
                    Console.WriteLine($"  Expected: {progId}");
                    Console.WriteLine($"  Got:      {currentProgId ?? "(null)"}");
                    Console.WriteLine();
                    Console.WriteLine("  This usually means UCPD blocked the change.");
                    return 1;
                }
            }
            else
            {
                Console.WriteLine();
                Console.WriteLine("[FAIL] Could not set protocol association.");
                return 1;
            }
        }

        static int GetFTA(string[] args)
        {
            if (args.Length < 1)
            {
                Console.WriteLine("Usage: SetFTA.exe get-fta <Extension>");
                return 1;
            }

            string extension = args[0];
            if (!extension.StartsWith("."))
            {
                extension = "." + extension;
            }

            var (progId, hash) = RegistryHelper.GetFileTypeAssociation(extension);

            Console.WriteLine($"Extension: {extension}");
            Console.WriteLine($"ProgId:    {progId ?? "(not set)"}");
            Console.WriteLine($"Hash:      {hash ?? "(not set)"}");

            return progId != null ? 0 : 1;
        }

        static int GetPTA(string[] args)
        {
            if (args.Length < 1)
            {
                Console.WriteLine("Usage: SetFTA.exe get-pta <Protocol>");
                return 1;
            }

            string protocol = args[0].ToLowerInvariant();

            var (progId, hash) = RegistryHelper.GetProtocolAssociation(protocol);

            Console.WriteLine($"Protocol: {protocol}");
            Console.WriteLine($"ProgId:   {progId ?? "(not set)"}");
            Console.WriteLine($"Hash:     {hash ?? "(not set)"}");

            return progId != null ? 0 : 1;
        }

        static int TestHash(string[] args)
        {
            if (args.Length < 2)
            {
                Console.WriteLine("Usage: SetFTA.exe test-hash <Extension> <ProgId>");
                return 1;
            }

            string extension = args[0];
            string progId = args[1];

            if (!extension.StartsWith(".") && !extension.Contains("://"))
            {
                extension = "." + extension;
            }

            string userSid = UserChoiceHash.GetUserSid();
            string timestamp = UserChoiceHash.GetHexDateTime();
            string hash = UserChoiceHash.ComputeHash(extension, userSid, progId, timestamp);

            Console.WriteLine("Hash Computation Test");
            Console.WriteLine("=====================");
            Console.WriteLine($"Extension/Protocol: {extension}");
            Console.WriteLine($"ProgId:             {progId}");
            Console.WriteLine($"User SID:           {userSid}");
            Console.WriteLine($"Timestamp:          {timestamp}");
            Console.WriteLine($"Computed Hash:      {hash}");

            return 0;
        }
    }
}
