using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Security.Principal;
using System.Windows.Forms;

// One portable .exe with embedded, versioned PowerShell/native recovery assets.
// It requires only Windows PowerShell 5.1 + .NET Framework on supported Windows.
// The protected ProgramData working directory preserves scheduled-task resume
// and existing pending.json/auth.json/device-id.txt across restarts.
internal static class PortableLauncher
{
    private sealed class EmbeddedAsset
    {
        public readonly string ResourceName;
        public readonly string OutputFile;

        public EmbeddedAsset(string resourceName, string outputFile)
        {
            ResourceName = resourceName;
            OutputFile = outputFile;
        }
    }

    // Public SP2 CA trust anchor: the DER SHA-256 fingerprint, not an unsigned file name.
    private const string SchoolCaFingerprint =
        "45581ba7ef494ddce73702c8f7f4174a5f8309ddf342f12b78c7a097f2bbcd33";

    private static readonly EmbeddedAsset[] Assets = new EmbeddedAsset[]
    {
        new EmbeddedAsset("SP2.Portable.Main", "SP2-Serwis-Domeny.ps1"),
        new EmbeddedAsset("SP2.Portable.Entra", "SP2-Entra-Transition.ps1"),
        new EmbeddedAsset("SP2.Portable.NativeSource", "MachineAccountRecovery.cs"),
        new EmbeddedAsset("SP2.Portable.NativeDll", "SP2MachineAccountRecovery.dll")
    };

    [STAThread]
    private static int Main(string[] args)
    {
        bool selfTest = args.Length == 1 &&
            string.Equals(args[0], "--self-test", StringComparison.OrdinalIgnoreCase);
        if (args.Length != 0 && !selfTest)
        {
            MessageBox.Show("Nieznany parametr programu.", "SP2 Serwis Domeny");
            return 2;
        }

        try
        {
            byte[][] contents = new byte[Assets.Length][];
            for (int i = 0; i < Assets.Length; i++)
            {
                contents[i] = ReadEmbedded(Assets[i].ResourceName);
                if (contents[i].Length < 500)
                    throw new InvalidDataException("Incomplete embedded resource");
            }

            // A production distribution may ship the *public* CA beside the EXE.
            // Verify its pinned DER fingerprint before writing it under ProgramData.
            byte[] schoolCa = ReadOptionalSchoolCa();
            string versionHash = BundleHash(contents, schoolCa).Substring(0, 20);
            if (selfTest)
            {
                // The CI self-test validates all four embedded resources without
                // modifying Windows, opening network connections or joining AD.
                if (contents[0].Length < 10000 || contents[1].Length < 1000 ||
                    contents[3].Length < 1000)
                    throw new InvalidDataException("Embedded resource size mismatch");
                if (contents[0][0] != 0xEF || contents[0][1] != 0xBB ||
                    contents[0][2] != 0xBF)
                    throw new InvalidDataException("PowerShell 5.1 UTF-8 BOM missing");
                return 0;
            }

            if (!IsElevated())
                return ElevateSelf();

            string baseRoot = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                "SP2-Domain-Recovery");
            string runtimeParent = Path.Combine(baseRoot, "PortableRuntime");
            string runtimeDir = Path.Combine(runtimeParent, "v-" + versionHash);

            // Only administrators and SYSTEM can edit the executable scripts.
            // Existing state and credentials are never deleted or overwritten.
            CreateProtectedDirectory(baseRoot);
            CreateProtectedDirectory(runtimeParent);
            CreateProtectedDirectory(runtimeDir);
            for (int i = 0; i < Assets.Length; i++)
            {
                WriteVerifiedAsset(
                    Path.Combine(runtimeDir, Assets[i].OutputFile), contents[i]);
            }
            if (schoolCa != null)
                WriteVerifiedAsset(
                    Path.Combine(runtimeDir, "sp2-internal-ca.crt"), schoolCa);

            string ps = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.Windows),
                @"System32\WindowsPowerShell\v1.0\powershell.exe");
            string script = Path.Combine(runtimeDir, "SP2-Serwis-Domeny.ps1");
            if (!File.Exists(ps))
                throw new FileNotFoundException("Windows PowerShell 5.1 unavailable");

            ProcessStartInfo info = new ProcessStartInfo(
                ps, "-NoProfile -STA -ExecutionPolicy RemoteSigned -File \"" + script + "\"");
            info.UseShellExecute = true;
            info.WorkingDirectory = runtimeDir;
            using (Process process = Process.Start(info))
            {
                if (process == null)
                    throw new InvalidOperationException("Could not start PowerShell");
                process.WaitForExit();
                int code = process.ExitCode;
                if (code != 0)
                {
                    // PowerShell may exit before creating the GUI (for example when
                    // a previous SP2 instance holds the global mutex). The launcher
                    // must not silently vanish on a failed child process.
                    LogError("PowerShellExit_" + code.ToString());
                    if (code != 12 && code != 13) // PowerShell already displayed the mutex occupied / access denied dialog.
                    {
                        MessageBox.Show(
                            "SP2 Serwis Domeny zakonczyl dzialanie przed otwarciem okna. " +
                            "Kod PowerShell: " + code.ToString() + ".\n\n" +
                            "Zamknij starsze instancje SP2 Serwis Domeny i uruchom program ponownie. " +
                            "Jesli problem pozostanie, sprawdz:\n" +
                            "C:\\ProgramData\\SP2-Domain-Recovery\\crash.log\n" +
                            "%LOCALAPPDATA%\\SP2-Domain-Recovery-portable-launcher.log\n\n" +
                            "Nie usuwaj pending.json ani nie powtarzaj join.",
                            "SP2 Serwis Domeny - Portable", MessageBoxButtons.OK,
                            MessageBoxIcon.Warning);
                    }
                }
                return code;
            }
        }
        catch (System.ComponentModel.Win32Exception error)
        {
            // Codes, unlike exception strings, do not expose account names or secrets.
            int code = error.NativeErrorCode;
            LogError("Win32Exception_" + code.ToString());
            if (!selfTest)
            {
                MessageBox.Show(
                    GetSafeWin32StartupMessage(code),
                    "SP2 Serwis Domeny - Portable", MessageBoxButtons.OK,
                    MessageBoxIcon.Error);
            }
            return 1;
        }
        catch (Exception error)
        {
            // Do not write exception details or command arguments to logs:
            // they may contain sensitive workstation/account information.
            LogError(error.GetType().Name);
            if (!selfTest)
            {
                MessageBox.Show(
                    "Nie uruchomiono SP2 Serwis Domeny. Sprawdz uprawnienia administratora, " +
                    "Windows PowerShell 5.1 i polityke wykonywania skryptow. " +
                    "Nie usuwaj zapisanej naprawy z ProgramData.",
                    "SP2 Serwis Domeny - Portable", MessageBoxButtons.OK,
                    MessageBoxIcon.Error);
            }
            return 1;
        }
    }

    private static string GetSafeWin32StartupMessage(int code)
    {
        string general =
            "Nie mozna uruchomic SP2 Serwis Domeny. Kod Windows: " +
            code.ToString() + ".\n";
        switch (code)
        {
            case 1223:
                return general +
                    "Anulowano potwierdzenie UAC. Uruchom z konta administratora Windows. " +
                    "Nie usuwaj pending.json ani zapisanej naprawy.";
            case 5:
                return general +
                    "Odmowa dostepu. Konto Windows moze nie miec pelnych uprawnien " +
                    "administratora lub blokade utrzymuje wczesniejsza instancja. " +
                    "Zamknij stare okna SP2 i sprawdz UAC; nie zmieniaj ACL ProgramData.";
            case 740:
                return general +
                    "Windows wymaga podniesienia uprawnien (UAC). " +
                    "Uruchom Portable jako administrator.";
            default:
                return general +
                    "Sprawdz konto administratora Windows, zgode UAC, dzialajace " +
                    "instancje SP2 i dziennik portable-launcher.log. " +
                    "Nie usuwaj pending.json ani nie ponawiaj join.";
        }
    }

    private static bool IsElevated()
    {
        using (WindowsIdentity identity = WindowsIdentity.GetCurrent())
        {
            WindowsPrincipal principal = new WindowsPrincipal(identity);
            return principal.IsInRole(WindowsBuiltInRole.Administrator);
        }
    }

    private static int ElevateSelf()
    {
        ProcessStartInfo info = new ProcessStartInfo(
            Assembly.GetExecutingAssembly().Location);
        info.UseShellExecute = true;
        info.Verb = "runas";
        using (Process process = Process.Start(info))
        {
            if (process == null)
                throw new InvalidOperationException("UAC elevation failed");
            process.WaitForExit();
            return process.ExitCode;
        }
    }

    private static byte[] ReadEmbedded(string name)
    {
        using (Stream input = Assembly.GetExecutingAssembly().GetManifestResourceStream(name))
        {
            if (input == null)
                throw new InvalidDataException("Missing embedded resource");
            using (MemoryStream output = new MemoryStream())
            {
                byte[] buffer = new byte[8192];
                int n;
                while ((n = input.Read(buffer, 0, buffer.Length)) > 0)
                    output.Write(buffer, 0, n);
                return output.ToArray();
            }
        }
    }

    private static byte[] ReadOptionalSchoolCa()
    {
        // A production portable build can embed the known *public* CA.
        // Sidecar mode remains supported for existing stand-alone releases.
        byte[] embeddedCa = null;
        using (Stream resource = Assembly.GetExecutingAssembly()
            .GetManifestResourceStream("SP2.Portable.SchoolCa"))
        {
            if (resource != null)
            {
                using (MemoryStream memory = new MemoryStream())
                {
                    byte[] buffer = new byte[8192];
                    int count;
                    while ((count = resource.Read(buffer, 0, buffer.Length)) > 0)
                        memory.Write(buffer, 0, count);
                    embeddedCa = memory.ToArray();
                }
            }
        }
        if (embeddedCa != null)
            VerifySchoolCaBytes(embeddedCa);

        string source = Path.Combine(
            Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location),
            "sp2-internal-ca.crt");
        if (File.Exists(source))
        {
            if ((File.GetAttributes(source) & FileAttributes.ReparsePoint) != 0)
                throw new IOException("Unsafe school CA file redirect");
            byte[] sidecar = File.ReadAllBytes(source);
            VerifySchoolCaBytes(sidecar);
            return embeddedCa ?? sidecar;
        }
        return embeddedCa;
    }

    private static void VerifySchoolCaBytes(byte[] fileBytes)
    {
        if (fileBytes.Length < 500 || fileBytes.Length > 131072)
            throw new InvalidDataException("Unexpected CA file size");

        // .NET Framework 4.x accepts DER reliably. Decode an ASCII PEM
        // explicitly and reject unrelated/multiple PEM objects.
        byte[] der = fileBytes;
        string pem = Encoding.ASCII.GetString(fileBytes).Trim();
        const string begin = "-----BEGIN CERTIFICATE-----";
        const string end = "-----END CERTIFICATE-----";
        if (pem.Contains(begin) || pem.Contains(end))
        {
            if (!pem.StartsWith(begin, StringComparison.Ordinal) ||
                !pem.EndsWith(end, StringComparison.Ordinal))
                throw new InvalidDataException("Unexpected school CA PEM content");
            string base64 = pem.Substring(begin.Length, pem.Length - begin.Length - end.Length);
            der = Convert.FromBase64String(base64);
        }

        using (X509Certificate2 ca = new X509Certificate2(der))
        using (SHA256 sha = SHA256.Create())
        {
            string digest = Hex(sha.ComputeHash(ca.RawData));
            if (!string.Equals(digest, SchoolCaFingerprint, StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("School CA fingerprint mismatch");
            if (!string.Equals(ca.Subject, "CN=SP2 ADMIN Internal CA", StringComparison.Ordinal) ||
                !string.Equals(ca.Issuer, ca.Subject, StringComparison.Ordinal) ||
                ca.NotBefore > DateTime.Now || ca.NotAfter < DateTime.Now)
                throw new InvalidDataException("School CA identity or validity mismatch");
            bool isCa = false;
            foreach (X509Extension extension in ca.Extensions)
            {
                if (extension.Oid.Value == "2.5.29.19")
                {
                    X509BasicConstraintsExtension basic =
                        new X509BasicConstraintsExtension(extension, extension.Critical);
                    isCa = basic.CertificateAuthority;
                }
                if (extension.Oid.Value == "2.5.29.15")
                {
                    X509KeyUsageExtension usage =
                        new X509KeyUsageExtension(extension, extension.Critical);
                    if ((usage.KeyUsages & X509KeyUsageFlags.KeyCertSign) == 0)
                        throw new InvalidDataException("School CA cannot sign certificates");
                }
            }
            if (!isCa)
                throw new InvalidDataException("School CA missing CA basic constraint");
        }
    }

    private static string BundleHash(byte[][] contents, byte[] schoolCa)
    {
        using (MemoryStream input = new MemoryStream())
        {
            for (int i = 0; i < contents.Length; i++)
                input.Write(contents[i], 0, contents[i].Length);
            if (schoolCa != null)
                input.Write(schoolCa, 0, schoolCa.Length);
            using (SHA256 sha = SHA256.Create())
                return Hex(sha.ComputeHash(input.ToArray()));
        }
    }

    private static string Hex(byte[] bytes)
    {
        char[] table = "0123456789abcdef".ToCharArray();
        char[] result = new char[bytes.Length * 2];
        for (int i = 0; i < bytes.Length; i++)
        {
            result[2 * i] = table[bytes[i] >> 4];
            result[2 * i + 1] = table[bytes[i] & 15];
        }
        return new string(result);
    }

    private static bool Identical(byte[] left, byte[] right)
    {
        if (left.Length != right.Length)
            return false;
        for (int i = 0; i < left.Length; i++)
            if (left[i] != right[i])
                return false;
        return true;
    }

    private static void CreateProtectedDirectory(string path)
    {
        if (Directory.Exists(path))
        {
            if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
                throw new IOException("Unsafe directory redirect");
        }
        else if (File.Exists(path))
        {
            throw new IOException("Runtime directory is occupied by a file");
        }

        Directory.CreateDirectory(path);
        DirectorySecurity acl = new DirectorySecurity();
        acl.SetAccessRuleProtection(true, false);
        foreach (string sid in new string[] { "S-1-5-18", "S-1-5-32-544" })
        {
            acl.AddAccessRule(new FileSystemAccessRule(
                new SecurityIdentifier(sid), FileSystemRights.FullControl,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                PropagationFlags.None, AccessControlType.Allow));
        }
        Directory.SetAccessControl(path, acl);
    }

    private static void WriteVerifiedAsset(string destination, byte[] bytes)
    {
        if (Directory.Exists(destination))
            throw new IOException("Asset path is a directory");
        if (File.Exists(destination))
        {
            if ((File.GetAttributes(destination) & FileAttributes.ReparsePoint) != 0)
                throw new IOException("Unsafe asset redirect");
            if (Identical(File.ReadAllBytes(destination), bytes))
                return;
        }

        string temporary = destination + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            File.WriteAllBytes(temporary, bytes);
            if (File.Exists(destination))
                File.Delete(destination);
            File.Move(temporary, destination);
            if (!Identical(File.ReadAllBytes(destination), bytes))
                throw new IOException("Extracted asset verification failed");
        }
        finally
        {
            if (File.Exists(temporary))
                File.Delete(temporary);
        }
    }

    private static void LogError(string errorType)
    {
        try
        {
            string location = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "SP2-Domain-Recovery-portable-launcher.log");
            File.AppendAllText(
                location,
                DateTime.UtcNow.ToString("o") + " " + errorType + Environment.NewLine);
        }
        catch { }
    }
}
