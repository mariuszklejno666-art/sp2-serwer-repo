using System;
using System.Diagnostics;
using System.IO;
using System.Windows.Forms;

internal static class Launcher
{
    [STAThread]
    private static int Main(string[] args)
    {
        try
        {
            string script = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "SP2-Serwis-Domeny.ps1");
            if (!File.Exists(script)) throw new FileNotFoundException("Missing companion script");
            bool test = args.Length == 1 && args[0] == "--self-test";
            string exe = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), @"System32\WindowsPowerShell\v1.0\powershell.exe");
            var start = new ProcessStartInfo(exe, "-NoProfile -STA -ExecutionPolicy RemoteSigned -File \"" + script + "\"" + (test ? " -SelfTest" : ""));
            start.UseShellExecute = !test;
            if (!test) start.Verb = "runas";
            start.WorkingDirectory = AppDomain.CurrentDomain.BaseDirectory;
            using (Process child = Process.Start(start))
            {
                child.WaitForExit();
                if (child.ExitCode != 0) throw new InvalidOperationException("PowerShell exit " + child.ExitCode);
            }
            return 0;
        }
        catch (Exception error)
        {
            string log = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "SP2-Domain-Recovery-launcher.log");
            File.AppendAllText(log, DateTime.UtcNow.ToString("o") + " " + error.GetType().Name + Environment.NewLine);
            MessageBox.Show("Nie uruchomiono programu. Wypakuj caly ZIP. Sprawdz podpis/skrypt, polityke PowerShell i zgode UAC. Log: " + log, "SP2 Serwis Domeny");
            return 1;
        }
    }
}
