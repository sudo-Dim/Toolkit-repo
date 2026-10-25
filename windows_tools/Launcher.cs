using System;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Reflection;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Windows.Forms;

internal static class Launcher
{
    [STAThread]
    private static int Main(string[] args)
    {
#if DEBLOAT
        const string tool = "Debloat";
#else
        const string tool = "Diagnostic";
#endif
        bool selfTest = args.Length == 1 && args[0] == "--self-test";
        if (args.Length > 0 && !selfTest) return 2;
        string folder = Path.Combine(Path.GetTempPath(), "Toolkit-" + Guid.NewGuid().ToString("N"));
        try
        {
            WindowsIdentity identity = WindowsIdentity.GetCurrent();
            bool elevated = new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
            string system = Environment.GetFolderPath(Environment.SpecialFolder.System);
            if (elevated) folder = Path.Combine(Path.GetDirectoryName(system), "Temp", "Toolkit-" + Guid.NewGuid().ToString("N"));
            if (folder.StartsWith(@"\\", StringComparison.Ordinal)) throw new IOException("Network temporary directories are not allowed.");
            DirectorySecurity access = new DirectorySecurity();
            access.SetAccessRuleProtection(true, false);
            SecurityIdentifier owner = elevated ? new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null) : identity.User;
            access.SetOwner(owner);
            InheritanceFlags inherit = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;
            access.AddAccessRule(new FileSystemAccessRule(owner, FileSystemRights.FullControl, inherit, PropagationFlags.None, AccessControlType.Allow));
            access.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null), FileSystemRights.FullControl, inherit, PropagationFlags.None, AccessControlType.Allow));
            Directory.CreateDirectory(folder, access);
            Assembly assembly = Assembly.GetExecutingAssembly();
            foreach (string name in assembly.GetManifestResourceNames())
            {
                string path = Path.Combine(folder, name.Replace('/', Path.DirectorySeparatorChar));
                Directory.CreateDirectory(Path.GetDirectoryName(path));
                using (Stream resource = assembly.GetManifestResourceStream(name))
                using (GZipStream source = new GZipStream(resource, CompressionMode.Decompress))
                using (FileStream target = File.Create(path)) source.CopyTo(target);
            }
            string powershell = Path.Combine(system, @"WindowsPowerShell\v1.0\powershell.exe");
            ProcessStartInfo start = new ProcessStartInfo(powershell);
            start.Arguments = "-NoLogo -NoProfile -NonInteractive -STA -ExecutionPolicy Bypass -File \""
                + Path.Combine(folder, "Start-Tool.ps1") + "\" -Tool " + tool + (selfTest ? " -SmokeTest" : "");
            start.WorkingDirectory = folder;
            start.UseShellExecute = false;
            start.CreateNoWindow = true;
            start.RedirectStandardError = true;
            // Elevated tools must not autoload attacker-controlled modules from Documents.
            start.EnvironmentVariables["PSModulePath"] = Path.Combine(system, @"WindowsPowerShell\v1.0\Modules");
            start.EnvironmentVariables["PATH"] = system + ";" + Path.GetDirectoryName(powershell);
            start.EnvironmentVariables["SystemRoot"] = Path.GetDirectoryName(system);
            start.EnvironmentVariables["WINDIR"] = Path.GetDirectoryName(system);
            start.EnvironmentVariables["TEMP"] = folder;
            start.EnvironmentVariables["TMP"] = folder;
            using (Process process = Process.Start(start))
            {
                // Drain before waiting: a full error pipe must not block the child process.
                string error = process.StandardError.ReadToEnd();
                process.WaitForExit();
                if (process.ExitCode != 0)
                {
                    if (!selfTest) MessageBox.Show(error.Length > 0 ? error : "PowerShell konnte nicht gestartet werden.", tool, MessageBoxButtons.OK, MessageBoxIcon.Error);
                    return process.ExitCode;
                }
            }
            return 0;
        }
        catch (Exception error)
        {
            if (!selfTest) MessageBox.Show(error.Message, tool, MessageBoxButtons.OK, MessageBoxIcon.Error);
            return 1;
        }
        finally
        {
            try { if (Directory.Exists(folder)) Directory.Delete(folder, true); }
            catch (IOException) { }
            catch (UnauthorizedAccessException) { }
        }
    }
}
