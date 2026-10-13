using System;
using System.Runtime.InteropServices;
using System.Security;

// Documented local Windows APIs only. No unjoin, account reuse or registry writes.
public static class SP2MachineAccountRecovery
{
    public const uint JoinFlags = 0x00000001 | 0x00000002 | 0x00000020 |
                                 0x00000400 | 0x00020000;

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool SetComputerNameEx(int type, string name);

    [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
    private static extern uint NetJoinDomain(string server, string domain, string ou,
                                            string account, IntPtr password, uint options);

    public static uint Join(string name, string domain, string ou, string account,
                            SecureString password)
    {
        // ComputerNamePhysicalDnsHostname: stage the name through the supported API.
        // If join fails the staged name is uncertain; reconcile, never blindly undo.
        if (!SetComputerNameEx(5, name))
            return (uint)Marshal.GetLastWin32Error();
        IntPtr secret = IntPtr.Zero;
        try
        {
            secret = Marshal.SecureStringToGlobalAllocUnicode(password);
            return NetJoinDomain(null, domain, ou, account, secret, JoinFlags);
        }
        finally
        {
            if (secret != IntPtr.Zero) Marshal.ZeroFreeGlobalAllocUnicode(secret);
        }
    }
}
