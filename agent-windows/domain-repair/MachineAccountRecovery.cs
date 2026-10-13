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


// Query the device registration state using Microsoft's native Windows API.
// This avoids parsing localized/encoded output from "dsregcmd /status".
// No registration, unjoin, credential handling, network or registry writes.
public static class SP2NativeCloudJoin
{
    private const int DeviceJoin = 1;
    private const int WorkplaceJoin = 2;

    [DllImport("netapi32.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    private static extern int NetGetAadJoinInformation(string tenantId,
                                                       out IntPtr joinInfo);

    [DllImport("netapi32.dll", ExactSpelling = true)]
    private static extern void NetFreeAadJoinInformation(IntPtr joinInfo);

    // Returns 1 for device Entra join, 0 for no device join.
    // Throws when the Windows API cannot determine an authoritative state.
    public static int GetDeviceJoinState()
    {
        IntPtr info = IntPtr.Zero;
        try
        {
            int hr = NetGetAadJoinInformation(null, out info);
            // HRESULT S_FALSE (1) is not failure. Windows may use it when
            // there is no cloud registration; success is any hr >= 0.
            if (hr < 0)
                throw new InvalidOperationException("Entra status unavailable (HRESULT " +
                                                    ((uint)hr).ToString("X8") + ")");
            if (info == IntPtr.Zero)
                return 0;

            // DSREG_JOIN_INFO starts with the 32-bit DSREG_JOIN_TYPE enum.
            // Do not marshal account/tenant identifiers: no need to read them.
            int joinType = Marshal.ReadInt32(info);
            if (joinType == DeviceJoin)
                return 1;
            if (joinType == WorkplaceJoin)
                return 0; // User workplace registration != device Entra join.
            throw new InvalidOperationException("Unrecognized Entra device join type");
        }
        finally
        {
            if (info != IntPtr.Zero)
                NetFreeAadJoinInformation(info);
        }
    }
}
