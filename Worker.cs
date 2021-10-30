using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using System;
using System.Diagnostics;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Reflection;
using System.Runtime.InteropServices;
using Microsoft.Diagnostics.Tracing.Session;
using DnsClient.Protocol;
using Newtonsoft.Json;
using System.IO;

namespace VenkmanClient
{
    public class Worker : BackgroundService
    {
        private readonly ILogger<Worker> _logger;

        private static int sysmon_pid = 0;
        private static string sysmon_process_name = "RocketDR";
        private static int vera_pid = 0;
        private static string vera_process_name = "vera";

        public Worker(ILogger<Worker> logger)
        {
            _logger = logger;
        }

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            _logger.LogInformation("Punch the clock! Venkman came to work at: {time}", DateTimeOffset.Now);

            Thread PKEMeter_thread = new Thread(new ThreadStart(ETWMonitor))
            {
                IsBackground = true
            };
            _logger.LogInformation("Venkman created a new PKE Meter");
            try
            {
                PKEMeter_thread.Start();
                _logger.LogInformation("PKE Meter started in the background");
            }
            catch (SystemException err)
            {
                _logger.LogError("Exception occurred while starting PKE Meter: {0}", err.Message);
            }

            while (!stoppingToken.IsCancellationRequested)
            {
                
                await Task.Delay(1000, stoppingToken);
            }
            _logger.LogInformation("Shutting down PKE Meter");
        }

        static void ETWMonitor()
        {
            // ETW Providers to monitor in the default configuration (if no config is available by DNS)
            const string WinINet = "Microsoft-Windows-WinINet";
            const string KernelProcess = "Microsoft-Windows-Kernel-Process";
            const string KernelFile = "Microsoft-Windows-Kernel-File";

            string[] DefaultProviderList = new string[3] { WinINet, KernelProcess, KernelFile };
            string[] ProviderList = DefaultProviderList;

            while (true)
            {
                // Dictionary to hold ETW count indexed by PID
                Dictionary<int, Dictionary<string, int>> ParanormalDatabase = new Dictionary<int, Dictionary<string, int>> ();
                // Dictionary to hold process name indexed by PID
                Dictionary<int, string> ProcessNames = new Dictionary<int, string>();

                // Now go through all running processes and create entries for each one
                Process[] allProcesses = Process.GetProcesses();
                Console.WriteLine("Venkman: making note of {0} processes.", (allProcesses.Length).ToString());
                foreach (Process proc in allProcesses)
                {
                    if (proc.ProcessName == sysmon_process_name)
                    {
                        sysmon_pid = proc.Id;
                    }
                    if (proc.ProcessName == vera_process_name)
                    {
                        vera_pid = proc.Id;
                    }

                    // Create an entry in the ETW count dictionary 
                    if (!ParanormalDatabase.ContainsKey(proc.Id))
                    {
                        ParanormalDatabase[proc.Id] = new Dictionary<string, int>(); // holds ETW event counts of each type per process
                        foreach (string provider in ProviderList)
                        {
                            ParanormalDatabase[proc.Id][provider] = 0;
                        }
                    }
                    
                    // Create an entry in the process names dictionary
                    if (!ProcessNames.ContainsKey(proc.Id))
                    {
                        ProcessNames[proc.Id] = proc.ProcessName;
                    }
                }

                var containmentUnitLock = new object();
               // var GhostSurvey = Task.Run(() =>
                //{
                if (true) { 
                    TraceEventSession Aurascope = null;

                    using (Aurascope = new TraceEventSession("VenkmanAurascope", TraceEventSessionOptions.Create))
                    {
                        Console.CancelKeyPress += (object sender, ConsoleCancelEventArgs cancelArgs) =>
                        {
                            if (Aurascope != null)
                            {
                                Aurascope.Dispose();
                            }
                            cancelArgs.Cancel = false;
                        };

                        // Get logging share path from DNS TXT record
                        var domainName = System.Net.NetworkInformation.IPGlobalProperties.GetIPGlobalProperties().DomainName;
                        var txtFQDN = Ecto1.Default.DNSPath + "." + domainName;
                        var etwFQDN = Ecto1.Default.DNSETW + "." + domainName;
                        var lookup = new DnsClient.LookupClient();
                        var result = lookup.Query(txtFQDN, DnsClient.QueryType.TXT);
                        var record = result.Answers.OfType<TxtRecord>().FirstOrDefault();
                        string logPath = record?.Text.FirstOrDefault();

                        if (null == logPath || logPath.Length < 5)
                        {
                            logPath = Ecto1.Default.DefaultLogPath;
                        }

                        Console.WriteLine("Path to save logs: {0}", logPath);

                        // Get the names of ETW providers from DNS TXT record
                        result = lookup.Query(etwFQDN, DnsClient.QueryType.TXT);
                        record = result.Answers.OfType<TxtRecord>().FirstOrDefault();
                        string etwProvidersConfigString = record?.Text.FirstOrDefault();
                        if (null == etwProvidersConfigString || etwProvidersConfigString.Length < 5)
                        {
                            ProviderList = DefaultProviderList;
                        }
                        else
                        {
                            ProviderList = etwProvidersConfigString.Split("|");
                        }



                        // Start scanning for paranormal activity
                        foreach (string provider in ProviderList)
                        {
                            Console.WriteLine("Attempting to enable ETW subscription for provider: {0}", provider);
                            try
                            {
                                Aurascope.EnableProvider(provider, Microsoft.Diagnostics.Tracing.TraceEventLevel.Verbose, 0x00);
                            } catch (SystemException err)
                            {
                                Console.WriteLine("Encountered an error while enabling provider {0}", provider);
                                Console.WriteLine(err.Message);
                            }
                            
                        }
                        // Aurascope.EnableProvider(WinINet, Microsoft.Diagnostics.Tracing.TraceEventLevel.Informational);
                        // Aurascope.EnableProvider(KernelProcess, Microsoft.Diagnostics.Tracing.TraceEventLevel.Informational, 0x00);
                        // Aurascope.EnableProvider(KernelFile, Microsoft.Diagnostics.Tracing.TraceEventLevel.Informational, 0x00);

                        var scopeReader = Aurascope.Source.Dynamic;

                        Stopwatch stopwatch = new Stopwatch();
                        stopwatch.Start();
                      
                        scopeReader.All += e =>
                        {
                            try
                            {
                                if (!ProcessNames.ContainsKey(e.ProcessID) && e.ProcessName != "")
                                {
                                    ProcessNames[e.ProcessID] = e.ProcessName;
                                }
                                if (!ParanormalDatabase.ContainsKey(e.ProcessID))
                                {
                                    ParanormalDatabase.Add(e.ProcessID,
                                                           new Dictionary<string, int>()); // add it if we don't already have this process
                                                                                           // set starting value of each event count to 0
                                    
                                    foreach (string provider in ProviderList)
                                    {
                                        ParanormalDatabase[e.ProcessID][provider] = 0;
                                    }
                                }
                                if (!ParanormalDatabase[e.ProcessID].ContainsKey(e.ProviderName))
                                {
                                    ParanormalDatabase[e.ProcessID][e.ProviderName] = 0;
                                }
                                // Add one to the event counter for that process and provider name
                                ParanormalDatabase[e.ProcessID][e.ProviderName] += 1;

                            }
                            catch (SystemException err)
                            { // TODO: handle exceptions
                                Console.Write("Exception while looking in ETW event for processID and processName: ");
                                Console.WriteLine(err.Message);
                            }
                            if (stopwatch.Elapsed.TotalSeconds > 60.0)
                            {
                                Aurascope.Source.StopProcessing(); // causes Process() call to return when timer goes off
                            }
                        };
                        Aurascope.Source.Process(); // magic happens

                        // Serialize to JSON
                        //string output = JsonConvert.SerializeObject(ParanormalDatabase);
                        string hostname = System.Net.Dns.GetHostName();
                        string logfilename = hostname + ".txt";
                        string[] paths = { logPath, logfilename };
                        string logFilePath = System.IO.Path.Combine(paths);
                        string ISO8601_Date = DateTime.UtcNow.ToString("o");

                        Console.WriteLine("Preparing to write event counts to log file {0}", logFilePath);
                        System.IO.StreamWriter w;
                        try
                        {
                            using (w = File.AppendText(logFilePath))
                            {
                                // Write the ETW Provider names that apply to the following set of process event counts
                                w.Write("\n#Date|Hostname|PID|ProcessName|" + String.Join('|', ProviderList) + "|Total");
                                w.Close();
                            }
                              
                        }
                        catch (SystemException err)
                        {
                            Console.Write("Exception caught when writing to log file: ");
                            Console.WriteLine(err.Message);
                        }
                        // Now write one line for each of the processes we're tracking
                        foreach (KeyValuePair<int, Dictionary<string, int>> entry in ParanormalDatabase)
                        {
                            int pid = entry.Key;
                            var processName = (ProcessNames.ContainsKey(pid) ? ProcessNames[pid] : "(unknown)");
                            try
                            {

                                using (w = File.AppendText(logFilePath))
                                {
                                    w.Write($"\n{ISO8601_Date}" + "|" + hostname + "|" + pid.ToString() + "|" + processName);
                                    // Write the counts and the total
                                    int totalCount = 0;
                                    foreach (string providerName in ProviderList)
                                    {
                                        if (entry.Value.ContainsKey(providerName))
                                        {
                                            w.Write("|" + entry.Value[providerName].ToString());
                                            totalCount += entry.Value[providerName];
                                        }
                                        else
                                        {
                                            w.Write("|0");
                                        }
                                    }
                                    w.Write("|" + totalCount.ToString()); // last value is the total of all ETW event counts
                                    w.Close();
                                }
                            }
                            catch
                            {}
           
                        }
                        Console.WriteLine("Done writing output to log!");
                    }
                }//);
            }
        }


        public enum ThreadAccess : int
        {
            TERMINATE = (0x0001),
            SUSPEND_RESUME = (0x0002),
            GET_CONTEXT = (0x0008),
            SET_CONTEXT = (0x0010),
            SET_INFORMATION = (0x0020),
            QUERY_INFORMATION = (0x0040),
            SET_THREAD_TOKEN = (0x0080),
            IMPERSONATE = (0x0100),
            DIRECT_IMPERSONATION = (0x0200)
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern int SuspendThread(IntPtr hThread);

        [DllImport("kernel32.dll")]
        static extern IntPtr OpenThread(ThreadAccess dwDesiredAccess, bool bInheritHandle, uint dwThreadId);
    }

   
}
