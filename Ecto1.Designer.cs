﻿//------------------------------------------------------------------------------
// <auto-generated>
//     This code was generated by a tool.
//     Runtime Version:4.0.30319.42000
//
//     Changes to this file may cause incorrect behavior and will be lost if
//     the code is regenerated.
// </auto-generated>
//------------------------------------------------------------------------------

namespace VenkmanClient {
    
    
    [global::System.Runtime.CompilerServices.CompilerGeneratedAttribute()]
    [global::System.CodeDom.Compiler.GeneratedCodeAttribute("Microsoft.VisualStudio.Editors.SettingsDesigner.SettingsSingleFileGenerator", "16.8.1.0")]
    internal sealed partial class Ecto1 : global::System.Configuration.ApplicationSettingsBase {
        
        private static Ecto1 defaultInstance = ((Ecto1)(global::System.Configuration.ApplicationSettingsBase.Synchronized(new Ecto1())));
        
        public static Ecto1 Default {
            get {
                return defaultInstance;
            }
        }
        
        [global::System.Configuration.ApplicationScopedSettingAttribute()]
        [global::System.Diagnostics.DebuggerNonUserCodeAttribute()]
        [global::System.Configuration.DefaultSettingValueAttribute("venkman-logs-path")]
        public string DNSPath {
            get {
                return ((string)(this["DNSPath"]));
            }
        }
        
        [global::System.Configuration.ApplicationScopedSettingAttribute()]
        [global::System.Diagnostics.DebuggerNonUserCodeAttribute()]
        [global::System.Configuration.DefaultSettingValueAttribute("\\\\HQ-DC1\\Logs\\Heartbeat\\")]
        public string DefaultLogPath {
            get {
                return ((string)(this["DefaultLogPath"]));
            }
        }
        
        [global::System.Configuration.ApplicationScopedSettingAttribute()]
        [global::System.Diagnostics.DebuggerNonUserCodeAttribute()]
        [global::System.Configuration.DefaultSettingValueAttribute("venkman-etw-providers")]
        public string DNSETW {
            get {
                return ((string)(this["DNSETW"]));
            }
        }
    }
}