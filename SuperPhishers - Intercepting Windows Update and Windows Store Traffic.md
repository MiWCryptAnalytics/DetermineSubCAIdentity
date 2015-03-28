SuperPhishers PoC :: DetermineSubCAIdentity Bypass
===============================================
## bypass Windows Update Code 80245006, Microsoft CA check ##
### or How to intercept Windows Update and Windows Store Traffic ###

- https://skydrive.live.com/redir?resid=817C744373ADD084!165 (script + Deviare2 bins)
- https://www.github.com/MiWCryptAnalytics/DetermineSubCAIdentity (python script authoritative)
- https://www.youtube.com/watch?v=EyDaTkU2sKY  (PoC video)

###by _MiW, March 2015###

    Is your internet connection SSL intercepted? 
    Maybe by choice, maybe by force;
    Maybe for debugging, Maybe for spying...

## Intro ##
Since the Lenovo SuperFish outrage of Feb 2015, 
I have been researching SSL interception software and countermeasures to determine what fails even 
when a Trusted Certificate is installed in the Trust Store.

Windows Update and Windows store have long been known to be interception resistant. Microsoft had added additional checks to critical update code to ensure that only an expected certificate is used from Microsoft Store and Update front ends, even in the event a Trusted Root Certificate has been deployed by domain or Group Policy Objects.
It does not do this by Certificate Pinning, as expected, but by checking the issuer cert to determine if it is the expected 'SubCA' of Microsoft.

Most commonly this will manifest as 
Windows Update Code 80245006 
"Windows Update ran into a problem"

## Tool ##
DetermineSubCAIdentity.py is a tool that patches the call to DetermineSubCAIdentity in wuaueng.dll, 
which check that the chain root of the certificate presented over https links to a Microsoft CA.
It does this by using Nektra Deviare2 to intercept calls to this function and leave the CPU registers in the right Microsoft CA state.

Additionally, there is a check in storewuauth.dll of the same name that prevents applications from installing over an intercepted connection. This can also be bypassed.

Ultimately this allows Windows Update and Windows Store traffic to be intercepted (ie: standard Certificate Substitution, SSL Interception/Inspection) and the Microsoft signature check on binaries be bypassed if required. 

Released is a video to demonstrate PoC.

[https://www.youtube.com/watch?v=EyDaTkU2sKY](https://www.youtube.com/watch?v=EyDaTkU2sKY "SuperPhishers DetermineSubCAIdentity Bypass")

## PoC Setup ##
The Windows 8.1 VM was connected to a Linux VM with 2 interfaces ('interception bridge'),
an internal network using iptables nat rules & sslsplit; and a second interface connected to a standard home internet connection and did not modify traffic.
sslsplit was modified to use SHA256, as Windows required it on the update traffic.
Trusted 'SuperPhish Interception CA' certificate was installed in the Windows 8.1 VM as shown.

Special thanks for Nektra who have released Deviare2 under GPL
https://github.com/nektra

### Usage Notes ###
Windows Update runs as a module in netsvc (svchost.exe) with NT AUTHORITY\SYSTEM rights.
You will need a SYSTEM level shell to execute this.
The example uses psexec from Administrator level to reach SYSTEM.

## Download ##
https://skydrive.live.com/redir?resid=817C744373ADD084!165
Run:
py DetermineSubCAIdentity.py

* Works on Windows 8.1 23/03/2015. May need new offset values on newer patches.
* Requires python 3
* Requires to register Nektra Deviare2 COM Objects https://github.com/nektra/Deviare2/
* Requires pyWin32 for python windows COM support http://sourceforge.net/projects/pywin32/
* Requires python psutil https://github.com/giampaolo/psutil


## Windows Update and Windows Store Intercepting SSL Technical ##

### Technical Introduction ###
There are several cases of Windows Update error: 80245006 and 803D000A documented in the wild,
indeed, any network administrator that has found Windows Store or Windows Update
suddenly failing when TLS interception is enabled is quick to put a MiTM bypass
on the microsoft domains. Microsoft have the luxury of selling their own TLS interception
product and including their own bypasses.

But how can we allow our trust anchor to pass the internet windows certificate checks?

As part of their anti-stuxnet defence[*], Microsoft increased the checking being done against
internal, critical certificate checks on Windows.

The Windows Update server, and Windows Store service use a local check IdentifySubCAIdentity()
to verify that the certificate presented by the apparent microsoft front end is chained to
their root.

We want to bypass this check, so we can locally bump Windows Update and Windows Store traffic.

[*] Because Stuxnet was abusing Windows Update channels for malicious distribution

###Countermeasures###
Windows 8.1 will allow Internet Explorer to bypass any EV or pinned certificates
if the server certificate can be parented by our Interception CA root in the Trust Store.
Windows Mail client and OneDrive will also not care and gladly be intercepted.
Likewise, Chrome will also Not Care* (they care but its hard, ya know?).
The latest care attempt will be a blue building next to the 'lock' to show 
'corporate interception of https traffic'.
I would be impressed if Google did for Chrome and GFE as Microsoft as done to theirs
with Windows Update and Windows Store and respective Microsoft https front ends.

Windows Update employs several technical measures -- to the local function CertVerifyCertificateChainPolicy 
makes sure these measures are called, and do not blindly trust the regular Cert trust verify calls.
First, the certificate signing must be STRONG, ie: SHA256. 
Many TLS interception products use SHA1 on the bumped certs. Boo!

A quick patch to sslsplit caused it to start issuing SHA256 certificates. This was a simple bypass for 
Countermeasure 1.

Countermeasure 2 is that the certificate is chained to "Microsoft Root CA"...
This is done by calling the function DetermineSubCAIdentity, included in to both wuaueng.dll & storewuauth.dll

###Bypassing Countermeasure 1 - Windows Update Error 0x803D000###

A Bumped TLS connection will not pass WindowsUpdate or WindowsStore Functions.
You will get Error Code 803D000A Windows Update ran into a problem

Error 0x803D000A relates to a Trust failure on the certificate if it is not strongly signed.
A bumped certificate with a SHA-256 signature will pass.

The SSLSplit tool version 0.4.10 uses SHA1 on its bumped certificates. This kinda-sorta works 
in browsers as of March 2015, which chrome singing the loudest that these need to be deprecated.

Additionally, SSLSplit uses the destination ip address and port as a string in the filename. 
This causes the : delimiter to be included in the filename, which is an illegal character for 
filenames in windows. 

Adjusting the SSLStrip source to call OpenSSL EVP_sha256();
Using replace.c from http://creativeandcritical.net/str-replace-c sorted
this, changing the : to a .
	
Finally, We bump up the keysize to RSA2048 by changing:
opts->key = ssl_key_genrsa(1024)
to
opts->key = ssl_key_genrsa(2048)
in main.c

    This patch for SSLStrip 4.10.0 is: sslsplit-0.4.10-sha256+filename-change-to-dots.patch

###Bypassing Countermeasure 2: Windows Update Error 0x8024006###

Windows Update employs an additional validation step that tries to check the 
certificate chain to a known Microsoft SubCA.

Functions wuaueng.dll!CheckSSLCertificateTrust() and storewuauth.dll!CheckSSLCertificateTrust()
call a function called wuaueng.dll!DetermineSubCAIdentity and storewuauth.dll!DetermineSubCAIdentity
respectively to check this chain.

The expected result of calling DetermineSubCAIdentity in wuaueng.dll is EAX = 0x00000002
It is interpreted that this means a Microsoft SubCA.

The first attempt was to patch the dll files directly on the file system to check against 
1 number higher:
add         eax,0FFFFFFFFh  
This did allow the success case but the tampered files did show up in a sfc /scannow
(System File Check). Changes to these critical windows files would cause alarm.

Rather then touch the filesystem we can modify the behavior of these functions in memory.
We use Nektra Deviare2 to 'detour' the functions to our code where we can change the value
of CPU registers.

The hook on DetermineSubCAIdentity() should allow us to return this result or at least pass
the ja or jbe instructions that take us to the failure case.

Replacing EAX=3 as a result of calling DetermineSubCAIdentity allowed both these tests to pass
and the certificate presented on https was considered a Microsoft CA.

   
    
<code>
From debug outputs-
30/05/2014 wuaueng.dll:
00007FFAD88BCD4F 44 8B C7             mov         r8d,edi  
00007FFAD88BCD52 BA 1E 00 00 00       mov         edx,1Eh  
00007FFAD88BCD57 C7 85 83 00 00 00 02 00 00 00 mov         dword ptr [rbp+83h],2  
00007FFAD88BCD61 E8 1A 43 F6 FF       call        Trace::CTrace::TraceLine (07FFAD8821080h)  
00007FFAD88BCD66 E8 3D 75 09 00       call        AreTestKeysAllowed (07FFAD89542A8h)  
00007FFAD88BCD6B 85 C0                test        eax,eax  
00007FFAD88BCD6D 0F 85 A0 C9 05 00    jne         CheckSSLCertificateTrust+5CBC7h (07FFAD8919713h)  
00007FFAD88BCD73 48 8B 4D 77          mov         rcx,qword ptr [rbp+77h]  
00007FFAD88BCD77 4D 8B C6             mov         r8,r14  
00007FFAD88BCD7A 8B D6                mov         edx,esi  
00007FFAD88BCD7C E8 27 FC FF FF       call        DetermineSubCAIdentity (07FFAD88BC9A8h)  
00007FFAD88BCD81 83 C0 FE             add         eax,0FFFFFFFEh  
00007FFAD88BCD84 83 F8 01             cmp         eax,1  
00007FFAD88BCD87 0F 87 A2 C9 05 00    ja          CheckSSLCertificateTrust+5CBE3h (07FFAD891972Fh)  
00007FFAD88BCD8D 49 8B D6             mov         rdx,r14  
00007FFAD88BCD90 8B CE                mov         ecx,esi  
00007FFAD88BCD92 E8 29 00 00 00       call        FreeSubCAOverrides (07FFAD88BCDC0h)  
00007FFAD88BCD97 48 8B 4D 77          mov         rcx,qword ptr [rbp+77h]  

13/11/2014:
00007FFEBE25D4D9 C7 85 83 00 00 00 02 00 00 00 mov         dword ptr [rbp+83h],2  
00007FFEBE25D4E3 E8 98 3B FF FF       call        Trace::CTrace::TraceLine (07FFEBE251080h)  
00007FFEBE25D4E8 E8 E7 43 FF FF       call        __AreTestKeysAllowed (07FFEBE2518D4h)  
00007FFEBE25D4ED 85 C0                test        eax,eax  
00007FFEBE25D4EF 0F 85 04 46 16 00    jne         CWUTaskHandler::AddRef+18AB9h (07FFEBE3C1AF9h)  
00007FFEBE25D4F5 48 8B 4D 77          mov         rcx,qword ptr [rbp+77h]  
00007FFEBE25D4F9 4D 8B C6             mov         r8,r14  
00007FFEBE25D4FC 8B D6                mov         edx,esi  
00007FFEBE25D4FE E8 29 FC FF FF       call        DetermineSubCAIdentity (07FFEBE25D12Ch)  
00007FFEBE25D503 83 C0 FE             add         eax,0FFFFFFFEh  
00007FFEBE25D506 83 F8 01             cmp         eax,1  
00007FFEBE25D509 0F 87 05 46 16 00    ja          CWUTaskHandler::AddRef+18AD4h (07FFEBE3C1B14h)  
00007FFEBE25D50F 49 8B D6             mov         rdx,r14  
00007FFEBE25D512 8B CE                mov         ecx,esi  
00007FFEBE25D514 E8 2B 00 00 00       call        FreeSubCAOverrides (07FFEBE25D544h)  
00007FFEBE25D519 48 8B 4D 77          mov         rcx,qword ptr [rbp+77h]  
00007FFEBE25D51D 48 85 C9             test        rcx,rcx  
00007FFEBE25D520 74 06                je          CheckSSLCertificateTrust+258h (07FFEBE25D528h)  
00007FFEBE25D522 FF 15 50 E7 33 00    call        qword ptr [__imp_CertFreeCertificateChain (07FFEBE59BC78h)]  
 
in storewuauth.dll:
00007FFB6DDF2DC7 E8 BC 03 00 00       call        GetSubCAOverrides (07FFB6DDF3188h)  
00007FFB6DDF2DCC 8B 75 67             mov         esi,dword ptr [rbp+67h]  
00007FFB6DDF2DCF 4C 8B 74 24 40       mov         r14,qword ptr [rsp+40h]  
00007FFB6DDF2DD4 48 8B 4D 77          mov         rcx,qword ptr [rbp+77h]  
00007FFB6DDF2DD8 4D 8B C6             mov         r8,r14  
00007FFB6DDF2DDB 8B D6                mov         edx,esi  
00007FFB6DDF2DDD E8 6A 00 00 00       call        DetermineSubCAIdentity (07FFB6DDF2E4Ch)  
00007FFB6DDF2DE2 83 C0 FE             add         eax,0FFFFFFFEh  
00007FFB6DDF2DE5 83 F8 01             cmp         eax,1  
00007FFB6DDF2DE8 76 2C                jbe         CheckSSLCertificateTrust+2FEh (07FFB6DDF2E16h)  
00007FFB6DDF2DEA 83 65 7F 00          and         dword ptr [rbp+7Fh],0  
00007FFB6DDF2DEE BA 1E 00 00 00       mov         edx,1Eh  
00007FFB6DDF2DF3 4C 8D 0D 36 07 FE FF lea         r9,[string L"Certificate failed S"... (07FFB6DDD3530h)]  
00007FFB6DDF2DFA 48 8D 4D 7F          lea         rcx,[rbp+7Fh]  
00007FFB6DDF2DFE 44 8D 42 E3          lea         r8d,[rdx-1Dh]  
00007FFB6DDF2E02 C7 85 83 00 00 00 03 00 00 00 mov         dword ptr [rbp+83h],3  
00007FFB6DDF2E0C E8 9F C4 FE FF       call        Trace::CTrace::TraceLine (07FFB6DDDF2B0h)  
00007FFB6DDF2E11 BB 0A 00 3D 80       mov         ebx,803D000Ah  
00007FFB6DDF2E16 49 8B D6             mov         rdx,r14  
</code>

The python script DetermineSubCAIdentity.py was developed that hooks this function in 
the service that is handling Windows Update.

This is service 'netsvcs' running svchost.exe as NT AUTHORITY\SYSTEM with about high 800's PID
soon after windows startup.
The script finds this PID using python psutil library and looks for svchost.exe with an 
command line argument of netsvcs.

Using previously discovered offsets of 0xD12c and 0x24A88 for the location of DetermineSubCAIdentity
in wuaueng.dll and storewuauth.dll, these are hooked with NktSpyMgrEvents object from EventHandlers.py
This object also checks for new libraries being loaded in the process and hooks storewuauth.dll
if it is loaded later (which it often is).

The OnFunctionCalled function in the NktSpyMgrEvents allows the real function to be called
and after it has completed, changes the value of EAX to 3.

The rest of the CertVerifyCertificateChainPolicy function completes, and believes that our
substituted certificate is from Microsoft.

Windows Updates, New Application downloads, New Applicaiton Auth checks and even Windows
Update file signatures ( checked with wuaueng!VerifyFileTrust ) can now be intercepted
with any trusted CA root as long as our hook is present.

Removing the hooks returns the Windows functions to normal and will only be successful
with a real Microsoft SubCA.

###Notes###
    https://support.microsoft.com/kb/287547 Microsoft Object Id for Microsoft Cryptography
    1.3.6.1.4.1.311.76.6.1
    What is this OID?
    Valid usage Code Signing, 1.3.6.1.4.1.311.76.6.1
    Common to both Windows and Java code signing
    
    https://msdn.microsoft.com/en-us/library/windows/desktop/aa377188%28v=vs.85%29.aspx
    CERT_CHAIN_POLICY_STATUS structure
    
    CertVerifyCertificateChainPolicy function
    https://msdn.microsoft.com/en-us/library/windows/desktop/aa377163%28v=vs.85%29.aspx
    