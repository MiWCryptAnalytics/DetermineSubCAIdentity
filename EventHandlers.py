# EventHandlers.py
# SuperPhishers PoC :: DetermineSubCAIdentity Bypass
# ===============================================
# bypass Windows Update Code 80245006, Microsoft CA check
# https://skydrive.live.com/redir?resid=817C744373ADD084!165
# by _MiW, March 2015
# Code released under the GNU Public License v3
#
# Based on a python code example by Nektra https://github.com/nektra
#
# Is your internet connection SSL intercepted? 
# Maybe by choice, maybe by force;
# Maybe for debugging, Maybe for spying...
# Event Handlers ======================================================================

import win32com.client
import ctypes

from AuxFunctions import HookFunctionForProcessMemoryOffset

class NktSpyMgrEvents:

        def OnAgentLoad(self, proc, errorCode):
                if not errorCode == 0:
                        print ("OnAgenLoad error code: %d" % (errorCode,))
                
        def OnProcessStarted(self, nktProcessAsPyIDispatch):
                nktProcess = win32com.client.Dispatch(nktProcessAsPyIDispatch)
                
        def OnProcessTerminated(self, nktProcessAsPyIDispatch):
                nktProcess = win32com.client.Dispatch(nktProcessAsPyIDispatch)

        def OnHookOverwritten(self, nktProcessAsPyIDispatch):
                MessageBox = ctypes.windll.user32.MessageBoxW
                MessageBox(None, "Hook overwritten", "Hooked DetermineSubCAIdentity", 0)
                
        def OnLoadLibraryCall(self, nktProcessAsPyIDispatch, dllName, moduleAddr):
                found = 0
                #print ("Loaded %s" % dllName)
                for hook in self.Hooks():
                        if hook.FunctionName in dllName:
                                print("already hooked %s!" % hook.FunctionName)
                                found = True
                if found:
                        return
                nktProcess = win32com.client.Dispatch(nktProcessAsPyIDispatch)
                if "wuaueng.dll" in dllName:
                        memoryOffset = 0xD12C
                        hook = HookFunctionForProcessMemoryOffset(self, nktProcess.ModuleByName("wuaueng.dll"), memoryOffset, nktProcess)
                        #print (hook)
                        return
                
                if "storewuauth.dll" in dllName:
                        memoryOffset = 0x24A88
                        hook = HookFunctionForProcessMemoryOffset(self, nktProcess.ModuleByName("storewuauth.dll"), memoryOffset, nktProcess)
                        #print (hook)
                        return

        def OnFreeLibraryCall(self, nktProcessAsPyIDispatch, moduleAddr):
                print ("%s freed" % moduleAddr)   

        def FixCheckSSLCertificateTrust(self, nktHookCallInfo):
                newEAX = 0x03
                oldEAX = nktHookCallInfo.Register(1)                                        
                if (oldEAX == 1):
                        #Trusted but not from Microsoft
                        print("\tEAX = %s" % oldEAX)
                        print ("\tSetting EAX = %d" % newEAX)
                        nktHookCallInfo.SetRegister(1, newEAX)
                        #Now its from Microsoft
                        print("\tEAX = %s" % nktHookCallInfo.Register(1))
                        
        def OnFunctionCalled(self, nktHookAsPyIDispatch, nktProcessAsPyIDispatch, nktHookCallInfoAsPyIDispatch):
                nktHookCallInfo = win32com.client.Dispatch(nktHookCallInfoAsPyIDispatch)
                #print("OnFunctionCalled: %s" % nktHookAsPyIDispatch)
                #print("E: %s" % nktHookCallInfo.LastError)
                if (not nktHookCallInfo.IsPreCall):
                        offset = nktHookCallInfo.StackTrace().Offset(0)
                        print("Parent Function Offset: %x" % offset)
                        if (offset == 0xd503):
                                print("wuaueng.dll!CheckSSLCertificateTrust()")
                                self.FixCheckSSLCertificateTrust(nktHookCallInfo)
                        elif (offset == 0x8b9b):
                                print("wuaueng!VerifyFileTrust()")
                                print("\tUnmodified call")
                        elif (offset == 0xb58e):
                                print("storewuauth.dll!CheckSSLCertificateTrust()")
                                print("\tEAX = %s" % nktHookCallInfo.Register(1))
                                print ("\tSetting EAX = %d" % 0x3)
                                nktHookCallInfo.SetRegister(1, 0x3)
# Aux Functions =========================================================================

        
        def SkipCall(self, nktHookCallInfo, nktProcess):
                nktHookCallInfo.SkipCall()
                if (nktProcess.PlatformBits == 64):
                        nktHookCallInfo.Result().LongLongVal = -1
                else:
                        nktHookCallInfo.Result().LongVal = -1
                nktHookCallInfo.LastError = 5

        def GetFileNameParam(self, nktParamsEnum):
                nktParam = nktParamsEnum.First()
                return nktParam.Value
