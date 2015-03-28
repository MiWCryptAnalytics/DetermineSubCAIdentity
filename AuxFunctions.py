# AuxFunctions.py v1.1
# SuperPhishers PoC :: DetermineSubCAIdentity Bypass
# ===============================================
# bypass Windows Update Code 80245006, Microsoft CA check
# https://skydrive.live.com/redir?resid=817C744373ADD084!165
# by _MiW, March 2015
# Code released under the GNU Public License v3
#
# Based on a python code example by Nektra https://github.com/nektra/Deviare2/tree/master/Samples/Python/
# Uses the Nektra Deviare2 libraries available here: https://github.com/nektra/Deviare2
# Nektra Deviare is awesome
#
# Is your internet connection SSL intercepted? 
# Maybe by choice, maybe by force;
# Maybe for debugging, Maybe for spying...
#
# DetermineSubCAIdentity is not a exported function in wuaueng.dll or storewuauth.dll
# its visibility to Visual Studio is by merit of the Microsoft Symbol Servers
# Its offsets was were discovered by Remote Debug Tracing in Visual Studio
# and the ability to set a breakpoint on this function.
# You cannot hook it directly by name from Deviare2 for this reason, so we need to use
# its memory location.

# Auxiliar Functions =====================================================================

from subprocess import *
import os, sys
import psutil

def GetServicePIDByProcessName(aServiceName, spyManager):
              
        for proc in psutil.process_iter():
                try:
                        if (proc.name() == 'svchost.exe'):
                                if (proc.cmdline()[2]  == aServiceName):
                                        return proc.pid
                except psutil.AccessDenied:
                        continue

def GetPIDByProcessName(aProcessName, spyManager):
        for proc in psutil.process_iter():
                try:
                        if (proc.name() == aProcessName):
                                return proc.pid
                except psutil.AccessDenied:
                        continue
                        #print ("Access Denied to %d" % proc.pid)

def AttachWindowsUpdate(spyManager, storemoduleenabled = True, wuauengmoduleenabled = True):
        nktProcessesEnum = spyManager.Processes()
        for proc in nktProcessesEnum:
                #print("%d %s" % (proc.Id, proc.Name))
                if (proc.Name == "python.exe"):
                        localpid = proc.Id
                        print(localpid)
        print ("Running as pid %d" % localpid)
        print ("Finding Windows Update...")
        pid = GetServicePIDByProcessName("netsvcs", spyManager)
        if (pid):
                print ("Found service PID for netsvc %d" % pid)
        else:
                print ("Unable to find netsvc service PID")
                sys.exit(0)
        pidObject = spyManager.ProcessFromPID(pid)
        print ("PID object is: %s" % pidObject)
        print ("Finding location of DetermineSubCAIdentity in wuaueng.dll")

        if wuauengmoduleenabled:
                wuauengModule = pidObject.ModuleByName("wuaueng.dll")
                memoryOffset = 0xD12C # this is the valid offset as of March 2015 for the wuaueng.dll location of DetermineSubCAIdentity
                if not (wuauengModule):
                        print("Windows Update Service not running")
                else:
                        hook = HookFunctionForProcessMemoryOffset(spyManager, wuauengModule, memoryOffset, pidObject)
                        
        if storemoduleenabled:
                storewuauthModule = pidObject.ModuleByName("storewuauth.dll")
                memoryOffset = 0x24A88 # this is the valid offset as of March 2015 for the wuaueng.dll location of DetermineSubCAIdentity
                if not (storewuauthModule):
                        print("Store Auth Service not running")
                else:
                        hook = HookFunctionForProcessMemoryOffset(spyManager, storewuauthModule, memoryOffset, pidObject) 
        return spyManager.Hooks()


def HookFunctionForProcessMemoryOffset(spyManager, module, memoryOffset, nktProcess):
        print ("%s base address: %x" % (module.Name, module.BaseAddress))
        print ("Hooking function %s!+%x for %s..." % (module.Name, memoryOffset, nktProcess.Name) )
        baseplusoffset = module.BaseAddress + memoryOffset
        print ("Function is at: %x" % baseplusoffset)
        hook = spyManager.CreateHookForAddress(baseplusoffset, module.Name, 0)
        hook.Hook(True)
        hook.Attach(nktProcess, True)
        if hook:
                print ("%s successfully hooked %s!+%x" % (nktProcess.Name, module.Name, memoryOffset))
        return hook

def HookFunctionForProcess(spyManager, functionModuleAndName, pid):
	print ("Hooking function " + functionModuleAndName + " for %s..." % pid )
	hook = spyManager.CreateHook(functionModuleAndName, 0)
	hook.Hook(True)
	hook.Attach(pid, True)
	if hook:
                print ("%s successfully hooked" % pid)
	return hook
