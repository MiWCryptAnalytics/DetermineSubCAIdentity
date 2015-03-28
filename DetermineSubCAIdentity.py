# DetermineSubCAIdentity.py
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
#
# Main ==================================================================

import win32com.client
import ctypes, sys
import admin

from EventHandlers import NktSpyMgrEvents
from AuxFunctions import *

if not admin.isUserAdmin():
        admin.runAsAdmin()
        sys.exit(1)

        
if sys.version_info.major < 3:
	warnings.warn("Need Python 3.0 for this program to run", RuntimeWarning)
	sys.exit(0)

win32com.client.pythoncom.CoInitialize()
spyManager = win32com.client.DispatchWithEvents("DeviareCOM.NktSpyMgr", NktSpyMgrEvents)
result = spyManager.Initialize()

if not result == 0:
	print ("ERROR: Could not initialize the SpyManager. Error code: %d" % (result))
	sys.exit(0)
       
AttachWindowsUpdate(spyManager)

MessageBox = ctypes.windll.user32.MessageBoxW
MessageBox(None, "Press OK to remove hook", "SuperPhishers", 0)
print("bye!")
sys.exit(0)

