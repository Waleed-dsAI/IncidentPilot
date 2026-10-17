"""Optional *manual* Windows-only read-only status collector.
Run on a device you own. Prints a JSON report; never uploads or changes security settings.
Requires Windows PowerShell and built-in Microsoft Defender cmdlets.
"""
import json
import subprocess
import platform
import sys

if platform.system()!='Windows':
    sys.exit('This collector runs only on Windows.')
cmd=('Get-MpComputerStatus | Select-Object AntivirusEnabled,RealTimeProtectionEnabled | ConvertTo-Json -Compress')
try:
    process=subprocess.run(['powershell','-NoProfile','-NonInteractive','-Command',cmd],
         capture_output=True,text=True,timeout=15,check=True)
    d=json.loads(process.stdout)
    print(json.dumps({'host_alias':'my-test-laptop',
        'defender_enabled':d.get('AntivirusEnabled'),
        'realtime_enabled':d.get('RealTimeProtectionEnabled'),
        'detections':[],'status':'manual-read-only'}))
except (subprocess.SubprocessError,ValueError,KeyError) as e:
    sys.exit('Unable to read Defender status: '+type(e).__name__)
