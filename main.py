import os
import psutil
import win32service


edrList = [
    "activeconsole", "ADA-PreCheck", "ahnlab", "amsi.dll", "anti malware", "anti-malware",
    "antimalware", "anti virus", "anti-virus", "antivirus", "appsense", "attivo networks", "attivonetworks",
    "authtap", "avast", "avecto", "bitdefender", "blackberry", "canary",
    "carbonblack", "carbon black", "cb.exe", "check point", "ciscoamp", "cisco amp",
    "countercept", "countertack", "cramtray", "crssvc", "crowdstrike", "csagent", "csfalcon",
    "csshell", "cybereason", "cyclorama", "cylance", "cynet", "cyoptics", "cyupdate", "cyvera",
    "cyserver", "cytray", "darktrace", "deep instinct", "defendpoint", "defender", "eectrl",
    "elastic", "endgame", "f-secure", "forcepoint", "fortinet", "fireeye", "groundling",
    "GRRservic", "harfanglab", "inspector", "ivanti", "juniper networks", "kaspersky", "lacuna",
    "logrhythm", "malware", "malwarebytes", "mandiant", "mcafee", "morphisec", "msascuil",
    "msmpeng", "mssense", "nissrv", "omni", "omniagent", "osquery", "Palo Alto Networks", "pgeposervice",
    "pgsystemtray", "privilegeguard", "procwall", "protectorservic", "qianxin", "qradar",
    "qualys", "rapid7", "redcloak", "red canary", "SanerNow", "sangfor", "secureworks",
    "securityhealthservice", "semlaunchsv", "sentinel", "sentinelone", "sepliveupdat",
    "sisidsservice", "sisipsservice", "sisipsutil", "smc.exe", "smcgui", "snac64", "somma",
    "sophos", "splunk", "srtsp", "symantec", "symcorpu", "symefasi", "sysinternal", "sysmon",
    "tanium", "tda.exe", "tdawork", "tehtris", "threat", "trellix", "tpython", "trend micro",
    "uptycs", "vectra", "watchguard", "wincollect", "windowssensor", "wireshark", "withsecure",
    "xagt.exe", "xagtnotif.exe"
]

# Convert a string to lowercase
def to_lower(s):
    return s.lower()

# Check if the string matches any known EDR strings
def is_edr_string(s):
    lower_s = to_lower(s)
    for edr in edrList:
        if edr in lower_s:
            return True
    return False

# Check running processes
def check_processes():
    p_edr = False
    print("\n===== Processes =====")

    for proc in psutil.process_iter(['pid', 'name', 'exe']):
        try:
            name = proc.info['name']
            path = proc.info['exe'] or "Path unavailable"

            if is_edr_string(name) or is_edr_string(path):
                print(f"[!] Potential EDR process found:\n")
                print(f"\tName: {name}")
                print(f"\tPath: {path}")
                print(f"\tPID: {proc.info['pid']}\n")
                p_edr = True
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            continue

    if not p_edr:
        print("[+] No interesting processes found\n")

# Check directories for EDR files
def check_directories():
    p_edr = False
    print("\n===== Directories =====")

    directories = [
        "C:\\Program Files",
        "C:\\Program Files (x86)",
        "C:\\ProgramData"
    ]

    for directory in directories:
        for root, dirs, files in os.walk(directory):
            for dir_name in dirs:
                if is_edr_string(dir_name):
                    print(f"[!] Potential EDR directory found: {os.path.join(root, dir_name)}")
                    p_edr = True

    if not p_edr:
        print("[+] No EDR directories found\n")

# Check Windows services for potential entries
def check_services():
    p_edr = False
    print("\n===== Services =====")

    try:
        sc_manager = win32service.OpenSCManager(None, None, win32service.SC_MANAGER_ENUMERATE_SERVICE)
        services = win32service.EnumServicesStatus(sc_manager, win32service.SERVICE_WIN32, win32service.SERVICE_STATE_ALL)

        for service in services:
            service_name = service[0]
            display_name = service[1]

            if is_edr_string(service_name) or is_edr_string(display_name):
                print(f"[!] Potential EDR service found:")
                print(f"\tName: {service_name}")
                print(f"\tDisplay Name: {display_name}\n")
                p_edr = True

    except Exception as e:
        print(f"[-] Failed to open Service Control Manager: {e}")

    if not p_edr:
        print("[+] No EDR services found\n")

# Run all checks
def main():
    check_processes()
    check_directories()
    check_services()

if __name__ == "__main__":
    main()