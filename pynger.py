import os
import sys
import json
import time
import scapy.all as scapy
import threading

version = "0.1.0"

configFile = "config.json"
whitelistFile = "whitelist.json"

class pynger:
    whitelist = {}
    config = {
        "timeout": 5,
        "minRefreshRate": 1
    }

    btwnTagAndStatus = 0
    amntDashEq = 0

    clearScreen = lambda: os.system("cls" if os.name == "nt" else "clear") # Makes sure clearing the screen won't throw errors, regardless of OS.

    def isReady(): # Checks if the config and whitelist file exist and aren't empty.
        if os.path.exists(configFile) \
            and os.stat(configFile).st_size > 0 \
            and os.path.exists(whitelistFile) \
            and os.stat(whitelistFile).st_size > 0:
            ready = True
        else:
            ready = False

        return ready


    def setup(): # Applies the default config to file, and begins a whitelist population prompt before applying that to file as well.
        with open(configFile, "w") as cfg:
            json.dump(pynger.config, cfg, indent=4)

        whitelistEntries = []
        print("Please enter space seperated IPs and related tags. (i.e. '10.0.0.1 John')\nOnce you're done, hit enter.")
        while True:
            entry = input("> ").split(" ")

            if entry == ['']:
                with open(whitelistFile, "w") as whitel:
                    json.dump(whitelistEntries, whitel, indent=4)
                    return

            whitelistEntries[entry[1]] = [entry[0], False]


    def loadFiles(): # Reads and parses the config and whitelist files. Then sets up spacing and the header for the whitelist board.
        with open(configFile, "r") as cfg:
            pynger.config = json.load(cfg)

        with open(whitelistFile, "r") as wht:
            pynger.whitelist = json.load(wht)

        longestTagLength = 0
        for tag in pynger.whitelist:
            longestTagLength = len(tag) if len(tag) > longestTagLength else longestTagLength

        pynger.btwnTagAndStatus = 5 + (longestTagLength - 7)
        pynger.amntDashEq = 29 + (longestTagLength - 7)

        pynger.header = f"{'=' * pynger.amntDashEq}\nTAG{' ' * pynger.btwnTagAndStatus}STATUS     IP\n{'=' * pynger.amntDashEq}"


    def ping(ip): # Pings ip and returns a boolean value corresponding to the response.
        icmp = scapy.IP(dst=ip)/scapy.ICMP()

        response = scapy.sr1(icmp, verbose=False, timeout=pynger.config["timeout"])

        if response == None:
            return False

        return True


    def updateWhitelist(tag): # Pings a given entry in the whitelist and then updates it's status.
        pynger.whitelist[tag][1] = pynger.ping(pynger.whitelist[tag][0])


    def drawWhitelist(): # Clears the screen and then prints a pretty representation of each entry in the whitelist.
        pynger.clearScreen()
        print(pynger.header)
        
        for tag in pynger.whitelist:
            status = "[CONN]" if pynger.whitelist[tag][1] else "[DISC]"
            pynger.btwnTagAndStatusFor = (pynger.btwnTagAndStatus + 3) - len(tag)
            print(f"{tag + ' ' * pynger.btwnTagAndStatusFor + status}     {pynger.whitelist[tag][0]}")
            print("-" * pynger.amntDashEq)


    def monitor(): # Checks if ready, if not, runs setup and loads the config. Begins monitoring.
        if not pynger.isReady(): # Runs the setup prompt and then loads the files.
            print("It seems that you haven't set Pynger up yet.\nGenerating config file and running prompt.")
            pynger.setup()

            pynger.clearScreen()
            input("Setup completed. Press enter to continue.\n")
        
        pynger.loadFiles()

        while True:
            threads = []

            for tag in pynger.whitelist:
                t = threading.Thread(target=pynger.updateWhitelist, args=((tag),))
                t.start()
                threads.append(t)

            for thread in threads:
                thread.join()

            pynger.drawWhitelist()

            time.sleep(pynger.config["minRefreshRate"])


if __name__ == "__main__":
    args = sys.argv[1:]
    flags = ""
    mode = ""

    for arg in args:
        if arg[0] == "-":
            flags += arg[1:] # Only include the letters in the flags.
        elif arg in ["monitor", "setup", "version"] and mode == "":
            mode = arg
        else:
            print(f"Either an invalid argument passed, ({arg}) or you supplied more than one.")
            sys.exit(1)
    try:
        if mode == "monitor":
            pynger.monitor()
        elif mode == "setup":
            pynger.setup()
        elif mode == "version":
            print(f"Pynger version {pynger.version}")
        else:
            print(f"I don't understand that mode: {mode}")
            sys.exit(1)
    except KeyboardInterrupt:
        pynger.clearScreen()
        sys.exit(0)