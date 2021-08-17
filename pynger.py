import os
import sys
import json
import time
import threading
import scapy.all as scapy
from plyer import notification

version = "0.4.1"

configFile = "config.json"
whitelistFile = "whitelist.json"

class pynger:
    notified = False
    whitelist = {}
    config = {
        "minRefreshRate": 1,
        "timeout" : 2,
        "notifications": False
    }

    btwnTagAndStatus = 0
    amntDashEq = 0

    argument = "-n" if os.name == "nt" else "-c"

    def clearScreen():
        os.system("cls" if os.name == "nt" else "clear") # Makes sure clearing the screen won't throw errors, regardless of OS.

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
        notifChoice = input("Would you like to be notified of devices coming online?")
        if notifChoice[0].lower() == "y":
            pynger.config["notifications"] = True
        
        with open(configFile, "a") as cfg:
            json.dump(pynger.config, cfg, indent=4)

        entry = []
        whitelistEntries = {}
        print("Please enter space seperated IPs and related tags. (i.e. '10.0.0.1 John')\nOnce you're done, hit enter.")
        while True:
            entry = input("> ").split(" ")

            if entry != ['']:
                whitelistEntries[entry[1]] = [entry[0], False]
            else:
                break

        with open(whitelistFile, "a") as whitel:
            json.dump(whitelistEntries, whitel, indent=4)
            return


    def loadFiles(): # Reads and parses the config and whitelist files. Then sets up spacing and the header for the whitelist board.
        with open(configFile, "r") as cfg:
            pynger.config = json.load(cfg)

        with open(whitelistFile, "r") as wht:
            for key, value in sorted(json.load(wht).items()):
                pynger.whitelist[key] = value

        longestTagLength = 0
        for tag in pynger.whitelist:
            longestTagLength = len(tag) if len(tag) > longestTagLength else longestTagLength

        pynger.btwnTagAndStatus = 7 + (longestTagLength - 7)
        pynger.amntDashEq = 31 + (longestTagLength - 7)

        pynger.header = f"{'=' * pynger.amntDashEq}\nTAG{' ' * pynger.btwnTagAndStatus}STATUS     IP\n{'=' * pynger.amntDashEq}"


    def ping(ip): # Pings ip and returns a boolean value corresponding to the response.
        response = os.popen(f"ping {pynger.argument} 1 {ip}").read()

        if "unreachable" in response or "timed" in response:
            return False

        return True


    def arp(ip): # Broadcasts an ARP request and returns a boolean corresponding to if the given ip responded or not.
        arpLayer = scapy.ARP(pdst=ip)
        return True if scapy.srp(scapy.Ether("ff:ff:ff:ff:ff:ff")/arpLayer, verbose=False, timeout=pynger.config["timeout"])[0] else False


    def notify(tagList):
        tagString = ""

        if len(tagList) > 1:
            for tag in tagList:
                tagString += f"{tag}, "
            tagString += "have"
        else:
            tagString = f"{tagList[0]} has"

        notification.notify(title="Arpy", message=f"{tagString} connected.")


    def updateWhitelist(tag): # Pings a given entry in the whitelist and then updates it's status.
        for _ in range(3): # This makes sure to get rid of false negatives by checking 3 times and taking any True as the truth.
            result = pynger.ping(pynger.whitelist[tag][0])
            if result == True:
                break
            time.sleep(.1)                

        if not result:
            for _ in range(3):
                result = pynger.arp(pynger.whitelist[tag][0])
                if result == True:
                    break
                time.sleep(.1)

        pynger.whitelist[tag][1] = result


    def drawWhitelist(): # Clears the screen and then prints a pretty representation of each entry in the whitelist.
        pynger.clearScreen()
        print(f"Pynger version {version}\n")
        print(pynger.header)
        
        for tag in pynger.whitelist:
            status = "\033[92m[CONN]\033[0m" if pynger.whitelist[tag][1] else "\033[91m[DISC]\033[0m"
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

            newlyOnline = []
            beforeScans = {}

            for tag in pynger.whitelist:
                beforeScans[tag] = pynger.whitelist[tag][1]

            for tag in pynger.whitelist:
                t = threading.Thread(target=pynger.updateWhitelist, args=((tag),))
                t.start()
                threads.append(t)

            for thread in threads:
                thread.join()

            pynger.drawWhitelist()

            for tag in pynger.whitelist:
                if pynger.whitelist[tag][1] == True and beforeScans[tag] == False:
                    newlyOnline.append(tag)

            if len(newlyOnline) != 0:
                pynger.notify(newlyOnline)

            time.sleep(pynger.config["minRefreshRate"])


if __name__ == "__main__":
    try:
        pynger.monitor()
    except KeyboardInterrupt:
        pynger.clearScreen()
        sys.exit(0)