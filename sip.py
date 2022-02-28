
#    Copyright 2014 Philippe THIRION
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.

#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.

#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.

import socketserver as SocketServer
import re
import logging
from wsgiref.util import request_uri

logging.basicConfig(format='%(asctime)s[::]%(message)s',
                    filename='proxy.log', level=logging.INFO, datefmt='%H:%M:%S')

rx_register = re.compile("^REGISTER")
rx_invite = re.compile("^INVITE")
rx_ack = re.compile("^ACK")
rx_prack = re.compile("^PRACK")
rx_cancel = re.compile("^CANCEL")
rx_bye = re.compile("^BYE")
rx_options = re.compile("^OPTIONS")
rx_subscribe = re.compile("^SUBSCRIBE")
rx_publish = re.compile("^PUBLISH")
rx_notify = re.compile("^NOTIFY")
rx_info = re.compile("^INFO")
rx_message = re.compile("^MESSAGE")
rx_refer = re.compile("^REFER")
rx_update = re.compile("^UPDATE")
rx_from = re.compile("^From:")
rx_cfrom = re.compile("^f:")
rx_to = re.compile("^To:")
rx_cto = re.compile("^t:")
rx_tag = re.compile(";tag")
rx_contact = re.compile("^Contact:")
rx_ccontact = re.compile("^m:")
rx_uri = re.compile("sip:([^@]*)@([^;>$]*)")
rx_addr = re.compile("sip:([^ ;>$]*)")
rx_code = re.compile("^SIP/2.0 ([^ ]*)")
rx_request_uri = re.compile("^([^ ]*) sip:([^ ]*) SIP/2.0")
rx_route = re.compile("^Route:")
rx_contentlength = re.compile("^Content-Length:")
rx_ccontentlength = re.compile("^l:")
rx_via = re.compile("^Via:")
rx_cvia = re.compile("^v:")
rx_branch = re.compile(";branch=([^;]*)")
rx_rport = re.compile(";rport$|;rport;")
rx_contact_expires = re.compile("expires=([^;$]*)")
rx_expires = re.compile("^Expires: (.*)$")

# global dictionnary
registrar = {}

ipaddress = '10.10.36.113'  # Upravit podla aktualnej pozicie proxy v sieti
recordroute = f"Record-Route: <sip:{ipaddress}:5060;lr>"
topvia = f"Via: SIP/2.0/UDP {ipaddress}:5060"


class UDPHandler(SocketServer.BaseRequestHandler):

    def removeRouteHeader(self):
        # delete Route
        data = []
        for line in self.data:
            if not rx_route.search(line):
                data.append(line)
        return data

    def addTopVia(self):
        branch = ""
        data = []
        for line in self.data:
            if rx_via.search(line) or rx_cvia.search(line):
                md = rx_branch.search(line)
                if md:
                    branch = md.group(1)
                    via = "%s;branch=%sm" % (topvia, branch)
                    data.append(via)
                # rport processing
                if rx_rport.search(line):
                    text = "received=%s;rport=%d" % self.client_address
                    via = line.replace("rport", text)
                else:
                    text = "received=%s" % self.client_address[0]
                    via = "%s;%s" % (line, text)
                data.append(via)
            else:
                data.append(line)
        return data

    def removeTopVia(self):
        data = []
        for line in self.data:
            if rx_via.search(line) or rx_cvia.search(line):
                if not line.startswith(topvia):
                    data.append(line)
            else:
                data.append(line)
        return data

    def getSocketInfo(self, uri):
        addrport, socket, client_addr = registrar[uri]
        return (socket, client_addr)

    def getDestination(self):
        destination = ""
        for line in self.data:
            if rx_to.search(line) or rx_cto.search(line):
                md = rx_uri.search(line)
                if md:
                    destination = "%s@%s" % (md.group(1), md.group(2))
                break
        return destination

    def getOrigin(self):
        origin = ""
        for line in self.data:
            if rx_from.search(line) or rx_cfrom.search(line):
                md = rx_uri.search(line)
                if md:
                    origin = f"{md.group(1)}@{md.group(2)}"
                break
        return origin

    def getCallID(self):
        for line in self.data:
            md = re.compile("^Call-ID: ([^ ]*)").search(line)
            if md:
                return md.group(1)
        return 0

    def pickedUp(self):
        request_uri = self.data[0]
        ok200 = re.compile("^SIP/2.0 200 Ok").search(request_uri)

        for line in self.data:
            if re.compile("^CSeq: 20 INVITE").search(line) and ok200:
                return True
        return False

    def validStart(self):
        for line in self.data:
            if re.compile("^Route:").search(line):
                return False
        return True

    def sendResponse(self, code):
        request_uri = "SIP/2.0 " + code
        self.data[0] = request_uri
        index = 0
        data = []
        for line in self.data:
            data.append(line)
            if rx_to.search(line) or rx_cto.search(line):
                if not rx_tag.search(line):
                    data[index] = f"{line};tag=123456"
            if rx_via.search(line) or rx_cvia.search(line):
                # rport processing
                if rx_rport.search(line):
                    text = f"received={self.client_address[0]};rport={self.client_address[1]}"
                    data[index] = line.replace("rport", text)
                else:
                    text = f"received={self.client_address[0]}"
                    data[index] = f"{line};{text}"
            if rx_contentlength.search(line):
                data[index] = "Content-Length: 0"
            if rx_ccontentlength.search(line):
                data[index] = "l: 0"
            index += 1
            if line == "":
                break
        data.append("")
        text = "\r\n".join(data)
        self.socket.sendto(text.encode("utf-8"), self.client_address)

    def processRegister(self):
        global registrar
        fromm = ""
        contact = ""
        for line in self.data:
            if rx_to.search(line) or rx_cto.search(line):
                md = rx_uri.search(line)
                if md:
                    fromm = f"{md.group(1)}@{md.group(2)}"
            if rx_contact.search(line) or rx_ccontact.search(line):
                md = rx_uri.search(line)
                if md:
                    contact = md.group(2)
                else:
                    md = rx_addr.search(line)
                    if md:
                        contact = md.group(1)

        logging.info(
            f"> Registrovany novy uzivatel: {fromm} [Adresa: {contact}]")
        registrar[fromm] = [contact, self.socket,
                            self.client_address]
        self.sendResponse("200 Registrovany!")

    def processInvite(self):
        origin = self.getOrigin()
        if len(origin) == 0 or not origin in registrar:
            self.sendResponse("400 Nie si registrovany")
            logging.info(f'> Nezaregistrovany zdroj({origin})')
            return
        destination = self.getDestination()
        valid_start = self.validStart()
        if len(destination) > 0:
            if destination in registrar:
                socket, claddr = self.getSocketInfo(destination)
                self.data = self.addTopVia()
                data = self.removeRouteHeader()
                # insert Record-Route
                data.insert(1, recordroute)
                text = "\r\n".join(data)
                socket.sendto(text.encode("utf-8"), claddr)
                callId = self.getCallID()
                if callId and valid_start:
                    logging.info(
                        f"> Zvonenie [{callId}] {origin} -> {destination}")
            else:
                self.sendResponse("480 Nezaregistrovany uzivatel")
                logging.info(f'> Nezaregistrovany ciel({destination})')
        else:
            self.sendResponse("500 Neplatna destinacia")
            logging.info(f'> Neplatny ciel({destination})')

    def processAck(self):
        destination = self.getDestination()
        if len(destination) > 0:
            if destination in registrar:
                socket, claddr = self.getSocketInfo(destination)
                self.data = self.addTopVia()
                data = self.removeRouteHeader()
                # insert Record-Route
                data.insert(1, recordroute)
                text = "\r\n".join(data)
                socket.sendto(text.encode("utf-8"), claddr)
                logging.debug(f'> ACK OK {destination}')

    def processNonInvite(self):
        origin = self.getOrigin()
        if len(origin) == 0 or not origin in registrar:
            self.sendResponse("400 Nie si registrovany")
            logging.info(f'> Nezaregistrovany zdroj({origin})')
            return
        destination = self.getDestination()
        if len(destination) > 0:
            if destination in registrar:
                socket, claddr = self.getSocketInfo(destination)
                self.data = self.addTopVia()
                data = self.removeRouteHeader()
                # insert Record-Route
                data.insert(1, recordroute)
                text = "\r\n".join(data)
                socket.sendto(text.encode("utf-8"), claddr)
                logging.debug(f"> Non-invite OK {origin} -> {destination}")
            else:
                self.sendResponse("406 Nezaregistrovany uzivatel")
                logging.info(
                    f'> Nezaregistrovany ciel({destination})')
        else:
            self.sendResponse("500 Neplatna destinacia")
            logging.info(f'> Neplatny ciel({destination})')

    def processCode(self):
        origin = self.getOrigin()
        if len(origin) > 0:
            if origin in registrar:
                socket, claddr = self.getSocketInfo(origin)
                self.data = self.removeRouteHeader()
                data = self.removeTopVia()
                text = "\r\n".join(data)
                socket.sendto(text.encode("utf-8"), claddr)
                if self.pickedUp():
                    callId = self.getCallID()
                    destination = self.getDestination()
                    logging.info(
                        f'> Zacatie hovoru [{callId}] {destination} -> {origin}')

    def processRequest(self):
        if len(self.data) > 0:
            request_uri = self.data[0]
            if rx_register.search(request_uri):
                logging.debug(f'REGISTER')
                self.processRegister()
            elif rx_invite.search(request_uri):
                logging.debug(f'INVITE')
                self.processInvite()
            elif rx_ack.search(request_uri):
                logging.debug(f'ACK')
                self.processAck()
            elif rx_bye.search(request_uri):
                logging.debug(f'BYE')
                callId = self.getCallID()
                origin = self.getOrigin()
                destination = self.getDestination()
                logging.info(
                    f'> Koniec hovoru [{callId}] {origin}->{destination}')
                self.processNonInvite()
            elif rx_cancel.search(request_uri):
                logging.debug(f'CANCEL')
                self.processNonInvite()
            elif rx_options.search(request_uri):
                logging.debug(f'OPTIONS')
                self.processNonInvite()
            elif rx_info.search(request_uri):
                logging.debug(f'INFO')
                self.processNonInvite()
            elif rx_message.search(request_uri):
                logging.debug(f'MESSAGE')
                self.processNonInvite()
            elif rx_refer.search(request_uri):
                logging.debug(f'REFER')
                self.processNonInvite()
            elif rx_prack.search(request_uri):
                logging.debug(f'PRACK')
                self.processNonInvite()
            elif rx_update.search(request_uri):
                logging.debug(f'UPDATE')
                self.processNonInvite()
            elif rx_subscribe.search(request_uri):
                logging.debug(f'SUBSCRIBE')
                self.sendResponse("200 0K")
            elif rx_publish.search(request_uri):
                logging.debug(f'PUBLISH')
                self.sendResponse("200 0K")
            elif rx_notify.search(request_uri):
                logging.debug(f'NOTIFY')
                self.sendResponse("200 0K")
            elif rx_code.search(request_uri):
                logging.debug(f'PROCESS CODE')
                self.processCode()
            else:
                logging.debug(f"> Neplatna ziadost na proxy: {request_uri}")

    def handle(self):
        data = self.request[0]
        if data[0] == 0x00:
            return
        try:
            data = data.decode('utf-8')
        except UnicodeDecodeError:
            return logging.debug('ERR: Linphone XML probably')

        self.data = data.split("\r\n")
        self.socket = self.request[1]
        request_uri = self.data[0]
        if rx_request_uri.search(request_uri) or rx_code.search(request_uri):
            print(request_uri)
            self.processRequest()
