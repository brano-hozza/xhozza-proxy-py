import socketserver as SocketServer
from sip import UDPHandler

if __name__ == "__main__":
    server = SocketServer.UDPServer(('0.0.0.0', 5060), UDPHandler)
    server.serve_forever()
