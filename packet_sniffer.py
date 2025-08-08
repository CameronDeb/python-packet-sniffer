import socket
import struct
import textwrap
import platform
import sys


def format_mac_address(mac_bytes):
    """Formats MAC address bytes (e.g., b'\x01\x02\x03\x04\x05\x06')
       into human-readable format (e.g., '01:02:03:04:05:06')."""
    return ':'.join(f'{b:02x}' for b in mac_bytes).upper()

def ipv4_addr_to_str(addr_bytes):
    """Converts packed IPv4 address bytes to a string."""
    return '.'.join(map(str, addr_bytes))

def unpack_ethernet_frame(data):
    """Unpacks the Ethernet header (first 14 bytes)."""
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return format_mac_address(dest_mac), format_mac_address(src_mac), socket.htons(proto), data[14:]

def unpack_ipv4_packet(data):
    """Unpacks the IPv4 header (first 20 bytes of the IP payload)."""
   
    version_header_length = data[0]
    version = version_header_length >> 4 # Shift right by 4 bits to get version
    header_length = (version_header_length & 15) * 4 # Mask with 0xF (15) and multiply by 4 for bytes

    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    # 8x = skip 8 bytes (ToS, Total Length, ID, Flags/Offset)
    # B = unsigned char (1 byte) for TTL
    # B = unsigned char (1 byte) for Protocol
    # 2x = skip 2 bytes (Header Checksum)
    # 4s = 4 bytes string for Source IP
    # 4s = 4 bytes string for Destination IP

    return version, header_length, ttl, proto, ipv4_addr_to_str(src), ipv4_addr_to_str(target), data[header_length:]


def main():
    """Main function to capture and process packets."""
    try:
        # On POSIX (Linux/macOS), check effective user ID. 0 is root.
        # On Windows, attempting to create a raw socket will fail without admin,
        # but we check explicitly for clarity if possible (requires external libs usually).
        # This basic check works for Linux/macOS. Windows will likely fail at socket creation.
        if platform.system() != "Windows" and os.geteuid() != 0:
             print("Error: This script requires root/administrator privileges to capture raw packets.")
             sys.exit(1)
    except AttributeError:
         # os.geteuid() doesn't exist on Windows
         print("Warning: Could not check privileges automatically. Ensure you are running as Administrator.")
         pass # Continue, socket creation will likely fail if not admin


    conn = None
    try:
        if platform.system() == "Windows":
             # On Windows, use AF_INET for IP packets. Requires specific setup.
             # This captures IP packets on a specific interface.
             host = socket.gethostbyname(socket.gethostname())
             conn = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
             conn.bind((host, 0))
             conn.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1) # Include IP headers
             conn.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON) # Promiscuous mode on Windows
             print(f"Sniffing on Windows host: {host}...")
        else:
             # On Linux/macOS, use AF_PACKET for raw Ethernet frames
             # socket.htons(3) means capture all protocols (EtherType 0x0003)
             conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
             print("Sniffing using AF_PACKET (Linux/macOS)...")

    except PermissionError:
         print("\nError: Permission denied. Please run this script as root or Administrator.")
         sys.exit(1)
    except OSError as e:
         print(f"\nOSError creating socket: {e}")
         print("Ensure you have the necessary permissions and the network interface is up.")
         sys.exit(1)
    except Exception as e:
         print(f"\nAn unexpected error occurred setting up the socket: {e}")
         sys.exit(1)


    packet_count = 0
    try:
        while True:
            raw_data, addr = conn.recvfrom(65535) # Receive up to 65535 bytes
            packet_count += 1
            print(f"\n--- Packet {packet_count} ---")

            if platform.system() == "Windows":
                # Data starts directly with IP header on Windows raw socket
                (ip_version, ip_header_length, ip_ttl, ip_proto,
                 ip_src, ip_target, payload) = unpack_ipv4_packet(raw_data)
                print("Ethernet Header (Not available on Windows raw socket)")
                print("IP Packet:")
                print(f"  - Version: {ip_version}, Header Length: {ip_header_length} bytes, TTL: {ip_ttl}")
                print(f"  - Protocol: {ip_proto} (TCP=6, UDP=17, ICMP=1)")
                print(f"  - Source IP: {ip_src}")
                print(f"  - Target IP: {ip_target}")

            else: # Linux/macOS
                dest_mac, src_mac, eth_proto, data = unpack_ethernet_frame(raw_data)
                print("Ethernet Frame:")
                print(f"  - Destination MAC: {dest_mac}")
                print(f"  - Source MAC: {src_mac}")
                print(f"  - EtherType (Protocol): {eth_proto}")

                # Check if EtherType is IPv4 (0x0800)
                if eth_proto == 8: # 0x0800 in decimal
                    (ip_version, ip_header_length, ip_ttl, ip_proto,
                     ip_src, ip_target, payload) = unpack_ipv4_packet(data)
                    print("IP Packet:")
                    print(f"  - Version: {ip_version}, Header Length: {ip_header_length} bytes, TTL: {ip_ttl}")
                    print(f"  - Protocol: {ip_proto} (TCP=6, UDP=17, ICMP=1)")
                    print(f"  - Source IP: {ip_src}")
                    print(f"  - Target IP: {ip_target}")
                else:
                    print(f"  - Non-IPv4 Packet (EtherType: {eth_proto})")



    except KeyboardInterrupt:
        print("\nSniffer stopped by user.")
        if platform.system() == "Windows" and conn:
            conn.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF) # Turn off promiscuous mode
            conn.close()
        elif conn:
             conn.close()
        print("Socket closed.")
    except Exception as e:
        print(f"\nAn error occurred during sniffing: {e}")
        if conn:
            if platform.system() == "Windows":
                 conn.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
            conn.close()


if __name__ == "__main__":
    # Need to import os for privilege check on Linux/macOS
    import os
    main()
