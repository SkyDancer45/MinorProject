import socket
import subprocess
import threading
import time

import pyshark

# Shared list to store the conversations
conversations = []
conversations_lock = threading.Lock()

# Variables for DDoS detection
incoming_request_count = 0  # Counter for incoming requests
max_incoming_threshold = 50  # DDoS detection threshold
last_packet_time = time.time()  # Timestamp of the last packet received
timeout_seconds = (
    10  # Timeout to reset the count if no packets are received within this time
)


# Get the host's actual IP address
def get_host_ip():
    try:
        # Create a socket to get the actual IP of the host (non-localhost)
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0)
        # This doesn't actually send any data. It's just used to get the IP.
        s.connect(("8.8.8.8", 80))
        host_ip = s.getsockname()[0]
        s.close()
        return host_ip
    except Exception as e:
        print(f"Error getting host IP: {e}")
        return None


# Get the host's correct IP address
host_ip = get_host_ip()
print(f"Host IP: {host_ip}")


# Function to block the port using iptables
def block_port(port):
    try:
        # Use iptables command to block traffic on the given port
        subprocess.run(
            [
                "sudo",
                "iptables",
                "-A",
                "INPUT",
                "-p",
                "tcp",
                "--dport",
                str(port),
                "-j",
                "DROP",
            ],
            check=True,
        )
        print(f"Port {port} has been blocked due to suspected DDoS attack.")
    except subprocess.CalledProcessError as e:
        print(f"Error blocking port {port}: {e}")


def log_network_conversations():
    """
    Thread 1: Logs network conversations continuously.
    This simulates a continuous packet capture process like `tcpdump`.
    """
    if not host_ip:
        print("Unable to determine the host IP, exiting...")
        return

    # Use the correct network interface from your available list
    capture = pyshark.LiveCapture(
        interface="wlp3s0"
    )  # Replace 'wlp3s0' with the correct interface

    for packet in capture.sniff_continuously():
        try:
            protocol = packet.transport_layer
            source_address = packet.ip.src
            destination_address = packet.ip.dst

            # Only capture incoming packets directed to the host's IP
            if destination_address == host_ip:
                source_port = packet[packet.transport_layer].srcport
                destination_port = packet[packet.transport_layer].dstport
                log_entry = f"{protocol} {source_address}:{source_port} --> {destination_address}:{destination_port}"

                # Safely add to the shared conversation log
                with conversations_lock:
                    conversations.append(
                        (protocol, source_address, source_port, destination_port)
                    )

                # Update the last packet time (for DDoS analysis)
                global last_packet_time
                last_packet_time = time.time()

                # Print captured packet (for debug purposes)
                print(f"Logged: {log_entry}")

        except AttributeError:
            # Ignore packets that don't have required attributes
            pass


def analyze_conversations():
    """
    Thread 2: Analyzes logged conversations in real-time.
    Simulates real-time traffic analysis with timeout handling for incoming traffic.
    """
    global incoming_request_count, last_packet_time
    port_request_count = {}

    while True:
        time.sleep(1)  # Analyze logs every second (adjust as needed)

        current_time = time.time()
        time_since_last_packet = current_time - last_packet_time

        # Reset the counter if no packets were received within the timeout period
        if time_since_last_packet > timeout_seconds:
            incoming_request_count = 0
            port_request_count.clear()

        with conversations_lock:
            if len(conversations) > 0:
                # Analyze the most recent 50 conversations
                recent_conversations = conversations[-50:]

                for conv in recent_conversations:
                    protocol, source_address, source_port, destination_port = conv

                    # Increment request count for each destination port
                    if destination_port not in port_request_count:
                        port_request_count[destination_port] = 1
                    else:
                        port_request_count[destination_port] += 1

                # Check if any port is receiving too many requests (DDoS detection)
                for port, count in port_request_count.items():
                    if count >= max_incoming_threshold:
                        print(
                            f"Potential DDoS attack detected on port {port} with {count} incoming requests."
                        )
                        block_port(port)  # Block the port
                        port_request_count[port] = 0  # Reset counter after blocking

        # Optionally, clear out old conversations to save memory if log grows too large
        with conversations_lock:
            if len(conversations) > 1000:  # Keep the log size reasonable
                del conversations[:500]


def main():
    # Start threads for logging and analyzing
    log_thread = threading.Thread(target=log_network_conversations)
    analyze_thread = threading.Thread(target=analyze_conversations)

    log_thread.start()
    analyze_thread.start()

    log_thread.join()
    analyze_thread.join()


if __name__ == "__main__":
    main()
