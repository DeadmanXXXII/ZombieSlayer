import socket
import threading
from tkinter import *
from tkinter import messagebox

class ZombieSlayer:
    def __init__(self):
        self.authorized_ips = []  # Initialize an empty list to store authorized IP addresses
        self.termination_commands = {  # Initialize a dictionary to store termination commands for each protocol
            'ssh': '',
            'telnet': '',
            'http': '',
            'https': '',
            'ftp': ''
        }
        self.options = {  # Initialize a dictionary to store options for the defense system
            'logging': False,
            'authentication': False,
            'encryption': False,
            'input_validation': False,
            'rate_limiting': False,
            'automated_response': False,
            'regular_updates': False,
            'testing': False,
            'permissions': False,
            'alerting': False,
            'suspicious_processes': False,
            'resource_intensive_activities': False,
            'dos_attacks': False,
            'data_exfiltration': False,
            'malware_detection': False,
            'unauthorized_access_attempts': False,
            'system_integrity_checks': False,
            'security_patch_management': False
        }

    def start_defense_system(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind(('0.0.0.0', 0))  # Bind to all interfaces on an ephemeral port
        port = server.getsockname()[1]  # Get the assigned port
        print(f"Zombie Slayer started on port {port}. Waiting for connections...")

        server.listen(5)
        while True:
            client, addr = server.accept()
            threading.Thread(target=self.handle_connection, args=(client, addr)).start()

    def handle_connection(self, client, addr):
        remote_ip = addr[0]  # Get the IP address of the remote client
        print(f"Incoming connection from {remote_ip}.")

        client.send(b"Welcome to the Zombie Slayer.\nDo you want to allow this connection? (Y/N)")
        choice = client.recv(1024).strip().decode().upper()  # Prompt the user to allow or deny the connection

        if choice == 'Y':
            if remote_ip in self.authorized_ips:  # Check if the remote IP is authorized
                print(f"{remote_ip} is authorized. Connection allowed.")
                client.send(b"Connection allowed.")
                # Implement your logic for handling the authorized connection here
            else:
                print(f"{remote_ip} is not authorized. Connection denied.")
                client.send(b"Connection denied. Unauthorized access.")
                self.terminate_connections(remote_ip)  # Terminate connections from unauthorized IP addresses
        else:
            print("Connection denied by user choice.")
            client.send(b"Connection denied by user choice.")

        client.close()

    def open_gui(self):
        def save_settings():
            self.save_ips(ip_input.get().split(','))
            self.termination_commands['ssh'] = ssh_input.get()
            for option, var in option_vars.items():
                self.options[option] = var.get()
            messagebox.showinfo("Info", "Settings saved.")

        root = Tk()
        root.title("Zombie Slayer")
        root.geometry("600x800")

        frame = Frame(root, padx=10, pady=10)
        frame.pack(fill=BOTH, expand=True)

        # Header
        header = Label(frame, text="Zombie Slayer", font=("Helvetica", 16, "bold"))
        header.pack(anchor=CENTER, pady=10)

        Label(frame, text="Enter authorized IP addresses (separated by commas):").pack(anchor=W)
        ip_input = Entry(frame, width=80)
        ip_input.pack(fill=X)

        # SSH Termination Command
        Label(frame, text="SSH Termination Command:").pack(anchor=W)
        ssh_input = Entry(frame, width=80)
        ssh_input.pack(fill=X)
        Button(frame, text="Save", command=save_settings).pack(pady=10)

        # Options
        Label(frame, text="Options:").pack(anchor=W)
        option_vars = {}
        for option in self.options:
            var = BooleanVar(value=self.options[option])
            Checkbutton(frame, text=option.replace('_', ' ').capitalize(), variable=var).pack(anchor=W)
            option_vars[option] = var

        # Footer
        footer = Label(frame, text="Built by DeadmanXXXII", font=("Helvetica", 10, "italic"))
        footer.pack(side=BOTTOM, pady=10)

        root.mainloop()

    def save_ips(self, ips):
        self.authorized_ips = [ip.strip() for ip in ips]  # Save authorized IP addresses

    def terminate_connections(self, ip):
        self.terminate_ssh_connections(ip)
        self.terminate_telnet_connections(ip)
        self.terminate_http_connections(ip)
        self.terminate_https_connections(ip)
        self.terminate_ftp_connections(ip)
        # Add more termination methods for other protocols if needed

    def terminate_ssh_connections(self, ip):
        if self.options['authentication']:  # Execute SSH termination command if authentication option is enabled
            self.execute_command(self.termination_commands['ssh'].replace('%IP%', ip))
        print(f"Terminated SSH connection from {ip}.")

    def terminate_telnet_connections(self, ip):
        # Implement similar method for terminating Telnet connections
        pass

    def terminate_http_connections(self, ip):
        # Implement similar method for terminating HTTP connections
        pass

    def terminate_https_connections(self, ip):
        # Implement similar method for terminating HTTPS connections
        pass

    def terminate_ftp_connections(self, ip):
        # Implement similar method for terminating FTP connections
        pass

    def execute_command(self, command):
        import os
        os.system(command)  # Execute system command

# Start the Zombie Slayer
zombie_slayer = ZombieSlayer()
threading.Thread(target=zombie_slayer.start_defense_system).start()  # Start the defense system
zombie_slayer.open_gui()  # Open the GUI for settings configuration