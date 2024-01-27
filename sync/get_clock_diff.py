import paramiko
from statistics import mean
import time
import subprocess
import sys

folder = "/home/bonsai/enrico-gregorini/sync/"
remote_ip = sys.argv[1]

def get_monotonic_clock(remote_ip=None, remote_username=None, remote_password=None):
    start_time = time.time()
    ssh_time = 0
    if remote_ip is None:
        # Run the compiled C program locally
        result = subprocess.run([folder + 'monotonic'], stdout=subprocess.PIPE, text=True)
        # Extract the MONOTONIC_CLOCK value from the output
        mn_ts_str = result.stdout.split(':')[-1].strip()
        mn_ts = float(mn_ts_str)
        # Now, mn_ts contains the MONOTONIC_CLOCK value in seconds
        # print(f"MONOTONIC_CLOCK in Python (Local): {mn_ts} seconds")
    else:
        # Run the compiled C program remotely via SSH
        ssh_client = paramiko.SSHClient()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        try:
            # Connect to the remote machine
            ssh_client.connect(remote_ip, username=remote_username, password=remote_password)
            
            # Measure the SSH connection delay
            ssh_time = time.time() - start_time

            # Execute the C program remotely
            _, stdout, _ = ssh_client.exec_command(folder + 'monotonic')
            remote_output = stdout.read().decode("utf-8")

            # Extract the MONOTONIC_CLOCK value from the remote output
            mn_ts_str = remote_output.split(':')[-1].strip()
            mn_ts = float(mn_ts_str)
            # Now, mn_ts contains the MONOTONIC_CLOCK value in seconds
            # print(f"MONOTONIC_CLOCK in Python (Remote): {mn_ts} seconds")
        finally:
            # Close the SSH connection
            ssh_client.close()

    return mn_ts, ssh_time

# Example usage:
time_diff = []
ssh_connection_times = []

for i in range(3):
    # Remote machine (replace with actual IP, username, and password)
    remote_ts, ssh_connection_time = get_monotonic_clock(remote_ip=remote_ip, remote_username="bonsai", remote_password="bonsai123")
    # Local machine
    local_ts, tmp = get_monotonic_clock()
    time_diff.append(remote_ts - local_ts)
    ssh_connection_times.append(ssh_connection_time)

# tells if local CPE (True) is ahead in time or remote CPE is ahead (False)
local_CPE_ahead = True if time_diff[-1] < 0 else False

average_ssh_connection_time = mean(ssh_connection_times)/11
#print(f"Average SSH Connection Time: {average_ssh_connection_time} seconds")
time_delta = abs(mean(time_diff) + average_ssh_connection_time)
print(time_delta, local_CPE_ahead)
