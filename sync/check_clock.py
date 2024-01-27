import paramiko
import time
from io import StringIO

remote_ip = "10.10.5.11"

# Python script to be executed remotely
remote_script = """
import time

# clk_id for monotonic clock
clk_id = time.CLOCK_MONOTONIC

# Get the time (in seconds) of the monotonic clock
t = time.clock_gettime(clk_id)

# Print the time (in seconds) of the monotonic clock
print("Value of monotonic clock time:", t)
"""

def run_remote_script(ip, username, password, script):
    # Create an SSH client
    ssh_client = paramiko.SSHClient()
    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        # Connect to the remote machine
        ssh_client.connect(ip, username=username, password=password)

        # Create a temporary file to store the Python script
        script_file = StringIO(script)

        # Upload the script to the remote machine
        sftp = ssh_client.open_sftp()
        sftp.putfo(script_file, "/tmp/remote_script.py")
        sftp.close()

        # Execute the script remotely
        _, stdout, _ = ssh_client.exec_command("python3 /tmp/remote_script.py")
        result = stdout.read().decode("utf-8")

        return result
    finally:
        # Close the SSH connection
        ssh_client.close()

# Get MONOTONIC_CLOCK value on the local machine
local_result = run_remote_script("localhost", "bonsai", "bonsai123", remote_script)
# Get MONOTONIC_CLOCK value on the remote machine
remote_result = run_remote_script(remote_ip, "bonsai", "bonsai123", remote_script)

# Print results
''' print("Local Machine:", local_result)
print("Remote Machine:", remote_result) '''

# Calculate the time difference
local_time = float(local_result.split(":")[-1])
remote_time = float(remote_result.split(":")[-1])
time_difference1 = local_time - remote_time

#print(f"Time Difference: {time_difference1} seconds")

# execute the script first at CPE A and then to CPE B to calculate the average difference

# Get MONOTONIC_CLOCK value on the remote machine
remote_result = run_remote_script(remote_ip, "bonsai", "bonsai123", remote_script)
# Get MONOTONIC_CLOCK value on the local machine
local_result = run_remote_script("localhost", "bonsai", "bonsai123", remote_script)

# Print results
''' print("Local Machine:", local_result)
print("Remote Machine:", remote_result) '''

# Calculate the time difference
local_time = float(local_result.split(":")[-1])
remote_time = float(remote_result.split(":")[-1])
time_difference2 = local_time - remote_time

#print(f"Time Difference: {time_difference2} seconds")

avg_td = (time_difference1+time_difference2)/2
print(avg_td)