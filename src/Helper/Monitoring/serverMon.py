import psutil
import time
from TelegramBot.TelegramBot import TelegramBot

telegramBot = TelegramBot()
pot_critical = False  # Flag to track if usage is potentially critical

# Lists to store usage metrics for the last 5 minutes
cpu_usage_history = []
memory_usage_history = []
disk_usage_history = []

while True:
    # CPU usage
    cpu_usage = psutil.cpu_percent(interval=1)
    
    # Memory usage
    memory_info = psutil.virtual_memory()
    memory_usage = memory_info.percent
    
    # Disk usage
    disk_usage = psutil.disk_usage('/')
    disk_usage_percent = disk_usage.percent

    # Threads count
    thread_count = psutil.cpu_count(logical=True)
    
    # Add the current usage to the history lists
    cpu_usage_history.append(cpu_usage)
    memory_usage_history.append(memory_usage)
    disk_usage_history.append(disk_usage_percent)
    
    # Ensure the history lists only contain the last 5 minutes of data (5 entries)
    if len(cpu_usage_history) > 5:
        cpu_usage_history.pop(0)
    if len(memory_usage_history) > 5:
        memory_usage_history.pop(0)
    if len(disk_usage_history) > 5:
        disk_usage_history.pop(0)
    
    # Calculate the average usage for the last 5 minutes
    avg_cpu_usage = sum(cpu_usage_history) / len(cpu_usage_history)
    avg_memory_usage = sum(memory_usage_history) / len(memory_usage_history)
    avg_disk_usage = sum(disk_usage_history) / len(disk_usage_history)


    print(f"Current CPU Usage: {cpu_usage}%, 5-min Avg: {avg_cpu_usage:.2f}%")
    print(f"Current Memory Usage: {memory_usage}%, 5-min Avg: {avg_memory_usage:.2f}%")
    print(f"Current Disk Usage: {disk_usage_percent}%, 5-min Avg: {avg_disk_usage:.2f}%")
    print(f" - Number Threads: {thread_count}")

    
    # Check if any of the usage metrics are above 90%
    if avg_cpu_usage > 90 or avg_memory_usage > 90 or avg_disk_usage > 90:
        if pot_critical:  # If it was already critical, issue a warning
            telegramBot.warning("[MONITORING] WARNING: Resource usage is critically high!")
            telegramBot.warning(f" - CPU Usage: {cpu_usage}%, 5-min Avg: {avg_cpu_usage:.2f}%")
            telegramBot.warning(f" - Memory Usage: {memory_usage}%, 5-min Avg: {avg_memory_usage:.2f}%")
            telegramBot.warning(f" - Disk Usage: {disk_usage_percent}%, 5-min Avg: {avg_disk_usage:.2f}%")
            telegramBot.warning(f" - Number Threads: {thread_count}")
        else:
            pot_critical = True  # Mark the system as potentially critical
    else:
        pot_critical = False  # Reset the critical flag if usage is below 90%
    
    time.sleep(60)  # Wait for 60 seconds before the next check

