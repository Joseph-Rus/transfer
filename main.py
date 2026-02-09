import requests
import time
import threading
from collections import defaultdict

# Statistics tracking
stats = defaultdict(int)
stats_lock = threading.Lock()

def client_worker(client_id):
    """Function that each client thread will run"""
    request_count = 0
    
    while True:
        try:
            request_count += 1
            
            response = requests.get("http://localhost:8000/")
            
            with stats_lock:
                stats['total_requests'] += 1
                stats[f'client_{client_id}'] += 1
            
            if request_count % 10 == 0:  # Print every 10 requests
                print(f"Client #{client_id} - Completed {request_count} requests")
            
        except Exception as e:
            with stats_lock:
                stats['errors'] += 1
            print(f"Client #{client_id} - Error: {e}")

def stats_reporter():
    """Prints statistics every few seconds"""
    while True:
        time.sleep(5)
        with stats_lock:
            print(f"\n=== STATS ===")
            print(f"Total Requests: {stats['total_requests']}")
            print(f"Errors: {stats['errors']}")
            print("=============\n")

def main():
    # Change this number to control how many simultaneous clients
    number_of_clients = 10
    
    threads = []
    
    print(f"Starting {number_of_clients} clients...\n")
    
    # Start stats reporter
    stats_thread = threading.Thread(target=stats_reporter)
    stats_thread.daemon = True
    stats_thread.start()
    
    # Create and start multiple client threads
    for i in range(number_of_clients):
        thread = threading.Thread(target=client_worker, args=(i + 1,))
        thread.daemon = True
        thread.start()
        threads.append(thread)
    
    # Keep the main thread alive
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping all clients...")
        with stats_lock:
            print(f"\nFinal Stats:")
            print(f"Total Requests: {stats['total_requests']}")
            print(f"Errors: {stats['errors']}")

if __name__ == "__main__":
    main()