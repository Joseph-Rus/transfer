import asyncio
import aiohttp
import time
from collections import defaultdict

stats = defaultdict(int)
start_time = time.time()

async def aggressive_async_client(session, client_id):
    """Ultra-aggressive async client"""
    while True:
        try:
            async with session.get("http://localhost:8000/", timeout=aiohttp.ClientTimeout(total=5)) as response:
                await response.read()
                stats['success'] += 1
                
        except asyncio.TimeoutError:
            stats['timeouts'] += 1
        except aiohttp.ClientError:
            stats['connection_errors'] += 1
        except Exception:
            stats['other_errors'] += 1

async def stats_reporter():
    """Reports statistics"""
    last_total = 0
    
    while True:
        await asyncio.sleep(2)
        
        current_total = stats['success']
        requests_this_interval = current_total - last_total
        last_total = current_total
        
        elapsed = time.time() - start_time
        total_requests = stats['success'] + stats['timeouts'] + stats['connection_errors'] + stats['other_errors']
        
        print(f"\n{'='*60}")
        print(f"  ASYNC LOAD TEST - {elapsed:.1f}s elapsed")
        print(f"{'='*60}")
        print(f"  Successful:             {stats['success']:,}")
        print(f"  Failed:                 {stats['timeouts'] + stats['connection_errors'] + stats['other_errors']:,}")
        print(f"  Total:                  {total_requests:,}")
        print(f"  Requests/sec (avg):     {stats['success'] / elapsed:.2f}")
        print(f"  Requests/sec (last 2s): {requests_this_interval / 2:.2f}")
        print(f"{'='*60}\n")

async def main():
    print("╔═══════════════════════════════════════════════════════════╗")
    print("║     ULTRA-AGGRESSIVE ASYNC LOAD TESTER (NO LIMITS!)      ║")
    print("╚═══════════════════════════════════════════════════════════╝\n")
    
    try:
        number_of_clients = int(input("Number of concurrent clients (50-1000 recommended): ") or "100")
    except ValueError:
        number_of_clients = 100
    
    print(f"\nLaunching {number_of_clients} concurrent async clients...")
    print("⚠️  WARNING: This will hammer your server HARD!")
    print("Press Ctrl+C to stop\n")
    
    # Configure connection pooling
    connector = aiohttp.TCPConnector(limit=0, limit_per_host=0)
    timeout = aiohttp.ClientTimeout(total=5)
    
    async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
        # Create tasks
        tasks = [
            asyncio.create_task(aggressive_async_client(session, i))
            for i in range(number_of_clients)
        ]
        tasks.append(asyncio.create_task(stats_reporter()))
        
        try:
            await asyncio.gather(*tasks)
        except KeyboardInterrupt:
            print("\n\nStopping...")
            
            elapsed = time.time() - start_time
            total = stats['success'] + stats['timeouts'] + stats['connection_errors'] + stats['other_errors']
            
            print(f"\n{'='*60}")
            print(f"  FINAL RESULTS:")
            print(f"  Duration:               {elapsed:.2f}s")
            print(f"  Total Requests:         {total:,}")
            print(f"  Successful:             {stats['success']:,}")
            print(f"  Average Requests/sec:   {stats['success'] / elapsed:.2f}")
            print(f"{'='*60}\n")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass