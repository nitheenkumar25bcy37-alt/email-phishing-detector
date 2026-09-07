import asyncio
import httpx
import time

URL = "http://127.0.0.1:8000/api/v1/analyze/text"
PAYLOAD = {
    "subject": "Stress Test Email",
    "sender": "alert@load-test-domain.com",
    "body": "Simultaneous execution to check database write concurrency and locking."
}

async def send_request(client, req_id):
    try:
        res = await client.post(URL, json=PAYLOAD, timeout=10.0)
        return res.status_code
    except Exception as e:
        return str(e)

async def main():
    async with httpx.AsyncClient() as client:
        tasks = [send_request(client, i) for i in range(50)] # 50 simultaneous requests
        start = time.time()
        results = await asyncio.gather(*tasks)
        elapsed = time.time() - start
        
        success = results.count(200)
        failures = len(results) - success
        print(f"Completed 50 concurrent requests in {elapsed:.2f}s")
        print(f"Success (200 OK): {success} | Failed: {failures}")

if __name__ == "__main__":
    asyncio.run(main())
