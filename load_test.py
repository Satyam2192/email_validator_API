import asyncio
import httpx

async def send_request(client, idx):
    try:
        response = await client.post(
            "http://127.0.0.1:10000/validate_email",
            json={"email": "test@example.com"}
        )
        print(f"Request {idx}: Status {response.status_code}")
        if response.status_code != 200:
            # Optionally, print the error details.
            print(f"  Response: {response.text}")
    except Exception as e:
        print(f"Request {idx} failed: {str(e)}")

async def main():
    async with httpx.AsyncClient() as client:
        tasks = []
        total_requests = 120  # Exceeding 100 to trigger rate limiting.
        for i in range(total_requests):
            tasks.append(send_request(client, i))
        await asyncio.gather(*tasks)

if __name__ == "__main__":
    asyncio.run(main()) 