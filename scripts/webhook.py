import os
import hmac
import hashlib
import subprocess
from aiohttp import web
import asyncio
import json

WEBHOOK_SECRET = os.environ.get("WEBHOOK_SECRET", "default_secret")

task_queue = asyncio.Queue()
worker_lock = asyncio.Lock()

async def worker():
    while True:
        task = await task_queue.get()
        json_body = json.loads(task)

        async with worker_lock:
            print(f"Processing task: {json_body['after']}")
            try:
                subprocess.run(['scripts/run_benchmark.sh', json_body['after']], check=True)
                print("Task completed successfully.")
            except subprocess.CalledProcessError as e:
                print(f"Task failed: {e}")
            
            task_queue.task_done()

def verify_signature(body, signature):
    hash_object = hmac.new(WEBHOOK_SECRET.encode('utf-8'), msg=body, digestmod=hashlib.sha256)
    calculated_signature = f"sha256={hash_object.hexdigest()}"
    print(f"Calculated signature: {calculated_signature}")
    return hmac.compare_digest(calculated_signature, signature)

async def handle_webhook(request):
    body = await request.read()
    json_body = json.loads(body)

    if not json_body['ref'] == "refs/heads/main":
        print("Ignoring request")
        return web.Response(text="Ignoring request", status=200)

    # verify that the request really came from github
    signature = request.headers.get("X-Hub-Signature-256", "")
    print(f"Received signature: {signature}")

    if not verify_signature(body, signature):  
        print("Invalid signature")
        return web.Response(text="Invalid signature", status=401)

    await task_queue.put(body)
    return web.Response(text="Task received and queued", status=202)

app = web.Application()
app.router.add_post("/trigger-benchmark", handle_webhook)

async def start_worker(app):
    asyncio.create_task(worker())

if __name__ == '__main__':
    app.on_startup.append(start_worker)
    web.run_app(app, port=5000)
