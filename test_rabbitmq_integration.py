#!/usr/bin/env python3
"""
Test script for RabbitMQ integration in Sentinel platform.
This script tests the asynchronous message broker architecture.
"""

import asyncio
import json
import time
import pika
import httpx
from typing import Dict, Any

# Configuration
API_GATEWAY_URL = "http://localhost:8000"
RABBITMQ_URL = "amqp://guest:guest@localhost:5672/"
TASK_QUEUE = "sentinel_task_queue"
RESULT_QUEUE = "sentinel_result_queue"

class RabbitMQIntegrationTest:
    def __init__(self):
        self.connection = None
        self.channel = None
        self.results = []
        
    def connect_rabbitmq(self):
        """Connect to RabbitMQ"""
        try:
            self.connection = pika.BlockingConnection(pika.URLParameters(RABBITMQ_URL))
            self.channel = self.connection.channel()
            self.channel.queue_declare(queue=TASK_QUEUE, durable=True)
            self.channel.queue_declare(queue=RESULT_QUEUE, durable=True)
            print("✅ Connected to RabbitMQ")
            return True
        except Exception as e:
            print(f"❌ Failed to connect to RabbitMQ: {e}")
            return False
    
    def publish_test_task(self, task_data: Dict[str, Any]):
        """Publish a test task to RabbitMQ"""
        try:
            message = json.dumps(task_data)
            self.channel.basic_publish(
                exchange='',
                routing_key=TASK_QUEUE,
                body=message,
                properties=pika.BasicProperties(
                    delivery_mode=2,  # make message persistent
                ))
            print(f"📤 Published task: {task_data.get('task', {}).get('task_id')}")
            return True
        except Exception as e:
            print(f"❌ Failed to publish task: {e}")
            return False
    
    def check_queue_depth(self):
        """Check the number of messages in the queue"""
        try:
            method = self.channel.queue_declare(queue=TASK_QUEUE, durable=True, passive=True)
            return method.method.message_count
        except Exception as e:
            print(f"❌ Failed to check queue depth: {e}")
            return -1
    
    async def test_http_endpoint(self):
        """Test the HTTP endpoint to ensure it still works"""
        async with httpx.AsyncClient() as client:
            try:
                # Test health endpoint
                response = await client.get(f"{API_GATEWAY_URL}/health")
                if response.status_code == 200:
                    print("✅ API Gateway health check passed")
                else:
                    print(f"❌ API Gateway health check failed: {response.status_code}")
                
                # Test creating a specification
                spec_data = {
                    "name": "RabbitMQ Test API",
                    "version": "1.0.0",
                    "openapi": "3.0.0",
                    "paths": {
                        "/test": {
                            "get": {
                                "summary": "Test endpoint",
                                "responses": {
                                    "200": {
                                        "description": "Success",
                                        "content": {
                                            "application/json": {
                                                "schema": {
                                                    "type": "object",
                                                    "properties": {
                                                        "message": {"type": "string"}
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                
                response = await client.post(
                    f"{API_GATEWAY_URL}/specs",
                    json=spec_data
                )
                
                if response.status_code in [200, 201]:
                    spec_id = response.json().get("id")
                    print(f"✅ Created test specification: {spec_id}")
                    return spec_id
                else:
                    print(f"❌ Failed to create specification: {response.status_code}")
                    return None
                    
            except Exception as e:
                print(f"❌ HTTP test failed: {e}")
                return None
    
    async def test_message_broker_flow(self, spec_id: str):
        """Test the complete message broker flow"""
        # Create test task
        test_task = {
            "task": {
                "task_id": f"rabbitmq-test-{int(time.time())}",
                "agent_type": "functional-positive",
                "spec_id": spec_id,
                "parameters": {  # Add required parameters field
                    "max_test_cases": 5
                },
                "target_environment": "test"
            },
            "api_spec": {
                "openapi": "3.0.0",
                "paths": {
                    "/test": {
                        "get": {
                            "summary": "Test endpoint",
                            "responses": {
                                "200": {
                                    "description": "Success"
                                }
                            }
                        }
                    }
                }
            }
        }
        
        # Check initial queue depth
        initial_depth = self.check_queue_depth()
        print(f"📊 Initial queue depth: {initial_depth}")
        
        # Publish task
        if self.publish_test_task(test_task):
            # Wait a bit for processing
            await asyncio.sleep(2)
            
            # Check queue depth after publishing
            after_publish_depth = self.check_queue_depth()
            print(f"📊 Queue depth after publish: {after_publish_depth}")
            
            # Wait for processing
            print("⏳ Waiting for task processing...")
            await asyncio.sleep(5)
            
            # Check final queue depth
            final_depth = self.check_queue_depth()
            print(f"📊 Final queue depth: {final_depth}")
            
            if final_depth < after_publish_depth:
                print("✅ Task was consumed from the queue")
                return True
            else:
                print("⚠️ Task may not have been processed")
                return False
        
        return False
    
    def cleanup(self):
        """Clean up connections"""
        if self.connection:
            self.connection.close()
            print("🧹 Closed RabbitMQ connection")

async def main():
    print("🚀 Starting RabbitMQ Integration Test")
    print("=" * 50)
    
    tester = RabbitMQIntegrationTest()
    
    # Step 1: Connect to RabbitMQ
    if not tester.connect_rabbitmq():
        print("❌ Cannot proceed without RabbitMQ connection")
        return
    
    # Step 2: Test HTTP endpoints
    print("\n📝 Testing HTTP endpoints...")
    spec_id = await tester.test_http_endpoint()
    
    if not spec_id:
        print("⚠️ Continuing with mock spec_id")
        spec_id = "test-spec-123"
    
    # Step 3: Test message broker flow
    print("\n📬 Testing message broker flow...")
    success = await tester.test_message_broker_flow(spec_id)
    
    # Step 4: Test multiple tasks
    print("\n📦 Testing multiple task publishing...")
    for i in range(3):
        test_task = {
            "task": {
                "task_id": f"batch-test-{i}-{int(time.time())}",
                "agent_type": "data-mocking",
                "spec_id": spec_id,
                "parameters": {  # Add required parameters field
                    "count": 3
                },
                "target_environment": "test"
            },
            "api_spec": {
                "openapi": "3.0.0",
                "paths": {
                    f"/test{i}": {
                        "get": {
                            "summary": f"Test endpoint {i}",
                            "responses": {
                                "200": {
                                    "description": "Success"
                                }
                            }
                        }
                    }
                }
            }
        }
        tester.publish_test_task(test_task)
        await asyncio.sleep(0.5)
    
    print("⏳ Waiting for batch processing...")
    await asyncio.sleep(5)
    
    final_queue_depth = tester.check_queue_depth()
    print(f"\n📊 Final queue depth after batch: {final_queue_depth}")
    
    # Cleanup
    tester.cleanup()
    
    print("\n" + "=" * 50)
    if success:
        print("✅ RabbitMQ integration test completed successfully!")
    else:
        print("⚠️ RabbitMQ integration test completed with warnings")
    
    print("\n📋 Test Summary:")
    print("- RabbitMQ connection: ✅")
    print(f"- HTTP endpoints: {'✅' if spec_id else '⚠️'}")
    print(f"- Message broker flow: {'✅' if success else '⚠️'}")
    print(f"- Final queue status: {final_queue_depth} messages remaining")

if __name__ == "__main__":
    asyncio.run(main())