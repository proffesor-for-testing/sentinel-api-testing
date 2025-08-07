import pika
import json
import structlog
from sentinel_backend.config.settings import get_broker_settings

logger = structlog.get_logger(__name__)
broker_settings = get_broker_settings()

def publish_task(task_data: dict):
    """
    Publishes a task to the RabbitMQ queue.
    """
    try:
        connection = pika.BlockingConnection(pika.URLParameters(broker_settings.url))
        channel = connection.channel()
        channel.queue_declare(queue=broker_settings.task_queue_name, durable=True)
        
        message = json.dumps(task_data)
        
        channel.basic_publish(
            exchange='',
            routing_key=broker_settings.task_queue_name,
            body=message,
            properties=pika.BasicProperties(
                delivery_mode=2,  # make message persistent
            ))
        
        connection.close()
        logger.info("Task published to RabbitMQ", task_id=task_data.get("task", {}).get("task_id"))
        return True
    except Exception as e:
        logger.error("Failed to publish task to RabbitMQ", error=str(e))
        return False