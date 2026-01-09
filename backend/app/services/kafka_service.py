"""
Apache Kafka Service - Enterprise Event Streaming

Provides high-throughput, durable event streaming for:
- Event ingestion pipeline
- Risk decision publishing
- Alert distribution
- Cross-service communication

Features:
- Async producer/consumer
- Automatic reconnection
- Schema validation
- Graceful degradation

Topic Strategy:
- raw.ingest.events: Raw incoming events
- core.risk.scored: Enriched events with risk scores
- ops.alerts.high: High-priority alerts
- audit.compliance.archive: Audit logs for archival
"""

import logging
import json
import asyncio
from typing import Optional, Dict, Any, List, Callable, Awaitable
from datetime import datetime
from dataclasses import dataclass, field
from enum import Enum

from aiokafka import AIOKafkaProducer, AIOKafkaConsumer
from aiokafka.errors import KafkaError, KafkaConnectionError

from app.config import REDIS_URL

logger = logging.getLogger("sentineliq.kafka")


class KafkaTopics(str, Enum):
    """Kafka topic names following the taxonomy strategy."""
    
    # Raw event ingestion
    RAW_EVENTS = "raw.ingest.events"
    
    # Processed events with risk scores
    RISK_SCORED = "core.risk.scored"
    
    # High-priority alerts
    ALERTS_HIGH = "ops.alerts.high"
    
    # Audit logs for compliance archival
    AUDIT_ARCHIVE = "audit.compliance.archive"
    
    # Outbox CDC events (from Debezium)
    OUTBOX_EVENTS = "sentineliq.event_outbox"


@dataclass
class KafkaConfig:
    """Kafka configuration."""
    
    # Broker connection
    bootstrap_servers: str = "kafka:29092"
    
    # Producer settings
    acks: str = "all"  # Wait for all replicas
    retries: int = 5
    retry_backoff_ms: int = 100
    
    # Consumer settings
    group_id: str = "sentineliq-consumers"
    auto_offset_reset: str = "earliest"
    enable_auto_commit: bool = False  # Manual commits for exactly-once
    
    # Serialization
    value_serializer: Callable = field(default=lambda: lambda v: json.dumps(v).encode('utf-8'))
    value_deserializer: Callable = field(default=lambda: lambda v: json.loads(v.decode('utf-8')))
    
    # Connection
    request_timeout_ms: int = 30000
    connections_max_idle_ms: int = 540000


class KafkaProducerService:
    """
    Async Kafka producer for publishing events.
    
    Usage:
        producer = await KafkaProducerService.create()
        await producer.send_event(KafkaTopics.RAW_EVENTS, event_data)
        await producer.close()
    """
    
    def __init__(self, config: Optional[KafkaConfig] = None):
        self.config = config or KafkaConfig()
        self._producer: Optional[AIOKafkaProducer] = None
        self._started = False
    
    @classmethod
    async def create(cls, config: Optional[KafkaConfig] = None) -> 'KafkaProducerService':
        """Factory method to create and start producer."""
        service = cls(config)
        await service.start()
        return service
    
    async def start(self):
        """Start the Kafka producer."""
        if self._started:
            return
        
        try:
            self._producer = AIOKafkaProducer(
                bootstrap_servers=self.config.bootstrap_servers,
                acks=self.config.acks,
                retries=self.config.retries,
                retry_backoff_ms=self.config.retry_backoff_ms,
                value_serializer=self.config.value_serializer(),
                request_timeout_ms=self.config.request_timeout_ms,
            )
            
            await self._producer.start()
            self._started = True
            logger.info(f"Kafka producer connected to {self.config.bootstrap_servers}")
            
        except KafkaConnectionError as e:
            logger.warning(f"Kafka connection failed: {e}")
            self._started = False
        except Exception as e:
            logger.error(f"Kafka producer start failed: {e}")
            self._started = False
    
    async def close(self):
        """Close the Kafka producer."""
        if self._producer and self._started:
            await self._producer.stop()
            self._started = False
            logger.info("Kafka producer closed")
    
    @property
    def is_connected(self) -> bool:
        """Check if producer is connected."""
        return self._started and self._producer is not None
    
    async def send_event(
        self,
        topic: KafkaTopics,
        event: Dict[str, Any],
        key: Optional[str] = None,
        headers: Optional[Dict[str, str]] = None
    ) -> bool:
        """
        Send an event to a Kafka topic.
        
        Args:
            topic: Target Kafka topic
            event: Event data to send
            key: Optional partition key (user_id for ordering)
            headers: Optional message headers
            
        Returns:
            True if sent successfully, False otherwise
        """
        if not self.is_connected:
            logger.warning("Kafka producer not connected, event not sent")
            return False
        
        try:
            # Add metadata
            event['_kafka_timestamp'] = datetime.utcnow().isoformat()
            
            # Prepare headers
            kafka_headers = []
            if headers:
                kafka_headers = [(k, v.encode()) for k, v in headers.items()]
            
            # Send
            key_bytes = key.encode() if key else None
            
            await self._producer.send_and_wait(
                topic=topic.value,
                value=event,
                key=key_bytes,
                headers=kafka_headers
            )
            
            logger.debug(f"Event sent to {topic.value}: {event.get('event_id', 'unknown')}")
            return True
            
        except KafkaError as e:
            logger.error(f"Kafka send failed: {e}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error sending to Kafka: {e}")
            return False
    
    async def send_batch(
        self,
        topic: KafkaTopics,
        events: List[Dict[str, Any]],
        key_func: Optional[Callable[[Dict], str]] = None
    ) -> int:
        """
        Send a batch of events to Kafka.
        
        Args:
            topic: Target Kafka topic
            events: List of events to send
            key_func: Function to extract partition key from event
            
        Returns:
            Number of events successfully sent
        """
        if not self.is_connected:
            return 0
        
        sent = 0
        for event in events:
            key = key_func(event) if key_func else None
            if await self.send_event(topic, event, key):
                sent += 1
        
        return sent


class KafkaConsumerService:
    """
    Async Kafka consumer for processing events.
    
    Usage:
        consumer = await KafkaConsumerService.create([KafkaTopics.RAW_EVENTS])
        
        async for message in consumer.consume():
            process(message)
            await consumer.commit(message)
    """
    
    def __init__(self, topics: List[KafkaTopics], config: Optional[KafkaConfig] = None):
        self.topics = topics
        self.config = config or KafkaConfig()
        self._consumer: Optional[AIOKafkaConsumer] = None
        self._started = False
    
    @classmethod
    async def create(
        cls,
        topics: List[KafkaTopics],
        config: Optional[KafkaConfig] = None
    ) -> 'KafkaConsumerService':
        """Factory method to create and start consumer."""
        service = cls(topics, config)
        await service.start()
        return service
    
    async def start(self):
        """Start the Kafka consumer."""
        if self._started:
            return
        
        try:
            topic_names = [t.value for t in self.topics]
            
            self._consumer = AIOKafkaConsumer(
                *topic_names,
                bootstrap_servers=self.config.bootstrap_servers,
                group_id=self.config.group_id,
                auto_offset_reset=self.config.auto_offset_reset,
                enable_auto_commit=self.config.enable_auto_commit,
                value_deserializer=self.config.value_deserializer(),
            )
            
            await self._consumer.start()
            self._started = True
            logger.info(f"Kafka consumer subscribed to {topic_names}")
            
        except KafkaConnectionError as e:
            logger.warning(f"Kafka consumer connection failed: {e}")
            self._started = False
        except Exception as e:
            logger.error(f"Kafka consumer start failed: {e}")
            self._started = False
    
    async def close(self):
        """Close the Kafka consumer."""
        if self._consumer and self._started:
            await self._consumer.stop()
            self._started = False
            logger.info("Kafka consumer closed")
    
    @property
    def is_connected(self) -> bool:
        """Check if consumer is connected."""
        return self._started and self._consumer is not None
    
    async def consume(self):
        """
        Async generator to consume messages.
        
        Yields:
            Kafka messages as they arrive
        """
        if not self.is_connected:
            logger.warning("Kafka consumer not connected")
            return
        
        try:
            async for message in self._consumer:
                yield message
        except Exception as e:
            logger.error(f"Error consuming messages: {e}")
    
    async def commit(self, message=None):
        """
        Commit offset after processing message.
        
        Args:
            message: Optional message to commit offset for
        """
        if not self.is_connected:
            return
        
        try:
            if message:
                await self._consumer.commit({
                    message.topic: message.offset + 1
                })
            else:
                await self._consumer.commit()
        except Exception as e:
            logger.error(f"Error committing offset: {e}")


# Global producer instance
_producer: Optional[KafkaProducerService] = None


async def get_kafka_producer() -> KafkaProducerService:
    """Get or create Kafka producer singleton."""
    global _producer
    if _producer is None or not _producer.is_connected:
        _producer = await KafkaProducerService.create()
    return _producer


async def shutdown_kafka():
    """Shutdown Kafka connections."""
    global _producer
    if _producer:
        await _producer.close()
        _producer = None


# Convenience functions
async def publish_event(topic: KafkaTopics, event: Dict[str, Any], key: Optional[str] = None) -> bool:
    """Publish an event to Kafka."""
    producer = await get_kafka_producer()
    return await producer.send_event(topic, event, key)


async def publish_risk_decision(event_id: str, user_id: str, risk_score: float, decision: str) -> bool:
    """Publish a risk decision event."""
    event = {
        "event_id": event_id,
        "user_id": user_id,
        "risk_score": risk_score,
        "decision": decision,
        "timestamp": datetime.utcnow().isoformat()
    }
    return await publish_event(KafkaTopics.RISK_SCORED, event, key=user_id)


async def publish_alert(
    alert_id: str,
    severity: str,
    user_id: str,
    alert_type: str,
    details: Dict[str, Any]
) -> bool:
    """Publish a high-priority alert."""
    event = {
        "alert_id": alert_id,
        "severity": severity,
        "user_id": user_id,
        "alert_type": alert_type,
        "details": details,
        "timestamp": datetime.utcnow().isoformat()
    }
    return await publish_event(KafkaTopics.ALERTS_HIGH, event, key=user_id)


__all__ = [
    'KafkaProducerService',
    'KafkaConsumerService',
    'KafkaTopics',
    'KafkaConfig',
    'get_kafka_producer',
    'shutdown_kafka',
    'publish_event',
    'publish_risk_decision',
    'publish_alert'
]
