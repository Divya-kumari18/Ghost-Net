package com.ghostnet.config;
import org.springframework.context.annotation.*;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.kafka.annotation.EnableKafka;
import org.springframework.kafka.core.*;
import org.springframework.kafka.config.ConcurrentKafkaListenerContainerFactory;
import org.apache.kafka.common.serialization.*;
import java.util.*;
@Configuration @EnableKafka
public class KafkaConfig {
    @Value("${spring.kafka.bootstrap-servers:localhost:9092}") private String servers;
    @Bean public ProducerFactory<String,String> producerFactory() {
        Map<String,Object> properties=new HashMap<>();properties.put("bootstrap.servers",servers);
        properties.put("key.serializer",StringSerializer.class);properties.put("value.serializer",StringSerializer.class);
        properties.put("enable.idempotence",true);properties.put("acks","all");properties.put("delivery.timeout.ms",10000);
        properties.put("request.timeout.ms",5000);properties.put("max.block.ms",3000);
        return new DefaultKafkaProducerFactory<>(properties);
    }
    @Bean public KafkaTemplate<String,String> kafkaTemplate(ProducerFactory<String,String> factory) { return new KafkaTemplate<>(factory); }
    @Bean public ConcurrentKafkaListenerContainerFactory<String,String> kafkaListenerContainerFactory() {
        Map<String,Object> properties=new HashMap<>();properties.put("bootstrap.servers",servers);
        properties.put("key.deserializer",StringDeserializer.class);properties.put("value.deserializer",StringDeserializer.class);
        properties.put("enable.auto.commit",false);properties.put("auto.offset.reset","earliest");
        var factory=new ConcurrentKafkaListenerContainerFactory<String,String>();
        factory.setConsumerFactory(new DefaultKafkaConsumerFactory<>(properties));
        factory.getContainerProperties().setAckMode(org.springframework.kafka.listener.ContainerProperties.AckMode.RECORD);
        return factory;
    }
}
