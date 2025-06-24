from time import sleep
import awsiot.greengrasscoreipc.clientv2 as clientV2
from os import environ
from logging import Logger

logger = Logger('publish_to_iot_core')

def main():
    topic = environ.get('MQTT_TOPIC', default='my/topic')
    qos = int(environ.get('MQTT_QOS', default='1'))
    payload = environ.get('MQTT_PAYLOAD', default='Hello, World')

    logger.info('Creating IPC client')
    ipc_client = clientV2.GreengrassCoreIPCClientV2()
    for i in range(5):
        logger.info(f'Preparing to publish {payload} to {topic} with QoS={qos}')
        resp = ipc_client.publish_to_iot_core(topic_name=topic, qos=qos, payload=payload)
        logger.info('Sleeping...')
        sleep(5)
    logger.info(f'Preparing to publish {payload} to {topic} with QoS={qos}')
    resp = ipc_client.publish_to_iot_core(topic_name=topic, qos=qos, payload=payload)
    logger.info('Stopping...')
    ipc_client.close()

if __name__ == "__main__":
    main()

