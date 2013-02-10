from __future__ import absolute_import
import pika
from webapp import app

# Create the RabbitMQ broker and then open up a channel to it
connection = pika.BlockingConnection(pika.ConnectionParameters('localhost'))
channel = connection.channel()
channel.queue_declare(queue='log')
channel.queue_declare(queue='audit')

def main():
	startApp()

if __name__ == '__main__':
    main()