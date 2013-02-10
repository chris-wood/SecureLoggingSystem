from __future__ import absolute_import
import pika
from webapp.app import app
import core

# Create the RabbitMQ broker and then open up a channel to it
connection = pika.BlockingConnection(pika.ConnectionParameters('localhost'))
channel = connection.channel()
channel.queue_declare(queue='log')
channel.queue_declare(queue='audit')

def main():
	''' Load up the web app and the core ABLS service.
	'''
	print("Starting the ABLS instance")
	ABLSMain.start() # Start the service in the background
	print("Starting the front-end web app")
	app.run(debug=True)

if __name__ == '__main__':
    main()