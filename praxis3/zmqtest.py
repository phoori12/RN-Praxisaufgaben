import zmq
import sys

context = zmq.Context()
socket = context.socket(zmq.REQ)  # Use REQ to match a REP server
socket.connect("tcp://127.0.0.1:1234")

# message = "fuck" # Get message from CLI arguments
test_message = "map\0"
socket.send(bytes(test_message, "ascii"))
print(f"Sent: {test_message}")
response = socket.recv_string()  # Wait for response (if any)
print(f"Received: {response}")
socket.close()

socket = context.socket(zmq.REQ)
socket.connect("tcp://127.0.0.1:2345")

message = "map" 
socket.send_string(message)
print(f"Sent: {message}")
response = socket.recv_string() 
print(f"Received: {response}")
socket.close()

socket = context.socket(zmq.REQ)
socket.connect("tcp://127.0.0.1:3456")

message = "rip" 
socket.send_string(message)
print(f"Sent: {message}")
response = socket.recv_string() 
print(f"Received: {response}")
socket.close()