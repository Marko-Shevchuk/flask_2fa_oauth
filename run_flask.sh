#!/bin/bash

echo "Building Docker image..."
docker build --tag flask-docker-multistage .

echo "Running Docker container..."
docker run -d -p 5000:5000 flask-docker-multistage

echo "Docker container has been built and started successfully!"