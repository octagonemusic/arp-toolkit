#!/bin/bash

# Make sure we're in the project root
cd "$(dirname "$0")"

# Copy requirements.txt to the docker directory if it doesn't exist
if [ ! -f docker/requirements.txt ]; then
  cp -v docker/requirements.txt .
fi

echo "Building Docker containers..."
cd docker
docker-compose build

echo "Starting the Docker environment..."
docker-compose up -d

echo ""
echo "Docker environment is running!"
echo ""
echo "To access the containers:"
echo "  Gateway: docker exec -it gateway bash"
echo "  Victim:  docker exec -it victim bash"
echo "  Attacker: docker exec -it attacker bash"
echo ""
echo "Attack example:"
echo "  docker exec -it attacker python /app/main.py attack --target 172.29.50.20 --gateway 172.29.50.10"
echo ""
echo "Defense example:"
echo "  docker exec -it victim python /app/main.py defense"
echo ""
echo "To stop the environment:"
echo "  cd docker && docker-compose down"
