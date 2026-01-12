#!/bin/bash

# Script to start both Django backend and React frontend

# Color codes for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${BLUE}================================${NC}"
echo -e "${BLUE}🚀 Starting CVE Alert System${NC}"
echo -e "${BLUE}================================${NC}"

# Get the script directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$SCRIPT_DIR"

# Function to cleanup on exit
cleanup() {
    echo -e "\n${RED}🛑 Shutting down servers...${NC}"
    kill $(jobs -p) 2>/dev/null
    exit
}

# Trap Ctrl+C and call cleanup
trap cleanup SIGINT SIGTERM

# Start Django backend
echo -e "\n${GREEN}📦 Starting Django backend on http://127.0.0.1:8000${NC}"
python manage.py runserver &
BACKEND_PID=$!

# Wait a moment for backend to start
sleep 2

# Start React frontend
echo -e "\n${GREEN}⚛️  Starting React frontend on http://localhost:3000${NC}"
cd cve-frontend
npm start &
FRONTEND_PID=$!

echo -e "\n${BLUE}================================${NC}"
echo -e "${GREEN}✅ Both servers are running!${NC}"
echo -e "${BLUE}================================${NC}"
echo -e "Backend:  http://127.0.0.1:8000"
echo -e "Frontend: http://localhost:3000"
echo -e "\nPress ${RED}Ctrl+C${NC} to stop both servers"
echo -e "${BLUE}================================${NC}\n"

# Wait for both processes
wait
