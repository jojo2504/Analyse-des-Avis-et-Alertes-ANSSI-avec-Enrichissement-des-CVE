#!/bin/bash

# Script to start both Django backend and React frontend

# Color codes for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${BLUE}================================${NC}"
echo -e "${BLUE}Starting CVE Alert System${NC}"
echo -e "${BLUE}================================${NC}"

# Get the script directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$SCRIPT_DIR"

# Function to cleanup on exit
cleanup() {
    echo -e "\n${RED}Shutting down servers...${NC}"
    kill $(jobs -p) 2>/dev/null
    exit
}

# Trap Ctrl+C and call cleanup
trap cleanup SIGINT SIGTERM

# Check if virtual environment exists, if not create it
VENV_DIR=""
if [ -d "venv" ]; then
    VENV_DIR="venv"
elif [ -d ".venv" ]; then
    VENV_DIR=".venv"
else
    echo -e "\n${BLUE}Creating virtual environment...${NC}"
    python3 -m venv venv
    VENV_DIR="venv"
    echo -e "${GREEN}Virtual environment created${NC}"
fi

# Activate virtual environment
echo -e "\n${BLUE}Activating virtual environment...${NC}"
source "$VENV_DIR/bin/activate"

# Install Python requirements
echo -e "\n${BLUE}Installing Python dependencies...${NC}"
pip install -q -r requirements.txt
echo -e "${GREEN}Python dependencies installed${NC}"

# Install npm dependencies in cve-frontend
echo -e "\n${BLUE}Installing npm dependencies in cve-frontend...${NC}"
cd cve-frontend
npm install
cd ..
echo -e "${GREEN}npm dependencies installed${NC}"

# Start Django backend
echo -e "\n${GREEN}Starting Django backend on http://127.0.0.1:8000${NC}"
python manage.py runserver &
BACKEND_PID=$!

# Wait a moment for backend to start
sleep 2

# Start React frontend
echo -e "\n${GREEN}Starting React frontend on http://localhost:3000${NC}"
cd cve-frontend
npm start &
FRONTEND_PID=$!

echo -e "\n${BLUE}================================${NC}"
echo -e "${GREEN}Both servers are running!${NC}"
echo -e "${BLUE}================================${NC}"
echo -e "Backend:  http://127.0.0.1:8000"
echo -e "Frontend: http://localhost:3000"
echo -e "\nPress ${RED}Ctrl+C${NC} to stop both servers"
echo -e "${BLUE}================================${NC}\n"

# Wait for both processes
wait
