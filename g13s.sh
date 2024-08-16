#!/bin/bash

echo "Working on it..."
sudo mkdir -p /etc/apt/keyrings
curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key | sudo gpg --dearmor -o /etc/apt/keyrings/nodesource.gpg
echo "deb [signed-by=/etc/apt/keyrings/nodesource.gpg] https://deb.nodesource.com/node_16.x nodistro main" | sudo tee /etc/apt/sources.list.d/nodesource.list
sudo apt update
sudo apt install -y nodejs npm
sudo mkdir -p /etc/g13
sudo curl -o /etc/g13/g13.js https://raw.githubusercontent.com/xehsoftware/G13/main/g13.js
sudo npm init -y
sudo npm install dockerode fs-extra axios path glob crypto pm2 -g
sudo pm2 start /etc/g13/g13.js --name "g13"
sudo pm2 save
sudo pm2 startup
echo "G13 has been set up."
