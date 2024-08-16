#!/bin/bash

echo "Working on it..."
curl -sL https://deb.nodesource.com/setup_16.x | sudo -E bash -
sudo apt update
sudo apt-get install -y nodejs
sudo mkdir -p /etc/g13
sudo curl -o /etc/g13/g13.js https://raw.githubusercontent.com/xehsoftware/G13/main/g13.js
cd /etc/g13
sudo npm init -y
sudo npm install dockerode fs-extra axios path glob crypto pm2 -g
sudo npm install dockerode fs-extra axios path glob crypto pm2
sudo pm2 start /etc/g13/g13.js --name "g13"
sudo pm2 save
sudo pm2 startup
echo "G13 has been set up."
