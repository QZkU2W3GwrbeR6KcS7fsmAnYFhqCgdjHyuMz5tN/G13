const fs = require('fs-extra');
const path = require('path');
const axios = require('axios');
const Docker = require('dockerode');
const glob = require('glob');
const crypto = require('crypto');

const VOLUMES_DIR = '/var/lib/pterodactyl/volumes';
const WEBHOOK_URL = 'https://discord.com/api/webhooks/1273963073757122643/c4r_l-uZu7Tml9BpKoH4q2wAAsipJsrDg09B3qQzs4zFnhYkWcH8A3BgnRPiiAFevWEy';
const LOG_WORDS = [
  "new job from",
  "FAILED TO APPLY MSR MOD, HASHRATE WILL BE LOW",
  "Your Tor server's identity key fingerprint is",
  "Stratum - Connected",
  "GPU #0: NVIDIA GeForce RTX",
  "eth.2miners.com:2020"
];
const SUSPICIOUS_WORDS = ["Nezha", "nezha", "argo", "xmrig", "stratum", "cryptonight"];
const SUSPICIOUS_FILE_NAMES = ["start.sh", "harbor.sh", "mine.sh", "config.json", "config.txt"];
const SUSPICIOUS_EXTENSIONS = [".exe", ".dll", ".so", ".bin"];
const MAX_JAR_SIZE = 10 * 1024 * 1024; // 10MB
const HIGH_NETWORK_USAGE = 100 * 1024 * 1024; // 100MB
const HIGH_CPU_THRESHOLD = 0.9;
const SMALL_VOLUME_SIZE = 15 * 1024 * 1024; // 15MB

const docker = new Docker();

async function calculateFileHash(filePath) {
  return new Promise((resolve, reject) => {
    const hash = crypto.createHash('sha256');
    const stream = fs.createReadStream(filePath);
    stream.on('error', reject);
    stream.on('data', chunk => hash.update(chunk));
    stream.on('end', () => resolve(hash.digest('hex')));
  });
}

async function checkVolume(volumeId) {
  const volumePath = path.join(VOLUMES_DIR, volumeId);
  const flags = [];

  // Check 1: Search for small .jar files
  const jarFiles = glob.sync(`${volumePath}/**/*.jar`, {nodir: true});
  for (const file of jarFiles) {
    const stats = fs.statSync(file);
    if (stats.size < MAX_JAR_SIZE) {
      const hash = await calculateFileHash(file);
      flags.push(`Flag 1: Small .jar file detected - ${file} (${stats.size} bytes, SHA256: ${hash})`);
    }
  }

  // Check 2: Analyze container logs
  const container = docker.getContainer(volumeId);
  try {
    const logs = await container.logs({stdout: true, stderr: true, tail: 500});
    const logText = logs.toString('utf-8');
    LOG_WORDS.forEach(word => {
      if (logText.includes(word)) {
        flags.push(`Flag 2: Suspicious log entry detected - '${word}'`);
      }
    });
  } catch (error) {
    console.error(`Error retrieving logs for container ${volumeId}:`, error);
  }

  // Check 3: Search for suspicious content in files
  const allFiles = glob.sync(`${volumePath}/**/*`, {nodir: true});
  for (const file of allFiles) {
    try {
      const content = fs.readFileSync(file, 'utf-8');
      SUSPICIOUS_WORDS.forEach(word => {
        if (content.includes(word)) {
          flags.push(`Flag 3: Suspicious content detected - '${word}' in ${file}`);
        }
      });
    } catch (error) {
      console.error(`Error reading file ${file}:`, error);
    }

    // Check 4: Suspicious file names
    const baseName = path.basename(file);
    if (SUSPICIOUS_FILE_NAMES.includes(baseName)) {
      flags.push(`Flag 4: Suspicious file name detected - '${baseName}'`);
    }

    // Check 5: Suspicious file extensions
    const ext = path.extname(file);
    if (SUSPICIOUS_EXTENSIONS.includes(ext)) {
      flags.push(`Flag 5: Suspicious file extension detected - '${ext}' (${file})`);
    }
  }

  // Check 6: Container resource usage
  try {
    const stats = await container.stats({stream: false});
    
    // Network usage check
    const networkUsage = stats.networks && Object.values(stats.networks)
      .reduce((acc, curr) => acc + curr.rx_bytes + curr.tx_bytes, 0);
    if (networkUsage > HIGH_NETWORK_USAGE) {
      flags.push(`Flag 6: High network usage detected - ${(networkUsage / (1024 * 1024)).toFixed(2)} MB`);
    }

    // CPU usage check
    const cpuUsage = stats.cpu_stats.cpu_usage.total_usage / stats.cpu_stats.system_cpu_usage;
    const volumeSize = fs.statSync(volumePath).size;
    if (cpuUsage > HIGH_CPU_THRESHOLD && volumeSize < SMALL_VOLUME_SIZE) {
      flags.push(`Flag 7: High CPU usage (${(cpuUsage * 100).toFixed(2)}%) with small volume size (${(volumeSize / (1024 * 1024)).toFixed(2)} MB)`);
    }

    // Memory usage check
    const memoryUsage = stats.memory_stats.usage / stats.memory_stats.limit;
    if (memoryUsage > 0.9) {
      flags.push(`Flag 8: High memory usage detected - ${(memoryUsage * 100).toFixed(2)}%`);
    }
  } catch (error) {
    console.error(`Error retrieving stats for container ${volumeId}:`, error);
  }

  return flags;
}

async function main() {
  const volumeIds = fs.readdirSync(VOLUMES_DIR).filter(id => id.length === 36); // Assuming UUIDs
  for (const volumeId of volumeIds) {
    const flags = await checkVolume(volumeId);
    if (flags.length > 0) {
      const message = {
        content: `Abuse flags detected for container ${volumeId}:\n\n` + flags.join('\n')
      };
      try {
        await axios.post(WEBHOOK_URL, message);
        console.log(`Sent alert for container ${volumeId}`);
      } catch (error) {
        console.error(`Error sending alert for container ${volumeId}:`, error);
      }
    }
  }
}

// Run the script
main().catch(error => console.error('Error in anti-abuse script:', error));
