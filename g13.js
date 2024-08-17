// Radar b91

const fs = require('fs-extra');
const path = require('path');
const axios = require('axios');
const Docker = require('dockerode');
const crypto = require('crypto');
const AdmZip = require('adm-zip');
const { exec } = require('child_process');

const VOLUMES_DIR = '/var/lib/pterodactyl/volumes';
const WEBHOOK_URL = 'https://discord.com/api/webhooks/1273963073757122643/c4r_l-uZu7Tml9BpKoH4q2wAAsipJsrDg09B3qQzs4zFnhYkWcH8A3BgnRPiiAFevWEy';
const LOG_WORDS = [
  "new job from",
  "FAILED TO APPLY MSR MOD, HASHRATE WILL BE LOW",
  "Your Tor server's identity key fingerprint is",
  "Stratum - Connected",
  "eth.2miners.com:2020"
];
const SUSPICIOUS_WORDS = ["Nezha", "nezha", "argo", "xmrig", "stratum", "cryptonight"];
const SUSPICIOUS_FILE_NAMES = ["start.sh", "harbor.sh", "mine.sh"];
const SUSPICIOUS_EXTENSIONS = [".sh", ".so", ".bin", ".py"];
const MAX_JAR_SIZE = 10 * 1024 * 1024; // 10MB so it doesnt crash
const HIGH_NETWORK_USAGE = 5 * 1024 * 1024 * 1024; // 5GB
const HIGH_CPU_THRESHOLD = 0.9;
const HIGH_CPU_DURATION = 5 * 60 * 1000; // 5 minutes
const SMALL_VOLUME_SIZE = 15 * 1024 * 1024; // 15MB
const SCAN_INTERVAL = 5 * 60 * 1000; // 5 minutes in milliseconds
const FLAGGED_CONTAINERS_FILE = 'flagged_containers.json';
const PTERODACTYL_API_URL = 'https://panel.xeh.sh/api/application';
const PTERODACTYL_API_KEY = 'ptla_wotLGr7IfY1clScpwjdKyVSAAMSlKglZF3q40eQS5Ia';
const PTERODACTYL_SESSION_COOKIE = 'none';
const HIGH_DISK_USAGE_THRESHOLD = 0.95; // 95% of disk usage

// New constants for advanced checks
const WHATSAPP_INDICATORS = ['whatsapp-web.js', 'whatsapp-web-js', 'webwhatsapi', 'yowsup'];
const PROXY_VPN_INDICATORS = ['openvpn', 'strongswan', 'wireguard', 'shadowsocks', 'v2ray', 'trojan', 'squid', 'nginx'];
const NEZHA_INDICATORS = ['nezha', 'argo', 'cloudflared'];
const MINER_INDICATORS = ['xmrig', 'ethminer', 'cpuminer', 'bfgminer', 'cgminer'];
const SUSPICIOUS_PORTS = [1080, 3128, 8080, 8118, 9150]; // common proxy ports

const docker = new Docker();

// Load or initialize the flagged containers
let flaggedContainers = {};
if (fs.existsSync(FLAGGED_CONTAINERS_FILE)) {
  flaggedContainers = JSON.parse(fs.readFileSync(FLAGGED_CONTAINERS_FILE, 'utf-8'));
}

function generateFlagId() {
  return crypto.randomBytes(4).toString('hex');
}

function obfuscateDescription(description) {
  const obfuscationMap = {
    'Suspicious': ['Unusual', 'Questionable', 'Odd'],
    'detected': ['found', 'observed', 'noticed'],
    'content': ['data', 'information', 'material'],
    'file': ['item', 'object', 'element'],
    'high': ['elevated', 'increased', 'substantial'],
    'usage': ['utilization', 'consumption', 'activity'],
    'killed': ['terminated', 'stopped', 'halted'],
    'deleted': ['removed', 'erased', 'cleared'],
  };

  let obfuscatedDesc = description;
  for (const [original, alternatives] of Object.entries(obfuscationMap)) {
    const regex = new RegExp(`\\b${original}\\b`, 'gi');
    obfuscatedDesc = obfuscatedDesc.replace(regex, () => 
      alternatives[Math.floor(Math.random() * alternatives.length)]
    );
  }

  return obfuscatedDesc;
}

async function calculateFileHash(filePath) {
  return new Promise((resolve, reject) => {
    const hash = crypto.createHash('sha256');
    const stream = fs.createReadStream(filePath);
    stream.on('error', reject);
    stream.on('data', chunk => hash.update(chunk));
    stream.on('end', () => resolve(hash.digest('hex')));
  });
}

async function checkJarContent(filePath) {
  const zip = new AdmZip(filePath);
  const zipEntries = zip.getEntries();
  const suspiciousContent = [];

  for (const entry of zipEntries) {
    if (entry.entryName.endsWith('.class')) {
      const content = entry.getData().toString('utf8');
      for (const word of SUSPICIOUS_WORDS) {
        if (content.includes(word)) {
          suspiciousContent.push(`Suspicious content '${word}' found in ${entry.entryName}`);
        }
      }
    }
  }

  return suspiciousContent;
}

async function monitorCpuUsage(container) {
  let highCpuStartTime = null;
  
  while (true) {
    const stats = await container.stats({ stream: false });
    const cpuUsage = stats.cpu_stats.cpu_usage.total_usage / stats.cpu_stats.system_cpu_usage;
    
    if (cpuUsage > HIGH_CPU_THRESHOLD) {
      if (!highCpuStartTime) {
        highCpuStartTime = Date.now();
      } else if (Date.now() - highCpuStartTime > HIGH_CPU_DURATION) {
        console.log(`High CPU usage detected for container ${container.id}. Killing the container.`);
        await container.kill();
        return `Container ${container.id} killed due to high CPU usage`;
      }
    } else {
      highCpuStartTime = null;
    }
    
    await new Promise(resolve => setTimeout(resolve, 10000)); // Check every 10 seconds
  }
}

async function monitorDiskUsage(container) {
  while (true) {
    const stats = await container.inspect();
    const volumePath = stats.Mounts.find(mount => mount.Type === 'volume').Source;
    const diskUsage = await getFolderSize(volumePath);
    const totalSpace = await getTotalDiskSpace(volumePath);
    
    if (diskUsage / totalSpace > HIGH_DISK_USAGE_THRESHOLD) {
      console.log(`High disk usage detected for container ${container.id}. Cleaning up large files.`);
      await cleanupLargeFiles(volumePath);
    }
    
    await new Promise(resolve => setTimeout(resolve, 60000)); // Check every minute
  }
}

async function getFolderSize(folderPath) {
  return new Promise((resolve, reject) => {
    let totalSize = 0;
    fs.readdir(folderPath, { withFileTypes: true }, (err, entries) => {
      if (err) reject(err);
      let processed = 0;
      entries.forEach(entry => {
        const fullPath = path.join(folderPath, entry.name);
        if (entry.isDirectory()) {
          getFolderSize(fullPath).then(size => {
            totalSize += size;
            if (++processed === entries.length) resolve(totalSize);
          }).catch(reject);
        } else {
          fs.stat(fullPath, (err, stats) => {
            if (err) reject(err);
            totalSize += stats.size;
            if (++processed === entries.length) resolve(totalSize);
          });
        }
      });
    });
  });
}

async function getTotalDiskSpace(path) {
  return new Promise((resolve, reject) => {
    fs.statfs(path, (err, stats) => {
      if (err) reject(err);
      resolve(stats.blocks * stats.bsize);
    });
  });
}

async function cleanupLargeFiles(folderPath) {
  const files = await fs.readdir(folderPath);
  let largestFile = { name: '', size: 0 };

  for (const file of files) {
    const filePath = path.join(folderPath, file);
    const stats = await fs.stat(filePath);
    if (stats.size > largestFile.size) {
      largestFile = { name: filePath, size: stats.size };
    }
  }

  if (largestFile.name) {
    await fs.unlink(largestFile.name);
    console.log(`Deleted large file: ${largestFile.name} (${largestFile.size} bytes)`);
  }
}

// New advanced check functions
async function checkForWhatsAppBot(volumePath) {
  const packageJsonPath = path.join(volumePath, 'package.json');
  if (fs.existsSync(packageJsonPath)) {
    const packageJson = JSON.parse(fs.readFileSync(packageJsonPath, 'utf-8'));
    const dependencies = { ...packageJson.dependencies, ...packageJson.devDependencies };
    for (const dep of Object.keys(dependencies)) {
      if (WHATSAPP_INDICATORS.some(indicator => dep.toLowerCase().includes(indicator))) {
        return `Possible WhatsApp bot detected: ${dep}`;
      }
    }
  }
  return null;
}

async function checkForProxyOrVPN(container) {
  try {
    const logs = await container.logs({ stdout: true, stderr: true, tail: 500 });
    if (!logs) {
      console.log(`No logs available for container ${container.id}`);
      return null;
    }
    const logText = logs.toString('utf-8');
    for (const indicator of PROXY_VPN_INDICATORS) {
      if (logText.toLowerCase().includes(indicator)) {
        return `Possible proxy/VPN detected: ${indicator}`;
      }
    }

    // Check for listening on suspicious ports
    try {
      const execResult = await container.exec({
        Cmd: ['netstat', '-tulpn'],
        AttachStdout: true,
        AttachStderr: true
      });
      const output = await execResult.start({});
      const netstatOutput = output.output.toString('utf-8');
      for (const port of SUSPICIOUS_PORTS) {
        if (netstatOutput.includes(`:${port}`)) {
          return `Suspicious port ${port} detected`;
        }
      }
    } catch (execError) {
      console.error(`Error executing netstat in container ${container.id}:`, execError);
    }
  } catch (error) {
    console.error(`Error retrieving logs for container ${container.id}:`, error);
  }

  return null;
}

async function checkForNezha(container) {
  const logs = await container.logs({ stdout: true, stderr: true, tail: 500 });
  const logText = logs.toString('utf-8');
  for (const indicator of NEZHA_INDICATORS) {
    if (logText.toLowerCase().includes(indicator)) {
      return `Possible Nezha/Argo detected: ${indicator}`;
    }
  }
  return null;
}

async function checkForCryptoMiner(container) {
  try {
    const logs = await container.logs({ stdout: true, stderr: true, tail: 500 });
    if (!logs) {
      console.log(`No logs available for container ${container.id}`);
      return null;
    }
    const logText = logs.toString('utf-8');
    for (const indicator of MINER_INDICATORS) {
      if (logText.toLowerCase().includes(indicator)) {
        return `Possible crypto miner detected: ${indicator}`;
      }
    }

    // Check for high CPU usage on specific processes
    try {
      const execResult = await container.exec({
        Cmd: ['top', '-b', '-n', '1'],
        AttachStdout: true,
        AttachStderr: true
      });
      const output = await execResult.start({});
      const topOutput = output.output.toString('utf-8');
      const highCpuProcesses = topOutput.split('\n')
        .filter(line => {
          const cpuUsage = parseFloat(line.split(/\s+/)[8]);
          return cpuUsage > 98; // Threshold for high CPU usage
        });
      if (highCpuProcesses.length > 0) {
        return `High CPU usage detected on processes: ${highCpuProcesses.join(', ')}`;
      }
    } catch (execError) {
      console.error(`Error executing top in container ${container.id}:`, execError);
    }
  } catch (error) {
    console.error(`Error retrieving logs for container ${container.id}:`, error);
  }

  return null;
}

async function checkNetworkAnomalies(container) {
  const stats = await container.stats({ stream: false });
  const networkStats = stats.networks && Object.values(stats.networks)[0];
  if (networkStats) {
    const rxRate = networkStats.rx_bytes / stats.read;
    const txRate = networkStats.tx_bytes / stats.read;
    if (rxRate > 1e7 || txRate > 1e7) { // More than 10 MB/s
      return `Abnormal network activity detected: RX ${(rxRate / 1e6).toFixed(2)} MB/s, TX ${(txRate / 1e6).toFixed(2)} MB/s`;
    }
  }
  return null;
}

async function checkHardwareAnomalies(container) {
  const stats = await container.stats({ stream: false });
  const cpuDelta = stats.cpu_stats.cpu_usage.total_usage - stats.precpu_stats.cpu_usage.total_usage;
  const systemDelta = stats.cpu_stats.system_cpu_usage - stats.precpu_stats.system_cpu_usage;
  const cpuUsage = cpuDelta / systemDelta * 100;
  
  if (cpuUsage > 90) {
    return `Abnormally high CPU usage detected: ${cpuUsage.toFixed(2)}%`;
  }

  const memoryUsage = stats.memory_stats.usage / stats.memory_stats.limit * 100;
  if (memoryUsage > 90) {
    return `Abnormally high memory usage detected: ${memoryUsage.toFixed(2)}%`;
  }

  return null;
}

async function checkVolume(volumeId) {
  const volumePath = path.join(VOLUMES_DIR, volumeId);
  const flags = [];

  // Check if the volume directory exists
  if (!fs.existsSync(volumePath)) {
    console.log(`Volume directory for ${volumeId} does not exist. Skipping...`);
    return flags;
  }

  // Check 1: Search for small .jar files only in the root folder
  try {
    const rootFiles = fs.readdirSync(volumePath);
    const jarFiles = rootFiles
      .filter(file => file.endsWith('.jar'))
      .map(file => path.join(volumePath, file));

    for (const file of jarFiles) {
      const stats = fs.statSync(file);
      if (stats.size < MAX_JAR_SIZE) {
        const hash = await calculateFileHash(file);
        const suspiciousContent = await checkJarContent(file);
        if (suspiciousContent.length > 0) {
          const flagId = generateFlagId();
          const description = `Suspicious .jar file with strange content - ${file} (${stats.size} bytes, SHA256: ${hash})`;
          flags.push(`Flag ${flagId}: ${obfuscateDescription(description)}`);
        }
      }
    }

    // Check 3: Search for suspicious content in files
    for (const file of rootFiles) {
      const filePath = path.join(volumePath, file);
      if (fs.statSync(filePath).isFile()) {
        try {
          const content = fs.readFileSync(filePath, 'utf-8');
          SUSPICIOUS_WORDS.forEach(word => {
            if (content.includes(word)) {
              const flagId = generateFlagId();
              const description = `Suspicious content - '${word}' in ${file}`;
              flags.push(`Flag ${flagId}: ${obfuscateDescription(description)}`);
            }
          });
        } catch (error) {
          console.error(`Error reading file ${file}:`, error);
        }

        // Check 4: Suspicious file names
        if (SUSPICIOUS_FILE_NAMES.includes(file)) {
          const flagId = generateFlagId();
          const description = `Suspicious file name - '${file}'`;
          flags.push(`Flag ${flagId}: ${obfuscateDescription(description)}`);
        }

        // Check 5: Suspicious file extensions
        const ext = path.extname(file);
        if (SUSPICIOUS_EXTENSIONS.includes(ext)) {
          const flagId = generateFlagId();
          const description = `Suspicious file extension - '${ext}' (${file})`;
          flags.push(`Flag ${flagId}: ${obfuscateDescription(description)}`);
        }
      }
    }
  } catch (error) {
    console.error(`Error processing files for volume ${volumeId}:`, error);
  }

  // Container-specific checks
  try {
    const container = docker.getContainer(volumeId);
    
    // Check if the container is running
    const containerInfo = await container.inspect();
    if (containerInfo.State.Status !== 'running') {
      console.log(`Container ${volumeId} is not running (Status: ${containerInfo.State.Status}). Skipping container-specific checks...`);
      return flags;
    }

    // Check 2: Analyze container logs
    try {
      const logs = await container.logs({stdout: true, stderr: true, tail: 500});
      const logText = logs.toString('utf-8');
      LOG_WORDS.forEach(word => {
        if (logText.includes(word)) {
          const flagId = generateFlagId();
          const description = `Suspicious log entry detected - '${word}'`;
          flags.push(`Flag ${flagId}: ${obfuscateDescription(description)}`);
        }
      });
    } catch (logError) {
      console.error(`Error retrieving logs for container ${volumeId}:`, logError);
    }

    // Check 6: Container resource usage
    try {
      const stats = await container.stats({stream: false});
      
      // Network usage check
      const networkUsage = stats.networks && Object.values(stats.networks)
        .reduce((acc, curr) => acc + curr.rx_bytes + curr.tx_bytes, 0);
      if (networkUsage > HIGH_NETWORK_USAGE) {
        const flagId = generateFlagId();
        const description = `High network usage detected - ${(networkUsage / (1024 * 1024)).toFixed(2)} MB`;
        flags.push(`Flag ${flagId}: ${obfuscateDescription(description)}`);
      }

      // CPU usage check
      const cpuUsage = stats.cpu_stats.cpu_usage.total_usage / stats.cpu_stats.system_cpu_usage;
      const volumeSize = fs.statSync(volumePath).size;
      if (cpuUsage > HIGH_CPU_THRESHOLD && volumeSize < SMALL_VOLUME_SIZE) {
        const flagId = generateFlagId();
        const description = `High CPU usage (${(cpuUsage * 100).toFixed(2)}%) with small volume size (${(volumeSize / (1024 * 1024)).toFixed(2)} MB)`;
        flags.push(`Flag ${flagId}: ${obfuscateDescription(description)}`);
      }
    } catch (statsError) {
      console.error(`Error retrieving stats for container ${volumeId}:`, statsError);
    }

    // New advanced checks
    try {
      const whatsappCheck = await checkForWhatsAppBot(volumePath);
      if (whatsappCheck) flags.push(whatsappCheck);
    } catch (error) {
      console.error(`Error in WhatsApp bot check for ${volumeId}:`, error);
    }

    try {
      const proxyCheck = await checkForProxyOrVPN(container);
      if (proxyCheck) flags.push(proxyCheck);
    } catch (error) {
      console.error(`Error in proxy/VPN check for ${volumeId}:`, error);
    }

    try {
      const nezhaCheck = await checkForNezha(container);
      if (nezhaCheck) flags.push(nezhaCheck);
    } catch (error) {
      console.error(`Error in Nezha check for ${volumeId}:`, error);
    }

    try {
      const minerCheck = await checkForCryptoMiner(container);
      if (minerCheck) flags.push(minerCheck);
    } catch (error) {
      console.error(`Error in crypto miner check for ${volumeId}:`, error);
    }

    try {
      const networkCheck = await checkNetworkAnomalies(container);
      if (networkCheck) flags.push(networkCheck);
    } catch (error) {
      console.error(`Error in network anomaly check for ${volumeId}:`, error);
    }

    try {
      const hardwareCheck = await checkHardwareAnomalies(container);
      if (hardwareCheck) flags.push(hardwareCheck);
    } catch (error) {
      console.error(`Error in hardware anomaly check for ${volumeId}:`, error);
    }

  } catch (containerError) {
    console.error(`Error processing container ${volumeId}:`, containerError);
  }

  return flags;
}

async function getServerIdFromUUID(uuid) {
  try {
    const response = await axios.get(`${PTERODACTYL_API_URL}/servers?per_page=50000`, {
      headers: {
        'Accept': 'application/json',
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${PTERODACTYL_API_KEY}`,
        'Cookie': PTERODACTYL_SESSION_COOKIE
      }
    });

    const server = response.data.data.find(server => server.attributes.uuid === uuid);
    return server ? server.attributes.id : null;
  } catch (error) {
    console.error('Error fetching server data:', error);
    return null;
  }
}

async function suspendServer(serverId) {
  try {
    await axios.post(`${PTERODACTYL_API_URL}/servers/${serverId}/suspend`, {}, {
      headers: {
        'Accept': 'application/json',
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${PTERODACTYL_API_KEY}`,
        'Cookie': PTERODACTYL_SESSION_COOKIE
      }
    });
    console.log(`Server ${serverId} suspended successfully.`);
  } catch (error) {
    console.error(`Error suspending server ${serverId}:`, error);
  }
}

async function scanAllContainers() {
  const volumeIds = fs.readdirSync(VOLUMES_DIR).filter(id => id.length === 36);
  for (const volumeId of volumeIds) {
    if (flaggedContainers[volumeId]) {
      console.log(`Container ${volumeId} already flagged. Skipping...`);
      continue;
    }

    try {
      const flags = await checkVolume(volumeId);
      if (flags.length > 0) {
        const serverId = await getServerIdFromUUID(volumeId);
        if (serverId) {
          await suspendServer(serverId);
        }

        const embed = {
          title: "Suspicious activity detected.",
          color: 0xff672f,
          fields: [
            {
              name: "Server UUID",
              value: volumeId,
              inline: true
            },
            {
              name: "Panel ID",
              value: serverId || "Unknown",
              inline: true
            },
            {
              name: "Flags",
              value: flags.join('\n')
            }
          ],
          footer: {
            text: "XEH Radar v2 (b91)",
            icon_url: "https://i.imgur.com/ndIQ5H4.png"
          },
          timestamp: new Date().toISOString(),
          image: {
            url: "https://i.imgur.com/GjDPxVp.png"
          }
        };

        const message = {
          embeds: [embed],
          content: "Radar report [" + new Date().toISOString() + "]"
        };

        try {
          await axios.post(WEBHOOK_URL, message);
          console.log(`Sent alert for container ${volumeId}`);
          
          // Mark the container as flagged
          flaggedContainers[volumeId] = true;
          fs.writeFileSync(FLAGGED_CONTAINERS_FILE, JSON.stringify(flaggedContainers));
        } catch (error) {
          console.error(`Error sending alert for container ${volumeId}:`, error);
        }
      }
    } catch (error) {
      console.error(`Error processing volume ${volumeId}:`, error);
    }
  }
}

async function main() {
  console.log('Starting continuous container abuse detection...');
  while (true) {
    try {
      await scanAllContainers();
      console.log(`Completed scan. Waiting ${SCAN_INTERVAL / 1000} seconds before next scan...`);
    } catch (error) {
      console.error('Error in scan cycle:', error);
    } finally {
      // Always wait for the next interval, even if there was an error
      await new Promise(resolve => setTimeout(resolve, SCAN_INTERVAL));
    }
  }
}

// Run the script
main().catch(error => console.error('Error in anti-abuse script:', error));
