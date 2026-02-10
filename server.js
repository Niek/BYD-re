#!/usr/bin/env node
'use strict';

const http = require('http');
const fs = require('fs');
const path = require('path');
const { spawn } = require('child_process');

// Configuration
const PORT = process.env.PORT || 3000;
const REFRESH_INTERVAL_MINUTES = parseInt(process.env.REFRESH_INTERVAL_MINUTES || '15', 10);
const REFRESH_INTERVAL_MS = REFRESH_INTERVAL_MINUTES * 60 * 1000;
const STATUS_FILE = path.join(__dirname, 'status.html');

let lastStatusHtml = '<html><body><p>Initializing...</p></body></html>';
let lastUpdateTime = null;
let isRefreshing = false;

function log(message) {
  const timestamp = new Date().toISOString();
  console.log(`[${timestamp}] ${message}`);
}

function refreshData() {
  if (isRefreshing) {
    log('Refresh already in progress, skipping...');
    return;
  }

  isRefreshing = true;
  log('Starting data refresh...');

  const child = spawn('node', ['client.js'], {
    cwd: __dirname,
    stdio: ['pipe', 'pipe', 'pipe'],
  });

  let stdout = '';
  let stderr = '';

  child.stdout.on('data', (data) => {
    stdout += data.toString();
  });

  child.stderr.on('data', (data) => {
    stderr += data.toString();
  });

  child.on('close', (code) => {
    isRefreshing = false;
    const timestamp = new Date().toISOString();

    if (code !== 0) {
      log(`client.js exited with code ${code}`);
      if (stderr) {
        log(`stderr: ${stderr.slice(0, 500)}`);
      }
      return;
    }

    try {
      const htmlMatch = stdout.match(/<html[\s\S]*<\/html>/i);
      if (htmlMatch) {
        lastStatusHtml = htmlMatch[0];
        lastUpdateTime = timestamp;
        log('Data refreshed successfully');

        // Write to file for persistence
        fs.writeFile(STATUS_FILE, lastStatusHtml, (err) => {
          if (err) {
            log(`Warning: failed to write status.html: ${err.message}`);
          }
        });
      } else {
        log('Warning: no HTML found in client.js output');
      }
    } catch (err) {
      log(`Error processing client.js output: ${err.message}`);
    }
  });

  child.on('error', (err) => {
    isRefreshing = false;
    log(`Failed to spawn client.js: ${err.message}`);
  });
}

function handleRequest(req, res) {
  // CORS headers
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') {
    res.writeHead(200);
    res.end();
    return;
  }

  if (req.method !== 'GET') {
    res.writeHead(405, { 'Content-Type': 'text/plain' });
    res.end('Method Not Allowed\n');
    return;
  }

  const pathname = new URL(req.url, `http://${req.headers.host}`).pathname;

  if (pathname === '/' || pathname === '/status') {
    res.writeHead(200, {
      'Content-Type': 'text/html; charset=utf-8',
      'Cache-Control': 'no-cache, no-store, must-revalidate',
    });
    res.end(lastStatusHtml);
  } else if (pathname === '/health') {
    const health = {
      ok: true,
      uptime: process.uptime(),
      lastUpdate: lastUpdateTime,
      refreshIntervalMinutes: REFRESH_INTERVAL_MINUTES,
      isRefreshing,
    };
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(health, null, 2));
  } else if (pathname === '/api/status') {
    const health = {
      ok: true,
      uptime: process.uptime(),
      lastUpdate: lastUpdateTime,
      refreshIntervalMinutes: REFRESH_INTERVAL_MINUTES,
      isRefreshing,
    };
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(health, null, 2));
  } else {
    res.writeHead(404, { 'Content-Type': 'text/plain' });
    res.end('Not Found\n');
  }
}

const server = http.createServer(handleRequest);

server.listen(PORT, () => {
  log(`Server listening on port ${PORT}`);
  log(`Refresh interval: ${REFRESH_INTERVAL_MINUTES} minutes (${REFRESH_INTERVAL_MS}ms)`);
  log(`Status available at http://localhost:${PORT}/`);
  log(`Health check available at http://localhost:${PORT}/health`);

  // Initial data refresh
  refreshData();

  // Schedule periodic refreshes
  setInterval(() => {
    refreshData();
  }, REFRESH_INTERVAL_MS);
});

// Graceful shutdown
process.on('SIGTERM', () => {
  log('SIGTERM received, shutting down gracefully...');
  server.close(() => {
    log('Server closed');
    process.exit(0);
  });
});

process.on('SIGINT', () => {
  log('SIGINT received, shutting down gracefully...');
  server.close(() => {
    log('Server closed');
    process.exit(0);
  });
});
