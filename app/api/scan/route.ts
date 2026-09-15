import { NextResponse } from 'next/server';
import { exec } from 'child_process';
import { promisify } from 'util';
import net from 'net';

const execAsync = promisify(exec);

function scanPort(port: number, host: string): Promise<string> {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    socket.setTimeout(2000);
    socket.on('connect', () => { socket.destroy(); resolve(`[+] Port ${port}/tcp : OPEN`); });
    socket.on('timeout', () => { socket.destroy(); resolve(`[-] Port ${port}/tcp : FILTERED`); });
    socket.on('error', () => { socket.destroy(); resolve(`[-] Port ${port}/tcp : CLOSED`); });
    socket.connect(port, host);
  });
}

export async function POST(request: Request) {
  try {
    const { target } = await request.json();
    if (!target) return NextResponse.json({ success: false, error: 'Target is required' }, { status: 400 });

    const isValidDomain = /^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(target);
    if (!isValidDomain) return NextResponse.json({ success: false, error: 'Invalid domain format.' }, { status: 400 });

    let finalOutput = `======================================\n`;
    finalOutput += ` TARGET ACQUIRED: ${target}\n`;
    finalOutput += ` SCAN INITIATED : ${new Date().toISOString()}\n`;
    finalOutput += `======================================\n`;

    // 1. PING TEST
    finalOutput += `\n[*] PHASE 1: PING TEST\n`;
    try {
      const { stdout } = await execAsync(`ping -n 4 ${target}`);
      finalOutput += stdout;
    } catch (err) {
      finalOutput += `Ping failed or timed out.\n`;
    }

    // 2. SUBDOMAINS
    finalOutput += `\n[*] PHASE 2: SUBDOMAIN ENUMERATION\n`;
    try {
      const htResponse = await fetch(`https://api.hackertarget.com/hostsearch/?q=${target}`);
      const htData = await htResponse.text();
      if (htData.includes('error')) {
        finalOutput += `No subdomains found.\n`;
      } else {
        finalOutput += htData.split('\n').slice(0, 10).join('\n') + '\n';
      }
    } catch (err) {
      finalOutput += `Failed to fetch subdomains.\n`;
    }

    // 3. PORT SCANNING
    finalOutput += `\n[*] PHASE 3: PORT SCANNING (TCP)\n`;
    const portsToScan = [21, 22, 80, 443, 3306, 8080];
    const scanResults = await Promise.all(portsToScan.map(port => scanPort(port, target)));
    finalOutput += scanResults.join('\n') + '\n';

    // 4. DIRECTORY FUZZING (Mini-FFUF)
    finalOutput += `\n[*] PHASE 4: DIRECTORY FUZZING (Mini-FFUF)\n`;
    const pathsToFuzz = ['/admin', '/login', '/api', '/.git', '/robots.txt', '/backup', '/dashboard', '/test'];
    
    const fuzzPromises = pathsToFuzz.map(async (path) => {
      try {
        const res = await fetch(`https://${target}${path}`, { method: 'HEAD' });
        if (res.status === 200) return `[+] https://${target}${path} [Status: 200 OK]`;
        if (res.status === 401) return `[+] https://${target}${path} [Status: 401 Unauthorized]`;
        if (res.status === 403) return `[+] https://${target}${path} [Status: 403 Forbidden]`;
        return null; // تجاهل الصفحات غير الموجودة (404)
      } catch (e) {
        return null;
      }
    });

    const fuzzResults = (await Promise.all(fuzzPromises)).filter(Boolean);
    if (fuzzResults.length > 0) {
      finalOutput += fuzzResults.join('\n') + '\n';
    } else {
      finalOutput += `[-] No common sensitive paths found.\n`;
    }

    finalOutput += `\n======================================\n`;
    finalOutput += ` SCAN SEQUENCE COMPLETED.\n`;
    finalOutput += `======================================\n`;

    return NextResponse.json({ success: true, result: finalOutput });
  } catch (error) {
    return NextResponse.json({ success: false, error: String(error) }, { status: 500 });
  }
}