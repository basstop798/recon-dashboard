'use client';

import { useState, useRef, useEffect } from 'react';

export default function Home() {
  const [target, setTarget] = useState('');
  const [result, setResult] = useState('');
  const [loading, setLoading] = useState(false);
  const terminalRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (terminalRef.current) {
      terminalRef.current.scrollTop = terminalRef.current.scrollHeight;
    }
  }, [result]);

  const handleScan = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!target) return;
    setLoading(true);
    setResult(`[SYSTEM] Initiating full recon sequence on ${target}...\nStandby...\n\n`);

    try {
      const response = await fetch('/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target }),
      });
      const data = await response.json();
      
      if (data.success) {
        setResult((prev) => prev + data.result);
      } else {
        setResult((prev) => prev + '\n[ERROR] ' + data.error);
      }
    } catch (error) {
      setResult((prev) => prev + '\n[ERROR] Network Failure.');
    } finally {
      setLoading(false);
    }
  };

  // دالة تحميل التقرير كملف نصي
  const exportReport = () => {
    if (!result) return;
    const blob = new Blob([result], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `Recon_Report_${target || 'target'}.txt`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  };

  return (
    <div className="min-h-screen bg-gray-950 text-gray-100 p-8 font-mono">
      <div className="max-w-4xl mx-auto space-y-6">
        
        <header className="border-b border-gray-800 pb-4">
          <h1 className="text-3xl font-bold text-emerald-400">Recon<span className="text-gray-100">Dash</span></h1>
          <p className="text-sm text-gray-400 mt-2">Advanced Bug Bounty & Reconnaissance Framework</p>
        </header>

        <form onSubmit={handleScan} className="flex gap-4">
          <input
            type="text"
            placeholder="target (e.g., scanme.nmap.org)"
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            className="flex-1 bg-gray-900 border border-gray-700 rounded-md px-4 py-3 focus:outline-none focus:border-emerald-500 focus:ring-1 focus:ring-emerald-500 transition-colors"
          />
          <button
            type="submit"
            disabled={loading}
            className={`px-8 py-3 rounded-md font-semibold transition-colors ${
              loading 
                ? 'bg-gray-700 text-gray-400 cursor-not-allowed' 
                : 'bg-emerald-600 hover:bg-emerald-500 text-white shadow-[0_0_15px_rgba(5,150,105,0.4)]'
            }`}
          >
            {loading ? 'Scanning...' : 'Launch Scan'}
          </button>
          
          {/* زر تحميل التقرير الجديد */}
          <button
            type="button"
            onClick={exportReport}
            disabled={!result || loading}
            className={`px-6 py-3 rounded-md font-semibold transition-colors border ${
              !result || loading
                ? 'border-gray-700 text-gray-600 cursor-not-allowed'
                : 'border-emerald-500 text-emerald-400 hover:bg-emerald-950'
            }`}
          >
            Save TXT
          </button>
        </form>

        <div className="bg-gray-900 border border-gray-800 rounded-md h-[550px] flex flex-col shadow-2xl">
          <div className="bg-gray-800 px-4 py-2 border-b border-gray-700 rounded-t-md flex items-center justify-between">
            <div className="flex items-center gap-2">
              <div className="w-3 h-3 rounded-full bg-red-500"></div>
              <div className="w-3 h-3 rounded-full bg-yellow-500"></div>
              <div className="w-3 h-3 rounded-full bg-green-500"></div>
              <span className="ml-2 text-xs text-gray-400">Terminal Output - {target || 'Idle'}</span>
            </div>
          </div>
          <div ref={terminalRef} className="p-4 flex-1 overflow-auto scroll-smooth">
            <pre className="text-sm text-emerald-400 whitespace-pre-wrap font-mono">
              {result || 'System ready. Enter a target to begin reconnaissance.'}
            </pre>
          </div>
        </div>

      </div>
    </div>
  );
}