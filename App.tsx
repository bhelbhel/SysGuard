
/*import React, { useState, useMemo, useRef, useEffect } from 'react';
import Layout from './components/Layout';
import { 
  RiskLevel, 
  AnalysisResult, 
  ViewState,
  SecurityAlert,
  LiveEvent,
  SyscallData
} from './types';
import { generateTimelineData } from './constants';
import { getAnalysisExplanation } from './services/geminiService';
import { parseSyscallFile, analyzeDeviations, getSampleCSV, ParsedData } from './services/dataProcessor';
import RiskMeter from './components/RiskMeter';
import SyscallChart from './components/SyscallChart';
import TrendChart from './components/TrendChart';
import { 
  AlertTriangle, 
  CheckCircle2, 
  Zap, 
  ShieldAlert,
  Info,
  RefreshCw,
  FileText,
  UploadCloud,
  Activity,
  History,
  Settings,
  Loader2,
  Trash2,
  Lock,
  User,
  ShieldCheck,
  Eye,
  EyeOff,
  Fingerprint,
  Target,
  Gauge,
  Bell,
  AlertOctagon,
  Radio,
  Cpu,
  Globe,
  Link as LinkIcon,
  X,
  Save,
  Check,
  Camera,
  BarChart3,
  Dna,
  Upload,
  Skull,
  ShieldX,
  Terminal,
  Timer,
  ArrowRight,
  Shield
} from 'lucide-react';

const HAZARDOUS_SYSCALLS = ['execve', 'ptrace', 'mprotect', 'socket', 'connect', 'bind', 'kill', 'clone', 'ptrace', 'prctl'];

const App: React.FC = () => {
  const [isAuthenticated, setIsAuthenticated] = useState<boolean>(() => {
    return sessionStorage.getItem('sysguard_auth') === 'true';
  });
  const [loginLoading, setLoginLoading] = useState(false);
  const [credentials, setCredentials] = useState({ id: 'ADMIN-01', key: '••••••••' });

  const [activeView, setActiveView] = useState<ViewState>('LIVE');
  const [threshold, setThreshold] = useState(25);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [isParsing, setIsParsing] = useState<{type: string, active: boolean}>({type: '', active: false});
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [history, setHistory] = useState<AnalysisResult[]>([]);
  const [alerts, setAlerts] = useState<SecurityAlert[]>([]);
  const [activeAlert, setActiveAlert] = useState<SecurityAlert | null>(null);
  
  const [muteLivePopups, setMuteLivePopups] = useState(true);
  const [alertCooldown, setAlertCooldown] = useState(() => Number(localStorage.getItem('sysguard_cooldown')) || 45);
  const [isDynamicCooldown, setIsDynamicCooldown] = useState(() => localStorage.getItem('sysguard_dynamic_cooldown') === 'true');
  const lastLiveAlertTimeRef = useRef<number>(0);
  const alertBurstCountRef = useRef<number>(0);
  const lastBurstCheckRef = useRef<number>(Date.now());

  const [liveEvents, setLiveEvents] = useState<LiveEvent[]>([]);
  const [wsStatus, setWsStatus] = useState<'CONNECTED' | 'DISCONNECTED' | 'CONNECTING'>('DISCONNECTED');
  const [wsUrl, setWsUrl] = useState(() => localStorage.getItem('sysguard_ws_url') || 'ws://localhost:8000/ws');
  
  const reconnectCountRef = useRef(0);
  const reconnectTimeoutRef = useRef<number | null>(null);

  const [liveAggregatedCounts, setLiveAggregatedCounts] = useState<ParsedData>({});
  const [livePidsObserved, setLivePidsObserved] = useState<Set<number>>(new Set());

  const [baselineParsed, setBaselineParsed] = useState<ParsedData | null>(null);
  const [testParsed, setTestParsed] = useState<ParsedData | null>(null);
  const [baselineFileName, setBaselineFileName] = useState<string | null>(null);
  const [testFileName, setTestFileName] = useState<string | null>(null);

  const baselineInputRef = useRef<HTMLInputElement>(null);
  const testInputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (!isAuthenticated) return;
    
    let socket: WebSocket | null = null;

    const connect = () => {
      if (reconnectTimeoutRef.current) window.clearTimeout(reconnectTimeoutRef.current);
      setWsStatus('CONNECTING');
      
      try {
        socket = new WebSocket(wsUrl);
        
        socket.onopen = () => {
          setWsStatus('CONNECTED');
          reconnectCountRef.current = 0;
        };

        socket.onmessage = (event) => {
          try {
            const data: LiveEvent = JSON.parse(event.data);
            setLiveEvents(prev => [data, ...prev].slice(0, 100));
            setLiveAggregatedCounts(prev => ({ ...prev, [data.syscall]: (prev[data.syscall] || 0) + 1 }));
            setLivePidsObserved(prev => { const next = new Set(prev); next.add(data.pid); return next; });
            
            const isHazardous = HAZARDOUS_SYSCALLS.includes(data.syscall.toLowerCase());
            if (data.alert || isHazardous) {
              const now = Date.now();
              const newAlert: SecurityAlert = {
                id: Math.random().toString(36).substr(2, 6),
                severity: isHazardous ? RiskLevel.HIGH : RiskLevel.MEDIUM,
                title: isHazardous ? 'Hazardous Event Injected' : 'Anomalous Activity',
                message: `Suspicious activity from PID ${data.pid}: ${data.syscall}() call detected.`,
                timestamp: new Date().toLocaleTimeString(),
                analysisId: 'LIVE_STREAM',
                read: false
              };
              setAlerts(prev => [newAlert, ...prev]);
              if (now - lastBurstCheckRef.current > 10000) { alertBurstCountRef.current = 0; lastBurstCheckRef.current = now; }
              alertBurstCountRef.current += 1;
              let effectiveCooldownMs = alertCooldown * 1000;
              if (isDynamicCooldown) effectiveCooldownMs *= Math.min(5, Math.max(1, alertBurstCountRef.current / 3));
              if (!muteLivePopups && (now - lastLiveAlertTimeRef.current > effectiveCooldownMs)) {
                setActiveAlert(newAlert);
                lastLiveAlertTimeRef.current = now;
              }
            }
          } catch (e) {}
        };

        socket.onclose = () => {
          setWsStatus('DISCONNECTED');
          // Exponential backoff: 1s, 2s, 4s, 8s, 16s... max 30s
          const delay = Math.min(30000, Math.pow(2, reconnectCountRef.current) * 1000);
          reconnectCountRef.current++;
          reconnectTimeoutRef.current = window.setTimeout(connect, delay);
        };

        socket.onerror = () => {
          setWsStatus('DISCONNECTED');
        };
      } catch (e) {
        setWsStatus('DISCONNECTED');
      }
    };

    connect();

    return () => {
      if (socket) socket.close();
      if (reconnectTimeoutRef.current) window.clearTimeout(reconnectTimeoutRef.current);
    };
  }, [isAuthenticated, wsUrl, muteLivePopups, alertCooldown, isDynamicCooldown]);

  const liveAnalysisData = useMemo((): SyscallData[] => {
    return Object.entries(liveAggregatedCounts)
      .map(([name, count]) => ({ name, baseline: 0, test: count as number, deviation: 0 }))
      .sort((a, b) => (b.test as number) - (a.test as number));
  }, [liveAggregatedCounts]);

  const handleFileUpload = async (event: React.ChangeEvent<HTMLInputElement>, type: 'baseline' | 'test') => {
    const file = event.target.files?.[0];
    if (!file) return;
    setIsParsing({ type, active: true });
    try {
      const content = await file.text();
      const parsed = parseSyscallFile(content);
      if (type === 'baseline') { setBaselineParsed(parsed); setBaselineFileName(file.name); }
      else { setTestParsed(parsed); setTestFileName(file.name); }
    } catch (error) {} finally { setIsParsing({ type: '', active: false }); }
  };

  const handleLogout = () => { sessionStorage.removeItem('sysguard_auth'); setIsAuthenticated(false); };
  const handleLogin = (e: React.FormEvent) => { e.preventDefault(); setLoginLoading(true); setTimeout(() => { sessionStorage.setItem('sysguard_auth', 'true'); setIsAuthenticated(true); setLoginLoading(false); }, 1000); };

  const handleRunAnalysis = async (customTest?: ParsedData) => {
    const baseline = baselineParsed || liveAggregatedCounts; 
    const test = customTest || testParsed;
    if (!baseline || !test) return;
    setIsAnalyzing(true);
    await new Promise(resolve => setTimeout(resolve, 1800));
    
    const { syscalls, avgDeviation } = analyzeDeviations(baseline, test);
    const peakDeviation = Math.max(...syscalls.map(s => s.deviation));
    const isIntrusion = avgDeviation > threshold || peakDeviation > threshold * 4;

    const status = isIntrusion ? 'INTRUSION' : 'NORMAL';
    let riskLevel = RiskLevel.LOW;
    if (isIntrusion) {
      if (peakDeviation > 400) riskLevel = RiskLevel.CRITICAL;
      else if (peakDeviation > 150) riskLevel = RiskLevel.HIGH;
      else riskLevel = RiskLevel.MEDIUM;
    }

    const timestamp = new Date().toLocaleString();
    const explanation = await getAnalysisExplanation(status, riskLevel, avgDeviation, syscalls);

    const newResult: AnalysisResult = {
      id: Math.random().toString(36).substr(2, 9),
      status, deviationScore: avgDeviation, riskLevel, syscalls,
      timeline: generateTimelineData(isIntrusion), timestamp, explanation,
      metadata: { baselineFile: baselineFileName || 'internal_baseline', testFile: testFileName || 'sensor_snapshot' }
    };

    setResult(newResult);
    if (status === 'INTRUSION') {
      const newAlert: SecurityAlert = {
        id: Math.random().toString(36).substr(2, 6),
        severity: riskLevel,
        title: 'Neural Engine Alert',
        message: explanation || "Anomalous system call sequences detected.",
        timestamp: new Date().toLocaleTimeString(),
        read: false,
        analysisId: newResult.id
      };
      setAlerts(prev => [newAlert, ...prev]);
      setActiveAlert(newAlert);
    }
    setIsAnalyzing(false);
    setActiveView('DASHBOARD');
  };

  const captureLiveSnapshot = () => {
    if (Object.keys(liveAggregatedCounts).length === 0) return;
    handleRunAnalysis(liveAggregatedCounts);
  };

  const saveCurrentToHistory = () => { if (result && !history.some(h => h.id === result.id)) setHistory(prev => [result, ...prev].slice(0, 50)); };
  const isCurrentResultSaved = useMemo(() => result ? history.some(h => h.id === result.id) : false, [result, history]);
  const markAlertRead = (id: string) => setAlerts(prev => prev.map(a => a.id === id ? { ...a, read: true } : a));
  const viewAlertAnalysis = (alert: SecurityAlert) => {
    const historicalResult = history.find(h => h.id === alert.analysisId);
    if (historicalResult) { setResult(historicalResult); markAlertRead(alert.id); setActiveView('DASHBOARD'); }
  };
  const resetAnalysis = () => { setResult(null); setBaselineParsed(null); setTestParsed(null); setBaselineFileName(null); setTestFileName(null); setActiveView('UPLOAD'); };

  /**
   * Professional Terminal-Style Live Monitor
   */
  /*const renderLiveView = () => (
    <div className="space-y-4 animate-in fade-in slide-in-from-bottom-4 duration-500">
      <div className="flex justify-between items-end">
        <div>
          <h2 className="text-xl font-black text-white uppercase tracking-tight flex items-center gap-2">
            <Radio className="w-5 h-5 text-sky-500 animate-pulse" />
            Live Monitor
          </h2>
          <p className="text-slate-500 text-[10px] uppercase font-bold tracking-widest mt-0.5">Kernel hook ingestion stream</p>
        </div>
        <button onClick={captureLiveSnapshot} disabled={liveEvents.length === 0} className="px-5 py-2.5 bg-sky-600 hover:bg-sky-500 disabled:bg-slate-800 text-white rounded-lg text-[10px] font-black uppercase tracking-widest shadow-lg flex items-center gap-2 transition-all active:scale-95">
          <Camera className="w-4 h-4" /> Snapshot
        </button>
      </div>

      <div className="grid lg:grid-cols-4 gap-4">
        <div className="lg:col-span-3 space-y-3">
          <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-2xl flex flex-col h-[520px]">
            <div className="bg-slate-950 p-3 border-b border-slate-800 flex justify-between items-center">
              <div className="flex items-center gap-2.5 font-mono text-[10px] font-bold">
                 <Terminal className="w-3.5 h-3.5 text-slate-500" />
                 <span className="text-slate-400 opacity-60">root@sysguard:~# tail -f kernel_audit</span>
              </div>
              <div className="flex items-center gap-3">
                 <button onClick={() => setMuteLivePopups(!muteLivePopups)} className={`p-1.5 rounded-lg transition-all ${muteLivePopups ? 'bg-slate-800 text-slate-500' : 'bg-sky-500/10 text-sky-400'}`}>
                    {muteLivePopups ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                 </button>
                 <button onClick={() => setLiveEvents([])} className="p-1.5 bg-slate-800 hover:bg-slate-700 text-slate-400 rounded-lg transition-all">
                    <Trash2 className="w-4 h-4" />
                 </button>
              </div>
            </div>
            <div className="flex-1 overflow-y-auto font-mono text-[13px] p-4 space-y-1.5 scrollbar-thin scrollbar-thumb-slate-800">
               {liveEvents.length === 0 ? (
                 <div className="h-full flex flex-col items-center justify-center opacity-10 gap-3">
                    <Cpu className="w-10 h-10" />
                    <p className="uppercase tracking-[0.4em] font-black text-[11px]">Ingesting...</p>
                 </div>
               ) : liveEvents.map((ev, i) => (
                 <div key={i} className={`flex items-center gap-5 py-1 px-3 rounded transition-colors group ${ev.alert ? 'bg-red-500/10 border-l-2 border-red-500' : 'hover:bg-slate-800/30'}`}>
                    <span className="text-slate-600 shrink-0 w-20">[{new Date(ev.timestamp).toLocaleTimeString([], { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' })}]</span>
                    <span className="text-sky-500 font-bold w-16 shrink-0">PID:{ev.pid}</span>
                    <span className={`px-2 py-0.5 rounded text-[10px] font-black uppercase shrink-0 ${ev.alert ? 'bg-red-500 text-white' : 'bg-slate-800 text-slate-500'}`}>
                      {ev.syscall}
                    </span>
                    <span className={`flex-1 truncate ${ev.alert ? 'text-red-400 font-bold' : 'text-slate-500'}`}>
                      {ev.alert ? 'THREAT DETECTED' : 'Verified'}
                    </span>
                    {ev.alert && <AlertTriangle className="w-4 h-4 text-red-500 animate-pulse" />}
                 </div>
               ))}
            </div>
          </div>
        </div>
        
        <div className="space-y-4">
           <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-xl space-y-5">
              <div>
                <h3 className="text-[9px] font-black uppercase text-slate-600 tracking-widest mb-3">Resources</h3>
                <div className="space-y-3">
                  <div className="space-y-1.5">
                    <div className="flex justify-between text-[9px] font-bold text-slate-500 uppercase"><span>CPU</span><span>12%</span></div>
                    <div className="h-0.5 bg-slate-800 rounded-full overflow-hidden"><div className="h-full bg-emerald-500/60 w-[12%]" /></div>
                  </div>
                  <div className="space-y-1.5">
                    <div className="flex justify-between text-[9px] font-bold text-slate-500 uppercase"><span>RAM</span><span>4.2GB</span></div>
                    <div className="h-0.5 bg-slate-800 rounded-full overflow-hidden"><div className="h-full bg-sky-500/60 w-[45%]" /></div>
                  </div>
                </div>
              </div>
              <div className="pt-3 border-t border-slate-800/50 flex justify-between items-center">
                <p className="text-[9px] font-black text-slate-600 uppercase tracking-widest">Invocations</p>
                <p className="text-base font-black text-white">{Object.values(liveAggregatedCounts).reduce((a: number, b: number) => a + b, 0)}</p>
              </div>
              <div className="flex justify-between items-center">
                <p className="text-[9px] font-black text-slate-600 uppercase tracking-widest">Endpoints</p>
                <p className="text-base font-black text-white">{livePidsObserved.size}</p>
              </div>
           </div>
           
           <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 shadow-xl flex flex-col justify-center gap-2 text-center py-5">
              <div className={`w-2.5 h-2.5 rounded-full mx-auto ${wsStatus === 'CONNECTED' ? 'bg-emerald-500 shadow-[0_0_10px_rgba(16,185,129,0.5)]' : 'bg-red-500'}`} />
              <div>
                 <p className="text-[9px] font-black text-slate-600 uppercase tracking-widest mb-0.5">Sensor Status</p>
                 <p className="text-[11px] font-black text-white uppercase">{wsStatus}</p>
                 {wsStatus === 'DISCONNECTED' && (
                   <div className="flex items-center justify-center gap-1.5 mt-1">
                      <Loader2 className="w-2.5 h-2.5 animate-spin text-slate-500" />
                      <p className="text-[8px] text-slate-600 font-bold uppercase">Reconnecting...</p>
                   </div>
                 )}
              </div>
           </div>
        </div>
      </div>
    </div>
  );

  /**
   * Results Dashboard
   */
  /*const renderDashboardView = () => {
    if (result) {
      const isIntrusion = result.status === 'INTRUSION';
      const peakDeviation = Math.max(...result.syscalls.map(s => s.deviation));
      return (
        <div className="space-y-6 animate-in fade-in slide-in-from-bottom-4 duration-500">
          <div className={`w-full py-5 px-8 rounded-3xl border flex flex-col md:flex-row items-center justify-between gap-4 shadow-2xl relative overflow-hidden transition-all duration-700 ${
            isIntrusion 
              ? 'bg-red-600/20 border-red-500/50 text-red-400 ring-2 ring-red-500/20' 
              : 'bg-emerald-600/10 border-emerald-500/30 text-emerald-400'
          }`}>
             <div className="flex items-center gap-5 relative z-10">
                <div className={`p-3 rounded-2xl ${isIntrusion ? 'bg-red-500/20 text-red-500' : 'bg-emerald-500/20 text-emerald-500'}`}>
                   {isIntrusion ? <AlertOctagon className="w-8 h-8 animate-bounce" /> : <ShieldCheck className="w-8 h-8" />}
                </div>
                <div>
                   <p className="text-[10px] font-black uppercase tracking-[0.3em] opacity-60 mb-0.5">Audit Response Protocol</p>
                   <p className="text-xl font-black uppercase tracking-widest leading-none">
                      {isIntrusion ? "SYSTEM ALERT: HOSTILE BEHAVIOR DETECTED" : "SYSTEM SECURE: NO ANOMALIES FOUND"}
                   </p>
                </div>
             </div>
             <div className="flex items-center gap-6 relative z-10">
                <div className={`flex items-center gap-2 px-4 py-2 rounded-full border text-[10px] font-black uppercase ${isIntrusion ? 'bg-red-500 text-white border-red-400' : 'bg-emerald-500/20 border-emerald-500/30 text-emerald-500'}`}>
                   <span className={`w-2 h-2 rounded-full ${isIntrusion ? 'bg-white animate-ping' : 'bg-emerald-500'}`} />
                   {isIntrusion ? 'Breach Active' : 'Optimal'}
                </div>
             </div>
          </div>

          <div className="flex flex-col md:flex-row justify-between items-start md:items-end gap-6">
            <div>
              <div className="flex items-center gap-2 mb-2">
                 <span className="text-[10px] font-black bg-slate-800 text-slate-400 px-2 py-0.5 rounded uppercase tracking-widest">Report GUID: {result.id}</span>
                 <span className="text-[10px] font-mono text-slate-500">{result.timestamp}</span>
              </div>
              <h2 className="text-4xl font-black text-white uppercase tracking-tighter flex items-center gap-3">
                {isIntrusion ? <><ShieldX className="w-10 h-10 text-red-500" /> Neural <span className="text-red-500">Alert</span></> : <><ShieldCheck className="w-10 h-10 text-emerald-500" /> Integrity <span className="text-emerald-500">Verified</span></>}
              </h2>
            </div>
            <div className="flex gap-3 w-full md:w-auto">
               <button onClick={resetAnalysis} className="flex-1 md:flex-none px-5 py-3 bg-slate-900 border border-slate-800 rounded-2xl text-xs font-bold text-slate-300 transition-all flex items-center justify-center gap-2 hover:bg-slate-800"><RefreshCw className="w-4 h-4" /> New Scan</button>
               <button onClick={saveCurrentToHistory} disabled={isCurrentResultSaved} className={`flex-1 md:flex-none px-5 py-3 border rounded-2xl text-xs font-black transition-all flex items-center justify-center gap-2 ${isCurrentResultSaved ? 'bg-emerald-500/10 border-emerald-500/20 text-emerald-500' : 'bg-slate-900 border-slate-800 text-slate-300 shadow-lg'}`}>{isCurrentResultSaved ? <Check className="w-4 h-4" /> : <Save className="w-4 h-4" />}{isCurrentResultSaved ? 'Archived' : 'Archive Report'}</button>
            </div>
          </div>
          
          <div className={`p-8 rounded-[32px] border ${isIntrusion ? 'bg-red-500/5 border-red-500/20' : 'bg-emerald-500/5 border-emerald-500/20'}`}>
            <h3 className="text-xs font-black uppercase text-slate-500 tracking-widest mb-4 flex items-center gap-2"><Zap className="w-4 h-4" /> Forensic Narrative</h3>
            <p className="text-lg text-slate-100 font-medium leading-relaxed italic border-l-4 border-slate-800 pl-6 py-2">"{result.explanation}"</p>
          </div>

          <div className="grid md:grid-cols-4 gap-6">
             <div className="bg-slate-900 border border-slate-800 rounded-[32px] p-6 shadow-xl"><RiskMeter level={result.riskLevel} /></div>
             <div className="bg-slate-900 border border-slate-800 rounded-[32px] p-6 shadow-xl flex flex-col justify-between">
                <span className="text-[10px] font-black uppercase text-slate-500 tracking-widest mb-1">Divergence Score</span>
                <span className={`text-4xl font-black ${isIntrusion ? 'text-red-500' : 'text-emerald-500'}`}>{result.deviationScore.toFixed(1)}%</span>
             </div>
             <div className="bg-slate-900 border border-slate-800 rounded-[32px] p-6 shadow-xl flex flex-col justify-between group">
                <span className="text-[10px] font-black uppercase text-slate-500 tracking-widest mb-1">Peak Variance</span>
                <span className={`text-4xl font-black ${peakDeviation > threshold * 2 ? 'text-orange-500' : 'text-white'}`}>{peakDeviation.toFixed(1)}%</span>
             </div>
             <div className="bg-slate-900 border border-slate-800 rounded-[32px] p-6 shadow-xl flex flex-col justify-between">
                <span className="text-[10px] font-black uppercase text-slate-500 tracking-widest mb-1">Flagged Nodes</span>
                <span className="text-4xl font-black text-white">{result.syscalls.filter(s => s.deviation > threshold).length}</span>
             </div>
          </div>

          <div className="grid lg:grid-cols-3 gap-8">
             <div className="lg:col-span-2 bg-slate-900 border border-slate-800 rounded-[32px] p-8 shadow-2xl overflow-hidden"><SyscallChart data={result.syscalls.slice(0, 25)} /></div>
             <div className="bg-slate-900 border border-slate-800 rounded-[32px] p-8 shadow-2xl"><h3 className="text-sm font-black uppercase text-slate-400 mb-6 tracking-widest">Hazard Timeline</h3><TrendChart data={result.timeline} /></div>
          </div>
        </div>
      );
    }

    return (
      <div className="text-center py-24 opacity-30">
        <Activity className="w-16 h-16 mx-auto mb-6 text-slate-700" />
        <p className="italic font-bold uppercase tracking-widest text-slate-600">No active analysis. Please run a snapshot or upload a capture.</p>
        <button onClick={() => setActiveView('UPLOAD')} className="mt-6 px-6 py-2 bg-slate-800 text-slate-300 rounded-xl text-xs uppercase font-black">Go to Ingestion</button>
      </div>
    );
  };

  /**
   * Enhanced Settings View with Alert Throttling
   */
  /*const renderSettingsView = () => (
    <div className="space-y-8 animate-in fade-in slide-in-from-bottom-4 duration-500">
       <div className="flex justify-between items-center mb-8">
          <div><h2 className="text-3xl font-black text-white uppercase tracking-tight">Configuration Console</h2><p className="text-slate-500 text-sm">Global thresholding and sensor tuning</p></div>
       </div>
       
       <div className="grid md:grid-cols-2 gap-8">
          {/* DETECTION SETTINGS */}
          /*<div className="bg-slate-900 border border-slate-800 rounded-[32px] p-10 space-y-8 shadow-xl">
             <div className="flex items-center gap-4"><div className="p-2 bg-orange-500/10 rounded-xl"><Gauge className="w-6 h-6 text-orange-400" /></div><h3 className="text-sm font-black uppercase tracking-[0.2em] text-white">Detection Delta</h3></div>
             <div className="space-y-8">
                <div className="space-y-4">
                   <div className="flex justify-between items-end">
                      <label className="text-[10px] font-black text-slate-500 uppercase tracking-[0.2em]">Divergence Sensitivity</label>
                      <span className="text-xl font-black text-sky-400 font-mono">{threshold}%</span>
                   </div>
                   <input type="range" min="1" max="100" value={threshold} onChange={(e) => setThreshold(parseInt(e.target.value))} className="w-full h-2 bg-slate-800 rounded-full appearance-none cursor-pointer accent-sky-500" />
                   <p className="text-[10px] text-slate-500 leading-relaxed italic">The variance percentage required to trigger an anomaly event.</p>
                </div>
             </div>
          </div>

          {/* ALERT THROTTLING */}
        /*  <div className="bg-slate-900 border border-slate-800 rounded-[32px] p-10 space-y-8 shadow-xl">
             <div className="flex items-center gap-4"><div className="p-2 bg-sky-500/10 rounded-xl"><Timer className="w-6 h-6 text-sky-400" /></div><h3 className="text-sm font-black uppercase tracking-[0.2em] text-white">Alert Throttling</h3></div>
             <div className="space-y-8">
                <div className="space-y-4">
                   <div className="flex justify-between items-end">
                      <label className="text-[10px] font-black text-slate-500 uppercase tracking-[0.2em]">Cooldown Window</label>
                      <span className="text-xl font-black text-sky-400 font-mono">{alertCooldown}s</span>
                   </div>
                   <input 
                      type="range" 
                      min="5" 
                      max="300" 
                      step="5" 
                      value={alertCooldown} 
                      onChange={(e) => {
                        const val = parseInt(e.target.value);
                        setAlertCooldown(val); 
                        localStorage.setItem('sysguard_cooldown', String(val));
                      }} 
                      className="w-full h-2 bg-slate-800 rounded-full appearance-none cursor-pointer accent-sky-500" 
                   />
                   <p className="text-[10px] text-slate-500 leading-relaxed italic">Minimum duration between modal alerts to prevent analyst fatigue during attacks.</p>
                </div>
                
                <div className="flex items-center justify-between p-6 bg-slate-950 rounded-[28px] border border-slate-800 group hover:border-sky-500/30 transition-all">
                   <div className="flex-1 pr-6">
                      <p className="text-sm font-black text-white uppercase tracking-tight mb-1">Dynamic Scaling</p>
                      <p className="text-[10px] text-slate-500 leading-normal font-medium uppercase">Increases cooldown automatically if alert density spikes.</p>
                   </div>
                   <button 
                      onClick={() => {
                        const next = !isDynamicCooldown; 
                        setIsDynamicCooldown(next); 
                        localStorage.setItem('sysguard_dynamic_cooldown', String(next));
                      }} 
                      className={`w-14 h-7 rounded-full transition-all relative flex items-center px-1 ${isDynamicCooldown ? 'bg-sky-600' : 'bg-slate-800'}`}
                   >
                      <div className={`w-5 h-5 bg-white rounded-full transition-all shadow-md ${isDynamicCooldown ? 'translate-x-7' : 'translate-x-0'}`} />
                   </button>
                </div>
             </div>
          </div>
       </div>
    </div>
  );

  const renderUploadView = () => (
    <div className="space-y-8 animate-in fade-in slide-in-from-bottom-4 duration-500">
      <div className="flex justify-between items-center mb-8">
        <div><h2 className="text-3xl font-black text-white uppercase tracking-tight flex items-center gap-3"><UploadCloud className="w-8 h-8 text-sky-500" /> Data Ingestion</h2><p className="text-slate-500 text-sm">Upload system traces for forensic modeling</p></div>
      </div>
      <div className="grid md:grid-cols-2 gap-8">
        <div className="bg-slate-900 border border-slate-800 rounded-[32px] p-10 space-y-6 shadow-xl relative overflow-hidden group">
          <div className="absolute top-0 right-0 p-8 opacity-10"><ShieldCheck className="w-32 h-32 text-emerald-500" /></div>
          <div className="space-y-2"><h3 className="text-sm font-black uppercase tracking-[0.2em] text-emerald-500 flex items-center gap-2">Clean Baseline</h3><p className="text-xs text-slate-400">Reference model of expected system behavior.</p></div>
          <div onClick={() => baselineInputRef.current?.click()} className={`border-2 border-dashed rounded-[32px] py-16 flex flex-col items-center justify-center cursor-pointer transition-all ${baselineParsed ? 'border-emerald-500/50 bg-emerald-500/5' : 'border-slate-800 hover:border-slate-700 bg-slate-950'}`}>
            <input type="file" ref={baselineInputRef} onChange={(e) => handleFileUpload(e, 'baseline')} className="hidden" accept=".csv,.txt,.log" />
            {baselineFileName ? <div className="text-center"><FileText className="w-10 h-10 text-emerald-500 mx-auto mb-4" /><p className="text-sm font-bold text-white truncate max-w-[200px]">{baselineFileName}</p></div> : <><Upload className="w-10 h-10 text-slate-700 mb-4" /><p className="text-[10px] font-black text-slate-500 uppercase tracking-[0.3em]">Attach Reference</p></>}
          </div>
        </div>
        <div className="bg-slate-900 border border-slate-800 rounded-[32px] p-10 space-y-6 shadow-xl relative overflow-hidden group">
          <div className="absolute top-0 right-0 p-8 opacity-10"><Skull className="w-32 h-32 text-red-500" /></div>
          <div className="space-y-2"><h3 className="text-sm font-black uppercase tracking-[0.2em] text-red-500 flex items-center gap-2">Behavioral Trace</h3><p className="text-xs text-slate-400">Suspicious system capture to be audited.</p></div>
          <div onClick={() => testInputRef.current?.click()} className={`border-2 border-dashed rounded-[32px] py-16 flex flex-col items-center justify-center cursor-pointer transition-all ${testParsed ? 'border-red-500/50 bg-red-500/5' : 'border-slate-800 hover:border-slate-700 bg-slate-950'}`}>
            <input type="file" ref={testInputRef} onChange={(e) => handleFileUpload(e, 'test')} className="hidden" accept=".csv,.txt,.log" />
            {testFileName ? <div className="text-center"><FileText className="w-10 h-10 text-red-500 mx-auto mb-4" /><p className="text-sm font-bold text-white truncate max-w-[200px]">{testFileName}</p></div> : <><Upload className="w-10 h-10 text-slate-700 mb-4" /><p className="text-[10px] font-black text-slate-500 uppercase tracking-[0.3em]">Attach Capture</p></>}
          </div>
        </div>
      </div>
      <div className="flex justify-center pt-8">
        <button onClick={() => handleRunAnalysis()} disabled={!baselineParsed || !testParsed || isAnalyzing} className="px-16 py-6 bg-sky-600 hover:bg-sky-500 disabled:bg-slate-800 text-white rounded-3xl font-black uppercase tracking-[0.3em] shadow-2xl transition-all flex items-center gap-5 active:scale-95">
          {isAnalyzing ? <><Loader2 className="w-6 h-6 animate-spin" /> Analyzing Trace...</> : <><Fingerprint className="w-6 h-6" /> Start Neural Audit</>}
        </button>
      </div>
    </div>
  );

  const renderAlertsView = () => (
    <div className="space-y-6 animate-in fade-in slide-in-from-bottom-4 duration-500">
      <div className="flex justify-between items-center mb-8">
        <div><h2 className="text-3xl font-black text-white uppercase tracking-tight flex items-center gap-3"><Bell className="w-8 h-8 text-sky-500" /> Alert Command</h2><p className="text-slate-500 text-sm">Review triggered detections</p></div>
        <button onClick={() => setAlerts([])} className="p-2 text-slate-500 hover:text-red-500 transition-colors"><Trash2 className="w-5 h-5" /></button>
      </div>
      <div className="grid gap-4">
        {alerts.length === 0 ? <div className="text-center py-24 opacity-30"><p className="italic font-bold uppercase tracking-widest text-slate-600">Secure: No incidents recorded</p></div> : alerts.map((alert) => (
          <div key={alert.id} className={`p-8 bg-slate-900 border rounded-[32px] transition-all ${alert.read ? 'border-slate-800 opacity-60' : 'border-red-500/40 shadow-lg shadow-red-500/5'}`}>
            <div className="flex items-start gap-6">
              <div className={`p-4 rounded-2xl ${alert.severity === RiskLevel.CRITICAL ? 'bg-red-500/20 text-red-500' : 'bg-orange-500/20 text-orange-500'}`}>
                <AlertOctagon className="w-6 h-6" />
              </div>
              <div className="flex-1">
                <div className="flex justify-between items-center mb-1">
                  <h3 className="font-black text-white text-lg uppercase tracking-tight">{alert.title}</h3>
                  <span className="text-[10px] font-mono font-bold text-slate-500">{alert.timestamp}</span>
                </div>
                <p className="text-slate-400 text-sm mb-6 leading-relaxed">"{alert.message}"</p>
                <div className="flex gap-6">
                  <button onClick={() => markAlertRead(alert.id)} className="text-[10px] font-black uppercase text-slate-500 hover:text-white transition-colors">Acknowledge</button>
                  {alert.analysisId !== 'LIVE_STREAM' && <button onClick={() => viewAlertAnalysis(alert)} className="text-[10px] font-black uppercase text-sky-500 flex items-center gap-2">Inspect Details <ArrowRight className="w-3 h-3" /></button>}
                </div>
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );

  const renderHistoryView = () => (
    <div className="space-y-6 animate-in fade-in slide-in-from-bottom-4 duration-500">
      <div className="flex justify-between items-center mb-8">
        <div><h2 className="text-3xl font-black text-white uppercase tracking-tight flex items-center gap-3"><History className="w-8 h-8 text-sky-500" /> Archives</h2><p className="text-slate-500 text-sm">Historical snapshots</p></div>
      </div>
      <div className="bg-slate-900 border border-slate-800 rounded-[32px] overflow-hidden shadow-2xl">
         <table className="w-full text-sm text-left">
            <thead className="text-[10px] uppercase font-black tracking-widest text-slate-500 bg-slate-950/50">
               <tr><th className="px-8 py-5">State</th><th className="px-8 py-5">Incident GUID</th><th className="px-8 py-5">Divergence</th><th className="px-8 py-5 text-right">Evidence</th></tr>
            </thead>
            <tbody className="divide-y divide-slate-800/50">
               {history.length === 0 ? <tr><td colSpan={4} className="px-8 py-16 text-center text-slate-600 italic">No historical records.</td></tr> : history.map((h) => (
                 <tr key={h.id} className="hover:bg-slate-800/30 transition-colors cursor-pointer" onClick={() => {setResult(h); setActiveView('DASHBOARD')}}>
                    <td className="px-8 py-6">
                       <div className="flex items-center gap-3">
                          <div className={`w-3 h-3 rounded-full ${h.status === 'INTRUSION' ? 'bg-red-500' : 'bg-emerald-500'}`} />
                          <span className={`text-[10px] font-black uppercase tracking-widest ${h.status === 'INTRUSION' ? 'text-red-400' : 'text-emerald-400'}`}>{h.status}</span>
                       </div>
                    </td>
                    <td className="px-8 py-6"><div className="font-bold text-white">{h.id}</div><div className="text-[10px] text-slate-500 uppercase font-mono">{h.timestamp}</div></td>
                    <td className="px-8 py-6 font-mono font-bold text-slate-300">{h.deviationScore.toFixed(2)}%</td>
                    <td className="px-8 py-6 text-right"><button className="p-3 bg-slate-800 rounded-xl text-slate-400 hover:text-white transition-all"><Eye className="w-4 h-4" /></button></td>
                 </tr>
               ))}
            </tbody>
         </table>
      </div>
    </div>
  );

  const renderLoginView = () => (
    <div className="min-h-screen bg-slate-950 flex items-center justify-center p-6 relative overflow-hidden">
      <div className="max-w-md w-full bg-slate-900 border border-slate-800 rounded-[48px] p-12 shadow-2xl relative z-10">
        <div className="bg-sky-500/10 w-20 h-20 rounded-3xl border border-sky-500/20 flex items-center justify-center mb-10 mx-auto">
          <ShieldCheck className="w-10 h-10 text-sky-400" />
        </div>
        <h1 className="text-4xl font-black text-white text-center mb-2 uppercase tracking-tighter">SysGuard <span className="text-sky-500">IDS</span></h1>
        <p className="text-slate-500 text-center text-[10px] mb-12 font-black uppercase tracking-[0.4em]">Audit Terminal Login</p>
        <form className="space-y-6" onSubmit={handleLogin}>
          <div className="space-y-2">
            <label className="text-[10px] font-black uppercase text-slate-500 tracking-widest ml-1">Operator ID</label>
            <div className="relative">
              <User className="absolute left-5 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-600" />
              <input type="text" value={credentials.id} onChange={(e) => setCredentials({...credentials, id: e.target.value})} className="w-full bg-slate-950 border border-slate-800 rounded-2xl py-5 pl-14 pr-4 text-white font-mono text-sm focus:outline-none focus:ring-2 focus:ring-sky-500/50" />
            </div>
          </div>
          <div className="space-y-2">
            <label className="text-[10px] font-black uppercase text-slate-500 tracking-widest ml-1">Access Passcode</label>
            <div className="relative">
              <Lock className="absolute left-5 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-600" />
              <input type="password" value={credentials.key} onChange={(e) => setCredentials({...credentials, key: e.target.value})} className="w-full bg-slate-950 border border-slate-800 rounded-2xl py-5 pl-14 pr-4 text-white font-mono text-sm focus:outline-none focus:ring-2 focus:ring-sky-500/50" />
            </div>
          </div>
          <button type="submit" disabled={loginLoading} className="w-full bg-sky-600 hover:bg-sky-500 text-white font-black uppercase py-6 rounded-3xl shadow-2xl transition-all flex items-center justify-center gap-4 active:scale-95">
            {loginLoading ? <Loader2 className="w-6 h-6 animate-spin" /> : <><Zap className="w-5 h-5" /> Initialize Session</>}
          </button>
        </form>
      </div>
    </div>
  );

  if (!isAuthenticated) return renderLoginView();

  return (
    <Layout activeView={activeView} setView={setActiveView} onLogout={handleLogout} alerts={alerts}>
      {activeView === 'LIVE' && renderLiveView()}
      {activeView === 'UPLOAD' && renderUploadView()}
      {activeView === 'DASHBOARD' && renderDashboardView()}
      {activeView === 'HISTORY' && renderHistoryView()}
      {activeView === 'ALERTS' && renderAlertsView()}
      {activeView === 'SETTINGS' && renderSettingsView()}
      {activeAlert && (
        <div className="fixed inset-0 z-[100] flex items-center justify-center p-6 bg-slate-950/90 backdrop-blur-md animate-in fade-in duration-300">
          <div className="max-w-xl w-full bg-slate-900 border border-slate-800 rounded-[48px] shadow-[0_0_100px_rgba(239,68,68,0.15)] overflow-hidden relative group">
            <div className={`h-2.5 w-full ${activeAlert.severity === RiskLevel.CRITICAL ? 'bg-red-500' : 'bg-orange-500'}`} />
            <button onClick={() => setActiveAlert(null)} className="absolute top-8 right-8 p-3 bg-slate-800 hover:bg-slate-700 text-slate-400 rounded-full transition-all"><X className="w-5 h-5" /></button>
            <div className="p-12 text-center">
              <div className={`w-24 h-24 mx-auto rounded-[32px] mb-10 flex items-center justify-center ${activeAlert.severity === RiskLevel.CRITICAL ? 'bg-red-500/20 text-red-500' : 'bg-orange-500/20 text-orange-500'}`}>
                 <ShieldAlert className="w-12 h-12" />
              </div>
              <span className="text-[10px] font-black uppercase tracking-[0.4em] text-slate-500">Security Breach Alert</span>
              <h2 className="text-4xl font-black text-white mt-4 mb-6 leading-tight uppercase tracking-tighter">{activeAlert.title}</h2>
              <p className="text-slate-400 mb-12 text-lg font-medium leading-relaxed">"{activeAlert.message}"</p>
              <div className="flex flex-col sm:flex-row gap-5">
                 <button onClick={() => {setActiveView('ALERTS'); setActiveAlert(null)}} className="flex-1 py-5 bg-red-600 hover:bg-red-500 text-white font-black uppercase text-xs tracking-[0.2em] rounded-3xl shadow-2xl transition-all active:scale-95">Inspect Evidence</button>
                 <button onClick={() => setActiveAlert(null)} className="px-10 py-5 bg-slate-800 hover:bg-slate-700 text-slate-300 font-black uppercase text-xs tracking-[0.2em] rounded-3xl transition-all">Dismiss</button>
              </div>
            </div>
          </div>
        </div>
      )}
    </Layout>
  );
};*/

function App() {
  return (
    <div style={{ padding: "40px", fontSize: "24px" }}>
      SysGuard is LIVE 🚀
    </div>
  );
}

export default App;


