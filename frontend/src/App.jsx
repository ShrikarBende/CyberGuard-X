import React, { useState, useEffect, useRef } from 'react';
import Sidebar from './components/Sidebar';
import Header from './components/Header';
import Overview from './pages/Overview';
import LiveMonitoring from './pages/LiveMonitoring';
import ThreatIntelligence from './pages/ThreatIntelligence';
import IncidentManagement from './pages/IncidentManagement';
import Explainability from './pages/Explainability';
import AIAssistant from './pages/AIAssistant';
import DataManagement from './pages/DataManagement';

export default function App() {
  const [activePage, setActivePage] = useState('overview');
  const [selectedIncidentIdForAssistant, setSelectedIncidentIdForAssistant] = useState(null);
  const [liveEvents, setLiveEvents] = useState([]);
  const [wsConnected, setWsConnected] = useState(false);
  const wsRef = useRef(null);

  // WebSocket Live Connection
  useEffect(() => {
    let reconnectTimeout = null;
    let isMounted = true;

    function connect() {
      const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
      const host = window.location.host;
      const wsUrl = `${protocol}//${host}/ws/live-events`;

      try {
        const ws = new WebSocket(wsUrl);
        wsRef.current = ws;

        ws.onopen = () => {
          if (isMounted) setWsConnected(true);
        };

        ws.onmessage = (event) => {
          try {
            const data = JSON.parse(event.data);
            if (data.type === 'SECURITY_EVENT') {
              setLiveEvents((prev) => [data, ...prev.slice(0, 150)]);
            }
          } catch (e) {
            console.error('Failed to parse WS payload:', e);
          }
        };

        ws.onclose = () => {
          if (isMounted) {
            setWsConnected(false);
            reconnectTimeout = setTimeout(connect, 3000);
          }
        };

        ws.onerror = () => {
          ws.close();
        };
      } catch (err) {
        console.error('WS Connection error:', err);
        reconnectTimeout = setTimeout(connect, 4000);
      }
    }

    connect();

    return () => {
      isMounted = false;
      if (reconnectTimeout) clearTimeout(reconnectTimeout);
      if (wsRef.current) wsRef.current.close();
    };
  }, []);

  const handleSelectIncidentForAssistant = (incId) => {
    setSelectedIncidentIdForAssistant(incId);
    setActivePage('assistant');
  };

  const pageTitles = {
    overview: 'Executive Overview Dashboard',
    live: 'Live Security Telemetry Stream',
    threats: 'Threat Intelligence & Open-Set Analysis',
    incidents: 'Incident Management & Correlation',
    explain: 'SHAP Explainability & Risk Scoring',
    assistant: 'Grounded AI Security Assistant (RAG)',
    data: 'Data Governance & Model Training',
  };

  return (
    <div className="flex h-screen w-screen bg-[#0A0F1D] text-[#F8FAFC] overflow-hidden">
      {/* Sidebar Navigation */}
      <Sidebar activePage={activePage} setActivePage={setActivePage} />

      {/* Main Content Area */}
      <div className="flex-1 flex flex-col min-w-0 overflow-hidden">
        <Header pageTitle={pageTitles[activePage] || 'SOC Dashboard'} wsConnected={wsConnected} />

        <main className="flex-1 overflow-y-auto p-8">
          {activePage === 'overview' && (
            <Overview onSelectIncident={handleSelectIncidentForAssistant} />
          )}
          {activePage === 'live' && <LiveMonitoring liveEvents={liveEvents} />}
          {activePage === 'threats' && <ThreatIntelligence />}
          {activePage === 'incidents' && (
            <IncidentManagement onSelectIncidentForAssistant={handleSelectIncidentForAssistant} />
          )}
          {activePage === 'explain' && <Explainability />}
          {activePage === 'assistant' && (
            <AIAssistant initialIncidentId={selectedIncidentIdForAssistant} />
          )}
          {activePage === 'data' && <DataManagement />}
        </main>
      </div>
    </div>
  );
}

