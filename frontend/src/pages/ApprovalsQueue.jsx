import React, { useCallback, useEffect, useState } from 'react';
import { api } from '../services/api';
import Card from '../components/ui/Card';

export default function ApprovalsQueue({ analyst = null }) {
  const [proposals, setProposals] = useState([]);
  const [notes, setNotes] = useState({});
  const [busyId, setBusyId] = useState('');
  const [error, setError] = useState('');
  const [message, setMessage] = useState('');
  const [agentConfig, setAgentConfig] = useState(null);
  const canReview = analyst?.role === 'admin' || analyst?.role === 'analyst';

  const refresh = useCallback(async () => {
    try {
      setProposals(await api.getAgentProposals('pending'));
      setError('');
    } catch (err) {
      setError(err.message || 'Pending proposals could not be loaded.');
    }
  }, []);

  useEffect(() => {
    api.getAgentConfig().then(setAgentConfig).catch(() => setAgentConfig({ allow_self_approval: false }));
    refresh();
    const timer = window.setInterval(refresh, 1500);
    return () => window.clearInterval(timer);
  }, [refresh]);

  const decide = async (proposal, decision) => {
    setBusyId(proposal.proposal_id);
    setError('');
    setMessage('');
    try {
      const note = notes[proposal.proposal_id] || '';
      if (decision === 'approved') await api.approveAgentProposal(proposal.proposal_id, note);
      else await api.rejectAgentProposal(proposal.proposal_id, note);
      setMessage(`Proposal ${decision}.`);
      await refresh();
    } catch (err) {
      setError(err.message || `Proposal could not be ${decision}.`);
    } finally {
      setBusyId('');
    }
  };

  return <div className="mx-auto w-full max-w-[1400px] space-y-5">
    <header><p className="text-xs uppercase tracking-[0.2em] text-amber-200">Human review</p><h1 className="mt-1 font-display text-3xl font-light text-slate-50">Action approvals</h1><p className="mt-2 text-sm text-slate-400">Each action needs a human decision. Approval records a dry run only.</p></header>
    {error && <div role="alert" className="rounded-xl border border-rose-500/25 bg-rose-500/[0.06] p-3 text-sm text-rose-200">{error}</div>}
    {message && <div role="status" className="rounded-xl border border-emerald-300/15 bg-emerald-300/[0.04] p-3 text-sm text-emerald-100">{message}</div>}
    {!canReview && <div role="note" className="rounded-xl border border-blue-300/15 bg-blue-300/[0.04] p-3 text-sm text-blue-100">Read-only view. Analysts and admins can review proposals.</div>}
    {proposals.length === 0 && !error && <Card className="p-8 text-center text-sm text-slate-400">No pending proposals.</Card>}
    <div className="space-y-4">{proposals.map((proposal) => {
      const isRequester = !agentConfig?.allow_self_approval && proposal.requested_by === analyst?.username;
      const disabled = !canReview || isRequester || busyId === proposal.proposal_id;
      const reason = isRequester ? 'four-eyes' : !canReview ? 'Read-only role' : undefined;
      return <Card key={proposal.proposal_id} className="space-y-4 p-5">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div><p className="font-mono text-[11px] text-slate-500">{proposal.proposal_id} · incident {proposal.incident_id}</p><h2 className="mt-1 text-lg font-semibold text-amber-100">{proposal.action_type} <span className="text-slate-300">→ {proposal.target_type}: {proposal.target}</span></h2></div>
          <span className="rounded-full border border-amber-300/20 bg-amber-300/[0.05] px-3 py-1 text-xs text-amber-100">Confidence {(proposal.confidence * 100).toFixed(0)}%</span>
        </div>
        <p className="text-sm leading-relaxed text-slate-300">{proposal.rationale}</p>
        <div><p className="text-[11px] uppercase tracking-wide text-slate-500">Evidence</p><div className="mt-2 flex flex-wrap gap-1.5">{proposal.evidence_ids.map((id) => <span key={id} className="rounded-md border border-blue-300/15 bg-blue-300/[0.06] px-2 py-0.5 font-mono text-[10px] text-blue-100">{id}</span>)}</div></div>
        <p className="text-xs text-slate-500">Requested by {proposal.requested_by} · {new Date(proposal.created_at).toLocaleString()}</p>
        <label className="block"><span className="mb-1.5 block text-xs text-slate-400">Decision note</span><textarea value={notes[proposal.proposal_id] || ''} onChange={(event) => setNotes((current) => ({ ...current, [proposal.proposal_id]: event.target.value }))} maxLength={1000} rows={2} className="w-full resize-y rounded-xl border border-white/[0.08] bg-slate-950/45 px-3 py-2 text-sm text-slate-100 placeholder:text-slate-600 focus:outline-none focus:ring-2 focus:ring-blue-300" placeholder="Optional note for the audit trail" /></label>
        <div className="flex flex-wrap gap-2"><button type="button" disabled={disabled} title={reason} onClick={() => decide(proposal, 'approved')} className="rounded-full border border-emerald-300/20 bg-emerald-300/[0.06] px-4 py-2 text-xs font-semibold text-emerald-100 hover:bg-emerald-300/[0.12] disabled:cursor-not-allowed disabled:opacity-40">Approve · simulate</button><button type="button" disabled={disabled} title={reason} onClick={() => decide(proposal, 'rejected')} className="rounded-full border border-rose-300/20 bg-rose-300/[0.05] px-4 py-2 text-xs font-semibold text-rose-100 hover:bg-rose-300/[0.1] disabled:cursor-not-allowed disabled:opacity-40">Reject</button></div>
      </Card>;
    })}</div>
  </div>;
}
