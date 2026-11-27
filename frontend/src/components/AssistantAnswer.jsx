import React from 'react';

function inline(text, keyPrefix) {
  const parts = text.split(/(`[^`]+`|\*\*[^*]+\*\*|\[[^\]]+\])/g);
  return parts.map((part, index) => {
    const key = `${keyPrefix}-${index}`;
    if (part.startsWith('`') && part.endsWith('`')) return <code key={key} className="assistant-inline-code rounded px-1 py-0.5 font-mono text-[0.92em]">{part.slice(1, -1)}</code>;
    if (part.startsWith('**') && part.endsWith('**')) return <strong key={key} className="font-semibold text-slate-900">{part.slice(2, -2)}</strong>;
    if (/^\[[^\]]+\]$/.test(part)) return <span key={key} className="font-mono text-purple-700">{part}</span>;
    return part;
  });
}

function isTableRow(line) {
  return /^\s*\|.*\|\s*$/.test(line);
}

function cells(line) {
  return line.trim().replace(/^\||\|$/g, '').split('|').map((cell) => cell.trim());
}

export default function AssistantAnswer({ text }) {
  const lines = String(text || '').split('\n');
  const blocks = [];
  let i = 0;
  while (i < lines.length) {
    const line = lines[i].trim();
    if (!line) { i += 1; continue; }

    if (isTableRow(line) && i + 1 < lines.length && /^\s*\|?\s*:?-{3,}/.test(lines[i + 1])) {
      const headers = cells(line);
      i += 2;
      const rows = [];
      while (i < lines.length && isTableRow(lines[i])) { rows.push(cells(lines[i])); i += 1; }
      blocks.push(<div key={`table-${i}`} className="grid gap-2 sm:grid-cols-2">
        {rows.map((row, rowIndex) => <div key={rowIndex} className="rounded-lg border border-slate-200 bg-white/70 p-3">
          {row.map((value, colIndex) => <div key={colIndex} className="mb-1 last:mb-0">
            <span className="mr-1 text-[11px] font-semibold uppercase tracking-wide text-slate-500">{headers[colIndex] || `Field ${colIndex + 1}`}:</span>
            <span>{inline(value, `table-${rowIndex}-${colIndex}`)}</span>
          </div>)}
        </div>)}
      </div>);
      continue;
    }

    const heading = line.match(/^(#{1,4})\s+(.+)$/);
    if (heading) {
      blocks.push(<h3 key={`h-${i}`} className="pt-2 text-sm font-bold text-slate-900">{inline(heading[2], `h-${i}`)}</h3>);
      i += 1; continue;
    }
    if (/^(---+|\*\*\*+)$/.test(line)) { i += 1; continue; }
    if (/^[-*]\s+/.test(line)) {
      const items = [];
      while (i < lines.length && /^\s*[-*]\s+/.test(lines[i])) {
        items.push(lines[i].trim().replace(/^[-*]\s+/, '')); i += 1;
      }
      blocks.push(<ul key={`ul-${i}`} className="list-disc space-y-1 pl-5">{items.map((item, index) => <li key={index}>{inline(item, `ul-${i}-${index}`)}</li>)}</ul>);
      continue;
    }
    if (/^\d+[.)]\s+/.test(line)) {
      const items = [];
      while (i < lines.length && /^\s*\d+[.)]\s+/.test(lines[i])) {
        items.push(lines[i].trim().replace(/^\d+[.)]\s+/, '')); i += 1;
      }
      blocks.push(<ol key={`ol-${i}`} className="list-decimal space-y-1 pl-5">{items.map((item, index) => <li key={index}>{inline(item, `ol-${i}-${index}`)}</li>)}</ol>);
      continue;
    }
    blocks.push(<p key={`p-${i}`}>{inline(line, `p-${i}`)}</p>);
    i += 1;
  }
  return <div className="assistant-answer space-y-2 break-words">{blocks}</div>;
}
