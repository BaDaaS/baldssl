// Plain HTML + Tailwind CSS v4, built with Vite. The only build-time logic
// is the plugin below, which renders the command tables from
// src/commands.json into static HTML (no client-side JavaScript).
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import tailwindcss from '@tailwindcss/vite';
import { defineConfig } from 'vite';

const commandsPath = fileURLToPath(
  new URL('./src/commands.json', import.meta.url),
);
const primitivesPath = fileURLToPath(
  new URL('./src/primitives.json', import.meta.url),
);
const examplesPath = fileURLToPath(
  new URL('./src/examples.json', import.meta.url),
);

const escapeHtml = s =>
  s
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;');

// `code` spans in descriptions and notes.
const inline = s =>
  escapeHtml(s).replace(
    /`([^`]+)`/g,
    '<code class="font-mono text-foreground">$1</code>',
  );

// Status badge: one definition, used for every row.
const STATUS = {
  supported: ['Supported', 'bg-success-subtle text-success'],
  partial: ['Partial', 'bg-warning-subtle text-warning'],
  planned: ['Planned', 'bg-info-subtle text-info'],
  'not-started': ['Not yet', 'bg-muted-subtle text-muted'],
};

const badge = status => {
  const [label, colors] = STATUS[status];
  return `<span class="inline-flex rounded-md px-2 py-0.5 text-xs font-medium whitespace-nowrap ${colors}">${label}</span>`;
};

const availability = versions =>
  versions.length === 2
    ? '<span class="text-muted">3.5, 4.1</span>'
    : `<span class="font-medium text-foreground">${versions[0]} only</span>`;

// On small screens the OpenSSL and Notes columns fold into a line under the
// description, so the status column stays visible without scrolling.
const standardRows = commands =>
  commands
    .map(
      c => `<tr class="border-t border-border align-top">
  <td class="py-3 pr-3 font-mono text-sm font-medium whitespace-nowrap text-foreground">${escapeHtml(c.name)}</td>
  <td class="py-3 pr-3 text-sm text-muted">${inline(c.description)}<span class="mt-1 block text-xs sm:hidden">OpenSSL ${availability(c.openssl)}${c.note ? `. ${inline(c.note)}` : ''}</span></td>
  <td class="hidden py-3 pr-4 text-sm whitespace-nowrap sm:table-cell">${availability(c.openssl)}</td>
  <td class="py-3 pr-3">${badge(c.status)}</td>
  <td class="hidden py-3 text-sm text-muted sm:table-cell">${inline(c.note)}</td>
</tr>`,
    )
    .join('\n');

const shortcutRows = commands =>
  commands
    .map(
      c => `<tr class="border-t border-border">
  <td class="py-2 pr-4 font-mono text-sm text-foreground">${escapeHtml(c.name)}</td>
  <td class="py-2 pr-4 text-sm text-muted">${inline(c.description)}</td>
  <td class="py-2">${badge(c.status)}</td>
</tr>`,
    )
    .join('\n');

// The program name `openssl`, where the shell runs it; the baldssl variant of
// a task replaces it (scripts/check-website-examples.py runs both).
const PROGRAM = /(?<![\w./-])openssl(?= )/g;

// A command block: a header with the copy button (shown by src/copy.js), and
// the command exactly as CI runs it, one displayed line per entry of `lines`.
// With `tools`, the block holds one <code> per tool, for the toggle.
const codeBlock = (lines, tools = null) => {
  const text = lines.join('\n');
  const codes = tools
    ? tools
        .map(
          (tool, i) =>
            `<code data-tool="${tool}"${i > 0 ? ' hidden' : ''}>${escapeHtml(
              tool === 'baldssl' ? text.replace(PROGRAM, 'baldssl') : text,
            )}</code>`,
        )
        .join('')
    : `<code>${escapeHtml(text)}</code>`;
  return `<div class="min-w-0 overflow-hidden rounded-lg border border-border bg-background">
  <div class="flex items-center justify-between border-b border-border px-3 py-1.5">
    <span class="font-mono text-xs text-muted">bash</span>
    <button type="button" data-copy hidden class="rounded-md px-2 py-0.5 text-xs font-medium text-muted transition-colors duration-200 hover:text-foreground focus-visible:ring-2 focus-visible:ring-focus focus-visible:outline-none">Copy</button>
  </div>
  <pre class="overflow-x-auto px-3 py-3 font-mono text-xs leading-relaxed text-foreground sm:px-4 sm:text-sm">${codes}</pre>
</div>`;
};

const TASK_STATUS = {
  supported: ['baldssl: supported', 'bg-success-subtle text-success'],
  'not-yet': ['baldssl: not yet', 'bg-muted-subtle text-muted'],
};

const taskCard = ex => {
  const [label, colors] = TASK_STATUS[ex.status];
  return `<article class="flex min-w-0 flex-col rounded-lg border border-border bg-surface p-4 sm:p-6">
  <div class="flex items-start justify-between gap-3">
    <h3 class="font-semibold">${escapeHtml(ex.title)}</h3>
    <span class="inline-flex shrink-0 rounded-md px-2 py-0.5 text-xs font-medium whitespace-nowrap ${colors}">${label}</span>
  </div>
  <p class="mt-2 text-sm text-muted">${inline(ex.explanation)}</p>
  <div class="mt-4">${codeBlock(ex.lines, ['openssl', 'baldssl'])}</div>
</article>`;
};

// The openssl / baldssl switch of the Common tasks section (src/copy.js).
const toolToggle = `<div role="group" aria-label="Show the commands for" data-tool-toggle hidden class="inline-flex shrink-0 rounded-lg border border-border bg-surface p-0.5 text-sm font-medium">
  ${['openssl', 'baldssl']
    .map(
      (tool, i) =>
        `<button type="button" data-tool-choice="${tool}" aria-pressed="${i === 0}" class="rounded-md px-3 py-1 font-mono text-muted transition-colors duration-200 hover:text-foreground focus-visible:ring-2 focus-visible:ring-focus focus-visible:outline-none aria-pressed:bg-primary aria-pressed:text-on-primary">${tool}</button>`,
    )
    .join('')}
</div>`;

function examples() {
  return {
    name: 'baldssl-examples',
    configureServer(server) {
      server.watcher.add(examplesPath);
    },
    transformIndexHtml(html) {
      const list = JSON.parse(readFileSync(examplesPath, 'utf8')).examples;
      let out = html.replace('<!-- tasks:toggle -->', toolToggle).replace(
        '<!-- tasks -->',
        list
          .filter(e => e.section === 'tasks')
          .map(taskCard)
          .join('\n'),
      );
      for (const ex of list) {
        out = out.replaceAll(`<!-- example:${ex.id} -->`, codeBlock(ex.lines));
      }
      const left = out.match(/<!-- (example:[\w-]+|tasks[\w:-]*) -->/);
      if (left) {
        throw new Error(`unknown example placeholder ${left[0]}`);
      }
      return out;
    },
  };
}

const PRIMITIVE_STATUS = {
  implemented: ['Implemented', 'bg-success-subtle text-success'],
  'in-progress': ['In progress', 'bg-warning-subtle text-warning'],
  planned: ['Planned', 'bg-info-subtle text-info'],
};

// The "Building blocks" table, from src/primitives.json.
function primitives() {
  return {
    name: 'baldssl-primitives',
    configureServer(server) {
      server.watcher.add(primitivesPath);
    },
    transformIndexHtml(html) {
      const list = JSON.parse(readFileSync(primitivesPath, 'utf8')).primitives;
      const rows = list
        .map(p => {
          const [label, colors] = PRIMITIVE_STATUS[p.status];
          const link = p.link
            ? `<a href="${escapeHtml(p.link)}" class="mt-1 inline-block rounded-md text-xs font-medium text-primary hover:underline focus-visible:ring-2 focus-visible:ring-focus focus-visible:outline-none">Pull request ${escapeHtml(p.link.split('/').pop())}</a>`
            : '';
          return `<tr class="border-t border-border align-top">
  <td class="py-3 pr-3 text-sm"><span class="font-medium text-foreground">${escapeHtml(p.name)}</span><span class="mt-1 block text-muted">${inline(p.purpose)}</span>${link}</td>
  <td class="py-3"><span class="inline-flex rounded-md px-2 py-0.5 text-xs font-medium whitespace-nowrap ${colors}">${label}</span></td>
</tr>`;
        })
        .join('\n');
      return html.replace('<!-- primitives -->', rows);
    },
  };
}

function commandTables() {
  return {
    name: 'baldssl-command-tables',
    configureServer(server) {
      server.watcher.add(commandsPath);
    },
    transformIndexHtml(html) {
      const { commands } = JSON.parse(readFileSync(commandsPath, 'utf8'));
      const of = kind => commands.filter(c => c.kind === kind);
      const standard = of('standard');
      const count = s => commands.filter(c => c.status === s).length;
      const summary =
        `${commands.length} commands: ${count('supported')} supported, ` +
        `${count('partial')} partial, ${count('planned')} planned, ` +
        `${count('not-started')} not started.`;
      return html
        .replace('<!-- commands:summary -->', escapeHtml(summary))
        .replace('<!-- commands:standard -->', standardRows(standard))
        .replace('<!-- commands:standard-count -->', String(standard.length))
        .replace('<!-- commands:digest -->', shortcutRows(of('digest')))
        .replace('<!-- commands:cipher -->', shortcutRows(of('cipher')));
    },
  };
}

export default defineConfig({
  // Relative URLs: the site is served from /baldssl/ on GitHub Pages.
  base: './',
  plugins: [tailwindcss(), commandTables(), examples(), primitives()],
});
