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

const standardRows = commands =>
  commands
    .map(
      c => `<tr class="border-t border-border align-top">
  <td class="py-3 pr-4 font-mono text-sm font-medium whitespace-nowrap text-foreground">${escapeHtml(c.name)}</td>
  <td class="py-3 pr-4 text-sm text-muted">${inline(c.description)}</td>
  <td class="py-3 pr-4 text-sm whitespace-nowrap">${availability(c.openssl)}</td>
  <td class="py-3 pr-4">${badge(c.status)}</td>
  <td class="py-3 text-sm text-muted">${inline(c.note)}</td>
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

// A command, verbatim, with a copy button (shown by src/copy.js). Every
// command passed here comes from src/examples.json, which CI executes.
const codeBlock = command => `<div class="relative">
  <pre class="overflow-x-auto rounded-lg border border-border bg-background p-4 pr-20 font-mono text-sm text-foreground"><code>${escapeHtml(command)}</code></pre>
  <button type="button" data-copy hidden class="absolute top-2 right-2 rounded-md border border-border bg-surface px-2 py-1 text-xs font-medium text-muted transition-colors duration-200 hover:text-foreground focus-visible:ring-2 focus-visible:ring-focus focus-visible:outline-none">Copy</button>
</div>`;

const TASK_STATUS = {
  supported: ['baldssl: supported', 'bg-success-subtle text-success'],
  'not-yet': ['baldssl: not yet', 'bg-muted-subtle text-muted'],
};

const taskCard = ex => {
  const [label, colors] = TASK_STATUS[ex.status];
  return `<article class="flex flex-col rounded-lg border border-border bg-surface p-6">
  <div class="flex items-start justify-between gap-4">
    <h3 class="font-semibold">${escapeHtml(ex.title)}</h3>
    <span class="inline-flex shrink-0 rounded-md px-2 py-0.5 text-xs font-medium whitespace-nowrap ${colors}">${label}</span>
  </div>
  <p class="mt-2 text-sm text-muted">${inline(ex.explanation)}</p>
  <div class="mt-4">${codeBlock(ex.command)}</div>
</article>`;
};

function examples() {
  return {
    name: 'baldssl-examples',
    configureServer(server) {
      server.watcher.add(examplesPath);
    },
    transformIndexHtml(html) {
      const list = JSON.parse(readFileSync(examplesPath, 'utf8')).examples;
      let out = html.replace(
        '<!-- tasks -->',
        list
          .filter(e => e.section === 'tasks')
          .map(taskCard)
          .join('\n'),
      );
      for (const ex of list) {
        out = out.replaceAll(
          `<!-- example:${ex.id} -->`,
          codeBlock(ex.command),
        );
      }
      const left = out.match(/<!-- (example:[\w-]+|tasks) -->/);
      if (left) {
        throw new Error(`unknown example placeholder ${left[0]}`);
      }
      return out;
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
  plugins: [tailwindcss(), commandTables(), examples()],
});
