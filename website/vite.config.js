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
  plugins: [tailwindcss(), commandTables()],
});
