// Copy buttons and the openssl / baldssl toggle. Without JavaScript the page
// shows the openssl commands and no buttons.
const STORAGE_KEY = 'baldssl-tool';

const visibleCode = block => block.querySelector('code:not([hidden])');

for (const button of document.querySelectorAll('[data-copy]')) {
  button.hidden = false;
  button.addEventListener('click', async () => {
    const block = button.closest('div').parentElement;
    await navigator.clipboard.writeText(visibleCode(block).textContent);
    button.textContent = 'Copied';
    setTimeout(() => {
      button.textContent = 'Copy';
    }, 1500);
  });
}

const showTool = tool => {
  for (const code of document.querySelectorAll('code[data-tool]')) {
    code.hidden = code.dataset.tool !== tool;
  }
  for (const choice of document.querySelectorAll('[data-tool-choice]')) {
    choice.setAttribute(
      'aria-pressed',
      String(choice.dataset.toolChoice === tool),
    );
  }
};

const toggle = document.querySelector('[data-tool-toggle]');
if (toggle) {
  toggle.hidden = false;
  for (const choice of toggle.querySelectorAll('[data-tool-choice]')) {
    choice.addEventListener('click', () => {
      const tool = choice.dataset.toolChoice;
      showTool(tool);
      try {
        localStorage.setItem(STORAGE_KEY, tool);
      } catch {
        // Storage may be unavailable (private mode); the choice still applies.
      }
    });
  }
  try {
    const saved = localStorage.getItem(STORAGE_KEY);
    if (saved === 'openssl' || saved === 'baldssl') {
      showTool(saved);
    }
  } catch {
    // Keep the default, openssl.
  }
}
