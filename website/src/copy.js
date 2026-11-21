// Copy buttons for the code blocks: copies the command exactly as shown.
for (const button of document.querySelectorAll('[data-copy]')) {
  button.hidden = false;
  button.addEventListener('click', async () => {
    const code = button.parentElement.querySelector('code');
    await navigator.clipboard.writeText(code.textContent);
    button.textContent = 'Copied';
    setTimeout(() => {
      button.textContent = 'Copy';
    }, 1500);
  });
}
