document.addEventListener('DOMContentLoaded', () => {
  // Navbar dropdown reuse (same behavior as app.js)
  const toggle = document.getElementById('userMenuToggle');
  const dropdown = document.getElementById('userDropdown');
  if (toggle && dropdown) {
    toggle.addEventListener('click', (e) => { e.preventDefault(); dropdown.classList.toggle('open'); });
    document.addEventListener('click', (e) => { if (!dropdown.contains(e.target) && !toggle.contains(e.target)) dropdown.classList.remove('open'); });
  }

  function formatBRL(cents) { return (cents / 100).toLocaleString('pt-BR', { minimumFractionDigits: 2, maximumFractionDigits: 2 }); }
  function updateBalanceDisplay(balanceCents) {
    const el = document.getElementById('balanceDisplay');
    if (el && typeof balanceCents === 'number') el.textContent = `Saldo: R$ ${formatBRL(balanceCents)}`;
  }

  const canvas = document.getElementById('crashCanvas');
  const ctx = canvas.getContext('2d');
  const hudMul = document.getElementById('crashHudMultiplier');
  const hudStatus = document.getElementById('crashHudStatus');

  const startForm = document.getElementById('crashStartForm');
  const amountInput = document.getElementById('crashAmount');
  const cashoutBtn = document.getElementById('crashCashoutBtn');
  const resetBtn = document.getElementById('crashResetBtn');

  let crashPoint = 1.0;
  let betId = null;
  let running = false;
  let startTs = 0;
  let animHandle = null;

  function clearCanvas() {
    ctx.clearRect(0, 0, canvas.width, canvas.height);
    // background gradient
    const g = ctx.createLinearGradient(0, 0, 0, canvas.height);
    g.addColorStop(0, '#180b0f');
    g.addColorStop(1, '#0e070a');
    ctx.fillStyle = g;
    ctx.fillRect(0, 0, canvas.width, canvas.height);
    // grid
    ctx.strokeStyle = 'rgba(255,255,255,0.08)';
    ctx.lineWidth = 1;
    for (let x=60; x<canvas.width; x+=60) { ctx.beginPath(); ctx.moveTo(x, 0); ctx.lineTo(x, canvas.height); ctx.stroke(); }
    for (let y=60; y<canvas.height; y+=60) { ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(canvas.width, y); ctx.stroke(); }
  }

  function drawCurve(mul) {
    const T = Math.log(crashPoint); // model duration factor
    const maxMul = Math.max(crashPoint, 2.0);
    const pad = 20;
    const h = canvas.height - pad*2;
    const w = canvas.width - pad*2;
    const yFromMul = (m) => h - (m / maxMul) * h + pad;
    clearCanvas();
    // glow line
    ctx.lineWidth = 3;
    const grad = ctx.createLinearGradient(pad, pad, w, h);
    grad.addColorStop(0, '#ff5a73');
    grad.addColorStop(1, '#b40024');
    ctx.strokeStyle = grad;
    // plot simple exponential curve from 1 to mul
    ctx.beginPath();
    ctx.moveTo(pad, yFromMul(1));
    const steps = 300;
    for (let i=1;i<=steps;i++) {
      const t = i/steps; // normalized
      const m = 1 + t * (mul - 1);
      const x = pad + t * w;
      const y = yFromMul(m);
      ctx.lineTo(x, y);
    }
    ctx.stroke();

    // current multiplier label
    ctx.fillStyle = 'rgba(255,255,255,0.85)';
    ctx.font = 'bold 28px Inter, system-ui, sans-serif';
    ctx.fillText(`${mul.toFixed(2)}x`, pad + 10, yFromMul(mul) - 10);
  }

  function stopAnim() { if (animHandle) cancelAnimationFrame(animHandle); animHandle = null; running = false; cashoutBtn.disabled = true; }

  function startAnim() {
    running = true; startTs = performance.now(); cashoutBtn.disabled = false; hudStatus.textContent = '';
    function step(ts) {
      const elapsed = (ts - startTs) / 1000; // seconds
      const targetDuration = Math.max(2.0, Math.min(9.0, Math.log(crashPoint) * 3));
      const t = Math.min(elapsed / targetDuration, 1);
      const mul = 1 + t * (crashPoint - 1);
      hudMul.textContent = `${mul.toFixed(2)}x`;
      drawCurve(mul);
      if (t >= 1) {
        // Crash
        stopAnim();
        hudStatus.textContent = `Crash em ${crashPoint.toFixed(2)}x`;
        if (betId) {
          fetch('/games/crash/cashout', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ betId, multiplier: crashPoint }) })
            .then(r=>r.json()).then(j=>{ updateBalanceDisplay(j.balance_cents); }).catch(()=>{});
        }
      } else { animHandle = requestAnimationFrame(step); }
    }
    animHandle = requestAnimationFrame(step);
  }

  if (startForm) {
    startForm.addEventListener('submit', (e) => {
      e.preventDefault(); hudStatus.textContent = ''; hudMul.textContent = '1.00x';
      const amount = amountInput.value;
      fetch('/games/crash/start', { method:'POST', headers:{'Content-Type':'application/json'}, credentials:'same-origin', body: JSON.stringify({ amount }) })
        .then(r=>r.json()).then(j=>{
          if (j.error) { hudStatus.textContent = 'Erro: ' + j.error; return; }
          betId = j.betId; crashPoint = j.crashPoint; updateBalanceDisplay(j.balance_cents);
          startForm.style.display = 'none';
          startAnim();
        }).catch(()=>{ hudStatus.textContent = 'Falha ao iniciar'; });
    });
  }

  if (cashoutBtn) {
    cashoutBtn.addEventListener('click', () => {
      if (!running || !betId) return;
      const currentMul = parseFloat(hudMul.textContent.replace('x','')) || 1.0;
      fetch('/games/crash/cashout', { method:'POST', headers:{'Content-Type':'application/json'}, credentials:'same-origin', body: JSON.stringify({ betId, multiplier: currentMul }) })
        .then(r=>r.json()).then(j=>{
          stopAnim();
          if (j.result === 'win') hudStatus.textContent = `Cashout! R$ ${formatBRL(j.payout_cents)}`; else hudStatus.textContent = `Crash em ${j.crashPoint.toFixed(2)}x`;
          updateBalanceDisplay(j.balance_cents);
        }).catch(()=>{});
    });
  }

  if (resetBtn) {
    resetBtn.addEventListener('click', () => {
      stopAnim(); betId = null; crashPoint = 1.0; hudMul.textContent = '1.00x'; hudStatus.textContent=''; startForm.style.display='grid'; clearCanvas(); drawCurve(1.0);
    });
  }

  // First render
  clearCanvas();
  drawCurve(1.0);
});
