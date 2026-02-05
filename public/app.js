document.addEventListener('DOMContentLoaded', () => {
  // Máscara CPF
  const cpfInputs = [
    document.querySelector('input[name="cpf"]'),
    document.querySelector('#cpfLogin')
  ].filter(Boolean);

  cpfInputs.forEach((input) => {
    input.addEventListener('input', (e) => {
      let v = e.target.value.replace(/\D/g, '').slice(0, 11);
      let r = '';
      if (v.length > 0) r = v.slice(0, 3);
      if (v.length >= 4) r = v.slice(0, 3) + '.' + v.slice(3, 6);
      if (v.length >= 7) r = v.slice(0, 3) + '.' + v.slice(3, 6) + '.' + v.slice(6, 9);
      if (v.length >= 10) r = v.slice(0, 3) + '.' + v.slice(3, 6) + '.' + v.slice(6, 9) + '-' + v.slice(9, 11);
      e.target.value = r;
    });
  });

  // Validação imediata da DOB
  const dobInput = document.querySelector('#dob');
  const dobMsg = document.querySelector('#dobMsg');
  if (dobInput && dobMsg) {
    const max = new Date(dobInput.max);
    function validate() {
      const val = new Date(dobInput.value);
      if (!dobInput.value) { dobMsg.textContent = ''; return; }
      if (isNaN(val.getTime())) { dobMsg.textContent = 'Data inválida.'; return; }
      if (val > max) {
        dobMsg.textContent = 'Você deve ser maior de idade.';
        dobMsg.style.color = '#ffb3b3';
      } else {
        dobMsg.textContent = 'OK';
        dobMsg.style.color = '#9ee09e';
      }
    }
    dobInput.addEventListener('input', validate);
    validate();
  }

  // Navbar: dropdown do usuário
  const toggle = document.getElementById('userMenuToggle');
  const dropdown = document.getElementById('userDropdown');
  if (toggle && dropdown) {
    toggle.addEventListener('click', (e) => {
      e.preventDefault();
      dropdown.classList.toggle('open');
    });
    document.addEventListener('click', (e) => {
      if (!dropdown.contains(e.target) && !toggle.contains(e.target)) {
        dropdown.classList.remove('open');
      }
    });
  }

  // Modal de configurações
  const openSettings = document.getElementById('openSettings');
  const modal = document.getElementById('settingsModal');
  const closeSettings = document.getElementById('closeSettings');
  const closeSettingsBtn = document.getElementById('closeSettingsBtn');
  function setModal(open) {
    if (!modal) return;
    modal.setAttribute('aria-hidden', open ? 'false' : 'true');
    modal.classList.toggle('open', open);
  }
  if (openSettings) openSettings.addEventListener('click', (e) => { e.preventDefault(); setModal(true); });
  if (closeSettings) closeSettings.addEventListener('click', () => setModal(false));
  if (closeSettingsBtn) closeSettingsBtn.addEventListener('click', () => setModal(false));
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') setModal(false);
  });

  // Modal de confirmação de exclusão de conta
  const openDeleteConfirm = document.getElementById('openDeleteConfirm');
  const deleteConfirmModal = document.getElementById('deleteConfirmModal');
  const closeDeleteConfirm = document.getElementById('closeDeleteConfirm');
  const closeDeleteConfirmBtn = document.getElementById('closeDeleteConfirmBtn');
  const cancelDeleteBtn = document.getElementById('cancelDeleteBtn');
  const confirmDeleteBtn = document.getElementById('confirmDeleteBtn');
  const deleteAccountForm = document.getElementById('deleteAccountForm');

  function setDeleteModal(open) {
    if (!deleteConfirmModal) return;
    deleteConfirmModal.setAttribute('aria-hidden', open ? 'false' : 'true');
    deleteConfirmModal.classList.toggle('open', open);
  }
  if (openDeleteConfirm) openDeleteConfirm.addEventListener('click', () => setDeleteModal(true));
  if (closeDeleteConfirm) closeDeleteConfirm.addEventListener('click', () => setDeleteModal(false));
  if (closeDeleteConfirmBtn) closeDeleteConfirmBtn.addEventListener('click', () => setDeleteModal(false));
  if (cancelDeleteBtn) cancelDeleteBtn.addEventListener('click', () => setDeleteModal(false));
  if (confirmDeleteBtn && deleteAccountForm) {
    confirmDeleteBtn.addEventListener('click', () => {
      // Envia o form somente após confirmação explícita
      deleteAccountForm.submit();
    });
  }

  // Modal de Depósito
  const openDepositModal = document.getElementById('openDepositModal');
  const depositModal = document.getElementById('depositModal');
  const closeDepositModal = document.getElementById('closeDepositModal');
  const closeDepositModalBtn = document.getElementById('closeDepositModalBtn');
  function setDepositModal(open) {
    if (!depositModal) return;
    depositModal.setAttribute('aria-hidden', open ? 'false' : 'true');
    depositModal.classList.toggle('open', open);
  }
  if (openDepositModal) openDepositModal.addEventListener('click', (e) => { e.preventDefault(); setDepositModal(true); });
  if (closeDepositModal) closeDepositModal.addEventListener('click', () => setDepositModal(false));
  if (closeDepositModalBtn) closeDepositModalBtn.addEventListener('click', () => setDepositModal(false));
  // Autoabrir depósito quando houver pendente recém-criado
  const depositPendingFlag = document.getElementById('depositPendingFlag');
  if (depositPendingFlag) {
    setDepositModal(true);
  }

  // Modais de Termos e Política (registro)
  const openTerms = document.getElementById('openTerms');
  const openPrivacy = document.getElementById('openPrivacy');
  const termsModal = document.getElementById('termsModal');
  const privacyModal = document.getElementById('privacyModal');
  const closeTerms = document.getElementById('closeTerms');
  const closeTermsBtn = document.getElementById('closeTermsBtn');
  const closePrivacy = document.getElementById('closePrivacy');
  const closePrivacyBtn = document.getElementById('closePrivacyBtn');

  function toggleModal(el, open) {
    if (!el) return;
    el.setAttribute('aria-hidden', open ? 'false' : 'true');
    el.classList.toggle('open', open);
  }
  if (openTerms) openTerms.addEventListener('click', (e) => { e.preventDefault(); e.stopPropagation(); toggleModal(termsModal, true); });
  if (openPrivacy) openPrivacy.addEventListener('click', (e) => { e.preventDefault(); e.stopPropagation(); toggleModal(privacyModal, true); });
  if (closeTerms) closeTerms.addEventListener('click', () => toggleModal(termsModal, false));
  if (closeTermsBtn) closeTermsBtn.addEventListener('click', () => toggleModal(termsModal, false));
  if (closePrivacy) closePrivacy.addEventListener('click', () => toggleModal(privacyModal, false));
  if (closePrivacyBtn) closePrivacyBtn.addEventListener('click', () => toggleModal(privacyModal, false));

  // Admin: auto-submit do seletor de usuário (sem inline handler)
  const adminPickerForm = document.getElementById('adminPickerForm');
  const userSelect = document.getElementById('userId');
  if (adminPickerForm && userSelect) {
    userSelect.addEventListener('change', () => {
      adminPickerForm.submit();
    });
  }

  // Admin: confirmação de exclusão (substitui onclick inline bloqueado pelo CSP)
  const deleteUserForms = Array.from(document.querySelectorAll('form[action="/admin/delete-user"]'));
  deleteUserForms.forEach((f) => {
    f.addEventListener('submit', (e) => {
      const ok = confirm('Excluir usuário? Esta ação é irreversível.');
      if (!ok) e.preventDefault();
    });
  });

  // Pix: copiar código copia-e-cola
  const copyBtn = document.getElementById('copyPixCode');
  const pixCodeInput = document.getElementById('pixCode');
  if (copyBtn && pixCodeInput) {
    copyBtn.addEventListener('click', async () => {
      try {
        pixCodeInput.select();
        document.execCommand('copy');
        copyBtn.textContent = 'Copiado!';
        setTimeout(() => (copyBtn.textContent = 'Copiar código'), 1500);
      } catch (e) {
        // Fallback
        navigator.clipboard.writeText(pixCodeInput.value).then(() => {
          copyBtn.textContent = 'Copiado!';
          setTimeout(() => (copyBtn.textContent = 'Copiar código'), 1500);
        });
      }
    });
  }

  // ---------- Jogos ----------
  function formatBRL(cents) {
    return (cents / 100).toLocaleString('pt-BR', { minimumFractionDigits: 2, maximumFractionDigits: 2 });
  }
  function updateBalanceDisplay(balanceCents) {
    const el = document.getElementById('balanceDisplay');
    if (el && typeof balanceCents === 'number') {
      el.textContent = `Saldo: R$ ${formatBRL(balanceCents)}`;
    }
  }

  // Crash: redirecionar para página dedicada
  const openCrashModal = document.getElementById('openCrashModal');
  if (openCrashModal) {
    openCrashModal.addEventListener('click', (e) => { e.preventDefault(); window.location.href = '/games/crash'; });
  }

  // Mines modal controls
  const openMinesModal = document.getElementById('openMinesModal');
  const minesModal = document.getElementById('minesModal');
  const closeMines = document.getElementById('closeMines');
  const closeMinesBtn = document.getElementById('closeMinesBtn');
  function toggleMines(open) { if (!minesModal) return; minesModal.setAttribute('aria-hidden', open ? 'false' : 'true'); minesModal.classList.toggle('open', open); }
  if (openMinesModal) openMinesModal.addEventListener('click', () => toggleMines(true));
  if (closeMines) closeMines.addEventListener('click', () => toggleMines(false));
  if (closeMinesBtn) closeMinesBtn.addEventListener('click', () => toggleMines(false));

  const minesStartForm = document.getElementById('minesStartForm');
  const minesGame = document.getElementById('minesGame');
  const minesGrid = document.getElementById('minesGrid');
  const minesCashoutBtn = document.getElementById('minesCashoutBtn');
  const minesResetBtn = document.getElementById('minesResetBtn');
  const minesInfo = document.getElementById('minesInfo');
  let minesBetId = null, minesMultiplier = 1.0;

  function buildMinesGrid() {
    minesGrid.innerHTML = '';
    for (let i=0;i<36;i++) {
      const btn = document.createElement('button');
      btn.textContent = '';
      btn.style.width='42px'; btn.style.height='42px';
      btn.addEventListener('click', () => {
        if (!minesBetId) return;
        fetch('/games/mines/reveal', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ betId: minesBetId, index: i }) })
          .then(r=>r.json()).then(j=>{
            if (j.already) return;
            if (j.boom) { btn.textContent='💣'; btn.classList.add('danger'); minesInfo.textContent = 'Explodiu!'; minesBetId = null; }
            else { btn.textContent='✔'; minesMultiplier = j.potentialMultiplier; minesInfo.textContent = `Multiplicador: ${minesMultiplier.toFixed(2)}x`; }
          }).catch(()=>{});
      });
      minesGrid.appendChild(btn);
    }
  }

  if (minesStartForm) {
    minesStartForm.addEventListener('submit', (e) => {
      e.preventDefault();
      const amount = document.getElementById('minesAmount').value;
      const bombs = parseInt(document.getElementById('minesBombs').value,10);
      fetch('/games/mines/start', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ amount, bombs }) })
        .then(r=>r.json()).then(j=>{
          if (j.error) { minesInfo.textContent = 'Erro: ' + j.error; return; }
          minesBetId = j.betId; updateBalanceDisplay(j.balance_cents);
          minesStartForm.style.display='none'; minesGame.style.display='block'; minesInfo.textContent='Abra casas seguras para aumentar o multiplicador.'; minesMultiplier = 1.0; buildMinesGrid();
        }).catch(()=>{ minesInfo.textContent='Falha ao iniciar'; });
    });
  }
  if (minesCashoutBtn) {
    minesCashoutBtn.addEventListener('click', ()=>{
      if (!minesBetId) return;
      fetch('/games/mines/cashout', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ betId: minesBetId }) })
        .then(r=>r.json()).then(j=>{ if (j.result==='win') { minesInfo.textContent = `Recebido R$ ${formatBRL(j.payout_cents)} (mult ${minesMultiplier.toFixed(2)}x)`; updateBalanceDisplay(j.balance_cents); } minesBetId=null; })
        .catch(()=>{});
    });
  }
  if (minesResetBtn) { minesResetBtn.addEventListener('click', ()=>{ minesBetId=null; minesGame.style.display='none'; minesStartForm.style.display='grid'; minesInfo.textContent=''; minesGrid.innerHTML=''; }); }

  // Slots modal
  const openSlotsModal = document.getElementById('openSlotsModal');
  const slotsModal = document.getElementById('slotsModal');
  const closeSlots = document.getElementById('closeSlots');
  const closeSlotsBtn = document.getElementById('closeSlotsBtn');
  function toggleSlots(open) { if (!slotsModal) return; slotsModal.setAttribute('aria-hidden', open ? 'false' : 'true'); slotsModal.classList.toggle('open', open); }
  if (openSlotsModal) openSlotsModal.addEventListener('click', () => toggleSlots(true));
  if (closeSlots) closeSlots.addEventListener('click', () => toggleSlots(false));
  if (closeSlotsBtn) closeSlotsBtn.addEventListener('click', () => toggleSlots(false));

  const slotsForm = document.getElementById('slotsForm');
  const slot1 = document.getElementById('slot1');
  const slot2 = document.getElementById('slot2');
  const slot3 = document.getElementById('slot3');
  const slotsResult = document.getElementById('slotsResult');
  if (slotsForm) {
    slotsForm.addEventListener('submit', (e)=>{
      e.preventDefault(); slotsResult.textContent='';
      const amount = document.getElementById('slotsAmount').value;
      fetch('/games/slots/spin', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ amount }) })
        .then(r=>r.json()).then(j=>{
          slot1.textContent = j.n1; slot2.textContent = j.n2; slot3.textContent = j.n3;
          if (j.result==='win') { slotsResult.textContent = `Você ganhou R$ ${formatBRL(j.payout_cents)}!`; }
          else { slotsResult.textContent = 'Sem combinação. Tente novamente.'; }
          updateBalanceDisplay(j.balance_cents);
        }).catch(()=>{ slotsResult.textContent='Falha ao girar'; });
    });
  }

  // ===== Sidebar (Início/Dashboard)
  const sidebar = document.getElementById('sidebar');
  const toggleBtn = document.getElementById('sidebarToggle');
  const closeBtn = document.getElementById('sidebarClose');
  const overlay = document.getElementById('sidebarOverlay');
  if (sidebar) {
    const open = () => {
      sidebar.classList.add('open');
      if (overlay) overlay.classList.add('visible');
    };
    const close = () => {
      sidebar.classList.remove('open');
      if (overlay) overlay.classList.remove('visible');
    };
    if (toggleBtn) toggleBtn.addEventListener('click', open);
    if (closeBtn) closeBtn.addEventListener('click', close);
    if (overlay) overlay.addEventListener('click', close);
    const nav = sidebar.querySelector('.sidebar-nav');
    if (nav) nav.addEventListener('click', (e) => {
      const a = e.target.closest('a');
      if (a) close();
    });
  }
});
