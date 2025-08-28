document.addEventListener('DOMContentLoaded', () => {
  const loginForm = document.querySelector('#loginForm');
  if (loginForm) {
    loginForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const f = e.currentTarget;
      const u = (f.querySelector('[name="usernameOrEmail"]') || {}).value || '';
      const p = (f.querySelector('[name="password"]') || {}).value || '';
      try {
        await WS.login({ usernameOrEmail: u.trim(), password: p });
        toast('Logged in'); setTimeout(()=>location.href='/', 300);
      } catch(err){ showErr(err); }
    });
  }

  const regForm = document.querySelector('#registerForm');
  if (regForm) {
    regForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const f = e.currentTarget;
      const u = (f.querySelector('[name="username"]') || {}).value || '';
      const em = (f.querySelector('[name="email"]') || {}).value || '';
      const p = (f.querySelector('[name="password"]') || {}).value || '';
      try {
        await WS.register({ username: u.trim(), email: em.trim(), password: p });
        toast('Registered & logged in'); setTimeout(()=>location.href='/', 300);
      } catch(err){ showErr(err); }
    });
  }

  const postForm = document.querySelector('#postForm');
  const feedList = document.querySelector('#feedList');
  if (postForm) {
    postForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const f = e.currentTarget;
      const body = (f.querySelector('[name="body"]') || {}).value || '';
      try {
        await WS.createPost({ body });
        toast('Posted'); f.reset();
        if (feedList) loadFeed();
      } catch(err){ showErr(err); }
    });
  }
  if (feedList) loadFeed();
  async function loadFeed(){
    try {
      const items = await WS.getFeed({ skip:0, take:20 });
      feedList.innerHTML = items.map(p => rowPost(p)).join('');
    } catch(err){ showErr(err); }
  }
  function rowPost(p){
    const dt = new Date(p.createdAt).toLocaleString();
    return `<div class="post">
      <div class="post-head"><b>${escapeHtml(p.author)}</b> <span class="muted">${dt}</span></div>
      <div class="post-body">${escapeHtml(p.body)}</div>
    </div>`;
  }

  const chCreate = document.querySelector('#channelCreateForm');
  if (chCreate) {
    chCreate.addEventListener('submit', async (e) => {
      e.preventDefault();
      const f = e.currentTarget;
      const name = (f.querySelector('[name="name"]') || {}).value || '';
      const isPrivate = !!(f.querySelector('[name="isPrivate"]') || {}).checked;
      try {
        const res = await WS.createChannel({ name, isPrivate });
        toast(`Channel created: ${res.name}${res.code? ' (code '+res.code+')':''}`);
      } catch(err){ showErr(err); }
    });
  }
  const chJoin = document.querySelector('#joinChannelForm');
  if (chJoin) {
    chJoin.addEventListener('submit', async (e) => {
      e.preventDefault();
      const f = e.currentTarget;
      const code = (f.querySelector('[name="code"]') || {}).value || '';
      try { await WS.joinChannel({ code }); toast('Joined'); } catch(err){ showErr(err); }
    });
  }
  const chFeedForm = document.querySelector('#channelFeedForm');
  const chFeedList = document.querySelector('#channelFeed');
  if (chFeedForm && chFeedList) {
    chFeedForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const id = (chFeedForm.querySelector('[name="channelId"]') || {}).value || '';
      try {
        const items = await WS.channelFeed({ id, skip:0, take:20 });
        chFeedList.innerHTML = items.map(p => rowPost(p)).join('');
      } catch(err){ showErr(err); }
    });
  }

  const mePanel = document.querySelector('#mePanel');
  if (mePanel) {
    WS.me().then(me => {
      mePanel.textContent = me?.username || '(unknown)';
    }).catch(()=>{ mePanel.textContent='(not logged)'; });
  }

  const logoutBtn = document.querySelector('#logoutBtn');
  if (logoutBtn) logoutBtn.addEventListener('click', () => { WS.logout(); toast('Logged out'); });

  function escapeHtml(s){ return (s||'').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }
  function toast(msg){
    let el = document.getElementById('ws-toast');
    if (!el) { el = document.createElement('div'); el.id='ws-toast';
      el.style.cssText='position:fixed;right:16px;bottom:16px;background:#111;color:#fff;padding:10px 12px;border-radius:10px;z-index:9999';
      document.body.appendChild(el);
    }
    el.textContent = msg; el.style.opacity='1';
    setTimeout(()=>{ el.style.opacity='0'; }, 1200);
  }
  function showErr(err){
    const msg = (err && err.json && err.json.message) ? err.json.message
              : (err && err.body) ? err.body
              : (err && err.message) ? err.message
              : String(err);
    console.error('[WS]', err);
    toast('Error: ' + msg);
  }
});
