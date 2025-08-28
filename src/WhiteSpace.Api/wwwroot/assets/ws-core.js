(function(){
  const store = window.localStorage;
  function apiBase() {
    const saved = store.getItem('API_BASE');
    return (saved && saved.trim()) ? saved.trim().replace(/\/+$/,'') : location.origin;
  }
  function token(){ return store.getItem('TOKEN') || ''; }
  function setToken(t){ t ? store.setItem('TOKEN', t) : store.removeItem('TOKEN'); }
  function setApiBase(v){ v ? store.setItem('API_BASE', v) : store.removeItem('API_BASE'); }

  async function call(path, opts={}) {
    const base = apiBase();
    a = base + (path.startsWith('/') ? path : '/'+path);
    const url = a;
    const method = (opts.method || 'GET').toUpperCase();
    const headers = new Headers(opts.headers || {});
    if (opts.body && !(opts.body instanceof FormData) && method !== 'GET' && method !== 'HEAD') {
      headers.set('Content-Type', 'application/json');
    }
    headers.set('Accept', 'application/json');
    if (opts.auth && token()) headers.set('Authorization','Bearer '+token());
    const resp = await fetch(url, { ...opts, method, headers });
    const text = await resp.text();
    let json = null; try { json = JSON.parse(text); } catch {}
    if (!resp.ok) {
      const err = new Error(`HTTP ${resp.status}`);
      err.status = resp.status; err.body = text; err.json = json;
      throw err;
    }
    return json ?? text;
  }

  async function register({username, email, password}) {
    const res = await call('/auth/register', { method:'POST', body: JSON.stringify({ username, email, password }) });
    if (res && res.token) setToken(res.token);
    return res;
  }
  async function login({usernameOrEmail, password}) {
    const res = await call('/auth/login', { method:'POST', body: JSON.stringify({ usernameOrEmail, password }) });
    if (res && res.token) setToken(res.token);
    return res;
  }
  function logout(){ setToken(null); }

  async function createPost({ body }) {
    return await call('/posts', { method:'POST', auth:true, body: JSON.stringify({ body }) });
  }
  async function getFeed({ skip=0, take=10 }={}) {
    return await call(`/feed?skip=${skip}&take=${take}`, { method:'GET' });
  }

  async function createChannel({ name, isPrivate }) {
    return await call('/channels', { method:'POST', auth:true, body: JSON.stringify({ name, isPrivate: !!isPrivate }) });
  }
  async function joinChannel({ code }) {
    return await call('/channels/join', { method:'POST', auth:true, body: JSON.stringify({ code }) });
  }
  async function channelFeed({ id, skip=0, take=10 }) {
    return await call(`/channels/${id}/feed?skip=${skip}&take=${take}`, { method:'GET', auth:true });
  }

  async function me(){ return await call('/me', { method:'GET', auth:true }); }
  async function ping(){ return await call('/version'); }

  window.WS = { apiBase, setApiBase, token, setToken, call, register, login, logout,
                createPost, getFeed, createChannel, joinChannel, channelFeed, me, ping };
})();
