// Service worker de Flash : reçoit les notifications push, même appli fermée
self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', e => e.waitUntil(self.clients.claim()));

self.addEventListener('push', e => {
  let d = {};
  try { d = e.data ? e.data.json() : {}; } catch { d = { title: 'Flash', body: e.data ? e.data.text() : 'Nouveau message' }; }
  e.waitUntil((async () => {
    await self.registration.showNotification(d.title || 'Flash', {
      body: d.body || 'Nouveau message',
      icon: 'icon.png', badge: 'icon.png',
      tag: d.chatId || 'flash', renotify: true,
      data: { chatId: d.chatId || '' }
    });
    try { if (self.navigator.setAppBadge) { const n = await self.registration.getNotifications(); self.navigator.setAppBadge(n.length); } } catch {}
  })());
});

self.addEventListener('notificationclick', e => {
  e.notification.close();
  const chatId = (e.notification.data && e.notification.data.chatId) || '';
  e.waitUntil((async () => {
    const wins = await self.clients.matchAll({ type: 'window', includeUncontrolled: true });
    for (const w of wins) { try { await w.focus(); } catch {} w.postMessage({ type: 'open-chat', chatId }); return; }
    await self.clients.openWindow('./' + (chatId ? '?chat=' + encodeURIComponent(chatId) : ''));
  })());
});
