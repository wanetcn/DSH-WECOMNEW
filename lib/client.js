// Web UI half of dsh-wecom: a status icon in the conversation header actions
// row. Clicking it opens a small panel with the bridge's live status — WeCom
// WebSocket connection, active chats, total historical sessions, message
// counters and pending interactions — polled from the plugin's
// `/api/wecom/status` route (registered by the node half in bridge.js).
//
// Loaded by the dsh client module system (`dsh.client` declaration in
// package.json → served at /plugins/dsh-wecom/client.js → booted via
// window.__DSH_BOOT__). Follows the same shape as the shipped client-ui
// modules: CommonJS factory + exports.inject + exports.apply, registering a
// React component into a named UI slot.

window.__ModuleLoader__.load({
	id: 'dsh-wecom',
	factory: (require) => {
		var module = { exports: {} };
		var exports = module.exports;
		Object.defineProperty(exports, Symbol.toStringTag, { value: 'Module' });
		let react = require('react');

		/** Required service: the UI slot registry. */
		const inject = ['slots'];

		// ------------------------------------------------------------- helpers

		function fmtDuration(totalSec) {
			const sec = Math.max(0, Math.round(totalSec));
			const d = Math.floor(sec / 86400);
			const h = Math.floor((sec % 86400) / 3600);
			const m = Math.floor((sec % 3600) / 60);
			const s = sec % 60;
			if (d > 0) return `${d}天${h}小时`;
			if (h > 0) return `${h}小时${m}分`;
			if (m > 0) return `${m}分${s}秒`;
			return `${s}秒`;
		}

		function fmtTime(ms) {
			if (typeof ms !== 'number' || !Number.isFinite(ms)) return '—';
			return new Date(ms).toLocaleString();
		}

		// -------------------------------------------------------------- styles

		const wrapStyle = { position: 'relative', display: 'inline-flex', alignItems: 'center' };
		const btnStyle = {
			display: 'inline-flex', alignItems: 'center', justifyContent: 'center',
			width: 30, height: 30, padding: 0, borderRadius: 8, border: 'none',
			background: 'transparent', cursor: 'pointer', fontSize: 16, lineHeight: 1
		};
		const panelStyle = {
			position: 'absolute', top: 'calc(100% + 8px)', right: 0, zIndex: 9999,
			width: 280, padding: '12px 14px', borderRadius: 10,
			background: 'var(--dsh-bg, #fff)', color: 'var(--dsh-fg, #1f2328)',
			border: '1px solid rgba(127,127,127,0.25)', boxShadow: '0 8px 24px rgba(0,0,0,0.16)',
			fontSize: 12.5, lineHeight: 1.5, textAlign: 'left'
		};
		const titleStyle = { fontWeight: 600, fontSize: 13, margin: '0 0 8px', display: 'flex', alignItems: 'center', gap: 6 };
		const rowStyle = { display: 'flex', justifyContent: 'space-between', gap: 12, padding: '2px 0' };
		const labelStyle = { opacity: 0.65, whiteSpace: 'nowrap' };
		const valueStyle = { fontWeight: 500, textAlign: 'right' };
		const dotOk = { color: '#1a9e55' };
		const dotBad = { color: '#d3382c' };

		// ----------------------------------------------------------- component

		function StatusRow(label, value) {
			return react.createElement('div', { style: rowStyle, key: label },
				react.createElement('span', { style: labelStyle }, label),
				react.createElement('span', { style: valueStyle }, value)
			);
		}

		function WecomStatusIcon() {
			const [open, setOpen] = react.useState(false);
			const [stats, setStats] = react.useState(null);
			const [error, setError] = react.useState(false);
			const wrapRef = react.useRef(null);

			react.useEffect(() => {
				if (!open) return undefined;
				let alive = true;
				const load = () => {
					fetch('/api/wecom/status', { headers: { accept: 'application/json' } })
						.then((r) => (r.ok ? r.json() : Promise.reject(new Error(`HTTP ${r.status}`))))
						.then((d) => {
							if (!alive) return;
							setStats(d);
							setError(false);
						})
						.catch(() => {
							if (alive) setError(true);
						});
				};
				load();
				const timer = setInterval(load, 5000);
				const onDocClick = (event) => {
					if (wrapRef.current && !wrapRef.current.contains(event.target)) setOpen(false);
				};
				document.addEventListener('mousedown', onDocClick);
				return () => {
					alive = false;
					clearInterval(timer);
					document.removeEventListener('mousedown', onDocClick);
				};
			}, [open]);

			const dot = stats?.connected;
			return react.createElement('span', { style: wrapStyle, ref: wrapRef },
				react.createElement('button', {
					type: 'button', title: '企业微信桥接状态', 'aria-label': '企业微信桥接状态',
					style: { ...btnStyle, background: open ? 'rgba(127,127,127,0.14)' : 'transparent' },
					onClick: () => setOpen((v) => !v)
				}, '💬'),
				open && react.createElement('div', { style: panelStyle },
					react.createElement('div', { style: titleStyle },
						'企业微信桥接',
						react.createElement('span', { style: dot ? dotOk : dotBad }, dot ? '●' : '○')
					),
					error && react.createElement('div', { style: { ...labelStyle, marginTop: 4 } }, '⚠️ 无法读取状态（插件未启用？）'),
					stats && [
						StatusRow('连接状态', stats.connected ? '🟢 已连接' : '🔴 未连接'),
						StatusRow('本次在线时长', fmtDuration(stats.connectedSec ?? 0)),
						StatusRow('活动会话', String(stats.activeChats ?? 0)),
						StatusRow('历史总会话', String(stats.totalSessions ?? 0)),
						StatusRow('待用户应答', String(stats.pendingInteractions ?? 0)),
						StatusRow('累计收到消息', String(stats.messagesIn ?? 0)),
						StatusRow('累计发出消息', String(stats.messagesOut ?? 0)),
						StatusRow('进程启动于', fmtTime(stats.startedAt))
					]
				)
			);
		}

		// --------------------------------------------------------------- apply

		/**
		 * Fill the conversation header actions slot with the status icon.
		 * @param ctx - Client root context.
		 */
		function apply(ctx) {
			ctx.slots.inject('conversation.session.header.actions', () => ctx.slots.register({
				name: 'conversation.session.header.actions',
				id: 'wecom-status',
				order: 90
			}, WecomStatusIcon));
		}

		exports.apply = apply;
		exports.inject = inject;
		return module.exports;
	}
});
