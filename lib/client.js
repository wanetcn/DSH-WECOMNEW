// Web UI half of dsh-wecom: a 📱 entry in the sidebar footer (right above the
// settings row) showing the bridge's live totals — WeCom users, sessions,
// connection state, message counters and pending interactions — polled from
// the plugin's `/api/wecom/status` route (registered by the node half in
// bridge.js).
//
// Loaded by the dsh client module system (`dsh.client` declaration in
// package.json → served at /plugins/dsh-wecom/client.js → booted via
// window.__DSH_BOOT__). Follows the same shape as the shipped client-ui
// modules: CommonJS factory + exports.inject + exports.apply, registering a
// React component into a named UI slot (`sidebar.footer.action` is a list
// slot rendered just above the settings row).

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

		const wrapStyle = { position: 'relative', display: 'block', width: '100%' };
		const entryStyle = {
			display: 'flex', alignItems: 'center', gap: 10, width: '100%',
			padding: '9px 14px', border: 'none', borderRadius: 10,
			background: 'transparent', cursor: 'pointer', fontSize: 13.5,
			color: 'inherit', textAlign: 'left', lineHeight: 1.4
		};
		const entryOpenStyle = { ...entryStyle, background: 'rgba(127,127,127,0.14)' };
		const badgeStyle = {
			marginLeft: 'auto', display: 'flex', gap: 6, fontSize: 11,
			opacity: 0.75, whiteSpace: 'nowrap'
		};
		const badgePillStyle = {
			padding: '1px 7px', borderRadius: 999,
			background: 'rgba(127,127,127,0.16)', fontWeight: 500
		};
		const panelStyle = {
			position: 'absolute', bottom: 'calc(100% + 8px)', left: 8, right: 8, zIndex: 9999,
			padding: '12px 14px', borderRadius: 10,
			background: 'var(--dsh-bg, #fff)', color: 'var(--dsh-fg, #1f2328)',
			border: '1px solid rgba(127,127,127,0.25)', boxShadow: '0 8px 24px rgba(0,0,0,0.18)',
			fontSize: 12.5, lineHeight: 1.5, textAlign: 'left', whiteSpace: 'nowrap'
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

		function WecomSidebarEntry({ wide }) {
			const [open, setOpen] = react.useState(false);
			const [stats, setStats] = react.useState(null);
			const [error, setError] = react.useState(false);
			const wrapRef = react.useRef(null);

			react.useEffect(() => {
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
				const timer = setInterval(load, 5_000);
				return () => {
					alive = false;
					clearInterval(timer);
				};
			}, []);

			react.useEffect(() => {
				if (!open) return undefined;
				const onDocClick = (event) => {
					if (wrapRef.current && !wrapRef.current.contains(event.target)) setOpen(false);
				};
				document.addEventListener('mousedown', onDocClick);
				return () => document.removeEventListener('mousedown', onDocClick);
			}, [open]);

			const totalUsers = stats?.totalUsers ?? '…';
			const totalSessions = stats?.totalSessions ?? '…';

			return react.createElement('span', { style: wrapStyle, ref: wrapRef },
				react.createElement('button', {
					type: 'button',
					title: stats ? `企微桥接：${totalUsers} 个用户 · ${totalSessions} 个会话` : '企微桥接状态',
					'aria-label': '企微桥接状态',
					style: open ? entryOpenStyle : entryStyle,
					onClick: () => setOpen((v) => !v)
				},
					react.createElement('span', { style: { fontSize: 16, lineHeight: 1 } }, '📱'),
					wide && react.createElement('span', { style: { fontWeight: 500 } }, '企微'),
					wide && react.createElement('span', { style: badgeStyle },
						react.createElement('span', { style: badgePillStyle }, `${totalUsers} 用户`),
						react.createElement('span', { style: badgePillStyle }, `${totalSessions} 会话`),
						react.createElement('span', {
							style: { ...badgePillStyle, ...(stats?.connected ? dotOk : dotBad) }
						}, stats?.connected ? '已连接' : '未连接')
					)
				),
				open && react.createElement('div', { style: panelStyle },
					react.createElement('div', { style: titleStyle },
						'企微桥接',
						react.createElement('span', { style: stats?.connected ? dotOk : dotBad }, stats?.connected ? '●' : '○')
					),
					error && react.createElement('div', { style: { ...labelStyle, marginTop: 4 } }, '⚠️ 无法读取状态（插件未启用？）'),
					stats && [
						StatusRow('总用户数', String(stats.totalUsers ?? 0)),
						StatusRow('总会话数', String(stats.totalSessions ?? 0)),
						StatusRow('活动会话', String(stats.activeChats ?? 0)),
						StatusRow('待用户应答', String(stats.pendingInteractions ?? 0)),
						StatusRow('连接状态', stats.connected ? '🟢 已连接' : '🔴 未连接'),
						StatusRow('本次在线时长', fmtDuration(stats.connectedSec ?? 0)),
						StatusRow('累计收到消息', String(stats.messagesIn ?? 0)),
						StatusRow('累计发出消息', String(stats.messagesOut ?? 0)),
						StatusRow('进程启动于', fmtTime(stats.startedAt))
					]
				)
			);
		}

		// --------------------------------------------------------------- apply

		/**
		 * Fill the sidebar footer slot (rendered right above the settings row).
		 * @param ctx - Client root context.
		 */
		function apply(ctx) {
			ctx.slots.inject('sidebar.footer.action', () => ctx.slots.register({
				name: 'sidebar.footer.action',
				id: 'wecom-status'
			}, WecomSidebarEntry));
		}

		exports.apply = apply;
		exports.inject = inject;
		return module.exports;
	}
});
