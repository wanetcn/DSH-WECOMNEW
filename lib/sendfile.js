// wecom_send_file tool: let the agent hand a file to the current WeCom chat.
//
// Registered through the standard dsh tools seam (ctx.tools.register) so the
// model can call it like any built-in tool. Path policy lives in
// Bridge.handleSendFileRequest: only files inside the chatting user's own
// workspace directory or the shared public directory may be sent, enforced
// after realpath resolution (no traversal), regular files only, size-capped.

import { defineTool } from '@deepseek-ai/dsh-tools';

/**
 * Register the wecom_send_file tool on the host tools service.
 * @param tools - the host `tools` service (ctx.get('tools')).
 * @param bridge - the Bridge instance (owns adapter, chat map, path policy).
 * @returns the registration disposer.
 */
export function registerSendFileTool(tools, bridge) {
  return tools.register(defineTool({
    name: 'wecom_send_file',
    description: '把一个已存在的文件通过企业微信发送给当前聊天的用户。仅允许发送当前用户私有工作区目录或公共工作区目录内的文件（绝对路径），其他路径一律拒绝；单文件有大小上限。',
    parameters: {
      path: {
        type: 'string',
        required: true,
        description: '要发送的文件的绝对路径（必须位于当前用户私有工作区目录或公共工作区目录内）。'
      },
      caption: {
        type: 'string',
        description: '可选：文件发出后追加的一条 Markdown 说明文字。'
      }
    },
    output: {
      schema: {
        type: 'object',
        additionalProperties: false,
        properties: {
          ok: { type: 'boolean', required: true },
          detail: { type: 'string', required: true }
        }
      },
      render: (_args, value) => [{ type: 'text', text: JSON.stringify(value) }]
    },
    async execute(args, exec) {
      return bridge.handleSendFileRequest(exec?.agent, args ?? {}, exec?.signal);
    }
  }));
}
