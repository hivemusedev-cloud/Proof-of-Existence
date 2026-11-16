// The renderer's only bridge to the main process. The renderer
// has no Node access (contextIsolation + sandbox); everything
// it can do is one of these calls, and every node interaction
// behind them goes through the node's control endpoint.

const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('poe', {
  env: () => ipcRenderer.invoke('env'),
  nodeStatus: () => ipcRenderer.invoke('node-status'),
  startNode: () => ipcRenderer.invoke('node-start'),
  stopNode: () => ipcRenderer.invoke('node-stop'),
  logs: () => ipcRenderer.invoke('node-logs'),
  call: (method, params) => ipcRenderer.invoke('call', method, params),
  pickFile: () => ipcRenderer.invoke('pick-file'),
  onLog: (cb) => ipcRenderer.on('node-log', (_e, line) => cb(line)),
  onState: (cb) => ipcRenderer.on('node-state', (_e, state) => cb(state)),
});
