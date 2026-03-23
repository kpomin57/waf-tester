const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('wafAPI', {
  runTests: (options) => ipcRenderer.invoke('run-tests', options),
  exportReport: (data) => ipcRenderer.invoke('export-report', data),
  exportHtmlReport: (data) => ipcRenderer.invoke('export-html-report', data),
  onProgress: (callback) => {
    ipcRenderer.on('test-progress', (_, data) => callback(data));
    return () => ipcRenderer.removeAllListeners('test-progress');
  }
});
