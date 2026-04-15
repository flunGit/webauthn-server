```markdown
# flun-webauthn-server <!-- omit in toc -->
### 本包现已丢弃CJS模式编写,改为 ESM 模块编写->未来趋势;只要你的 Node.js 版本大于22.12,可保留CJS `require()` 语法调用,否则请使用 `import` 语法;

![WebAuthn](https://img.shields.io/badge/WebAuthn-Simplified-blueviolet?style=for-the-badge&logo=WebAuthn)
[![npm (scoped)](https://img.shields.io/npm/v/flun-webauthn-server?style=for-the-badge&logo=npm)](https://www.npmjs.com/package/flun-webauthn-server)


- [安装](#安装)
  - [Node LTS 20.x 及以上版本](#node-lts-20x-及以上版本)
- [文档](#文档)
- [支持的认证格式](#支持的认证格式)

## 安装

本包可从 **[NPM](https://www.npmjs.com/package/flun-webauthn-server)**  安装：

### Node LTS 20.x 及以上版本

```sh
npm i flun-webauthn-server
```
---
## 使用
- 前端需安装 flun-webauthn-browser 或 下载调用右边链接文件 或 直接文件链接->`<script src="https://unpkg.com/flun-webauthn-browser/dist/index.js"></script>`

### 后端使用:
## 支持的认证格式

flunWebAuthn 支持 [当前所有 WebAuthn 认证格式](https://w3c.github.io/webauthn/#sctn-defined-attestation-formats)，包括：

- **Android Key**
- **Android SafetyNet**
- **Apple**
- **FIDO U2F**
- **Packed**
- **TPM**
- **None**
```