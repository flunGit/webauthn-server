# 变更日志
## [2.0.0] - 2026-04-22 09:03
### 重大优化:
- 本包现已丢弃CJS模式编写,改为 ESM 模块编写->未来趋势;只要你的 Node.js 版本大于22.12,可保留CJS `require()` 语法调用,否则请使用 `import` 语法;
- 直接导出isoBase64URL, isoCBOR, isoCrypto, isoUint8Array命名空间函数(命名空间不再支持);同步也优化了部分函数名:
>> 1. fromUTF8String->utf8Tob64url	(将 UTF-8 字符串编码为 Base64URL);
>> 2. toUTF8String->b64urlToUtf8	(将 Base64URL 字符串解码为 UTF-8 字符串);
>> 3. fromUTF8String->utf8Tobytes	(将 UTF-8 字符串转换为 Uint8Array);
>> 4. toUTF8String->bytesToUtf8	    (将 Uint8Array 转换为 UTF-8 字符串);
>> 5. fromASCIIString->asciiToBytes	(将 ASCII 字符串转换为 Uint8Array);
- 项目目录结构进行大幅调整,内部细节略,如需了解请自行查看;
- 对 .d.ts 文件进行了更细致优化,现在使用时鼠标焦点会提示当前项导出的细节内容(比如模块,函数等);
