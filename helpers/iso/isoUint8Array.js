/**
 * 确保两个 Uint8Array 深度相等
 */
const areEqual = (array1, array2) => {
    if (array1.length != array2.length) return false;
    return array1.every((val, i) => val === array2[i]);
},

    /**
     * 将 Uint8Array 转换为十六进制字符串;
     *
     * 替代 `Buffer.toString('hex')`
     */
    toHex = array => {
        const hexParts = Array.from(array, (i) => i.toString(16).padStart(2, '0'));
        return hexParts.join(''); // adce000235bcc60a648b0b25f1f05503
    },

    /**
     * 将十六进制字符串转换为 Uint8Array;
     *
     * 替代 `Buffer.from('...', 'hex')`
     */
    fromHex = hex => {
        if (!hex) return Uint8Array.from([]);

        const isValid = hex.length !== 0 && hex.length % 2 === 0 && !/[^a-fA-F0-9]/u.test(hex);
        if (!isValid) throw new Error('无效的十六进制字符串');

        const byteStrings = hex.match(/.{1,2}/g) ?? [];
        return Uint8Array.from(byteStrings.map((byte) => parseInt(byte, 16)));
    },

    /**
     * 将多个 Uint8Array 合并成一个 Uint8Array
     */
    concat = arrays => {
        let pointer = 0;
        const totalLength = arrays.reduce((prev, curr) => prev + curr.length, 0), toReturn = new Uint8Array(totalLength);
        arrays.forEach(arr => {
            toReturn.set(arr, pointer), pointer += arr.length;
        });
        return toReturn;
    },

    /**
     * 将字节数组转换为 UTF-8 字符串
     */
    toUTF8String = array => {
        const decoder = new globalThis.TextDecoder('utf-8');
        return decoder.decode(array);
    },

    /**
     * 将 UTF-8 字符串转换回字节数组
     */
    fromUTF8String = utf8String => {
        const encoder = new globalThis.TextEncoder();
        return encoder.encode(utf8String);
    },

    /**
     * 将 ASCII 字符串转换为 Uint8Array
     */
    fromASCIIString = value => {
        return Uint8Array.from(value.split('').map((x) => x.charCodeAt(0)));
    },

    /**
     * 创建一个 DataView，以便在解析 Uint8Array 的字节时可以灵活切分
     */
    toDataView = array => {
        return new DataView(array.buffer, array.byteOffset, array.length);
    };

export { areEqual, toHex, fromHex, concat, toUTF8String, fromUTF8String, fromASCIIString, toDataView };