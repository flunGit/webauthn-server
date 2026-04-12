'use strict';

/**
 * WebAuthn 相关工具函数集合
 *
 * 本模块聚合了处理认证器数据、证书、签名验证等常用方法;
 */

Object.assign(
    module.exports,
    require('./iso/index.js'),
    require('./convertAAGUIDToString.js'),
    require('./convertCertBufferToPEM.js'),
    require('./convertCOSEtoPKCS.js'),
    require('./cose.js'),
    require('./decodeAttestationObject.js'),
    require('./decodeClientDataJSON.js'),
    require('./decodeCredentialPublicKey.js'),
    require('./generateChallenge.js'),
    require('./generateUserID.js'),
    require('./getCertificateInfo.js'),
    require('./isCertRevoked.js'),
    require('./logging.js'),
    require('./matchExpectedRPID.js'),
    require('./parseAuthenticatorData.js'),
    require('./parseBackupFlags.js'),
    require('./toHash.js'),
    require('./validateCertificatePath.js'),
    require('./verifySignature.js'),
    require('../metadata/verifyMDSBlob.js')
);