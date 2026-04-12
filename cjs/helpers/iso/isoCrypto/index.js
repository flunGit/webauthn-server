'use strict';

/**
 * 一组与运行时无关的方法集合,用于处理 WebCrypto API
 * @module
 */

const { digest } = require('./digest.js'), { getRandomValues } = require('./getRandomValues.js'),
    { verify } = require('./verify.js');

module.exports = { digest, getRandomValues, verify };