'use strict';

const crypto = require('crypto');
const url = require('url');
const utils = require('./utils');

/**
 * Returns a string representing the request
 *
 * Cleaning involves:
 *
 * - stripping the oauth_signature from the params
 * - encoding the values ( yes this double encodes them )
 * - sorting the key/value pairs
 * - joining them with &
 * - encoding them again
 *
 * @param {object} body Body parameters
 * @param {object} query Query parameters
 * @returns {string}
 */
function _clean_request_body(body, query) {
  const out = [..._cleanParams(body), ..._cleanParams(query)];

  return utils.special_encode(out.sort().join('&'));
}

function _cleanParams(params) {
  if (typeof params !== 'object') {
    return [];
  }

  const clean = [];

  /* eslint-disable guard-for-in */
  for (const key in params) {
    const values = params[key];

    if (key === 'oauth_signature') {
      continue;
    }

    if (!Array.isArray(values)) {
      clean.push(_encodeParam(key, values));
      continue;
    }

    for (const val of Array.from(values)) {
      clean.push(_encodeParam(key, val));
    }
  }
  /* eslint-enable guard-for-in */

  return clean;
}

function _encodeParam(key, val) {
  return `${key}=${utils.special_encode(val)}`;
}

class HMAC_SHA1 {
  constructor(options) {
    this.trustProxy = true; //(options && options.trustProxy) || false;
  }

  toString() {
    return 'HMAC_SHA1';
  }

  build_signature_raw(
    req_url,
    parsed_url,
    method,
    params,
    consumer_secret,
    token
  ) {
    const sig = [
      method.toUpperCase(),
      utils.special_encode(req_url + '/ltiLogin'),
      _clean_request_body(params, parsed_url.query)
    ];
 
    console.log(req_url);
    console.log(_clean_request_body(params, parsed_url.query));

    return this.sign_string(sig.join('&'), consumer_secret, token);
  }

  host(req) {
    if (!this.trustProxy) {
      return req.headers.host;
    }

    return req.headers['x-forwarded-host'] || req.headers.host;
  }

  protocol(req) {
    const xProtocol = req.headers['x-forwarded-proto'];

    if (this.trustProxy && xProtocol) {
      return xProtocol;
    }

    if (req.protocol) {
      return req.protocol;
    }

    return req.connection.encrypted ? 'https' : 'http';
  }

  build_signature(req, body, consumer_secret, token) {
    const hapiRawReq = req.raw && req.raw.req;

    if (hapiRawReq) {
      req = hapiRawReq;
    }

    let originalUrl = req.originalUrl || req.url;
    const host = this.host(req);
    const protocol = this.protocol(req);

    // Since canvas includes query parameters in the body we can omit the query string
    if (
      body.tool_consumer_info_product_family_code === 'canvas' ||
      body.tool_consumer_info_product_family_code === 'schoology'
    ) {
      originalUrl = url.parse(originalUrl).pathname;
    }

    const parsedUrl = url.parse(originalUrl, true);
    const hitUrl = protocol + '://' + host + parsedUrl.pathname;

    console.log(hitUrl)
    console.log(parsedUrl)
    console.log(req.method)
    console.log(token)
    console.log(host)
    console.log(parsedUrl.pathname)

    return this.build_signature_raw(
      hitUrl,
      parsedUrl,
      req.method,
      body,
      consumer_secret,
      token
    );
  }

  sign_string(str, key, token) {
    key = `${key}&`;
    if (token) {
      key += token;
    }

    return crypto
      .createHmac('sha1', key)
      .update(str)
      .digest('base64');
  }
}

module.exports = HMAC_SHA1;
