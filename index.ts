/*!
 * cookies
 * Copyright(c) 2014 Jed Schmidt, http://jed.is/
 * Copyright(c) 2015-2016 Douglas Christopher Wilson
 * MIT Licensed
 */

/** 
 * 说明：
 * 原版本为 js，有本人改为 ts
 * 作者：麦舒
 */

import depd = require("depd");
import Keygrip = require('keygrip');
import http = require('http');

var deprecate = depd('cookies');
var cache = {}

/**
 * RegExp to match field-content in RFC 7230 sec 3.2
 *
 * field-content = field-vchar [ 1*( SP / HTAB ) field-vchar ]
 * field-vchar   = VCHAR / obs-text
 * obs-text      = %x80-FF
 */

var fieldContentRegExp = /^[\u0009\u0020-\u007e\u0080-\u00ff]+$/;

/**
 * RegExp to match Same-Site cookie attribute value.
 */

var SAME_SITE_REGEXP = /^(?:lax|none|strict)$/i

interface Opetions {
  keys?: [],
  secure?: boolean
}

class Cookies {
  private secure: boolean;
  private request: http.IncomingMessage;
  private response: http.IncomingMessage | http.ServerResponse;
  private keys: Keygrip;

  constructor(request: http.IncomingMessage, response: http.IncomingMessage | http.ServerResponse, options?: Opetions | Keygrip | []) {

    this.secure = undefined
    this.request = request
    this.response = response

    if (options) {
      if (Array.isArray(options)) {
        // array of key strings
        deprecate('"keys" argument; provide using options {"keys": [...]}')
        this.keys = new Keygrip(options)
      } else if (options.constructor && options.constructor.name === 'Keygrip') {
        // any keygrip constructor to allow different versions
        deprecate('"keys" argument; provide using options {"keys": keygrip}')
        this.keys = options as Keygrip;
      } else {
        let obj = options as Opetions;
        this.keys = Array.isArray(obj.keys) ? new Keygrip(obj.keys) : obj.keys
        this.secure = obj.secure
      }
    }
  }

  get(name: string, opts?) {
    var sigName = name + ".sig"
      , header, match, value, remote, data, index
      , signed = opts && opts.signed !== undefined ? opts.signed : !!this.keys

    header = this.request.headers["cookie"]
    if (!header) return

    match = header.match(getPattern(name))
    if (!match) return

    value = match[1]
    if (!opts || !signed) return value

    remote = this.get(sigName)
    if (!remote) return

    data = name + "=" + value
    if (!this.keys) throw new Error('.keys required for signed cookies');
    index = this.keys.index(data, remote)

    if (index < 0) {
      this.set(sigName, null, { path: "/", signed: false })
    } else {
      index && this.set(sigName, this.keys.sign(data), { signed: false })
      return value
    }
  }

  //{ signed?: boolean, secure?: boolean, secureProxy?: boolean, path?: string, overwrite?: boolean }
  set(name: string, value: string, opts?: CookieOptions & { signed?: boolean, secureProxy?: boolean }) {
    let res = this.response as http.ServerResponse;
    let headers = (res.getHeader ? res.getHeader("Set-Cookie") as string | string[] :
      (this.response as http.IncomingMessage).headers["Set-Cookie"]) || [];//res.getHeader("Set-Cookie") || [];

    let secure = this.secure; //this.secure !== undefined ? !!this.secure : req["protocol"] === 'https' || req.connection["encrypted"];
    let cookie = new Cookie(name, value, opts);
    let signed = opts && opts.signed !== undefined ? opts.signed : !!this.keys;

    if (typeof headers == "string") headers = [headers]

    if (!secure && opts && opts.secure) {
      throw new Error('Cannot send secure cookie over unencrypted connection')
    }

    cookie.secure = opts && opts.secure !== undefined
      ? opts.secure
      : secure

    if (opts && "secureProxy" in opts) {
      deprecate('"secureProxy" option; use "secure" option, provide "secure" to constructor if needed')
      cookie.secure = opts.secureProxy
    }

    pushCookie(headers, cookie)

    if (opts && signed) {
      if (!this.keys) throw new Error('.keys required for signed cookies');
      cookie.value = this.keys.sign(cookie.toString())
      cookie.name += ".sig"
      pushCookie(headers, cookie)
    }

    // var setHeader = res.set ? http.OutgoingMessage.prototype.setHeader : res.setHeader
    // setHeader.call(res, 'Set-Cookie', headers)
    if (res.setHeader)
      res.setHeader("Set-Cookie", headers);
    else
      (this.response as http.IncomingMessage).headers["Set-Cookie"] = headers;

    return this
  }

}


type CookieOptions = Pick<Cookie, "name" | "secure" | "path" | "overwrite" | "expires" | "httpOnly" | "domain" | "maxAge">;

class Cookie {
  name?: string;
  value?: string;
  secure?: boolean;
  path?: string = "/";
  overwrite?: boolean = false;
  expires?: Date = undefined;
  httpOnly?: boolean = true;
  domain?: string = undefined;
  maxAge?: number;

  private sameSite: string | boolean = false;


  // Cookie.prototype.path = "/";
  // Cookie.prototype.expires = undefined;
  // Cookie.prototype.domain = undefined;
  // Cookie.prototype.httpOnly = true;
  // Cookie.prototype.sameSite = false;
  // Cookie.prototype.secure = false;
  // Cookie.prototype.overwrite = false;

  constructor(name: string, value: string, attrs: CookieOptions) {
    if (!fieldContentRegExp.test(name)) {
      throw new TypeError('argument name is invalid');
    }

    if (value && !fieldContentRegExp.test(value)) {
      throw new TypeError('argument value is invalid');
    }

    this.name = name
    this.value = value || ""

    for (var key in attrs) {
      this[key] = attrs[key]
    }

    if (!this.value) {
      this.expires = new Date(0)
      this.maxAge = null
    }

    if (this.path && !fieldContentRegExp.test(this.path)) {
      throw new TypeError('option path is invalid');
    }

    if (this.domain && !fieldContentRegExp.test(this.domain)) {
      throw new TypeError('option domain is invalid');
    }

    if (this.sameSite && this.sameSite !== true && !SAME_SITE_REGEXP.test(this.sameSite)) {
      throw new TypeError('option sameSite is invalid')
    }
  }

  toString() {
    return this.name + "=" + this.value
  }

  toHeader() {
    var header = this.toString()

    if (this.maxAge) this.expires = new Date(Date.now() + this.maxAge);

    if (this.path) header += "; path=" + this.path
    if (this.expires) header += "; expires=" + this.expires.toUTCString()
    if (this.domain) header += "; domain=" + this.domain
    if (this.sameSite) header += "; samesite=" + (this.sameSite === true ? 'strict' : this.sameSite.toLowerCase())
    if (this.secure) header += "; secure"
    if (this.httpOnly) header += "; httponly"

    return header
  }
}





// // back-compat so maxage mirrors maxAge
// Object.defineProperty(Cookie.prototype, 'maxage', {
//   configurable: true,
//   enumerable: true,
//   get: function () { return this.maxAge },
//   set: function (val) { return this.maxAge = val }
// });
// deprecate.property(Cookie.prototype, 'maxage', '"maxage"; use "maxAge" instead')

function getPattern(name) {
  if (cache[name]) return cache[name]

  return cache[name] = new RegExp(
    "(?:^|;) *" +
    name.replace(/[-[\]{}()*+?.,\\^$|#\s]/g, "\\$&") +
    "=([^;]*)"
  )
}

function pushCookie(headers: string[], cookie: Cookie) {
  if (cookie.overwrite) {
    for (var i = headers.length - 1; i >= 0; i--) {
      if (headers[i].indexOf(cookie.name + '=') === 0) {
        headers.splice(i, 1)
      }
    }
  }

  headers.push(cookie.toHeader())
}

// Cookies.connect = Cookies.express = function (keys) {
//   return function (req, res, next) {
//     req.cookies = res.cookies = new Cookies(req, res, {
//       keys: keys
//     })

//     next()
//   }
// }


// Cookies.Cookie = Cookie

// module.exports = Cookies

export = Cookies;
