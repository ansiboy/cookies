/*!
 * cookies
 * Copyright(c) 2014 Jed Schmidt, http://jed.is/
 * Copyright(c) 2015-2016 Douglas Christopher Wilson
 * MIT Licensed
 */
/// <reference types="node" />
import Keygrip = require('keygrip');
import http = require('http');
interface Opetions {
    keys?: [];
    secure?: boolean;
}
declare class Cookies {
    private secure;
    private request;
    private response;
    private keys;
    constructor(request: http.IncomingMessage, response: http.IncomingMessage, options?: Opetions | Keygrip | []);
    get(name: string, opts?: any): any;
    set(name: string, value: string, opts?: CookieOptions & {
        signed?: boolean;
        secureProxy?: boolean;
    }): this;
}
declare type CookieOptions = Pick<Cookie, "name" | "secure" | "path" | "overwrite" | "expires" | "httpOnly" | "domain" | "maxAge">;
declare class Cookie {
    name?: string;
    value?: string;
    secure?: boolean;
    path?: string;
    overwrite?: boolean;
    expires?: Date;
    httpOnly?: boolean;
    domain?: string;
    maxAge?: number;
    private sameSite;
    constructor(name: string, value: string, attrs: CookieOptions);
    toString(): string;
    toHeader(): string;
}
export = Cookies;
