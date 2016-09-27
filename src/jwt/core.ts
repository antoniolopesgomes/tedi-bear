import * as jwt from "jsonwebtoken";
import * as express from "express";
import { Promise } from "tedi/core";
import { TediBearController } from "../core/shared";

export interface Authentication<TCredentials, TUserData> {
    login(credentials: TCredentials): TUserData;
    logout(userData: TUserData): any;
}

export interface JwtExpressManager<TCredentials> {
    getCredentialsFromRequest(req: express.Request): TCredentials;
    getTokenFromRequest(req: express.Request): string;
    sendLoginResponse(error: any, token: string, res: express.Response): any;
    sendLogoutResponse(error: any, token: string, res: express.Response): any;
    sendValidationResponse(error: any, res: express.Response): any;
}

export interface SignOptions extends jwt.SignOptions {}
export interface VerifyOptions extends jwt.VerifyOptions {}

export interface JwtConfigManager<TUserData> {
    getSecret(userData: TUserData): string;
    getSignOptions(userData: TUserData): SignOptions;
    getVerifyOptions(userData: TUserData): VerifyOptions;
}

export class JwtController<TCredentials, TUserData> implements TediBearController {

    constructor(
        private _authentication: Authentication<TCredentials, TUserData>,
        private _jwtExpressManager: JwtExpressManager<TCredentials>,
        private _jwtConfigManager: JwtConfigManager<TUserData>,
    ) { }

    login(req: express.Request, res: express.Response): Promise<any> {
        return Promise
            .resolve()
            .then(() => this._jwtExpressManager.getCredentialsFromRequest(req))
            .then(credentials => this._authentication.login(credentials))
            .then(userData => new Promise<string>((resolve, reject) => jwt.sign(
                    userData,
                    this._jwtConfigManager.getSecret(userData),
                    this._jwtConfigManager.getSignOptions(userData),
                    (err, token) => err ? reject(err) : resolve(token)
            )))
            .then(token => this._jwtExpressManager.sendLoginResponse(null, token, res))
            .catch(error => this._jwtExpressManager.sendLoginResponse(error, null, null));
    }

    validate(req: express.Request, res: express.Response): Promise<any> {
        return this
            ._decodeAndValidate(req)
            .then(decoded => this._jwtExpressManager.sendValidationResponse(null, res))
            .catch(error => this._jwtExpressManager.sendValidationResponse(error, null));
    }

    logout(req: express.Request, res: express.Response): Promise<any> {
        return this
            ._decodeAndValidate(req)
            .then(result => this._authentication.logout(result.userData))
            .then(() => this._jwtExpressManager.sendLogoutResponse(null, null, res))
            .catch(error => this._jwtExpressManager.sendLogoutResponse(error, null, null));
    }

    private _decodeAndValidate(req: express.Request): Promise<{token: string, userData: TUserData}> {
        return Promise
            .resolve()
            .then(() => this._jwtExpressManager.getTokenFromRequest(req))
            .then(token => ({
                token: token,
                userData: <TUserData> jwt.decode(token, { complete: true }).payload,
            }))
            .then(result => new Promise<{token: string, userData: TUserData}>((resolve, reject) => {
                jwt.verify(
                    result.token,
                    this._jwtConfigManager.getSecret(result.userData),
                    this._jwtConfigManager.getVerifyOptions(result.userData),
                    (err, decoded) => err ? reject(err) : resolve(result)
                );
            }));
    }
}
