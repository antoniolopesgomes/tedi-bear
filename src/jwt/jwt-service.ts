import * as jwt from "jsonwebtoken";
import * as express from "express";
import { Promise } from "tedi/utils";
import { Inject, Injectable } from "tedi/decorators";
import { AuthError, AuthErrorType } from "../lib";
import {
    JWT_CONFIG_TOKEN, JwtConfig,
    JWT_EXPRESS_TOKEN, JwtExpress,
    JwtService,
} from "./core";

@Injectable()
export class DefaultJwtService<TCredentials, TPayload> implements JwtService<TPayload> {

    constructor(
        @Inject(JWT_EXPRESS_TOKEN) private _jwtExpress: JwtExpress<TCredentials>,
        @Inject(JWT_CONFIG_TOKEN) private _jwtConfig: JwtConfig<TCredentials, TPayload>,
    ) { }

    login(req: express.Request, res: express.Response): Promise<any> {
        let payload: TPayload;
        return Promise
            .resolve()
            .then(() => this._jwtExpress.getCredentialsFromRequest(req))
            .then(credentials => this._jwtConfig.login(credentials))
            .then(_payload => new Promise<string>((resolve, reject) => {
                // always safe-guard promise completion
                try {
                    payload = _payload;
                    jwt.sign(
                        payload,
                        this._jwtConfig.getSecret(payload),
                        this._jwtConfig.getSignOptions ? this._jwtConfig.getSignOptions(payload) : undefined,
                        (err, token) => err ? reject(err) : resolve(token)
                    );
                } catch (error) {
                    reject(error);
                }
            }))
            .then(token => this._jwtExpress.sendLoginResponse(token, res))
            .catch(error => {
                throw new AuthError(AuthErrorType.Unauthorized, "Unauthorized", error);
            });
    }

    validate(req: express.Request, res: express.Response): Promise<any> {
        return this
            .verify(req)
            .then(result => this._jwtExpress.sendValidationResponse(result.token, res))
            .catch(error => {
                throw new AuthError(AuthErrorType.Unauthorized, "Unauthorized", error);
            });
    }

    logout(req: express.Request, res: express.Response): Promise<any> {
        return this
            .verify(req)
            .then(result => Promise
                .resolve(this._jwtConfig.logout(result.payload))
                .then(() => result))
            .then(result => this._jwtExpress.sendLogoutResponse(result.token, res))
            .catch(error => {
                throw new AuthError(AuthErrorType.Unauthorized, "Unauthorized", error);
            });
    }

    public verify(req: express.Request): Promise<{ token: string, payload: TPayload }> {
        return Promise
            .resolve()
            .then(() => this._jwtExpress.getTokenFromRequest(req))
            .then(token => new Promise((resolve, reject) => {
                // always safe-guard promise completion
                try {
                    let payload = <TPayload> jwt.decode(token, { complete: true }).payload;
                    jwt.verify(
                        token,
                        this._jwtConfig.getSecret(payload),
                        this._jwtConfig.getVerifyOptions ? this._jwtConfig.getVerifyOptions(payload) : undefined,
                        (err, decoded) => err ? reject(err) : resolve({ token: token, payload: payload })
                    );
                } catch (error) {
                    reject(error);
                }
            }));
    }
}