import * as express from "express";
import { Inject, Injectable } from "tedi/decorators";
import { Filter } from "tedi/core";
import { JWT_SERVICE_TOKEN, JwtService } from "./core";
import { AuthError, AuthErrorType } from "../lib";

export interface JwtFilterData<TPayload> {
    token: string;
    payload: TPayload;
}

@Injectable()
export class JwtFilter<TPayload> implements Filter<JwtFilterData<TPayload>> {

    private _jwtService: JwtService<TPayload>;

    constructor(
        @Inject(JWT_SERVICE_TOKEN) jwtService: JwtService<TPayload>
    ) {
        this._jwtService = jwtService;
    }

    apply(req: express.Request): any {
       return this._jwtService
        .verify(req)
        .then(result => req[this.getJwtProperyKey()] = <JwtFilterData<TPayload>> result)
        .catch(error => {
            throw new AuthError(AuthErrorType.Unauthorized, "Unauthorized", error);
        });
    }

    getDataFromRequest(req: express.Request): JwtFilterData<TPayload> {
        return <JwtFilterData<TPayload>> req[this.getJwtProperyKey()];
    }

    protected getJwtProperyKey(): string { return "jwt"; }

}
