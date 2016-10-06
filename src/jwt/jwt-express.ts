import * as express from "express";
import { Injectable } from "tedi/decorators";
import { JwtExpress } from "./core";

const AUTHORIZATION_HEADER = "authorization";

@Injectable()
export class DefaultJwtExpress<TCredentials> implements JwtExpress<TCredentials> {

    getCredentialsFromRequest(req: express.Request): TCredentials {
        if (!req.body) {
            throw new Error("body was not found in the request! Try to use 'body-parser'");
        }
        return req.body;
    }

    /*
    Reinforce the Bearer schema -> Authorization: Bearer <token>
    */
    getTokenFromRequest(req: express.Request): string {
        let authHeader = req.headers[AUTHORIZATION_HEADER];
        if (!authHeader) {
            throw new Error("Authorization header not present!");
        }
        let authTokens = authHeader.split(" ");
        if (authTokens[0] !== "Bearer") {
            throw new Error("Should be using Bearer schema in the Authorization header");
        }
        return authTokens[1];
    }

    /*
    Respond successfuly
    */
    sendLoginResponse(token: string, res: express.Response): any {
        res.json({ jwt: token });
    }

    /*
    Respond successfuly
    */
    sendLogoutResponse(token: string, res: express.Response): any {
        res.status(200).end();
    }

    /*
    Respond successfuly
    */
    sendValidationResponse(token: string, res: express.Response): any {
        res.status(200).end();
    }
}
