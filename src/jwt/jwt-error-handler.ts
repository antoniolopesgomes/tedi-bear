import * as express from "express";
import { Injectable } from "tedi/decorators";
import { AuthError, AuthErrorType } from "../lib";

@Injectable()
export class DefaultJwtErrorHandler {
    catch(error: any, req: express.Request, res: express.Response): void {
        let authError = error.search(AuthError);
        if (authError instanceof AuthError) {
            switch (authError.type) {
                case AuthErrorType.Unauthorized:
                    res.status(401).send(authError.messageStack);
                    break;
                case AuthErrorType.Forbidden:
                    res.status(403).send(authError.messageStack);
                    break;
                default:
                    break;
            }
        } else {
            throw(error);
        }
    }
}
