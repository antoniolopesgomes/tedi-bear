import { TediError } from "tedi/core";

// Errors
export enum AuthErrorType {
    Unauthorized,
    Forbidden
}

export class AuthError extends TediError {
    constructor(public type: AuthErrorType, msg: string, error?: any) {
        super(msg, error);
    }
}
