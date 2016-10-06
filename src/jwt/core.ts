import * as jwt from "jsonwebtoken";
import * as express from "express";

// Auth
export interface SignOptions extends jwt.SignOptions { }
export interface VerifyOptions extends jwt.VerifyOptions { }

export const JWT_EXPRESS_TOKEN = "JWT_EXPRESS";
export interface JwtExpress<TCredentials> {
    getCredentialsFromRequest(req: express.Request): TCredentials;
    getTokenFromRequest(req: express.Request): string;
    sendLoginResponse(token: string, res: express.Response): any;
    sendLogoutResponse(token: string, res: express.Response): any;
    sendValidationResponse(token: string, res: express.Response): any;
}

export const JWT_CONFIG_TOKEN = "JWT_CONFIG";
export interface JwtConfig<TCredentials, TPayload> {    
    login: (credentials: TCredentials) => TPayload;
    logout: (payload: TPayload) => void;
    getSecret: (payload: TPayload) => string;
    getSignOptions?: (payload: TPayload) => SignOptions;
    getVerifyOptions?: (payload: TPayload) => VerifyOptions;
}

export const JWT_SERVICE_TOKEN = "JWT_SERVICE";
export interface JwtService<TPayload> {
    login(req: express.Request, res: express.Response): Promise<any>;
    logout(req: express.Request, res: express.Response): Promise<any>;
    validate(req: express.Request, res: express.Response): Promise<any>;
    verify(req: express.Request): Promise<{ token: string, payload: TPayload }>;
}

export const JWT_FILTER_TOKEN = "JWT_FILTER";

export const JWT_ERROR_HANDLER_TOKEN = "JWT_ERROR_HANDLER";
