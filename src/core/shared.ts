import { Promise } from "tedi/core";
import * as express from "express";
export const TEDI_BEAR_VALIDATOR = "TEDI_BEAR_VALIDATOR";

export interface TediBearController {
    login(req: express.Request, res: express.Response): Promise<any>;
    logout(req: express.Request, res: express.Response): Promise<any>;
    validate(req: express.Request, res: express.Response): Promise<any>;
}
