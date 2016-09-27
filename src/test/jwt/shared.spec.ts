import * as express from "express";
import * as jwt from "../../jwt";

describe("JwtController", () => {

    interface Credentials {
        username: string;
        password: string;
    }

    interface UserData {
        id: any;
        name: string;
        groups: string[];
    }

    class AuthenticationMock implements jwt.Authentication<Credentials, UserData> {
        login(credentials: Credentials): UserData { return; }
        logout(userData: UserData): void { return; }
    }

    class JwtConfigManagerMock implements jwt.JwtConfigManager<UserData> {
        getSecret(userData: UserData): string { return "dummySecret"; }
        getSignOptions(userData: UserData): jwt.SignOptions { return undefined; }
        getVerifyOptions(userData: UserData): jwt.VerifyOptions { return undefined; }
    }

    class JwtExpressManagerMock implements jwt.JwtExpressManager<Credentials> {
        getCredentialsFromRequest(req: express.Request): Credentials { return; }
        getTokenFromRequest(req: express.Request): string { return; }
        sendLoginResponse(error: any, token: string, res: express.Response): any { return; };
        sendLogoutResponse(error: any, token: string, res: express.Response): any { return; };
        sendValidationResponse(error: any, res: express.Response): any { return; }
    }

    let authentication: AuthenticationMock;
    let jwtConfigManager: JwtConfigManagerMock;
    let jwtExpressManager: JwtExpressManagerMock;
    let jwtController: jwt.JwtController<Credentials, UserData>;
    // mocks

    beforeEach(() => {
        jwtController = new jwt.JwtController(authentication, jwtExpressManager, jwtConfigManager);
    });

    describe("#login", () => {
        let credentials: Credentials;
        let userData: UserData;
        let secret: string;
        beforeEach(() => {
            // mocks
            credentials = {
                username: "tester",
                password: "password",
            };
            userData = {
                id: 1,
                name: "user",
                groups: ["group1", "group2"],
            };
            secret = "SHHHH!";
            // stubs
            spyOn(jwtExpressManager, "getCredentialsFromRequest").and.returnValue(credentials);
            spyOn(authentication, "login").and.returnValue(userData);
            spyOn(jwtConfigManager, "getSecret").and.returnValue(secret);
            spyOn(jwtConfigManager, "getSignOptions");
            spyOn(jwtConfigManager, "getSignOptions");
        });
    });

});
