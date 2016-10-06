import * as express from "express";
import * as rq from "supertest-as-promised";
import * as jwt from "jsonwebtoken";
import { JwtModule, JwtConfig } from "../../jwt";
import { ExpressServer } from "tedi/express";
import { Logger, LoggerLevels, dependency } from "tedi/core";
import { Injectable, web } from "tedi/decorators";

let notImplemented = () => { throw new Error("Not Implemented"); };

describe("DefaultJwtModule", () => {

    interface Credentials {
        username: string;
        password: string;
    }

    interface Payload {
        id: number;
        name: string;
        groups: string[];
    }

    @Injectable()
    class PublicController {
        @web.get()
        get(req: express.Request, res: express.Response) {
            res.status(200).end();
        }
    }

    let jwtModule: JwtModule<Credentials, Payload>;
    let jwtConfig: JwtConfig<Credentials, Payload>;
    let server: ExpressServer;

    beforeEach(() => {
        jwtConfig = {
            login: notImplemented,
            getSecret: notImplemented,
            logout: notImplemented,
        };
        jwtModule = new JwtModule<Credentials, Payload>(jwtConfig);
        server = new ExpressServer();
        server
            .setJsonRoutes({
                "$errorHandlers": ["JWT_ERROR_HANDLER"],
                "/auth": "AuthModule",
                "/api": {
                    "$filters": ["JWT_FILTER"],
                    "/protected": {
                        "$controller": PublicController,
                    },
                },
            })
            .setModule("AuthModule", jwtModule)
            .dependencies(
                dependency("JWT_ERROR_HANDLER", { value: jwtModule.getJwtErrorHandler() }),
                dependency("JWT_FILTER", { value: jwtModule.getJwtFilter() }),
                PublicController
            );
        // Discard any error message logging
        server.getDependency<Logger>("Logger").setLevel(LoggerLevels.ALERT);
    });

    describe("#login", () => {
        let credentials: Credentials;
        let secret: string;
        beforeEach(() => {
            // This credentials will be used
            credentials = { username: "Dummy!", password: "Password!" };
            secret = "SHHH!";
            spyOn(jwtConfig, "getSecret").and.returnValue(secret);
        });
        describe("when credentials are valid", () => {
            let response: any;
            let payload: Payload;
            beforeEach((done: DoneFn) => {
                payload = { id: 1, name: "username", groups: ["group_1"] };
                // login is successful and returns a valid payload
                spyOn(jwtConfig, "login").and.returnValue(payload);
                // call!
                rq(server.getApp())
                    .post("/auth/login")
                    .send(credentials)
                    .expect(200)
                    .then((data) => { response = data.body; done(); })
                    .catch(done.fail);
            });
            it("login should have been called", () => {
                expect(jwtConfig.login).toHaveBeenCalledWith(credentials);
            });
            it("getSecret should have been called", () => {
                expect(jwtConfig.getSecret).toHaveBeenCalled();
            });
            it("jwt should be valid", () => {
                expect(response.jwt).toEqual(jwt.sign(payload, secret), "jwtoken is not valid!");
            });
        });
        describe("when credentials are invalid", () => {
            let request: rq.Test;
            beforeEach(() => {
                // login will fail
                spyOn(jwtConfig, "login").and.throwError("Invalid credentials!");
                request = rq(server.getApp()).post("/auth/login");
            });
            it("response should be a 401", (done: DoneFn) => {
                request.expect(401)
                    .then(res => {
                        expect(res.text).toEqual("AuthError: Unauthorized -> Error: Invalid credentials!");
                    })
                    .then(done)
                    .catch(done.fail);
            });
        });
    });

    describe("#validate", () => {
        describe("when we send a valid token", () => {
            let request: rq.Test;
            let payload: Payload;
            beforeEach(() => {
                payload = { id: 1, name: "username", groups: ["group_1"] };
                let secret = "SHHH!";
                let token = jwt.sign(payload, secret);
                spyOn(jwtConfig, "getSecret").and.returnValue(secret);
                request = rq(server.getApp()).get("/auth/validate").set("authorization", `Bearer ${token}`);
            });
            it("should return a 200", (done: DoneFn) => {
                request.expect(200).then(() => {
                    expect(jwtConfig.getSecret).toHaveBeenCalled();
                }).then(done).catch(done.fail);
            });
        });
        describe("when we send an invalid token", () => {
            let request: rq.Test;
            beforeEach(() => {
                let payload = { id: 1, name: "username", groups: ["group_1"] };
                let secret = "SHHH!";
                let token = jwt.sign(payload, secret);
                // we define a different secret so that the token signature is invalid
                spyOn(jwtConfig, "getSecret").and.returnValue("dunno!");
                request = rq(server.getApp()).get("/auth/validate").set("authorization", `Bearer ${token}`);
            });
            it("should return a 401", (done: DoneFn) => {
                request.expect(401).then(res => {
                    expect(res.text).toEqual("AuthError: Unauthorized -> JsonWebTokenError: invalid signature");
                }).then(done).catch(done.fail);
            });
        });
        describe("when we don't send a token in the headers", () => {
            let request: rq.Test;
            beforeEach(() => {
                request = rq(server.getApp()).get("/auth/validate");
            });
            it("request should send an 401", (done: DoneFn) => {
                request.expect(401).then(res => {
                    expect(res.text).toEqual("AuthError: Unauthorized -> Error: Authorization header not present!");
                }).then(done).catch(done.fail);
            });
        });
        describe("when we don't use the Bearer schema", () => {
            let request: rq.Test;
            beforeEach(() => {
                request = rq(server.getApp()).get("/auth/validate").set("Authorization", "valid.token");
            });
            it("request should send an 401", (done: DoneFn) => {
                request.expect(401).then(res => {
                    expect(res.text).toEqual("AuthError: Unauthorized -> Error: Should be using Bearer schema in the Authorization header");
                }).then(done).catch(done.fail);
            });
        });

    });

    describe("#logout", () => {
        let token: string;
        let payload: Payload;
        let secret: string;
        beforeEach(() => {
            payload = {
                id: 2,
                name: "username",
                groups: ["group_1"],
            };
            secret = "SHHH!";
            spyOn(jwtConfig, "getSecret").and.returnValue(secret);
            token = jwt.sign(payload, secret);
        });
        describe("when logout is successful", () => {
            let request: rq.Test;
            let logoutSpy: jasmine.Spy;
            beforeEach(() => {
                logoutSpy = spyOn(jwtConfig, "logout").and.callFake(() => undefined);
                request = rq(server.getApp()).get("/auth/logout").set("Authorization", `Bearer ${token}`);
            });
            it("should get ", (done: DoneFn) => {
                request.expect(200).then(res => {
                    let logoutCallArgs = logoutSpy.calls.mostRecent().args[0];
                    expect(logoutCallArgs).toEqual(jasmine.objectContaining(payload));
                }).then(done).catch(done.fail);
            });
        });
        describe("when logout throws an error", () => {
            let request: rq.Test;
            let logoutError: string;
            beforeEach(() => {
                logoutError = "Invalid logout";
                spyOn(jwtConfig, "logout").and.throwError(logoutError);
                request = rq(server.getApp()).get("/auth/logout").set("Authorization", `Bearer ${token}`);
            });
            it("should get ", (done: DoneFn) => {
                request.expect(401).then(done).catch(done.fail);
            });
        });
    });

});
