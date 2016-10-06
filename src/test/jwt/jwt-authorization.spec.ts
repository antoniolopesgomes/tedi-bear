import * as jwt from "jsonwebtoken";
import * as express from "express";
import * as rq from "supertest-as-promised";
import { ExpressServer } from "tedi/express";
import { dependency, Logger, LoggerLevels } from "tedi/core";
import { Injectable, web } from "tedi/decorators";
import { JwtConfig, JwtModule, AuthDecoration, AuthCheck } from "../../jwt";

describe("Authorization", () => {

    interface Credentials {
        username: string;
        password: string;
    }

    interface Payload {
        id: number;
    }

    let server: ExpressServer;
    let jwtConfig: JwtConfig<Credentials, Payload>;
    let jwtModule: JwtModule<Credentials, Payload>;
    let auth: AuthDecoration<Payload>;

    beforeEach(() => {
        /*
            Define jwt auth config.
            We are presuming that the authentication was already taken care of.
            login and logout can be ignored (they are only used when authenticating)
        */
        jwtConfig = {
            getSecret: () => "SHHH!",
            login: () => undefined,
            logout: () => undefined,
        };
        // Create jwt module 
        jwtModule = new JwtModule(jwtConfig);
        // Get decorators
        auth = jwtModule.getDecorators();
        // Create Express server
        server = new ExpressServer();
        server.setJsonRoutes({
            "/api": {
                "$filters": ["JWT_FILTER"],
                "$errorHandlers": ["JWT_ERROR_HANDLER"],
                "/public": {
                    "$controller": "PublicController",
                },
            },
        });
        server.dependencies(
            dependency("JWT_FILTER", { value: jwtModule.getJwtFilter() }),
            dependency("JWT_ERROR_HANDLER", { value: jwtModule.getJwtErrorHandler() }),
        );
        // turn off logging
        server.getDependency<Logger>("Logger").setLevel(LoggerLevels.ALERT);
    });

    describe("when we restrict an action", () => {
        let authCheck: AuthCheck<Payload>;
        let authCheckStub: AuthCheck<Payload>;
        beforeEach(() => {
            authCheckStub = (_payload) => authCheck(_payload);
            // Create a restricted controller
            @Injectable()
            class PublicController {
                @web.get() @auth.restrict(authCheckStub)
                get(req: express.Request, res: express.Response) {
                    res.status(200).end();
                }
            }
            // Add PublicController dependency to the server
            server.setDependency(dependency("PublicController", { class: PublicController }));
        });
        describe("to only authorize payloads with id === 1 ", () => {
            beforeEach(() => {
                authCheck = (_payload) => _payload.id === 1;
            });
            describe("and we do a request with an authorized token", () => {
                let authHeader: string;
                beforeEach(() => {
                    let payload = { id: 1 };
                    let token = jwt.sign(payload, jwtConfig.getSecret(null));
                    authHeader = `Bearer ${token}`;
                });
                it("request should be 'Ok'", (done: DoneFn) => {
                    rq(server.getApp())
                        .get("/api/public")
                        .set("Authorization", authHeader)
                        .expect(200).then(done).catch(done.fail);
                });
                describe("but we don't have a valid jwt filter installed in the server", () => {
                    beforeEach(() => {
                        @Injectable()
                        class DummyFilter {
                            apply() { return; }
                            getDataFromRequest() { return; }
                        }
                        server.dependencies(dependency("JWT_FILTER", { class: DummyFilter }));
                    });
                    it("request should be 'Forbidden'", (done: DoneFn) => {
                        rq(server.getApp())
                            .get("/api/public")
                            .set("Authorization", authHeader)
                            .expect(403).then(res => {
                                expect(res.text).toEqual("AuthError: Unauthorized -> Could not find jwt filter data.");
                            }).then(done).catch(done.fail);
                    });
                });
            });
            describe("and we do a request with an unauthorized token", () => {
                let request: rq.Test;
                beforeEach(() => {
                    let payload = { id: 2 };
                    let token = jwt.sign(payload, jwtConfig.getSecret(null));
                    request = rq(server.getApp()).get("/api/public").set("Authorization", `Bearer ${token}`);
                });
                it("request should be 'Forbidden'", (done: DoneFn) => {
                    request.expect(403).then(res => {
                        expect(res.text).toEqual("AuthError: Unauthorized -> Authorization check failed.");
                    }).then(done).catch(done.fail);
                });
            });
        });
    });
});
