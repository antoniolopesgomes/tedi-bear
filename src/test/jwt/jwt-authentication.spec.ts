import * as express from "express";
import * as rq from "supertest-as-promised";
import * as jwt from "jsonwebtoken";
import { JwtModule, JwtConfig } from "../../jwt";
import { ExpressServer } from "tedi/express";
import { Logger, LoggerLevels, dependency, Filter } from "tedi/core";
import { Injectable, web } from "tedi/decorators";

describe("when we try to access a protected api", () => {

    interface Credentials { username: string; password: string; }
    interface Payload { id: number; username: string; password: string; }

    @Injectable()
    class DummyController {
        @web.get()
        get(req: express.Request, res: express.Response) {
            res.status(200).end();
        }
    }

    let server: ExpressServer;
    let jwtConfig: JwtConfig<Credentials, Payload>;
    let jwtModule: JwtModule<Credentials, Payload>;

    beforeEach(() => {
        // Set jwt configuration
        jwtConfig = {
            getSecret: () => "SHHH!",
            login: () => undefined,
            logout: () => undefined,
        };
        // Create Auth module
        jwtModule = new JwtModule(jwtConfig);
        server = new ExpressServer();
        server
            .setJsonRoutes({
                "$filters": ["JWT_FILTER"],
                "$errorHandlers": ["JWT_ERROR_HANDLER"],
                "/api": {
                    "/protected": { "$controller": DummyController },
                },
            })
            .dependencies(
                DummyController,
                dependency("JWT_FILTER", { value: jwtModule.getJwtFilter() }),
                dependency("JWT_ERROR_HANDLER", { value: jwtModule.getJwtErrorHandler() }),
            );
        // turn off logging
        server.getDependency<Logger>("Logger").setLevel(LoggerLevels.ALERT);
    });
    describe("and we don't are authenticated", () => {
        let request: rq.Test;
        beforeEach(() => {
            request = rq(server.getApp()).get("/api/protected");
        });
        it("request should be 'Unauthorized' 401", (done: DoneFn) => {
            request.expect(401).then(done).catch(done.fail);
        });
    });
    describe("and we are authenticated", () => {
        let token: string;
        let authHeader: string;
        let payload: any;
        let dummyController: DummyController;
        let dummyGetSpy: jasmine.Spy;
        let jwtFilter: Filter<any>;
        beforeEach(() => {
            payload = { id: 1, user: "username" };
            token = jwt.sign(payload, jwtConfig.getSecret(null));
            authHeader = `Bearer ${token}`;
            dummyController = server.getDependency(DummyController);
            jwtFilter = server.getDependency<Filter<any>>("JWT_FILTER");
            dummyGetSpy = spyOn(dummyController, "get").and.callThrough();
        });
        it("request should be 'OK", (done: DoneFn) => {
            rq(server.getApp())
                .get("/api/protected").set("authorization", `Bearer ${token}`)
                .expect(200)
                .then(done).catch(done.fail);
        });
        it("jwt filter should have the correct payload", (done: DoneFn) => {
            rq(server.getApp()).get("/api/protected").set("authorization", `Bearer ${token}`)
                .then(() => {
                    expect(dummyGetSpy).toHaveBeenCalledTimes(1);
                    let req: express.Request = dummyGetSpy.calls.mostRecent().args[0];
                    expect(jwtFilter.getDataFromRequest(req)).toEqual({
                        token: token,
                        payload: jasmine.objectContaining(payload),
                    });
                }).then(done).catch(done.fail);
        });
    });
});
