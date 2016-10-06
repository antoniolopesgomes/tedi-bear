import * as bodyParser from "body-parser";
import { Module, dependency, Filter, ErrorHandler } from "tedi/core";
import { ExpressMiddlewareFilter } from "tedi/express";
import {
    JWT_SERVICE_TOKEN,
    JWT_EXPRESS_TOKEN,
    JWT_CONFIG_TOKEN, JwtConfig,
    JWT_FILTER_TOKEN,
    JWT_ERROR_HANDLER_TOKEN
} from "./core";
import { DefaultJwtService } from "./jwt-service";
import { DefaultJwtErrorHandler } from "./jwt-error-handler";
import { DefaultJwtExpress } from "./jwt-express";
import { JwtFilter } from "./jwt-filter";
import { AuthDecorators, AuthDecoration } from "./jwt-decorators";

// Body parser to be used in auth module
const JSON_BODY_PARSER_TOKEN = "JSON_BODY_PARSER_TOKEN";
const JSON_BODY_PARSER_FILTER = new ExpressMiddlewareFilter(bodyParser.json());

export class JwtModule<TCredentials, TPayload> extends Module {

    private _decorators: AuthDecoration<TPayload>;

    constructor(jwtConfig: JwtConfig<TCredentials, TPayload>) {
        super();
        // set module routes
        this.setJsonRoutes({
            "$filters": [JSON_BODY_PARSER_TOKEN],
            "/login": {
                "post": [JWT_SERVICE_TOKEN, "login"],
            },
            "/logout": {
                "get": [JWT_SERVICE_TOKEN, "logout"],
            },
            "/validate": {
                "get": [JWT_SERVICE_TOKEN, "validate"],
            },
        });
        // set module dependencies
        this.dependencies(
            dependency(JWT_CONFIG_TOKEN, { value: jwtConfig }),
            dependency(JWT_EXPRESS_TOKEN, { class: DefaultJwtExpress }),
            dependency(JWT_SERVICE_TOKEN, { class: DefaultJwtService }),
            dependency(JSON_BODY_PARSER_TOKEN, { value: JSON_BODY_PARSER_FILTER }),
            dependency(JWT_FILTER_TOKEN, { class: JwtFilter }),
            dependency(JWT_ERROR_HANDLER_TOKEN, { class: DefaultJwtErrorHandler }),
        );
    }

    getJwtFilter(): Filter<TPayload> {
        return this.getDependency<Filter<TPayload>>(JWT_FILTER_TOKEN);
    }

    getJwtErrorHandler(): ErrorHandler {
        return this.getDependency<ErrorHandler>(JWT_ERROR_HANDLER_TOKEN);
    }

    getDecorators(): AuthDecoration<TPayload> {
        if (!this._decorators) {
            this._decorators = AuthDecorators(this.getDependency<JwtFilter<TPayload>>(JWT_FILTER_TOKEN));
        }
        return this._decorators;
    }

}
