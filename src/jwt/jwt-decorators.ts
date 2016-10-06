import * as express from "express";
import { AuthError, AuthErrorType } from "../lib";
import { JwtFilter, JwtFilterData } from "./jwt-filter";

export type AuthCheck<TPayload> = (payload: TPayload) => boolean;

export interface AuthDecoration<TPayload> {
    restrict: (validation: AuthCheck<TPayload>) => MethodDecorator;
}

export function AuthDecorators<TPayload>(jwtFilter: JwtFilter<TPayload>): AuthDecoration<TPayload> {

    function assertAuthorization(filterData: JwtFilterData<TPayload>, authorization: AuthCheck<TPayload>) {
        if (!filterData) {
            throw new AuthError(AuthErrorType.Forbidden, "Unauthorized", "Could not find jwt filter data.");
        }
        if (!authorization(filterData.payload)) {
            throw new AuthError(AuthErrorType.Forbidden, "Unauthorized", "Authorization check failed.");
        }
    }

    let restrictDecorator = (validation: AuthCheck<TPayload>) => {
        return function (target: Object, propertyKey: string | symbol, descriptor: TypedPropertyDescriptor<Function>) {
            let originalValue = descriptor.value;
            descriptor.value = (req: express.Request, res: express.Response) => {
                // Assert that the request is authorized
                assertAuthorization(jwtFilter.getDataFromRequest(req), validation);
                // Authorization assertions did not failed, the request is authorized
                return originalValue(req, res);
            };
        };
    };

    return <AuthDecoration<TPayload>> {
        restrict: (validation: AuthCheck<TPayload>) => restrictDecorator(validation),
    };
}
