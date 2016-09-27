import { Module, dependency } from "tedi/core";
import { TEDI_BEAR_VALIDATOR } from "./shared";

export class TediBearModule extends Module {

    init(): void {
        this
            .setJsonRoutes({
                "/login": {
                    "post": [TEDI_BEAR_VALIDATOR, "login"],
                },
                "/logout": {
                    "post": [TEDI_BEAR_VALIDATOR, "logout"],
                },
                "validate": {
                    "post": [TEDI_BEAR_VALIDATOR, "validate"],
                },
            })
            .dependencies(dependency(TEDI_BEAR_VALIDATOR, { value: {} }));
    }

};
