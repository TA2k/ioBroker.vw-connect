// @ts-nocheck
"use strict";

/*
 * Created with @iobroker/create-adapter v1.17.0
 */

// The adapter-core module gives you access to the core ioBroker functions
// you need to create an adapter
const utils = require("@iobroker/adapter-core");

const request = require("request");
const crypto = require("crypto");
const { Crypto } = require("@peculiar/webcrypto");
const { v4: uuidv4 } = require("uuid");
const traverse = require("traverse");
const { extractKeys } = require("./lib/extractKeys");
class VwWeconnect extends utils.Adapter {
    /**
     * @param {Partial<ioBroker.AdapterOptions>} [options={}]
     */
    constructor(options) {
        super({
            ...options,
            name: "vw-connect",
        });
        this.on("ready", this.onReady.bind(this));
        // this.on("objectChange", this.onObjectChange.bind(this));
        this.on("stateChange", this.onStateChange.bind(this));
        // this.on("message", this.onMessage.bind(this));
        this.on("unload", this.onUnload.bind(this));
        this.extractKeys = extractKeys;

        this.jar = request.jar();

        this.refreshTokenInterval = null;
        this.vwrefreshTokenInterval = null;
        this.updateInterval = null;
        this.fupdateInterval = null;
        this.refreshTokenTimeout = null;

        this.homeRegion = {};
        this.homeRegionSetter = {};

        this.vinArray = [];
        this.etags = {};

        this.statesArray = [
            {
                url: "$homeregion/fs-car/bs/departuretimer/v1/$type/$country/vehicles/$vin/timer",
                path: "timer",
                element: "timer",
            },
            {
                url: "$homeregion/fs-car/bs/climatisation/v1/$type/$country/vehicles/$vin/climater",
                path: "climater",
                element: "climater",
            },
            {
                url: "$homeregion/fs-car/bs/cf/v1/$type/$country/vehicles/$vin/position",
                path: "position",
                element: "storedPositionResponse",
                element2: "position",
                element3: "findCarResponse",
                element4: "Position",
            },
            {
                url: "$homeregion/fs-car/bs/tripstatistics/v1/$type/$country/vehicles/$vin/tripdata/$tripType?type=list",
                path: "tripdata",
                element: "tripDataList",
            },
            {
                url: "$homeregion/fs-car/bs/vsr/v1/$type/$country/vehicles/$vin/status",
                path: "status",
                element: "StoredVehicleDataResponse",
                element2: "vehicleData",
            },
            {
                url: "$homeregion/fs-car/destinationfeedservice/mydestinations/v1/$type/$country/vehicles/$vin/destinations",
                path: "destinations",
                element: "destinations",
            },
            {
                url: "$homeregion/fs-car/bs/batterycharge/v1/$type/$country/vehicles/$vin/charger",
                path: "charger",
                element: "charger",
            },
            {
                url: "$homeregion/fs-car/bs/rs/v1/$type/$country/vehicles/$vin/status",
                path: "remoteStandheizung",
                element: "statusResponse",
            },
            {
                url: "$homeregion/fs-car/bs/dwap/v1/$type/$country/vehicles/$vin/history",
                path: "history",
            },
        ];
    }

    /**
     * Is called when databases are connected and adapter received configuration.
     */
    async onReady() {
        // Initialize your adapter here

        this.setState("info.connection", false, true);
        // Reset the connection indicator during startup
        this.type = "VW";
        this.country = "DE";
        this.clientId = "9496332b-ea03-4091-a224-8c746b885068%40apps_vw-dilab_com";
        this.xclientId = "38761134-34d0-41f3-9a73-c4be88d7d337";
        this.scope = "openid%20profile%20mbb%20email%20cars%20birthdate%20badge%20address%20vin";
        this.redirect = "carnet%3A%2F%2Fidentity-kit%2Flogin";
        this.xrequest = "de.volkswagen.carnet.eu.eremote";
        this.responseType = "id_token%20token%20code";
        this.xappversion = "5.1.2";
        this.xappname = "eRemote";
        if (this.config.type === "id") {
            this.type = "Id";
            this.country = "DE";
            this.clientId = "a24fba63-34b3-4d43-b181-942111e6bda8@apps_vw-dilab_com";
            this.xclientId = "";
            this.scope = "openid profile badge cars dealers birthdate vin";
            this.redirect = "weconnect://authenticated";
            this.xrequest = "com.volkswagen.weconnect";
            this.responseType = "code id_token token";
            this.xappversion = "";
            this.xappname = "";
        }
        if (this.config.type === "skoda") {
            this.type = "Skoda";
            this.country = "CZ";
            this.clientId = "7f045eee-7003-4379-9968-9355ed2adb06%40apps_vw-dilab_com";
            this.xclientId = "28cd30c6-dee7-4529-a0e6-b1e07ff90b79";
            this.scope = "openid%20profile%20phone%20address%20cars%20email%20birthdate%20badge%20dealers%20driversLicense%20mbb";
            this.redirect = "skodaconnect%3A%2F%2Foidc.login%2F";
            this.xrequest = "cz.skodaauto.connect";
            this.responseType = "code%20id_token";
            this.xappversion = "3.2.6";
            this.xappname = "cz.skodaauto.connect";
        }
        if (this.config.type === "seat") {
            this.type = "Seat";
            this.country = "ES";
            this.clientId = "50f215ac-4444-4230-9fb1-fe15cd1a9bcc@apps_vw-dilab_com";
            this.xclientId = "9dcc70f0-8e79-423a-a3fa-4065d99088b4";
            this.scope = "openid profile mbb cars birthdate nickname address phone";
            this.redirect = "seatconnect://identity-kit/login";
            this.xrequest = "cz.skodaauto.connect";
            this.responseType = "code%20id_token";
            this.xappversion = "1.1.29";
            this.xappname = "SEATConnect";
        }
        if (this.config.type === "vwv2") {
            this.type = "VW";
            this.country = "DE";
            this.clientId = "9496332b-ea03-4091-a224-8c746b885068@apps_vw-dilab_com";
            this.xclientId = "89312f5d-b853-4965-a471-b0859ee468af";
            this.scope = "openid profile mbb cars birthdate nickname address phone";
            this.redirect = "carnet://identity-kit/login";
            this.xrequest = "de.volkswagen.car-net.eu.e-remote";
            this.responseType = "id_token%20token%20code";
            this.xappversion = "5.6.7";
            this.xappname = "We Connect";
        }
        if (this.config.type === "audi") {
            this.type = "Audi";
            this.country = "DE";
            this.clientId = "09b6cbec-cd19-4589-82fd-363dfa8c24da@apps_vw-dilab_com";
            this.xclientId = "77869e21-e30a-4a92-b016-48ab7d3db1d8";
            this.scope = "address profile badge birthdate birthplace nationalIdentifier nationality profession email vin phone nickname name picture mbb gallery openid";
            this.redirect = "myaudi:///";
            this.xrequest = "de.myaudi.mobile.assistant";
            this.responseType = "token%20id_token";
            // this.responseType = "code";
            this.xappversion = "3.22.0";
            this.xappname = "myAudi";
        }
        if (this.config.type === "go") {
            this.type = "";
            this.country = "";
            this.clientId = "ac42b0fa-3b11-48a0-a941-43a399e7ef84@apps_vw-dilab_com";
            this.xclientId = "";
            this.scope = "openid%20profile%20address%20email%20phone";
            this.redirect = "vwconnect%3A%2F%2Fde.volkswagen.vwconnect%2Foauth2redirect%2Fidentitykit";
            this.xrequest = "";
            this.responseType = "code";
            this.xappversion = "";
            this.xappname = "";
        }
        if (this.config.interval === 0) {
            this.log.info("Interval of 0 is not allowed reset to 1");
            this.config.interval = 1;
        }
        this.tripTypes = [];
        if (this.config.tripShortTerm == true) {
            this.tripTypes.push("shortTerm");
        }
        if (this.config.tripLongTerm == true) {
            this.tripTypes.push("longTerm");
        }
        if (this.config.tripCyclic == true) {
            this.tripTypes.push("cyclic");
        }
        this.login()
            .then(() => {
                this.log.debug("Login successful");
                this.setState("info.connection", true, true);
                this.getPersonalData()
                    .then(() => {
                        this.getVehicles()
                            .then(() => {
                                if (this.config.type !== "go") {
                                    this.vinArray.forEach((vin) => {
                                        if (this.config.type === "id") {
                                            this.getIdStatus(vin).catch(() => {
                                                this.log.error("get id status Failed");
                                            });
                                        } else {
                                            this.getHomeRegion(vin)
                                                .catch(() => {
                                                    this.log.debug("get home region Failed " + vin);
                                                })
                                                .finally(() => {
                                                    this.getVehicleData(vin).catch(() => {
                                                        this.log.error("get vehicle data Failed");
                                                    });
                                                    this.getVehicleRights(vin).catch(() => {
                                                        this.log.error("get vehicle rights Failed");
                                                    });
                                                    this.requestStatusUpdate(vin)
                                                        .finally(() => {
                                                            this.statesArray.forEach((state) => {
                                                                if (state.path == "tripdata") {
                                                                    this.tripTypes.forEach((tripType) => {
                                                                        this.getVehicleStatus(
                                                                            vin,
                                                                            state.url,
                                                                            state.path,
                                                                            state.element,
                                                                            state.element2,
                                                                            state.element3,
                                                                            state.element4,
                                                                            tripType
                                                                        ).catch(() => {
                                                                            this.log.debug("error while getting " + state.url);
                                                                        });
                                                                    });
                                                                } else {
                                                                    this.getVehicleStatus(vin, state.url, state.path, state.element, state.element2, state.element3, state.element4).catch(() => {
                                                                        this.log.debug("error while getting " + state.url);
                                                                    });
                                                                }
                                                            });
                                                        })
                                                        .catch(() => {
                                                            this.log.error("status update Failed " + vin);
                                                        });
                                                })
                                                .catch(() => {
                                                    this.log.error("Error getting home region");
                                                });
                                        }
                                    });
                                }

                                this.updateInterval = setInterval(() => {
                                    if (this.config.type === "go") {
                                        this.getVehicles();
                                        return;
                                    } else if (this.config.type === "id") {
                                        this.vinArray.forEach((vin) => {
                                            this.getIdStatus(vin).catch(() => {
                                                this.log.error("get id status Failed");
                                                this.refreshIDToken().catch(() => {});
                                            });
                                            this.getWcData();
                                        });
                                        return;
                                    } else {
                                        this.vinArray.forEach((vin) => {
                                            this.statesArray.forEach((state) => {
                                                if (state.path == "tripdata") {
                                                    this.tripTypes.forEach((tripType) => {
                                                        this.getVehicleStatus(vin, state.url, state.path, state.element, state.element2, null, null, tripType).catch(() => {
                                                            this.log.debug("error while getting " + state.url);
                                                        });
                                                    });
                                                } else {
                                                    this.getVehicleStatus(vin, state.url, state.path, state.element, state.element2).catch(() => {
                                                        this.log.debug("error while getting " + state.url);
                                                    });
                                                }
                                            });
                                        });
                                    }
                                }, this.config.interval * 60 * 1000);

                                if (this.config.type !== "id") {
                                    if (this.config.forceinterval > 0) {
                                        this.fupdateInterval = setInterval(() => {
                                            if (this.config.type === "go") {
                                                this.getVehicles();
                                                return;
                                            }
                                            this.vinArray.forEach((vin) => {
                                                this.requestStatusUpdate(vin).catch(() => {
                                                    this.log.error("force status update Failed");
                                                });
                                            });
                                        }, this.config.forceinterval * 60 * 1000);
                                    }
                                }
                            })
                            .catch(() => {
                                this.log.error("Get Vehicles Failed");
                            });
                    })
                    .catch(() => {
                        this.log.error("get personal data Failed");
                    });
            })
            .catch(() => {
                this.log.error("Login Failed");
            });
        this.subscribeStates("*");
    }
    login() {
        return new Promise(async (resolve, reject) => {
            const nonce = this.getNonce();
            const state = uuidv4();

            const [code_verifier, codeChallenge] = this.getCodeChallenge();

            const method = "GET";
            const form = {};
            let url =
                "https://identity.vwgroup.io/oidc/v1/authorize?client_id=" +
                this.clientId +
                "&scope=" +
                this.scope +
                "&response_type=" +
                this.responseType +
                "&redirect_uri=" +
                this.redirect +
                "&nonce=" +
                nonce +
                "&state=" +
                state;
            if (this.config.type === "vw" || this.config.type === "vwv2" || this.config.type === "go") {
                url += "&code_challenge=" + codeChallenge + "&code_challenge_method=S256";
            }
            if (this.config.type === "audi") {
                url += "&ui_locales=de-DE%20de&prompt=login";
            }
            if (this.config.type === "id" && this.type !== "Wc") {
                url = await this.receiveLoginUrl().catch(() => {
                    this.log.warn("Failed to get login url");
                });
                if (!url) {
                    url = "https://login.apps.emea.vwapps.io/authorize?nonce=" + this.randomString(16) + "&redirect_uri=weconnect://authenticated";
                }
            }
            const loginRequest = request(
                {
                    method: method,
                    url: url,
                    headers: {
                        "User-Agent": "Mozilla/5.0 (Linux; Android 10) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/74.0.3729.185 Mobile Safari/537.36",
                        Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3",
                        "Accept-Language": "en-US,en;q=0.9",
                        "Accept-Encoding": "gzip, deflate",
                        "x-requested-with": this.xrequest,
                        "upgrade-insecure-requests": 1,
                    },
                    jar: this.jar,
                    form: form,
                    gzip: true,
                    followAllRedirects: true,
                },
                (err, resp, body) => {
                    if (err || (resp && resp.statusCode >= 400)) {
                        if (this.type === "Wc") {
                            if (err && err.message === "Invalid protocol: wecharge:") {
                                this.log.debug("Found WeCharge connection");
                                this.getTokens(loginRequest, code_verifier, reject, resolve);
                            } else {
                                this.log.debug("No WeCharge found, cancel login");
                                resolve();
                            }
                            return;
                        }
                        if (err && err.message.indexOf("Invalid protocol:") !== -1) {
                            this.log.debug("Found Token");
                            this.getTokens(loginRequest, code_verifier, reject, resolve);
                            return;
                        }
                        this.log.error("Failed in first login step ");
                        err && this.log.error(err);
                        err && this.log.error(JSON.stringify(err));
                        resp && this.log.error(resp.statusCode.toString());
                        body && this.log.error(JSON.stringify(body));

                        loginRequest && loginRequest.uri && loginRequest.uri.query && this.log.debug(loginRequest.uri.query.toString());
                        reject();
                        return;
                    }

                    try {
                        let form = {};
                        if (body.indexOf("emailPasswordForm") !== -1) {
                            this.log.debug("parseEmailForm");
                            form = this.extractHidden(body);
                            form["email"] = this.config.user;
                        } else {
                            this.log.error("No Login Form found for type: " + this.type);
                            this.log.debug(JSON.stringify(body));
                            reject();
                            return;
                        }
                        request.post(
                            {
                                url: "https://identity.vwgroup.io/signin-service/v1/" + this.clientId + "/login/identifier",
                                headers: {
                                    "Content-Type": "application/x-www-form-urlencoded",
                                    "User-Agent": "Mozilla/5.0 (Linux; Android 10) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/74.0.3729.185 Mobile Safari/537.36",
                                    Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3",
                                    "Accept-Language": "en-US,en;q=0.9",
                                    "Accept-Encoding": "gzip, deflate",
                                    "x-requested-with": this.xrequest,
                                },
                                form: form,
                                jar: this.jar,
                                gzip: true,
                                followAllRedirects: true,
                            },
                            (err, resp, body) => {
                                if (err || (resp && resp.statusCode >= 400)) {
                                    this.log.error("Failed to get login identifier");
                                    err && this.log.error(err);
                                    resp && this.log.error(resp.statusCode.toString());
                                    body && this.log.error(JSON.stringify(body));
                                    reject();
                                    return;
                                }
                                try {
                                    if (body.indexOf("credentialsForm") !== -1) {
                                        this.log.debug("credentialsForm");
                                        form = this.extractHidden(body);
                                        form["password"] = this.config.password;
                                    } else {
                                        this.log.error("No Login Form found. Please check your E-Mail in the app.");
                                        this.log.debug(JSON.stringify(body));
                                        reject();
                                        return;
                                    }
                                    request.post(
                                        {
                                            url: "https://identity.vwgroup.io/signin-service/v1/" + this.clientId + "/login/authenticate",
                                            headers: {
                                                "Content-Type": "application/x-www-form-urlencoded",
                                                "User-Agent": "Mozilla/5.0 (Linux; Android 10) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/74.0.3729.185 Mobile Safari/537.36",
                                                Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3",
                                                "Accept-Language": "en-US,en;q=0.9",
                                                "Accept-Encoding": "gzip, deflate",
                                                "x-requested-with": this.xrequest,
                                            },
                                            form: form,
                                            jar: this.jar,
                                            gzip: true,
                                            followAllRedirects: false,
                                        },
                                        (err, resp, body) => {
                                            if (err || (resp && resp.statusCode >= 400)) {
                                                this.log.error("Failed to get login authenticate");
                                                err && this.log.error(err);
                                                resp && this.log.error(resp.statusCode.toString());
                                                body && this.log.error(JSON.stringify(body));
                                                reject();
                                                return;
                                            }

                                            try {
                                                this.log.debug(JSON.stringify(body));
                                                this.log.debug(JSON.stringify(resp.headers));

                                                if (resp.headers.location.split("&").length <= 2 || resp.headers.location.indexOf("/terms-and-conditions?") !== -1) {
                                                    this.log.warn(resp.headers.location);
                                                    this.log.warn("No valid userid, please visit this link or logout and login in your app account:");
                                                    this.log.warn("https://" + resp.request.host + resp.headers.location);
                                                    this.log.warn("Try to auto accept new consent");

                                                    request.get(
                                                        {
                                                            url: "https://" + resp.request.host + resp.headers.location,
                                                            jar: this.jar,
                                                            headers: {
                                                                "User-Agent":
                                                                    "Mozilla/5.0 (Linux; Android 10) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/74.0.3729.185 Mobile Safari/537.36",
                                                                Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3",
                                                                "Accept-Language": "en-US,en;q=0.9",
                                                                "Accept-Encoding": "gzip, deflate",
                                                                "x-requested-with": this.xrequest,
                                                            },
                                                            followAllRedirects: true,
                                                            gzip: true,
                                                        },
                                                        (err, resp, body) => {
                                                            this.log.debug(body);

                                                            const form = this.extractHidden(body);
                                                            const url = "https://" + resp.request.host + resp.req.path.split("?")[0];
                                                            this.log.debug(JSON.stringify(form));
                                                            request.post(
                                                                {
                                                                    url: url,
                                                                    jar: this.jar,
                                                                    headers: {
                                                                        "Content-Type": "application/x-www-form-urlencoded",
                                                                        "User-Agent":
                                                                            "Mozilla/5.0 (Linux; Android 10) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/74.0.3729.185 Mobile Safari/537.36",
                                                                        Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3",
                                                                        "Accept-Language": "en-US,en;q=0.9",
                                                                        "Accept-Encoding": "gzip, deflate",
                                                                        "x-requested-with": this.xrequest,
                                                                    },
                                                                    form: form,
                                                                    followAllRedirects: true,
                                                                    gzip: true,
                                                                },
                                                                (err, resp, body) => {
                                                                    if ((err && err.message.indexOf("Invalid protocol:") !== -1) || (resp && resp.statusCode >= 400)) {
                                                                        this.log.warn("Failed to auto accept");
                                                                        err && this.log.error(err);
                                                                        resp && this.log.error(resp.statusCode.toString());
                                                                        body && this.log.error(JSON.stringify(body));
                                                                        reject();
                                                                        return;
                                                                    }
                                                                    this.log.info("Auto accept succesful. Restart adapter in 10sec");
                                                                    setTimeout(() => {
                                                                        this.restart();
                                                                    }, 10 * 1000);
                                                                }
                                                            );
                                                        }
                                                    );

                                                    reject();
                                                    return;
                                                }
                                                this.config.userid = resp.headers.location.split("&")[2].split("=")[1];
                                                if (!this.stringIsAValidUrl(resp.headers.location)) {
                                                    if (resp.headers.location.indexOf("&error=") !== -1) {
                                                        const location = resp.headers.location;
                                                        this.log.error("Error: " + location.substring(location.indexOf("error="), location.length - 1));
                                                    } else {
                                                        this.log.error("No valid login url, please download the log and visit:");
                                                        this.log.error("http://" + resp.request.host + resp.headers.location);
                                                    }
                                                    reject();
                                                    return;
                                                }

                                                let getRequest = request.get(
                                                    {
                                                        url: resp.headers.location || "",
                                                        headers: {
                                                            "User-Agent":
                                                                "Mozilla/5.0 (Linux; Android 10) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/74.0.3729.185 Mobile Safari/537.36",
                                                            Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3",
                                                            "Accept-Language": "en-US,en;q=0.9",
                                                            "Accept-Encoding": "gzip, deflate",
                                                            "x-requested-with": this.xrequest,
                                                        },
                                                        jar: this.jar,
                                                        gzip: true,
                                                        followAllRedirects: true,
                                                    },
                                                    (err, resp, body) => {
                                                        if (err) {
                                                            this.log.debug(err);
                                                            this.getTokens(getRequest, code_verifier, reject, resolve);
                                                        } else {
                                                            this.log.debug("No Token received visiting url and accept the permissions.");
                                                            const form = this.extractHidden(body);
                                                            getRequest = request.post(
                                                                {
                                                                    url: getRequest.uri.href,
                                                                    headers: {
                                                                        "Content-Type": "application/x-www-form-urlencoded",
                                                                        "User-Agent":
                                                                            "Mozilla/5.0 (Linux; Android 10) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/74.0.3729.185 Mobile Safari/537.36",
                                                                        Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3",
                                                                        "Accept-Language": "en-US,en;q=0.9",
                                                                        "Accept-Encoding": "gzip, deflate",
                                                                        "x-requested-with": this.xrequest,
                                                                        referer: getRequest.uri.href,
                                                                    },
                                                                    form: form,
                                                                    jar: this.jar,
                                                                    gzip: true,
                                                                    followAllRedirects: true,
                                                                },
                                                                (err, resp, body) => {
                                                                    if (err) {
                                                                        this.getTokens(getRequest, code_verifier, reject, resolve);
                                                                    } else {
                                                                        this.log.error("No Token received.");
                                                                        try {
                                                                            this.log.debug(JSON.stringify(body));
                                                                        } catch (err) {
                                                                            this.log.error(err);
                                                                            reject();
                                                                        }
                                                                    }
                                                                }
                                                            );
                                                        }
                                                    }
                                                );
                                            } catch (err2) {
                                                this.log.error("Login was not successful, please check your login credentials and selected type");
                                                err && this.log.error(err);
                                                this.log.error(err2);
                                                this.log.error(err2.stack);
                                                reject();
                                            }
                                        }
                                    );
                                } catch (err) {
                                    this.log.error(err);
                                    reject();
                                }
                            }
                        );
                    } catch (err) {
                        this.log.error(err);
                        reject();
                    }
                }
            );
        });
    }
    receiveLoginUrl() {
        return new Promise((resolve, reject) => {
            request(
                {
                    method: "GET",
                    url: "https://login.apps.emea.vwapps.io/authorize?nonce=" + this.randomString(16) + "&redirect_uri=weconnect://authenticated",
                    headers: {
                        Host: "login.apps.emea.vwapps.io",
                        "user-agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 14_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0.1 Mobile/15E148 Safari/604.1",
                        accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                        "accept-language": "de-de",
                    },
                    jar: this.jar,
                    gzip: true,
                    followAllRedirects: false,
                },
                (err, resp, body) => {
                    if (err || (resp && resp.statusCode >= 400)) {
                        this.log.error("Failed in receive login url ");
                        err && this.log.error(err);
                        resp && this.log.error(resp.statusCode.toString());
                        body && this.log.error(JSON.stringify(body));
                        reject();
                        return;
                    }
                    resolve(resp.request.href);
                }
            );
        });
    }
    replaceVarInUrl(url, vin, tripType) {
        const curHomeRegion = this.homeRegion[vin];
        return url
            .replace("/$vin", "/" + vin + "")
            .replace("$homeregion/", curHomeRegion + "/")
            .replace("/$type/", "/" + this.type + "/")
            .replace("/$country/", "/" + this.country + "/")
            .replace("/$tripType", "/" + tripType);
    }
    getTokens(getRequest, code_verifier, reject, resolve) {
        let hash = "";
        if (getRequest.uri.hash) {
            hash = getRequest.uri.hash;
        } else {
            hash = getRequest.uri.query;
        }
        const hashArray = hash.split("&");
        // eslint-disable-next-line no-unused-vars
        let state;
        let jwtauth_code;
        let jwtaccess_token;
        let jwtid_token;
        let jwtstate;
        hashArray.forEach((hash) => {
            const harray = hash.split("=");
            if (harray[0] === "#state" || harray[0] === "state") {
                state = harray[1];
            }
            if (harray[0] === "code") {
                jwtauth_code = harray[1];
            }
            if (harray[0] === "access_token") {
                jwtaccess_token = harray[1];
            }
            if (harray[0] === "id_token") {
                jwtid_token = harray[1];
            }
            if (harray[0] === "#state") {
                jwtstate = harray[1];
            }
        });
        // const state = hashArray[0].substring(hashArray[0].indexOf("=") + 1);
        // const jwtauth_code = hashArray[1].substring(hashArray[1].indexOf("=") + 1);
        // const jwtaccess_token = hashArray[2].substring(hashArray[2].indexOf("=") + 1);
        // const jwtid_token = hashArray[5].substring(hashArray[5].indexOf("=") + 1);
        let method = "POST";
        let body = "auth_code=" + jwtauth_code + "&id_token=" + jwtid_token;
        let url = "https://tokenrefreshservice.apps.emea.vwapps.io/exchangeAuthCode";
        let headers = {
            // "user-agent": "okhttp/3.7.0",
            "X-App-version": this.xappversion,
            "content-type": "application/x-www-form-urlencoded",
            "x-app-name": this.xappname,
            accept: "application/json",
        };
        if (this.config.type === "vw" || this.config.type === "vwv2") {
            body += "&code_verifier=" + code_verifier;
        } else {
            body += "&brand=" + this.config.type;
        }
        if (this.config.type === "go") {
            url = "https://dmp.apps.emea.vwapps.io/mobility-platform/token";
            body =
                "code=" +
                jwtauth_code +
                "&client_id=" +
                this.clientId +
                "&redirect_uri=vwconnect://de.volkswagen.vwconnect/oauth2redirect/identitykit&grant_type=authorization_code&code_verifier=" +
                code_verifier;
        }
        if (this.config.type === "id") {
            url = "https://login.apps.emea.vwapps.io/login/v1";
            let redirerctUri = "weconnect://authenticated";

            body = JSON.stringify({
                state: jwtstate,
                id_token: jwtid_token,
                redirect_uri: redirerctUri,
                region: "emea",
                access_token: jwtaccess_token,
                authorizationCode: jwtauth_code,
            });
            // @ts-ignore
            headers = {
                accept: "*/*",
                "content-type": "application/json",
                "x-newrelic-id": "VgAEWV9QDRAEXFlRAAYPUA==",
                "user-agent": "WeConnect/5 CFNetwork/1206 Darwin/20.1.0",
                "accept-language": "de-de",
            };
            if (this.type === "Wc") {
                method = "GET";
                url = "https://wecharge.apps.emea.vwapps.io/user-identity/v1/identity/login?redirect_uri=wecharge://authenticated&code=" + jwtauth_code;
                redirerctUri = "wecharge://authenticated";
                headers["x-api-key"] = "yabajourasW9N8sm+9F/oP==";
            }
        }
        if (this.config.type === "audi") {
            this.getVWToken({}, jwtid_token, reject, resolve);
            return;
        }
        request(
            {
                method: method,
                url: url,
                headers: headers,
                body: body,
                jar: this.jar,
                gzip: true,
                followAllRedirects: false,
            },
            (err, resp, body) => {
                if (err || (resp && resp.statusCode >= 400)) {
                    this.log.error("Failed to get token");
                    err && this.log.error(err);
                    resp && this.log.error(resp.statusCode.toString());
                    body && this.log.error(JSON.stringify(body));
                    reject();
                    return;
                }
                try {
                    const tokens = JSON.parse(body);

                    this.getVWToken(tokens, jwtid_token, reject, resolve);
                } catch (err) {
                    this.log.error(err);
                    reject();
                }
            }
        );
    }

    getVWToken(tokens, jwtid_token, reject, resolve) {
        if (this.config.type !== "audi") {
            if (this.config.type === "id") {
                if (this.type === "Wc") {
                    this.config.wc_access_token = tokens.wc_access_token;
                    this.config.wc_refresh_token = tokens.refresh_token;
                    this.log.debug("Wallcharging login successfull");
                    this.getWcData(100);
                    resolve();
                    return;
                }
                this.config.atoken = tokens.accessToken;
                this.config.rtoken = tokens.refreshToken;

                //configure for wallcharging login

                this.refreshTokenInterval = setInterval(() => {
                    this.refreshIDToken().catch(() => {});
                }, 0.9 * 60 * 60 * 1000); // 0.9hours

                //this.config.type === "wc"
                this.type = "Wc";
                this.country = "DE";
                this.clientId = "0fa5ae01-ebc0-4901-a2aa-4dd60572ea0e@apps_vw-dilab_com";
                this.xclientId = "";
                this.scope = "openid profile address email";
                this.redirect = "wecharge://authenticated";
                this.xrequest = "com.volkswagen.weconnect";
                this.responseType = "code id_token token";
                this.xappversion = "";
                this.xappname = "";
                this.login().catch(() => {
                    this.log.warn("Failled wall charger login");
                });
                resolve();
                return;
            }

            this.config.atoken = tokens.access_token;
            this.config.rtoken = tokens.refresh_token;
            this.refreshTokenInterval = setInterval(() => {
                this.refreshToken().catch(() => {
                    this.log.error("Refresh Token was not successful");
                });
            }, 0.9 * 60 * 60 * 1000); // 0.9hours
        }
        if (this.config.type === "go" || this.config.type === "id") {
            resolve();
            return;
        }
        request.post(
            {
                url: "https://mbboauth-1d.prd.ece.vwg-connect.com/mbbcoauth/mobile/oauth2/v1/token",
                headers: {
                    "User-Agent": "okhttp/3.7.0",
                    "X-App-Version": this.xappversion,
                    "X-App-Name": this.xappname,
                    "X-Client-Id": this.xclientId,
                    Host: "mbboauth-1d.prd.ece.vwg-connect.com",
                },
                form: {
                    grant_type: "id_token",
                    token: jwtid_token,
                    scope: "sc2:fal",
                },
                jar: this.jar,
                gzip: true,
                followAllRedirects: true,
            },
            (err, resp, body) => {
                if (err || (resp && resp.statusCode >= 400)) {
                    this.log.error("Failed to get VWToken");
                    err && this.log.error(err);
                    resp && this.log.error(resp.statusCode.toString());
                    body && this.log.error(JSON.stringify(body));
                    resolve();
                    return;
                }
                try {
                    const tokens = JSON.parse(body);
                    this.config.vwatoken = tokens.access_token;
                    this.config.vwrtoken = tokens.refresh_token;
                    this.vwrefreshTokenInterval = setInterval(() => {
                        this.refreshToken(true).catch(() => {
                            this.log.error("Refresh Token was not successful");
                        });
                    }, 0.9 * 60 * 60 * 1000); //0.9hours
                    resolve();
                } catch (err) {
                    this.log.error(err);
                    reject();
                }
            }
        );
    }

    refreshToken(isVw) {
        let url = "https://tokenrefreshservice.apps.emea.vwapps.io/refreshTokens";
        let rtoken = this.config.rtoken;
        let body = "refresh_token=" + rtoken;
        let form = "";
        body = "brand=" + this.config.type + "&" + body;

        if (isVw) {
            url = "https://mbboauth-1d.prd.ece.vwg-connect.com/mbbcoauth/mobile/oauth2/v1/token";
            rtoken = this.config.vwrtoken;
            body = "grant_type=refresh_token&scope=sc2%3Afal&token=" + rtoken; //+ "&vin=" + vin;
        } else if (this.config.type === "go") {
            url = "https://dmp.apps.emea.vwapps.io/mobility-platform/token";
            body = "";
            // @ts-ignore
            form = {
                scope: "openid+profile+address+email+phone",
                client_id: this.clientId,
                grant_type: "refresh_token",
                refresh_token: rtoken,
            };
        }
        return new Promise((resolve, reject) => {
            this.log.debug("refreshToken ");
            this.log.debug(isVw ? "vw" : "");
            request.post(
                {
                    url: url,
                    headers: {
                        "user-agent": "okhttp/3.7.0",
                        "content-type": "application/x-www-form-urlencoded",
                        "X-App-version": this.xappversion,
                        "X-App-name": this.xappname,
                        "X-Client-Id": this.xclientId,
                        accept: "application/json",
                    },
                    body: body,
                    form: form,
                    gzip: true,
                    followAllRedirects: true,
                },
                (err, resp, body) => {
                    if (err || (resp && resp.statusCode >= 400)) {
                        this.log.error("Failing to refresh token. ");
                        this.log.error(isVw ? "VwToken" : "");
                        err && this.log.error(err);
                        body && this.log.error(body);
                        resp && this.log.error(resp.statusCode.toString());
                        setTimeout(() => {
                            this.log.error("Relogin");
                            this.login().catch(() => {
                                this.log.error("Failed relogin");
                            });
                        }, 1 * 60 * 1000);

                        reject();
                        return;
                    }
                    try {
                        this.log.debug(JSON.stringify(body));
                        const tokens = JSON.parse(body);
                        if (tokens.error) {
                            this.log.error(JSON.stringify(body));
                            this.refreshTokenTimeout = setTimeout(() => {
                                this.refreshToken(isVw).catch(() => {
                                    this.log.error("refresh token failed");
                                });
                            }, 5 * 60 * 1000);
                            reject();
                            return;
                        }
                        if (isVw) {
                            this.config.vwatoken = tokens.access_token;
                            if (tokens.refresh_token) {
                                this.config.vwrtoken = tokens.refresh_token;
                            }
                        } else {
                            this.config.atoken = tokens.access_token;
                            if (tokens.refresh_token) {
                                this.config.rtoken = tokens.refresh_token;
                            }
                            if (tokens.accessToken) {
                                this.config.atoken = tokens.accessToken;
                                this.config.rtoken = tokens.refreshToken;
                            }
                        }
                        resolve();
                    } catch (err) {
                        this.log.error("Failing to parse refresh token. The instance will do restart and try a relogin.");
                        this.log.error(err);
                        this.log.error(JSON.stringify(body));
                        this.log.error(resp.statusCode.toString());
                        this.log.error(err.stack);
                        this.restart();
                    }
                }
            );
        });
    }

    getPersonalData() {
        return new Promise((resolve, reject) => {
            if (this.config.type === "audi" || this.config.type === "go" || this.config.type === "id") {
                resolve();
                return;
            }
            this.log.debug("getData");
            request.get(
                {
                    url: "https://customer-profile.apps.emea.vwapps.io/v1/customers/" + this.config.userid + "/personalData",
                    headers: {
                        "user-agent": "okhttp/3.7.0",
                        "X-App-version": this.xappversion,
                        "X-App-name": this.xappname,
                        authorization: "Bearer " + this.config.atoken,
                        accept: "application/json",
                        Host: "customer-profile.apps.emea.vwapps.io",
                    },
                    followAllRedirects: true,
                },
                (err, resp, body) => {
                    if (err || (resp && resp.statusCode >= 400)) {
                        err && this.log.error(err);
                        resp && this.log.error(resp.statusCode.toString());
                        reject();
                        return;
                    }
                    try {
                        if (body.error) {
                            this.log.error(JSON.stringify(body.error));
                            reject();
                        }
                        this.log.debug(JSON.stringify(body));
                        const data = JSON.parse(body);
                        this.config.identifier = data.businessIdentifierValue;
                        Object.keys(data).forEach((key) => {
                            this.setObjectNotExistsAsync("personal." + key, {
                                type: "state",
                                common: {
                                    name: key,
                                    role: "indicator",
                                    type: "mixed",
                                    write: false,
                                    read: true,
                                },
                                native: {},
                            })
                                .then(() => {
                                    this.setState("personal." + key, data[key], true);
                                })
                                .catch((error) => {
                                    this.log.error(error);
                                });
                        });

                        resolve();
                    } catch (err) {
                        this.log.error(err);
                        reject();
                    }
                }
            );
        });
    }
    getHomeRegion(vin) {
        return new Promise((resolve, reject) => {
            this.log.debug("getHomeRegion");
            request.get(
                {
                    url: "https://mal-1a.prd.ece.vwg-connect.com/api/cs/vds/v1/vehicles/" + vin + "/homeRegion",
                    headers: {
                        "user-agent": "okhttp/3.7.0",
                        "X-App-version": this.xappversion,
                        "X-App-name": this.xappname,
                        authorization: "Bearer " + this.config.vwatoken,
                        accept: "application/json",
                    },
                    followAllRedirects: true,
                    gzip: true,
                    json: true,
                },
                (err, resp, body) => {
                    if (err || (resp && resp.statusCode >= 400)) {
                        err && this.log.error(err);
                        resp && this.log.error(resp.statusCode.toString());
                        reject();
                        return;
                    }
                    try {
                        if (body.error) {
                            this.log.error(JSON.stringify(body.error));
                            reject();
                        }
                        this.log.debug(vin + ": " + JSON.stringify(body));
                        this.homeRegion[vin] = "https://msg.volkswagen.de";
                        if (body.homeRegion && body.homeRegion.baseUri && body.homeRegion.baseUri.content) {
                            if (body.homeRegion.baseUri.content !== "https://mal-1a.prd.ece.vwg-connect.com/api") {
                                this.homeRegion[vin] = body.homeRegion.baseUri.content.split("/api")[0].replace("mal-", "fal-");
                                this.homeRegionSetter[vin] = body.homeRegion.baseUri.content.split("/api")[0];
                                this.log.debug("Set URL to: " + this.homeRegion[vin]);
                            }
                        }
                        resolve();
                    } catch (err) {
                        this.log.error(err);
                        reject();
                    }
                }
            );
        });
    }
    getCarData() {
        return new Promise((resolve, reject) => {
            this.log.debug("getData");
            request.get(
                {
                    url: "https://customer-profile.apps.emea.vwapps.io/v1/customers/" + this.config.userid + "/realCarData",
                    headers: {
                        "user-agent": "okhttp/3.7.0",
                        "X-App-version": this.xappversion,
                        "X-App-name": this.xappname,
                        authorization: "Bearer " + this.config.atoken,
                        accept: "application/json",
                        Host: "customer-profile.apps.emea.vwapps.io",
                    },
                    followAllRedirects: true,
                },
                (err, resp, body) => {
                    if (err || (resp && resp.statusCode >= 400)) {
                        err && this.log.error(err);
                        resp && this.log.error(resp.statusCode.toString());
                        reject();
                        return;
                    }
                    try {
                        if (body.error) {
                            this.log.error(JSON.stringify(body.error));
                            reject();
                        }
                        this.log.debug(JSON.stringify(body));
                        const data = JSON.parse(body);
                        Object.keys(data).forEach((key) => {
                            this.setObjectNotExistsAsync("car." + key, {
                                type: "state",
                                common: {
                                    name: key,
                                    role: "indicator",
                                    type: "mixed",
                                    write: false,
                                    read: true,
                                },
                                native: {},
                            })
                                .then(() => {
                                    this.setState("car." + key, data[key], true);
                                })
                                .catch((error) => {
                                    this.log.error(error);
                                });
                        });

                        resolve();
                    } catch (err) {
                        this.log.error(err);
                        reject();
                    }
                }
            );
        });
    }

    getVehicles() {
        return new Promise((resolve, reject) => {
            let url = this.replaceVarInUrl("https://msg.volkswagen.de/fs-car/usermanagement/users/v1/$type/$country/vehicles");
            let headers = {
                "User-Agent": "okhttp/3.7.0",
                "X-App-Version": this.xappversion,
                "X-App-Name": this.xappname,
                Authorization: "Bearer " + this.config.vwatoken,
                Accept: "application/json",
            };
            if (this.config.type === "go") {
                url = "https://dmp.apps.emea.vwapps.io/mobility-platform/vehicles";
                // @ts-ignore
                headers = {
                    "user-agent": "okhttp/3.9.1",
                    authorization: "Bearer " + this.config.atoken,
                    "accept-language": "de-DE",
                    "dmp-api-version": "v2.0",
                    "dmp-client-info": "Android/7.0/VW Connect/App/2.9.4",
                    accept: "application/json;charset=UTF-8",
                };
            }
            if (this.config.type === "id") {
                url = "https://mobileapi.apps.emea.vwapps.io/vehicles";
                // @ts-ignore
                headers = {
                    accept: "*/*",
                    "content-type": "application/json",
                    "content-version": "1",
                    "x-newrelic-id": "VgAEWV9QDRAEXFlRAAYPUA==",
                    "user-agent": "WeConnect/5 CFNetwork/1206 Darwin/20.1.0",
                    "accept-language": "de-de",
                    authorization: "Bearer " + this.config.atoken,
                };
            }
            request.get(
                {
                    url: url,
                    headers: headers,
                    followAllRedirects: true,
                    gzip: true,
                    json: true,
                },
                (err, resp, body) => {
                    if (err || (resp && resp.statusCode >= 400)) {
                        if (resp && resp.statusCode === 429) {
                            this.log.error("Too many requests. Please turn on your car to send new requests. Maybe force update/update erzwingen is too often.");
                        }
                        err && this.log.error(err);
                        resp && this.log.error(resp.statusCode.toString());
                        reject();
                    }
                    try {
                        if (body.errorCode) {
                            this.log.error(JSON.stringify(body));
                            reject();
                            return;
                        }
                        this.log.debug(JSON.stringify(body));
                        if (this.config.type === "id") {
                            body.data.forEach((element) => {
                                const vin = element.vin;

                                this.vinArray.push(vin);
                                this.setObjectNotExists(element.vin, {
                                    type: "device",
                                    common: {
                                        name: element.nickname,
                                        role: "indicator",
                                        type: "mixed",
                                        write: false,
                                        read: true,
                                    },
                                    native: {},
                                });
                                this.extractKeys(this, vin + ".general", element);

                                this.setObjectNotExists(vin + ".remote", {
                                    type: "state",
                                    common: {
                                        name: "Remote controls",
                                        write: true,
                                    },
                                    native: {},
                                });
                                this.setObjectNotExists(vin + ".remote.charging", {
                                    type: "state",
                                    common: {
                                        name: "Start/Stop Battery Charge",
                                        type: "boolean",
                                        role: "boolean",
                                        write: true,
                                    },
                                    native: {},
                                });
                                this.setObjectNotExists(vin + ".remote.climatisation", {
                                    type: "state",
                                    common: {
                                        name: "Start/Stop Climatisation",
                                        type: "boolean",
                                        role: "boolean",
                                        write: true,
                                    },
                                    native: {},
                                });
                            });
                            resolve();
                            return;
                        }
                        if (this.config.type === "go") {
                            body.forEach((element) => {
                                const vin = element.vehicle.vin;
                                this.setObjectNotExists(element.vehicle.vin, {
                                    type: "device",
                                    common: {
                                        name: element.licencePlate,
                                        role: "indicator",
                                        type: "mixed",
                                        write: false,

                                        read: true,
                                    },
                                    native: {},
                                });
                                const adapter = this;

                                traverse(element).forEach(function (value) {
                                    if (this.path.length > 0 && this.isLeaf) {
                                        const modPath = this.path;
                                        this.path.forEach((pathElement, pathIndex) => {
                                            if (!isNaN(parseInt(pathElement))) {
                                                let stringPathIndex = parseInt(pathElement) + 1 + "";
                                                while (stringPathIndex.length < 2) stringPathIndex = "0" + stringPathIndex;
                                                const key = this.path[pathIndex - 1] + stringPathIndex;
                                                const parentIndex = modPath.indexOf(pathElement) - 1;
                                                modPath[parentIndex] = key;
                                                modPath.splice(parentIndex + 1, 1);
                                            }
                                        });

                                        adapter
                                            .setObjectNotExistsAsync(vin + ".status." + modPath.join("."), {
                                                type: "state",
                                                common: {
                                                    name: this.key,
                                                    role: "indicator",
                                                    type: typeof value,
                                                    write: false,
                                                    read: true,
                                                },
                                                native: {},
                                            })
                                            .then(() => {
                                                if (typeof value === "object") {
                                                    value = JSON.stringify(value);
                                                }
                                                adapter.setState(vin + ".status." + modPath.join("."), value || this.node, true);
                                            })
                                            .catch((error) => {
                                                this.log.error(error);
                                            });
                                    }
                                });
                            });
                            resolve();
                            return;
                        }
                        if (!body.userVehicles) {
                            this.log.info("No Vehicles found");
                            resolve();
                            return;
                        }
                        const vehicles = body.userVehicles.vehicle;
                        vehicles.forEach((vehicle) => {
                            this.vinArray.push(vehicle);
                            this.setObjectNotExists(vehicle, {
                                type: "device",
                                common: {
                                    name: vehicle.title,
                                    role: "indicator",
                                    type: "mixed",
                                    write: false,
                                    read: true,
                                },
                                native: {},
                            });
                            this.setObjectNotExists(vehicle + ".remote", {
                                type: "state",
                                common: {
                                    name: "Remote controls",
                                    write: true,
                                },
                                native: {},
                            });
                            this.setObjectNotExists(vehicle + ".remote.batterycharge", {
                                type: "state",
                                common: {
                                    name: "Start Battery Charge",
                                    type: "boolean",
                                    role: "switch",
                                    write: true,
                                },
                                native: {},
                            });
                            this.setObjectNotExists(vehicle + ".remote.maxChargeCurrent", {
                                type: "state",
                                common: {
                                    name: "Set maxChargeCurrent",
                                    type: "number",
                                    role: "number",
                                    write: true,
                                },
                                native: {},
                            });
                            this.setObjectNotExists(vehicle + ".remote.climatisation", {
                                type: "state",
                                common: {
                                    name: "Start/Stop Climatisation",
                                    type: "boolean",
                                    role: "switch",
                                    write: true,
                                },
                                native: {},
                            });
                            this.setObjectNotExists(vehicle + ".remote.climatisationv2", {
                                type: "state",
                                common: {
                                    name: "Start/Stop Climatisation v2",
                                    type: "boolean",
                                    role: "switch",
                                    write: true,
                                },
                                native: {},
                            });
                            this.setObjectNotExists(vehicle + ".remote.climatisationTemperature", {
                                type: "state",
                                common: {
                                    name: "Temperature in °C",
                                    type: "number",
                                    role: "number",
                                    write: true,
                                },
                                native: {},
                            });
                            this.setObjectNotExists(vehicle + ".remote.windowheating", {
                                type: "state",
                                common: {
                                    name: "Start Windowheating",
                                    type: "boolean",
                                    role: "switch",
                                    write: true,
                                },
                                native: {},
                            });
                            this.setObjectNotExists(vehicle + ".remote.honk", {
                                type: "state",
                                common: {
                                    name: "Start Honk",
                                    type: "boolean",
                                    role: "button",
                                    write: true,
                                },
                                native: {},
                            });
                            this.setObjectNotExists(vehicle + ".remote.flash", {
                                type: "state",
                                common: {
                                    name: "Start Flash",
                                    type: "boolean",
                                    role: "button",
                                    write: true,
                                },
                                native: {},
                            });
                            this.setObjectNotExists(vehicle + ".remote.standheizung", {
                                type: "state",
                                common: {
                                    name: "Standheizung aktiviert",
                                    type: "boolean",
                                    role: "switch",
                                    write: true,
                                },
                                native: {},
                            });
                            this.setObjectNotExists(vehicle + ".remote.lock", {
                                type: "state",
                                common: {
                                    name: "Verriegeln (true) / Entriegeln (false)",
                                    type: "boolean",
                                    role: "switch",
                                    write: true,
                                },
                                native: {},
                            });
                            this.setObjectNotExists(vehicle + ".remote.ventilationv2", {
                                type: "state",
                                common: {
                                    name: "Ventilation aktiviert/deaktivieren",
                                    type: "boolean",
                                    role: "switch",
                                    write: true,
                                },
                                native: {},
                            });
                            this.setObjectNotExists(vehicle + ".remote.standheizungv2", {
                                type: "state",
                                common: {
                                    name: "Standheizung aktiviert/deaktivieren",
                                    type: "boolean",
                                    role: "switch",
                                    write: true,
                                },
                                native: {},
                            });
                            this.setObjectNotExists(vehicle + ".remote.lockv2", {
                                type: "state",
                                common: {
                                    name: "Verriegeln (true) / Entriegeln (false)",
                                    type: "boolean",
                                    role: "switch",
                                    write: true,
                                },
                                native: {},
                            });
                            this.setObjectNotExists(vehicle + ".remote.ventilation", {
                                type: "state",
                                common: {
                                    name: "Start Ventilation",
                                    type: "boolean",
                                    role: "switch",
                                    write: true,
                                },
                                native: {},
                            });
                            this.setObjectNotExists(vehicle + ".remote.ventilationDuration", {
                                type: "state",
                                common: {
                                    name: "Dauer Lüftung in min",
                                    role: "number",
                                    write: true,
                                },
                                native: {},
                            });
                        });
                        resolve();
                    } catch (err) {
                        this.log.error(err);
                        this.log.error(err.stack);
                        this.log.error("Not able to find vehicle, did you choose the correct type in the settings?");
                        reject();
                    }
                }
            );
        });
    }
    getIdStatus(vin) {
        return new Promise((resolve, reject) => {
            request.get(
                {
                    url: "https://mobileapi.apps.emea.vwapps.io/vehicles/" + vin + "/status",

                    headers: {
                        accept: "*/*",
                        "content-type": "application/json",
                        "content-version": "1",
                        "x-newrelic-id": "VgAEWV9QDRAEXFlRAAYPUA==",
                        "user-agent": "WeConnect/5 CFNetwork/1206 Darwin/20.1.0",
                        "accept-language": "de-de",
                        authorization: "Bearer " + this.config.atoken,
                    },
                    followAllRedirects: true,
                    gzip: true,
                    json: true,
                },
                (err, resp, body) => {
                    if (err || (resp && resp.statusCode >= 400)) {
                        err && this.log.error(err);
                        resp && this.log.error(resp.statusCode.toString());

                        reject();
                        return;
                    }
                    this.log.debug(JSON.stringify(body));
                    try {
                        this.extractKeys(this, vin + ".status", body.data);
                        resolve();
                    } catch (err) {
                        this.log.error(err);
                        reject();
                    }
                }
            );
        });
    }
    getWcData(limit) {
        if (!limit) {
            limit = 25;
        }
        this.setObjectNotExists("wecharge", {
            type: "state",
            common: {
                name: "WeCharge Data",
                write: false,
            },
            native: {},
        });
        const header = {
            accept: "*/*",
            "content-type": "application/json",
            "content-version": "1",
            "x-newrelic-id": "VgAEWV9QDRAEXFlRAAYPUA==",
            "user-agent": "WeConnect/5 CFNetwork/1206 Darwin/20.1.0",
            "accept-language": "de-de",
            authorization: "Bearer " + this.config.atoken,
            wc_access_token: this.config.wc_access_token,
        };
        this.genericRequest("https://wecharge.apps.emea.vwapps.io/charge-and-pay/v1/user/subscriptions", header, "wecharge.chargeandpay.subscriptions", [404], "result")
            .then((body) => {
                body.forEach((subs) => {
                    this.genericRequest("https://wecharge.apps.emea.vwapps.io/charge-and-pay/v1/user/tariffs/" + subs.tariff_id, header, "wecharge.chargeandpay.tariffs." + subs.tariff_id, [
                        404,
                    ]).catch((hideError) => {
                        if (hideError) {
                            this.log.debug("Failed to get tariff");
                            return;
                        }
                        this.log.error("Failed to get tariff");
                    });
                });
            })
            .catch((hideError) => {
                if (hideError) {
                    this.log.debug("Failed to get subscription");
                    return;
                }
                this.log.error("Failed to get subscription");
            });
        this.genericRequest("https://wecharge.apps.emea.vwapps.io/charge-and-pay/v1/charging/records?limit=" + limit + "&offset=0", header, "wecharge.chargeandpay.records", [404], "result")
            .then((body) => {
                this.setObjectNotExistsAsync("wecharge.chargeandpay.recordsJson", {
                    type: "state",
                    common: {
                        name: "Raw Json Last 100",
                        role: "indicator",
                        type: "string",
                        write: true,
                        read: true,
                    },
                    native: {},
                })
                    .then(() => {
                        this.setState("wecharge.chargeandpay.recordsJson", JSON.stringify(body), true);
                    })
                    .catch((error) => {
                        this.log.error(error);
                    });
                this.extractKeys(this, "wecharge.chargeandpay.records.latestItem", body[0]);
            })
            .catch((hideError) => {
                if (hideError) {
                    this.log.debug("Failed to get chargeandpay records");
                    return;
                }
                this.log.error("Failed to get chargeandpay records");
            });
        this.genericRequest("https://wecharge.apps.emea.vwapps.io/home-charging/v1/stations?limit=" + limit, header, "wecharge.homecharging.stations", [404], "result", "stations")
            .then((body) => {
                body.forEach((station) => {
                    this.genericRequest(
                        "https://wecharge.apps.emea.vwapps.io/home-charging/v1/charging/sessions?station_id=" + station.id + "&limit=" + limit,
                        header,
                        "wecharge.homecharging.stations." + station.name + ".sessions",
                        [404],
                        "charging_sessions"
                    )
                        .then((body) => {
                            this.setObjectNotExistsAsync("wecharge.homecharging.stations." + station.name + ".sessionsJson", {
                                type: "state",
                                common: {
                                    name: "Raw Json Last 100",
                                    role: "indicator",
                                    type: "string",
                                    write: true,
                                    read: true,
                                },
                                native: {},
                            })
                                .then(() => {
                                    this.setState("wecharge.homecharging.stations." + station.name + ".sessionsJson", JSON.stringify(body), true);
                                })
                                .catch((error) => {
                                    this.log.error(error);
                                });

                            this.extractKeys(this, "wecharge.homecharging.stations." + station.name + ".sessions.latestItem", body[0]);
                        })
                        .catch((hideError) => {
                            if (hideError) {
                                this.log.debug("Failed to get sessions");
                                return;
                            }
                            this.log.error("Failed to get sessions");
                        });
                });
            })
            .catch((hideError) => {
                if (hideError) {
                    this.log.debug("Failed to get stations");
                    return;
                }
                this.log.error("Failed to get stations");
            });
        const dt = new Date();
        this.genericRequest(
            "https://wecharge.apps.emea.vwapps.io/home-charging/v1/charging/records?start_date_time_after=2020-05-01T00:00:00.000Z&start_date_time_before=" + dt.toISOString() + "&limit=" + limit,
            header,
            "wecharge.homecharging.records",
            [404],
            "charging_records"
        )
            .then((body) => {
                this.setObjectNotExistsAsync("wecharge.homecharging.recordsJson", {
                    type: "state",
                    common: {
                        name: "Raw Json Last 100",
                        role: "indicator",
                        type: "string",
                        write: true,
                        read: true,
                    },
                    native: {},
                })
                    .then(() => {
                        this.setState("wecharge.homecharging.recordsJson", JSON.stringify(body), true);
                    })
                    .catch((error) => {
                        this.log.error(error);
                    });
                this.extractKeys(this, "wecharge.homecharging.records.latestItem", body[0]);
            })
            .catch((hideError) => {
                if (hideError) {
                    this.log.debug("Failed to get records");
                    return;
                }
                this.log.error("Failed to get records");
            });
        //Pay
        //Home
    }
    genericRequest(url, header, path, codesToIgnoreArray, selector1, selector2) {
        return new Promise(async (resolve, reject) => {
            request.get(
                {
                    url: url,
                    headers: header,
                    followAllRedirects: true,
                    gzip: true,
                    json: true,
                },
                (err, resp, body) => {
                    if (err || (resp && resp.statusCode >= 400)) {
                        if (resp && resp.statusCode && codesToIgnoreArray.includes(resp.statusCode)) {
                            err && this.log.debug(err);
                            resp && this.log.debug(resp.statusCode.toString());
                            body && this.log.debug(JSON.stringify(body));
                            reject(true);
                            return;
                        }
                        err && this.log.error(err);
                        resp && this.log.error(resp.statusCode.toString());
                        body && this.log.error(JSON.stringify(body));
                        reject();
                        return;
                    }
                    this.log.debug(JSON.stringify(body));
                    try {
                        if (selector1) {
                            body = body[selector1];
                            if (selector2) {
                                body = body[selector2];
                            }
                        }
                        this.extractKeys(this, path, body);
                        resolve(body);
                    } catch (err) {
                        this.log.error(err);
                        reject();
                    }
                }
            );
        });
    }
    setIdRemote(vin, action, value, bodyContent) {
        return new Promise(async (resolve, reject) => {
            const pre = this.name + "." + this.instance;
            let body = bodyContent || {};
            if (action === "climatisation" && value === "start") {
                const climateStates = await this.getStatesAsync(pre + "." + vin + ".status.climatisationSettings.*");
                body = {};
                const allIds = Object.keys(climateStates);
                allIds.forEach((keyName) => {
                    const key = keyName.split(".").splice(-1)[0];
                    if (key.indexOf("Timestamp") === -1) {
                        body[key] = climateStates[keyName].val;
                    }
                });

                // body = JSON.stringify(body);
            }
            let method = "POST";
            if (value === "settings") {
                method = "PUT";
            }
            this.log.debug("https://mobileapi.apps.emea.vwapps.io/vehicles/" + vin + "/" + action + "/" + value);
            this.log.debug(JSON.stringify(body));
            request(
                {
                    method: method,
                    url: "https://mobileapi.apps.emea.vwapps.io/vehicles/" + vin + "/" + action + "/" + value,

                    headers: {
                        "content-type": "application/json",
                        accept: "*/*",
                        "accept-language": "de-de",
                        "user-agent": "WeConnect/5 CFNetwork/1206 Darwin/20.1.0",
                        "content-version": "1",
                        "x-newrelic-id": "VgAEWV9QDRAEXFlRAAYPUA==",
                        authorization: "Bearer " + this.config.atoken,
                    },
                    body: body,
                    followAllRedirects: true,
                    json: true,
                    gzip: true,
                },
                (err, resp, body) => {
                    if (err || (resp && resp.statusCode >= 400)) {
                        if (resp && resp.statusCode === 401) {
                            err && this.log.error(err);
                            resp && this.log.error(resp.statusCode.toString());
                            body && this.log.error(JSON.stringify(body));
                            this.refreshIDToken().catch(() => {});
                            this.log.error("Refresh Token");
                            reject();
                            return;
                        }
                        err && this.log.error(err);
                        resp && this.log.error(resp.statusCode.toString());
                        body && this.log.error(JSON.stringify(body));
                        reject();
                        return;
                    }
                    try {
                        this.log.debug(JSON.stringify(body));
                        resolve();
                    } catch (err) {
                        this.log.error(err);
                        reject();
                    }
                }
            );
        });
    }
    refreshIDToken() {
        return new Promise((resolve, reject) => {
            this.log.debug("Token Refresh started");
            request.get(
                {
                    url: "https://login.apps.emea.vwapps.io/refresh/v1",

                    headers: {
                        accept: "*/*",
                        "content-type": "application/json",
                        "content-version": "1",
                        "x-newrelic-id": "VgAEWV9QDRAEXFlRAAYPUA==",
                        "user-agent": "WeConnect/5 CFNetwork/1206 Darwin/20.1.0",
                        "accept-language": "de-de",
                        authorization: "Bearer " + this.config.rtoken,
                    },
                    followAllRedirects: true,
                    gzip: true,
                    json: true,
                },
                (err, resp, body) => {
                    if (err || (resp && resp.statusCode >= 400)) {
                        err && this.log.error(err);
                        resp && this.log.error(resp.statusCode.toString());
                        body && this.log.error(JSON.stringify(body));
                        this.log.error("Failed refresh token. Relogin");
                        //reset login parameters because of wecharge
                        this.type = "Id";
                        this.clientId = "a24fba63-34b3-4d43-b181-942111e6bda8@apps_vw-dilab_com";
                        this.scope = "openid profile badge cars dealers birthdate vin";
                        this.redirect = "weconnect://authenticated";
                        this.xrequest = "com.volkswagen.weconnect";
                        this.responseType = "code id_token token";
                        setTimeout(() => {
                            this.log.error("Relogin");
                            this.login().catch(() => {
                                this.log.error("Failed relogin");
                            });
                        }, 1 * 60 * 1000);
                        reject();
                        return;
                    }
                    try {
                        this.log.debug("Token Refresh successful");
                        this.config.atoken = body.accessToken;
                        this.config.rtoken = body.refreshToken;
                        if (this.type === "Wc") {
                            //wallcharging relogin no refresh token available
                            this.login().catch(() => {
                                this.log.debug("No able to Login in WeCharge");
                            });
                        }
                        resolve();
                    } catch (err) {
                        this.log.error(err);
                        reject();
                    }
                }
            );
        });
    }
    getVehicleData(vin) {
        return new Promise((resolve, reject) => {
            if (this.config.type === "go") {
                resolve();
                return;
            }
            let accept = "application/vnd.vwg.mbb.vehicleDataDetail_v2_1_0+json, application/vnd.vwg.mbb.genericError_v1_0_2+json";
            let url = this.replaceVarInUrl("$homeregion/fs-car/vehicleMgmt/vehicledata/v2/$type/$country/vehicles/$vin/", vin);
            if (this.config.type !== "vw" && this.config.type !== "vwv2" && this.config.type !== "audi" && this.config.type !== "id" && this.config.type !== "seat" && this.config.type !== "skoda") {
                url = this.replaceVarInUrl("https://msg.volkswagen.de/fs-car/promoter/portfolio/v1/$type/$country/vehicle/$vin/carportdata", vin);
                accept = "application/json";
            }
            const atoken = this.config.vwatoken;

            request.get(
                {
                    url: url,
                    headers: {
                        "User-Agent": "okhttp/3.7.0",
                        "X-App-Version": this.xappversion,
                        "X-App-Name": this.xappname,
                        "X-Market": "de_DE",
                        Authorization: "Bearer " + atoken,
                        "If-None-Match": this.etags[url] || "",
                        Accept: accept,
                    },
                    followAllRedirects: true,
                    gzip: true,
                    json: true,
                },
                (err, resp, body) => {
                    if (err || (resp && resp.statusCode >= 400)) {
                        if (resp && resp.statusCode === 429) {
                            this.log.error("Too many requests. Please turn on your car to send new requests. Maybe force update/update erzwingen is too often.");
                        }
                        err && this.log.error(err);
                        resp && this.log.error(resp.statusCode.toString());
                        body && this.log.error(JSON.stringify(body));
                        reject();
                        return;
                    }
                    try {
                        this.log.debug(JSON.stringify(body));
                        let result = body.vehicleData;
                        if (!result) {
                            result = body.vehicleDataDetail;
                        }
                        if (resp) {
                            this.etags[url] = resp.headers.etag;
                            if (resp.statusCode === 304) {
                                this.log.debug("304 No values updated");
                                resolve();
                                return;
                            }
                        }
                        if (result && result.carportData && result.carportData.modelName) {
                            this.updateName(vin, result.carportData.modelName);
                        }

                        this.extractKeys(this, vin + ".general", result);

                        resolve();
                    } catch (err) {
                        this.log.error(err);
                        reject();
                    }
                }
            );
        });
    }

    getVehicleRights(vin) {
        return new Promise((resolve, reject) => {
            if (this.config.type === "go" || !this.config.rights) {
                resolve();
                return;
            }
            let url = "https://mal-1a.prd.ece.vwg-connect.com/api/rolesrights/operationlist/v3/vehicles/" + vin;
            if (this.config.type === "vw" || this.config.type === "vwv2") {
                url += "/users/" + this.config.identifier;
            }
            request.get(
                {
                    url: url,
                    qs: {
                        scope: "All",
                    },
                    headers: {
                        "User-Agent": "okhttp/3.7.0",
                        "X-App-Version": this.xappversion,
                        "X-App-Name": this.xappname,
                        Authorization: "Bearer " + this.config.vwatoken,
                        Accept: "application/json, application/vnd.vwg.mbb.operationList_v3_0_2+xml, application/vnd.vwg.mbb.genericError_v1_0_2+xml",
                    },
                    followAllRedirects: true,
                    gzip: true,
                    json: true,
                },
                (err, resp, body) => {
                    if (err || (resp && resp.statusCode >= 400)) {
                        if (resp && resp.statusCode === 429) {
                            this.log.error("Too many requests. Please turn on your car to send new requests. Maybe force update/update erzwingen is too often.");
                        }
                        err && this.log.error(err);
                        resp && this.log.error(resp.statusCode.toString());
                        reject();
                        return;
                    }
                    try {
                        const adapter = this;
                        traverse(body.operationList).forEach(function (value) {
                            if (this.path.length > 0 && this.isLeaf) {
                                const modPath = this.path;
                                this.path.forEach((pathElement, pathIndex) => {
                                    if (!isNaN(parseInt(pathElement))) {
                                        let stringPathIndex = parseInt(pathElement) + 1 + "";
                                        while (stringPathIndex.length < 2) stringPathIndex = "0" + stringPathIndex;
                                        const key = this.path[pathIndex - 1] + stringPathIndex;
                                        const parentIndex = modPath.indexOf(pathElement) - 1;
                                        modPath[parentIndex] = key;
                                        modPath.splice(parentIndex + 1, 1);
                                    }
                                });
                                if (modPath[modPath.length - 1] !== "$") {
                                    adapter
                                        .setObjectNotExistsAsync(vin + ".rights." + modPath.join("."), {
                                            type: "state",
                                            common: {
                                                name: this.key,
                                                role: "indicator",
                                                type: "mixed",
                                                write: false,
                                                read: true,
                                            },
                                            native: {},
                                        })
                                        .then(() => {
                                            if (typeof value === "object") {
                                                value = JSON.stringify(value);
                                            }
                                            adapter.setState(vin + ".rights." + modPath.join("."), value || this.node, true);
                                        })
                                        .catch((error) => {
                                            this.log.error(error);
                                        });
                                }
                            }
                        });

                        resolve();
                    } catch (err) {
                        this.log.error(err);
                        reject();
                    }
                }
            );
        });
    }

    requestStatusUpdate(vin) {
        return new Promise((resolve, reject) => {
            try {
                if (this.config.type === "audi") {
                    resolve();
                    return;
                }
                let method = "POST";
                let url = this.replaceVarInUrl("$homeregion/fs-car/bs/vsr/v1/$type/$country/vehicles/$vin/requests", vin);

                let accept = "application/json";
                if (this.config.type === "vw") {
                    accept =
                        "application/vnd.vwg.mbb.VehicleStatusReport_v1_0_0+json, application/vnd.vwg.mbb.climater_v1_0_0+json, application/vnd.vwg.mbb.carfinderservice_v1_0_0+json, application/vnd.volkswagenag.com-error-v1+json, application/vnd.vwg.mbb.genericError_v1_0_2+json";
                }
                if (this.config.type === "vwv2") {
                    method = "GET";
                    url = this.replaceVarInUrl("$homeregion/fs-car/vehicleMgmt/vehicledata/v2/$type/$country/vehicles/$vin", vin);
                    accept = " application/vnd.vwg.mbb.vehicleDataDetail_v2_1_0+json, application/vnd.vwg.mbb.genericError_v1_0_2+json";
                }
                request(
                    {
                        method: method,
                        url: url,
                        headers: {
                            "User-Agent": "okhttp/3.7.0",
                            "X-App-Version": this.xappversion,
                            "X-App-Name": this.xappname,
                            Authorization: "Bearer " + this.config.vwatoken,
                            "Accept-charset": "UTF-8",
                            Accept: accept,
                        },
                        followAllRedirects: true,
                        gzip: true,
                        json: true,
                    },
                    (err, resp, body) => {
                        if (err || (resp && resp.statusCode >= 400)) {
                            this.log.error(vin);
                            if (resp && resp.statusCode === 429) {
                                this.log.error("Too many requests. Please turn on your car to send new requests. Maybe force update/update erzwingen is too often.");
                            }
                            err && this.log.error(err);
                            resp && this.log.error(resp.statusCode.toString());
                            body && this.log.error(JSON.stringify(body));
                            reject();
                            return;
                        }
                        try {
                            this.log.debug(JSON.stringify(body));
                            resolve();
                        } catch (err) {
                            this.log.error(vin);
                            this.log.error(err);
                            reject();
                        }
                    }
                );
            } catch (err) {
                this.log.error(err);
                reject();
            }
        });
    }

    getVehicleStatus(vin, url, path, element, element2, element3, element4, tripType) {
        return new Promise((resolve, reject) => {
            url = this.replaceVarInUrl(url, vin, tripType);
            if (path === "tripdata") {
                if (this.tripsActive == false) {
                    resolve();
                    return;
                }
            }
            let accept = "application/json";
            if (this.config.type === "vw" || this.config.type === "vwv2") {
                accept =
                    "application/vnd.vwg.mbb.VehicleStatusReport_v1_0_0+json, application/vnd.vwg.mbb.climater_v1_0_0+json, application/vnd.vwg.mbb.carfinderservice_v1_0_0+json, application/vnd.volkswagenag.com-error-v1+json, application/vnd.vwg.mbb.genericError_v1_0_2+json, */*";
                if (this.homeRegion[vin] === "https://msg.volkswagen.de") {
                    accept += ", application/json";
                }
            }
            request.get(
                {
                    url: url,
                    headers: {
                        "User-Agent": "okhttp/3.7.0",
                        "X-App-Version": this.xappversion,
                        "X-App-Name": this.xappname,
                        "If-None-Match": this.etags[url] || "",
                        Authorization: "Bearer " + this.config.vwatoken,
                        "Accept-charset": "UTF-8",
                        Accept: accept,
                    },
                    followAllRedirects: true,
                    gzip: true,
                    json: true,
                },
                (err, resp, body) => {
                    if (err || (resp && resp.statusCode >= 400)) {
                        if ((resp && resp.statusCode === 403) || (resp && resp.statusCode === 502) || (resp && resp.statusCode === 406) || (resp && resp.statusCode === 500)) {
                            body && this.log.debug(JSON.stringify(body));
                            resolve();
                            return;
                        } else if (resp && resp.statusCode === 401) {
                            this.log.error(vin);
                            err && this.log.error(err);
                            resp && this.log.error(resp.statusCode.toString());
                            body && this.log.error(JSON.stringify(body));
                            this.refreshToken(true).catch(() => {
                                this.log.error("Refresh Token was not successful");
                            });
                            reject();
                            return;
                        } else {
                            if (resp && resp.statusCode === 429) {
                                this.log.error("Too many requests. Please turn on your car to send new requests. Maybe force update/update erzwingen is too often.");
                            }
                            err && this.log.error(err);
                            resp && this.log.error(resp.statusCode.toString());
                            body && this.log.error(JSON.stringify(body));
                            reject();
                            return;
                        }
                    }
                    try {
                        this.log.debug(JSON.stringify(body));
                        if (resp) {
                            this.etags[url] = resp.headers.etag;
                            if (resp.statusCode === 304) {
                                this.log.debug("304 No values updated");
                                resolve();
                                return;
                            }
                        }
                        if (path === "position") {
                            this.setObjectNotExistsAsync(vin + ".position.isMoving", {
                                type: "state",
                                common: {
                                    name: "is car moving",
                                    role: "indicator",
                                    type: "boolean",
                                    write: false,
                                    read: true,
                                },
                                native: {},
                            })
                                .then(() => {
                                    if (resp.statusCode === 204) {
                                        this.setState(vin + ".position.isMoving", true, true);
                                        resolve();
                                        return;
                                    } else {
                                        this.setState(vin + ".position.isMoving", false, true);
                                    }
                                    if (body && body.storedPositionResponse && body.storedPositionResponse.parkingTimeUTC) {
                                        body.storedPositionResponse.position.parkingTimeUTC = body.storedPositionResponse.parkingTimeUTC;
                                    }
                                })
                                .catch((error) => {
                                    this.log.error(error);
                                });
                        }

                        if (body === undefined || body === "" || body.error) {
                            if (body && body.error && body.error.description.indexOf("Token expired") !== -1) {
                                this.log.error("Error response try to refresh token " + path);
                                this.log.error(JSON.stringify(body));
                                this.refreshToken(true).catch(() => {
                                    this.log.error("Refresh Token was not successful");
                                });
                            } else {
                                this.log.debug("Not able to get " + path);
                            }
                            this.log.debug(JSON.stringify(body));
                            reject();
                            return;
                        }

                        const adapter = this;

                        let result = body;
                        if (result === "") {
                            resolve();
                            return;
                        }
                        if (result) {
                            if (element && result[element]) {
                                result = result[element];
                            }
                            if (element2 && result[element2]) {
                                result = result[element2];
                            }
                            if (element3 && result[element3]) {
                                result = result[element3];
                            }
                            if (element4 && result[element4]) {
                                result = result[element4];
                            }
                            const isStatusData = path === "status";
                            const isTripData = path === "tripdata";

                            if (isTripData) {
                                if (this.tripsActive == false) {
                                    resolve();
                                    return;
                                }
                                // result.tripData = result.tripData.reverse();
                                result.tripData.sort((a, b) => {
                                    return new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime();
                                });
                                if (this.config.numberOfTrips > 0) result.tripData = result.tripData.slice(0, this.config.numberOfTrips);
                                this.setObjectNotExistsAsync(vin + ".tripdata" + tripType + ".rawJson", {
                                    type: "state",
                                    common: {
                                        name: "Raw Json",
                                        role: "indicator",
                                        type: "mixed",
                                        write: false,
                                        read: true,
                                    },
                                    native: {},
                                })
                                    .then(() => {
                                        this.setState(vin + ".tripdata" + tripType + ".rawJson", JSON.stringify(result.tripData), true);
                                    })
                                    .catch((error) => {
                                        this.log.error(error);
                                    });

                                this.setObjectNotExistsAsync(vin + ".tripdata" + tripType + ".lastTrip", {
                                    type: "state",
                                    common: {
                                        name: "indexOfOldestTrip",
                                        role: "indicator",
                                        type: "mixed",
                                        write: false,
                                        read: true,
                                    },
                                    native: {},
                                })
                                    .then(() => {
                                        this.setState(vin + ".tripdata" + tripType + ".lastTrip", result.tripData.length, true);
                                    })
                                    .catch((error) => {
                                        this.log.error(error);
                                    });

                                this.extractKeys(this, vin + ".tripdata" + tripType, result, null, true);

                                resolve();
                                return;
                            }

                            let statusKeys = null;
                            if (isStatusData) {
                                statusKeys = this.getStatusKeys(result);
                            }
                            const tripKeys = null;

                            traverse(result).forEach(function (value) {
                                const modPath = this.path.slice();
                                let dataId = null;
                                let dataIndex = -1;
                                let fieldId = null;
                                let fieldUnit = null;
                                let isNumberNode = false;
                                let skipNode = false;
                                this.path.forEach((pathElement, pathIndex) => {
                                    if (isNaN(parseInt(pathElement))) {
                                        isNumberNode = false;
                                    } else {
                                        isNumberNode = true;
                                        let key;
                                        if (isStatusData && this.path[pathIndex - 1] === "data") {
                                            dataIndex = parseInt(pathElement);
                                            dataId = statusKeys[dataIndex].dataId;
                                            key = "_" + dataId;
                                        } else if (isStatusData && this.path[pathIndex - 1] === "field") {
                                            if (dataIndex >= 0) {
                                                fieldId = statusKeys[dataIndex].fieldIds[parseInt(pathElement)].id;
                                                key = "_" + fieldId;
                                                if (this.key == "value" && statusKeys[dataIndex].fieldIds[parseInt(pathElement)].unit) {
                                                    fieldUnit = statusKeys[dataIndex].fieldIds[parseInt(pathElement)].unit;
                                                }
                                            } else {
                                                adapter.log.error("no data entry found for field (path = " + this.path.join("."));
                                                key = parseInt(pathElement) + 1 + "";
                                            }
                                        } else if (isTripData && this.path[pathIndex - 1]) {
                                            const tripKey = tripKeys[parseInt(pathElement)];
                                            if (tripKey === null) {
                                                skipNode = true;
                                            } else {
                                                key = "_" + tripKeys[parseInt(pathElement)];
                                            }
                                        } else {
                                            key = parseInt(pathElement) + 1 + "";
                                            while (key.length < 2) key = "0" + key;
                                        }
                                        if (!skipNode) {
                                            const parentIndex = modPath.indexOf(pathElement) - 1;
                                            modPath[parentIndex] = this.path[pathIndex - 1] + key;
                                            modPath.splice(parentIndex + 1, 1);
                                        }
                                    }
                                });
                                if (!skipNode) {
                                    const newPath = vin + "." + path + "." + modPath.join(".");
                                    if (this.path.length > 0 && this.isLeaf) {
                                        value = value || this.node;
                                        if (!isNaN(Number(value)) && Number(value) === parseFloat(value)) {
                                            value = Number(value);
                                        }
                                        adapter
                                            .setObjectNotExistsAsync(newPath, {
                                                type: "state",
                                                common: {
                                                    name: this.key,
                                                    role: "indicator",
                                                    type: typeof value,
                                                    unit: fieldUnit,
                                                    write: false,
                                                    read: true,
                                                },
                                                native: {},
                                            })
                                            .then(() => {
                                                if (typeof value === "object") {
                                                    value = JSON.stringify(value);
                                                }
                                                adapter.setState(newPath, value, true);
                                            })
                                            .catch((error) => {
                                                this.log.error(error);
                                            });
                                        //if (isStatusData && newPath.endsWith(".outdoorTemperature.content")) {
                                        //	setOutsideTemperature(vin, value);
                                        //}
                                        if (isStatusData && this.key == "value") {
                                            // Audi and Skoda have different (shorter) dataId
                                            if ((dataId == "0x030104FFFF" || dataId == "0x0301FFFFFF") && fieldId == "0x0301040001") {
                                                adapter.setIsCarLocked(vin, value);
                                            }
                                            if ((dataId == "0x030102FFFF" || dataId == "0x0301FFFFFF") && fieldId == "0x0301020001") {
                                                adapter.setOutsideTemperature(vin, value);
                                            }
                                            adapter.updateUnit(newPath, fieldUnit);
                                        }
                                    } else if (isStatusData && isNumberNode) {
                                        let text = null;
                                        if (this.node.textId) {
                                            text = this.node.textId;
                                        }
                                        adapter.setObjectNotExists(newPath, {
                                            type: "channel",
                                            common: {
                                                name: text,
                                                role: "indicator",
                                                type: "mixed",
                                                write: false,
                                                read: true,
                                            },
                                            native: {},
                                        });
                                        adapter.updateName(newPath, text);
                                    } else if (isTripData && isNumberNode) {
                                        let text = null;
                                        if (this.node.timestamp) {
                                            text = this.node.timestamp;
                                        }
                                        adapter.setObjectNotExists(newPath, {
                                            type: "channel",
                                            common: {
                                                name: text,
                                                role: "indicator",
                                                type: "mixed",
                                                write: false,
                                                read: true,
                                            },
                                            native: {},
                                        });
                                        adapter.updateName(newPath, text);
                                    }
                                }
                            });
                            resolve();
                        } else {
                            this.log.error("Cannot find vehicle data " + path);
                            this.log.error(JSON.stringify(body));
                            reject();
                        }
                    } catch (err) {
                        this.log.error(err);
                        this.log.error(err.stack);
                        reject();
                    }
                }
            );
        });
    }

    async setIsCarLocked(vin, value) {
        await this.setObjectNotExistsAsync(vin + ".status.isCarLocked", {
            type: "state",
            common: {
                name: "is car locked",
                role: "indicator",
                type: "boolean",
                write: false,
                read: true,
            },
            native: {},
        });
        this.setState(vin + ".status.isCarLocked", value == 2, true);
    }

    async setOutsideTemperature(vin, value) {
        await this.setObjectNotExistsAsync(vin + ".status.outsideTemperature", {
            type: "state",
            common: {
                name: "outside temperature",
                role: "value.temperature",
                type: "number",
                unit: "°C",
                write: false,
                read: true,
            },
            native: {},
        });
        this.setState(vin + ".status.outsideTemperature", Math.round(value - 2731.5) / 10.0, true);
    }

    getStatusKeys(statusJson) {
        const adapter = this;
        let result = null;
        if (statusJson && statusJson.data) {
            if (Array.isArray(statusJson.data)) {
                result = new Array(statusJson.data.length);
                statusJson.data.forEach(function (dataValue, dataIndex) {
                    if (dataValue && dataValue.id) {
                        if (dataValue.field && Array.isArray(dataValue.field)) {
                            const newList = new Array(dataValue.field.length);
                            dataValue.field.forEach(function (fieldValue, fieldIndex) {
                                if (fieldValue && fieldValue.id) {
                                    newList[fieldIndex] = { id: fieldValue.id, unit: fieldValue.unit };
                                } else {
                                    adapter.log.warn("status[" + dataIndex + "," + fieldIndex + "] has no id");
                                    adapter.log.debug(JSON.stringify(fieldValue));
                                }
                            });
                            result[dataIndex] = { dataId: dataValue.id, fieldIds: newList };
                        } else {
                            adapter.log.warn("status[" + dataIndex + "] has no fields/is not an array");
                            adapter.log.debug(JSON.stringify(dataValue));
                        }
                    } else {
                        adapter.log.warn("status[" + dataIndex + "] has no id");
                        adapter.log.debug(JSON.stringify(dataValue));
                    }
                });
            } else {
                adapter.log.warn("status is not an array");
                adapter.log.debug(JSON.stringify(statusJson.data));
            }
        } else {
            adapter.log.warn("status data without status field");
            adapter.log.debug(JSON.stringify(statusJson));
        }
        adapter.log.debug(JSON.stringify(result));
        return result;
    }

    updateUnit(pathString, unit) {
        const adapter = this;
        this.getObject(pathString, function (err, obj) {
            if (err) adapter.log.error('Error "' + err + '" reading object ' + pathString + " for unit");
            else {
                // @ts-ignore
                if (obj && obj.common && obj.common.unit !== unit) {
                    adapter.extendObject(pathString, {
                        type: "state",
                        common: {
                            unit: unit,
                        },
                    });
                }
            }
        });
    }

    updateName(pathString, name) {
        const adapter = this;
        this.getObject(pathString, function (err, obj) {
            if (err) adapter.log.error('Error "' + err + '" reading object ' + pathString + " for name");
            else {
                if (obj && obj.common && obj.common.name !== name) {
                    adapter.extendObject(pathString, {
                        type: "channel",
                        common: {
                            name: name,
                        },
                    });
                }
            }
        });
    }

    setVehicleStatus(vin, url, body, contentType, secToken) {
        return new Promise((resolve, reject) => {
            url = this.replaceVarInUrl(url, vin);
            this.log.debug(JSON.stringify(body));
            this.log.debug(contentType);
            const headers = {
                "User-Agent": "okhttp/3.7.0",
                "X-App-Version": this.xappversion,
                "X-App-Name": this.xappname,
                Authorization: "Bearer " + this.config.vwatoken,
                "Accept-charset": "UTF-8",
                "Content-Type": contentType,
                Accept: "application/json, application/vnd.vwg.mbb.ChargerAction_v1_0_0+xml,application/vnd.volkswagenag.com-error-v1+xml,application/vnd.vwg.mbb.genericError_v1_0_2+xml, application/vnd.vwg.mbb.RemoteStandheizung_v2_0_0+xml, application/vnd.vwg.mbb.genericError_v1_0_2+xml,application/vnd.vwg.mbb.RemoteLockUnlock_v1_0_0+xml,*/*",
            };

            if (secToken) {
                headers["x-mbbSecToken"] = secToken;
            }

            request.post(
                {
                    url: url,
                    headers: headers,
                    body: body,
                    followAllRedirects: true,
                    gzip: true,
                },
                (err, resp, body) => {
                    if (err || (resp && resp.statusCode >= 400)) {
                        err && this.log.error(err);
                        resp && this.log.error(resp.statusCode.toString());
                        body && this.log.error(body);
                        reject();
                        return;
                    }
                    try {
                        this.log.debug(JSON.stringify(body));
                        if (body.indexOf("<error>") !== -1) {
                            this.log.error("Error response try to refresh token " + url);
                            this.log.error(JSON.stringify(body));
                            this.refreshToken(true).catch(() => {
                                this.log.error("Refresh Token was not successful");
                            });
                            reject();
                            return;
                        }
                        resolve();
                        this.log.info(body);
                    } catch (err) {
                        this.log.error(err);
                        this.log.error(err.stack);
                        reject();
                    }
                }
            );
        });
    }
    setVehicleStatusv2(vin, url, body, contentType, secToken) {
        return new Promise((resolve, reject) => {
            url = this.replaceVarInUrl(url, vin);
            this.log.debug(JSON.stringify(body));
            this.log.debug(contentType);
            const headers = {
                "User-Agent": "okhttp/3.7.0",
                "X-App-Version": this.xappversion,
                "X-App-Name": this.xappname,
                Authorization: "Bearer " + this.config.vwatoken,
                "Accept-charset": "UTF-8",
                "Content-Type": contentType,
                Accept: "application/json, application/vnd.vwg.mbb.ChargerAction_v1_0_0+xml,application/vnd.volkswagenag.com-error-v1+xml,application/vnd.vwg.mbb.genericError_v1_0_2+xml, application/vnd.vwg.mbb.RemoteStandheizung_v2_0_0+xml, application/vnd.vwg.mbb.genericError_v1_0_2+xml,application/vnd.vwg.mbb.RemoteLockUnlock_v1_0_0+xml,*/*",
            };
            if (secToken) {
                headers["x-mbbSecToken"] = secToken;
            }

            request.post(
                {
                    url: url,
                    headers: headers,
                    body: body,
                    followAllRedirects: true,
                    gzip: true,
                },
                (err, resp, body) => {
                    if (err || (resp && resp.statusCode >= 400)) {
                        err && this.log.error(err);
                        resp && this.log.error(resp.statusCode.toString());
                        reject();
                        return;
                    }
                    try {
                        this.log.debug(JSON.stringify(body));
                        if (body.indexOf("<error>") !== -1) {
                            this.log.error("Error response try to refresh token " + url);
                            this.log.error(JSON.stringify(body));
                            this.refreshToken(true).catch(() => {
                                this.log.error("Refresh Token was not successful");
                            });
                            reject();
                            return;
                        }
                        this.log.info(body);
                    } catch (err) {
                        this.log.error(err);
                        this.log.error(err.stack);
                        reject();
                    }
                }
            );
        });
    }
    requestSecToken(vin, service) {
        return new Promise((resolve, reject) => {
            let url = "https://mal-1a.prd.ece.vwg-connect.com/api/rolesrights/authorization/v2/vehicles/" + vin + "/services/" + service + "/security-pin-auth-requested";
            if (this.homeRegionSetter[vin]) {
                url = url.replace("https://mal-1a.prd.ece.vwg-connect.com", this.homeRegionSetter[vin]);
            }
            this.log.debug(url);
            request.get(
                {
                    url: url,
                    headers: {
                        "user-agent": "okhttp/3.7.0",
                        "X-App-version": this.xappversion,
                        "X-App-name": this.xappname,
                        authorization: "Bearer " + this.config.vwatoken,
                        accept: "application/json",
                    },
                    followAllRedirects: true,
                    json: true,
                    gzip: true,
                },
                async (err, resp, body) => {
                    if (err || (resp && resp.statusCode >= 400)) {
                        err && this.log.error(err);
                        resp && this.log.error(resp.statusCode.toString());
                        body && this.log.error(JSON.stringify(body));
                        reject();
                        return;
                    }
                    try {
                        if (body.error) {
                            this.log.error(JSON.stringify(body.error));
                            reject();
                        }
                        this.log.debug(JSON.stringify(body));
                        if (body.securityPinAuthInfo) {
                            const secToken = body.securityPinAuthInfo.securityToken;
                            const challenge = body.securityPinAuthInfo.securityPinTransmission.challenge;
                            const securPin = await this.generateSecurPin(challenge);
                            const rBody = {
                                securityPinAuthentication: {
                                    securityPin: {
                                        challenge: challenge,
                                        securityPinHash: securPin,
                                    },
                                    securityToken: secToken,
                                },
                            };
                            let url = "https://mal-1a.prd.ece.vwg-connect.com/api/rolesrights/authorization/v2/security-pin-auth-completed";
                            if (this.homeRegionSetter[vin]) {
                                url = url.replace("https://mal-1a.prd.ece.vwg-connect.com", this.homeRegionSetter[vin]);
                            }
                            request.post(
                                {
                                    url: url,
                                    headers: {
                                        "user-agent": "okhttp/3.7.0",
                                        "Content-Type": "application/json",
                                        "X-App-version": this.xappversion,
                                        "X-App-name": this.xappname,
                                        authorization: "Bearer " + this.config.vwatoken,
                                        Accept: "application/json",
                                    },
                                    body: rBody,
                                    gzip: true,
                                    json: true,
                                    followAllRedirects: true,
                                },
                                (err, resp, body) => {
                                    if (err || (resp && resp.statusCode >= 400)) {
                                        this.log.error("Failing to get sec token.");
                                        err && this.log.error(err);
                                        body && this.log.error(JSON.stringify(body));
                                        resp && this.log.error(resp.statusCode.toString());
                                        reject();
                                        return;
                                    }
                                    try {
                                        this.log.debug(JSON.stringify(body));
                                        if (body.securityToken) {
                                            resolve(body.securityToken);
                                        } else {
                                            this.log.error("No Security token found");
                                            this.log.error(JSON.stringify(body));
                                            reject();
                                        }
                                    } catch (err) {
                                        this.log.error(err);
                                        reject();
                                    }
                                }
                            );
                        } else {
                            this.log.error("No Security information found");
                            this.log.error(JSON.stringify(body));
                            reject();
                        }
                    } catch (err) {
                        this.log.error(err);
                        reject();
                    }
                }
            );
        });
    }
    generateSecurPin(challenge) {
        return new Promise((resolve, reject) => {
            if (!this.config.pin) {
                this.log.error("Please Enter your S-Pin in the Instance Options");
                reject();
                return;
            }
            const pin = this.toByteArray(this.config.pin);

            const byteChallenge = this.toByteArray(challenge);
            const webcrypto = new Crypto();
            const concat = new Int8Array(pin.concat(byteChallenge));
            webcrypto.subtle
                .digest("SHA-512", concat)
                .then((digest) => {
                    const utf8Array = new Int8Array(digest);
                    resolve(this.toHexString(utf8Array));
                })
                .catch((error) => {
                    this.log.error(error);
                });
        });
    }
    getCodeChallenge() {
        let hash = "";
        let result = "";
        while (hash === "" || hash.indexOf("+") !== -1 || hash.indexOf("/") !== -1 || hash.indexOf("=") !== -1 || result.indexOf("+") !== -1 || result.indexOf("/") !== -1) {
            const chars = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
            result = "";
            for (let i = 64; i > 0; --i) result += chars[Math.floor(Math.random() * chars.length)];
            result = Buffer.from(result).toString("base64");
            result = result.replace(/=/g, "");
            hash = crypto.createHash("sha256").update(result).digest("base64");
            hash = hash.slice(0, hash.length - 1);
        }
        return [result, hash];
    }
    getNonce() {
        const timestamp = Date.now();
        let hash = crypto.createHash("sha256").update(timestamp.toString()).digest("base64");
        hash = hash.slice(0, hash.length - 1);
        return hash;
    }
    toHexString(byteArray) {
        return Array.prototype.map
            .call(byteArray, function (byte) {
                return ("0" + (byte & 0xff).toString(16).toUpperCase()).slice(-2);
            })
            .join("");
    }

    toByteArray(hexString) {
        const result = [];
        for (let i = 0; i < hexString.length; i += 2) {
            result.push(parseInt(hexString.substr(i, 2), 16));
        }
        return result;
    }
    stringIsAValidUrl(s) {
        try {
            new URL(s);
            return true;
        } catch (err) {
            return false;
        }
    }
    randomString(length) {
        let result = "";
        const characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        const charactersLength = characters.length;
        for (let i = 0; i < length; i++) {
            result += characters.charAt(Math.floor(Math.random() * charactersLength));
        }
        return result;
    }
    extractHidden(body) {
        const returnObject = {};
        let matches;
        if (body.matchAll) {
            matches = body.matchAll(/<input (?=[^>]* name=["']([^'"]*)|)(?=[^>]* value=["']([^'"]*)|)/g);
        } else {
            this.log.warn("The adapter needs in the future NodeJS v12. https://forum.iobroker.net/topic/22867/how-to-node-js-f%C3%BCr-iobroker-richtig-updaten");
            matches = this.matchAll(/<input (?=[^>]* name=["']([^'"]*)|)(?=[^>]* value=["']([^'"]*)|)/g, body);
        }
        for (const match of matches) {
            returnObject[match[1]] = match[2];
        }
        return returnObject;
    }
    matchAll(re, str) {
        let match;
        const matches = [];

        while ((match = re.exec(str))) {
            // add all matched groups
            matches.push(match);
        }

        return matches;
    }
    /**
     * Is called when adapter shuts down - callback has to be called under any circumstances!
     * @param {() => void} callback
     */
    onUnload(callback) {
        try {
            this.setState("info.connection", false, true);
            this.log.info("cleaned everything up...");
            clearInterval(this.refreshTokenInterval);
            clearInterval(this.vwrefreshTokenInterval);
            clearInterval(this.updateInterval);
            clearInterval(this.fupdateInterval);
            clearTimeout(this.refreshTokenTimeout);
            callback();
        } catch (e) {
            callback();
        }
    }

    /**
     * Is called if a subscribed state changes
     * @param {string} id
     * @param {ioBroker.State | null | undefined} state
     */
    async onStateChange(id, state) {
        try {
            if (state) {
                if (!state.ack) {
                    const vin = id.split(".")[2];
                    let body = "";
                    let contentType = "";
                    if (id.indexOf("Settings.") != -1) {
                        if (this.config.type === "id") {
                            const action = id.split(".")[5];
                            const settingsPath = id.split(".")[4];
                            const pre = this.name + "." + this.instance;
                            const states = await this.getStatesAsync(pre + "." + vin + ".status." + settingsPath + ".*");
                            const body = {};
                            const allIds = Object.keys(states);
                            allIds.forEach((keyName) => {
                                const key = keyName.split(".").splice(-1)[0];
                                if (key.indexOf("Timestamp") === -1) {
                                    body[key] = states[keyName].val;
                                }
                            });
                            body[action] = state.val;
                            const firstPart = settingsPath.split("Settings")[0];
                            this.setIdRemote(vin, firstPart, "settings", body).catch(() => {
                                this.log.error("failed set state " + action);
                            });
                            return;
                        }
                    }

                    if (id.indexOf("remote.") !== -1) {
                        const action = id.split(".")[4];
                        if (action === "batterycharge") {
                            body = '<?xml version="1.0" encoding= "UTF-8" ?>\n<action>\n   <type>start</type>\n</action>';
                            if (state.val === false) {
                                body = '<?xml version="1.0" encoding= "UTF-8" ?>\n<action>\n   <type>stop</type>\n</action>';
                            }
                            contentType = "application/vnd.vwg.mbb.ChargerAction_v1_0_0+xml";
                            this.setVehicleStatus(vin, "$homeregion/fs-car/bs/batterycharge/v1/$type/$country/vehicles/$vin/charger/actions", body, contentType).catch(() => {
                                this.log.error("failed set state");
                            });
                        }
                        if (action === "maxChargeCurrent") {
                            body =
                                '<action xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:noNamespaceSchemaLocation="ChargerAction_v1_0_0.xsd">\n<type>setSettings</type> \n  <settings> \n<maxChargeCurrent>' +
                                state.val +
                                "</maxChargeCurrent> \n  </settings>\n</action>";
                            contentType = "application/vnd.vwg.mbb.ChargerAction_v1_0_0+xml";
                            this.setVehicleStatus(vin, "$homeregion/fs-car/bs/batterycharge/v1/$type/$country/vehicles/$vin/charger/actions", body, contentType).catch(() => {
                                this.log.error("failed set state");
                            });
                        }
                        if (action === "charging") {
                            if (this.config.type === "id") {
                                const value = state.val ? "start" : "stop";
                                this.setIdRemote(vin, action, value).catch(() => {
                                    this.log.error("failed set state " + action);
                                });
                                return;
                            }
                        }

                        if (action === "climatisation" || action === "climatisationv2") {
                            if (this.config.type === "id") {
                                const value = state.val ? "start" : "stop";
                                this.setIdRemote(vin, action, value).catch(() => {
                                    this.log.error("failed set state " + action);
                                });
                                return;
                            } else {
                                body = '<?xml version="1.0" encoding= "UTF-8" ?>\n<action>\n   <type>startClimatisation</type>\n</action>';
                                if (action === "climatisationv2") {
                                    const heaterSourceState = await this.getStateAsync(vin + ".climater.settings.heaterSource.content");
                                    let heaterSource = "electric";
                                    if (heaterSourceState.val) {
                                        heaterSource = heaterSourceState.val;
                                    }
                                    body =
                                        '<?xml version="1.0" encoding= "UTF-8" ?>\n<action>\n   <type>startClimatisation</type> <settings> <heaterSource>' +
                                        heaterSource +
                                        "</heaterSource> </settings>\n</action>";
                                }
                                if (state.val === false) {
                                    body = '<?xml version="1.0" encoding= "UTF-8" ?>\n<action>\n   <type>stopClimatisation</type>\n</action>';
                                }
                                contentType = "application/vnd.vwg.mbb.ClimaterAction_v1_0_0+xml";
                                this.setVehicleStatus(vin, "$homeregion/fs-car/bs/climatisation/v1/$type/$country/vehicles/$vin/climater/actions", body, contentType).catch(() => {
                                    this.log.error("failed set state");
                                });
                            }
                        }

                        if (action === "ventilation" || action === "ventilationv2") {
                            const idArray = id.split(".");
                            idArray.pop();
                            idArray.push(action + "Duration");
                            const ventilationDurationPath = idArray.join(".");
                            const durationState = await this.getStateAsync(ventilationDurationPath);
                            let duration = 30;
                            if (durationState && durationState.val) {
                                duration = durationState.val;
                            }
                            let body =
                                '<?xml version="1.0" encoding= "UTF-8" ?>\n<performAction xmlns="http://audi.de/connect/rs">\n   <quickstart>\n      <active>true</active>\n<climatisationDuration>' +
                                duration +
                                "</climatisationDuration>\n	<startMode>" +
                                action +
                                "</startMode></quickstart>\n</performAction>";
                            if (state.val === false) {
                                body =
                                    '<?xml version="1.0" encoding= "UTF-8" ?>\n<performAction xmlns="http://audi.de/connect/rs">\n   <quickstop>\n      <active>false</active>\n   </quickstop>\n</performAction>';
                            }
                            contentType = "application/vnd.vwg.mbb.RemoteStandheizung_v2_0_2+xml";
                            if (action === "ventilationv2") {
                                body = '{"performAction":{"quickstart":{"startMode":"ventilation","active":true,"climatisationDuration":' + duration + "}}}";
                                if (state.val === false) {
                                    body = '{"performAction":{"quickstop":{"active":false}}}';
                                }
                                contentType = "application/vnd.vwg.mbb.RemoteStandheizung_v2_0_2+json";
                            }

                            const secToken = await this.requestSecToken(vin, "rheating_v1/operations/P_QSACT");
                            this.setVehicleStatus(vin, "$homeregion/fs-car/bs/rs/v1/$type/$country/vehicles/$vin/action", body, contentType, secToken).catch(() => {
                                this.log.error("failed set state");
                            });
                        }

                        if (action === "climatisationTemperature") {
                            let temp = 2950;
                            if (state.val && !isNaN(state.val)) {
                                temp = (parseFloat(state.val) + 273) * 10;
                            }

                            const climatisationWithoutHVpowerState = await this.getStateAsync(vin + ".climater.settings.climatisationWithoutHVpower.content");
                            let climatisationWithoutHVpower = false;

                            if (climatisationWithoutHVpowerState.val) {
                                climatisationWithoutHVpower = climatisationWithoutHVpowerState.val;
                            }
                            const heaterSourceState = await this.getStateAsync(vin + ".climater.settings.heaterSource.content");
                            let heaterSource = "electric";
                            if (heaterSourceState.val) {
                                heaterSource = heaterSourceState.val;
                            }
                            body =
                                '<?xml version="1.0" encoding= "UTF-8" ?>\n<action>\n   <type>setSettings</type> <settings> <targetTemperature>' +
                                temp +
                                "</targetTemperature> <climatisationWithoutHVpower>" +
                                climatisationWithoutHVpower +
                                "</climatisationWithoutHVpower> <heaterSource>" +
                                heaterSource +
                                "</heaterSource> </settings>\n</action>";
                            contentType = "application/vnd.vwg.mbb.ClimaterAction_v1_0_0+xml";
                            this.setVehicleStatus(vin, "$homeregion/fs-car/bs/climatisation/v1/$type/$country/vehicles/$vin/climater/actions", body, contentType).catch(() => {
                                this.log.error("failed set state");
                            });
                        }

                        if (action === "windowheating") {
                            body = '<?xml version="1.0" encoding= "UTF-8" ?>\n<action>\n   <type>startWindowHeating</type>\n</action>';
                            if (state.val === false) {
                                body = '<?xml version="1.0" encoding= "UTF-8" ?>\n<action>\n   <type>stopWindowHeating</type>\n</action>';
                            }
                            contentType = "application/vnd.vwg.mbb.ClimaterAction_v1_0_0+xml";
                            this.setVehicleStatus(vin, "$homeregion/fs-car/bs/climatisation/v1/$type/$country/vehicles/$vin/climater/actions", body, contentType).catch(() => {
                                this.log.error("failed set state");
                            });
                        }
                        if (action === "flash") {
                            //HONK_AND_FLASH
                            const idArray = id.split(".");
                            idArray.pop();
                            idArray.pop();
                            idArray.push("position.carCoordinate");
                            const posId = idArray.join(".");
                            const longitude = await this.getStateAsync(posId + ".longitude");
                            const latitude = await this.getStateAsync(posId + ".latitude");
                            if (!longitude || !latitude) {
                                this.log.info("No Location available, location information needed for this action");
                                return;
                            }
                            body = '{"honkAndFlashRequest":{"serviceOperationCode":"FLASH_ONLY","userPosition":{"latitude":' + latitude.val + ',"longitude":' + longitude.val + "}}}";
                            contentType = "application/json; charset=UTF-8";
                            this.setVehicleStatus(vin, "$homeregion/fs-car/bs/rhf/v1/$type/$country/vehicles/$vin/honkAndFlash", body, contentType).catch(() => {
                                this.log.error("failed set state");
                            });
                        }

                        if (action === "honk") {
                            //
                            const idArray = id.split(".");
                            idArray.pop();
                            idArray.pop();
                            idArray.push("position.carCoordinate");
                            const posId = idArray.join(".");
                            const longitude = await this.getStateAsync(posId + ".longitude");
                            const latitude = await this.getStateAsync(posId + ".latitude");
                            if (!longitude || !latitude) {
                                this.log.info("No Location available, location information needed for this action");
                                return;
                            }
                            body = '{"honkAndFlashRequest":{"serviceOperationCode":"HONK_AND_FLASH","userPosition":{"latitude":' + latitude.val + ',"longitude":' + longitude.val + "}}}";
                            contentType = "application/json; charset=UTF-8";
                            this.setVehicleStatus(vin, "$homeregion/fs-car/bs/rhf/v1/$type/$country/vehicles/$vin/honkAndFlash", body, contentType).catch(() => {
                                this.log.error("failed set state");
                            });
                        }

                        if (action === "standheizung" || action === "standheizungv2") {
                            body =
                                '<?xml version="1.0" encoding= "UTF-8" ?>\n<performAction xmlns="http://audi.de/connect/rs">\n   <quickstart>\n      <active>true</active>\n   </quickstart>\n</performAction>';
                            if (state.val === false) {
                                body =
                                    '<?xml version="1.0" encoding= "UTF-8" ?>\n<performAction xmlns="http://audi.de/connect/rs">\n   <quickstop>\n      <active>false</active>\n   </quickstop>\n</performAction>';
                            }
                            contentType = "application/vnd.vwg.mbb.RemoteStandheizung_v2_0_0+xml";
                            if (action === "standheizungv2") {
                                body = '{"performAction":{"quickstart":{"startMode":"heating","active":true,"climatisationDuration":30}}}';
                                if (state.val === false) {
                                    body = '{"performAction":{"quickstop":{"active":false}}}';
                                }
                                contentType = "application/vnd.vwg.mbb.RemoteStandheizung_v2_0_2+json";
                            }

                            const secToken = await this.requestSecToken(vin, "rheating_v1/operations/P_QSACT");
                            this.setVehicleStatus(vin, "$homeregion/fs-car/bs/rs/v1/$type/$country/vehicles/$vin/action", body, contentType, secToken).catch(() => {
                                this.log.error("failed set state");
                            });
                        }
                        if (action === "lock" || action === "lockv2") {
                            body = '<?xml version="1.0" encoding= "UTF-8" ?>\n<rluAction xmlns="http://audi.de/connect/rlu">\n   <action>lock</action>\n</rluAction>';
                            let lockAction = "LOCK";
                            if (state.val === false) {
                                body = '<?xml version="1.0" encoding= "UTF-8" ?>\n<rluAction xmlns="http://audi.de/connect/rlu">\n   <action>unlock</action>\n</rluAction>';
                                lockAction = "UNLOCK";
                            }
                            contentType = "application/vnd.vwg.mbb.RemoteLockUnlock_v1_0_0+xml";
                            const secToken = await this.requestSecToken(vin, "rlu_v1/operations/" + lockAction);
                            this.setVehicleStatus(vin, "$homeregion/fs-car/bs/rlu/v1/$type/$country/vehicles/$vin/actions", body, contentType, secToken).catch(() => {
                                this.log.error("failed set state");
                            });
                        }
                    }
                } else {
                    const vin = id.split(".")[2];
                    if (id.indexOf("climatisationState.content") !== -1) {
                        let value = false;
                        if (state.val === "on" || state.val === "heating") {
                            value = true;
                        }
                        this.setState(vin + ".remote.climatisation", value, true);
                        this.setState(vin + ".remote.climatisationv2", value, true);
                    }
                    if (id.indexOf("maxChargeCurrent.content") !== -1) {
                        this.setState(vin + ".remote.maxChargeCurrent", state.val, true);
                    }
                    if (id.indexOf("climatisationStatus.climatisationState") !== -1) {
                        let value = false;
                        if (state.val === "on" || state.val === "heating") {
                            value = true;
                        }
                        this.setState(vin + ".remote.climatisation", value, true);
                    }
                    if (id.indexOf("chargingStatus.chargingState") !== -1) {
                        if (this.config.type === "id") {
                            this.setState(vin + ".remote.charging", state.val !== "readyForCharging" ? true : false, true);
                        } else {
                            this.setState(vin + ".remote.batterycharge", state.val !== "readyForCharging" ? true : false, true);
                        }
                    }
                    if (id.indexOf(".status.isCarLocked") !== -1) {
                        this.setState(vin + ".remote.lock", state.val, true);
                    }

                    if (id.indexOf("carCoordinate.latitude") !== -1 && state.ts === state.lc) {
                        const longitude = await this.getStateAsync(id.replace("latitude", "longitude"));
                        const longitudeValue = parseFloat(longitude.val);

                        await this.setObjectNotExistsAsync(vin + ".position.latitudeConv", {
                            type: "state",
                            common: {
                                name: "latitude converted",
                                role: "indicator",
                                type: "mixed",
                                write: false,
                                read: true,
                            },
                            native: {},
                        });
                        this.setState(vin + ".position.latitudeConv", state.val / 1000000, true);
                        await this.setObjectNotExistsAsync(vin + ".position.longitudeConv", {
                            type: "state",
                            common: {
                                name: "longitude converted",
                                role: "indicator",
                                type: "mixed",
                                write: false,
                                read: true,
                            },
                            native: {},
                        });
                        this.setState(vin + ".position.longitudeConv", longitudeValue / 1000000, true);
                        if (!this.config.reversePos) {
                            this.log.debug("reverse pos deactivated");
                            return;
                        }
                        this.log.debug("reverse pos started");
                        request.get(
                            {
                                url: "https://nominatim.openstreetmap.org/reverse?lat=" + state.val / 1000000 + "&lon=" + longitudeValue / 1000000 + "&format=json",

                                headers: {
                                    "User-Agent": "ioBroker/vw-connect",
                                },
                                json: true,
                                followAllRedirects: true,
                            },
                            async (err, resp, body) => {
                                this.log.debug("reverse pos received");
                                this.log.debug(JSON.stringify(body));
                                if (err || resp.statusCode >= 400 || !body) {
                                    body && this.log.error(JSON.stringify(body));
                                    resp && this.log.error(resp.statusCode.toString());
                                    err && this.log.error(err);
                                    return;
                                }
                                if (body.display_name) {
                                    try {
                                        const number = body.address.house_number || "";
                                        const city = body.address.city || body.address.town || body.address.village;
                                        const fullAdress = body.address.road + " " + number + ", " + body.address.postcode + " " + city + ", " + body.address.country;
                                        await this.setObjectNotExistsAsync(vin + ".position.address.displayName", {
                                            type: "state",
                                            common: {
                                                name: "displayName",
                                                role: "indicator",
                                                type: "mixed",
                                                write: false,
                                                read: true,
                                            },
                                            native: {},
                                        });
                                        this.setState(vin + ".position.address.displayName", fullAdress, true);
                                        Object.keys(body.address).forEach((key) => {
                                            this.setObjectNotExistsAsync(vin + ".position.address." + key, {
                                                type: "state",
                                                common: {
                                                    name: key,
                                                    role: "indicator",
                                                    type: "mixed",
                                                    write: false,
                                                    read: true,
                                                },
                                                native: {},
                                            })
                                                .then(() => {
                                                    this.setState(vin + ".position.address." + key, body.address[key], true);
                                                })
                                                .catch((error) => {
                                                    this.log.error(error);
                                                });
                                        });
                                    } catch (err) {
                                        this.log.error(err);
                                    }
                                } else {
                                    this.log.error(JSON.stringify(body));
                                }
                            }
                        );
                    }
                }
            } else {
                // The state was deleted
                //	this.log.info(`state ${id} deleted`);
            }
        } catch (err) {
            this.log.error("Error in OnStateChange: " + err);
        }
    }
}

// @ts-ignore parent is a valid property on module
if (module.parent) {
    // Export the constructor in compact mode
    /**
     * @param {Partial<ioBroker.AdapterOptions>} [options={}]
     */
    module.exports = (options) => new VwWeconnect(options);
} else {
    // otherwise start the instance directly
    new VwWeconnect();
}
