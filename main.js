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
const uuidv4 = require("uuid/v4");
const traverse = require("traverse");
const jsdom = require("jsdom");
const { JSDOM } = jsdom;
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

        this.jar = request.jar();

        this.refreshTokenInterval = null;
        this.vwrefreshTokenInterval = null;
        this.updateInterval = null;
        this.fupdateInterval = null;
        this.refreshTokenTimeout = null;

        this.homeRegion = "https://msg.volkswagen.de";

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
        if (this.config.type === "audi") {
            this.type = "Audi";
            this.country = "DE";
            this.clientId = "mmiconnect_android";
            this.xclientId = "77869e21-e30a-4a92-b016-48ab7d3db1d8";
            this.scope = "openid profile email mbb offline_access mbbuserid myaudi selfservice:read selfservice:write";
            this.redirect = "";
            this.xrequest = "";
            this.responseType = "token id_token";
            this.xappversion = "3.14.0";
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
                                        this.getHomeRegion(vin)
                                            .catch(() => {
                                                this.log.debug("get home region Failed");
                                            })
                                            .finally(() => {
                                                this.getVehicleData(vin).catch(() => {
                                                    this.log.error("get vehicle data Failed");
                                                });
                                                this.getVehicleRights(vin).catch(() => {
                                                    this.log.error("get vehicle rights Failed");
                                                });
                                                this.requestStatusUpdate(vin)
                                                    .then(() => {
                                                        this.statesArray.forEach((state) => {
                                                            this.getVehicleStatus(vin, state.url, state.path, state.element, state.element2, state.element3, state.element4).catch(() => {
                                                                this.log.debug("error while getting " + state.url);
                                                            });
                                                        });
                                                    })
                                                    .catch(() => {
                                                        this.log.error("status update Failed");
                                                    });
                                            });
                                    });
                                }

                                this.updateInterval = setInterval(() => {
                                    if (this.config.type === "go") {
                                        this.getVehicles();
                                        return;
                                    }
                                    this.vinArray.forEach((vin) => {
                                        this.statesArray.forEach((state) => {
                                            this.getVehicleStatus(vin, state.url, state.path, state.element, state.element2).catch(() => {
                                                this.log.debug("error while getting " + state.url);
                                            });
                                        });
                                    });
                                }, this.config.interval * 60 * 1000);
                                if (this.config.forceinterval > 0) {
                                    this.fupdateInterval = setInterval(() => {
                                        if (this.config.type === "go") {
                                            this.getVehicles();
                                            return;
                                        }
                                        this.vinArray.forEach((vin) => {
                                            this.requestStatusUpdate(vin);
                                        });
                                    }, this.config.forceinterval * 60 * 1000);
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
        return new Promise((resolve, reject) => {
            const nonce = this.getNonce();
            const state = uuidv4();
            const [code_verifier, codeChallenge] = this.getCodeChallenge();

            let method = "GET";
            let form = {};
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
            if (this.config.type === "vw" || this.config.type === "go") {
                url += "&code_challenge=" + codeChallenge + "&code_challenge_method=s256";
            }
            if (this.config.type === "audi") {
                url = "https://id.audi.com/v1/token";
                method = "POST";
                form = {
                    client_id: this.clientId,
                    scope: this.scope,
                    response_type: this.responseType,
                    grant_type: "password",
                    username: this.config.user,
                    password: this.config.password,
                };
            }
            request(
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
                    followAllRedirects: true,
                },
                (err, resp, body) => {
                    if (err || (resp && resp.statusCode >= 400)) {
                        this.log.error("Failed in first login step ");
                        err && this.log.error(err);
                        resp && this.log.error(resp.statusCode);
                        body && this.log.error(JSON.stringify(body));
                        reject();
                        return;
                    }

                    try {
                        if (this.config.type === "audi") {
                            const tokens = JSON.parse(body);
                            this.getVWToken(tokens, tokens.id_token, reject, resolve);
                            return;
                        }

                        const dom = new JSDOM(body);
                        const form = {};
                        const formLogin = dom.window.document.querySelector("#emailPasswordForm");
                        if (formLogin) {
                            this.log.debug("parseEmailForm");
                            for (const formElement of dom.window.document.querySelector("#emailPasswordForm").children) {
                                if (formElement.type === "hidden") {
                                    form[formElement.name] = formElement.value;
                                }
                            }
                            form["email"] = this.config.user;
                        } else {
                            this.log.error("No Login Form found");
                            this.log.debug(body);
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
                                followAllRedirects: true,
                            },
                            (err, resp, body) => {
                                if (err || (resp && resp.statusCode >= 400)) {
                                    this.log.error("Failed to get login identifier");
                                    err && this.log.error(err);
                                    resp && this.log.error(resp.statusCode);
                                    body && this.log.error(JSON.stringify(body));
                                    reject();
                                    return;
                                }
                                try {
                                    const dom = new JSDOM(body);
                                    const form = {};
                                    const formLogin = dom.window.document.querySelector("#credentialsForm");
                                    if (formLogin) {
                                        this.log.debug("parsePasswordForm");
                                        for (const formElement of dom.window.document.querySelector("#credentialsForm").children) {
                                            if (formElement.type === "hidden") {
                                                form[formElement.name] = formElement.value;
                                            }
                                        }
                                        form["password"] = this.config.password;
                                    } else {
                                        this.log.error("No Login Form found. Please check your E-Mail in the app.");
                                        this.log.debug(body);
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
                                            followAllRedirects: false,
                                        },
                                        (err, resp, body) => {
                                            if (err || (resp && resp.statusCode >= 400)) {
                                                this.log.error("Failed to get login authenticate");
                                                err && this.log.error(err);
                                                resp && this.log.error(resp.statusCode);
                                                body && this.log.error(JSON.stringify(body));
                                                reject();
                                                return;
                                            }

                                            try {
                                                this.log.debug(JSON.stringify(body));
                                                this.log.debug(JSON.stringify(resp.headers));
                                                if (resp.headers.location.split("&").length <= 1) {
                                                    this.log.error("No userId found, please check your account");
                                                    return;
                                                }
                                                this.config.userid = resp.headers.location.split("&")[2].split("=")[1];
                                                let getRequest = request.get(
                                                    {
                                                        url: resp.headers.location,
                                                        headers: {
                                                            "User-Agent":
                                                                "Mozilla/5.0 (Linux; Android 10) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/74.0.3729.185 Mobile Safari/537.36",
                                                            Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3",
                                                            "Accept-Language": "en-US,en;q=0.9",
                                                            "Accept-Encoding": "gzip, deflate",
                                                            "x-requested-with": this.xrequest,
                                                        },
                                                        jar: this.jar,
                                                        followAllRedirects: true,
                                                    },
                                                    (err, resp, body) => {
                                                        if (err) {
                                                            this.log.debug(err);
                                                            this.getTokens(getRequest, code_verifier, reject, resolve);
                                                        } else {
                                                            this.log.debug("No Token received visiting url and accept the permissions.");
                                                            const dom = new JSDOM(body);
                                                            let form = "";
                                                            for (const formElement of dom.window.document.querySelectorAll("input")) {
                                                                if (formElement.type === "hidden") {
                                                                    form += formElement.name + "=" + formElement.value + "&";
                                                                }
                                                            }
                                                            getRequest = request.post(
                                                                {
                                                                    url: getRequest.uri.href,
                                                                    headers: {
                                                                        "Content-Type": "application/x-www-form-urlencoded",
                                                                        "User-Agent":
                                                                            "Mozilla/5.0 (Linux; Android 10) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/74.0.3729.185 Mobile Safari/537.36",
                                                                        Accept:
                                                                            "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3",
                                                                        "Accept-Language": "en-US,en;q=0.9",
                                                                        "Accept-Encoding": "gzip, deflate",
                                                                        "x-requested-with": this.xrequest,
                                                                        referer: getRequest.uri.href,
                                                                    },
                                                                    form: form,
                                                                    jar: this.jar,
                                                                    followAllRedirects: true,
                                                                },
                                                                (err, resp, body) => {
                                                                    if (err) {
                                                                        this.getTokens(getRequest, code_verifier, reject, resolve);
                                                                    } else {
                                                                        this.log.error("No Token received.");
                                                                        try {
                                                                            this.log.debug(body);
                                                                        } catch (error) {
                                                                            this.log.error(error);
                                                                            reject();
                                                                        }
                                                                    }
                                                                }
                                                            );
                                                        }
                                                    }
                                                );
                                            } catch (error) {
                                                this.log.error("Login was not successful, please check your login credentials and selected type");
                                                err && this.log.error(err);
                                                this.log.error(error);
                                                this.log.error(error.stack);
                                                reject();
                                            }
                                        }
                                    );
                                } catch (error) {
                                    this.log.error(error);
                                    reject();
                                }
                            }
                        );
                    } catch (error) {
                        this.log.error(error);
                        reject();
                    }
                }
            );
        });
    }

    replaceVarInUrl(url, vin) {
        return url
            .replace("/$vin/", "/" + vin + "/")
            .replace("$homeregion/", this.homeRegion + "/")
            .replace("/$type/", "/" + this.type + "/")
            .replace("/$country/", "/" + this.country + "/")
            .replace("/$tripType", "/" + this.config.tripType);
    }
    getTokens(getRequest, code_verifier, reject, resolve) {
        let hash = "";
        if (getRequest.uri.hash) {
            hash = getRequest.uri.hash;
        } else {
            hash = getRequest.uri.query;
        }
        const hashArray = hash.split("&");
        let state;
        let jwtauth_code;
        let jwtaccess_token;
        let jwtid_token;
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
        });
        // const state = hashArray[0].substring(hashArray[0].indexOf("=") + 1);
        // const jwtauth_code = hashArray[1].substring(hashArray[1].indexOf("=") + 1);
        // const jwtaccess_token = hashArray[2].substring(hashArray[2].indexOf("=") + 1);
        // const jwtid_token = hashArray[5].substring(hashArray[5].indexOf("=") + 1);
        let body = "auth_code=" + jwtauth_code + "&id_token=" + jwtid_token;
        let url = "https://tokenrefreshservice.apps.emea.vwapps.io/exchangeAuthCode";
        if (this.config.type === "vw") {
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
        request.post(
            {
                url: url,
                headers: {
                    // "user-agent": "okhttp/3.7.0",
                    "X-App-version": this.xappversion,
                    "content-type": "application/x-www-form-urlencoded",
                    "x-app-name": this.xappname,
                    accept: "application/json",
                },
                body: body,
                jar: this.jar,
                followAllRedirects: false,
            },
            (err, resp, body) => {
                if (err || (resp && resp.statusCode >= 400)) {
                    this.log.error("Failed to get token");
                    err && this.log.error(err);
                    resp && this.log.error(resp.statusCode);
                    body && this.log.error(JSON.stringify(body));
                    reject();
                    return;
                }
                try {
                    const tokens = JSON.parse(body);

                    this.getVWToken(tokens, jwtid_token, reject, resolve);
                } catch (error) {
                    this.log.error(error);
                    reject();
                }
            }
        );
    }

    getVWToken(tokens, jwtid_token, reject, resolve) {
        this.config.atoken = tokens.access_token;
        this.config.rtoken = tokens.refresh_token;
        this.refreshTokenInterval = setInterval(() => {
            this.refreshToken().catch(() => {});
        }, 0.9 * 60 * 60 * 1000); // 0.9hours
        if (this.config.type === "go") {
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
                followAllRedirects: true,
            },
            (err, resp, body) => {
                if (err || (resp && resp.statusCode >= 400)) {
                    err && this.log.error(err);
                    resp && this.log.error(resp.statusCode);
                    reject();
                    return;
                }
                try {
                    const tokens = JSON.parse(body);
                    this.config.vwatoken = tokens.access_token;
                    this.config.vwrtoken = tokens.refresh_token;
                    this.vwrefreshTokenInterval = setInterval(() => {
                        this.refreshToken(true).catch(() => {});
                    }, 0.9 * 60 * 60 * 1000); //0.9hours
                    resolve();
                } catch (error) {
                    this.log.error(error);
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
        if (isVw) {
            url = "https://mbboauth-1d.prd.ece.vwg-connect.com/mbbcoauth/mobile/oauth2/v1/token";
            rtoken = this.config.vwrtoken;
            body = "grant_type=refresh_token&scope=sc2%3Afal&token=" + rtoken;
        } else if (this.config.type === "audi") {
            url = "https://id.audi.com/v1/token";
            body = "";
            form = {
                client_id: this.clientId,
                grant_type: "refresh_token",
                response_type: "token id_token",
                refresh_token: rtoken,
            };
        } else if (this.config.type === "go") {
            url = "https://dmp.apps.emea.vwapps.io/mobility-platform/token";
            body = "";
            form = {
                scope: "openid+profile+address+email+phone",
                client_id: this.clientId,
                grant_type: "refresh_token",
                refresh_token: rtoken,
            };
        }
        return new Promise((resolve, reject) => {
            this.log.debug("refreshToken");
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
                        this.log.error("Failing to refresh token.");
                        err && this.log.error(err);
                        resp && this.log.error(resp.statusCode);
                        reject();
                        return;
                    }
                    try {
                        this.log.debug(body);
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
                        }
                        resolve();
                    } catch (error) {
                        this.log.error("Failing to parse refresh token. The instance will do restart and try a relogin.");
                        this.log.error(error);
                        this.log.error(JSON.stringify(body));
                        this.log.error(resp.statusCode);
                        this.log.error(error.stack);
                        this.restart();
                    }
                }
            );
        });
    }

    getPersonalData() {
        return new Promise((resolve, reject) => {
            if (this.config.type === "audi" || this.config.type === "go") {
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
                        resp && this.log.error(resp.statusCode);
                        reject();
                        return;
                    }
                    try {
                        if (body.error) {
                            this.log.error(JSON.stringify(body.error));
                            reject();
                        }
                        this.log.debug(body);
                        const data = JSON.parse(body);
                        this.config.identifier = data.businessIdentifierValue;
                        Object.keys(data).forEach((key) => {
                            this.setObjectNotExists("personal." + key, {
                                type: "state",
                                common: {
                                    name: key,
                                    role: "indicator",
                                    type: "mixed",
                                    write: false,
                                    read: true,
                                },
                                native: {},
                            });
                            this.setState("personal." + key, data[key], true);
                        });

                        resolve();
                    } catch (error) {
                        this.log.error(error);
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
                        resp && this.log.error(resp.statusCode);
                        reject();
                        return;
                    }
                    try {
                        if (body.error) {
                            this.log.error(JSON.stringify(body.error));
                            reject();
                        }
                        this.log.debug(body);
                        if (body.homeRegion && body.homeRegion.baseUri && body.homeRegion.baseUri.content) {
                            if (body.homeRegion.baseUri.content !== "https://mal-1a.prd.ece.vwg-connect.com/api") {
                                this.homeRegion = body.homeRegion.baseUri.content.split("/api")[0].replace("mal-", "fal-");
                                this.log.debug("Set URL to: " + this.homeRegion);
                            }
                        }
                        resolve();
                    } catch (error) {
                        this.log.error(error);
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
                        resp && this.log.error(resp.statusCode);
                        reject();
                        return;
                    }
                    try {
                        if (body.error) {
                            this.log.error(JSON.stringify(body.error));
                            reject();
                        }
                        this.log.debug(body);
                        const data = JSON.parse(body);
                        Object.keys(data).forEach((key) => {
                            this.setObjectNotExists("car." + key, {
                                type: "state",
                                common: {
                                    name: key,
                                    role: "indicator",
                                    type: "mixed",
                                    write: false,
                                    read: true,
                                },
                                native: {},
                            });
                            this.setState("car." + key, data[key], true);
                        });

                        resolve();
                    } catch (error) {
                        this.log.error(error);
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
                headers = {
                    "user-agent": "okhttp/3.9.1",
                    authorization: "Bearer " + this.config.atoken,
                    "accept-language": "de-DE",
                    "dmp-api-version": "v2.0",
                    "dmp-client-info": "Android/7.0/VW Connect/App/2.9.4",
                    accept: "application/json;charset=UTF-8",
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
                        err && this.log.error(err);
                        resp && this.log.error(resp.statusCode);
                        reject();
                    }
                    try {
                        if (body.errorCode) {
                            this.log.error(JSON.stringify(body));
                            reject();
                            return;
                        }
                        this.log.debug(JSON.stringify(body));
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

                                const result = body.vehicleData;

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
                                        adapter.setObjectNotExists(vin + ".status." + modPath.join("."), {
                                            type: "state",
                                            common: {
                                                name: this.key,
                                                role: "indicator",
                                                type: "mixed",
                                                write: false,
                                                read: true,
                                            },
                                            native: {},
                                        });
                                        adapter.setState(vin + ".status." + modPath.join("."), value || this.node, true);
                                    }
                                });
                            });
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
                                    role: "button",
                                    write: true,
                                },
                                native: {},
                            });
                            this.setObjectNotExists(vehicle + ".remote.climatisation", {
                                type: "state",
                                common: {
                                    name: "Start Climatisation",
                                    type: "boolean",
                                    role: "button",
                                    write: true,
                                },
                                native: {},
                            });
                            this.setObjectNotExists(vehicle + ".remote.climatisationTemperature", {
                                type: "state",
                                common: {
                                    name: "Temperature in °C",
                                    type: "boolean",
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
                                    role: "button",
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
                            this.setObjectNotExists(vehicle + ".remote.ventilation", {
                                type: "state",
                                common: {
                                    name: "Start Ventilation",
                                    type: "boolean",
                                    role: "button",
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
                            this.setObjectNotExists(vehicle + ".remote.heating", {
                                type: "state",
                                common: {
                                    name: "Start Heizung",
                                    type: "boolean",
                                    role: "button",
                                    write: true,
                                },
                                native: {},
                            });
                            this.setObjectNotExists(vehicle + ".remote.heatingDuration", {
                                type: "state",
                                common: {
                                    name: "Dauer Heizung in min",
                                    role: "number",
                                    write: true,
                                },
                                native: {},
                            });
                        });
                        resolve();
                    } catch (error) {
                        this.log.error(error);
                        this.log.error(error.stack);
                        this.log.error("Not able to find vehicle, did you choose the correct type?");
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
            if (this.config.type !== "vw") {
                url = this.replaceVarInUrl("https://msg.volkswagen.de/fs-car/promoter/portfolio/v1/$type/$country/vehicle/$vin/carportdata", vin);
                accept = "application/json";
            }
            let atoken = this.config.vwatoken;
            if (this.config.type === "audi") {
                url = "https://msg.audi.de/myaudi/vehicle-management/v1/vehicles";
                atoken = this.config.atoken;
                accept = "application/json";
            }
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
                        err && this.log.error(err);
                        resp && this.log.error(resp.statusCode);
                        body && this.log.error(JSON.stringify(body));
                        reject();
                        return;
                    }
                    try {
                        this.log.debug(JSON.stringify(body));
                        const adapter = this;
                        let result = body.vehicleData;
                        if (this.config.type === "audi") {
                            const index = body.vehicles.findIndex((vehicle) => vehicle.vin === vin);
                            result = body.vehicles[index];
                        }
                        if (resp) {
                            this.etags[url] = resp.headers.etag;
                            if (resp.statusCode === 304) {
                                this.log.debug("304 No values updated");
                                resolve();
                                return;
                            }
                        }
                        traverse(result).forEach(function (value) {
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
                                adapter.setObjectNotExists(vin + ".general." + modPath.join("."), {
                                    type: "state",
                                    common: {
                                        name: this.key,
                                        role: "indicator",
                                        type: "mixed",
                                        write: false,
                                        read: true,
                                    },
                                    native: {},
                                });
                                adapter.setState(vin + ".general." + modPath.join("."), value || this.node, true);
                            }
                        });

                        resolve();
                    } catch (error) {
                        this.log.error(error);
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
            if (this.config.type === "vw") {
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
                        err && this.log.error(err);
                        resp && this.log.error(resp.statusCode);
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
                                    adapter.setObjectNotExists(vin + ".rights." + modPath.join("."), {
                                        type: "state",
                                        common: {
                                            name: this.key,
                                            role: "indicator",
                                            type: "mixed",
                                            write: false,
                                            read: true,
                                        },
                                        native: {},
                                    });
                                    adapter.setState(vin + ".rights." + modPath.join("."), value || this.node, true);
                                }
                            }
                        });

                        resolve();
                    } catch (error) {
                        this.log.error(error);
                        reject();
                    }
                }
            );
        });
    }

    requestStatusUpdate(vin) {
        return new Promise((resolve, reject) => {
            const url = this.replaceVarInUrl("$homeregion/fs-car/bs/vsr/v1/$type/$country/vehicles/$vin/requests", vin);
            let accept = "application/json";
            if (this.config.type === "vw") {
                accept =
                    "application/vnd.vwg.mbb.VehicleStatusReport_v1_0_0+json, application/vnd.vwg.mbb.climater_v1_0_0+json, application/vnd.vwg.mbb.carfinderservice_v1_0_0+json, application/vnd.volkswagenag.com-error-v1+json, application/vnd.vwg.mbb.genericError_v1_0_2+json";
            }
            request.post(
                {
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
                        err && this.log.error(err);
                        resp && this.log.error(resp.statusCode);
                        reject();
                        return;
                    }
                    try {
                        this.log.debug(JSON.stringify(body));
                        resolve();
                    } catch (error) {
                        this.log.error(error);
                        reject();
                    }
                }
            );
        });
    }

    getVehicleStatus(vin, url, path, element, element2, element3, element4) {
        return new Promise((resolve, reject) => {
            url = this.replaceVarInUrl(url, vin);
            if (path === "tripdata") {
                if (this.config.tripType === "none") {
                    resolve();
                    return;
                }
            }
            let accept = "application/json";
            if (this.config.type === "vw") {
                accept =
                    "application/vnd.vwg.mbb.VehicleStatusReport_v1_0_0+json, application/vnd.vwg.mbb.climater_v1_0_0+json, application/vnd.vwg.mbb.carfinderservice_v1_0_0+json, application/vnd.volkswagenag.com-error-v1+json, application/vnd.vwg.mbb.genericError_v1_0_2+json, */*";
                if (this.homeRegion === "https://msg.volkswagen.de") {
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
                        } else {
                            err && this.log.error(err);
                            resp && this.log.error(resp.statusCode);
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
                            this.setObjectNotExists(vin + ".position.isMoving", {
                                type: "state",
                                common: {
                                    name: "is car moving",
                                    role: "indicator",
                                    type: "boolean",
                                    write: false,
                                    read: true,
                                },
                                native: {},
                            });

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
                            this.log.debug(body);
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
                            if (path === "tripdata") {
                                if (this.config.tripType === "none") {
                                    resolve();
                                    return;
                                }
                                adapter.setObjectNotExists(vin + "." + path + ".lastTrip", {
                                    type: "state",
                                    common: {
                                        name: "numberOfLastTrip",
                                        role: "indicator",
                                        type: "mixed",
                                        write: false,
                                        read: true,
                                    },
                                    native: {},
                                });
                                adapter.setState(vin + "." + path + ".lastTrip", result.tripData.length, true);
                            }

                            if (path === "status") {
                            	this.setObjectNotExists(vin + ".status.isCarLocked", {
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
                            }
                            if (path === "climater") {
                            	this.setObjectNotExists(vin + ".climater.outsideTemperature", {
                            		type: "state",
                            		common: {
                            			name: "outside temperature",
                            			role: "indicator.temperature",
                            			type: "number",
                            			write: false,
                            			read: true,
                            		},
                            		native: {},
                            	});
                            }
                            
                            traverse(result).forEach(function (value) {
                                if (this.path.length > 0 && this.isLeaf) {
                                	var mainId = "";
                                	var subID = "";
                                    const modPath = this.path;
                                    this.path.forEach((pathElement, pathIndex) => {
                                        if (!isNaN(parseInt(pathElement))) {
                                        	if (path === "status") {
                                        		if (this.path[pathIndex -1] == 'data' && this.node.id)
                                        			mainID = this.node.id;
                                        		if (this.path[pathIndex -1] == 'field' && this.node.id)
                                        			subID = this.node.id;
                                        	}
                                            let stringPathIndex = parseInt(pathElement) + 1 + "";
                                            while (stringPathIndex.length < 2) stringPathIndex = "0" + stringPathIndex;
                                            const key = this.path[pathIndex - 1] + stringPathIndex;
                                            const parentIndex = modPath.indexOf(pathElement) - 1;
                                            modPath[parentIndex] = key;
                                            modPath.splice(parentIndex + 1, 1);
                                        }
                                    });

                                    adapter.setObjectNotExists(vin + "." + path + "." + modPath.join("."), {
                                        type: "state",
                                        common: {
                                            name: this.key,
                                            role: "indicator",
                                            type: "mixed",
                                            write: false,
                                            read: true,
                                        },
                                        native: {},
                                    });
                                    log("value = " + value + "/" + this.node + " of: " + modPath.join(".") + " ID = " + mainID + "/" + subID);
                                    if (mainID == "0x030104FFFF" && subID == "0x0301040001") {
                                    	adapter.setState(vin + "." + path + ".isCarLocked", value == 2, true);
                                    }
                                    adapter.setState(vin + "." + path + "." + modPath.join("."), value || this.node, true);
                                } else if ((path === "status" || path === "tripdata") && this.path.length > 0 && !isNaN(this.path[this.path.length - 1])) {
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

                                    if (this.node.field && this.node.field[this.node.field.length - 1].textId) {
                                        adapter.setObjectNotExists(vin + "." + path + "." + modPath.join("."), {
                                            type: "state",
                                            common: {
                                                name: this.node.field[this.node.field.length - 1].textId,
                                                role: "indicator",
                                                type: "mixed",
                                                write: false,
                                                read: true,
                                            },
                                            native: {},
                                        });
                                    }
                                    if (this.node.textId) {
                                        adapter.setObjectNotExists(vin + "." + path + "." + modPath.join("."), {
                                            type: "state",
                                            common: {
                                                name: this.node.textId,
                                                role: "indicator",
                                                type: "mixed",
                                                write: false,
                                                read: true,
                                            },
                                            native: {},
                                        });
                                    } else if (this.node.timestamp) {
                                        adapter.setObjectNotExists(vin + "." + path + "." + modPath.join("."), {
                                            type: "state",
                                            common: {
                                                name: this.node.timestamp,
                                                role: "indicator",
                                                type: "mixed",
                                                write: false,
                                                read: true,
                                            },
                                            native: {},
                                        });
                                    }
                                }
                            });
                            resolve();
                        } else {
                            this.log.error("Cannot find vehicle data " + path);
                            this.log.error(JSON.stringify(body));
                            reject();
                        }
                    } catch (error) {
                        this.log.error(error);
                        this.log.error(error.stack);
                        reject();
                    }
                }
            );
        });
    }

    setVehicleStatus(vin, url, body, contentType, secToken) {
        return new Promise((resolve, reject) => {
            url = this.replaceVarInUrl(url, vin);
            this.log.debug(body);
            this.log.debug(contentType);
            const headers = {
                "User-Agent": "okhttp/3.7.0",
                "X-App-Version": this.xappversion,
                "X-App-Name": this.xappname,
                Authorization: "Bearer " + this.config.vwatoken,
                "Accept-charset": "UTF-8",
                "Content-Type": contentType,
                Accept:
                    "application/json, application/vnd.vwg.mbb.ChargerAction_v1_0_0+xml,application/vnd.volkswagenag.com-error-v1+xml,application/vnd.vwg.mbb.genericError_v1_0_2+xml, application/vnd.vwg.mbb.RemoteStandheizung_v2_0_0+xml, application/vnd.vwg.mbb.genericError_v1_0_2+xml,application/vnd.vwg.mbb.RemoteLockUnlock_v1_0_0+xml,*/*",
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
                        resp && this.log.error(resp.statusCode);
                        reject();
                        return;
                    }
                    try {
                        this.log.debug(body);
                        if (body.indexOf("<error>") !== -1) {
                            this.log.error("Error response try to refresh token " + url);
                            this.log.error(JSON.stringify(body));
                            this.refreshToken(true);
                            reject();
                            return;
                        }
                        this.log.info(body);
                    } catch (error) {
                        this.log.error(error);
                        this.log.error(error.stack);
                        reject();
                    }
                }
            );
        });
    }
    requestSecToken(vin, service) {
        return new Promise((resolve, reject) => {
            request.get(
                {
                    url: "https://mal-1a.prd.ece.vwg-connect.com/api/rolesrights/authorization/v2/vehicles/" + vin + "/services/" + service + "/security-pin-auth-requested",
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
                        resp && this.log.error(resp.statusCode);
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
                            request.post(
                                {
                                    url: "https://mal-1a.prd.ece.vwg-connect.com/api/rolesrights/authorization/v2/security-pin-auth-completed",
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
                                        resp && this.log.error(resp.statusCode);
                                        reject();
                                        return;
                                    }
                                    try {
                                        this.log.debug(body);
                                        if (body.securityToken) {
                                            resolve(body.securityToken);
                                        } else {
                                            this.log.error("No Security token found");
                                            this.log.error(JSON.stringify(body));
                                            reject();
                                        }
                                    } catch (error) {
                                        this.log.error(error);
                                        reject();
                                    }
                                }
                            );
                        } else {
                            this.log.error("No Security information found");
                            this.log.error(JSON.stringify(body));
                            reject();
                        }
                    } catch (error) {
                        this.log.error(error);
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
            const digest = webcrypto.subtle.digest("SHA-512", concat).then((digest) => {
                const utf8Array = new Int8Array(digest);
                resolve(this.toHexString(utf8Array));
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
    /**
     * Is called when adapter shuts down - callback has to be called under any circumstances!
     * @param {() => void} callback
     */
    onUnload(callback) {
        try {
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
        if (state) {
            if (!state.ack) {
                const vin = id.split(".")[2];
                let body = "";
                let contentType = "";
                if (id.indexOf("remote") !== -1) {
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

                    if (action === "climatisation") {
                        body = '<?xml version="1.0" encoding= "UTF-8" ?>\n<action>\n   <type>startClimatisation</type>\n</action>';
                        if (state.val === false) {
                            body = '<?xml version="1.0" encoding= "UTF-8" ?>\n<action>\n   <type>stopClimatisation</type>\n</action>';
                        }
                        contentType = "application/vnd.vwg.mbb.ClimaterAction_v1_0_0+xml";
                        this.setVehicleStatus(vin, "$homeregion/fs-car/bs/climatisation/v1/$type/$country/vehicles/$vin/climater/actions", body, contentType).catch(() => {
                            this.log.error("failed set state");
                        });
                    }

                    if (action === "ventilation") {
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
                        const secToken = await this.requestSecToken(vin, "rheating_v1/operations/P_QSACT");
                        this.setVehicleStatus(vin, "$homeregion/fs-car/bs/rs/v1/$type/$country/vehicles/$vin/action", body, contentType, secToken).catch(() => {
                            this.log.error("failed set state");
                        });
                    }

                    if (action === "climatisationTemperature") {
                        let temp = 2950;
                        if (state.val && !isNaN(state.val)) {
                            temp = (parseFloat(state.val) + 273, 6) * 10;
                        }
                        body =
                            '<?xml version="1.0" encoding= "UTF-8" ?>\n<action>\n   <type>setSettings</type> <settings> <targetTemperature>' +
                            temp +
                            "</targetTemperature> <climatisationWithoutHVpower>false</climatisationWithoutHVpower> <heaterSource>electric</heaterSource> </settings>\n</action>";
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
                    if (action === "standheizung") {
                        body =
                            '<?xml version="1.0" encoding= "UTF-8" ?>\n<performAction xmlns="http://audi.de/connect/rs">\n   <quickstart>\n      <active>true</active>\n   </quickstart>\n</performAction>';
                        if (state.val === false) {
                            body =
                                '<?xml version="1.0" encoding= "UTF-8" ?>\n<performAction xmlns="http://audi.de/connect/rs">\n   <quickstop>\n      <active>false</active>\n   </quickstop>\n</performAction>';
                        }
                        contentType = "application/vnd.vwg.mbb.RemoteStandheizung_v2_0_0+xml";
                        const secToken = await this.requestSecToken(vin, "rheating_v1/operations/P_QSACT");
                        this.setVehicleStatus(vin, "$homeregion/fs-car/bs/rs/v1/$type/$country/vehicles/$vin/action", body, contentType, secToken).catch(() => {
                            this.log.error("failed set state");
                        });
                    }
                    if (action === "lock") {
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
                if (id.indexOf("carCoordinate.latitude") !== -1 && state.ts === state.lc) {
                    const vin = id.split(".")[2];
                    const longitude = await this.getStateAsync(id.replace("latitude", "longitude"));
                    const longitudeValue = parseFloat(longitude.val);

                    this.setObjectNotExists(vin + ".position.latitudeConv", {
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
                    this.setObjectNotExists(vin + ".position.longitudeConv", {
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
                        (err, resp, body) => {
                            this.log.debug("reverse pos received");
                            this.log.debug(JSON.stringify(body));
                            if (err || resp.statusCode >= 400 || !body) {
                                body && this.log.error(JSON.stringify(body));
                                resp && this.log.error(resp.statusCode);
                                err && this.log.error(err);
                                return;
                            }
                            if (body.display_name) {
                                try {
                                    const number = body.address.house_number || "";
                                    const city = body.address.city || body.address.town || body.address.village;
                                    const fullAdress = body.address.road + " " + number + ", " + body.address.postcode + " " + city + ", " + body.address.country;
                                    this.setObjectNotExists(vin + ".position.address.displayName", {
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
                                        this.setObjectNotExists(vin + ".position.address." + key, {
                                            type: "state",
                                            common: {
                                                name: key,
                                                role: "indicator",
                                                type: "mixed",
                                                write: false,
                                                read: true,
                                            },
                                            native: {},
                                        });
                                        this.setState(vin + ".position.address." + key, body.address[key], true);
                                    });
                                } catch (error) {
                                    this.log.error(error);
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
