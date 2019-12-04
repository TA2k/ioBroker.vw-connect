"use strict";

/*
 * Created with @iobroker/create-adapter v1.17.0
 */

// The adapter-core module gives you access to the core ioBroker functions
// you need to create an adapter
const utils = require("@iobroker/adapter-core");


const request = require("request");
const crypto = require("crypto");
const uuidv4 = require("uuid/v4");
const traverse = require("traverse");
const jsdom = require("jsdom");
const {
	JSDOM
} = jsdom;
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

		this.vinArray = [];

		this.statesArray = [{
			url: "https://msg.volkswagen.de/fs-car/bs/departuretimer/v1/$type/$country/vehicles/$vin/timer",
			path: "timer",
			element: "timer"
		}, {
			url: "https://msg.volkswagen.de/fs-car/bs/climatisation/v1/$type/$country/vehicles/$vin/climater",
			path: "climater",
			element: "climater"

		}, {
			url: "https://msg.volkswagen.de/fs-car/bs/cf/v1/$type/$country/vehicles/$vin/position",
			path: "position",
			element: "storedPositionResponse",
			element2: "position"

		}, {
			url: "https://msg.volkswagen.de/fs-car/bs/tripstatistics/v1/$type/$country/vehicles/$vin/tripdata/$tripType?type=list",
			path: "tripdata",
			element: "tripDataList"
		}, {
			url: "https://msg.volkswagen.de/fs-car/bs/vsr/v1/$type/$country/vehicles/$vin/status",
			path: "status",
			element: "StoredVehicleDataResponse",
			element2: "vehicleData"

		}, {
			url: "https://msg.volkswagen.de/fs-car/destinationfeedservice/mydestinations/v1/$type/$country/vehicles/$vin/destinations",
			path: "destinations",
			element: "destinations"

		}, {
			url: "https://msg.volkswagen.de/fs-car/bs/batterycharge/v1/$type/$country/vehicles/$vin/charger",
			path: "charger",
			element: "charger"

		}, {
			url: "https://msg.volkswagen.de/fs-car/bs/dwap/v1/$type/$country/vehicles/$vin/history",
			path: "history"
		}];
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
			this.xappversion = "3.1.6";
			this.xappname = "cz.skodaauto.connect";
		}
		if (this.config.type === "audi") {
			this.type = "Audi";
			this.country = "DE";
			this.clientId = 'mmiconnect_android';
			this.xclientId = "77869e21-e30a-4a92-b016-48ab7d3db1d8";
			this.scope = 'openid profile email mbb offline_access mbbuserid myaudi selfservice:read selfservice:write';
			this.redirect = "";
			this.xrequest = "";
			this.responseType = 'token id_token';
			this.xappversion = "3.14.0";
			this.xappname = "myAudi";
		}
		this.login().then(() => {
			this.log.debug("Login successful");
			this.setState("info.connection", true, true);
			this.getPersonalData().then(() => {
				this.getVehicles().then(() => {

					this.vinArray.forEach(vin => {
						this.getVehicleData(vin);
						this.getVehicleRights(vin);
						this.requestStatusUpdate(vin).then(()=> {
							this.statesArray.forEach(state => {
								this.getVehicleStatus(vin, state.url, state.path, state.element, state.element2).catch(()=>{
									this.log.debug("error while getting " + state.url)
								});
							});
						})

					});

					this.updateInterval = setInterval(() => {
						this.vinArray.forEach(vin => {
							this.requestStatusUpdate(vin).then(()=> {
								this.statesArray.forEach(state => {
									this.getVehicleStatus(vin, state.url, state.path, state.element, state.element2).catch(()=>{
										this.log.debug("error while getting " + state.url)
									});
								});
							})
						});
					}, this.config.interval * 60 * 1000);

				});

			});
		});
		this.subscribeStates("*");
	}
	login() {
		return new Promise((resolve, reject) => {
			const nonce = this.getNonce();
			const state = uuidv4();
			const [code_verifier, codeChallenge] = this.getCodeChallenge();

			let method = "GET"
			let form ={};
			let url = "https://identity.vwgroup.io/oidc/v1/authorize?client_id=" + this.clientId + "&scope=" + this.scope + "&response_type=" + this.responseType + "&redirect_uri=" + this.redirect + "&nonce=" + nonce + "&state=" + state;
			if (this.config.type === "vw") {
				url += "&code_challenge=" + codeChallenge + "&code_challenge_method=s256";
			}
			if (this.config.type === "audi") {
				url="https://id.audi.com/v1/token";
				method="POST";
				form= { client_id: this.clientId,
				  scope: this.scope,
				  response_type: this.responseType,
				  grant_type: 'password',
				  username: this.config.user,
				  password: this.config.password } 
			}
			request({
				method:method,
				url: url,
				headers: {
					"User-Agent": "Mozilla/5.0 (Linux; Android 10) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/74.0.3729.185 Mobile Safari/537.36",
					"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3",
					"Accept-Language": "en-US,en;q=0.9",
					"Accept-Encoding": "gzip, deflate",
					"x-requested-with": this.xrequest,
					"upgrade-insecure-requests": 1
				},
				jar: this.jar,
		form: form,
				followAllRedirects: true

			}, (err, resp, body) => {
				if (err) {
					this.log.error(err);
					reject();
				}


				try {
					if (this.config.type === "audi") {
						const tokens = JSON.parse(body)
						this.getVWToken(tokens,tokens.id_token,reject,resolve);
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
					}
					request.post({
						url: "https://identity.vwgroup.io/signin-service/v1/" + this.clientId + "/login/identifier",
						headers: {
							"Content-Type": "application/x-www-form-urlencoded",
							"User-Agent": "Mozilla/5.0 (Linux; Android 10) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/74.0.3729.185 Mobile Safari/537.36",
							"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3",
							"Accept-Language": "en-US,en;q=0.9",
							"Accept-Encoding": "gzip, deflate",
							"x-requested-with": this.xrequest
						},
						form: form,
						jar: this.jar,
						followAllRedirects: true
					}, (err, resp, body) => {
						if (err) {
							this.log.error(err);
							reject();
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
								this.log.error("No Login Form found");
								this.log.debug(body);
								reject();
							}
							request.post({
								url: "https://identity.vwgroup.io/signin-service/v1/" + this.clientId + "/login/authenticate",
								headers: {
									"Content-Type": "application/x-www-form-urlencoded",
									"User-Agent": "Mozilla/5.0 (Linux; Android 10) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/74.0.3729.185 Mobile Safari/537.36",
									"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3",
									"Accept-Language": "en-US,en;q=0.9",
									"Accept-Encoding": "gzip, deflate",
									"x-requested-with": this.xrequest
								},
								form: form,
								jar: this.jar,
								followAllRedirects: false,
							}, (err, resp, body) => {
								if (err) {
									this.log.error(err);
									reject();
								}

								try {
									this.log.debug(JSON.stringify(body));
									this.log.debug(JSON.stringify(resp.headers));
									this.config.userid = resp.headers.location.split("&")[2].split("=")[1];
									let getRequest = request.get({
										url: resp.headers.location,
										headers: {
											"User-Agent": "Mozilla/5.0 (Linux; Android 10) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/74.0.3729.185 Mobile Safari/537.36",
											"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3",
											"Accept-Language": "en-US,en;q=0.9",
											"Accept-Encoding": "gzip, deflate",
											"x-requested-with": this.xrequest
										},
										jar: this.jar,
										followAllRedirects: true,
									}, (err, resp, body) => {

										if (err) {
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
											getRequest = request.post({
												url: getRequest.uri.href,
												headers: {
													"Content-Type": "application/x-www-form-urlencoded",
													"User-Agent": "Mozilla/5.0 (Linux; Android 10) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/74.0.3729.185 Mobile Safari/537.36",
													"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3",
													"Accept-Language": "en-US,en;q=0.9",
													"Accept-Encoding": "gzip, deflate",
													"x-requested-with": this.xrequest,
													"referer": getRequest.uri.href
												},
												form: form,
												jar: this.jar,
												followAllRedirects: true,
											}, (err, resp, body) => {
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

											});
										}
									});
								} catch (error) {
									this.log.error(error);
									reject();
								}
							});
						} catch (error) {
							this.log.error(error);
							reject();
						}
					});
				} catch (error) {
					this.log.error(error);
					reject();
				}
			});
		});
	}

	replaceVarInUrl(url, vin) {
		return url.replace("/$vin/", "/" + vin + "/").replace("/$type/", "/" + this.type + "/").replace("/$country/", "/" + this.country + "/").replace("/$tripType", "/" + this.config.tripType);
	}
	getTokens(getRequest, code_verifier, reject, resolve) {
		const hashArray = getRequest.uri.hash.split("&");
		let state;
		let jwtauth_code;
		let jwtaccess_token;
		let jwtid_token;
		hashArray.forEach(hash => {
			const harray = hash.split("=");
			if (harray[0] === "#state") {
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
		if (this.config.type === "vw") {
			body += "&code_verifier=" + code_verifier;
		} else {
			body += "&brand=" + this.config.type;
		}
		request.post({
			url: "https://tokenrefreshservice.apps.emea.vwapps.io/exchangeAuthCode",
			headers: {
				// "user-agent": "okhttp/3.7.0",
				"X-App-version": this.xappversion,
				"content-type": "application/x-www-form-urlencoded",
				"x-app-name": this.xappname,
				accept: "application/json"
			},
			body: body,
			jar: this.jar,
			followAllRedirects: false,
		}, (err, resp, body) => {
			if (err) {
				this.log.error(err);
				reject();
			}
			try {
				const tokens = JSON.parse(body);
				this.getVWToken(tokens, jwtid_token, reject, resolve);
			} catch (error) {
				this.log.error(error);
				reject();
			}
		});
	}

	getVWToken(tokens, jwtid_token, reject, resolve) {
		this.config.atoken = tokens.access_token;
		this.config.rtoken = tokens.refresh_token;
		this.refreshTokenInterval = setInterval(() => {
			this.refreshToken().catch(() => {
				
			});
		}, 0.9 * 60 * 60 * 1000); // 0.9hours
		request.post({
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
				scope: "sc2:fal"
			},
			jar: this.jar,
			followAllRedirects: true,
		}, (err, resp, body) => {
			if (err) {
				this.log.error(err);
				reject();
			}
			try {
				const tokens = JSON.parse(body);
				this.config.vwatoken = tokens.access_token;
				this.config.vwrtoken = tokens.refresh_token;
				this.vwrefreshTokenInterval = setInterval(() => {
					this.refreshToken(true).catch(() => {
						
					});
				}, 0.9 * 60 * 60 * 1000); //0.9hours
				resolve();
			}
			catch (error) {
				this.log.error(error);
				reject();
			}
		});
	}

	refreshToken(isVw) {
		let url = "https://tokenrefreshservice.apps.emea.vwapps.io/refreshTokens";
		let rtoken = this.config.rtoken;
		let body = "refresh_token=" + rtoken;
		let form= "";
		if (isVw) {
			url = "https://mbboauth-1d.prd.ece.vwg-connect.com/mbbcoauth/mobile/oauth2/v1/token";
			rtoken = this.config.vwrtoken;
			body = "grant_type=refresh_token&scope=sc2%3Afal&token=" + rtoken;
		} else if (this.config.type==="audi") {
			url= 'https://id.audi.com/v1/token';
			body ="";
			form ={ client_id: this.clientId,
			grant_type: 'refresh_token',
			response_type: 'token id_token',
			refresh_token: rtoken }
		}
		return new Promise((resolve, reject) => {
			this.log.debug("refreshToken");
			request.post({
				url: url,
				headers: {
					"user-agent": "okhttp/3.7.0",
					"content-type": "application/x-www-form-urlencoded",
					"X-App-version": this.xappversion,
					"X-App-name": this.xappname,
					"X-Client-Id": this.xclientId,
					"accept": "application/json"
				},
				body: body,	
				form: form,
				gzip: true,
				followAllRedirects: true
			}, (err, resp, body) => {
				if (err) {
					this.log.error("Failing to refresh token.");
					this.log.error(err);
					reject();
					return;
				}
				try {
					this.log.debug(body);
					const tokens = JSON.parse(body);
					if (tokens.error) {
						this.log.error(body);
						setTimeout(() => {
							this.refreshToken(isVw);
						}, 5 * 60 * 1000);
						reject();
						return;
					}
					if (isVw) {

						this.config.vwatoken = tokens.access_token;
						if(tokens.refresh_token) {
							this.config.vwrtoken = tokens.refresh_token;
						}

					} else {
						this.config.atoken = tokens.access_token;
						if(tokens.refresh_token) {
							this.config.rtoken = tokens.refresh_token;

						}
					}
					resolve();

				} catch (error) {
					this.log.error("Failing to parse refresh token. The instance will do restart and try a relogin.");
					this.log.error(error);
					this.log.error(body);
					this.log.error(resp.statusCode);
					this.log.error(error.stack);
					this.restart();
					reject();
				}
			});
		});
	}

	getPersonalData() {
		return new Promise((resolve, reject) => {
			if (this.config.type ==="audi") {
				resolve();
				return;
			}
			this.log.debug("getData");
			request.get({
				url: "https://customer-profile.apps.emea.vwapps.io/v1/customers/" + this.config.userid + "/personalData",
				headers: {
					"user-agent": "okhttp/3.7.0",
					"X-App-version": this.xappversion,
					"X-App-name": this.xappname,
					authorization: "Bearer " + this.config.atoken,
					accept: "application/json",
					Host: "customer-profile.apps.emea.vwapps.io"
				},
				followAllRedirects: true
			}, (err, resp, body) => {
				if (err) {
					this.log.error(err);
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
					Object.keys(data).forEach(key => {
						this.setObjectNotExists("personal." + key, {
							type: "state",
							common: {
								name: key,
								role: "indicator",
								type: "mixed",
								write: false,
								read: true
							},
							native: {}
						});
						this.setState("personal." + key, data[key], true);
					});

					resolve();

				} catch (error) {
					this.log.error(error);
					reject();
				}
			});
		});
	}

	getCarData() {
		return new Promise((resolve, reject) => {
			this.log.debug("getData");
			request.get({
				url: "https://customer-profile.apps.emea.vwapps.io/v1/customers/" + this.config.userid + "/realCarData",
				headers: {
					"user-agent": "okhttp/3.7.0",
					"X-App-version": this.xappversion,
					"X-App-name": this.xappname,
					authorization: "Bearer " + this.config.atoken,
					accept: "application/json",
					Host: "customer-profile.apps.emea.vwapps.io"
				},
				followAllRedirects: true
			}, (err, resp, body) => {
				if (err) {
					this.log.error(err);
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
					Object.keys(data).forEach(key => {
						this.setObjectNotExists("car." + key, {
							type: "state",
							common: {
								name: key,
								role: "indicator",
								type: "mixed",
								write: false,
								read: true
							},
							native: {}
						});
						this.setState("car." + key, data[key], true);
					});

					resolve();

				} catch (error) {
					this.log.error(error);
					reject();
				}
			});
		});
	}

	getVehicles() {
		return new Promise((resolve, reject) => {
			const url = this.replaceVarInUrl("https://msg.volkswagen.de/fs-car/usermanagement/users/v1/$type/$country/vehicles");
			request.get({
				url: url,
				headers: {
					"User-Agent": "okhttp/3.7.0",
					Host: "msg.volkswagen.de",
					"X-App-Version": this.xappversion,
					"X-App-Name": this.xappname,
					Authorization: "Bearer " + this.config.vwatoken,
					Accept: "application/json"
				},
				followAllRedirects: true,
				gzip: true,
				json: true,
			}, (err, resp, body) => {
				if (err) {
					this.log.error(err);
					reject();
				}
				try {
					if (body.errorCode) {
						this.log.error(JSON.stringify(body));
						reject();
						return;
					}
					this.log.debug(JSON.stringify(body));
					const vehicles = body.userVehicles.vehicle;
					vehicles.forEach(vehicle => {
						this.vinArray.push(vehicle);
						this.setObjectNotExists(vehicle, {
							type: "device",
							common: {
								name: vehicle.title,
								role: "indicator",
								type: "mixed",
								write: false,
								read: true
							},
							native: {}
						});
						this.setObjectNotExists(vehicle + ".remote", {
							type: "state",
							common: {
								name: "Remote controls",
								write: true,
							},
							native: {}
						});
						this.setObjectNotExists(vehicle + ".remote.batterycharge", {
							type: "state",
							common: {
								name: "Start Battery Charge",
								type: "boolean",
								role: "button",
								write: true,
							},
							native: {}
						});
						this.setObjectNotExists(vehicle + ".remote.climatisation", {
							type: "state",
							common: {
								name: "Start Climatisation",
								type: "boolean",
								role: "button",
								write: true,
							},
							native: {}
						});
						this.setObjectNotExists(vehicle + ".remote.climatisationTemperature", {
							type: "state",
							common: {
								name: "Temperature in °C",
								type: "boolean",
								role: "number",
								write: true,
							},
							native: {}
						});
						this.setObjectNotExists(vehicle + ".remote.windowheating", {
							type: "state",
							common: {
								name: "Start Windowheating",
								type: "boolean",
								role: "button",
								write: true,
							},
							native: {}
						});
						this.setObjectNotExists(vehicle + ".remote.honk", {
							type: "state",
							common: {
								name: "Start Honk",
								type: "boolean",
								role: "button",
								write: true,
							},
							native: {}
						});
						this.setObjectNotExists(vehicle + ".remote.flash", {
							type: "state",
							common: {
								name: "Start Flash",
								type: "boolean",
								role: "button",
								write: true,
							},
							native: {}
						});

					});
					resolve();

				} catch (error) {
					this.log.error(error);
					this.log.error(error.stack);
					this.log.error("Not able to find vehicle, did you choose the correct type?.")
					reject();
				}
			});
		});
	}

	getVehicleData(vin) {
		return new Promise((resolve, reject) => {
			let url = this.replaceVarInUrl("https://msg.volkswagen.de/fs-car/vehicleMgmt/vehicledata/v2/$type/$country/vehicles/$vin/", vin);
			if (this.config.type !== "vw") {
				url = this.replaceVarInUrl("https://msg.volkswagen.de/fs-car/promoter/portfolio/v1/$type/$country/vehicle/$vin/carportdata", vin);
			}
			let atoken = this.config.vwatoken;
			if (this.config.type === "audi") {
				url = "https://msg.audi.de/myaudi/vehicle-management/v1/vehicles";
				atoken = this.config.atoken;
			}
			request.get({
				url: url,
				headers: {
					"User-Agent": "okhttp/3.7.0",
					"X-App-Version": this.xappversion,
					"X-App-Name": this.xappname,
					"X-Market": "de_DE",
					Authorization: "Bearer " + atoken,
					Accept: "application/json, application/vnd.vwg.mbb.vehicleDataDetail_v2_1_0+xml, application/vnd.vwg.mbb.genericError_v1_0_2+xml"
				},
				followAllRedirects: true,
				gzip: true,
				json: true,
			}, (err, resp, body) => {
				if (err) {
					this.log.error(err);
					reject();
					return;
				}
				try {

					this.log.debug(JSON.stringify(body));
					const adapter = this;
					let result = body.vehicleData;
					if (this.config.type ==="audi") {
						result = body.vehicles[this.vinArray.indexOf(vin)]
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
									read: true
								},
								native: {}
							});
							adapter.setState(vin + ".general." + modPath.join("."), value || this.node, true);
						}
					});

					resolve();

				} catch (error) {
					this.log.error(error);
					reject();
				}
			});
		});
	}

	getVehicleRights(vin) {
		return new Promise((resolve, reject) => {

			let url = "https://mal-1a.prd.ece.vwg-connect.com/api/rolesrights/operationlist/v3/vehicles/" + vin;
			if (this.config.type === "vw") {
				url += "/users/" + this.config.identifier
			}
			request.get({
				url: url,
				qs: {
					scope: "All"
				},
				headers: {
					"User-Agent": "okhttp/3.7.0",
					"X-App-Version": this.xappversion,
					"X-App-Name": this.xappname,
					Authorization: "Bearer " + this.config.vwatoken,
					Accept: "application/json, application/vnd.vwg.mbb.operationList_v3_0_2+xml, application/vnd.vwg.mbb.genericError_v1_0_2+xml"
				},
				followAllRedirects: true,
				gzip: true,
				json: true,
			}, (err, resp, body) => {
				if (err) {
					this.log.error(err);
					reject();
					return;
				}
				try {

					if (!this.config.rights) {
						resolve();
						return;
					}
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
										read: true
									},
									native: {}
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
			});
		});
	}

	requestStatusUpdate(vin) {
		return new Promise((resolve, reject) => {
	
			const url = this.replaceVarInUrl("https://msg.volkswagen.de/fs-car/bs/vsr/v1/$type/$country/vehicles/$vin/requests", vin);
			request.post({
				url: url,
				headers: {
					"User-Agent": "okhttp/3.7.0",
					Host: "msg.volkswagen.de",
					"X-App-Version": this.xappversion,
					"X-App-Name": this.xappname,
					Authorization: "Bearer " + this.config.vwatoken,
					"Accept-charset": "UTF-8",
					Accept: "application/json, application/vnd.vwg.mbb.VehicleStatusReport_v1_0_0+xml, application/vnd.vwg.mbb.climater_v1_0_0+xml, application/vnd.vwg.mbb.carfinderservice_v1_0_0+xml, application/vnd.volkswagenag.com-error-v1+xml, application/vnd.vwg.mbb.genericError_v1_0_2+xml, */*"

				},
				followAllRedirects: true,
				gzip: true,
				json: true
			}, (err, resp, body) => {
				if (err) {
					this.log.error(err);
					reject();
					return;
				}
				try {
					this.log.debug(JSON.stringify(body))
					resolve();

				} catch (error) {
					this.log.error(error);
					reject();
				}
			});
		});
	}

	getVehicleStatus(vin, url, path, element, element2) {
		return new Promise((resolve, reject) => {
			url = this.replaceVarInUrl(url, vin);
			request.get({
				url: url,
				headers: {
					"User-Agent": "okhttp/3.7.0",
					Host: "msg.volkswagen.de",
					"X-App-Version": this.xappversion,
					"X-App-Name": this.xappname,
					Authorization: "Bearer " + this.config.vwatoken,
					"Accept-charset": "UTF-8",
					Accept: "application/json, application/vnd.vwg.mbb.VehicleStatusReport_v1_0_0+xml, application/vnd.vwg.mbb.climater_v1_0_0+xml, application/vnd.vwg.mbb.carfinderservice_v1_0_0+xml, application/vnd.volkswagenag.com-error-v1+xml, application/vnd.vwg.mbb.genericError_v1_0_2+xml, */*"

				},
				followAllRedirects: true,
				gzip: true,
				json: true
			}, (err, resp, body) => {
				if (err) {
					this.log.error(err);
					reject();
					return;
				}
				try {

					this.log.debug(JSON.stringify(body));

					if (path === "position"){
						this.setObjectNotExists(vin + ".position.isMoving", {
							type: "state",
							common: {
								name: "is car moving",
								role: "indicator",
								type: "boolean",
								write: false,
								read: true
							},
							native: {}
						});
						
						if(resp.statusCode === 204) {
							this.setState(vin + ".position.isMoving", true, true);
							resolve();
							return;
						}else {
							this.setState(vin + ".position.isMoving", false, true);
						}
						if (body &&  body.storedPositionResponse && body.storedPositionResponse.parkingTimeUTC) {
							body.storedPositionResponse.position.parkingTimeUTC = body.storedPositionResponse.parkingTimeUTC;
						}
					}

					if (body === undefined || body === "" || body.error) {
						if (body && body.error && body.error.description.indexOf("Token expired") !== -1) {
							this.log.error("Error response try to refresh token " + path);
							this.log.error(JSON.stringify(body));
							this.refreshToken(true);
						} else {
							this.log.debug("Not able to get " + path);
						}
						this.log.debug(body);
						reject();
						return;
					}
					// const parser = new xml2js.Parser({
					// 	explicitArray: false,
					// 	explicitRoot: false,
					// 	mergeAttrs: true,
					// 	tagNameProcessors: [xml2js.processors.stripPrefix],
					// 	attrNameProcessors: [xml2js.processors.stripPrefix]
					// });

					const adapter = this;


					let result = body;
					if (result === "") {
						resolve();
						return;
					}
					if (result) {
						if (element) {
							result = result[element];
						}
						if (element2) {
							result = result[element2];
						}
						if (path === "tripdata") {
							adapter.setObjectNotExists(vin + "." + path + ".lastTrip", {
								type: "state",
								common: {
									name: "numberOfLastTrip",
									role: "indicator",
									type: "mixed",
									write: false,
									read: true
								},
								native: {}
							});
							adapter.setState(vin + "." + path + ".lastTrip", result.tripData.length, true);
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

								adapter.setObjectNotExists(vin + "." + path + "." + modPath.join("."), {
									type: "state",
									common: {
										name: this.key,
										role: "indicator",
										type: "mixed",
										write: false,
										read: true
									},
									native: {}
								});
								adapter.setState(vin + "." + path + "." + modPath.join("."), value || this.node, true);
							} else if ((path === "status" || path ==="tripdata" ) && this.path.length > 0 && !isNaN(this.path[this.path.length - 1])) {
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

								if (this.node.field && this.node.field[this.node.field.length -1].textId) {
									adapter.setObjectNotExists(vin + "." + path + "." + modPath.join("."), {
										type: "state",
										common: {
											name: this.node.field[this.node.field.length -1].textId,
											role: "indicator",
											type: "mixed",
											write: false,
											read: true
										},
										native: {}
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
											read: true
										},
										native: {}
									});
								} else if (this.node.timestamp) {
									adapter.setObjectNotExists(vin + "." + path + "." + modPath.join("."), {
										type: "state",
										common: {
											name: this.node.timestamp,
											role: "indicator",
											type: "mixed",
											write: false,
											read: true
										},
										native: {}
									});
								}
								

							}
						});
						resolve();
					} else {
						this.log.error("Cannot find vehicle data " + path);
						this.log.error(body);
						reject();
					}





				} catch (error) {
					this.log.error(error);
					this.log.error(error.stack);
					reject();
				}
			});
		});
	}

	setVehicleStatus(vin, url, body, contentType) {
		return new Promise((resolve, reject) => {
			url = this.replaceVarInUrl(url, vin);
			this.log.debug(body);
			this.log.debug(contentType);
			request.post({
				url: url,
				headers: {
					"User-Agent": "okhttp/3.7.0",
					Host: "msg.volkswagen.de",
					"X-App-Version": this.xappversion,
					"X-App-Name": this.xappname,
					Authorization: "Bearer " + this.config.vwatoken,
					"Accept-charset": "UTF-8",
					"Content-Type": contentType,
					Accept: "application/json, application/vnd.vwg.mbb.ChargerAction_v1_0_0+xml,application/vnd.volkswagenag.com-error-v1+xml,application/vnd.vwg.mbb.genericError_v1_0_2+xml, */*"
				},
				body: body,
				followAllRedirects: true,
				gzip: true,
			}, (err, resp, body) => {
				if (err) {
					this.log.error(err);
					reject();
					return;
				}
				try {
					this.log.debug(body);
					if (body.indexOf("<error>") !== -1) {
						this.log.error("Error response try to refresh token " + url);
						this.log.error(body);
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
						this.setVehicleStatus(vin, "https://msg.volkswagen.de/fs-car/bs/batterycharge/v1/$type/$country/vehicles/$vin/charger/actions", body, contentType);
					}

					if (action === "climatisation") {
						body = '<?xml version="1.0" encoding= "UTF-8" ?>\n<action>\n   <type>startClimatisation</type>\n</action>';
						if (state.val === false) {
							body = '<?xml version="1.0" encoding= "UTF-8" ?>\n<action>\n   <type>stopClimatisation</type>\n</action>';
						}
						contentType = "application/vnd.vwg.mbb.ClimaterAction_v1_0_0+xml";
						this.setVehicleStatus(vin, "https://msg.volkswagen.de/fs-car/bs/climatisation/v1/$type/$country/vehicles/$vin/climater/actions", body, contentType);
					}

					if (action === "climatisationTemperature") {
						let temp = 2950;
						if (state.val && !isNaN(state.val)) {
							temp = (parseFloat(state.val) + 273, 6) * 10;
						}
						body = '<?xml version="1.0" encoding= "UTF-8" ?>\n<action>\n   <type>setSettings</type> <settings> <targetTemperature>' + temp + "</targetTemperature> <climatisationWithoutHVpower>false</climatisationWithoutHVpower> <heaterSource>electric</heaterSource> </settings>\n</action>";
						contentType = "application/vnd.vwg.mbb.ClimaterAction_v1_0_0+xml";
						this.setVehicleStatus(vin, "https://msg.volkswagen.de/fs-car/bs/climatisation/v1/$type/$country/vehicles/$vin/climater/actions", body, contentType);
					}

					if (action === "windowheating") {
						body = '<?xml version="1.0" encoding= "UTF-8" ?>\n<action>\n   <type>startWindowHeating</type>\n</action>';
						if (state.val === false) {
							body = '<?xml version="1.0" encoding= "UTF-8" ?>\n<action>\n   <type>stopWindowHeating</type>\n</action>';
						}
						contentType = "application/vnd.vwg.mbb.ClimaterAction_v1_0_0+xml";
						this.setVehicleStatus(vin, "https://msg.volkswagen.de/fs-car/bs/climatisation/v1/$type/$country/vehicles/$vin/climater/actions", body, contentType);
					}
					if (action === "flash") {
						//HONK_AND_FLASH
						const idArray = id.split(".");
						idArray.pop();
						idArray.pop();
						idArray.push("position.carCoordinate")
						const posId = idArray.join(".");
						const longitude = await this.getStateAsync(posId + ".longitude");
						const latitude = await this.getStateAsync(posId + ".latitude");
						body = '{"honkAndFlashRequest":{"serviceOperationCode":"FLASH_ONLY","userPosition":{"latitude":'+latitude.val+',"longitude":'+longitude.val+'}}}';
						contentType = 'application/json; charset=UTF-8';
						this.setVehicleStatus(vin, "https://msg.volkswagen.de/fs-car/bs/rhf/v1/$type/$country/vehicles/$vin/honkAndFlash", body, contentType);
					}

					if (action === "honk") {
						//
						const idArray = id.split(".");
						idArray.pop();
						idArray.pop();
						idArray.push("position.carCoordinate")
						const posId = idArray.join(".");
						const longitude = await this.getStateAsync(posId + ".longitude");
						const latitude = await this.getStateAsync(posId + ".latitude");
						body = '{"honkAndFlashRequest":{"serviceOperationCode":"HONK_AND_FLASH","userPosition":{"latitude":'+latitude.val+',"longitude":'+longitude.val+'}}}';
						contentType = 'application/json; charset=UTF-8';
						this.setVehicleStatus(vin, "https://msg.volkswagen.de/fs-car/bs/rhf/v1/$type/$country/vehicles/$vin/honkAndFlash", body, contentType);
					}
				}
			} else {
				if (id.indexOf("carCoordinate.latitude") !== -1 && state.ts === state.lc && this.config.reversePos) {

					const vin = id.split(".")[2];
					const longitude = await this.getStateAsync(id.replace("latitude", "longitude"));
					const longitudeValue = parseFloat(longitude.val);

					request.get({
						url: "https://nominatim.openstreetmap.org/reverse?lat=" + state.val / 1000000 + "&lon=" + longitudeValue / 1000000 + "&format=json",

						headers: {
							"User-Agent": "ioBroker/vw-connect"
						},
						json: true,
						followAllRedirects: true
					}, (err, resp, body) => {
						if (err || resp.statusCode >= 400 || !body) {
							this.log.error(body)
							this.log.error(resp.statusCode)
							this.log.error(err);
							return;
						}
						if (body.display_name) {
							try {
								const number  = body.address.house_number || "";
								const city = body.address.city  || body.address.town || body.address.village;
								const fullAdress = body.address.road + " " + number + ", "+ body.address.postcode+ " "+ city + ", " + body.address.country;
								this.setObjectNotExists(vin + ".position.address.displayName", {
									type: "state",
									common: {
										name: "displayName",
										role: "indicator",
										type: "mixed",
										write: false,
										read: true
									},
									native: {}
								});
								this.setState(vin + ".position.address.displayName", fullAdress, true);
								Object.keys(body.address).forEach(key => {
									this.setObjectNotExists(vin + ".position.address." + key, {
										type: "state",
										common: {
											name: key,
											role: "indicator",
											type: "mixed",
											write: false,
											read: true
										},
										native: {}
									});
									this.setState(vin + ".position.address." + key, body.address[key], true);

								});

							} catch (error) {
								this.log.error(error);
							}
						} else {
							this.log.error(body)
						}

					});

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