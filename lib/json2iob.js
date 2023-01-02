//v1.9
/*
options:
write //set common write variable to true
forceIndex //instead of trying to find names for array entries, use the index as the name
channelName //set name of the root channel
preferedArrayName //set key to use this as an array entry name
preferedArrayDec //set key to use this as an array entry description
autoCast (true false) // make JSON.parse to parse numbers correctly
descriptions: Object of names for state keys
*/
const JSONbig = require("json-bigint")({ storeAsString: true });
module.exports = class Json2iob {
  constructor(adapter) {
    this.adapter = adapter;
    this.alreadyCreatedObjects = {};
  }

  async parse(path, element, options) {
    try {
      if (element === null || element === undefined) {
        this.adapter.log.debug("Cannot extract empty: " + path);
        return;
      }

      const objectKeys = Object.keys(element);

      if (!options || !options.write) {
        if (!options) {
          options = { write: false };
        } else {
          options["write"] = false;
        }
      }

      if (typeof element === "string" || typeof element === "number") {
        const lastPathElement = path.split(".").pop();

        if (!this.alreadyCreatedObjects[path]) {
          await this.adapter
            .setObjectNotExistsAsync(path, {
              type: "state",
              common: {
                name: lastPathElement,
                role: this.getRole(element, options.write),
                type: element !== null ? typeof element : "mixed",
                write: options.write,
                read: true,
              },
              native: {},
            })
            .then(() => {
              this.alreadyCreatedObjects[path] = true;
            })
            .catch((error) => {
              this.adapter.log.error(error);
            });
        }
        await this.adapter.setStateAsync(path, element, true);

        return;
      }
      if (!this.alreadyCreatedObjects[path]) {
        let name = options.channelName || "";
        if (options.preferedArrayDesc && element[options.preferedArrayDesc]) {
          name = element[options.preferedArrayDesc];
        }
        await this.adapter
          .setObjectNotExistsAsync(path, {
            type: "channel",
            common: {
              name: name,
              write: false,
              read: true,
            },
            native: {},
          })
          .then(() => {
            this.alreadyCreatedObjects[path] = true;
            options.channelName = undefined;
          })
          .catch((error) => {
            this.adapter.log.error(error);
          });
      }
      if (Array.isArray(element)) {
        await this.extractArray(element, "", path, options);
        return;
      }

      for (const key of objectKeys) {
        if (this.isJsonString(element[key]) && options.autoCast) {
          element[key] = JSONbig.parse(element[key]);
        }

        if (Array.isArray(element[key])) {
          await this.extractArray(element, key, path, options);
        } else if (element[key] !== null && typeof element[key] === "object") {
          await this.parse(path + "." + key, element[key], options);
        } else {
          const pathKey = key.replace(/\./g, "_");
          if (!this.alreadyCreatedObjects[path + "." + pathKey]) {
            let objectName = key;
            if (options.descriptions && options.descriptions[key]) {
              objectName = options.descriptions[key];
            }
            const type = element[key] !== null ? typeof element[key] : "mixed";
            const common = {
              name: objectName,
              role: this.getRole(element[key], options.write),
              type: type,
              write: options.write,
              read: true,
            };

            await this.adapter
              .setObjectNotExistsAsync(path + "." + pathKey, {
                type: "state",
                common: common,
                native: {},
              })
              .then(() => {
                this.alreadyCreatedObjects[path + "." + pathKey] = true;
              })
              .catch((error) => {
                this.adapter.log.error(error);
              });
          }
          await this.adapter.setStateAsync(path + "." + pathKey, element[key], true);
        }
      }
    } catch (error) {
      this.adapter.log.error("Error extract keys: " + path + " " + JSON.stringify(element));
      this.adapter.log.error(error);
    }
  }
  async extractArray(element, key, path, options) {
    try {
      if (key) {
        element = element[key];
      }
      for (let index in element) {
        const arrayElement = element[index];
        index = parseInt(index) + 1;
        if (index < 10) {
          index = "0" + index;
        }
        let arrayPath = key + index;
        if (typeof arrayElement === "string" && key !== "") {
          await this.parse(path + "." + key + "." + arrayElement, arrayElement, options);
          continue;
        }
        if (typeof arrayElement[Object.keys(arrayElement)[0]] === "string") {
          arrayPath = arrayElement[Object.keys(arrayElement)[0]];
        }
        for (const keyName of Object.keys(arrayElement)) {
          if (keyName.endsWith("Id") && arrayElement[keyName] !== null) {
            if (arrayElement[keyName] && arrayElement[keyName].replace) {
              arrayPath = arrayElement[keyName].replace(/\./g, "");
            } else {
              arrayPath = arrayElement[keyName];
            }
          }
        }
        for (const keyName in Object.keys(arrayElement)) {
          if (keyName.endsWith("Name")) {
            if (arrayElement[keyName] && arrayElement[keyName].replace) {
              arrayPath = arrayElement[keyName].replace(/\./g, "");
            } else {
              arrayPath = arrayElement[keyName];
            }
          }
        }

        if (arrayElement.id) {
          if (arrayElement.id.replace) {
            arrayPath = arrayElement.id.replace(/\./g, "");
          } else {
            arrayPath = arrayElement.id;
          }
        }
        if (arrayElement.name) {
          arrayPath = arrayElement.name.replace(/\./g, "");
        }
        if (arrayElement.label) {
          arrayPath = arrayElement.label.replace(/\./g, "");
        }
        if (arrayElement.labelText) {
          arrayPath = arrayElement.labelText.replace(/\./g, "");
        }
        if (arrayElement.start_date_time) {
          arrayPath = arrayElement.start_date_time.replace(/\./g, "");
        }
        if (options.preferedArrayName && options.preferedArrayName.indexOf("+") !== -1) {
          const preferedArrayNameArray = options.preferedArrayName.split("+");
          if (arrayElement[preferedArrayNameArray[0]]) {
            const element0 = arrayElement[preferedArrayNameArray[0]].replace(/\./g, "").replace(/ /g, "");
            let element1 = "";
            if (preferedArrayNameArray[1].indexOf("/") !== -1) {
              const subArray = preferedArrayNameArray[1].split("/");
              const subElement = arrayElement[subArray[0]];
              if (subElement && subElement[subArray[1]] !== undefined) {
                element1 = subElement[subArray[1]];
              } else if (arrayElement[subArray[1]] !== undefined) {
                element1 = arrayElement[subArray[1]];
              }
            } else {
              element1 = arrayElement[preferedArrayNameArray[1]].replace(/\./g, "").replace(/ /g, "");
            }
            arrayPath = element0 + "-" + element1;
          }
        } else if (options.preferedArrayName && options.preferedArrayName.indexOf("/") !== -1) {
          const preferedArrayNameArray = options.preferedArrayName.split("/");
          const subElement = arrayElement[preferedArrayNameArray[0]];
          if (subElement) {
            arrayPath = subElement[preferedArrayNameArray[1]].replace(/\./g, "").replace(/ /g, "");
          }
        } else if (options.preferedArrayName && arrayElement[options.preferedArrayName]) {
          arrayPath = arrayElement[options.preferedArrayName].toString().replace(/\./g, "");
        }

        if (options.forceIndex) {
          arrayPath = key + index;
        }
        //special case array with 2 string objects
        if (
          !options.forceIndex &&
          Object.keys(arrayElement).length === 2 &&
          typeof Object.keys(arrayElement)[0] === "string" &&
          typeof Object.keys(arrayElement)[1] === "string" &&
          typeof arrayElement[Object.keys(arrayElement)[0]] !== "object" &&
          typeof arrayElement[Object.keys(arrayElement)[1]] !== "object" &&
          arrayElement[Object.keys(arrayElement)[0]] !== "null"
        ) {
          let subKey = arrayElement[Object.keys(arrayElement)[0]];
          const subValue = arrayElement[Object.keys(arrayElement)[1]];
          const subName = Object.keys(arrayElement)[0] + " " + Object.keys(arrayElement)[1];
          if (key) {
            subKey = key + "." + subKey;
          }
          if (!this.alreadyCreatedObjects[path + "." + subKey]) {
            await this.adapter
              .setObjectNotExistsAsync(path + "." + subKey, {
                type: "state",
                common: {
                  name: subName,
                  role: this.getRole(subValue, options.write),
                  type: subValue !== null ? typeof subValue : "mixed",
                  write: options.write,
                  read: true,
                },
                native: {},
              })
              .then(() => {
                this.alreadyCreatedObjects[path + "." + subKey] = true;
              });
          }
          await this.adapter.setStateAsync(path + "." + subKey, subValue, true);
          continue;
        }
        await this.parse(path + "." + arrayPath, arrayElement, options);
      }
    } catch (error) {
      this.adapter.log.error("Cannot extract array " + path);
      this.adapter.log.error(error);
    }
  }
  isJsonString(str) {
    try {
      JSON.parse(str);
    } catch (e) {
      return false;
    }
    return true;
  }
  getRole(element, write) {
    if (typeof element === "boolean" && !write) {
      return "indicator";
    }
    if (typeof element === "boolean" && write) {
      return "switch";
    }
    if (typeof element === "number" && !write) {
      return "value";
    }
    if (typeof element === "number" && write) {
      return "level";
    }
    if (typeof element === "string") {
      return "text";
    }
    return "state";
  }
};
