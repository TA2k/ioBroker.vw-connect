//v2.0
async function extractKeys(adapter, path, element) {
    try {
        if (element === null) {
            adapter.log.debug("Cannot extract empty: " + path);
            return;
        }
        const objectKeys = Object.keys(element);
        let write = false;
        if (Array.isArray(element)) {
            extractArray(adapter, element, "", path, write);
            return;
        }
        if (path.endsWith("Settings")) {
            await adapter.setObjectNotExistsAsync(path, {
                type: "state",
                common: {
                    name: "Einstellungen sind hier änderbar / You can change the settings here",
                    role: "indicator",
                    write: false,
                    read: true,
                },
                native: {},
            });
            write = true;
        }
        objectKeys.forEach(async (key) => {
            if (isJsonString(element[key])) {
                element[key] = JSON.parse(element[key]);
            }

            if (Array.isArray(element[key])) {
                extractArray(adapter, element, key, path, write);
            } else if (element[key] !== null && typeof element[key] === "object") {
                extractKeys(adapter, path + "." + key, element[key]);
            } else {
                await adapter.setObjectNotExistsAsync(path + "." + key, {
                    type: "state",
                    common: {
                        name: key,
                        role: "indicator",
                        type: typeof element[key],
                        write: write,
                        read: true,
                    },
                    native: {},
                });
                adapter.setState(path + "." + key, element[key], true);
            }
        });
    } catch (error) {
        adapter.log.error("Error extract keys: " + path + " " + JSON.stringify(element));
        adapter.log.error(error);
    }
}
function extractArray(adapter, element, key, path, write) {
    try {
        if (key) {
            element = element[key];
        }
        element.forEach(async (arrayElement, index) => {
            index = index + 1;
            if (index < 10) {
                index = "0" + index;
            }
            let arrayPath = key + index;

            if (typeof arrayElement[Object.keys(arrayElement)[0]] === "string") {
                arrayPath = arrayElement[Object.keys(arrayElement)[0]];
            }
            Object.keys(arrayElement).forEach((keyName) => {
                if (keyName.endsWith("Id")) {
                    arrayPath = arrayElement[keyName];
                }
            });
            Object.keys(arrayElement).forEach((keyName) => {
                if (keyName.endsWith("Name")) {
                    arrayPath = arrayElement[keyName];
                }
            });
            if (arrayElement.id) {
                arrayPath = arrayElement.id;
            }
            if (arrayElement.name) {
                arrayPath = arrayElement.name;
            }
            //special case array with 2 string objects
            if (Object.keys(arrayElement).length === 2 && typeof Object.keys(arrayElement)[0] === "string" && typeof Object.keys(arrayElement)[1] === "string") {
                let subKey = arrayElement[Object.keys(arrayElement)[0]];
                let subValue = arrayElement[Object.keys(arrayElement)[1]];
                let subName = Object.keys(arrayElement)[0] + " " + Object.keys(arrayElement)[1];
                if (key) {
                    subKey = key + "." + subKey;
                }
                await adapter.setObjectNotExistsAsync(path + "." + subKey, {
                    type: "state",
                    common: {
                        name: subName,
                        role: "indicator",
                        type: typeof subValue,
                        write: write,
                        read: true,
                    },
                    native: {},
                });
                adapter.setState(path + "." + subKey, subValue, true);
                return;
            }
            extractKeys(adapter, path + "." + arrayPath, arrayElement);
        });
    } catch (error) {
        adapter.log.error("Cannot extract array " + path);
        adapter.log.error(error);
    }
}
function isJsonString(str) {
    try {
        JSON.parse(str);
    } catch (e) {
        return false;
    }
    return true;
}
module.exports = {
    extractKeys,
};
