import * as storage from "./storage";
import { Client } from "./max";
import { question } from "readline-sync";
import { randomUUID } from "crypto";

const client = new Client();
await client.init();

let authData = storage.getAuthData();
if(!authData.id || !authData.token) {
    authData.id = randomUUID();
    await client.presentDevice(authData.id);
    const phone = question("phone: ");
    const verifyToken = await client.requestCode(phone);
    const code = question("sms code: ");
    authData.token = await client.presentCode(verifyToken, code);
    if(authData.token === "") {
        console.error("wrong code!");
        process.exit(1);
    }
    storage.setAuthData(authData.id, authData.token);
} else {
    await client.presentDevice(authData.id);
}
let afterTokenData = await client.presentToken(authData.token);
console.log(`Logged in as ${afterTokenData.profile.contact.names[0].name}`);