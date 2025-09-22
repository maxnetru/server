import * as storage from "./storage";
import { b85ToU8, decrypt, deriveSharedKey, encrypt, genKeypair } from "./crypto";
import { Client } from "./max";
import { question } from "readline-sync";
import { randomUUID } from "crypto";
import { decodePacket, encodePacket, OutcomingPacket } from "./packets";
import { whitelist } from "./whitelist";
import http from "http";
import net from "net";
import { IncomingAccumulator, OutcomingAccumulator } from "./accumulator";

process.on("uncaughtException", err => console.error(err));
process.on("unhandledRejection", err => console.error(err));

const keys = await genKeypair();

const secrets = {};

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

const requests: Record<string, http.ClientRequest> = {};
const sockets: Record<string, net.Socket> = {};

const incomingAccumulators: Record<string, IncomingAccumulator> = {};
const outcomingAccumulators: Record<string, OutcomingAccumulator> = {};

const getEnc = async (packet: string, secret: CryptoKey) => {
    const enc = await encrypt(Buffer.from(packet), secret);
    return `s${enc[0]}~${enc[1]}`;
}

const one = arr => arr.length === 1 ? arr[0] : arr;

client.addMessageHandler(async packet => {
    if(packet.opcode === 1 || packet.cmd === 3) {
        console.log("reconnect");
        await client.reopen();
        await client.presentDevice(authData.id);
        afterTokenData = await client.presentToken(authData.token);
        return;
    }
    if(packet.opcode !== 128) return;
    const { message, chatId: chatID } = packet.payload as { message: { sender: number, text: string, id: string }, chatId: number };
    console.log(`message from ${message.sender} #${message.id}: ${message.text}`);
    if(message.sender === afterTokenData.profile.contact.id) return;

    if(!whitelist.includes(message.sender)) return;

    if(message.text === "/id")
        return await client.sendMessage(chatID, message.sender.toString());

    if(message.text[0] === "k") {
        // key packet, unencrypted
        const packet = decodePacket(message.text);
        if(!packet || packet.type !== "key") return;
        const theirPublicKey = await crypto.subtle.importKey("jwk", packet.key, { name: "ECDH", namedCurve: "P-256" }, true, []);
        const secret = await deriveSharedKey(keys.privateKey, theirPublicKey);
        secrets[chatID] = secret;

        await client.sendMessage(chatID, encodePacket({
            type: "key",
            key: await crypto.subtle.exportKey("jwk", keys.publicKey)
        }));
    } else if(message.text[0] === "s") {
        // other packet types, encrypted
        if(!(chatID in secrets)) return;
        const key = secrets[chatID];
        const parts = message.text.slice(1).split("~");
        const dec = await decrypt(parts[1], parts[0], key);
        const packet = decodePacket(Buffer.from(dec).toString());
        if(!packet) return;

        if(packet.type === "req") {
            const rkey = `${chatID}:${packet.reqseq}`;
            requests[rkey] = http.request({
                hostname: packet.hostname,
                port: packet.port,
                path: packet.path,
                method: packet.method,
                headers: Object.fromEntries(Array.from(new Set(packet.headers.map(x => x[0]))).map(x => [x, one(packet.headers.filter(y => y[0] === x).map(y => y[1]))]))
            }, async res => {
                await client.sendMessage(chatID, await getEnc(encodePacket({
                    type: "res",
                    reqseq: packet.reqseq,
                    status: res.statusCode || 200,
                    statusText: res.statusMessage || "OK",
                    headers: res.rawHeaders.map((x, i, a) => i % 2 === 0 ? [x, a[i + 1]] : null).filter(x => x !== null) as [string, string][],
                    body: Buffer.alloc(0)
                }), secrets[chatID]));
                let datseq = 0;
                res.on("data", async (data: Buffer) => {
                    for(let n = 0; n < data.length; n += 1500) {
                        const outpacket: OutcomingPacket = {
                            type: "resData",
                            reqseq: packet.reqseq,
                            datseq: datseq++,
                            data: data.subarray(n, n + 1500)
                        };
                        outcomingAccumulators[rkey].addPacket(outpacket.datseq, await getEnc(encodePacket(outpacket), secrets[chatID]));
                    }
                });
                res.on("end", async () => {
                    const outpacket: OutcomingPacket = {
                        type: "resData",
                        reqseq: packet.reqseq,
                        datseq: 0xffffffff,
                        data: Buffer.alloc(0)
                    };
                    outcomingAccumulators[rkey].addPacket(outpacket.datseq, await getEnc(encodePacket(outpacket), secrets[chatID]));
                });
            });

            incomingAccumulators[rkey] = new IncomingAccumulator(data => {
                if(data.length === 0) requests[rkey].end();
                else requests[rkey].write(data);
            });
            outcomingAccumulators[rkey] = new OutcomingAccumulator(client, chatID);

            requests[rkey].write(packet.body);
        } else if(packet.type === "reqData") {
            const rkey = `${chatID}:${packet.reqseq}`;
            // requests[packet.reqseq].write(packet.data);
            incomingAccumulators[rkey].addPacket(packet.datseq, packet.data);
        } else if(packet.type === "encInit") {
            let [host, portStr] = (packet.host as string).split(":");
            if(!portStr) portStr = "443";
            const port = parseInt(portStr);
            let datseq = 0;
            const rkey = `${chatID}:${packet.reqseq}`;
            sockets[rkey] = net.connect(port, host);

            incomingAccumulators[rkey] = new IncomingAccumulator(data => {
                if(data.length === 0) sockets[rkey].end();
                else sockets[rkey].write(data);
            });
            outcomingAccumulators[rkey] = new OutcomingAccumulator(client, chatID);

            sockets[rkey].on("data", async data => {
                for(let n = 0; n < data.length; n += 1500) {
                    const outpacket: OutcomingPacket = {
                        type: "encData",
                        reqseq: packet.reqseq,
                        datseq: datseq++,
                        data: data.subarray(n, n + 1500)
                    }
                    outcomingAccumulators[rkey].addPacket(outpacket.datseq, await getEnc(encodePacket(outpacket), secrets[chatID]));
                }
            });
            sockets[rkey].on("end", async () => {
                const outpacket: OutcomingPacket = {
                    type: "encData",
                    reqseq: packet.reqseq,
                    datseq: 0xffffffff,
                    data: Buffer.alloc(0)
                };
                outcomingAccumulators[rkey].addPacket(outpacket.datseq, await getEnc(encodePacket(outpacket), secrets[chatID]));
            });
            sockets[rkey].write(packet.data);
        } else if(packet.type === "encData") {
            const rkey = `${chatID}:${packet.reqseq}`;
            incomingAccumulators[rkey].addPacket(packet.datseq, packet.data);
            // sockets[packet.reqseq].write(packet.data);
        }
    }
});