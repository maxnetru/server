import base85 from "base85";

export type IncomingPacket = {
    type: "encInit",
    host: string,
    data: Buffer,
    reqseq: number
} | {
    type: "encData",
    data: Buffer,
    reqseq: number,
    datseq: number
} | {
    type: "req",
    reqseq: number,
    hostname: string,
    port: number,
    path: string,
    method: string,
    headers: [string, string][],
    body: Buffer
} | {
    type: "reqData",
    data: Buffer,
    reqseq: number,
    datseq: number
} | {
    type: "key",
    key: object
};
export type OutcomingPacket = {
    type: "encData",
    data: Buffer,
    reqseq: number,
    datseq: number
} | {
    type: "resData",
    data: Buffer,
    reqseq: number,
    datseq: number
} | {
    type: "res",
    reqseq: number,
    status: number,
    statusText: string,
    headers: [string, string][],
    body: Buffer
} | {
    type: "key",
    key: object
};

export const decodePacket = (text: string): IncomingPacket | false => {
    if(text.length < 1) return false;
    const type = text[0];
    text = text.slice(1);

    let obj = {} as IncomingPacket;
    switch(type) {
    case "i":
        obj.type = "encInit";
        break;
    case "d":
        obj.type = "encData";
        break;
    case "r":
        obj.type = "req";
        break;
    case "D":
        obj.type = "reqData";
        break;
    case "k":
        obj.type = "key";
        break;
    default:
        return false;
    }
    // i hate typescript
    const rest = text.split("~").map(x => base85.decode(x, "z85pad" as base85.Base85Encoding)) as Buffer[];
    if((rest as (Buffer | false)[]).includes(false)) return false;
    switch(obj.type) {
    case "encInit":
        obj.reqseq = rest[0].readUInt32BE();
        obj.host = rest[1].toString();
        obj.data = rest[2];
        break;
    case "encData":
        obj.reqseq = rest[0].readUInt32BE();
        obj.datseq = rest[1].readUInt32BE();
        obj.data = rest[2];
        break;
    case "req":
        obj.reqseq = rest[0].readUInt32BE();
        obj.hostname = rest[1].toString();
        obj.port = rest[2].readUInt16BE();
        obj.path = rest[3].toString();
        obj.method = rest[4].toString();
        obj.headers = rest[5].toString().split("\n").map(x => {
            const ind = x.indexOf(":");
            return [x.slice(0, ind), x.slice(ind + 1)];
        });
        obj.body = rest[6];
        break;
    case "reqData":
        obj.reqseq = rest[0].readUInt32BE();
        obj.datseq = rest[1].readUInt32BE();
        obj.data = rest[2];
        break;
    case "key":
        obj.key = JSON.parse(rest[0].toString());
        break;
    }

    return obj;
};

export const encodePacket = (packet: OutcomingPacket): string => {
    let out: string = "";
    let parts: Buffer[] = [];
    switch(packet.type) {
    case "encData":
        out = "d";
        const reqseq = Buffer.alloc(4); reqseq.writeUInt32BE(packet.reqseq);
        const datseq = Buffer.alloc(4); datseq.writeUInt32BE(packet.datseq);
        parts.push(reqseq, datseq, packet.data);
        break;
    case "key":
        out = "k";
        parts.push(Buffer.from(JSON.stringify(packet.key)));
        break;
    case "res":
        out = "r";
        // why can't i use the same variable name multiple times lol
        const reqseq2 = Buffer.alloc(4); reqseq2.writeUInt32BE(packet.reqseq);
        const status = Buffer.alloc(2); status.writeUInt16BE(packet.status);
        parts.push(reqseq2, status, Buffer.from(packet.statusText), Buffer.from(packet.headers.map(x => x.join(":")).join("\n")), packet.body);
        break;
    case "resData":
        out = "D";
        // why can't i use the same variable name multiple times lol
        const reqseq3 = Buffer.alloc(4); reqseq3.writeUInt32BE(packet.reqseq);
        const datseq2 = Buffer.alloc(4); datseq2.writeUInt32BE(packet.datseq);
        parts.push(reqseq3, datseq2, packet.data);
        break;
    }
    out += parts.map(x => base85.encode(x, "z85pad" as base85.Base85Encoding)).join("~");
    return out;
};