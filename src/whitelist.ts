import fs from "fs";

if(!fs.existsSync("whitelist.txt")) console.warn("whitelist not present!");

export const whitelist = fs.existsSync("whitelist.txt")
    ? fs.readFileSync("whitelist.txt", "utf-8").split("\n").filter(x => x).map(x => parseInt(x))
    : [];