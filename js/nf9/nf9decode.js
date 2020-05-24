let debug = require('debug')('NetFlowV9');

const decMacRule = "buf.toString('hex',$pos,$pos+$len);"

function compileStatement(nf, variables) {
    let cr;
    if (!nf || !(cr = nf.compileRule)) {
        debug('Unable to compile NAME: %d POS: %d LEN: %d',nf.name,variables.pos,variables.len);
        return "";
    }

    if(typeof cr !== 'string'){
        cr = cr[variables.len]
    }
    if (!cr) {
        debug('Unknown compile NAME: %d POS: %d LEN: %d',nf.name,variables.pos,variables.len);
        return "";
    }

    return cr.replace(/\$[a-z]+/g, matched=>variables[matched.substr(1)]);
}

function nf9PktDecode(msg,rinfo = {}) {
    // Get templates for this server
    const templates = this.nfInfoTemplates(rinfo);

    // Get parsing types & scope definitions
    const nfTypes = this.nfTypes || {};
    const nfScope = this.nfScope || {};

    let out = { header: {
        version: msg.readUInt16BE(0),
        count: msg.readUInt16BE(2),
        uptime: msg.readUInt32BE(4),
        seconds: msg.readUInt32BE(8),
        sequence: msg.readUInt32BE(12),
        sourceId: msg.readUInt32BE(16)
    }, flows: [], commands: [] };

    function appendTemplate(tId) {
        let id = rinfo.address + ':' + rinfo.port;
        out.templates = out.templates || {};
        out.templates[id] = out.templates[id] || {};
        out.templates[id][tId] = templates[tId];
    }

    function compileTemplate(list) {
        let f = "let t; return {\n";
        const listLen = list ? list.length : 0;
        for (let i = 0, n = 0, z; i < listLen; i++, n += z.len) {
            z = list[i];
            let nf = nfTypes[z.type];
            if (!nf) {
                debug('Unknown NF type %d', z.type);
                nf = nfTypes[z.type] = {
                    name: 'unknown_type_'+ z.type,
                    compileRule: decMacRule
                }
            }
            f += nf.name + ": " + compileStatement(nf, {pos:n, len:z.len}) + ",\n";
        }
        f += "}";
        
        debug('The template will be compiled to %s',f);
        return new Function('buf', 'nfTypes', f);
    }

    function readTemplate(buf) {
        // let fsId = buffer.readUInt16BE(0);
        let len = buf.readUInt16BE(2);
        if(len > buf.length){
            throw new RangeError(`NF9 template length too long, got ${len} was a maximum of ${buf.length}`)
        }
        buf = buf.slice(4, len);
        while (buf.length > 0) {
            let tId = buf.readUInt16BE(0);
            let cnt = buf.readUInt16BE(2)*4;
            let list = [];
            let len = 0;
            debug('compile template %s for %s:%d', tId, rinfo.address, rinfo.port);
            if(cnt > buf.len){
                throw new RangeError(`Template flowset length too long, got ${cnt} was a maximum of ${buf.length}`)
            }
            for (let i = 0; i < cnt; i+=4) {
                list.push({type: buf.readUInt16BE(4 + i), len: buf.readUInt16BE(6 + i)});
                len += buf.readUInt16BE(6 + i);
            }
            templates[tId] = {len, list, compiled: compileTemplate(list)};
            appendTemplate(tId);
            buf = buf.slice(4 + cnt);
        }
    }

    function decodeTemplate(fsId, buf) {
        if (typeof templates[fsId].compiled !== 'function') {
            templates[fsId].compiled = compileTemplate(templates[fsId].list);
        }
        let o = templates[fsId].compiled(buf, nfTypes);
        o.fsId = fsId;
        return o;
    }

    function readOptions(buffer) {
        let len = buffer.readUInt16BE(2);
        let tId = buffer.readUInt16BE(4);
        let osLen = buffer.readUInt16BE(6);
        let oLen = buffer.readUInt16BE(8);
        let buff = buffer.slice(10,len);
        debug('readOptions: len:%d tId:%d osLen:%d oLen:%d for %s:%d',len,tId,osLen,oLen,buff,rinfo.address,rinfo.port);
        let plen = 0;
        let cr = "let t; return { isOption: true, \n";
        let type; let tlen;

        // Read the SCOPE
        let buf = buff.slice(0, osLen);
        while (buf.length > 3) {
            type = buf.readUInt16BE(0);
            tlen = buf.readUInt16BE(2);
            let nf = nfScope[type]
            if (!nfScope[type]) {
                nf = nfScope[type] = { name: 'unknown_scope_'+type, compileRule: decMacRule };
                debug('Unknown scope TYPE: %d POS: %d LEN: %d',type,pos,len);
            }

            debug('    SCOPE type: %d (%s) len: %d, plen: %d', type, nf ? nf.name : 'unknown',tlen,plen);
            if (type) {
                cr+=nf.name  + ": " + compileStatement(nf, {pos:plen, len:tlen})+",\n";
            }
            buf = buf.slice(4);
            plen += tlen;
        }

        // Read the Fields
        buf = buff.slice(osLen);
        while (buf.length > 3) {
            type = buf.readUInt16BE(0);
            tlen = buf.readUInt16BE(2);
            const nf = nfTypes[type]
            debug('    FIELD type: %d (%s) len: %d, plen: %d', type, nf ? nf.name : 'unknown',tlen,plen);
            if (type) {
                cr+=nf.name  + ": " + compileStatement(nf, {pos:plen, len:tlen}) + ",\n";
            }
            buf = buf.slice(4);
            plen += tlen;
        }
        //cr+="// option "+tId+"\n";
        cr+="}";
        debug('option template compiled to %s',cr);
        templates[tId] = { len: plen, compiled: new Function('buf','nfTypes',cr) };
        appendTemplate(tId);
    }

    function readControl(buf){
        let len = buf.readUInt16BE(2);
        let cmd = buf.readUInt16BE(4);
        let data = buf.slice(6, len - 6);
        out.commands.push({cmd, data})
    }

    function wasRender(w){
        return `${w[0]}: ${w[1]} bytes`
    }

    let was = []
    let buf = msg.slice(20);
    while (buf.length > 3) { // length > 3 allows us to skip padding
        let fsId = buf.readUInt16BE(0);
        let len = buf.readUInt16BE(2);
        if(len < 4){
            debug("A length of %d for flowset id %d is invalid\n", len, fsId)
            return out;
        }
        try {
            if (fsId == 0) {
                was.push(["template", len])
                readTemplate(buf);
            } else if (fsId == 1) {
                was.push(["options", len])
                readOptions(buf);
            } else if (fsId == 2) {
                was.push(["control", len])
                readControl(buf);
            } else if (fsId > 1 && fsId < 256) {
                was.push(["unknown", len])
                debug('Unknown Flowset ID %d!', fsId);
            }
            else if (fsId > 255 && typeof templates[fsId] != 'undefined') {
                was.push(["flow", len])
                let tbuf = buf.slice(4, len);
                while (tbuf.length >= templates[fsId].len) {
                    out.flows.push(decodeTemplate(fsId, tbuf));
                    tbuf = tbuf.slice(templates[fsId].len);
                }
            } else if (fsId > 255) {
                was.push(["unknown2", len])
                debug('Unknown template/option data with flowset id %d for %s:%d',fsId,rinfo.address,rinfo.port);
            }
        } catch(ex){
            if(ex instanceof RangeError) {
//                debug(ex)
                debug(`Message was:\n${was.map(wasRender).join("\n")}`)
                console.log(buf)
                throw ex
            } else{
                throw ex
            }
        }
        buf = buf.slice(len);
    }

    return out;
}

module.exports = nf9PktDecode;
