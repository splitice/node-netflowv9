let debug = require('debug')('NetFlowV9');

const highwayhash = require('highwayhash');

const decMacRule = "buf.toString('hex',$pos,$pos+$len);"

const hashKey = Buffer.allocUnsafe(32)

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

    return nf.name  + ": " + cr.replace(/\$[a-z]+/g, matched=>variables[matched.substr(1)]);
}

function nf9PktDecode(msg,rinfo = {}) {
    // Get templates for this server
    const templates = this.nfInfoTemplates(rinfo);

    // Get parsing types & scope definitions
    const nfTypes = this.nfTypes || {};
    const nfScope = this.nfScope || {};
    if(!this._templateCache) this._templateCache = {}
    const templateCache = this._templateCache

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
        let f = "let t; return {fsId,\n";
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
            f += compileStatement(nf, {pos:n, len:z.len}) + ",\n";
        }
        f += "}";
        
        debug('The template will be compiled to %s',f);
        return new Function('buf', 'nfTypes', 'fsId', f);
    }

    function _readTemplate(bufSliced){
        let list = [];
        let len = 0;
        for (let i = 0, cnt = bufSliced.length; i < cnt; i+=4) {
            let l = bufSliced.readUInt16BE(2 + i)
            list.push({type: bufSliced.readUInt16BE(i), len: l});
            len += l;
        }

        const t = compileTemplate(list)
        t.len = len
        t.list = list
        return t
    }

    function readTemplate(buf){
        let tId = buf.readUInt16BE(0);
        let cnt = buf.readUInt16BE(2)*4;
        
        let t
        let bufSliced = buf.slice(4, cnt + 4)
        const cacheKey = highwayhash.asString(hashKey, bufSliced);
        t = templateCache[cacheKey]
        if(t) {
            templates[tId] = t
        }else{
            debug('compile template %s for %s:%d', tId, rinfo.address, rinfo.port);
            if(cnt > bufSliced.len){
                throw new RangeError(`Template flowset length too long, got ${cnt} was a maximum of ${bufSliced.length}`)
            }
            t = _readTemplate(bufSliced, cnt)
            templateCache[cacheKey] = templates[tId] = t
        }
        appendTemplate(tId);
        return cnt
    }

    function readTemplates(buf, len) {
        // let fsId = buffer.readUInt16BE(0);
        buf = buf.slice(4, len);

        while (buf.length > 0) {
            const cnt = readTemplate(buf)
            buf = buf.slice(4 + cnt);
        }
    }

    function readOptions(buffer) {
        let len = buffer.readUInt16BE(2);
        let tId = buffer.readUInt16BE(4);
        let osLen = buffer.readUInt16BE(6);
        let oLen = buffer.readUInt16BE(8);
        let buff = buffer.slice(10,len);
        debug('readOptions: len:%d tId:%d osLen:%d oLen:%d for %s:%d',len,tId,osLen,oLen,buff,rinfo.address,rinfo.port);
        let plen = 0;
        let cr = "let t; return { fsId, isOption: true, \n";
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
                cr+=compileStatement(nf, {pos:plen, len:tlen})+",\n";
            }
            buf = buf.slice(4);
            plen += tlen;
        }

        // Read the Fields
        buf = buff.slice(osLen);

        /*let t
        const cacheKey = highwayhash.asString(hashKey, buf);
        t = templateCache[cacheKey]
        if(t) {
            templates[tId] = t
        }else{
            debug('compile template %s for %s:%d', tId, rinfo.address, rinfo.port);
            _readTemplate(buf, osLen)
            templateCache[cacheKey] = templates[tId] = t
        }
        appendTemplate(tId);*/

        while (buf.length > 3) {
            type = buf.readUInt16BE(0);
            tlen = buf.readUInt16BE(2);
            const nf = nfTypes[type]
            debug('    FIELD type: %d (%s) len: %d, plen: %d', type, nf ? nf.name : 'unknown',tlen,plen);
            if (type) {
                cr+=compileStatement(nf, {pos:plen, len:tlen}) + ",\n";
            }
            buf = buf.slice(4);
            plen += tlen;
        }
        //cr+="// option "+tId+"\n";
        cr+="}";
        debug('option template compiled to %s',cr);
        const t = new Function('buf','nfTypes','fsId',cr)
        t.len = plen
        templates[tId] = t
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
                readTemplates(buf, len);
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
            else if (fsId > 255 && templates[fsId] !== undefined) {
                was.push(["flow", len])
                let tbuf = buf.slice(4, len);
                const t = templates[fsId]
                while (tbuf.length >= t.len) {
                    out.flows.push(t(buf, nfTypes, fsId));
                    tbuf = tbuf.slice(t.len);
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
