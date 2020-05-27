/**
 * This version support only compiled code and works with streams API
 */

//require('debug').enable('NetFlowV9');
var debug = require('debug')('NetFlowV9');
var dgram = require('dgram');
var util = require('util');
var EventEmitter = require('asynchronous-emitter');
var nf9PktDecode = require('./lib/nf9/nf9decode');
const FifoQueue = require('./lib/FifoQueue')

var nft = require('./lib/nf9/nftypes');
var nfInfoTemplates = require('./lib/nf9/nfinfotempl');

function nfPktDecode(msg,rinfo) {
    const version = msg.readUInt16BE(0);
    switch (version) {
        case 9:
            return this.nf9PktDecode(msg,rinfo);
        default:
            debug('bad header version %d', version);
            return;
    }
}

class NetFlowV9 extends EventEmitter {
    constructor(options = {}) {
        super()
        this.templates = {};
        this.nfTypes = nft.nfTypes;
        this.nfScope = nft.nfScope;
        this.cb = null;
        this.templateCb = null;
        this.port = null;
        this.fifo = new FifoQueue(options.queueSize || 2048);
        if (typeof options == 'function') this.cb = options; else
        if (typeof options.cb == 'function') this.cb = options.cb;
        if (typeof options.templateCb == 'function') this.templateCb = options.templateCb;
        if (typeof options == 'object') {
            if (options.ipv4num) decIpv4Rule[4] = "o['$name']=buf.readUInt32BE($pos);";
            if (options.nfTypes) this.nfTypes = util._extend(this.nfTypes,options.nfTypes); // Inherit nfTypes
            if (options.nfScope) this.nfScope = util._extend(this.nfScope,options.nfScope); // Inherit nfTypes
            if (options.port) this.port = options.port;
            if (options.templates) this.templates = options.templates;
        }

        this.server = dgram.createSocket(options.socketType || 'udp4');
        this.server.on('message',(msg,rinfo)=>{
            this.fifo.push({msg, rinfo});
            if (!this.closed && this.set) {
                this.set = false;
                setImmediate(()=>this.fetch())
            }
        });

        this.server.on('close', () => {
            this.closed = true;
        });

        if (this.port) this.listen(options.port, options.host);
    }

    listen (port,host,cb) {
        this.fetch();

        if (host && typeof host === 'function')
            this.server.bind(port,host);
        else if (host && typeof host === 'string' && cb)
            this.server.bind(port,host,cb);
        else if (host && typeof host === 'string' && !cb)
            this.server.bind(port,host);
        else if (!host && cb)
            this.server.bind(port, cb);
        else
            this.server.bind(port);
    }

    getDropped (){
        return this.fifo.dropped
    }

    async fetch () {
        const all = this.fifo.shiftAll()
        for(const {msg,rinfo} of all){
            if (rinfo.size<20) return;
            const o = this.nfPktDecode(msg, rinfo);
            // If the packet does not contain flows, only templates we do not decode
            if (!o) return 
            o.rinfo = rinfo;
            o.packet = msg;
            await this.emit('data',o)
        }
    
        this.set = true;
    }
}

NetFlowV9.prototype.nfInfoTemplates = nfInfoTemplates;
NetFlowV9.prototype.nfPktDecode = nfPktDecode;
NetFlowV9.prototype.nf9PktDecode = nf9PktDecode;

module.exports = NetFlowV9;
