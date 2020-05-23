/**
 * This version support only compiled code and works with streams API
 */

//require('debug').enable('NetFlowV9');
var debug = require('debug')('NetFlowV9');
var dgram = require('dgram');
var clone = require('clone');
var util = require('util');
var e = require('events').EventEmitter;
var nf9PktDecode = require('./js/nf9/nf9decode');
var Dequeue = require('dequeue');

var nft = require('./js/nf9/nftypes');
var nfInfoTemplates = require('./js/nf9/nfinfotempl');

function nfPktDecode(msg,rinfo) {
    var version = msg.readUInt16BE(0);
    switch (version) {
        case 9:
            return this.nf9PktDecode(msg,rinfo);
        default:
            debug('bad header version %d', version);
            return;
    }
}

function NetFlowV9(options = {}) {
    if (!(this instanceof NetFlowV9)) return new NetFlowV9(options);
    var me = this;
    this.templates = {};
    this.nfTypes = clone(nft.nfTypes);
    this.nfScope = clone(nft.nfScope);
    this.cb = null;
    this.templateCb = null;
    this.socketType = 'udp4';
    this.port = null;
    this.fifo = new Dequeue();
    if (typeof options == 'function') this.cb = options; else
    if (typeof options.cb == 'function') this.cb = options.cb;
    if (typeof options.templateCb == 'function') this.templateCb = options.templateCb;
    if (typeof options == 'object') {
        if (options.ipv4num) decIpv4Rule[4] = "o['$name']=buf.readUInt32BE($pos);";
        if (options.nfTypes) this.nfTypes = util._extend(this.nfTypes,options.nfTypes); // Inherit nfTypes
        if (options.nfScope) this.nfScope = util._extend(this.nfScope,options.nfScope); // Inherit nfTypes
        if (options.socketType) this.socketType = options.socketType;
        if (options.port) this.port = options.port;
        if (options.templates) this.templates = options.templates;
        e.call(this,options);
    }

    this.server = dgram.createSocket(this.socketType);
    this.server.on('message',(msg,rinfo)=>{
        me.fifo.push([msg, rinfo]);
        if (!me.closed && me.set) {
            me.set = false;
            setImmediate(()=>this.fetch())
        }
    });

    this.server.on('close', function() {
        this.closed = true;
    });

    this.listen = function(port,host,cb) {
        this.fetch();

        if (host && typeof host === 'function')
            me.server.bind(port,host);
        else if (host && typeof host === 'string' && cb)
            me.server.bind(port,host,cb);
        else if (host && typeof host === 'string' && !cb)
            me.server.bind(port,host);
        else if (!host && cb)
            me.server.bind(port, cb);
        else
            me.server.bind(port);
    };

    this.fetch = function() {
        while (this.fifo.length > 0 && !this.closed) {
            var data = me.fifo.shift();
            var msg = data[0];
            var rinfo = data[1];
            var startTime = new Date().getTime();
            if (rinfo.size<20) return;
            var o = this.nfPktDecode(msg, rinfo);
            if (o) { // If the packet does not contain flows, only templates we do not decode
                o.rinfo = rinfo;
                o.packet = msg;
                o.decodeMs = (new Date().getTime()) - startTime;
                this.emit('data',o);
            }
        }

        me.set = true;
    };

    if (this.port) this.listen(options.port, options.host);
}

util.inherits(NetFlowV9,e);
NetFlowV9.prototype.nfInfoTemplates = nfInfoTemplates;
NetFlowV9.prototype.nfPktDecode = nfPktDecode;
NetFlowV9.prototype.nf9PktDecode = nf9PktDecode;
module.exports = NetFlowV9;
