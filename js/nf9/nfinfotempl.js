function nfInfoTemplates(rinfo) {
    const templates = this.templates;
    const id = rinfo.address + ':' + rinfo.port;
    if (templates[id] === undefined) {
        templates[id] = {};
    }
    return templates[id];
}

module.exports = nfInfoTemplates;