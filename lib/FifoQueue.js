class FifoQueue {
    constructor(size = 1024){
        this._data = new Array(size)
        this._pos = 0
        this.dropped = 0
    }
    push(val){
        if(this._pos == this._max)
        if(this._data[this._pos]) this.dropped ++
        this._data[this._pos] = val
        this._pos = (this._pos + 1) % this._data.length
    }
    shiftAll(){
        const ret = []
        for(let i=1; i<=this._data.length; i++){
            const idx = (i+this._pos) % this._data.length
            const d = this._data[idx]
            if(d) {
                ret.push(d)
                this._data[idx] = null
            }
        }
        return ret
    }
}
module.exports = FifoQueue