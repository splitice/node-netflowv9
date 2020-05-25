var expect = require('chai').expect;

var NetFlowV9 = require('../netflowv9');


const n9 = new NetFlowV9({})


describe('NetFlowV9', function () {

    it('should be a function', function (done) {
        expect(NetFlowV9).to.be.an('function'); //is actually a constructor
        done();
    });

    it('should have nfPktDecode', function (done) {
        expect(n9).to.have.property('nfPktDecode');
        done();
    });

    describe('nfPktDecode', function () {
        it('should be able to decode vyos packet', function (done) {
            var VYOS_PACKET = '000900070002549b53b289a200000001000000000000005c0400001500150004001600040001000400020004003c0001000a0002000e0002003d00010003000400080004000c000400070002000b00020005000100060001000400010038000600500006003a000200c90004003000010000005c0401001500150004001600040001000400020004003c0001000a0002000e0002003d00010003000400080004000c000400070002000b00020005000100060001000400010051000600390006003b000200c90004003000010000005c0800001500150004001600040001000400020004003c0001000a0002000e0002003d000100030004001b0010001c00100005000100070002000b000200060001000400010038000600500006003a000200c90004003000010000005c0801001500150004001600040001000400020004003c0001000a0002000e0002003d000100030004001b0010001c00100005000100070002000b000200060001000400010051000600390006003b000200c90004003000010001001a10000004000c000100040030000100310001003200041000000e000000000102000001f4040000400000209e0000209e0000002800000001040003000000000000000a640054c0004c0264aa0050001006001b2fb9484980ee7395562800000000000301';

            var buffer = Buffer.from(VYOS_PACKET, 'hex');
            expect(buffer).to.have.length(VYOS_PACKET.length/2);
            var r = n9.nfPktDecode(buffer);
            const templates = Object.values(r.templates)[0]
            expect(templates).to.have.property('1024');
            expect(templates).to.have.property('1025');
            expect(templates).to.have.property('2048');
            expect(templates).to.have.property('2049');
            expect(r).to.have.property('header');
            expect(r).to.have.property('flows');

            var header = r.header;
            expect(header).to.have.property('version', 9);
            expect(header).to.have.property('count', 7);
            expect(header).to.have.property('uptime', 152731);
            expect(header).to.have.property('seconds', 1404209570);
            expect(header).to.have.property('sequence', 1);
            expect(header).to.have.property('sourceId', 0);

            var flows = r.flows;
            expect(flows).to.have.length(2);
            
            var f1 = flows[1];
            expect(f1).to.have.property('ipv4_src_addr', '10.100.0.84');
            expect(f1).to.have.property('ipv4_dst_addr', '192.0.76.2');
            expect(f1).to.have.property('in_pkts', 1);
            //TODO:test everything
            done();
        });

        
    
        it('should be able to decode big packet', function (done) {
            const bigPacket = "0009003120bbfbf85ecbc5a700000059000000000000002c0104000900080004000c000400070002000b000200060001000200040001000400040001003d00010104001c0ead2efd2d20466cbada003500000000010000003f110000000000300105000a00080004000c000400070002000b000200060001000200040001000400040001003d000100590001010500347647a1a32d20466cafd9005002000000010000003c06007f1b4db7d52d20466cd775003500000000010000004011007f010400340ebe0b222d20466c86a500350000000001000000401100734f58da2d20466c9f8c003500000000010000003a110000000105001cb23ea54e67646b02c65a22b8100000000100000034060080010400342d20466c6c3db2e3028f028f0000000001000004f0110195381c0567646beba4cc0eee020000000100000028060000000105001cabf000ee2d20466c0572003500000000010000003811007f0104001c5e66319f67646b45a7879e620200000001000000280600000102001c0a8001f20a8001f3d50700b3060000038e04030003000000010600182d20466cabfbc78b0303000000010000005b0101010300180a8001f20a8001f3ecb100b3060000018e100000010200300a8001f20a8001f3ecb100b3060000018e80030003000a8001f20a8001f3ecb100b3060000018e20030003000104001c71be92a72d20466c8f570035000000000100000040110000010600182d20466c7116ba360303000000010000005c0101010400bc7f0000017f000001004ee67210000000010000003406010ea9af732d20466cbd1f00350000000001000000401100c9f31ba467646b84742b01bd02000000010000003406002d20466c1b48a40a0050e0f914000000010000002806012d20466c6c3db2e3028f028f00000000010000008011015e66357067646bfac3ebb14802000000010000002806006c3db2e32d20466c028f028f00000000010000008011002a74f2c52d20466ce03f00350000000001000000411100010600182d20466c2a74f2c50303000000010000005501010104001c2d20466c88909c96bdc82743180000000100000b84060100010600182d20466c7b1ad4300303000000010000006201010105001c7b1ad4302d20466cda49003500000000010000004611007f010400346d7d859c67646b2cd7c5059902000000010000002c060088909c962d20587d22b8c65a180000000100000038060000000105001c2a721f092d20466cb10f003500000000010000004011007f0104004c71b397922d20466cce89003500000000010000004011005e66319f67646bc3a787ab1402000000010000002806007b10472a2d20466c5dd400350000000001000000481100000000010600182d20466c2a721f09030300000001000000560101010400340137cc942d20466c34730035000000000100000040110088909c962d20587d22b8c65a180000000100000038060000000105001c0ee7cf6c2d20466cad79003500000000010000003f11007f0104001c2d4c24072d20466c028f028f000000000100000050110000010500340ebd2ff02d20466ce201003500000000010000003a11007f0ea6e2982d20466cbb21003500000000010000004011007f010600182d20466cabe0b53b0303000000010000005c01010105001c0136835b2d20466c845d003500000000010000003c11007f010300180a8001f20a8001f3e78100b3060000018e100000010200300a8001f20a8001f3e78100b3060000018e80030003000a8001f20a8001f3e78100b3060000018e2003000300"
            var buffer = Buffer.from(bigPacket, 'hex');
            expect(buffer).to.have.length(bigPacket.length/2);
            var r = n9.nfPktDecode(buffer);

            const templates = {
                '260': {
                    len: 23,
                    list: [
                      { type: 8, len: 4 },
                      { type: 12, len: 4 },
                      { type: 7, len: 2 },
                      { type: 11, len: 2 },
                      { type: 6, len: 1 },
                      { type: 2, len: 4 },
                      { type: 1, len: 4 },
                      { type: 4, len: 1 },
                      { type: 61, len: 1 }
                    ],
                  },
                  '261': {
                    len: 24,
                    list: [
                      { type: 8, len: 4 },
                      { type: 12, len: 4 },
                      { type: 7, len: 2 },
                      { type: 11, len: 2 },
                      { type: 6, len: 1 },
                      { type: 2, len: 4 },
                      { type: 1, len: 4 },
                      { type: 4, len: 1 },
                      { type: 61, len: 1 },
                      { type: 89, len: 1 }
                    ],
                  }
            }

            const rTemplates = Object.values(r.templates)[0]
            for(const tId in rTemplates){
                const rt = rTemplates[tId]
                rTemplates[tId] = {len: rt.len, list: rt.list}
            }

            
            expect(rTemplates).to.deep.equal(templates)
            
//            for(const tId in rTemplates)

            const flows = [{
                ipv4_src_addr: '14.173.46.253',
                ipv4_dst_addr: '45.32.70.108',
                l4_src_port: 47834,
                l4_dst_port: 53,
                tcp_flags: 0,
                in_pkts: 1,
                in_bytes: 63,
                protocol: 17,
                direction: 0,
                fsId: 260
            },
            {
                ipv4_src_addr: '118.71.161.163',
                ipv4_dst_addr: '45.32.70.108',
                l4_src_port: 45017,
                l4_dst_port: 80,
                tcp_flags: 2,
                in_pkts: 1,
                in_bytes: 60,
                protocol: 6,
                direction: 0,
                fw_status: 127,
                fsId: 261
            },
            {
                ipv4_src_addr: '27.77.183.213',
                ipv4_dst_addr: '45.32.70.108',
                l4_src_port: 55157,
                l4_dst_port: 53,
                tcp_flags: 0,
                in_pkts: 1,
                in_bytes: 64,
                protocol: 17,
                direction: 0,
                fw_status: 127,
                fsId: 261
            },
            {
                ipv4_src_addr: '14.190.11.34',
                ipv4_dst_addr: '45.32.70.108',
                l4_src_port: 34469,
                l4_dst_port: 53,
                tcp_flags: 0,
                in_pkts: 1,
                in_bytes: 64,
                protocol: 17,
                direction: 0,
                fsId: 260
            },
            {
                ipv4_src_addr: '115.79.88.218',
                ipv4_dst_addr: '45.32.70.108',
                l4_src_port: 40844,
                l4_dst_port: 53,
                tcp_flags: 0,
                in_pkts: 1,
                in_bytes: 58,
                protocol: 17,
                direction: 0,
                fsId: 260
            },
            {
                ipv4_src_addr: '178.62.165.78',
                ipv4_dst_addr: '103.100.107.2',
                l4_src_port: 50778,
                l4_dst_port: 8888,
                tcp_flags: 16,
                in_pkts: 1,
                in_bytes: 52,
                protocol: 6,
                direction: 0,
                fw_status: 128,
                fsId: 261
            },
            {
                ipv4_src_addr: '45.32.70.108',
                ipv4_dst_addr: '108.61.178.227',
                l4_src_port: 655,
                l4_dst_port: 655,
                tcp_flags: 0,
                in_pkts: 1,
                in_bytes: 1264,
                protocol: 17,
                direction: 1,
                fsId: 260
            },
            {
                ipv4_src_addr: '149.56.28.5',
                ipv4_dst_addr: '103.100.107.235',
                l4_src_port: 42188,
                l4_dst_port: 3822,
                tcp_flags: 2,
                in_pkts: 1,
                in_bytes: 40,
                protocol: 6,
                direction: 0,
                fsId: 260
            },
            {
                ipv4_src_addr: '171.240.0.238',
                ipv4_dst_addr: '45.32.70.108',
                l4_src_port: 1394,
                l4_dst_port: 53,
                tcp_flags: 0,
                in_pkts: 1,
                in_bytes: 56,
                protocol: 17,
                direction: 0,
                fw_status: 127,
                fsId: 261
            },
            {
                ipv4_src_addr: '94.102.49.159',
                ipv4_dst_addr: '103.100.107.69',
                l4_src_port: 42887,
                l4_dst_port: 40546,
                tcp_flags: 2,
                in_pkts: 1,
                in_bytes: 40,
                protocol: 6,
                direction: 0,
                fsId: 260
            },
            {
                ipv4_src_addr: '113.190.146.167',
                ipv4_dst_addr: '45.32.70.108',
                l4_src_port: 36695,
                l4_dst_port: 53,
                tcp_flags: 0,
                in_pkts: 1,
                in_bytes: 64,
                protocol: 17,
                direction: 0,
                fsId: 260
            },
            {
                ipv4_src_addr: '127.0.0.1',
                ipv4_dst_addr: '127.0.0.1',
                l4_src_port: 78,
                l4_dst_port: 58994,
                tcp_flags: 16,
                in_pkts: 1,
                in_bytes: 52,
                protocol: 6,
                direction: 1,
                fsId: 260
            },
            {
                ipv4_src_addr: '14.169.175.115',
                ipv4_dst_addr: '45.32.70.108',
                l4_src_port: 48415,
                l4_dst_port: 53,
                tcp_flags: 0,
                in_pkts: 1,
                in_bytes: 64,
                protocol: 17,
                direction: 0,
                fsId: 260
            },
            {
                ipv4_src_addr: '201.243.27.164',
                ipv4_dst_addr: '103.100.107.132',
                l4_src_port: 29739,
                l4_dst_port: 445,
                tcp_flags: 2,
                in_pkts: 1,
                in_bytes: 52,
                protocol: 6,
                direction: 0,
                fsId: 260
            },
            {
                ipv4_src_addr: '45.32.70.108',
                ipv4_dst_addr: '27.72.164.10',
                l4_src_port: 80,
                l4_dst_port: 57593,
                tcp_flags: 20,
                in_pkts: 1,
                in_bytes: 40,
                protocol: 6,
                direction: 1,
                fsId: 260
            },
            {
                ipv4_src_addr: '45.32.70.108',
                ipv4_dst_addr: '108.61.178.227',
                l4_src_port: 655,
                l4_dst_port: 655,
                tcp_flags: 0,
                in_pkts: 1,
                in_bytes: 128,
                protocol: 17,
                direction: 1,
                fsId: 260
            },
            {
                ipv4_src_addr: '94.102.53.112',
                ipv4_dst_addr: '103.100.107.250',
                l4_src_port: 50155,
                l4_dst_port: 45384,
                tcp_flags: 2,
                in_pkts: 1,
                in_bytes: 40,
                protocol: 6,
                direction: 0,
                fsId: 260
            },
            {
                ipv4_src_addr: '108.61.178.227',
                ipv4_dst_addr: '45.32.70.108',
                l4_src_port: 655,
                l4_dst_port: 655,
                tcp_flags: 0,
                in_pkts: 1,
                in_bytes: 128,
                protocol: 17,
                direction: 0,
                fsId: 260
            },
            {
                ipv4_src_addr: '42.116.242.197',
                ipv4_dst_addr: '45.32.70.108',
                l4_src_port: 57407,
                l4_dst_port: 53,
                tcp_flags: 0,
                in_pkts: 1,
                in_bytes: 65,
                protocol: 17,
                direction: 0,
                fsId: 260
            },
            {
                ipv4_src_addr: '45.32.70.108',
                ipv4_dst_addr: '136.144.156.150',
                l4_src_port: 48584,
                l4_dst_port: 10051,
                tcp_flags: 24,
                in_pkts: 1,
                in_bytes: 2948,
                protocol: 6,
                direction: 1,
                fsId: 260
            },
            {
                ipv4_src_addr: '123.26.212.48',
                ipv4_dst_addr: '45.32.70.108',
                l4_src_port: 55881,
                l4_dst_port: 53,
                tcp_flags: 0,
                in_pkts: 1,
                in_bytes: 70,
                protocol: 17,
                direction: 0,
                fw_status: 127,
                fsId: 261
            },
            {
                ipv4_src_addr: '109.125.133.156',
                ipv4_dst_addr: '103.100.107.44',
                l4_src_port: 55237,
                l4_dst_port: 1433,
                tcp_flags: 2,
                in_pkts: 1,
                in_bytes: 44,
                protocol: 6,
                direction: 0,
                fsId: 260
            },
            {
                ipv4_src_addr: '136.144.156.150',
                ipv4_dst_addr: '45.32.88.125',
                l4_src_port: 8888,
                l4_dst_port: 50778,
                tcp_flags: 24,
                in_pkts: 1,
                in_bytes: 56,
                protocol: 6,
                direction: 0,
                fsId: 260
            },
            {
                ipv4_src_addr: '42.114.31.9',
                ipv4_dst_addr: '45.32.70.108',
                l4_src_port: 45327,
                l4_dst_port: 53,
                tcp_flags: 0,
                in_pkts: 1,
                in_bytes: 64,
                protocol: 17,
                direction: 0,
                fw_status: 127,
                fsId: 261
            },
            {
                ipv4_src_addr: '113.179.151.146',
                ipv4_dst_addr: '45.32.70.108',
                l4_src_port: 52873,
                l4_dst_port: 53,
                tcp_flags: 0,
                in_pkts: 1,
                in_bytes: 64,
                protocol: 17,
                direction: 0,
                fsId: 260
            },
            {
                ipv4_src_addr: '94.102.49.159',
                ipv4_dst_addr: '103.100.107.195',
                l4_src_port: 42887,
                l4_dst_port: 43796,
                tcp_flags: 2,
                in_pkts: 1,
                in_bytes: 40,
                protocol: 6,
                direction: 0,
                fsId: 260
            },
            {
                ipv4_src_addr: '123.16.71.42',
                ipv4_dst_addr: '45.32.70.108',
                l4_src_port: 24020,
                l4_dst_port: 53,
                tcp_flags: 0,
                in_pkts: 1,
                in_bytes: 72,
                protocol: 17,
                direction: 0,
                fsId: 260
            },
            {
                ipv4_src_addr: '1.55.204.148',
                ipv4_dst_addr: '45.32.70.108',
                l4_src_port: 13427,
                l4_dst_port: 53,
                tcp_flags: 0,
                in_pkts: 1,
                in_bytes: 64,
                protocol: 17,
                direction: 0,
                fsId: 260
            },
            {
                ipv4_src_addr: '136.144.156.150',
                ipv4_dst_addr: '45.32.88.125',
                l4_src_port: 8888,
                l4_dst_port: 50778,
                tcp_flags: 24,
                in_pkts: 1,
                in_bytes: 56,
                protocol: 6,
                direction: 0,
                fsId: 260
            },
            {
                ipv4_src_addr: '14.231.207.108',
                ipv4_dst_addr: '45.32.70.108',
                l4_src_port: 44409,
                l4_dst_port: 53,
                tcp_flags: 0,
                in_pkts: 1,
                in_bytes: 63,
                protocol: 17,
                direction: 0,
                fw_status: 127,
                fsId: 261
            },
            {
                ipv4_src_addr: '45.76.36.7',
                ipv4_dst_addr: '45.32.70.108',
                l4_src_port: 655,
                l4_dst_port: 655,
                tcp_flags: 0,
                in_pkts: 1,
                in_bytes: 80,
                protocol: 17,
                direction: 0,
                fsId: 260
            },
            {
                ipv4_src_addr: '14.189.47.240',
                ipv4_dst_addr: '45.32.70.108',
                l4_src_port: 57857,
                l4_dst_port: 53,
                tcp_flags: 0,
                in_pkts: 1,
                in_bytes: 58,
                protocol: 17,
                direction: 0,
                fw_status: 127,
                fsId: 261
            },
            {
                ipv4_src_addr: '14.166.226.152',
                ipv4_dst_addr: '45.32.70.108',
                l4_src_port: 47905,
                l4_dst_port: 53,
                tcp_flags: 0,
                in_pkts: 1,
                in_bytes: 64,
                protocol: 17,
                direction: 0,
                fw_status: 127,
                fsId: 261
            },
            {
                ipv4_src_addr: '1.54.131.91',
                ipv4_dst_addr: '45.32.70.108',
                l4_src_port: 33885,
                l4_dst_port: 53,
                tcp_flags: 0,
                in_pkts: 1,
                in_bytes: 60,
                protocol: 17,
                direction: 0,
                fw_status: 127,
                fsId: 261
            }]
            
            expect(r.flows).to.deep.equal(flows)
            done()

            /*const templates = Object.values(r.templates)[0]
            expect(templates).to.have.property('1024');
            expect(templates).to.have.property('1025');
            expect(templates).to.have.property('2048');
            expect(templates).to.have.property('2049');
            expect(r).to.have.property('header');
            expect(r).to.have.property('flows');

            var header = r.header;
            expect(header).to.have.property('version', 9);
            expect(header).to.have.property('count', 7);
            expect(header).to.have.property('uptime', 152731);
            expect(header).to.have.property('seconds', 1404209570);
            expect(header).to.have.property('sequence', 1);
            expect(header).to.have.property('sourceId', 0);

            var flows = r.flows;
            expect(flows).to.have.length(2);
            
            var f1 = flows[1];
            expect(f1).to.have.property('ipv4_src_addr', '10.100.0.84');
            expect(f1).to.have.property('ipv4_dst_addr', '192.0.76.2');
            expect(f1).to.have.property('in_pkts', 1);
            //TODO:test everything
            done();*/
        });
    })

});