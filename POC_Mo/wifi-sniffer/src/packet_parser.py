from scapy.all import RadioTap
from scapy.layers.dot11 import Dot11, Dot11Elt, Dot11QoS, Dot11Beacon
import time


# =========================
# AWID HEADERS
# =========================

AWID_HEADERS = [
"frame.interface_id","frame.dlt","frame.offset_shift","frame.time_epoch",
"frame.time_delta","frame.time_delta_displayed","frame.time_relative",
"frame.len","frame.cap_len","frame.marked","frame.ignored",

"radiotap.version","radiotap.pad","radiotap.length",
"radiotap.present.tsft","radiotap.present.flags","radiotap.present.rate",
"radiotap.present.channel","radiotap.present.fhss",
"radiotap.present.dbm_antsignal","radiotap.present.dbm_antnoise",
"radiotap.present.lock_quality","radiotap.present.tx_attenuation",
"radiotap.present.db_tx_attenuation","radiotap.present.dbm_tx_power",
"radiotap.present.antenna","radiotap.present.db_antsignal",
"radiotap.present.db_antnoise","radiotap.present.rxflags",
"radiotap.present.xchannel","radiotap.present.mcs",
"radiotap.present.ampdu","radiotap.present.vht",

"radiotap.mactime",
"radiotap.flags.cfp","radiotap.flags.preamble","radiotap.flags.wep",
"radiotap.flags.frag","radiotap.flags.fcs","radiotap.flags.datapad",
"radiotap.flags.badfcs","radiotap.flags.shortgi",

"radiotap.datarate","radiotap.channel.freq",
"radiotap.channel.type.turbo","radiotap.channel.type.cck",
"radiotap.channel.type.ofdm","radiotap.channel.type.2ghz",
"radiotap.channel.type.5ghz","radiotap.channel.type.passive",
"radiotap.channel.type.dynamic","radiotap.channel.type.gfsk",
"radiotap.channel.type.gsm","radiotap.channel.type.sturbo",
"radiotap.channel.type.half","radiotap.channel.type.quarter",

"radiotap.dbm_antsignal","radiotap.antenna","radiotap.rxflags.badplcp",

"wlan.fc.type_subtype","wlan.fc.version","wlan.fc.type",
"wlan.fc.subtype","wlan.fc.ds","wlan.fc.frag","wlan.fc.retry",
"wlan.fc.pwrmgt","wlan.fc.moredata","wlan.fc.protected","wlan.fc.order",

"wlan.duration","wlan.ra","wlan.da","wlan.ta","wlan.sa","wlan.bssid",
"wlan.frag","wlan.seq",

"wlan.bar.type","wlan.ba.control.ackpolicy",
"wlan.ba.control.multitid","wlan.ba.control.cbitmap",
"wlan.bar.compressed.tidinfo","wlan.ba.bm",

"wlan.fcs_good",

"wlan_mgt.fixed.capabilities.ess",
"wlan_mgt.fixed.capabilities.ibss",
"wlan_mgt.fixed.capabilities.cfpoll.ap",
"wlan_mgt.fixed.capabilities.privacy",
"wlan_mgt.fixed.capabilities.preamble",
"wlan_mgt.fixed.capabilities.pbcc",
"wlan_mgt.fixed.capabilities.agility",
"wlan_mgt.fixed.capabilities.spec_man",
"wlan_mgt.fixed.capabilities.short_slot_time",
"wlan_mgt.fixed.capabilities.apsd",
"wlan_mgt.fixed.capabilities.radio_measurement",
"wlan_mgt.fixed.capabilities.dsss_ofdm",
"wlan_mgt.fixed.capabilities.del_blk_ack",
"wlan_mgt.fixed.capabilities.imm_blk_ack",

"wlan_mgt.fixed.listen_ival","wlan_mgt.fixed.current_ap",
"wlan_mgt.fixed.status_code","wlan_mgt.fixed.timestamp",
"wlan_mgt.fixed.beacon","wlan_mgt.fixed.aid",
"wlan_mgt.fixed.reason_code","wlan_mgt.fixed.auth.alg",
"wlan_mgt.fixed.auth_seq","wlan_mgt.fixed.category_code",
"wlan_mgt.fixed.htact","wlan_mgt.fixed.chanwidth",
"wlan_mgt.fixed.fragment","wlan_mgt.fixed.sequence",

"wlan_mgt.tagged.all","wlan_mgt.ssid","wlan_mgt.ds.current_channel",

"wlan_mgt.tim.dtim_count","wlan_mgt.tim.dtim_period",
"wlan_mgt.tim.bmapctl.multicast","wlan_mgt.tim.bmapctl.offset",

"wlan_mgt.country_info.environment",

"wlan_mgt.rsn.version","wlan_mgt.rsn.gcs.type",
"wlan_mgt.rsn.pcs.count","wlan_mgt.rsn.akms.count",
"wlan_mgt.rsn.akms.type",

"wlan_mgt.rsn.capabilities.preauth",
"wlan_mgt.rsn.capabilities.no_pairwise",
"wlan_mgt.rsn.capabilities.ptksa_replay_counter",
"wlan_mgt.rsn.capabilities.gtksa_replay_counter",
"wlan_mgt.rsn.capabilities.mfpr",
"wlan_mgt.rsn.capabilities.mfpc",
"wlan_mgt.rsn.capabilities.peerkey",

"wlan_mgt.tcprep.trsmt_pow",
"wlan_mgt.tcprep.link_mrg",

"wlan.wep.iv","wlan.wep.key","wlan.wep.icv",
"wlan.tkip.extiv","wlan.ccmp.extiv",

"wlan.qos.tid","wlan.qos.priority","wlan.qos.eosp",
"wlan.qos.ack","wlan.qos.amsdupresent",
"wlan.qos.buf_state_indicated","wlan.qos.bit4",
"wlan.qos.txop_dur_req",

"data.len",

"class"
]

def parse_capabilities(pkt, data):

    if not pkt.haslayer(Dot11Beacon):
        return

    beacon = pkt[Dot11Beacon]

    cap = getattr(beacon, "cap", 0)

    # 16-bit capability field
    data["wlan_mgt.fixed.capabilities.ess"] = 1 if cap & 0x0001 else 0
    data["wlan_mgt.fixed.capabilities.ibss"] = 1 if cap & 0x0002 else 0
    data["wlan_mgt.fixed.capabilities.cfpoll.ap"] = 1 if cap & 0x0004 else 0
    data["wlan_mgt.fixed.capabilities.privacy"] = 1 if cap & 0x0010 else 0
    data["wlan_mgt.fixed.capabilities.preamble"] = 1 if cap & 0x0020 else 0
    data["wlan_mgt.fixed.capabilities.pbcc"] = 1 if cap & 0x0040 else 0
    data["wlan_mgt.fixed.capabilities.agility"] = 1 if cap & 0x0080 else 0
    data["wlan_mgt.fixed.capabilities.spec_man"] = 1 if cap & 0x0100 else 0
    data["wlan_mgt.fixed.capabilities.short_slot_time"] = 1 if cap & 0x0400 else 0
    data["wlan_mgt.fixed.capabilities.apsd"] = 1 if cap & 0x0800 else 0
    data["wlan_mgt.fixed.capabilities.radio_measurement"] = 1 if cap & 0x1000 else 0
    data["wlan_mgt.fixed.capabilities.dsss_ofdm"] = 1 if cap & 0x2000 else 0
    data["wlan_mgt.fixed.capabilities.del_blk_ack"] = 1 if cap & 0x4000 else 0
    data["wlan_mgt.fixed.capabilities.imm_blk_ack"] = 1 if cap & 0x8000 else 0

def parse_rsn(pkt, data):

    if not pkt.haslayer(Dot11Elt):
        return

    elt = pkt.getlayer(Dot11Elt)

    while elt:

        if elt.ID == 48:  # RSN IE

            rsn = elt.info

            try:

                # Version
                data["wlan_mgt.rsn.version"] = int.from_bytes(rsn[0:2], "little")

                # Group Cipher Suite
                data["wlan_mgt.rsn.gcs.type"] = rsn[5]

                # Pairwise Cipher Count
                pairwise_count = int.from_bytes(rsn[6:8], "little")
                data["wlan_mgt.rsn.pcs.count"] = pairwise_count

                pos = 8 + pairwise_count * 4

                # AKM count
                akm_count = int.from_bytes(rsn[pos:pos+2], "little")
                data["wlan_mgt.rsn.akms.count"] = akm_count

                pos += 2

                if akm_count > 0:
                    data["wlan_mgt.rsn.akms.type"] = rsn[pos+3]

                pos += akm_count * 4

                # RSN Capabilities
                cap = int.from_bytes(rsn[pos:pos+2], "little")

                data["wlan_mgt.rsn.capabilities.preauth"] = 1 if cap & 0x01 else 0
                data["wlan_mgt.rsn.capabilities.no_pairwise"] = 1 if cap & 0x02 else 0
                data["wlan_mgt.rsn.capabilities.ptksa_replay_counter"] = (cap >> 2) & 0x03
                data["wlan_mgt.rsn.capabilities.gtksa_replay_counter"] = (cap >> 4) & 0x03
                data["wlan_mgt.rsn.capabilities.mfpr"] = 1 if cap & 0x40 else 0
                data["wlan_mgt.rsn.capabilities.mfpc"] = 1 if cap & 0x80 else 0
                data["wlan_mgt.rsn.capabilities.peerkey"] = 1 if cap & 0x200 else 0

            except:
                pass

        elt = elt.payload.getlayer(Dot11Elt)
# =========================
# FRAME
# =========================

def parse_frame(pkt,data):

    now=time.time()

    data["frame.time_epoch"]=now
    data["frame.len"]=len(pkt)
    data["frame.cap_len"]=len(pkt)


# =========================
# RADIOTAP
# =========================

def parse_radiotap(pkt,data):

    if not pkt.haslayer(RadioTap):
        return

    rt=pkt[RadioTap]

    data["radiotap.length"]=getattr(rt,"len",0)
    data["radiotap.datarate"]=getattr(rt,"Rate",0)
    data["radiotap.channel.freq"]=getattr(rt,"ChannelFrequency",0)
    data["radiotap.dbm_antsignal"]=getattr(rt,"dBm_AntSignal",0)
    data["radiotap.antenna"]=getattr(rt,"Antenna",0)

    flags=getattr(rt,"Flags",0)

    data["radiotap.flags.wep"]=1 if flags & 0x10 else 0
    data["radiotap.flags.frag"]=1 if flags & 0x04 else 0
    data["radiotap.flags.badfcs"]=1 if flags & 0x40 else 0


# =========================
# WLAN CORE
# =========================

def parse_wlan(pkt,data):

    if not pkt.haslayer(Dot11):
        return

    dot11=pkt[Dot11]

    data["wlan.fc.type"]=dot11.type
    data["wlan.fc.subtype"]=dot11.subtype
    data["wlan.fc.type_subtype"]=dot11.type*16+dot11.subtype

    fc=dot11.FCfield

    data["wlan.fc.retry"]=1 if fc & 0x08 else 0
    data["wlan.fc.pwrmgt"]=1 if fc & 0x10 else 0
    data["wlan.fc.moredata"]=1 if fc & 0x20 else 0
    data["wlan.fc.protected"]=1 if fc & 0x40 else 0
    data["wlan.fc.order"]=1 if fc & 0x80 else 0

    data["wlan.ra"]=dot11.addr1 or ""
    data["wlan.ta"]=dot11.addr2 or ""
    data["wlan.sa"]=dot11.addr2 or ""
    data["wlan.da"]=dot11.addr1 or ""
    data["wlan.bssid"]=dot11.addr3 or ""

    sc=getattr(dot11,"SC",0) or 0

    data["wlan.seq"]=sc>>4
    data["wlan.frag"]=sc & 0xF

    data["wlan.duration"]=getattr(dot11,"ID",0)


# =========================
# MANAGEMENT FRAMES
# =========================

def parse_management(pkt,data):

    if pkt.haslayer(Dot11Beacon):

        beacon=pkt[Dot11Beacon]

        data["wlan_mgt.fixed.beacon"]=beacon.beacon_interval

    if not pkt.haslayer(Dot11Elt):
        return

    elt=pkt.getlayer(Dot11Elt)

    while elt:

        if elt.ID==0:

            try:
                data["wlan_mgt.ssid"]=elt.info.decode(errors="ignore")
            except:
                pass

        elif elt.ID==3:

            if elt.info:
                data["wlan_mgt.ds.current_channel"]=elt.info[0]

        elif elt.ID==5:

            if len(elt.info)>=2:
                data["wlan_mgt.tim.dtim_count"]=elt.info[0]
                data["wlan_mgt.tim.dtim_period"]=elt.info[1]

        elif elt.ID==48:

            data["wlan_mgt.rsn.version"]=1

        elt=elt.payload.getlayer(Dot11Elt)


# =========================
# QOS
# =========================

def parse_qos(pkt,data):

    if not pkt.haslayer(Dot11QoS):
        return

    qos=pkt[Dot11QoS]

    data["wlan.qos.tid"]=qos.TID


# =========================
# DATA
# =========================

def parse_data(pkt,data):

    try:
        data["data.len"]=len(pkt.payload)
    except:
        pass


# =========================
# MAIN PARSER
# =========================

def extract_awid_fields(pkt):

    data = {h:0 for h in AWID_HEADERS}

    parse_frame(pkt,data)
    parse_rsn(pkt,data)
    parse_radiotap(pkt,data)
    parse_wlan(pkt,data)
    parse_management(pkt,data)
    parse_capabilities(pkt,data)
    parse_qos(pkt,data)
    parse_data(pkt,data)

    return data


# =========================
# PACKET HANDLER
# =========================

def handle_packet(pkt,writer,logger):

    if not pkt.haslayer(Dot11):
        return

    try:

        data=extract_awid_fields(pkt)

        row=[data.get(h,0) for h in AWID_HEADERS]

        writer.writerow(row)

    except Exception:

        logger.exception("Packet parsing error")