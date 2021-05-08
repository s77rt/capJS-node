'use strict';
var bigInt = require("big-integer");

var fflate = require("fflate");

if (!String.prototype.padStart) {
	Object.defineProperty(String.prototype, 'padStart', {
		configurable: true,
		writable: true,
		value: function(targetLength, padString) {
			targetLength = targetLength >> 0; //floor if number or convert non-number to 0;
			padString = String(typeof padString !== 'undefined' ? padString : ' ');
			if (this.length > targetLength) {
				return String(this);
			} else {
				targetLength = targetLength - this.length;
				if (targetLength > padString.length) {
					padString += padString.repeat(targetLength / padString.length); //append to original to ensure we are longer than needed
				}
				return padString.slice(0, targetLength) + String(this);
			}
		},
	});
}

if (!Uint8Array.prototype.slice) {
	Uint8Array.prototype.slice = function(a, b) {
		var Uint8ArraySlice = new Uint8Array(this.buffer.slice(a, b));
		return Uint8ArraySlice;
	}
}

Uint8Array.prototype.toString = function() {
	var arr = [];
	for (var i = 0; i < this.length; i++) {
		arr.push(this[i]);
	}
	return arr.join(',');
}

function is_BIG_ENDIAN_HOST() {
	const array = new Uint8Array(4);
	const view = new Uint32Array(array.buffer);
	return !((view[0] = 1) & array[0]);
}

const CAPJS_VERSION = "0.2.1+dev",
	HCWPAX_SIGNATURE = "WPA",
	TCPDUMP_MAGIC = 0xa1b2c3d4,
	TCPDUMP_CIGAM = 0xd4c3b2a1,
	PCAPNG_MAGIC = 0x1A2B3C4D,
	PCAPNG_CIGAM = 0xD4C3B2A1,
	TCPDUMP_DECODE_LEN = 65535,
	DLT_IEEE802_11 = 105,
	DLT_IEEE802_11_PRISM = 119,
	DLT_IEEE802_11_RADIO = 127,
	DLT_IEEE802_11_PPI_HDR = 192,
	IEEE80211_FCTL_FTYPE = 0x000c,
	IEEE80211_FCTL_STYPE = 0x00f0,
	IEEE80211_FCTL_TODS = 0x0100,
	IEEE80211_FCTL_FROMDS = 0x0200,
	IEEE80211_FTYPE_MGMT = 0x0000,
	IEEE80211_FTYPE_DATA = 0x0008,
	IEEE80211_STYPE_ASSOC_REQ = 0x0000,
	IEEE80211_STYPE_REASSOC_REQ = 0x0020,
	IEEE80211_STYPE_PROBE_REQ = 0x0040,
	IEEE80211_STYPE_PROBE_RESP = 0x0050,
	IEEE80211_STYPE_BEACON = 0x0080,
	IEEE80211_STYPE_QOS_DATA = 0x0080,
	IEEE80211_LLC_DSAP = 0xAA,
	IEEE80211_LLC_SSAP = 0xAA,
	IEEE80211_LLC_CTRL = 0x03,
	IEEE80211_DOT1X_AUTHENTICATION = 0x8E88,
	WPA_KEY_INFO_TYPE_MASK = 7,
	WPA_KEY_INFO_INSTALL = 64,
	WPA_KEY_INFO_ACK = 128,
	WPA_KEY_INFO_SECURE = 512,
	MFIE_TYPE_SSID = 0,
	BROADCAST_MAC = [255, 255, 255, 255, 255, 255],
	MAX_ESSID_LEN = 32,
	EAPOL_TTL = 1,
	AK_PSK = 2,
	AK_PSKSHA256 = 6,
	AK_SAFE = -1,
	EXC_PKT_NUM_1 = 1,
	EXC_PKT_NUM_2 = 2,
	EXC_PKT_NUM_3 = 3,
	EXC_PKT_NUM_4 = 4,
	MESSAGE_PAIR_M12E2 = 0,
	MESSAGE_PAIR_M14E4 = 1,
	MESSAGE_PAIR_M32E2 = 2,
	MESSAGE_PAIR_M32E3 = 3,
	MESSAGE_PAIR_M34E3 = 4,
	MESSAGE_PAIR_M34E4 = 5,
	MESSAGE_PAIR_APLESS = 0b00010000,
	MESSAGE_PAIR_LE = 0b00100000,
	MESSAGE_PAIR_BE = 0b01000000,
	MESSAGE_PAIR_NC = 0b10000000,
	Enhanced_Packet_Block = 0x00000006,
	Section_Header_Block = 0x0A0D0D0A,
	Custom_Block = 0x0000000bad,
	Custom_Option_Codes = [2988, 2989, 19372, 19373],
	if_tsresol_code = 9,
	opt_endofopt = 0,
	HCXDUMPTOOL_PEN = [0x2a, 0xce, 0x46, 0xa1],
	HCXDUMPTOOL_MAGIC_NUMBER = [0x2a, 0xce, 0x46, 0xa1, 0x79, 0xa0, 0x72, 0x33, 0x83, 0x37, 0x27, 0xab, 0x59, 0x33, 0xb3, 0x62, 0x45, 0x37, 0x11, 0x47, 0xa7, 0xcf, 0x32, 0x7f, 0x8d, 0x69, 0x80, 0xc0, 0x89, 0x5e, 0x5e, 0x98],
	HCXDUMPTOOL_OPTIONCODE_RC = 0xf29c,
	HCXDUMPTOOL_OPTIONCODE_ANONCE = 0xf29d,
	SUITE_OUI = [0, 15, 172],
	ZEROED_PMKID = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
const BIG_ENDIAN_HOST = is_BIG_ENDIAN_HOST();
var byteToHex = [];
for (var n = 0; n <= 0xff; ++n) {
	const hexOctet = n.toString(16).padStart(2, 0);
	byteToHex.push(hexOctet);
}

function hex(arrayBuffer) {
	const buff = new Uint8Array(arrayBuffer);
	const hexOctets = [];
	for (var i = 0; i < buff.length; ++i)
		hexOctets.push(byteToHex[buff[i]]);
	return hexOctets.join("");
}

function mod(n, base) {
	return n - Math.floor(n / base) * base;
}

function isNumber(n) {
	return !isNaN(parseFloat(n)) && !isNaN(n - 0)
}

function GetUint16(b) {
	return (b[0] | b[1] << 8) >>> 0
}

function GetUint32(b) {
	return (b[0] | b[1] << 8 | b[2] << 16 | b[3] << 24) >>> 0
}

function GetUint64(b) {
	return (bigInt(b[0]).or(bigInt(b[1]).shiftLeft(8)).or(bigInt(b[2]).shiftLeft(16)).or(bigInt(b[3]).shiftLeft(24)).or(bigInt(b[4]).shiftLeft(32)).or(bigInt(b[5]).shiftLeft(40)).or(bigInt(b[6]).shiftLeft(48)).or(bigInt(b[7]).shiftLeft(56)))
}

function PutUint16(v) {
	return [(v & 0x00ff) >>> 0, (v & 0xff00) >>> 8]
}

function PutUint32(v) {
	return [(v & 0x000000ff) >>> 0, (v & 0x0000ff00) >>> 8, (v & 0x00ff0000) >>> 16, (v & 0xff000000) >>> 24]
}

function byte_swap_16(n) {
	return ((n & 0xff00) >>> 8 | ((n & 0x00ff) >>> 0) << 8) >>> 0
}

function byte_swap_32(n) {
	return ((n & 0xff000000) >>> 24 | (n & 0x00ff0000) >>> 8 | ((n & 0x0000ff00) >>> 0) << 8 | ((n & 0x000000ff) >>> 0) << 24) >>> 0
}

function byte_swap_64(n) {
	return ((bigInt(n).and(bigInt(0xff00000000000000))).shiftRight(56) | (bigInt(n).and(bigInt(0x00ff000000000000))).shiftRight(40) | (bigInt(n).and(bigInt(0x0000ff0000000000))).shiftRight(24) | (bigInt(n).and(bigInt(0x000000ff00000000))).shiftRight(8) | (bigInt(n).and(bigInt(0x00000000ff000000))).shiftLeft(8) | (bigInt(n).and(bigInt(0x0000000000ff0000))).shiftLeft(24) | (bigInt(n).and(bigInt(0x000000000000ff00))).shiftLeft(40) | (bigInt(n).and(bigInt(0x00000000000000ff))).shiftLeft(56))
}

function to_signed_32(n) {
	n = (n & 0xffffffff) >>> 0;
	return ((n ^ 0x80000000) >>> 0) - 0x80000000
}

var DB = {};
DB.essids = {};
DB.pmkids = {};
DB.excpkts = {};
DB.hcwpaxs = {};
DB.pcapng_info = {};
DB.passwords = [];

function DB_essid_add(bssid, essid, essid_len) {
	if (DB.essids.hasOwnProperty(bssid))
		return
	if (essid_len == 0)
		return
	DB.essids[bssid] = {
		'bssid': bssid,
		'essid': essid,
		'essid_len': essid_len
	}
}

function DB_pmkid_add(mac_ap, mac_sta, pmkid, akm) {
	DB.pmkids[[mac_ap, mac_sta]] = {
		'mac_ap': mac_ap,
		'mac_sta': mac_sta,
		'pmkid': pmkid,
		'akm': akm
	}
}

function DB_excpkt_add(excpkt_num, tv_sec, tv_usec, replay_counter, mac_ap, mac_sta, nonce, eapol_len, eapol, keyver, keymic) {
	if (nonce.toString() == Array(32).fill(0).toString())
		return
	var key = mac_ap;
	var subkey = mac_sta;
	var subsubkey;
	if (excpkt_num == EXC_PKT_NUM_1 || excpkt_num == EXC_PKT_NUM_3) {
		subsubkey = 'ap';
	} else {
		subsubkey = 'sta';
	}
	if (!DB.excpkts.hasOwnProperty(key)) {
		DB.excpkts[key] = {};
	}
	if (!DB.excpkts[key].hasOwnProperty(subkey)) {
		DB.excpkts[key][subkey] = {};
	}
	if (!DB.excpkts[key][subkey].hasOwnProperty(subsubkey)) {
		DB.excpkts[key][subkey][subsubkey] = [];
	}
	DB.excpkts[key][subkey][subsubkey].push({
		'excpkt_num': excpkt_num,
		'tv_sec': tv_sec,
		'tv_usec': tv_usec,
		'tv_abs': (tv_sec * 1000 * 1000) + tv_usec,
		'replay_counter': replay_counter,
		'mac_ap': key,
		'mac_sta': subkey,
		'nonce': nonce,
		'eapol_len': eapol_len,
		'eapol': eapol,
		'keyver': keyver,
		'keymic': keymic
	});
}

function DB_hcwpaxs_add(signature, ftype, pmkid_or_mic, mac_ap, mac_sta, essid, anonce, eapol, message_pair) {
	var key;
	if (ftype == "01") {
		key = pmkid_or_mic;
		if (DB.hcwpaxs[key])
			return;
		DB.hcwpaxs[key] = {
			'signature': signature,
			'type': ftype,
			'pmkid_or_mic': hex(pmkid_or_mic),
			'mac_ap': hex(mac_ap),
			'mac_sta': hex(mac_sta),
			'essid': hex(essid),
			'anonce': '',
			'eapol': '',
			'message_pair': ''
		};
	} else if (ftype == "02") {
		key = [pmkid_or_mic, message_pair];
		if (DB.hcwpaxs[key])
			return;
		DB.hcwpaxs[key] = {
			'signature': signature,
			'type': ftype,
			'pmkid_or_mic': hex(pmkid_or_mic),
			'mac_ap': hex(mac_ap),
			'mac_sta': hex(mac_sta),
			'essid': hex(essid),
			'anonce': hex(anonce),
			'eapol': hex(eapol),
			'message_pair': message_pair.toString(16).padStart(2, 0)
		};
	}
}

function DB_pcapng_info_add(key, info) {
	DB.pcapng_info[key] = info;
}

function DB_password_add(password) {
	for (var i = password.length - 1; i >= 0; i--) {
		var char = password[i];
		if (char < 0x20 || char > 0x7e) {
			DB.passwords.push("$HEX[" + hex(password) + "]");
			return;
		}
	}
	DB.passwords.push(new TextDecoder().decode(new Uint8Array(password)));
}

var bytes;
var format;
var best_only;
var export_unauthenticated;
var ignore_ts;
var ignore_ie;
var pos; // read cursor position

function capjs(bytes_input, format_input, best_only_input, export_unauthenticated_input, ignore_ts_input, ignore_ie_input) {
	bytes = new Uint8Array(bytes_input); // bytes must be an ArrayBuffer
	format = format_input;
	best_only = best_only_input;
	export_unauthenticated = export_unauthenticated_input;
	ignore_ts = ignore_ts_input;
	ignore_ie = ignore_ie_input;
	pos = 0; // read cursor position

	DB = {};
	DB.essids = {};
	DB.pmkids = {};
	DB.excpkts = {};
	DB.hcwpaxs = {};
	DB.pcapng_info = {};
	DB.passwords = [];

}

function Analysis() {
	if ((format == "pcap") || (format == "cap")) {
		_pcap2hcwpax();
	} else if (format == "pcapng") {
		_pcapng2hcwpax();
	} else if ((format == "pcap.gz") || (format == "cap.gz")) {
		__Decompress();
		_pcap2hcwpax();
	} else if (format == "pcapng.gz") {
		__Decompress();
		_pcapng2hcwpax();
	} else {
		console.log('Unsupported capture file');
	}
}

function Get(x) {
	if (x == 'hcwpax') {
		return DB.hcwpaxs;
	}
	return;
}

function Getf(x) {
	var data = [];
	if (x == 'hcwpax') {
		Object.values(DB.hcwpaxs).forEach(function(hcwpax) {
			data.push((Object.values(hcwpax).join('*')));
		});
	}
	return data.join('\n');
}

function GetPasswords() {
	return Array.from(new Set(DB.passwords)).join('\n');
}

function __Decompress() {
	try {
		bytes = fflate.gunzipSync(bytes);
	} catch (err) {
		console.log(err);
	}
}

function __Tell() {
	return pos;
}

function __Seek(n) {
	pos = n;
}

function __Read(n) {
	var data = bytes.slice(pos, pos + n);
	pos += n;
	return data;
}

function __get_essid_from_tag(packet, header, length_skip) {
	if (length_skip > header['caplen'])
		return [-1, NaN];
	var length = header['caplen'] - length_skip;
	var beacon = packet.slice(length_skip, length_skip + length);
	var cur = 0;
	var end = beacon.length;
	var tagtype, taglen;
	while (cur < end) {
		if ((cur + 2) >= end)
			break
		tagtype = beacon[cur];
		cur += 1;
		taglen = beacon[cur];
		cur += 1;
		if ((cur + taglen) >= end)
			break
		if (tagtype == MFIE_TYPE_SSID) {
			if (taglen <= MAX_ESSID_LEN) {
				var essid = {};
				essid['essid'] = new Uint8Array(MAX_ESSID_LEN);
				essid['essid'].set(beacon.slice(cur, cur + taglen));
				essid['essid_len'] = taglen;
				return [0, essid];
			}
		}
		cur += taglen;
	}
	return [-1, NaN];
}

function __get_pmkid_from_packet(packet, source) {
	var i, pos, skip, tag_id, tag_len, tag_data, tag_pairwise_suite_count, tag_authentication_suite_count, pmkid_count, akm;
	if (source == "EAPOL-M1") {
		akm = NaN; // Unknown AKM
		pos = 0;
		while (true) {
			tag_id = packet[pos];
			if (tag_id == undefined)
				break;
			tag_len = packet[pos + 1];
			if (tag_id == 221) {
				tag_data = packet.slice(pos + 2, pos + 2 + tag_len);
				if (tag_data.slice(0, 3).toString() == SUITE_OUI.toString()) {
					var pmkid = tag_data.slice(4);
					if (pmkid.toString() != ZEROED_PMKID.toString())
						return [pmkid, akm];
				}
			}
			pos = pos + 2 + tag_len;
		}
		return;
	} else if (source == "EAPOL-M2") {
		pos = 0;
	} else if (source == IEEE80211_STYPE_ASSOC_REQ) {
		pos = 28;
	} else if (source == IEEE80211_STYPE_REASSOC_REQ) {
		pos = 34;
	} else {
		return;
	}
	while (true) {
		tag_id = packet[pos];
		if (tag_id == undefined)
			break;
		tag_len = packet[pos + 1];
		if (tag_id == 48) {
			tag_data = packet.slice(pos + 2, pos + 2 + tag_len);
			tag_pairwise_suite_count = GetUint16(tag_data.slice(6, 8));
			if (BIG_ENDIAN_HOST)
				tag_pairwise_suite_count = byte_swap_16(tag_pairwise_suite_count);
			pos = 8;
			pos += 4 * tag_pairwise_suite_count;
			// AKM Suite
			tag_authentication_suite_count = GetUint16(tag_data.slice(pos, pos + 2));
			if (BIG_ENDIAN_HOST)
				tag_authentication_suite_count = byte_swap_16(tag_authentication_suite_count);
			pos = pos + 2;
			skip = 0;
			for (i = 0; i < tag_authentication_suite_count; i++) {
				pos += (4 * i) + 4;
				akm = tag_data.slice(pos - 4, pos);
				if (akm.slice(0, 3).toString() != SUITE_OUI.toString()) {
					skip = 1;
					break;
				}
			}
			if (skip == 1)
				break
			pmkid_count = GetUint16(tag_data.slice(pos + 2, pos + 4));
			if (BIG_ENDIAN_HOST)
				pmkid_count = byte_swap_16(pmkid_count);
			pos = pos + 4;
			for (i = 0; i < pmkid_count; i++) {
				pos += (16 * i) + 16;
				var pmkid = tag_data.slice(pos - 16, pos);
				if (pmkid.toString() != ZEROED_PMKID.toString())
					return [pmkid, akm[3]];
			}
			break;
		}
		pos = pos + 2 + tag_len;
	}
}

function __handle_llc(ieee80211_llc_snap_header) {
	if (ieee80211_llc_snap_header['dsap'] != IEEE80211_LLC_DSAP)
		return -1
	if (ieee80211_llc_snap_header['ssap'] != IEEE80211_LLC_SSAP)
		return -1
	if (ieee80211_llc_snap_header['ctrl'] != IEEE80211_LLC_CTRL)
		return -1
	if (ieee80211_llc_snap_header['ethertype'] != IEEE80211_DOT1X_AUTHENTICATION)
		return -1
	return 0
}

function __handle_auth(auth_packet, auth_packet_copy, auth_packet_t_size, keymic_size, rest_packet, pkt_offset, pkt_size) {
	var ap_length = byte_swap_16(auth_packet['length']);
	var ap_key_information = byte_swap_16(auth_packet['key_information']);
	var ap_replay_counter = byte_swap_64(auth_packet['replay_counter']);
	var ap_wpa_key_data_length = byte_swap_16(auth_packet['wpa_key_data_length']);
	if (ap_length == 0)
		return [-1, NaN];
	var excpkt_num;
	if ((ap_key_information & WPA_KEY_INFO_ACK) >>> 0) {
		if ((ap_key_information & WPA_KEY_INFO_INSTALL) >>> 0) {
			excpkt_num = EXC_PKT_NUM_3;
		} else {
			excpkt_num = EXC_PKT_NUM_1;
		}
	} else {
		if ((ap_key_information & WPA_KEY_INFO_SECURE) >>> 0) {
			excpkt_num = EXC_PKT_NUM_4;
		} else {
			excpkt_num = EXC_PKT_NUM_2;
		}
	}
	var excpkt = {};
	excpkt['nonce'] = new Uint8Array(32);
	excpkt['nonce'].set(auth_packet['wpa_key_nonce']);
	excpkt['replay_counter'] = ap_replay_counter;
	excpkt['excpkt_num'] = excpkt_num;
	excpkt['eapol_len'] = auth_packet_t_size + ap_wpa_key_data_length;
	if ((pkt_offset + excpkt['eapol_len']) > pkt_size)
		return [-1, NaN];
	if ((auth_packet_t_size + ap_wpa_key_data_length) > 256)
		return [-1, NaN];
	excpkt['eapol'] = new Uint8Array(256);
	excpkt['eapol'].set(auth_packet_copy);
	excpkt['eapol'].set(rest_packet.slice(0, ap_wpa_key_data_length), auth_packet_t_size);
	excpkt['keymic'] = auth_packet['wpa_key_mic'];
	excpkt['keyver'] = (ap_key_information & WPA_KEY_INFO_TYPE_MASK) >>> 0;
	if ((excpkt_num == EXC_PKT_NUM_3) || (excpkt_num == EXC_PKT_NUM_4))
		excpkt['replay_counter'] = bigInt(excpkt['replay_counter']).minus(1);
	return [0, excpkt];
}
/* PCAPNG ONLY */
function __read_blocks() {
	var blocks = [];
	while (true) {
		var block_type = __Read(4);
		var block_length = __Read(4);
		if (!block_type.length || !block_length.length)
			break;
		block_type = GetUint32(block_type);
		block_length = GetUint32(block_length);
		if (BIG_ENDIAN_HOST) {
			block_type = byte_swap_32(block_type);
			block_length = byte_swap_32(block_length);
		}
		var block_body_length = Math.max(block_length - 12, 0);
		var block = {
			'block_type': block_type,
			'block_length': block_length,
			'block_body': __Read(block_body_length),
			'block_length_2': GetUint32(__Read(4))
		}
		blocks.push(block);
	}
	return blocks;
}

function __read_options(options_block, bitness) {
	var options = [];
	while (true) {
		var option = {};
		option['code'] = options_block.slice(0, 2);
		option['length'] = options_block.slice(2, 4);
		if (!option['code'].length || !option['length'].length)
			break;
		option['code'] = GetUint16(option['code']);
		option['length'] = GetUint16(option['length']);
		if (BIG_ENDIAN_HOST) {
			option['code'] = byte_swap_16(option['code']);
			option['length'] = byte_swap_16(option['length']);
		}
		if (bitness) {
			option['code'] = byte_swap_16(option['code']);
			option['length'] = byte_swap_16(option['length']);
		}
		if (option['code'] == opt_endofopt)
			break;
		var option_length = option['length'] + mod(-(option['length']), 4);
		option['value'] = options_block.slice(4, 4 + option_length);
		if (Custom_Option_Codes.includes(option['code'])) {
			var pen = option['value'].slice(0, 4);
			if (pen.toString() == HCXDUMPTOOL_PEN.toString()) {
				var magic = option['value'].slice(4, 36);
				if (magic.toString() == HCXDUMPTOOL_MAGIC_NUMBER.toString()) {
					__read_options(option['value'].slice(36), bitness).forEach(function(custom_option) {
						options.push(custom_option);
					});
				}
			}
			options_block = options_block.slice(4 + option_length); // keep those lines as they are (we were using a generator)
		} else {
			options_block = options_block.slice(4 + option_length); // keep those lines as they are (we were using a generator)
			options.push(option);
		}
	}
	return options;
}

function __read_custom_block(custom_block, bitness) {
	var name, data, options;
	var pen = custom_block.slice(0, 4);
	if (pen.toString() == HCXDUMPTOOL_PEN.toString()) {
		var magic = custom_block.slice(4, 36);
		if (magic.toString() == HCXDUMPTOOL_MAGIC_NUMBER.toString()) {
			name = 'hcxdumptool';
			data = undefined;
			options = [];
			__read_options(custom_block.slice(36), bitness).forEach(function(option) {
				if (option['code'] == HCXDUMPTOOL_OPTIONCODE_RC) {
					option['value'] = GetUint64(option['value']);
					if (BIG_ENDIAN_HOST)
						option['value'] = byte_swap_64(option['value']);
					if (bitness)
						option['value'] = byte_swap_64(option['value']);
				}
				options.push(option);
			});
		}
	}
	return [name, data, options];
}
/* END PCAPNG ONLY */
function __process_packet(packet, header) {
	if (header['caplen'] < 24)
		return
	var ieee80211_hdr_3addr = {
		'frame_control': GetUint16(packet.slice(0, 2)),
		//duration_id
		'addr1': [packet[4], packet[5], packet[6], packet[7], packet[8], packet[9]],
		'addr2': [packet[10], packet[11], packet[12], packet[13], packet[14], packet[15]],
		'addr3': [packet[16], packet[17], packet[18], packet[19], packet[20], packet[21]]
		//seq_ctrl
	}
	if (BIG_ENDIAN_HOST)
		ieee80211_hdr_3addr['frame_control'] = byte_swap_16(ieee80211_hdr_3addr['frame_control']);
	var frame_control = ieee80211_hdr_3addr['frame_control'];
	var ret;
	if ((frame_control & IEEE80211_FCTL_FTYPE) >>> 0 == IEEE80211_FTYPE_MGMT) {
		var rc_beacon, essid;
		var stype = (frame_control & IEEE80211_FCTL_STYPE) >>> 0;
		if (stype == IEEE80211_STYPE_BEACON) {
			ret = __get_essid_from_tag(packet, header, 36);
			rc_beacon = ret[0];
			essid = ret[1];
			if (rc_beacon == -1)
				return
			DB_password_add(essid['essid'].slice(0, essid['essid_len'])); // AP-LESS
			if (ieee80211_hdr_3addr['addr3'] == BROADCAST_MAC)
				return
			DB_essid_add(ieee80211_hdr_3addr['addr3'], essid['essid'], essid['essid_len']);
		} else if (stype == IEEE80211_STYPE_PROBE_REQ) {
			ret = __get_essid_from_tag(packet, header, 24);
			rc_beacon = ret[0];
			essid = ret[1];
			if (rc_beacon == -1)
				return
			DB_password_add(essid['essid'].slice(0, essid['essid_len'])); // AP-LESS
			if (ieee80211_hdr_3addr['addr3'] == BROADCAST_MAC)
				return
			DB_essid_add(ieee80211_hdr_3addr['addr3'], essid['essid'], essid['essid_len']);
		} else if (stype == IEEE80211_STYPE_PROBE_RESP) {
			ret = __get_essid_from_tag(packet, header, 36);
			rc_beacon = ret[0];
			essid = ret[1];
			if (rc_beacon == -1)
				return
			DB_password_add(essid['essid'].slice(0, essid['essid_len'])); // AP-LESS
			if (ieee80211_hdr_3addr['addr3'] == BROADCAST_MAC)
				return
			DB_essid_add(ieee80211_hdr_3addr['addr3'], essid['essid'], essid['essid_len']);
		} else if (stype == IEEE80211_STYPE_ASSOC_REQ) {
			ret = __get_essid_from_tag(packet, header, 28);
			rc_beacon = ret[0];
			essid = ret[1];
			if (rc_beacon == -1)
				return
			DB_password_add(essid['essid'].slice(0, essid['essid_len'])); // AP-LESS
			if (ieee80211_hdr_3addr['addr3'] == BROADCAST_MAC)
				return
			DB_essid_add(ieee80211_hdr_3addr['addr3'], essid['essid'], essid['essid_len']);
			var mac_ap = ieee80211_hdr_3addr['addr3'];
			var mac_sta = (mac_ap == ieee80211_hdr_3addr['addr1']) ? ieee80211_hdr_3addr['addr2'] : ieee80211_hdr_3addr['addr1'];
			var pmkid_akm = __get_pmkid_from_packet(packet, stype);
			if (pmkid_akm != undefined)
				DB_pmkid_add(mac_ap, mac_sta, pmkid_akm[0], pmkid_akm[1]);
		} else if (stype == IEEE80211_STYPE_REASSOC_REQ) {
			ret = __get_essid_from_tag(packet, header, 34);
			rc_beacon = ret[0];
			essid = ret[1];
			if (rc_beacon == -1)
				return
			DB_password_add(essid['essid'].slice(0, essid['essid_len'])); // AP-LESS
			if (ieee80211_hdr_3addr['addr3'] == BROADCAST_MAC)
				return
			DB_essid_add(ieee80211_hdr_3addr['addr3'], essid['essid'], essid['essid_len']);
			var mac_ap = ieee80211_hdr_3addr['addr3'];
			var mac_sta = (mac_ap == ieee80211_hdr_3addr['addr1']) ? ieee80211_hdr_3addr['addr2'] : ieee80211_hdr_3addr['addr1'];
			var pmkid_akm = __get_pmkid_from_packet(packet, stype);
			if (pmkid_akm != undefined)
				DB_pmkid_add(mac_ap, mac_sta, pmkid_akm[0], pmkid_akm[1]);
		}
	} else if ((frame_control & IEEE80211_FCTL_FTYPE) >>> 0 == IEEE80211_FTYPE_DATA) {
		var llc_offset;
		var addr4_exist = ((frame_control & (IEEE80211_FCTL_TODS | IEEE80211_FCTL_FROMDS) >>> 0) >>> 0 == (IEEE80211_FCTL_TODS | IEEE80211_FCTL_FROMDS) >>> 0);
		if ((frame_control & IEEE80211_FCTL_STYPE) >>> 0 == IEEE80211_STYPE_QOS_DATA) {
			llc_offset = 26;
		} else {
			llc_offset = 24;
		}
		if (header['caplen'] < (llc_offset + 8))
			return;
		if (addr4_exist)
			llc_offset += 6
		var ieee80211_llc_snap_header = {
			'dsap': packet[llc_offset],
			'ssap': packet[llc_offset + 1],
			'ctrl': packet[llc_offset + 2],
			//'oui': (packet[llc_offset+3], packet[llc_offset+4], packet[llc_offset+5]),
			'ethertype': GetUint16(packet.slice(llc_offset + 6, llc_offset + 8))
		}
		if (BIG_ENDIAN_HOST)
			ieee80211_llc_snap_header['ethertype'] = byte_swap_16(ieee80211_llc_snap_header['ethertype']);
		var rc_llc = __handle_llc(ieee80211_llc_snap_header);
		if (rc_llc == -1)
			return
		var auth_offset = llc_offset + 8;
		var auth_head_type = packet[auth_offset + 1];
		var auth_head_length = GetUint16(packet.slice(auth_offset + 2, auth_offset + 4));
		if (BIG_ENDIAN_HOST)
			auth_head_length = byte_swap_16(auth_head_length);
		var keymic_size, auth_packet_t_size;
		if (auth_head_type == 3) {
			if (packet.slice(auth_offset).length < 107) {
				keymic_size = 16;
				auth_packet_t_size = 99;
			} else {
				var l1 = GetUint16(packet.slice(auth_offset + 97, auth_offset + 99));
				var l2 = GetUint16(packet.slice(auth_offset + 105, auth_offset + 107));
				if (BIG_ENDIAN_HOST) {
					l1 = byte_swap_16(l1);
					l2 = byte_swap_16(l2);
				}
				auth_head_length = byte_swap_16(auth_head_length);
				l1 = byte_swap_16(l1);
				l2 = byte_swap_16(l2);
				if (l1 + 99 == auth_head_length + 4) {
					keymic_size = 16;
					auth_packet_t_size = 99;
				} else if (l2 + 107 == auth_head_length + 4) {
					keymic_size = 24;
					auth_packet_t_size = 107;
				} else {
					return;
				}
			}
			if (header['caplen'] < (auth_offset + auth_packet_t_size))
				return
			var auth_packet, auth_packet_copy;
			if (keymic_size == 16) {
				auth_packet = {
					'length': GetUint16(packet.slice(auth_offset + 2, auth_offset + 4)),
					'key_information': GetUint16(packet.slice(auth_offset + 5, auth_offset + 7)),
					'replay_counter': GetUint64(packet.slice(auth_offset + 9, auth_offset + 17)),
					'wpa_key_nonce': packet.slice(auth_offset + 17, auth_offset + 49),
					'wpa_key_mic': packet.slice(auth_offset + 81, auth_offset + 97),
					'wpa_key_data_length': GetUint16(packet.slice(auth_offset + 97, auth_offset + 99))
				}
				auth_packet_copy = new Uint8Array(auth_packet_t_size);
				auth_packet_copy.set(packet.slice(auth_offset, auth_offset + 81));
				auth_packet_copy.set([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], 81);
				auth_packet_copy.set((packet.slice(auth_offset + 97, auth_offset + 99)), 97);
			} else if (keymic_size == 24) {
				auth_packet = {
					'length': GetUint16(packet.slice(auth_offset + 2, auth_offset + 4)),
					'key_information': GetUint16(packet.slice(auth_offset + 5, auth_offset + 7)),
					'replay_counter': GetUint64(packet.slice(auth_offset + 9, auth_offset + 17)),
					'wpa_key_nonce': packet.slice(auth_offset + 17, auth_offset + 49),
					'wpa_key_mic': packet.slice(auth_offset + 81, auth_offset + 105),
					'wpa_key_data_length': GetUint16(packet.slice(auth_offset + 105, auth_offset + 107))
				}
				auth_packet_copy = new Uint8Array(auth_packet_t_size);
				auth_packet_copy.set(packet.slice(auth_offset, auth_offset + 81));
				auth_packet_copy.set([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], 81);
				auth_packet_copy.set((packet.slice(auth_offset + 105, auth_offset + 107)), 105);
			} else {
				return;
			}
			if (BIG_ENDIAN_HOST) {
				auth_packet['length'] = byte_swap_16(auth_packet['length']);
				auth_packet['key_information'] = byte_swap_16(auth_packet['key_information']);
				//auth_packet['key_length']          = byte_swap_16(auth_packet['key_length']);
				auth_packet['replay_counter'] = byte_swap_64(auth_packet['replay_counter']);
				auth_packet['wpa_key_data_length'] = byte_swap_16(auth_packet['wpa_key_data_length']);
			}
			var rest_packet = packet.slice(auth_offset + auth_packet_t_size);
			var rc_auth, excpkt;
			ret = __handle_auth(auth_packet, auth_packet_copy, auth_packet_t_size, keymic_size, rest_packet, auth_offset, header['caplen']);
			rc_auth = ret[0];
			excpkt = ret[1];
			if (rc_auth == -1)
				return;
			if (excpkt['excpkt_num'] == EXC_PKT_NUM_1 || excpkt['excpkt_num'] == EXC_PKT_NUM_3) {
				DB_excpkt_add(excpkt['excpkt_num'], header['tv_sec'], header['tv_usec'], excpkt['replay_counter'], ieee80211_hdr_3addr['addr2'], ieee80211_hdr_3addr['addr1'], excpkt['nonce'], excpkt['eapol_len'], excpkt['eapol'], excpkt['keyver'], excpkt['keymic']);
				if (excpkt['excpkt_num'] == EXC_PKT_NUM_1) {
					var pmkid_akm = __get_pmkid_from_packet(rest_packet, "EAPOL-M1");
					if (pmkid_akm != undefined) {
						if (isNaN(pmkid_akm[1]) && excpkt['keyver'] >= 1 && excpkt['keyver'] <= 3)
							pmkid_akm[1] = AK_SAFE;
						DB_pmkid_add(ieee80211_hdr_3addr['addr2'], ieee80211_hdr_3addr['addr1'], pmkid_akm[0], pmkid_akm[1]);
					}
				}
			} else if (excpkt['excpkt_num'] == EXC_PKT_NUM_2 || excpkt['excpkt_num'] == EXC_PKT_NUM_4) {
				DB_excpkt_add(excpkt['excpkt_num'], header['tv_sec'], header['tv_usec'], excpkt['replay_counter'], ieee80211_hdr_3addr['addr1'], ieee80211_hdr_3addr['addr2'], excpkt['nonce'], excpkt['eapol_len'], excpkt['eapol'], excpkt['keyver'], excpkt['keymic']);
				if (excpkt['excpkt_num'] == EXC_PKT_NUM_2) {
					var pmkid_akm = __get_pmkid_from_packet(rest_packet, "EAPOL-M2");
					if (pmkid_akm != undefined) {
						if (isNaN(pmkid_akm[1]) && excpkt['keyver'] >= 1 && excpkt['keyver'] <= 3)
							pmkid_akm[1] = AK_SAFE;
						DB_pmkid_add(ieee80211_hdr_3addr['addr1'], ieee80211_hdr_3addr['addr2'], pmkid_akm[0], pmkid_akm[1]);
					}
				}
			}
		}
	}
}

function __read_pcap_file_header() {
	var pcap_header = __Read(24);
	if (!pcap_header.length)
		return;
	var pcap_file_header = {
		'magic': GetUint32(pcap_header.slice(0, 4)),
		//version_major
		//version_minor
		//thiszone
		//sigfigs
		//snaplen
		'linktype': GetUint32(pcap_header.slice(20, 24))
	};
	if (BIG_ENDIAN_HOST) {
		pcap_file_header['magic'] = byte_swap_32(pcap_file_header['magic']);
		pcap_file_header['linktype'] = byte_swap_32(pcap_file_header['linktype']);
	}
	var bitness;
	if (pcap_file_header['magic'] == TCPDUMP_MAGIC) {
		bitness = 0;
	} else if (pcap_file_header['magic'] == TCPDUMP_CIGAM) {
		bitness = 1;
		pcap_file_header['linktype'] = byte_swap_32(pcap_file_header['linktype']);
	} else {
		console.log('Invalid pcap header');
		return;
	}
	if ((pcap_file_header['linktype'] != DLT_IEEE802_11) && (pcap_file_header['linktype'] != DLT_IEEE802_11_PRISM) && (pcap_file_header['linktype'] != DLT_IEEE802_11_RADIO) && (pcap_file_header['linktype'] != DLT_IEEE802_11_PPI_HDR)) {
		console.log('Unsupported linktype detected');
		return;
	}
	return [pcap_file_header, bitness];
}

function __read_pcap_packets(pcap_file_header, bitness) {
	while (true) {
		var pcap_pkthdr = __Read(16);
		if (!pcap_pkthdr.length)
			break;
		var header = {
			'tv_sec': GetUint32(pcap_pkthdr.slice(0, 4)),
			'tv_usec': GetUint32(pcap_pkthdr.slice(4, 8)),
			'caplen': GetUint32(pcap_pkthdr.slice(8, 12)),
			'len': GetUint32(pcap_pkthdr.slice(12, 16))
		}
		if (BIG_ENDIAN_HOST) {
			header['tv_sec'] = byte_swap_32(header['tv_sec']);
			header['tv_usec'] = byte_swap_32(header['tv_usec']);
			header['caplen'] = byte_swap_32(header['caplen']);
			header['len'] = byte_swap_32(header['len']);
		}
		if (bitness) {
			header['tv_sec'] = byte_swap_32(header['tv_sec']);
			header['tv_usec'] = byte_swap_32(header['tv_usec']);
			header['caplen'] = byte_swap_32(header['caplen']);
			header['len'] = byte_swap_32(header['len']);
		}
		if (header['tv_sec'] == 0 && header['tv_usec'] == 0) {
			console.log('Zero value timestamps detected');
			if (!ignore_ts)
				continue;
		}
		if (header['caplen'] >= TCPDUMP_DECODE_LEN || to_signed_32(header['caplen']) < 0) {
			console.log('Oversized packet detected');
			continue;
		}
		var packet = __Read(Math.max(header['caplen'], 0));
		if (pcap_file_header['linktype'] == DLT_IEEE802_11_PRISM) {
			if (header['caplen'] < 144) {
				console.log('Could not read prism header');
				continue;
			}
			var prism_header = {
				'msgcode': GetUint32(packet.slice(0, 4)),
				'msglen': GetUint32(packet.slice(4, 8))
				//devname
				//hosttime
				//mactime
				//channel
				//rssi
				//sq
				//signal
				//noise
				//rate
				//istx
				//frmlen
			}
			if (BIG_ENDIAN_HOST) {
				prism_header['msgcode'] = byte_swap_32(prism_header['msgcode']);
				prism_header['msglen'] = byte_swap_32(prism_header['msglen']);
			}
			if (to_signed_32(prism_header['msglen']) < 0) {
				console.log('Oversized packet detected');
				continue;
			}
			if (to_signed_32(header['caplen'] - prism_header['msglen']) < 0) {
				console.log('Oversized packet detected');
				continue;
			}
			packet = packet.slice(prism_header['msglen']);
			header['caplen'] -= prism_header['msglen'];
			header['len'] -= prism_header['msglen'];
		} else if (pcap_file_header['linktype'] == DLT_IEEE802_11_RADIO) {
			if (header['caplen'] < 8) {
				console.log('Could not read radiotap header');
				continue;
			}
			var ieee80211_radiotap_header = {
				'it_version': packet[0],
				//it_pad
				'it_len': GetUint16(packet.slice(2, 4)),
				'it_present': GetUint32(packet.slice(4, 8))
			}
			if (BIG_ENDIAN_HOST) {
				ieee80211_radiotap_header['it_len'] = byte_swap_16(ieee80211_radiotap_header['it_len']);
				ieee80211_radiotap_header['it_present'] = byte_swap_32(ieee80211_radiotap_header['it_present']);
			}
			if (ieee80211_radiotap_header['it_version'] != 0) {
				console.log('Invalid radiotap header');
				continue;
			}
			packet = packet.slice(ieee80211_radiotap_header['it_len']);
			header['caplen'] -= ieee80211_radiotap_header['it_len'];
			header['len'] -= ieee80211_radiotap_header['it_len'];
		} else if (pcap_file_header['linktype'] == DLT_IEEE802_11_PPI_HDR) {
			if (header['caplen'] < 8) {
				console.log('Could not read ppi header');
				continue;
			}
			var ppi_packet_header = {
				//pph_version
				//pph_flags
				'pph_len': GetUint16(packet.slice(2, 4))
				//pph_dlt
			}
			if (BIG_ENDIAN_HOST)
				ppi_packet_header['pph_len'] = byte_swap_16(ppi_packet_header['pph_len']);
			packet = packet.slice(ppi_packet_header['pph_len']);
			header['caplen'] -= ppi_packet_header['pph_len'];
			header['len'] -= ppi_packet_header['pph_len'];
		}
		__process_packet(packet, header);
	}
}

function __read_pcapng_file_header_then_packets() {
	var blocks = __read_blocks();
	for (var i = 0; i < blocks.length; i++) {
		var block = blocks[i];
		if (block['block_type'] == Section_Header_Block) {
			if (i + 1 > blocks.length - 1)
				break
			i += 1;
			var interface_block = blocks[i];
			var pcapng_file_header = {};
			pcapng_file_header['magic'] = block['block_body'].slice(0, 4);
			pcapng_file_header['linktype'] = interface_block['block_body'][0];
			if (BIG_ENDIAN_HOST) {
				pcapng_file_header['magic'] = byte_swap_32(pcapng_file_header['magic']);
				pcapng_file_header['linktype'] = byte_swap_32(pcapng_file_header['linktype']);
			}
			var magic = GetUint32(pcapng_file_header['magic']);
			var bitness;
			if (magic == PCAPNG_MAGIC) {
				bitness = 0;
			} else if (magic == PCAPNG_CIGAM) {
				bitness = 1;
				pcapng_file_header['linktype'] = byte_swap_32(pcapng_file_header['linktype']);
				console.log('WARNING! BigEndian (Endianness) files are not well tested.');
			} else {
				continue;
			}
			pcapng_file_header['section_options'] = [];
			__read_options(block['block_body'].slice(16), bitness).forEach(function(option) {
				pcapng_file_header['section_options'].push(option);
			});
			var if_tsresol = 6;
			pcapng_file_header['interface_options'] = [];
			__read_options(interface_block['block_body'].slice(8), bitness).forEach(function(option) {
				var ok = true;
				if (option['code'] == if_tsresol_code) {
					if_tsresol = option['value'].slice(option['length']);
					// currently only supports if_tsresol = 6
					if (if_tsresol != 6) {
						console.log('WARNING! Unsupported if_tsresol');
						ok = false;
					}
				}
				if (ok)
					pcapng_file_header['interface_options'].push(option);
			});
			if ((pcapng_file_header['linktype'] != DLT_IEEE802_11) &&
				(pcapng_file_header['linktype'] != DLT_IEEE802_11_PRISM) &&
				(pcapng_file_header['linktype'] != DLT_IEEE802_11_RADIO) &&
				(pcapng_file_header['linktype'] != DLT_IEEE802_11_PPI_HDR))
				continue;
			__read_pcapng_packets(pcapng_file_header, bitness, if_tsresol, blocks, i);
		}
	}
}

function __read_pcapng_packets(pcapng_file_header, bitness, if_tsresol, blocks, i) {
	while (true) {
		if (i + 1 > blocks.length - 1)
			break
		i += 1;
		var header_block = blocks[i];
		if (header_block['block_type'] == Enhanced_Packet_Block) {
			void(0);
		} else if (header_block['block_type'] == Custom_Block) {
			var ret;
			var name, data, options;
			ret = __read_custom_block(header_block['block_body'], bitness);
			namee = ret[0];
			data = ret[1];
			options = ret[2];
			if (name == 'hcxdumptool')
				DB_pcapng_info_add('hcxdumptool', options);
			continue;
		} else if (header_block['block_type'] == Section_Header_Block) {
			__Seek(__Tell() - header_block['block_length']);
			break;
		} else {
			continue;
		}
		var header = {};
		var timestamp = (bigInt(header_block['block_body'][8]).or(
			(bigInt(header_block['block_body'][9]).shiftLeft(8)).shiftRight(0)).or(
			(bigInt(header_block['block_body'][10]).shiftLeft(16)).shiftRight(0)).or(
			(bigInt(header_block['block_body'][11]).shiftLeft(24)).shiftRight(0)).or(
			(bigInt(header_block['block_body'][4]).shiftLeft(32)).shiftRight(0)).or(
			(bigInt(header_block['block_body'][5]).shiftLeft(40)).shiftRight(0)).or(
			(bigInt(header_block['block_body'][6]).shiftLeft(48)).shiftRight(0)).or(
			(bigInt(header_block['block_body'][7]).shiftLeft(56)).shiftRight(0))).shiftRight(0);
		header['caplen'] = GetUint32(header_block['block_body'].slice(12, 16));
		header['len'] = GetUint32(header_block['block_body'].slice(16, 20));
		if (BIG_ENDIAN_HOST) {
			timestamp = byte_swap_64(timestamp);
			header['caplen'] = byte_swap_32(header['caplen']);
			header['len'] = byte_swap_32(header['len']);
		}
		if (bitness) {
			timestamp = byte_swap_64(timestamp);
			header['caplen'] = byte_swap_32(header['caplen']);
			header['len'] = byte_swap_32(header['len']);
		}
		header['tv_sec'] = Number(timestamp.divide(1000000));
		header['tv_usec'] = Number(timestamp.divmod(1000000).remainder);
		if (header['tv_sec'] == 0 && header['tv_usec'] == 0) {
			console.log('Zero value timestamps detected');
			if (!ignore_ts)
				continue;
		}
		if (header['caplen'] >= TCPDUMP_DECODE_LEN || to_signed_32(header['caplen']) < 0) {
			console.log('Oversized packet detected');
			continue;
		}
		var packet = header_block['block_body'].slice(20, 20 + header['caplen']);
		if (pcapng_file_header['linktype'] == DLT_IEEE802_11_PRISM) {
			if (header['caplen'] < 144) {
				console.log('Could not read prism header');
				continue;
			}
			var prism_header = {
				'msgcode': GetUint32(packet.slice(0, 4)),
				'msglen': GetUint32(packet.slice(4, 8)),
				//devname
				//hosttime
				//mactime
				//channel
				//rssi
				//sq
				//signal
				//noise
				//rate
				//istx
				//frmlen
			}
			if (BIG_ENDIAN_HOST) {
				prism_header['msgcode'] = byte_swap_32(prism_header['msgcode']);
				prism_header['msglen'] = byte_swap_32(prism_header['msglen']);
			}
			if (to_signed_32(prism_header['msglen']) < 0) {
				console.log('Oversized packet detected');
				continue;
			}
			if (to_signed_32(header['caplen'] - prism_header['msglen']) < 0) {
				console.log('Oversized packet detected');
				continue;
			}
			packet = packet.slice(prism_header['msglen']);
			header['caplen'] -= prism_header['msglen'];
			header['len'] -= prism_header['msglen'];
		} else if (pcapng_file_header['linktype'] == DLT_IEEE802_11_RADIO) {
			if (header['caplen'] < 8) {
				console.log('Could not read radiotap header');
				continue;
			}
			var ieee80211_radiotap_header = {
				'it_version': packet[0],
				//it_pad
				'it_len': GetUint16(packet.slice(2, 4)),
				'it_present': GetUint32(packet.slice(4, 8)),
			}
			if (BIG_ENDIAN_HOST) {
				ieee80211_radiotap_header['it_len'] = byte_swap_16(ieee80211_radiotap_header['it_len']);
				ieee80211_radiotap_header['it_present'] = byte_swap_32(ieee80211_radiotap_header['it_present']);
			}
			if (ieee80211_radiotap_header['it_version'] != 0) {
				console.log('Invalid radiotap header');
				continue;
			}
			packet = packet.slice(ieee80211_radiotap_header['it_len']);
			header['caplen'] -= ieee80211_radiotap_header['it_len'];
			header['len'] -= ieee80211_radiotap_header['it_len'];
		} else if (pcapng_file_header['linktype'] == DLT_IEEE802_11_PPI_HDR) {
			if (header['caplen'] < 8) {
				console.log('Could not read ppi header');
				continue;
			}
			var ppi_packet_header = {
				//pph_version
				//pph_flags
				'pph_len': GetUint16(packet.slice(2, 4)),
				//pph_dlt
			}
			if (BIG_ENDIAN_HOST)
				ppi_packet_header['pph_len'] = byte_swap_16(ppi_packet_header['pph_len']);
			packet = packet.slice(ppi_packet_header['pph_len']);
			header['caplen'] -= ppi_packet_header['pph_len'];
			header['len'] -= ppi_packet_header['pph_len'];
		}
		__process_packet(packet, header);
	}
}

function __build() {
	var tmp_tobeadded, tmp_key;
	if (Object.keys(DB.essids).length === 0) {
		console.log('No Networks found');
		return;
	}
	for (var essid_key in DB.essids) {
		var essid = DB.essids[essid_key];
		tmp_tobeadded = {};
		var excpkts_AP_ = DB.excpkts[essid['bssid']];
		if (!excpkts_AP_)
			continue;
		for (var excpkts_AP_STA_key in excpkts_AP_) {
			var excpkts_AP_STA_ = excpkts_AP_[excpkts_AP_STA_key];
			var excpkts_AP_STA_ap = excpkts_AP_STA_['ap'];
			if (!excpkts_AP_STA_ap)
				continue;
			for (var excpkt_ap_key in excpkts_AP_STA_ap) {
				var excpkt_ap = excpkts_AP_STA_ap[excpkt_ap_key];
				var excpkts_AP_STA_sta = excpkts_AP_STA_['sta'];
				if (!excpkts_AP_STA_sta)
					continue;
				for (var excpkt_sta_key in excpkts_AP_STA_sta) {
					var excpkt_sta = excpkts_AP_STA_sta[excpkt_sta_key];
					if (excpkt_ap['replay_counter'] != excpkt_sta['replay_counter'])
						continue
					if (excpkt_ap['excpkt_num'] < excpkt_sta['excpkt_num']) {
						if (excpkt_ap['tv_abs'] > excpkt_sta['tv_abs'])
							continue;
						if ((excpkt_ap['tv_abs'] + (EAPOL_TTL * 1000 * 1000)) < excpkt_sta['tv_abs'])
							continue;
					} else {
						if (excpkt_sta['tv_abs'] > excpkt_ap['tv_abs'])
							continue;
						if ((excpkt_sta['tv_abs'] + (EAPOL_TTL * 1000 * 1000)) < excpkt_ap['tv_abs'])
							continue;
					}
					var message_pair = 255;
					if ((excpkt_ap['excpkt_num'] == EXC_PKT_NUM_1) && (excpkt_sta['excpkt_num'] == EXC_PKT_NUM_2)) {
						if (excpkt_sta['eapol_len'] > 0) {
							message_pair = MESSAGE_PAIR_M12E2;
						} else {
							continue;
						}
					} else if ((excpkt_ap['excpkt_num'] == EXC_PKT_NUM_1) && (excpkt_sta['excpkt_num'] == EXC_PKT_NUM_4)) {
						if (excpkt_sta['eapol_len'] > 0) {
							message_pair = MESSAGE_PAIR_M14E4;
						} else {
							continue;
						}
					} else if ((excpkt_ap['excpkt_num'] == EXC_PKT_NUM_3) && (excpkt_sta['excpkt_num'] == EXC_PKT_NUM_2)) {
						if (excpkt_sta['eapol_len'] > 0) {
							message_pair = MESSAGE_PAIR_M32E2;
						} else if (excpkt_ap['eapol_len'] > 0) {
							message_pair = MESSAGE_PAIR_M32E3;
						} else {
							continue;
						}
					} else if ((excpkt_ap['excpkt_num'] == EXC_PKT_NUM_3) && (excpkt_sta['excpkt_num'] == EXC_PKT_NUM_4)) {
						if (excpkt_ap['eapol_len'] > 0) {
							message_pair = MESSAGE_PAIR_M34E3;
						} else if (excpkt_sta['eapol_len'] > 0) {
							message_pair = MESSAGE_PAIR_M34E4;
						} else {
							continue;
						}
					} else {
						console.log('BUG AP:' + excpkt_ap['excpkt_num'] + ' STA:' + excpkt_ap['excpkt_num']);
					}
					var auth = 1;
					if (message_pair == MESSAGE_PAIR_M32E3 || message_pair == MESSAGE_PAIR_M34E3)
						continue;
					if (message_pair == MESSAGE_PAIR_M12E2) {
						auth = 0;
						/* HCXDUMPTOOL (AP-LESS) */
						var check_1, check_2;
						if (DB.pcapng_info['hcxdumptool']) {
							check_1 = false;
							check_2 = false;
							DB.pcapng_info['hcxdumptool'].some(function(pcapng_info) {
								if (pcapng_info['code'] == HCXDUMPTOOL_OPTIONCODE_RC) {
									if (excpkt_ap['replay_counter'] == pcapng_info['value'])
										check_1 = true;
								} else if (pcapng_info['code'] == HCXDUMPTOOL_OPTIONCODE_ANONCE) {
									if (excpkt_ap['nonce'].toString() == pcapng_info['value'].toString())
										check_2 = true;
								}
								if (check_1 && check_2) {
									message_pair = (message_pair | MESSAGE_PAIR_APLESS) >>> 0;
									return true;
								}
							}, this);
						}
						/* ##################### */
					}
					/* LE/BE/NC */
					for (var excpkt_ap_k_key in excpkts_AP_STA_ap) {
						var excpkt_ap_k = excpkts_AP_STA_ap[excpkt_ap_k_key];
						if ((excpkt_ap['nonce'].slice(0, 28).toString() == excpkt_ap_k['nonce'].slice(0, 28).toString()) && (excpkt_ap['nonce'].slice(28).toString() != excpkt_ap_k['nonce'].slice(28).toString())) {
							message_pair = (message_pair | MESSAGE_PAIR_NC) >>> 0;
							if (excpkt_ap['nonce'][31] != excpkt_ap_k['nonce'][31]) {
								message_pair = (message_pair | MESSAGE_PAIR_LE) >>> 0;
							} else if (excpkt_ap['nonce'][28] != excpkt_ap_k['nonce'][28]) {
								message_pair = (message_pair | MESSAGE_PAIR_BE) >>> 0;
							}
						}
					}
					for (var excpkt_sta_k_key in excpkts_AP_STA_sta) {
						var excpkt_sta_k = excpkts_AP_STA_sta[excpkt_sta_k_key];
						if ((excpkt_sta['nonce'].slice(0, 28).toString() == excpkt_sta_k['nonce'].slice(0, 28).toString()) && (excpkt_sta['nonce'].slice(28).toString() != excpkt_sta_k['nonce'].slice(28).toString())) {
							message_pair = (message_pair | MESSAGE_PAIR_NC) >>> 0;
							if (excpkt_sta['nonce'][31] != excpkt_sta_k['nonce'][31]) {
								message_pair = (message_pair | MESSAGE_PAIR_LE) >>> 0;
							} else if (excpkt_sta['nonce'][28] != excpkt_sta_k['nonce'][28]) {
								message_pair = (message_pair | MESSAGE_PAIR_BE) >>> 0;
							}
						}
					}
					if (auth == 0) {
						if (!export_unauthenticated)
							continue;
					}
					var data = {}
					data['message_pair'] = message_pair;
					data['essid_len'] = essid['essid_len'];
					data['essid'] = essid['essid'];
					data['mac_ap'] = excpkt_ap['mac_ap'];
					data['nonce_ap'] = excpkt_ap['nonce'];
					data['mac_sta'] = excpkt_sta['mac_sta'];
					data['nonce_sta'] = excpkt_sta['nonce'];
					if (excpkt_sta['eapol_len'] > 0) {
						data['keyver'] = excpkt_sta['keyver'];
						data['keymic'] = excpkt_sta['keymic'];
						data['eapol_len'] = excpkt_sta['eapol_len'];
						data['eapol'] = excpkt_sta['eapol'];
					} else {
						data['keyver'] = excpkt_ap['keyver'];
						data['keymic'] = excpkt_ap['keymic'];
						data['eapol_len'] = excpkt_ap['eapol_len'];
						data['eapol'] = excpkt_ap['eapol'];
					}
					tmp_key = Math.abs(excpkt_ap['tv_abs'] - excpkt_sta['tv_abs']);
					while (tmp_tobeadded[tmp_key])
						tmp_key += 0.0001;
					tmp_key = Number(tmp_key.toFixed(4));
					tmp_tobeadded[tmp_key] = [HCWPAX_SIGNATURE, "02", data['keymic'], data['mac_ap'], data['mac_sta'], data['essid'].slice(0, data['essid_len']), data['nonce_ap'], data['eapol'].slice(0, data['eapol_len']), data['message_pair']];
				}
			}
		}
		for (var pmkdid_key in DB.pmkids) {
			var pmkid = DB.pmkids[pmkdid_key];
			if (pmkid['mac_ap'].toString() == essid['bssid'].toString()) {
				if (ignore_ie === true || [AK_PSK, AK_PSKSHA256, AK_SAFE].includes(pmkid['akm'])) {
					tmp_key = 0;
					while (tmp_tobeadded[tmp_key])
						tmp_key += 0.0001;
					tmp_key = Number(tmp_key.toFixed(4));
					tmp_tobeadded[tmp_key] = [HCWPAX_SIGNATURE, "01", pmkid['pmkid'], pmkid['mac_ap'], pmkid['mac_sta'], essid['essid'].slice(0, essid['essid_len']), '', '', ''];
				}
			}
		}
		var tmp_tobeadded_length = Object.keys(tmp_tobeadded).length;
		if (tmp_tobeadded_length === 0) {
			console.log(hex(essid['bssid']) + ': No eligible hs/pmkid found');
			continue;
		} else {
			console.log(hex(essid['bssid']) + ': ' + tmp_tobeadded_length + ' eligible hs/pmkid found');
			if (best_only === true) {
				var hcwpax = tmp_tobeadded[Math.min.apply(null, Object.keys(tmp_tobeadded))];
				DB_hcwpaxs_add(hcwpax[0], hcwpax[1], hcwpax[2], hcwpax[3], hcwpax[4], hcwpax[5], hcwpax[6], hcwpax[7], hcwpax[8]);
			} else {
				Object.values(tmp_tobeadded).forEach(function(hcwpax) {
					DB_hcwpaxs_add(hcwpax[0], hcwpax[1], hcwpax[2], hcwpax[3], hcwpax[4], hcwpax[5], hcwpax[6], hcwpax[7], hcwpax[8]);
				}, this);
			}
		}
	}
}

function _pcap2hcwpax() {
	var ret;
	var pcap_file_header, bitness;
	var read_pcap_file_header = __read_pcap_file_header();
	if (read_pcap_file_header == undefined) {
		console.log('Could not read pcap header');
		return;
	}
	ret = read_pcap_file_header;
	pcap_file_header = ret[0];
	bitness = ret[1];
	__read_pcap_packets(pcap_file_header, bitness);
	__build();
}

function _pcapng2hcwpax() {
	__read_pcapng_file_header_then_packets()
	__build();
}

//////////////////////////////////////////////////////////////////////////////////////

var myArgs = process.argv.slice(2);
if (myArgs.length == 1) {
	myArgs = myArgs[0].split(' ');
}
if (myArgs.length != 6) {
	console.log([
		"Usage:",
		"node" + " " + __filename.slice(__dirname.length + 1) + " " + "capture_file best_only export_unauthenticated ignore_ts ignore_ie debug",
		"low" + " " + "\"\"" + " " + __filename.slice(__dirname.length + 1) + " " + "\"capture_file best_only export_unauthenticated ignore_ts ignore_ie debug\"",
		"",
		"capture_file: string", // 0
		"best_only: bool", // 1
		"export_unauthenticated: bool", // 2
		"ignore_ts: bool", // 3
		"ignore_ie: bool", // 4
		"debug: bool", // 5
		"",
		"Examples:",
		"node" + " " + __filename.slice(__dirname.length + 1) + " " + "capture.cap true false false false false",
		"low" + " " + "\"\"" + " " + __filename.slice(__dirname.length + 1) + " " + "\"capture.cap true false false false false\"",
	].join('\n'));
	return;
}

var console_log = console.log;
var debug = myArgs[5] == "true";
console.log = function(msg, force) {
	if (debug || force)
		console_log(msg);
}

var filename = myArgs[0];
var best_only_input = myArgs[1] == "true";
var export_unauthenticated_input = myArgs[2]  == "true";
var ignore_ts_input = myArgs[3]  == "true";
var ignore_ie_input = myArgs[4]  == "true";

var fs = require('fs');
fs.readFile(filename, function(err, data) {
	if (err) {
		throw err
	}
	var bytes_input = data;
	var format_input = filename.split('.').pop().toLowerCase();
	if (format_input == "gz")
		format_input = filename.split('.').slice(-2).join('.');
	capjs(bytes_input, format_input, best_only_input, export_unauthenticated_input, ignore_ts_input, ignore_ie_input);
	Analysis();
	console.log(Getf('hcwpax'), true);
});
