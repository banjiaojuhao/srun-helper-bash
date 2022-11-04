LC_CTYPE=en_US.utf8

str2hex() {
	local str="$1" pad=${2:- 0} i str_len=${#1}
	for ((i = 0, pad /= 2; i < str_len; i++)); do printf '%02x' "'${str:i:1}"; done
	while ((pad && i++ % pad)); do echo -n '00'; done
}

hex2str() {
	local hex=$1 i hex_len str
	for ((i = 0, hex_len = ${#hex}; i < hex_len; i += 2)); do str+="\x${hex:i:2}"; done
	echo -ne "$str"
}

base64() {
    # input: hex format
	local msg=$1 msg_len=${#1} result i
    # local -r dict="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	local -r dict="LVoJPiCN2R8G90yg+hmFHuacZ1OWMnrsSTXkYpUq/3dlbfKwv6xztjI7DeBE45QA"

	while ((${#msg} % 6 != 0)); do msg+='00'; done
	for ((i = 0; i < msg_len; i += 6)); do
		result+=${dict:$((0x${msg:i:2} >> 2)):1}
		result+=${dict:$((0x${msg:i+1:2} & 0x3F)):1}
		result+=${dict:$((0x${msg:i+3:2} >> 2)):1}
		result+=${dict:$((0x${msg:i+4:2} & 0x3F)):1}
	done
	((msg_len % 6 == 2)) && result=${result:0:-2}"=="
	((msg_len % 6 == 4)) && result=${result:0:-1}"="
	echo -n "$result"
}

sha1() {
    # from https://github.com/neutronscott/bash-totp/blob/master/totp
	local msg=$1
	local h0 h1 h2 h3 h4
	local a b c d e f
	local i j temp len plen chunk w
    local m=$((0xFFFFFFFF)) #32-bit mask

	((h0 = 0x67452301, h1 = 0xEFCDAB89, h2 = 0x98BADCFE, h3 = 0x10325476, h4 = 0xC3D2E1F0))

	((len = ${#msg} << 2))
    # pad80
	msg+='80'
	while ((${#msg} % 128 != 112)); do msg+='00'; done
	printf -v msg '%s%016X' "$msg" "$len"
	plen=${#msg}

    # 512-bit chunks = 128 hex chars
	for ((i = 0; i < plen; i += 128)); do
		chunk=${msg:i:128}
		for ((j = 0, k = 0; j < 16; j++, k += 8)); do
            # convert to 32-bit int
			w[j]=$((0x${chunk:k:8}))
		done
        # extend into 80 qwords
		for ((j = 16; j < 80; j++)); do
			((w[j] = w[j - 3] ^ w[j - 8] ^ w[j - 14] ^ w[j - 16]))
            # left rotate 1 with shift
			((w[j] = (w[j] >> 31) | (w[j] << 1)))
			((w[j] &= m))
		done
		((a = h0, b = h1, c = h2, d = h3, e = h4))
		for ((j = 0; j < 80; j++)); do
			if ((j < 20)); then
				((k = 0x5A827999, f = (b & c) | (~b & d)))
			elif ((j < 40)); then
				((k = 0x6ED9EBA1, f = b ^ c ^ d))
			elif ((j < 60)); then
				((k = 0x8F1BBCDC, f = (b & c) | (b & d) | (c & d)))
			else
				((k = 0xCA62C1D6, f = b ^ c ^ d))
			fi
			((f &= m))
			((temp = ((a << 5) | (a >> 27)) + f + e + k + w[j]))
			((temp &= m))
			((e = d, d = c, c = (b >> 2) | (b << 30), b = a, a = temp))
		done
		((h0 += a, h1 += b, h2 += c, h3 += d, h4 += e))
		((h0 &= m, h1 &= m, h2 &= m, h3 &= m, h4 &= m))
	done
	printf '%08x%08x%08x%08x%08x' "$h0" "$h1" "$h2" "$h3" "$h4"
}

xencode() {
    # http://10.248.98.2/static/js/jquery.srun.portal.js?v=2.00.20190222
	local msg=$(str2hex "$1" 8) key=$(str2hex "$2" 8) v k len=${#1}

	for ((i = 0, j = 0; i < ${#msg}; i += 8)); do
		((v[j++] = 0x${msg:i:2} | 0x${msg:i+2:2} << 8 | 0x${msg:i+4:2} << 16 | 0x${msg:i+6:2} << 24))
	done
	for ((i = 0, j = 0; i < ${#key}; i += 8)); do
		((k[j++] = 0x${key:i:2} | 0x${key:i+2:2} << 8 | 0x${key:i+4:2} << 16 | 0x${key:i+6:2} << 24))
	done
	v+=($len)

	local n z y c m e p q d
	((n = ${#v[@]} - 1, z = v[n], y = v[0], d = 0, index = 0, c = 0x86014019 | 0x183639A0))

	for ((q = 6 + 52 / (n + 1); q > 0; q--)); do
		((d += c & (0x8CE0D9BF | 0x731F2640)))
		((e = d >> 2 & 3))
		for ((p = 0; p < n; p++)); do
			((y = v[p + 1]))
			((m = z >> 5 ^ y << 2))
			((m += (y >> 3 ^ z << 4) ^ (d ^ y)))
			((m += k[(p & 3) ^ e] ^ z))
			((v[p] = v[p] + m & (0xEFB8D130 | 0x10472ECF)))
			((z = v[p]))
		done
		((y = v[0]))
		((m = z >> 5 ^ y << 2))
		((m += (y >> 3 ^ z << 4) ^ (d ^ y)))
		((m += k[(n & 3) ^ e] ^ z))
		((v[n] = v[n] + m & (0xBB390742 | 0x44C6F8BD)))
		((z = v[n]))
	done

	local result=""
	for ((i = 0, len = ${#v[@]}; i < len; i++)); do
		printf -v result '%s%02x%02x%02x%02x' "$result" $((${v[$i]} & 0xFF)) $((${v[$i]} >> 8 & 0xFF)) $((${v[$i]} >> 16 & 0xFF)) $((${v[$i]} >> 24 & 0xFF))
	done

	result=$(base64 $result)
	echo -n "{SRBX1}$result"
}

urlencode() {
	for ((i = 0, len = ${#1}; i < len; i++)); do
		local c="${1:i:1}"
		case $c in
		[a-zA-Z0-9.~_-]) printf "$c" ;;
		*) printf '%%%02x' "'$c" ;;
		esac
	done
}

login() {
	local -r SRUN_USERNAME="$1"
	local -r SRUN_PASSWORD="$2"

	[ -z "$SRUN_USERNAME" ] && echo "Error: empty username" && return 1
	[ -z "$SRUN_PASSWORD" ] && echo "Error: empty password" && return 1

	local resp=$(curl "$CHALLENGE_URL?username=$SRUN_USERNAME&callback=jsonp20210505" $SRUN_INTERFACE -sSf)

	local challenge=${resp#*challenge\":*\"}
	challenge=${challenge%%\"*}
	local client_ip=${resp#*client_ip\":*\"}
	client_ip=${client_ip%%\"*}

    # echo "chanllenge=$challenge"
	echo "client_ip=$client_ip"

	local user_info='{"username":"'"$SRUN_USERNAME"'","password":"'"$SRUN_PASSWORD"'","ip":"'"$client_ip"'","acid":"1","enc_ver":"srun_bx1"}'
    # echo "user_info=$user_info"
    
    local xencode_str=$(xencode "$user_info" "$challenge")
    # echo "xencode=$xencode_str"

	local hmd5="202105055e524099e16909613a5cded6"

	local checksum="$challenge$SRUN_USERNAME$challenge$hmd5${challenge}1$challenge$client_ip${challenge}200${challenge}1$challenge$xencode_str"
    # echo "checksum=$checksum"
	checksum=$(sha1 $(str2hex "$checksum"))
    # echo "checksum=$checksum"

	local query="callback=jQuery20210505&action=login&username=$(urlencode "$SRUN_USERNAME")&password=$(urlencode {MD5}$hmd5)&ac_id=1&ip=$client_ip&chksum=$(urlencode $checksum)&info=$(urlencode $xencode_str)&n=200&type=1&os=Linux&name=Linux&double_stack=0"
    # echo "query=$query"

	resp=$(curl "$LOGIN_URL?$query" $SRUN_INTERFACE -sSf)
	[[ -n $SRUN_DEBUG ]] && echo "$resp"
	local res=${resp#*res\":*\"}
	res=${res%%\"*}


	echo "result=$res"
	if [ $res == "ok" ]; then
		local suc_msg=${resp#*suc_msg\":*\"}
		suc_msg=${suc_msg%%\"*}
		echo "suc_msg=$suc_msg"
	else
		local error_msg=${resp#*error_msg\":*\"}
		error_msg=${error_msg%%\"*}
		echo "error_msg=$error_msg"
	fi
}

logout() {
	local SRUN_USERNAME="$1"
	local CLIENT_IP="$2"

	if [ -n "$SRUN_USERNAME" ]; then
		local query="action=logout&username=${SRUN_USERNAME}mac-yx-hitg&ac_id=1&ip=$CLIENT_IP"
		[[ -n $SRUN_DEBUG ]] && echo "$LOGIN_URL?$query"
		resp=$(curl "$LOGIN_URL?$query" $SRUN_INTERFACE -sSf)
		echo $resp
	fi
}

get_user_info() {
	local -n user_name=$1

	if [ -z "$2" ]; then
		local client_ip
	else
		local -n client_ip="$2"
	fi

	local resp=$(curl "$STATE_URL?callback=jsonp20210505" $SRUN_INTERFACE -sSf)
	[[ -n $SRUN_DEBUG ]] && echo "get_user_info_resp=$resp"

	local client_ip=${resp#*online_ip\":*\"}
	client_ip=${client_ip%%\"*}

	local error=${resp#*error\":*\"}
	error=${error%%\"*}

	user_name=${resp#*user_name\":*\"}
	user_name=${user_name%%\"*}

	echo "client_ip=$client_ip"
	if [ $error == "not_online_error" ]; then
		echo "you are not online"
		user_name=""
	else
		echo "user_name=$user_name"
	fi
}

help() {
	echo "Usage: 
    Connect network:
        bash srun-helper.sh login --username '3321S150000' --password 'pwd_xxx'
    Disconnect network:
        bash srun-helper.sh logout
    Show this help message:
        bash srun-helper.sh help
    Show network state:
        bash srun-helper.sh
    Optional environments:
        SRUN_INTERFACE: Bind to the interface when send web requests.(default empty)
        SRUN_HOST: IP of authentication page. (default 10.248.98.2)"
}

[ -z $(which curl) ] && echo "Error: curl not found" && exit 1

[ -z "$SRUN_HOST" ] && SRUN_HOST='10.248.98.2'
[ -n "$SRUN_INTERFACE" ] && SRUN_INTERFACE="--interface $SRUN_INTERFACE"
STATE_URL="http://$SRUN_HOST/cgi-bin/rad_user_info"
CHALLENGE_URL="http://$SRUN_HOST/cgi-bin/get_challenge"
LOGIN_URL="http://$SRUN_HOST/cgi-bin/srun_portal"

ACTION=""
while ((${#@} > 0)); do
	case "$1" in
	"--username" | "-u")
		shift
		SRUN_USERNAME="$1"
		;;
	"--password" | "-p")
		shift
		SRUN_PASSWORD="$1"
		;;
	"--verbose" | "-v")
		shift
		SRUN_DEBUG="1"
		;;
	"login") ACTION="login" ;;
	"logout") ACTION="logout" ;;
	"help" | "--help" | "-h") ACTION="help" ;;
	*)
		echo "unknown option: $1"
		ACTION="help"
		;;
	esac
	shift
done

case $ACTION in
"login") login "$SRUN_USERNAME" "$SRUN_PASSWORD" ;;
"logout")
    declare _CLIENT_IP
	get_user_info SRUN_USERNAME _CLIENT_IP
	logout "$SRUN_USERNAME" "$_CLIENT_IP"
	;;
"")
	get_user_info SRUN_USERNAME
	help
	;;
"help") help ;;
esac

[ $? != 0 ] && help

# ~/shfmt_v3.5.1_linux_amd64 -mn srun-helper-bash.sh > srun-helper.sh
