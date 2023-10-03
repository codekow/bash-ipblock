#!/bin/sh
# Version: 0.99

# put this script in your path
# ex: /opt/usr/bin/ipblock.sh

# modify to specfy config / blocklist dir
BLOCKLIST_DIR=/opt/etc/ipblock
BLOCKLIST_GIT=https://raw.githubusercontent.com/codekow/simple-ipblock/dev
BLOCKLIST_FILE=00-aggregated.zone

ZONE_URL=https://www.ipdeny.com/ipblocks/data/aggregated
ZONE_DENY="cn tw in ru br ar bg cz ca"
ZONE_ALLOW="us"
PORTS="22,80,443"

# no vars to modify below this line

SCRIPT=$0
LOG_PREFIX="BLOCKED "
IPSET_MAX=65535
DROP_TARGET=BLOCK
PREFIX=block-
JUMP="PREROUTING -i eth0 -p tcp -m multiport --dports ${PORTS} -j ${DROP_TARGET}"

TMP_DIR=$(mktemp -d -t ipblock.XXXX)

send_log(){
  echo "$@" | logger -s -t "$SCRIPT"
}

setup_dir(){
  mkdir -p ${BLOCKLIST_DIR} > /dev/null 2>&1 || BLOCKLIST_DIR="./ipblock" 

  BLOCKLIST_URLS=${BLOCKLIST_DIR}/ipblock.urls 
  BLOCKLIST_ALLOW=${BLOCKLIST_DIR}/ipblock.allow
  BLOCKLIST_DENY=${BLOCKLIST_DIR}/ipblock.deny

  [ ! -d ${BLOCKLIST_DIR} ] \
    && mkdir -p ${BLOCKLIST_DIR}

  [ ! -s ${BLOCKLIST_URLS} ] \
    && curl -sL "${BLOCKLIST_GIT}/cfg/$(basename ${BLOCKLIST_URLS})" -o ${BLOCKLIST_URLS}

  [ ! -s ${BLOCKLIST_ALLOW} ] \
    && curl -sL "${BLOCKLIST_GIT}/cfg/$(basename ${BLOCKLIST_ALLOW})" -o ${BLOCKLIST_ALLOW}

  [ ! -s ${BLOCKLIST_DENY} ] \
    && curl -sL "${BLOCKLIST_GIT}/cfg/$(basename ${BLOCKLIST_DENY})" -o ${BLOCKLIST_DENY}

  cd "${TMP_DIR}"
}

check_root(){
  if [ "$(id -u)" != "0" ]; then
    echo "This script is intended to be run as root"
  fi
}

init_ipset(){
  case $(ipset -v | grep -o "v[4,6,7]") in

  v[6,7])
    MATCH_SET='--match-set'
    CREATE='n'
    DESTROY='destroy'
    RESTORE='restore'
    ADD='add'
    SWAP='swap'
    IPHASH='hash:ip'
    NETHASH='hash:net'
    ESL=7
    lsmod | grep -q "xt_set" || for module in ip_set ip_set_hash_net ip_set_hash_ip xt_set
      do modprobe $module
      done
    ;;

  v4)
    MATCH_SET='--set'
    CREATE='-N'
    DESTROY='--destroy'
    RESTORE='--restore'
    ADD='-A'
    SWAP='--swap'
    IPHASH='iphash'
    NETHASH='nethash'
    ESL=6
    lsmod | grep -q "ipt_set" || for module in ip_set ip_set_nethash ip_set_iphash ipt_set
      do modprobe $module
      done
    ;;

  *) send_log "Unknown ipset version. Exiting." && exit 1
    ;;

  esac
}

create_jump(){
  iptables -t raw -I ${JUMP}
}

create_chain(){
  CHAIN_NAME=$1

  iptables -t raw -N "${CHAIN_NAME}"
  iptables -t raw -A "${CHAIN_NAME}" \
    -m limit \
    --limit 1/min \
    -j LOG \
    --log-prefix "${LOG_PREFIX}" \
    --log-tcp-sequence \
    --log-tcp-options \
    --log-ip-options
  iptables -t raw -A "${CHAIN_NAME}" -j DROP
}

get_countries(){

  for country in  ${ZONE_ALLOW} ${ZONE_DENY}
  do
    curl -sL "${ZONE_URL}/${country}-aggregated.zone" -O
  done

  for file in *.zone
  do
    name=${file%-aggregated.zone}
    echo "name: $name"
    echo "file: $file"

    ipset destroy $name.zone
    ipset create $name.zone hash:net

    for IP in $(cat $file)
    do
      ipset add $name.zone $IP
    done

    if echo $name | grep -q ${ZONE_ALLOW}; then
      iptables -t raw -I ${DROP_TARGET} -m set --match-set $name.zone src -j RETURN
    else
      iptables -t raw -I ${DROP_TARGET} -m set --match-set $name.zone src -j DROP
    fi

  done

  # curl -sL "${ZONE_URL}/MD5SUM" -o md5sum
  # md5sum -c md5sum 2>/dev/null | grep OK
}

get_lists(){
  [ -t 1 ] && send_log "get list"

  ( (while read -r url
  do
    nice -n 15 curl "$url" -sL
  done <${BLOCKLIST_URLS} ); [ -s ${BLOCKLIST_DENY} ] && cat ${BLOCKLIST_DENY}) | \
    nice -n 15 sed -n "s/\r//;s/#.*$//;/^$/d;/^[0-9,\.,\/]*$/p" | \
    nice -n 15 grep -vf ${BLOCKLIST_ALLOW} | \
    nice -n 15 awk '!a[$0]++' > ${BLOCKLIST_FILE}
}

init(){
  
  setup_dir

  check_root
  clean_iptables
  init_ipset
  load_ipset

  create_chain "${DROP_TARGET}"
  create_jump "${DROP_TARGET}"
}

ipset_all_cidr(){
  [ -t 1 ] && send_log "setup CIDR ipset"
  IPSET_FILE=${BLOCKLIST_FILE}
  IPSET_NAME=${PREFIX}CIDR
  CHAIN_TARGET=${DROP_TARGET}

  ipset -q ${CREATE} ${IPSET_NAME} ${NETHASH}
  ipset -q ${DESTROY} ${PREFIX}.tmp

  (echo "${CREATE} ${PREFIX}.tmp ${NETHASH}"
  sed -n "/\//s/^/$ADD ${PREFIX}.tmp /p" ${IPSET_FILE}
  echo "COMMIT") | nice -n 15 ipset ${RESTORE} && ipset ${SWAP} ${PREFIX}.tmp ${IPSET_NAME}
  iptables -t raw -nL ${DROP_TARGET} | grep -q ${IPSET_NAME} || \
    iptables -t raw -I ${DROP_TARGET} \
    -m set ${MATCH_SET} ${IPSET_NAME} src \
    -j DROP
}

ipset_all_ip(){
  [ -t 1 ] && send_log "setup IPs ipset"
  
  listCount=$(wc -l <${BLOCKLIST_FILE})
  cidrCount=$(grep -c "/" ${BLOCKLIST_FILE} )
  ipCount=$(( listCount - cidrCount ))
  maxSet=$((( ipCount / IPSET_MAX ) + 1))
  setCount=1

  send_log "Total:$listCount IPS:$ipCount NETS:$cidrCount"

  while [ $setCount -le $maxSet ]
  do 
    send_log "adding rule for ${PREFIX}IP${setCount}..."

    ipset -q ${CREATE} ${PREFIX}IP${setCount} ${IPHASH}
    ipset -q ${DESTROY} ${PREFIX}.tmp

    (echo "${CREATE} ${PREFIX}.tmp ${IPHASH}"
    sed -n "/\//!p" ${BLOCKLIST_FILE} | \
      sed -n "$(((( setCount - 1) * IPSET_MAX) + 1)),$(( setCount * IPSET_MAX )) s/^/$ADD ${PREFIX}.tmp /p"
    echo "COMMIT") | nice -n 15 ipset ${RESTORE} && \
      ipset ${SWAP} ${PREFIX}.tmp ${PREFIX}IP${setCount}

    iptables -t raw -nL ${DROP_TARGET} | grep -q ${PREFIX}IP${setCount} || \
      iptables -t raw -I ${DROP_TARGET} -m set ${MATCH_SET} ${PREFIX}IP${setCount} src -j DROP

    msg="$msg ${PREFIX}IP${setCount} (( $(ipset -L ${PREFIX}IP${setCount} | wc -l) - ${ESL}))"
    setCount=$((setCount+1))

  done
}

clean_iptables(){
  [ -t 1 ] && send_log "clean iptables"

  iptables -t raw -D ${JUMP}

  iptables -t raw -F "${DROP_TARGET}"
  iptables -t raw -X "${DROP_TARGET}"
}

cleanup(){
  [ -t 1 ] && send_log "cleanup"
  ipset ${DESTROY} ${PREFIX}.tmp
  cd /tmp
  # rm -rf ${TMP_DIR}
}

main(){
  send_log "Begin Processing"

  get_lists
  get_countries

  ipset_all_ip
  ipset_all_cidr

  send_log "End Processing"
}

set -x
if [ "$1" = "clean" ]; then
  clean_iptables
  load_ipset
  exit 0
fi

init || cleanup
main
