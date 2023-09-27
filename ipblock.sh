#!/bin/sh
# Version: 0.99

# put this script in your path
# ex: /opt/usr/bin/ipblock.sh

# modify to specfy config / blocklist dir
BLOCKLIST_DIR=/opt/etc/ipblock

BLOCKLIST_URLS=${BLOCKLIST_DIR}/ipblock.urls 
BLOCKLIST_ALLOW=${BLOCKLIST_DIR}/ipblock.allow
BLOCKLIST_DENY=${BLOCKLIST_DIR}/ipblock.deny
BLOCKLIST_GIT=https://raw.githubusercontent.com/codekow/simple-ipblock/main
BLOCKLIST_FILE=/tmp/block.list

SCRIPT=$0
LOG_PREFIX="BLOCKED "
IPSET_MAX=65535
DROP_TARGET=BLOCKDROP
PREFIX=block-

send_log(){
  echo "$@" | logger -s -t "$SCRIPT"
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

init() {

  [ ! -d ${BLOCKLIST_DIR} ] \
    && mkdir -p ${BLOCKLIST_DIR}

  [ ! -s ${BLOCKLIST_URLS} ] \
    && wget "${BLOCKLIST_GIT}/cfg/$(basename ${BLOCKLIST_URLS})" -qO ${BLOCKLIST_URLS}

  [ ! -s ${BLOCKLIST_ALLOW} ] \
    && wget "${BLOCKLIST_GIT}/cfg/$(basename ${BLOCKLIST_ALLOW})" -qO ${BLOCKLIST_ALLOW}

  [ ! -s ${BLOCKLIST_DENY} ] \
    && wget "${BLOCKLIST_GIT}/cfg/$(basename ${BLOCKLIST_DENY})" -qO ${BLOCKLIST_DENY}

  create_drop_chain ${DROP_TARGET}
  create_chain BLOCKED
  create_jump BLOCKED

  init_ipset
}

create_jump(){
  CHAIN_NAME=$1
  JUMP="PREROUTING -i eth0 -p tcp -m multiport --dports ${PORTS} -j ${CHAIN_NAME}"

  iptables -t raw -D ${JUMP}
  iptables -t raw -I ${JUMP}

}

create_chain() {
  CHAIN_NAME=$1

  # setup logging drop chain
  iptables -t raw -N "${CHAIN_NAME}"
  iptables -t raw -F "${CHAIN_NAME}"
}

create_drop_chain() {
  CHAIN_NAME=$1

  create_chain $1

  iptables -t raw -A "${CHAIN_NAME}" \
    -m limit \
    --limit 1/min \
    -j LOG \
    --log-prefix "${LOG_PREFIX}" \
    --log-tcp-sequence \
    --log-tcp-options \
    --log-ip-options

  iptables -t raw -A "${CHAIN_NAME}" \
	 -j DROP
}

ipset_all_cidr() {
  [ -t 1 ] && send_log "setup CIDR ipset"
  IPSET_FILE=${BLOCKLIST_FILE}
  IPSET_NAME=${PREFIX}CIDR
  CHAIN_TARGET=${DROP_TARGET}

  ipset -q ${CREATE} ${IPSET_NAME} ${NETHASH}
  ipset -q ${DESTROY} ${PREFIX}.tmp

  (echo "${CREATE} ${PREFIX}.tmp ${NETHASH}"
  sed -n "/\//s/^/$ADD ${PREFIX}.tmp /p" ${IPSET_FILE}
  echo "COMMIT") | nice -n 15 ipset ${RESTORE} && ipset ${SWAP} ${PREFIX}.tmp ${IPSET_NAME}
  iptables -t raw -nL PREROUTING | grep -q ${IPSET_NAME} || iptables -t raw -I PREROUTING -m set ${MATCH_SET} ${IPSET_NAME} src -j ${CHAIN_TARGET}
}

ipset_all_ip() {
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
  sed -n "/\//!p" ${BLOCKLIST_FILE} | sed -n "$(((( setCount - 1) * IPSET_MAX) + 1)),$(( setCount * IPSET_MAX )) s/^/$ADD ${PREFIX}.tmp /p"
  echo "COMMIT") | nice -n 15 ipset ${RESTORE} && ipset ${SWAP} ${PREFIX}.tmp ${PREFIX}IP${setCount}

  iptables -t raw -nL PREROUTING | grep -q ${PREFIX}IP${setCount} || iptables -t raw -I PREROUTING -m set ${MATCH_SET} ${PREFIX}IP${setCount} src -j ${DROP_TARGET}

  msg="$msg ${PREFIX}IP${setCount} (( $(ipset -L ${PREFIX}IP${setCount} | wc -l) - ${ESL}))"
  setCount=$((setCount+1))

  done
}

clean_iptables() {
  [ -t 1 ] && send_log "clean iptables"

  for SRC in $(iptables -nL PREROUTING -t raw | sed -n "/match-set/ s/.* \(${PREFIX}.*\) .*/\1/p")
do
  send_log "removing ipset / iptables SRC for ${SRC}"
  ipset -q "${SWAP}" "${SRC}" "${SRC}" && \
    iptables -t raw \
      -D PREROUTING \
      -m set ${MATCH_SET} "${SRC}" src \
      -j ${DROP_TARGET} && ipset ${DESTROY} "${SRC}"
done
}

get_lists() {
  [ -t 1 ] && send_log "get list"

  ( (while read -r url
  do
    nice -n 15 wget "$url" -qO-
  done <${BLOCKLIST_URLS} ); [ -s ${BLOCKLIST_DENY} ] && cat ${BLOCKLIST_DENY}) | \
    nice -n 15 sed -n "s/\r//;s/#.*$//;/^$/d;/^[0-9,\.,\/]*$/p" | \
    nice -n 15 grep -vf ${BLOCKLIST_ALLOW} | \
    nice -n 15 awk '!a[$0]++' > ${BLOCKLIST_FILE}
}

cleanup() {
  [ -t 1 ] && send_log "cleanup"
  ipset ${DESTROY} ${PREFIX}.tmp
  rm ${BLOCKLIST_FILE}
}

main() {
  send_log "Begin Processing"

  get_lists

  clean_iptables

  ipset_all_ip
  ipset_all_cidr

  cleanup

  send_log "End Processing"
}

[ "$1" = "clean" ] && \
  init_ipset && \
  clean_iptables && \
  exit 0

init || cleanup
main
