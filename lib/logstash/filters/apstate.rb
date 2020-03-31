# encoding:utf-8

require "logstash/filters/base"
require "logstash/namespace"
require "json"
require "dalli"

class LogStash::Filters::Apstate < LogStash::Filters::Base

  config_name "apstate"

  #Constants
  #Common
  CLIENT_MAC="client_mac"
  WIRELESS_STATION="wireless_station"     #msg sensor
  WIRELESS_ID="wireless_id"               #msg sensor
  SRC_IP="src_ip"
  SENSOR_IP="sensor_ip"                   #msg sensor
  DST_IP="dst_ip"
  SENSOR_NAME="sensor_name"               #msg sensor
  CLIENT_LATLNG="client_latlong" 
  CLIENT_PROFILE="client_profile"
  CLIENT_RSSI="client_rssi"
  CLIENT_RSSI_NUM="client_rssi_num"
  CLIENT_SNR="client_snr"
  CLIENT_SNR_NUM="client_snr_num"
  TIMESTAMP="timestamp"                     #msg sensor
  FIRST_SWITCHED="first_switched"
  DURATION="duration"
  PKTS="pkts"
  BYTES="bytes"
  TYPE="type"
  SRC_VLAN="src_vlan"
  DST_VLAN="dst_vlan"
  WAN_VLAN="wan_vlan"
  LAN_VLAN="lan_vlan"
  CLIENT_MAC_VENDOR="client_mac_vendor"
  CLIENT_ID="client_id"
  SRC_AS_NAME="src_as_name"
  SRC_AS="src_as"
  LAN_IP_AS_NAME="lan_ip_as_name"
  SRC_PORT="src_port"
  LAN_L4_PORT="lan_l4_port"
  SRC_MAP="src_map"
  SRV_PORT="srv_port"
  DST_AS_NAME="dst_as_name"
  WAN_IP_AS_NAME="wan_ip_as_name"
  DST_PORT="dst_port"
  WAN_L4_PORT="wan_l4_port"
  DST_MAP="dst_map"
  DST_AS="dst_as"
  ZONE_UUID="zone_uuid"
  APPLICATION_ID_NAME="application_id_name"
  BIFLOW_DIRECTION="biflow_direction"
  CONVERSATION="conversation"
  DIRECTION="direction"
  ENGINE_ID_NAME="engine_id_name"
  HTTP_HOST="host"
  HTTP_SOCIAL_MEDIA="http_social_media"
  HTTP_SOCIAL_USER="http_social_user"
  HTTP_USER_AGENT_OS="http_user_agent"
  HTTP_REFER_L1="referer"
  IP_PROTOCOL_VERSION="ip_protocol_version"
  L4_PROTO="l4_proto"
  LAN_IP_NET_NAME="lan_ip_net_name"
  SRC_NET_NAME="src_net_name"
  WAN_IP_NET_NAME="wan_ip_net_name"
  DST_NET_NAME="dst_net_name"
  TOS="tos"
  DST_COUNTRY_CODE="dst_country_code"
  WAN_IP_COUNTRY_CODE="wan_ip_country_code"
  SRC_COUNTRY_CODE="src_country_code"
  SRC_COUNTRY="src_country"
  DST_COUNTRY="dst_country"
  LAN_IP_COUNTRY_CODE="lan_ip_country_code"
  SCATTERPLOT="scatterplot"
  INPUT_SNMP="lan_interface_name"
  OUTPUT_SNMP="wan_interface_name"
  INPUT_VRF="input_vrf"
  OUTPUT_VRF="output_vrf"
  SERVICE_PROVIDER="service_provider"             #msg sensor
  SERVICE_PROVIDER_UUID="service_provider_uuid"   #msg sensor 
  SRC="src"
  LAN_IP="lan_ip"
  PUBLIC_IP="public_ip"
  IP_COUNTRY_CODE="ip_country_code"
  IP_AS_NAME="ip_as_name"

  BUILDING="building"
  BUILDING_UUID="building_uuid"
  CAMPUS="campus"
  CAMPUS_UUID="campus_uuid"
  FLOOR="floor"
  FLOOR_UUID="floor_uuid"
  ZONE="zone"

  COORDINATES_MAP="coordinates_map"
  HNBLOCATION="hnblocation"
  HNBGEOLOCATION="hnbgeolocation"
  RAT="rat"
  DOT11PROTOCOL="dot11_protocol"
  DEPLOYMENT="deployment"
  DEPLOYMENT_UUID="deployment_uuid"
  NAMESPACE="namespace"                 #Msg Sensor
  NAMESPACE_UUID="namespace_uuid"       #Msg sensor
  TIER="tier"
  MSG="msg"
  HTTPS_COMMON_NAME="https_common_name"
  TARGET_NAME="target_name"

  CLIENT_FULLNAME="client_fullname"
  PRODUCT_NAME="product_name"

  URL="url"
  FILE_NAME="file_name"
  EMAIL_SENDER="email_sender"
  EMAIL_DESTINATION="email_destination"
  EMAIL_ID="email_id"

  #Event
  ACTION="action"
  CLASSIFICATION="classification"
  DOMAIN_NAME="domain_name"
  ETHLENGTH_RANGE="ethlength_range"
  GROUP_NAME="group_name"
  SIG_GENERATOR="sig_generator"
  ICMPTYPE="icmptype"
  IPLEN_RANGE="iplen_range"
  REV="rev"
  SENSOR_UUID="sensor_uuid"
  PRIORITY="priority"
  SIG_ID="sig_id"
  ETHSRC="ethsrc"
  ETHSRC_VENDOR="ethsrc_vendor"
  ETHDST="ethdst"
  ETHDST_VENDOR="ethdst_vendor"
  DST="dst"
  WAN_IP="wan_ip"
  TTL="ttl"
  VLAN="vlan"
  MARKET="market"
  MARKET_UUID="market_uuid"
  ORGANIZATION="organization"
  ORGANIZATION_UUID="organization_uuid"
  CLIENT_LATLONG="client_latlong"
  FILE_SIZE="file_size"
  FILE_URI="file_uri"
  FILE_HOSTNAME="file_hostname"
  GROUP_UUID="group_uuid"
  CLIENT_NAME="client_name"

  #State
  WIRELESS_CHANNEL="wireless_channel"
  WIRELESS_TX_POWER="wireless_tx_power"
  WIRELESS_ADMIN_STATE="wireless_admin_state"
  WIRELESS_OP_STATE="wireless_op_state"
  WIRELESS_MODE="wireless_mode"
  WIRELESS_SLOT="wireless_slot"
  WIRELESS_STATION_IP="wireless_station_ip"
  STATUS="status"
  WIRELESS_STATION_NAME="wireless_station_name"

  #Custom
  DATASOURCE = "rb_state"
  COUNTER_STORE = "counterStore"
  FLOWS_NUMBER = "flowsNumber"
  #endofConstants

  public
  
  def set_stores
    @store = Hash.new if @store.nil?
  end

  def register
    @store = {}
    options = {:expires_in => 0}
    @memcached = Dalli::Client.new("localhost:11211", options)
    set_stores
  end

  def filter(event)

    namespace = event.get(NAMESPACE_UUID)
    datasource = (namespace) ? DATASOURCE + "_" + namespace : DATASOURCE

    counterStore = @memcached.get(COUNTER_STORE)
    counterStore = Hash.new if counterStore.nil?
    counterStore[datasource] = counterStore[datasource].nil? ? 0 : (counterStore[datasource]+1)
    @memcached.set(COUNTER_STORE,counterStore)

    flowsNumber = @memcached.get(FLOWS_NUMBER)
    flowsNumber = Hash.new if flowsNumber.nil?
    flows = flowsNumber[datasource]
    if (!flows.nil?) then
      event.set("flows_count", flows)
    end

    filter_matched(event)
  end  # def filter

end    # classLogstash::Filter::Apstate
