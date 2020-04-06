# encoding:utf-8

require "logstash/filters/base"
require "logstash/namespace"
require "json"
require "time"
require "dalli"
require "yaml"

require_relative "util/location_constant"
require_relative "util/memcached_config"
require_relative "store/store_manager"



class LogStash::Filters::Apstate < LogStash::Filters::Base
  include LocationConstant

  config_name "apstate"

  config :memcached_server, :validate => :string, :default => "", :required => false

  #Custom
  DATASOURCE = "rb_state"

  public

  def register
    @memcached_server = MemcachedConfig::servers.first if @memcached_server.empty?
    @memcached = Dalli::Client.new(@memcached_server, {:expires_in => 0})
    @store_manager = StoreManager.new(@memcached)  

  end

  def filter(event)
 
    enrichment = {}
    enrichment.merge!(event)

    store_enrichment = @store_manager.enrich(enrichment)
   
    namespace = store_enrichment[NAMESPACE_UUID]
    datasource = (namespace) ? DATASOURCE + "_" + namespace : DATASOURCE

    counterStore = @memcached.get(COUNTER_STORE)
    counterStore = Hash.new if counterStore.nil?
    counterStore[datasource] = counterStore[datasource].nil? ? 0 : (counterStore[datasource]+1)
    @memcached.set(COUNTER_STORE,counterStore)

    flowsNumber = @memcached.get(FLOWS_NUMBER)
    flowsNumber = Hash.new if flowsNumber.nil?
    store_enrichment["flows_count"] = flowsNumber[datasource] if flowsNumber[datasource]

    enrichmentEvent = LogStash::Event.new
    store_enrichment.each {|k,v| enrichmentEvent.set(k,v)}
    yield enrichmentEvent
 
    event.cancel
   
  end  # def filter
end    # classLogstash::Filter::Apstate
