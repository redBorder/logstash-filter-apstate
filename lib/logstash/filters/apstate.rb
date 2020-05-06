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
  config :counter_store_counter, :validate => :boolean, :default => false,   :required => false
  config :flow_counter,          :validate => :boolean, :default => false,   :required => false
  config :update_stores_rate,    :validate => :number,  :default => 60,      :required => false

  #Custom
  DATASOURCE = "rb_state"

  public

  def register
    @memcached_server = MemcachedConfig::servers if @memcached_server.empty?
    @memcached = Dalli::Client.new(@memcached_server, {:expires_in => 0, :value_max_bytes => 4000000})
    @store_manager = StoreManager.new(@memcached)  
    @last_refresh_stores = nil
  end

  def filter(event)
 
    enrichment = event.to_hash

    store_enrichment = @store_manager.enrich(enrichment)

    if @counter_store_counter or @flow_counter
        datasource = store_enrichment[NAMESPACE_UUID] ? DATASOURCE + "_" + store_enrichment[NAMESPACE_UUID] :       DATASOURCE
 
       if @counter_store_counter
         counter_store = @memcached.get(COUNTER_STORE) || {}
         counter = counter_store[datasource] || 0
         counter_store[datasource] = counter + splitted_msg.size
         @memcached.set(COUNTER_STORE,counter_store)
       end
 
       if @flow_counter
        flows_number = @memcached.get(FLOWS_NUMBER) || {}
        store_enrichment["flows_count"] = (flows_number[datasource] || 0)
      end
    end   

    enrichment_event = LogStash::Event.new
    store_enrichment.each {|k,v| enrichment_event.set(k,v)}
    yield enrichment_event

   event.cancel
   
  end  # def filter
end    # classLogstash::Filter::Apstate
