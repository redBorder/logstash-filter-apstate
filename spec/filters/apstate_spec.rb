# encoding: utf-8
require 'spec_helper'
require "logstash/filters/apstate"

describe LogStash::Filters::Apstate do
  describe "Set to Hello World" do
    let(:config) do <<-CONFIG
      filter {
        apstate {
          message => "Hello World"
        }
      }
    CONFIG
    end

    sample("message" => "some text") do
      expect(subject.get("message")).to eq('Hello World')
    end
  end
end
