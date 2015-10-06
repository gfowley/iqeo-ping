require 'net/ping'
require 'iqeo/hostspec'

module Iqeo
module Ping

class Pinger

  TIMEOUT = 3
  PROTOCOL = :icmp
  PORT = nil
  PORTS = { icmp: nil, tcp: 80, udp: 53 }

  def self.classes
    unless @classes
      classes = Net::Ping::constants.collect { |c| Net::Ping::const_get(c) }.select { |val| val.is_a? Class }
      names = classes.collect { |c| c.name.split('::').last.downcase.to_sym }
      @classes = Hash[names.zip(classes)]
    end
    @classes
  end
  
  attr_reader :hostspec, :protocol, :port, :klass, :timeout, :threads

  def initialize ip, protocol: PROTOCOL, port: PORT, timeout: TIMEOUT
    @hostspec = ip.is_a?( Iqeo::Hostspec::Hostspec ) ? ip : Iqeo::Hostspec::Hostspec.new( ip ) 
    @protocol = protocol
    @port = port || PORTS[@protocol]
    @timeout = timeout
    raise "No Net::Ping class for: #{@protocol}" unless @klass = Pinger.classes[@protocol]
  end

  def start
    @threads = @hostspec.collect do |ip|
      Thread.new do
        ping = @klass.new(ip,@port,@timeout)
        result = ping.ping
        { ip: ip, ping: result, time: ping.duration, exception: ping.exception }
      end
    end
  end

  def started?
    !!@threads
  end

  def running?
    @threads.any?(&:alive?)
  end

  def finished?
    @threads.none?(&:alive?)
  end

  def results
    @threads.collect(&:value)
  end

end

end
end
