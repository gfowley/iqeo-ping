require 'net/ping'
require 'iqeo/hostspec'

module Iqeo
module Scan

class Scanner

  TIMEOUT = 3
  PROTOCOL = :icmp
  PORT = nil
  PORTS = { icmp: nil, tcp: 80, udp: 53 }

  attr_reader :hostspec, :protocol, :port, :timeout

  def initialize ip, protocol: PROTOCOL, port: PORT, timeout: TIMEOUT, pingers: Net::Ping
    @hostspec = ip.is_a?( Iqeo::Hostspec::Hostspec ) ? ip : Iqeo::Hostspec::Hostspec.new( ip )
    @protocol = protocol
    @port     = port || PORTS[@protocol]
    @timeout  = timeout
    unless @ping_class = pingers.const_get( ping_classname = @protocol.upcase )
      raise "No class #{pingers}::#{ping_classname} for protocol #{@protocol}"
    end
  end

  def start
    unless started?
      @threads = @hostspec.collect do |ip|
        Thread.new do
          ping = @ping_class.new(ip,@port,@timeout)
          result = ping.ping
          { ip: ip, ping: result, time: ping.duration, exception: ping.exception }
        end
      end
    end
  end

  def started?
    !!@threads
  end

  def running?
    started? && @threads.any?(&:alive?)
  end

  def finished?
    started? && @threads.none?(&:alive?)
  end

  def results
    started? ? collect_thread_values_without_blocking : []
  end

  def stop
    !!( started? && @threads.each(&:kill) )
  end

  private

  def collect_thread_values_without_blocking
    @threads.collect do |thread|
      # calling value for running thread will block until it finishes
      # status = nil || false for finished thread
      thread.status ? nil : thread.value
    end
  end

end

end
end
