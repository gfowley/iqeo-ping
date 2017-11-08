require 'net/ping'
require 'iqeo/hostspec'

module Iqeo
module Scan

class Scanner

  # TODO: default and choose host or port response interpretation
  # TODO: accept multiple protocols
  # TODO: accept multiple ports, and a port-spec like nmap
  # TODO: default multiple common ports for protocol = TCP, UDP, default
  # TODO: default protocol will ICMP ping, TCP, UDP common parts 
  
  # TODO: maintain results hash structure: { address => { protocol => { port => result } } }
  # TODO: accept a portspec for { protocol => portspec } (a nmap port spec)

  DEFAULT_ICMP_PORTS = [ nil ]
  DEFAULT_TCP_PORTS  = [ 7, 9, 20, 21, 22, 23, 25, 53, 80, 88, 110, 111, 135, 139, 143, 194, 389, 443, 445, 464, 500, 515, 631, 636, 873, 993, 994, 995, 1080, 1433, 1434, 3389, 9100 ]
  DEFAULT_UDP_PORTS  = [ 9, 53, 67, 69, 123, 137, 161, 162, 514, 1812, 5353 ]

  DEFAULT_SERVICES = {
    icmp: DEFAULT_ICMP_PORTS,
    tcp:  DEFAULT_TCP_PORTS,
    udp:  DEFAULT_UDP_PORTS
  }

  TIMEOUT = 2
  PROTOCOL = :icmp
  PORT = nil
  PORTS = { icmp: nil, tcp: 80, udp: 53 }

  attr_reader :hostspec, :services, :timeout

  def initialize ip, services: DEFAULT_SERVICES, timeout: TIMEOUT, pingers: Net::Ping
    @hostspec     = ip.is_a?( Iqeo::Hostspec::Hostspec ) ? ip : Iqeo::Hostspec::Hostspec.new( ip )
    @services     = configure_services_defaults services
    @ping_classes = configure_services_ping_classes services, pingers
    @timeout      = timeout
  end

  def configure_services_ping_classes services, pingers
    ping_classes = {}
    services.each do |protocol,ports|
      if ping_class = pingers.const_get( ping_classname = protocol.upcase )
        ping_classes[protocol] = ping_class
      else
        raise "No class #{pingers}::#{ping_classname} for protocol #{protocol}"
      end
    end
    ping_classes
  end

  def configure_services_defaults services
    services.each do |protocol,ports|
      if ( ports.nil? || ports.empty? || ports[0].nil? )
        services[protocol] = DEFAULT_SERVICES[protocol] if DEFAULT_SERVICES.has_key? protocol 
      end
    end
    services
  end

  def start
    unless started?
      @threads = @hostspec.collect do |address|
        @services.collect do |protocol,ports|
          ports.collect do |port|
            Thread.new do
              ping = @ping_classes[protocol].new(address,port,@timeout)
              result = ping.ping
              { address: address, protocol: protocol, port: port, ping: result, time: ping.duration, exception: ping.exception }
            end
          end
        end
      end.flatten
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
