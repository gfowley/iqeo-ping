require 'net/ping'
require 'iqeo/hostspec'

module Iqeo
module Scan

class Scanner

  # TODO: choose host or port response interpretation
  # TODO: accept a portspec for { protocol => portspec } (a nmap port spec)

  DEFAULT_ICMP_PORTS = [ nil ]
  DEFAULT_TCP_PORTS  = [ 7, 9, 20, 21, 22, 23, 25, 53, 80, 88, 110, 111, 135, 139, 143, 194, 389, 443, 445, 464, 500, 515, 631, 636, 873, 993, 994, 995, 1080, 1433, 1434, 3389, 9100 ]
  DEFAULT_UDP_PORTS  = [ 9, 53, 67, 69, 123, 137, 161, 162, 514, 1812, 5353 ]

  DEFAULT_SERVICES = {
    icmp: DEFAULT_ICMP_PORTS,
    tcp:  DEFAULT_TCP_PORTS,
    udp:  DEFAULT_UDP_PORTS
  }

  DEFAULT_PROTOCOLS = [ :icmp, :tcp ]
  DEFAULT_TIMEOUT   = 2
  DEFAULT_ATTEMPTS  = 2

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
      if protocol == :icmp || ( ports.nil? || ports.empty? || ports[0].nil? )
        services[protocol] = DEFAULT_SERVICES[protocol] if DEFAULT_SERVICES.has_key? protocol 
      end
    end
    services
  end

  def start
    unless @started
      init_results
      init_threads
    end
    @started = true
  end

  def started?
    !!@started
  end

  def running?
    started? && @threads.values.any?(&:alive?)
  end

  def finished?
    started? && @threads.values.none?(&:alive?)
  end

  def stop
    !!( started? && @threads.values.each(&:kill) )
  end

  def results
    return @results if @results_are_final
    if started? 
      if finished?
        finish_results
        @results_are_final = true
      else
        update_results
      end
      @results
    end
  end

  private

  def init_threads
    @thread_results = Queue.new
    @threads = @hostspec.map do |address|
      [ address, address_thread( address ) ]
    end.to_h
  end

  def address_thread address
    Thread.new do
      @services.map do |protocol,ports|
        protocol_thread address, protocol, ports
      end.each(&:join)
    end
  end

  def protocol_thread address, protocol, ports
    Thread.new do
      ports.map do |port|
        port_thread address, protocol, port
      end.each(&:join)
    end
  end

  def port_thread address, protocol, port
    Thread.new do
      pinger = @ping_classes[protocol].new(address,port,@timeout)
      ping = pinger.ping
      @thread_results.push(
        {
          address:   address,
          protocol:  protocol,
          port:      port,
          state:     port_state( protocol, ping, pinger.exception ),
          ping:      ping,
          time:      pinger.duration,
          exception: pinger.exception,
        }
      )
    end
  end

  def port_state protocol, ping, exception
    case protocol
    when :icmp
      ping ? :open : :none
    when :tcp
      case 
      when ping then :open  
      when exception.class == Errno::ECONNREFUSED then :close 
      when exception.class == Timeout::Error      then :none 
      end
    when :udp
      case 
      when ping then :open  
      when exception.class == Errno::ECONNREFUSED then :close 
      when exception.class == Timeout::Error      then :none
      end
    end
  end

  def init_results
    @results = @hostspec.map do |address|
      [ 
        address,
        {
          state: :unknown,
          scan:  @services.map do |protocol,ports|
            [
              protocol,
              ports.map do |port|
                [ port, nil ]
              end.to_h
            ]
          end.to_h
        }
      ]
    end.to_h
  end

  def finish_results
    update_results
    finalize_host_states
  end

  def update_results
    until @thread_results.empty? do
      thread_result = @thread_results.pop
      host = @results[thread_result[:address]]
      host[:scan][thread_result[:protocol]][thread_result[:port]] = thread_result
      host[:state] = host_state( thread_result )
    end
  end

  def finalize_host_states
    @results.each { |_,host| host[:state] = :down unless host[:state] == :up  }
  end

  def host_state thread_result
    :up if thread_result[:state] == :open || thread_result[:state] == :close
  end

end

end
end
