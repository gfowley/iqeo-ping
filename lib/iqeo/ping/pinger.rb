require 'net/ping'
require 'iqeo/hostspec'

module Iqeo
module Ping

class Pinger

=begin
pings = {}
{}
ips.each { |ip| pings[ip] = Thread.new { p = Net::Ping::ICMP.new(ip) ; { ping: p.ping, time: p.duration, exception: p.exception } } }
[
    [0] "10.1.1.1",
    [1] "10.1.1.2",
    [2] "10.1.1.3"
]
2.2.2 :041 > pings.values.collect(&:alive?)
[
    [0] true,
    [1] true,
    [2] true
]
2.2.2 :042 > pings.values.collect(&:alive?)
[
    [0] false,
    [1] false,
    [2] false
]
pings.values.collect(&:value)                                                                                                                                                    
[
    [0] {
             :ping => false,
             :time => nil,
        :exception => #<Timeout::Error: execution expired>
    },
    [1] {
             :ping => false,
             :time => nil,
        :exception => #<Timeout::Error: execution expired>
    },
    [2] {
             :ping => false,
             :time => nil,
        :exception => #<Timeout::Error: execution expired>
    }
]
=end

  TIMEOUT = 3
  PROTOCOL = :icmp
  PORT = nil

  attr_reader :hostspec, :protocol, :port, :timeout, :threads

  def initialize ip, protocol: PROTOCOL, port: PORT, timeout: TIMEOUT
    @hostspec = ip.is_a?( Iqeo::Hostspec::Hostspec ) ? ip : Iqeo::Hostspec::Hostspec.new( ip ) 
    @protocol = protocol
    @port = port
    @timeout = timeout
  end

  def start
    @threads = @hostspec.collect do |ip|
      Thread.new do
        ping = Net::Ping::ICMP.new(ip,nil,@timeout)
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
