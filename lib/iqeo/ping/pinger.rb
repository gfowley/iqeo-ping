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

  attr_reader :hostspec, :protocol, :port

  def initialize ip, protocol: :icmp, port: nil
    @hostspec = ip.is_a?( Iqeo::Hostspec::Hostspec ) ? ip : Iqeo::Hostspec::Hostspec.new( ip ) 
    @protocol = protocol
    @port = port
  end

end

end
end
