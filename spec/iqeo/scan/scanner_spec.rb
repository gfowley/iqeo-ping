require 'spec_helper'
 
describe Iqeo::Scan::Scanner do

  HOST_SPEC           = '127.0.0.1'
  ALL_HOSTS_SPEC      = '127.0.0.1-3,252-254'
  FAST_HOSTS          = [ '127.0.0.1','127.0.0.2','127.0.0.3' ]
  FAST_HOSTS_SPEC     = '127.0.0.1-3'
  SLOW_HOSTS          = [ '127.0.0.252','127.0.0.253','127.0.0.254' ]
  SLOW_HOSTS_SPEC     = '127.0.0.252-254'
  SLOW_HOSTS_IPTABLES = '127.0.0.252/30'
  RESULT_KEYS         = [ :ping, :time, :exception ]

  DEFAULT_SERVICES   = Iqeo::Scan::Scanner::DEFAULT_SERVICES
  DEFAULT_TCP_PORTS  = Iqeo::Scan::Scanner::DEFAULT_TCP_PORTS
  DEFAULT_UDP_PORTS  = Iqeo::Scan::Scanner::DEFAULT_UDP_PORTS
  DEFAULT_ICMP_PORTS = Iqeo::Scan::Scanner::DEFAULT_ICMP_PORTS
  TIMEOUT            = Iqeo::Scan::Scanner::TIMEOUT

  PORTS_PER_HOST     = DEFAULT_TCP_PORTS.count + DEFAULT_UDP_PORTS.count + DEFAULT_ICMP_PORTS.count

  # before( :all ) { `iptables -I INPUT -d #{SLOW_HOSTS_IPTABLES} -j DROP` }

  module FakePinger
    class Base
      def initialize ip, port, timeout
        @ip = ip
      end 
      def ping      ; sleep 0.1 if SLOW_HOSTS.include? @ip ; end
      def duration  ; end
      def exception ; Timeout::Error if SLOW_HOSTS.include? @ip ; end
    end
    class ICMP < Base ; end
    class TCP  < Base ; end
    class UDP  < Base ; end
  end

  def wait_for
    Timeout.timeout 1 do
      sleep 0.001 until yield
    end
  end

  context 'initializes' do

    it ( 'requires an argument'         ) { expect { Iqeo::Scan::Scanner.new }.to raise_error ArgumentError }
    it ( 'accepts an IP address string' ) { expect { Iqeo::Scan::Scanner.new HOST_SPEC }.to_not raise_error                                 }
    it ( 'accepts a Hostspec'           ) { expect { Iqeo::Scan::Scanner.new( Iqeo::Hostspec::Hostspec.new HOST_SPEC ) }.to_not raise_error }

    it ( 'accepts timeout'  ) { expect( Iqeo::Scan::Scanner.new( HOST_SPEC, timeout: 99).timeout ).to eq 99 }
    it ( 'defaults timeout' ) { expect( Iqeo::Scan::Scanner.new( HOST_SPEC             ).timeout ).to eq TIMEOUT  }

    context 'default ports' do

      # TODO: test services: {}, services: nil

      context 'no protocol specified' do
        before( :all ) { @scanner = Iqeo::Scan::Scanner.new HOST_SPEC }
        it( 'ICMP' ) { expect( @scanner.services[:icmp] ).to eq DEFAULT_ICMP_PORTS }
        it( 'TCP'  ) { expect( @scanner.services[:tcp]  ).to eq DEFAULT_TCP_PORTS  }
        it( 'UDP'  ) { expect( @scanner.services[:udp]  ).to eq DEFAULT_UDP_PORTS  }
      end

      context 'single protocol specified' do

        # todo: test services: { protocol => nil }

        context 'ICMP specified' do
          before( :all ) { @scanner = Iqeo::Scan::Scanner.new HOST_SPEC, services: { icmp: [] } }
          it( 'ICMP'   ) { expect( @scanner.services[:icmp] ).to eq DEFAULT_ICMP_PORTS }
          it( 'no TCP' ) { expect( @scanner.services[:tcp] ).to be_nil }
          it( 'no UDP' ) { expect( @scanner.services[:udp] ).to be_nil }
        end

        context 'TCP specified' do
          before( :all )  { @scanner = Iqeo::Scan::Scanner.new HOST_SPEC, services: { tcp: [] } }
          it( 'no ICMP' ) { expect( @scanner.services[:icmp] ).to be_nil }
          it( 'TCP'     ) { expect( @scanner.services[:tcp] ).to eq DEFAULT_TCP_PORTS }
          it( 'no UDP'  ) { expect( @scanner.services[:udp] ).to be_nil }
        end

        context 'UDP specified' do
          before( :all )           { @scanner = Iqeo::Scan::Scanner.new HOST_SPEC, services: { udp: [] } }
          it( 'no ICMP' ) { expect( @scanner.services[:icmp] ).to be_nil }
          it( 'UDP'     ) { expect( @scanner.services[:udp] ).to eq DEFAULT_UDP_PORTS }
          it( 'no TCP'  ) { expect( @scanner.services[:tcp] ).to be_nil }
        end

      end

      context 'multiple protocols specified' do

        context 'TCP & UDP specified' do
          before( :all )  { @scanner = Iqeo::Scan::Scanner.new HOST_SPEC, services: { tcp: [], udp: [] } }
          it( 'no ICMP' ) { expect( @scanner.services[:icmp] ).to be_nil }
          it( 'TCP'     ) { expect( @scanner.services[:tcp] ).to eq DEFAULT_TCP_PORTS }
          it( 'UDP'     ) { expect( @scanner.services[:udp] ).to eq DEFAULT_UDP_PORTS }
        end

        context 'ICMP & TCP specified' do
          before( :all ) { @scanner = Iqeo::Scan::Scanner.new HOST_SPEC, services: { icmp: [], tcp: [] } }
          it( 'ICMP'   ) { expect( @scanner.services[:icmp] ).to eq DEFAULT_ICMP_PORTS }
          it( 'TCP'    ) { expect( @scanner.services[:tcp] ).to eq DEFAULT_TCP_PORTS }
          it( 'no UDP' ) { expect( @scanner.services[:udp] ).to be_nil }
        end

        context 'ICMP & UDP specified' do
          before( :all ) { @scanner = Iqeo::Scan::Scanner.new HOST_SPEC, services: { icmp: [], udp: [] } }
          it( 'ICMP'   ) { expect( @scanner.services[:icmp] ).to eq DEFAULT_ICMP_PORTS }
          it( 'no TCP' ) { expect( @scanner.services[:tcp] ).to be_nil }
          it( 'UDP'    ) { expect( @scanner.services[:udp] ).to eq DEFAULT_UDP_PORTS }
        end

      end

    end
   
    context 'specified ports' do
      before( :all ) { @scanner = Iqeo::Scan::Scanner.new HOST_SPEC, services: { tcp: [0, 80, 65535], udp: [0, 53, 65535] } }
      it( 'TCP are accepted' ) { expect( @scanner.services[:tcp] ).to eq [0, 80, 65535] }
      it( 'UDP are accepted' ) { expect( @scanner.services[:udp] ).to eq [0, 53, 65535] }
    end

    context 'icmp ports' do
      before( :all ) { @scanner = Iqeo::Scan::Scanner.new HOST_SPEC, services: { icmp: [ 1 ,2 ,3 ] } }
      it( 'are ignored' ) { expect( @scanner.services[:icmp] ).to eq DEFAULT_ICMP_PORTS }
    end
   
  end

  context '#hostspec' do
    it( 'is from string'      ) { expect( Iqeo::Scan::Scanner.new( HOST_SPEC ).hostspec ).to be_a Iqeo::Hostspec::Hostspec }
    it( 'is passed from .new' ) { expect( Iqeo::Scan::Scanner.new( Iqeo::Hostspec::Hostspec.new HOST_SPEC ).hostspec ).to be_a Iqeo::Hostspec::Hostspec }
  end

  context 'initial state' do
    before( :all )          { @scanner = Iqeo::Scan::Scanner.new HOST_SPEC }
    it( 'is not started'  ) { expect( @scanner ).to_not be_started   }
    it( 'is not running'  ) { expect( @scanner ).to_not be_running   }
    it( 'is not finished' ) { expect( @scanner ).to_not be_finished  }
    it( 'has no results'  ) { expect( @scanner.results ).to be_nil   }
    it( 'cannot stop'     ) { expect( @scanner.stop    ).to eq false }
  end

  context 'fast scan' do

    before( :each ) do
      @scanner = Iqeo::Scan::Scanner.new FAST_HOSTS_SPEC, pingers: FakePinger
      @scanner.start
      wait_for { @scanner.finished? }
    end

    context 'state' do
      it( 'is #started?'  ) { expect( @scanner ).to be_started     }
      it( 'is #running?'  ) { expect( @scanner ).to_not be_running }
      it( 'is #finished?' ) { expect( @scanner ).to be_finished    }
    end

    context '#results' do

      it( 'hosts'     ) { expect( @scanner.results.keys ).to eq FAST_HOSTS }
      it( 'protocols' ) { expect( @scanner.results[FAST_HOSTS.first].keys).to eq DEFAULT_SERVICES.keys }

      context 'ports' do
        it( 'tcp'  ) { expect( @scanner.results[FAST_HOSTS.first][:tcp ].keys ).to eq DEFAULT_TCP_PORTS  }
        it( 'udp'  ) { expect( @scanner.results[FAST_HOSTS.first][:udp ].keys ).to eq DEFAULT_UDP_PORTS  }
        it( 'icmp' ) { expect( @scanner.results[FAST_HOSTS.first][:icmp].keys ).to eq DEFAULT_ICMP_PORTS }
      end

      context 'keys' do
        it( 'tcp'  ) { expect( @scanner.results[FAST_HOSTS.first][:tcp ][DEFAULT_TCP_PORTS.first ].keys ).to eq RESULT_KEYS }
        it( 'udp'  ) { expect( @scanner.results[FAST_HOSTS.first][:udp ][DEFAULT_UDP_PORTS.first ].keys ).to eq RESULT_KEYS }
        it( 'icmp' ) { expect( @scanner.results[FAST_HOSTS.first][:icmp][DEFAULT_ICMP_PORTS.first].keys ).to eq RESULT_KEYS }
      end

      context 'no timeouts' do
        it( 'tcp'  ) { expect( @scanner.results[FAST_HOSTS.first][:tcp ].values.collect { |r| r[:exception] } ).to all( eq nil ) }
        it( 'udp'  ) { expect( @scanner.results[FAST_HOSTS.first][:udp ].values.collect { |r| r[:exception] } ).to all( eq nil ) }
        it( 'icmp' ) { expect( @scanner.results[FAST_HOSTS.first][:icmp].values.collect { |r| r[:exception] } ).to all( eq nil ) }
      end

    end

  end

  context 'slow scan' do

    before( :each ) do
      @scanner = Iqeo::Scan::Scanner.new SLOW_HOSTS_SPEC, pingers: FakePinger
      @scanner.start
      wait_for { @scanner.started? }
    end

    context 'state' do
      it( 'is #started?'   ) { expect( @scanner ).to be_started      }
      it( 'is #running?'   ) { expect( @scanner ).to be_running      }
      it( 'not #finished?' ) { expect( @scanner ).to_not be_finished }
    end

    context '#results' do

      before( :each )       { wait_for { @scanner.finished? } }

      it( 'hosts'     ) { expect( @scanner.results.keys ).to eq SLOW_HOSTS }
      it( 'protocols' ) { expect( @scanner.results[SLOW_HOSTS.first].keys).to eq DEFAULT_SERVICES.keys }

      context 'ports' do
        it( 'tcp'  ) { expect( @scanner.results[SLOW_HOSTS.first][:tcp ].keys ).to eq DEFAULT_TCP_PORTS  }
        it( 'udp'  ) { expect( @scanner.results[SLOW_HOSTS.first][:udp ].keys ).to eq DEFAULT_UDP_PORTS  }
        it( 'icmp' ) { expect( @scanner.results[SLOW_HOSTS.first][:icmp].keys ).to eq DEFAULT_ICMP_PORTS }
      end

      context 'keys' do
        it( 'tcp'  ) { expect( @scanner.results[SLOW_HOSTS.first][:tcp ][DEFAULT_TCP_PORTS.first ].keys ).to eq RESULT_KEYS }
        it( 'udp'  ) { expect( @scanner.results[SLOW_HOSTS.first][:udp ][DEFAULT_UDP_PORTS.first ].keys ).to eq RESULT_KEYS }
        it( 'icmp' ) { expect( @scanner.results[SLOW_HOSTS.first][:icmp][DEFAULT_ICMP_PORTS.first].keys ).to eq RESULT_KEYS }
      end

      context 'no timeouts' do
        it( 'tcp'  ) { expect( @scanner.results[SLOW_HOSTS.first][:tcp ].values.collect { |r| r[:exception] } ).to all( eq Timeout::Error ) }
        it( 'udp'  ) { expect( @scanner.results[SLOW_HOSTS.first][:udp ].values.collect { |r| r[:exception] } ).to all( eq Timeout::Error ) }
        it( 'icmp' ) { expect( @scanner.results[SLOW_HOSTS.first][:icmp].values.collect { |r| r[:exception] } ).to all( eq Timeout::Error ) }
      end

    end

  end

  context 'stop scan' do

    def all_port_scans
      @scanner.results.values.collect{ |protocol| protocol.values.collect { |port| port.values } }.flatten
    end

    def finished_port_scans_count
      all_port_scans.compact.count
    end

    def unfinished_port_scans_count
      all_port_scans.count - finished_port_scans_count
    end

    def finished_host_scans
      @scanner.results.select{ |address,protocol| protocol.values.all? { |port| port.values.all? } }
    end

    before( :each ) do
      @scanner = Iqeo::Scan::Scanner.new ALL_HOSTS_SPEC, pingers: FakePinger
      @scanner.start
      wait_for do
        finished_host_scans.count == FAST_HOSTS.count
      end
      expect( @scanner.stop ).to eq true
      wait_for { @scanner.finished? }
      # binding.pry
    end

    context 'state' do
      it( 'is #started?'     ) { expect( @scanner ).to be_started     }
      it( 'is not #running?' ) { expect( @scanner ).to_not be_running }
      it( 'is #finished?'    ) { expect( @scanner ).to be_finished    }
    end

    context '#results' do
      it( 'exist for finished hosts' ) { expect(   finished_port_scans_count ).to eq FAST_HOSTS.count * PORTS_PER_HOST }
      it( 'nil for unfinished hosts' ) { expect( unfinished_port_scans_count ).to eq SLOW_HOSTS.count * PORTS_PER_HOST }
    end

  end

  # after( :all ) { `iptables -D INPUT -d #{SLOW_HOSTS_IPTABLES} -j DROP` }

end

