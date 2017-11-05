require 'spec_helper'
 
describe Iqeo::Scan::Scanner do

  HOST_SPEC           = '127.0.0.1'
  ALL_HOSTS_SPEC      = '127.0.0.1-3,252-254'
  FAST_HOSTS          = [ '127.0.0.1','127.0.0.2','127.0.0.3' ]
  FAST_HOSTS_SPEC     = '127.0.0.1-3'
  SLOW_HOSTS          = [ '127.0.0.252','127.0.0.253','127.0.0.254' ]
  SLOW_HOSTS_SPEC     = '127.0.0.252-254'
  SLOW_HOSTS_IPTABLES = '127.0.0.252/30'
  RESULT_KEYS         = [ :ip, :ping, :time, :exception ]

  # before( :all ) { `iptables -I INPUT -d #{SLOW_HOSTS_IPTABLES} -j DROP` }

  module FakePinger
    class ICMP
      def initialize ip, port, timeout
        @ip = ip
      end 
      def ping      ; sleep 0.1 if SLOW_HOSTS.include? @ip ; end
      def duration  ; end
      def exception ; Timeout::Error if SLOW_HOSTS.include? @ip ; end
    end
  end

  def wait_for
    Timeout.timeout 1 do
      sleep 0.001 until yield
    end
  end

  context '.new' do

    context 'with defaults' do
      it( 'accepts an IP address string' ) { expect { Iqeo::Scan::Scanner.new HOST_SPEC }.to_not raise_error                                 }
      it( 'accepts a Hostspec'           ) { expect { Iqeo::Scan::Scanner.new( Iqeo::Hostspec::Hostspec.new HOST_SPEC ) }.to_not raise_error }
      it( 'requires an argument'         ) { expect { Iqeo::Scan::Scanner.new }.to raise_error ArgumentError                                 }
    end

    context 'with specifics' do
     
      it ( 'accepts timeout' )  { expect( Iqeo::Scan::Scanner.new( HOST_SPEC, timeout: 99).timeout ).to eq 99 }

      context 'ICMP' do
        before( :all )           { @scanner = Iqeo::Scan::Scanner.new HOST_SPEC, protocol: :icmp, timeout: 99 }
        it( 'accepts protocol' ) { expect( @scanner.protocol ).to eq :icmp }
        it( 'sets port'        ) { expect( @scanner.port ).to be nil       }
      end

      context 'TCP' do
        before( :all )           { @scanner = Iqeo::Scan::Scanner.new HOST_SPEC, protocol: :tcp, timeout: 99 }
        it( 'accepts protocol' ) { expect( @scanner.protocol ).to eq :tcp }
        it( 'sets port'        ) { expect( @scanner.port ).to be 80       }
      end

      context 'UDP' do
        before( :all )           { @scanner = Iqeo::Scan::Scanner.new HOST_SPEC, protocol: :udp, timeout: 99 }
        it( 'accepts protocol' ) { expect( @scanner.protocol ).to eq :udp }
        it( 'sets port'        ) { expect( @scanner.port ).to be 53       }
      end

    end
    
  end

  context '#hostspec' do
    it( 'is from string'      ) { expect( Iqeo::Scan::Scanner.new( HOST_SPEC ).hostspec ).to be_a Iqeo::Hostspec::Hostspec }
    it( 'is passed from .new' ) { expect( Iqeo::Scan::Scanner.new( Iqeo::Hostspec::Hostspec.new HOST_SPEC ).hostspec ).to be_a Iqeo::Hostspec::Hostspec }
  end

  context 'defaults' do
    before( :all )     { @scanner = Iqeo::Scan::Scanner.new HOST_SPEC }
    it( '#protocol' ) { expect( @scanner.protocol ).to eq Iqeo::Scan::Scanner::PROTOCOL }
    it( '#port'     ) { expect( @scanner.port     ).to eq Iqeo::Scan::Scanner::PORT     }
    it( '#timeout'  ) { expect( @scanner.timeout  ).to eq Iqeo::Scan::Scanner::TIMEOUT  }
  end

  context 'initial state' do
    before( :all )          { @scanner = Iqeo::Scan::Scanner.new HOST_SPEC }
    it( 'is not started'  ) { expect( @scanner ).to_not be_started   }
    it( 'is not running'  ) { expect( @scanner ).to_not be_running   }
    it( 'is not finished' ) { expect( @scanner ).to_not be_finished  }
    it( 'has no results'  ) { expect( @scanner.results ).to be_empty }
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
      it( 'expected keys'  ) { expect( @scanner.results ).to all( include *RESULT_KEYS )                 }
      it( 'expected hosts' ) { expect( @scanner.results.collect { |r| r[:ip] } ).to eq FAST_HOSTS        }
      it( 'no timeouts'    ) { expect( @scanner.results.collect { |r| r[:exception] } ).to all( eq nil ) }
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
      it( 'expected keys' ) { expect( @scanner.results ).to all( include *RESULT_KEYS )                            }
      it( 'for each host' ) { expect( @scanner.results.collect { |r| r[:ip] } ).to eq SLOW_HOSTS                   }
      it( 'all timed out' ) { expect( @scanner.results.collect { |r| r[:exception] } ).to all( eq Timeout::Error ) }
    end

  end

  context 'stop scan' do

    before( :each ) do
      @scanner = Iqeo::Scan::Scanner.new ALL_HOSTS_SPEC, pingers: FakePinger
      @scanner.start
      wait_for { @scanner.results.compact.count == FAST_HOSTS.count }
      expect( @scanner.stop ).to eq true
      wait_for { @scanner.finished? }
    end

    context 'state' do
      it( 'is #started?'     ) { expect( @scanner ).to be_started     }
      it( 'is not #running?' ) { expect( @scanner ).to_not be_running }
      it( 'is #finished?'    ) { expect( @scanner ).to be_finished    }
    end

    context '#results' do
      it( 'for fast hosts' ) { expect( @scanner.results.compact.collect { |r| r[:ip] } ).to eq FAST_HOSTS }
      it( 'nil for others' ) { expect( @scanner.results ).to include nil                                  }
    end

  end

  # after( :all ) { `iptables -D INPUT -d #{SLOW_HOSTS_IPTABLES} -j DROP` }

end

