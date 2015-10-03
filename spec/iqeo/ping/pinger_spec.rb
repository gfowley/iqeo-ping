require 'spec_helper'

describe Iqeo::Ping::Pinger do

  before( :all ) { `iptables -I INPUT -d 127.0.0.252/30 -j DROP` }

  context '#new' do
    it( 'accepts an IP address string' ) { expect { Iqeo::Ping::Pinger.new '127.0.0.1' }.to_not raise_error }
    it( 'accepts a Hostspec' )           { expect { Iqeo::Ping::Pinger.new( Iqeo::Hostspec::Hostspec.new '127.0.0.1' ) }.to_not raise_error }
    it( 'requires an argument' )         { expect { Iqeo::Ping::Pinger.new }.to raise_error ArgumentError }
  end

  context '#hostspec' do
    it( 'is created from string' )       { expect( Iqeo::Ping::Pinger.new('127.0.0.1').hostspec ).to be_a Iqeo::Hostspec::Hostspec }
    it( 'is passed from #new' )          { expect( Iqeo::Ping::Pinger.new( Iqeo::Hostspec::Hostspec.new '127.0.0.1' ).hostspec ).to be_a Iqeo::Hostspec::Hostspec }
  end

  context 'defaults' do

    before( :all ) { @pinger = Iqeo::Ping::Pinger.new '127.0.0.1' }

    it( 'protocol' ) { expect( @pinger.protocol ).to eq Iqeo::Ping::Pinger::PROTOCOL }
    it( 'port' )     { expect( @pinger.port ).to eq Iqeo::Ping::Pinger::PORT }
    it( 'timeout' )  { expect( @pinger.timeout ).to eq Iqeo::Ping::Pinger::TIMEOUT }

  end

  context 'short scan' do

    before( :all ) { @pinger = Iqeo::Ping::Pinger.new '127.0.0.1-3' }

    it( 'starts' ) do
      expect { @pinger.start }.to_not raise_error
      sleep 0.1 # wait for it
    end

    context 'state' do
      it( 'is started' )          { expect( @pinger ).to be_started }
      it( 'is running' )          { expect( @pinger ).to_not be_running }
      it( 'is finished' )         { expect( @pinger ).to be_finished }
    end

    context 'threads' do
      it( 'one per host' )        { expect( @pinger.threads.count ).to eq @pinger.hostspec.count }
      it( 'all finished' )        { expect( @pinger.threads.none?(&:alive?) ).to be true }
    end

    context 'finishes' do
      it( 'successfully' )        { expect( @pinger.threads.first.value[:exception] ).to_not be_a Exception }
    end

    context 'results' do
      it( 'for number of hosts' ) { expect( @pinger.results.count ).to eq @pinger.hostspec.count }
      it( 'expected keys' )       { expect( @pinger.results ).to all( include :ip, :ping, :time, :exception ) }
      it( 'for each host' )       { expect( @pinger.results.collect { |r| r[:ip] } ).to eq [ '127.0.0.1','127.0.0.2','127.0.0.3' ] }
    end

  end

  context 'long scan' do

    before( :all ) { @pinger = Iqeo::Ping::Pinger.new '127.0.0.252-254' }

    it( 'starts' ) do
      expect { @pinger.start }.to_not raise_error
      sleep 0.1 # wait for it
    end

    context 'state' do
      it( 'is started' )          { expect( @pinger ).to be_started }
      it( 'is running' )          { expect( @pinger ).to be_running }
      it( 'is not finished' )     { expect( @pinger ).to_not be_finished }
    end

    context 'threads' do
      it( 'one per host' )        { expect( @pinger.threads.count ).to eq @pinger.hostspec.count }
      it( 'some alive' )          { expect( @pinger.threads.none?(&:alive?) ).to be false }
    end

    context 'finishes' do
      it( 'with timeout' )        { expect( @pinger.threads.first.value[:exception] ).to be_a TimeoutError }
    end

    context 'results' do
      it( 'for number of hosts' ) { expect( @pinger.results.count ).to eq @pinger.hostspec.count }
      it( 'expected keys' )       { expect( @pinger.results ).to all( include :ip, :ping, :time, :exception ) }
      it( 'for each host' )       { expect( @pinger.results.collect { |r| r[:ip] } ).to eq [ '127.0.0.252','127.0.0.253','127.0.0.254' ] }
    end

  end

  after( :all ) { `iptables -D INPUT -d 127.0.0.252/30 -j DROP` }

end

