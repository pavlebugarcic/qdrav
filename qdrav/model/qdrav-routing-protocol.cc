/*
 * Copyright (c) 2009 IITP RAS
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation;
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */
#define NS_LOG_APPEND_CONTEXT                                                                      \
    if (m_ipv4)                                                                                    \
    {                                                                                              \
        std::clog << "[node " << m_ipv4->GetObject<Node>()->GetId() << "] ";                       \
    }

#include "qdrav-routing-protocol.h"
#include "qdrav-qtable.h"
#include "ns3/double.h"
#include "ns3/adhoc-wifi-mac.h"
#include "ns3/boolean.h"
#include "ns3/inet-socket-address.h"
#include "ns3/log.h"
#include "ns3/pointer.h"
#include "ns3/random-variable-stream.h"
#include "ns3/string.h"
#include "ns3/trace-source-accessor.h"
#include "ns3/udp-header.h"
#include "ns3/udp-l4-protocol.h"
#include "ns3/udp-socket-factory.h"
#include "ns3/wifi-mpdu.h"
#include "ns3/wifi-net-device.h"
#include "ns3/node-list.h"
#include "ns3/mobility-model.h"

#include <algorithm>
#include <limits>

#include <iostream>
#include "ns3/output-stream-wrapper.h"
#include "ns3/ptr.h"

namespace ns3
{

NS_LOG_COMPONENT_DEFINE("QdravRoutingProtocol");

namespace qdrav
{
NS_OBJECT_ENSURE_REGISTERED(RoutingProtocol);

/// UDP Port for AODV control traffic
const uint32_t RoutingProtocol::AODV_PORT = 654;

/**
 * \ingroup qdrav
 * \brief Tag used by Q-DRAV implementation
 */
class DeferredRouteOutputTag : public Tag
{
  public:
    /**
     * \brief Constructor
     * \param o the output interface
     */
    DeferredRouteOutputTag(int32_t o = -1)
        : Tag(),
          m_oif(o)
    {
    }

    /**
     * \brief Get the type ID.
     * \return the object TypeId
     */
    static TypeId GetTypeId()
    {
        static TypeId tid = TypeId("ns3::qdrav::DeferredRouteOutputTag")
                                .SetParent<Tag>()
                                .SetGroupName("Qdrav")
                                .AddConstructor<DeferredRouteOutputTag>();
        return tid;
    }

    TypeId GetInstanceTypeId() const override
    {
        return GetTypeId();
    }

    /**
     * \brief Get the output interface
     * \return the output interface
     */
    int32_t GetInterface() const
    {
        return m_oif;
    }

    /**
     * \brief Set the output interface
     * \param oif the output interface
     */
    void SetInterface(int32_t oif)
    {
        m_oif = oif;
    }

    uint32_t GetSerializedSize() const override
    {
        return sizeof(int32_t);
    }

    void Serialize(TagBuffer i) const override
    {
        i.WriteU32(m_oif);
    }

    void Deserialize(TagBuffer i) override
    {
        m_oif = i.ReadU32();
    }

    void Print(std::ostream& os) const override
    {
        os << "DeferredRouteOutputTag: output interface = " << m_oif;
    }

  private:
    /// Positive if output device is fixed in RouteOutput
    int32_t m_oif;
};

NS_OBJECT_ENSURE_REGISTERED(DeferredRouteOutputTag);

//-----------------------------------------------------------------------------
RoutingProtocol::RoutingProtocol()
    : m_lpreqRetries(2),
      m_ttlStart(5),  
      m_timeoutBuffer(2),
      m_lpreqRateLimit(10),
      m_netDiameter(35),
      m_nodeTraversalTime(MilliSeconds(40)),
      m_netTraversalTime(Time((2 * m_netDiameter) * m_nodeTraversalTime)),
      m_pathDiscoveryTime(Time(2 * m_netTraversalTime)),
      m_helloInterval(Seconds(0.75)),
      m_maxQueueLen(640), 
      m_maxQueueTime(Seconds(1.03)),  
      m_routingTable(),
      m_queue(m_maxQueueLen, m_maxQueueTime),
      m_requestId(0),
      m_lpreqIdCache(m_pathDiscoveryTime),
      m_dpd(m_pathDiscoveryTime),
      m_nb(m_helloInterval),
      m_lpreqCount(0),
      m_htimer(Timer::CANCEL_ON_DESTROY),
      m_lpreqRateLimitTimer(Timer::CANCEL_ON_DESTROY),
      m_bandwidthTimer (Timer::CANCEL_ON_DESTROY),  
      m_usedBandwidth (0), 
      m_usedBandwidthNew (0),  
      m_t (0.75),  
      m_lastBcastTime(Seconds(0)),
      m_vMax(13.89), //50 km/h - set according to scenario
      m_maxD(350.0), 
      m_qTrigger(0.95), 
      m_penalty(0.6), 
      m_reward(1.1), 
      m_sendPrevHello(false) 
{
    m_nb.SetCallback(MakeCallback(&RoutingProtocol::DecreaseQValues, this));
    m_deltadMax = 2*m_vMax*m_helloInterval.GetSeconds(); 
}

TypeId
RoutingProtocol::GetTypeId()
{
    static TypeId tid =
        TypeId("ns3::qdrav::RoutingProtocol")
            .SetParent<Ipv4RoutingProtocol>()
            .SetGroupName("Qdrav")
            .AddConstructor<RoutingProtocol>()
            .AddAttribute("HelloInterval",
                          "HELLO messages emission interval.",
                          TimeValue(Seconds(0.75)),
                          MakeTimeAccessor(&RoutingProtocol::m_helloInterval),
                          MakeTimeChecker())
            .AddAttribute("TtlStart",
                          "Initial TTL value for LPREQ.",
                          UintegerValue(5),
                          MakeUintegerAccessor(&RoutingProtocol::m_ttlStart),
                          MakeUintegerChecker<uint16_t>())
            .AddAttribute("TimeoutBuffer",
                          "Provide a buffer for the timeout.",
                          UintegerValue(2),
                          MakeUintegerAccessor(&RoutingProtocol::m_timeoutBuffer),
                          MakeUintegerChecker<uint16_t>())
            .AddAttribute("LpreqRetries",
                          "Maximum number of retransmissions of LPREQ to discover a route",
                          UintegerValue(2),
                          MakeUintegerAccessor(&RoutingProtocol::m_lpreqRetries),
                          MakeUintegerChecker<uint32_t>())
            .AddAttribute("LpreqRateLimit",
                          "Maximum number of LPREQ per second.",
                          UintegerValue(10),
                          MakeUintegerAccessor(&RoutingProtocol::m_lpreqRateLimit),
                          MakeUintegerChecker<uint32_t>())
            .AddAttribute("NodeTraversalTime",
                          "Conservative estimate of the average one hop traversal time for packets "
                          "and should include "
                          "queuing delays, interrupt processing times and transfer times.",
                          TimeValue(MilliSeconds(40)),
                          MakeTimeAccessor(&RoutingProtocol::m_nodeTraversalTime),
                          MakeTimeChecker())
            .AddAttribute("NetDiameter",
                          "Net diameter measures the maximum possible number of hops between two "
                          "nodes in the network",
                          UintegerValue(35),
                          MakeUintegerAccessor(&RoutingProtocol::m_netDiameter),
                          MakeUintegerChecker<uint32_t>())
            .AddAttribute("NetTraversalTime",
                          "Estimate of the average net traversal time = 2 * NodeTraversalTime * NetDiameter",
                          TimeValue(Seconds(2.8)),
                          MakeTimeAccessor(&RoutingProtocol::m_netTraversalTime),
                          MakeTimeChecker())
            .AddAttribute("PathDiscoveryTime",
                          "Estimate of maximum time needed to find route in network = 2 * NetTraversalTime",
                          TimeValue(Seconds(5.6)),
                          MakeTimeAccessor(&RoutingProtocol::m_pathDiscoveryTime),
                          MakeTimeChecker())
            .AddAttribute("MaxQueueLen",
                          "Maximum number of packets that we allow a routing protocol to buffer.",
                          UintegerValue(640),
                          MakeUintegerAccessor(&RoutingProtocol::SetMaxQueueLen,
                                               &RoutingProtocol::GetMaxQueueLen),
                          MakeUintegerChecker<uint32_t>())
            .AddAttribute("MaxQueueTime",
                          "Maximum time packets can be queued (in seconds)",
                          TimeValue(Seconds(1.03)),  
                          MakeTimeAccessor(&RoutingProtocol::SetMaxQueueTime,
                                           &RoutingProtocol::GetMaxQueueTime),
                          MakeTimeChecker())
            .AddAttribute("EnableBroadcast",
                          "Indicates whether a broadcast data packets forwarding enable.",
                          BooleanValue(true),
                          MakeBooleanAccessor(&RoutingProtocol::SetBroadcastEnable,
                                              &RoutingProtocol::GetBroadcastEnable),
                          MakeBooleanChecker())
            .AddAttribute("UniformRv",
                          "Access to the underlying UniformRandomVariable",
                          StringValue("ns3::UniformRandomVariable"),
                          MakePointerAccessor(&RoutingProtocol::m_uniformRandomVariable),
                          MakePointerChecker<UniformRandomVariable>())	
            .AddAttribute ("vMax", "Maximum vehicle velocity",
                          DoubleValue (13.89),
                          MakeDoubleAccessor (&RoutingProtocol::m_vMax),
                          MakeDoubleChecker<double> ())
            .AddAttribute ("T", "Time period for BW calculation",
                          DoubleValue (0.75),
                          MakeDoubleAccessor (&RoutingProtocol::m_t),
                          MakeDoubleChecker<double> ())
            .AddAttribute ("maxD", "Maximum diametar",
                          DoubleValue (350.0),
                          MakeDoubleAccessor (&RoutingProtocol::m_maxD),
                          MakeDoubleChecker<double> ())
            .AddAttribute ("qTrigger", "Trigger for RPP",
                          DoubleValue (0.95),
                          MakeDoubleAccessor (&RoutingProtocol::m_qTrigger),
                          MakeDoubleChecker<double> ())
            .AddAttribute ("penalty", "Penalty for not receiving RPP_ACK",
                          DoubleValue (0.6),
                          MakeDoubleAccessor (&RoutingProtocol::m_penalty),
                          MakeDoubleChecker<double> ())
            .AddAttribute ("reward", "Reward for next hop with max RQ",
                          DoubleValue (1.1),
                          MakeDoubleAccessor (&RoutingProtocol::m_reward),
                          MakeDoubleChecker<double> ())
            ;					
    return tid;
}

void
RoutingProtocol::SetMaxQueueLen(uint32_t len)
{
    m_maxQueueLen = len;
    m_queue.SetMaxQueueLen(len);
}

void
RoutingProtocol::SetMaxQueueTime(Time t)
{
    m_maxQueueTime = t;
    m_queue.SetQueueTimeout(t);
}

RoutingProtocol::~RoutingProtocol()
{
}

void
RoutingProtocol::DoDispose()
{
    m_ipv4 = nullptr;
    for (std::map<Ptr<Socket>, Ipv4InterfaceAddress>::iterator iter = m_socketAddresses.begin();
         iter != m_socketAddresses.end();
         iter++)
    {
        iter->first->Close();
    }
    m_socketAddresses.clear();
    for (std::map<Ptr<Socket>, Ipv4InterfaceAddress>::iterator iter =
             m_socketSubnetBroadcastAddresses.begin();
         iter != m_socketSubnetBroadcastAddresses.end();
         iter++)
    {
        iter->first->Close();
    }
    m_socketSubnetBroadcastAddresses.clear();
    Ipv4RoutingProtocol::DoDispose();
}

void
RoutingProtocol::PrintRoutingTable(Ptr<OutputStreamWrapper> stream, Time::Unit unit) const
{
    *stream->GetStream() << "Node: " << m_ipv4->GetObject<Node>()->GetId()
                         << "; Time: " << Now().As(unit)
                         << ", Local time: " << m_ipv4->GetObject<Node>()->GetLocalTime().As(unit)
                         << ", Q-DRAV Routing table" << std::endl;

    m_routingTable.Print(stream, unit);
    *stream->GetStream() << std::endl;
}

int64_t
RoutingProtocol::AssignStreams(int64_t stream)
{
    NS_LOG_FUNCTION(this << stream);
    m_uniformRandomVariable->SetStream(stream);
    return 1;
}

void
RoutingProtocol::Start()
{
    NS_LOG_FUNCTION(this);
    m_nb.ScheduleTimer();

    m_lpreqRateLimitTimer.SetFunction(&RoutingProtocol::LpreqRateLimitTimerExpire, this);
    m_lpreqRateLimitTimer.Schedule(Seconds(1));

    m_bandwidthTimer.SetFunction (&RoutingProtocol::BandwidthTimerExpire,this); 
    m_bandwidthTimer.Schedule (Seconds (m_t)); 

    m_rppTimer.SetFunction(&RoutingProtocol::RppTimerExpire, this);

    if (m_dst.empty())
    {
      for (NodeList::Iterator it = NodeList::Begin (); it < NodeList::End (); it++)
      {
        Ptr<Ipv4> ipv4 = (*it)->GetObject<Ipv4> ();
        Ipv4InterfaceAddress iaddr = ipv4->GetAddress (1,0); 
        Ipv4Address ipAddr = iaddr.GetLocal (); 
        uint16_t id = (uint16_t)(*it)->GetId();
        m_dst.insert (std::make_pair(ipAddr, id));
        NS_LOG_DEBUG("Node list element: ID = " << id << ", IP = " << ipAddr);
      }
    }
}

Ptr<Ipv4Route>
RoutingProtocol::RouteOutput(Ptr<Packet> p,
                             const Ipv4Header& header,
                             Ptr<NetDevice> oif,
                             Socket::SocketErrno& sockerr)
{
    NS_LOG_FUNCTION(this << header << (oif ? oif->GetIfIndex() : 0));
    if (!p)
    {
        NS_LOG_DEBUG("Packet is == 0");
        return LoopbackRoute(header, oif); // later
    }
    if (m_socketAddresses.empty())
    {
        sockerr = Socket::ERROR_NOROUTETOHOST;
        NS_LOG_LOGIC("No qdrav interfaces");
        Ptr<Ipv4Route> route;
        return route;
    }
    sockerr = Socket::ERROR_NOTERROR;
    Ptr<Ipv4Route> route;
    Ipv4Address dst = header.GetDestination();
    QTableEntry qrt; 
    if (m_qTable.FindRouteToDstWithMaxQValueViaNeigbor (dst, m_nb, qrt) && qrt.GetQValue () > 0) 
    {
        route = qrt.GetRoute();  
        NS_ASSERT(route);
    
        NS_LOG_LOGIC("Exist route to " << route->GetDestination() << " from interface " << route->GetSource());
        if (oif && route->GetOutputDevice() != oif)
        {
            NS_LOG_DEBUG("Output device doesn't match. Dropped.");
            sockerr = Socket::ERROR_NOROUTETOHOST;
            return Ptr<Ipv4Route>();
        }
        
        
        if (!m_rppTimer.IsRunning())
        {
            TypeHeader tHeader;
            p->PeekHeader(tHeader); 
            if(!tHeader.IsValid()) 
            {
                SendRpp(dst); 
            }
            else
            {
                NS_LOG_DEBUG("Control packet, do not send RPP");
            }
            
        }
                
        return route; 
    }

    // Valid route not found, in this case we return loopback.
    // Actual route request will be deferred until packet will be fully formed,
    // routed to loopback, received from loopback and passed to RouteInput (see below)
    uint32_t iif = (oif ? m_ipv4->GetInterfaceForDevice(oif) : -1);
    DeferredRouteOutputTag tag(iif);
    NS_LOG_DEBUG("Q-value > 0 not found");
    if (!p->PeekPacketTag(tag))
    {
        p->AddPacketTag(tag);
    }
    return LoopbackRoute(header, oif);
}

void
RoutingProtocol::DeferredRouteOutput(Ptr<const Packet> p,
                                     const Ipv4Header& header,
                                     UnicastForwardCallback ucb,
                                     ErrorCallback ecb)
{
    NS_LOG_FUNCTION(this << p << header);
    NS_ASSERT(p && p != Ptr<Packet>());

    QueueEntry newEntry(p, header, ucb, ecb);
    bool result = m_queue.Enqueue(newEntry);
    if (result)
    {
        NS_LOG_LOGIC("Add packet " << p->GetUid() << " to queue. Protocol "
                                   << (uint16_t)header.GetProtocol());
        RoutingTableEntry rt;
        bool result = m_routingTable.LookupRoute(header.GetDestination(), rt);       
        if (!result)
        {
            NS_LOG_LOGIC("Send new LPREQ for outbound packet to " << header.GetDestination());
            Ipv4Address dst = header.GetDestination();
            if (m_addressReqTimer.find(dst) == m_addressReqTimer.end())
            {
                Timer timer(Timer::CANCEL_ON_DESTROY);
                m_addressReqTimer[dst] = timer;
            }
            m_addressReqTimer[dst].SetFunction(&RoutingProtocol::RouteRequestTimerExpire, this);
            m_addressReqTimer[dst].Cancel();
            m_addressReqTimer[dst].SetArguments(dst);
            m_addressReqTimer[dst].Schedule(m_helloInterval);
            //SendRequest(header.GetDestination());  //LPREQ is not used in simulations, it is possible to add it
        }
    }
}

bool
RoutingProtocol::RouteInput(Ptr<const Packet> p,
                            const Ipv4Header& header,
                            Ptr<const NetDevice> idev,
                            UnicastForwardCallback ucb,
                            MulticastForwardCallback mcb,
                            LocalDeliverCallback lcb,
                            ErrorCallback ecb)
{
    NS_LOG_FUNCTION(this << p->GetUid() << header.GetDestination() << idev->GetAddress());
    if (m_socketAddresses.empty())
    {
        NS_LOG_LOGIC("No qdrav interfaces");
        return false;
    }
    NS_ASSERT(m_ipv4);
    NS_ASSERT(p);
    // Check if input device supports IP
    NS_ASSERT(m_ipv4->GetInterfaceForDevice(idev) >= 0);
    int32_t iif = m_ipv4->GetInterfaceForDevice(idev);

    Ipv4Address dst = header.GetDestination();
    Ipv4Address origin = header.GetSource();

    // Deferred route request
    if (idev == m_lo)
    {
        DeferredRouteOutputTag tag;
        if (p->PeekPacketTag(tag))
        {
            DeferredRouteOutput(p, header, ucb, ecb);
            return true;
        }
    }

    m_usedBandwidthNew += p->GetSize ();

    // Duplicate of own packet
    if (IsMyOwnAddress(origin))
    {
        return true;
    }

    // AODV is not a multicast routing protocol
    if (dst.IsMulticast())
    {
        return false;
    }

    // Broadcast local delivery/forwarding
    for (std::map<Ptr<Socket>, Ipv4InterfaceAddress>::const_iterator j = m_socketAddresses.begin();
         j != m_socketAddresses.end();
         ++j)
    {
        Ipv4InterfaceAddress iface = j->second;
        if (m_ipv4->GetInterfaceForAddress(iface.GetLocal()) == iif)
        {
            if (dst == iface.GetBroadcast() || dst.IsBroadcast())
            {
                if (m_dpd.IsDuplicate(p, header))
                {
                    NS_LOG_DEBUG("Duplicated packet " << p->GetUid() << " from " << origin
                                                      << ". Drop.");
                    return true;
                }
                Ptr<Packet> packet = p->Copy();
                if (lcb.IsNull() == false)
                {
                    NS_LOG_LOGIC("Broadcast local delivery to " << iface.GetLocal());
                    lcb(p, header, iif);
                    // Fall through to additional processing
                }
                else
                {
                    NS_LOG_ERROR("Unable to deliver packet locally due to null callback "
                                 << p->GetUid() << " from " << origin);
                    ecb(p, header, Socket::ERROR_NOROUTETOHOST);
                }
                if (!m_enableBroadcast)
                {
                    return true;
                }
                if (header.GetProtocol() == UdpL4Protocol::PROT_NUMBER)
                {
                    UdpHeader udpHeader;
                    p->PeekHeader(udpHeader);
                    if (udpHeader.GetDestinationPort() == AODV_PORT)
                    {
                        // AODV packets sent in broadcast are already managed
                        return true;
                    }
                }
                if (header.GetTtl() > 1)
                {
                    NS_LOG_LOGIC("Forward broadcast. TTL " << (uint16_t)header.GetTtl());
                    RoutingTableEntry toBroadcast;
                    if (m_routingTable.LookupRoute(dst, toBroadcast)) 
                    {
                        m_usedBandwidthNew += packet->GetSize ();  
                        Ptr<Ipv4Route> route = toBroadcast.GetRoute();
                        ucb(route, packet, header);
                    }
                    else
                    {
                        NS_LOG_DEBUG("No route to forward broadcast. Drop packet " << p->GetUid());
                    }
                }
                else
                {
                    NS_LOG_DEBUG("TTL exceeded. Drop packet " << p->GetUid());
                }
                return true;
            }
        }
    }

    // Unicast local delivery
    if (m_ipv4->IsDestinationAddress(dst, iif))
    {
        if (lcb.IsNull() == false)
        {
            NS_LOG_LOGIC("Unicast local delivery to " << dst);
            lcb(p, header, iif);
        }
        else
        {
            NS_LOG_ERROR("Unable to deliver packet locally due to null callback "
                         << p->GetUid() << " from " << origin);
            ecb(p, header, Socket::ERROR_NOROUTETOHOST);
        }
        return true;
    }

    // Check if input device supports IP forwarding
    if (m_ipv4->IsForwarding(iif) == false)
    {
        NS_LOG_LOGIC("Forwarding disabled for this interface");
        ecb(p, header, Socket::ERROR_NOROUTETOHOST);
        return true;
    }

    // Forwarding
    return Forwarding(p, header, ucb, ecb);
}

bool
RoutingProtocol::Forwarding(Ptr<const Packet> p, 
                            const Ipv4Header& header,
                            UnicastForwardCallback ucb,
                            ErrorCallback ecb)
{
    NS_LOG_FUNCTION(this);
    Ipv4Address dst = header.GetDestination();
    Ipv4Address origin = header.GetSource();
    QTableEntry toDst;
    if (m_qTable.FindRouteToDstWithMaxQValueViaNeigbor(dst, m_nb, toDst))
    {
        Ptr<Ipv4Route> route = toDst.GetRoute();
        NS_LOG_LOGIC(route->GetSource() << " forwarding to " << dst << " from " << origin
                                        << " packet " << p->GetUid());
            
        m_usedBandwidthNew += p->GetSize ();  
        
        ucb(route, p, header);

        return true;
    }   
    
    NS_LOG_LOGIC("Route not found to " << dst);
    NS_LOG_DEBUG("Drop packet " << p->GetUid() << " because no route to forward it.");
    return false;
}

void
RoutingProtocol::SetIpv4(Ptr<Ipv4> ipv4)
{
    NS_ASSERT(ipv4);
    NS_ASSERT(!m_ipv4);

    m_ipv4 = ipv4;

    // Create lo route. It is asserted that the only one interface up for now is loopback
    NS_ASSERT(m_ipv4->GetNInterfaces() == 1 &&
              m_ipv4->GetAddress(0, 0).GetLocal() == Ipv4Address("127.0.0.1"));
    m_lo = m_ipv4->GetNetDevice(0);
    NS_ASSERT(m_lo);
    // Remember lo route
    RoutingTableEntry rt(
        /*dev=*/m_lo,
        /*dst=*/Ipv4Address::GetLoopback(),
        /*iface=*/Ipv4InterfaceAddress(Ipv4Address::GetLoopback(), Ipv4Mask("255.0.0.0")),
        /*nextHop=*/Ipv4Address::GetLoopback(),
        /*lifetime=*/Simulator::GetMaximumSimulationTime(),
        /*flag=*/VALID);
    m_routingTable.AddRoute(rt);

    Simulator::ScheduleNow(&RoutingProtocol::Start, this);
}

void
RoutingProtocol::NotifyInterfaceUp(uint32_t i)
{
    NS_LOG_FUNCTION(this << m_ipv4->GetAddress(i, 0).GetLocal());
    Ptr<Ipv4L3Protocol> l3 = m_ipv4->GetObject<Ipv4L3Protocol>();
    if (l3->GetNAddresses(i) > 1)
    {
        NS_LOG_WARN("Q-DRAV does not work with more then one address per each interface.");
    }
    Ipv4InterfaceAddress iface = l3->GetAddress(i, 0);
    if (iface.GetLocal() == Ipv4Address("127.0.0.1"))
    {
        return;
    }

    // Create a socket to listen only on this interface
    Ptr<Socket> socket = Socket::CreateSocket(GetObject<Node>(), UdpSocketFactory::GetTypeId());
    NS_ASSERT(socket);
    socket->SetRecvCallback(MakeCallback(&RoutingProtocol::RecvAodv, this));
    socket->BindToNetDevice(l3->GetNetDevice(i));
    socket->Bind(InetSocketAddress(iface.GetLocal(), AODV_PORT));
    socket->SetAllowBroadcast(true);
    socket->SetIpRecvTtl(true);
    m_socketAddresses.insert(std::make_pair(socket, iface));

    // create also a subnet broadcast socket
    socket = Socket::CreateSocket(GetObject<Node>(), UdpSocketFactory::GetTypeId());
    NS_ASSERT(socket);
    socket->SetRecvCallback(MakeCallback(&RoutingProtocol::RecvAodv, this));
    socket->BindToNetDevice(l3->GetNetDevice(i));
    socket->Bind(InetSocketAddress(iface.GetBroadcast(), AODV_PORT));
    socket->SetAllowBroadcast(true);
    socket->SetIpRecvTtl(true);
    m_socketSubnetBroadcastAddresses.insert(std::make_pair(socket, iface));

    // Add local broadcast record to the routing table
    Ptr<NetDevice> dev = m_ipv4->GetNetDevice(m_ipv4->GetInterfaceForAddress(iface.GetLocal()));
    RoutingTableEntry rt(/*dev=*/dev,
                         /*dst=*/iface.GetBroadcast(),
                         /*iface=*/iface,
                         /*nextHop=*/iface.GetBroadcast(),
                         /*lifetime=*/Simulator::GetMaximumSimulationTime(),
                         /*flag=*/VALID);
    m_routingTable.AddRoute(rt);

    if (l3->GetInterface(i)->GetArpCache())
    {
        m_nb.AddArpCache(l3->GetInterface(i)->GetArpCache());
    }

    // Allow neighbor manager use this interface for layer 2 feedback if possible
    Ptr<WifiNetDevice> wifi = dev->GetObject<WifiNetDevice>();
    if (!wifi)
    {
        return;
    }
    Ptr<WifiMac> mac = wifi->GetMac();
    if (!mac)
    {
        return;
    }

    mac->TraceConnectWithoutContext("DroppedMpdu",
                                    MakeCallback(&RoutingProtocol::NotifyTxError, this));
}

void
RoutingProtocol::NotifyTxError(WifiMacDropReason reason, Ptr<const WifiMpdu> mpdu)
{
    m_nb.GetTxErrorCallback()(mpdu->GetHeader());   //calling function Neighbors::ProcessTxError
}

void
RoutingProtocol::NotifyInterfaceDown(uint32_t i)
{
    NS_LOG_FUNCTION(this << m_ipv4->GetAddress(i, 0).GetLocal());

    // Disable layer 2 link state monitoring (if possible)
    Ptr<Ipv4L3Protocol> l3 = m_ipv4->GetObject<Ipv4L3Protocol>();
    Ptr<NetDevice> dev = l3->GetNetDevice(i);
    Ptr<WifiNetDevice> wifi = dev->GetObject<WifiNetDevice>();
    if (wifi)
    {
        Ptr<WifiMac> mac = wifi->GetMac()->GetObject<AdhocWifiMac>();
        if (mac)
        {
            mac->TraceDisconnectWithoutContext("DroppedMpdu",
                                               MakeCallback(&RoutingProtocol::NotifyTxError, this));
            m_nb.DelArpCache(l3->GetInterface(i)->GetArpCache());
        }
    }

    // Close socket
    Ptr<Socket> socket = FindSocketWithInterfaceAddress(m_ipv4->GetAddress(i, 0));
    NS_ASSERT(socket);
    socket->Close();
    m_socketAddresses.erase(socket);

    // Close socket
    socket = FindSubnetBroadcastSocketWithInterfaceAddress(m_ipv4->GetAddress(i, 0));
    NS_ASSERT(socket);
    socket->Close();
    m_socketSubnetBroadcastAddresses.erase(socket);

    if (m_socketAddresses.empty())
    {
        NS_LOG_LOGIC("No aodv interfaces");
        m_htimer.Cancel();
        m_nb.Clear();
        m_routingTable.Clear();
        m_qTable.Clear(); 
        return;
    }
    m_routingTable.DeleteAllRoutesFromInterface(m_ipv4->GetAddress(i, 0));
    m_qTable.DeleteAllRoutesFromInterface(m_ipv4->GetAddress(i, 0)); 
}

void
RoutingProtocol::NotifyAddAddress(uint32_t i, Ipv4InterfaceAddress address)
{
    NS_LOG_FUNCTION(this << " interface " << i << " address " << address);
    Ptr<Ipv4L3Protocol> l3 = m_ipv4->GetObject<Ipv4L3Protocol>();
    if (!l3->IsUp(i))
    {
        return;
    }
    if (l3->GetNAddresses(i) == 1)
    {
        Ipv4InterfaceAddress iface = l3->GetAddress(i, 0);
        Ptr<Socket> socket = FindSocketWithInterfaceAddress(iface);
        if (!socket)
        {
            if (iface.GetLocal() == Ipv4Address("127.0.0.1"))
            {
                return;
            }
            // Create a socket to listen only on this interface
            Ptr<Socket> socket =
                Socket::CreateSocket(GetObject<Node>(), UdpSocketFactory::GetTypeId());
            NS_ASSERT(socket);
            socket->SetRecvCallback(MakeCallback(&RoutingProtocol::RecvAodv, this));
            socket->BindToNetDevice(l3->GetNetDevice(i));
            socket->Bind(InetSocketAddress(iface.GetLocal(), AODV_PORT));
            socket->SetAllowBroadcast(true);
            m_socketAddresses.insert(std::make_pair(socket, iface));

            // create also a subnet directed broadcast socket
            socket = Socket::CreateSocket(GetObject<Node>(), UdpSocketFactory::GetTypeId());
            NS_ASSERT(socket);
            socket->SetRecvCallback(MakeCallback(&RoutingProtocol::RecvAodv, this));
            socket->BindToNetDevice(l3->GetNetDevice(i));
            socket->Bind(InetSocketAddress(iface.GetBroadcast(), AODV_PORT));
            socket->SetAllowBroadcast(true);
            socket->SetIpRecvTtl(true);
            m_socketSubnetBroadcastAddresses.insert(std::make_pair(socket, iface));

            // Add local broadcast record to the routing table
            Ptr<NetDevice> dev =
                m_ipv4->GetNetDevice(m_ipv4->GetInterfaceForAddress(iface.GetLocal()));
            RoutingTableEntry rt(/*dev=*/dev,
                                 /*dst=*/iface.GetBroadcast(),
                                 /*iface=*/iface,
                                 /*nextHop=*/iface.GetBroadcast(),
                                 /*lifetime=*/Simulator::GetMaximumSimulationTime(),
                                 /*flag=*/VALID);
            m_routingTable.AddRoute(rt);
        }
    }
    else
    {
        NS_LOG_LOGIC("Q-DRAV does not work with more then one address per each interface. Ignore "
                     "added address");
    }
}

void
RoutingProtocol::NotifyRemoveAddress(uint32_t i, Ipv4InterfaceAddress address)
{
    NS_LOG_FUNCTION(this);
    Ptr<Socket> socket = FindSocketWithInterfaceAddress(address);
    if (socket)
    {
        m_routingTable.DeleteAllRoutesFromInterface(address);
        m_qTable.DeleteAllRoutesFromInterface(address); 
        socket->Close();
        m_socketAddresses.erase(socket);

        Ptr<Socket> unicastSocket = FindSubnetBroadcastSocketWithInterfaceAddress(address);
        if (unicastSocket)
        {
            unicastSocket->Close();
            m_socketAddresses.erase(unicastSocket);
        }

        Ptr<Ipv4L3Protocol> l3 = m_ipv4->GetObject<Ipv4L3Protocol>();
        if (l3->GetNAddresses(i))
        {
            Ipv4InterfaceAddress iface = l3->GetAddress(i, 0);
            // Create a socket to listen only on this interface
            Ptr<Socket> socket =
                Socket::CreateSocket(GetObject<Node>(), UdpSocketFactory::GetTypeId());
            NS_ASSERT(socket);
            socket->SetRecvCallback(MakeCallback(&RoutingProtocol::RecvAodv, this));
            // Bind to any IP address so that broadcasts can be received
            socket->BindToNetDevice(l3->GetNetDevice(i));
            socket->Bind(InetSocketAddress(iface.GetLocal(), AODV_PORT));
            socket->SetAllowBroadcast(true);
            socket->SetIpRecvTtl(true);
            m_socketAddresses.insert(std::make_pair(socket, iface));

            // create also a unicast socket
            socket = Socket::CreateSocket(GetObject<Node>(), UdpSocketFactory::GetTypeId());
            NS_ASSERT(socket);
            socket->SetRecvCallback(MakeCallback(&RoutingProtocol::RecvAodv, this));
            socket->BindToNetDevice(l3->GetNetDevice(i));
            socket->Bind(InetSocketAddress(iface.GetBroadcast(), AODV_PORT));
            socket->SetAllowBroadcast(true);
            socket->SetIpRecvTtl(true);
            m_socketSubnetBroadcastAddresses.insert(std::make_pair(socket, iface));

            // Add local broadcast record to the routing table
            Ptr<NetDevice> dev =
                m_ipv4->GetNetDevice(m_ipv4->GetInterfaceForAddress(iface.GetLocal()));
            RoutingTableEntry rt(/*dev=*/dev,
                                 /*dst=*/iface.GetBroadcast(),
                                 /*iface=*/iface,
                                 /*nextHop=*/iface.GetBroadcast(),
                                 /*lifetime=*/Simulator::GetMaximumSimulationTime(),
                                 /*flag=*/VALID);
            m_routingTable.AddRoute(rt);
        }
        if (m_socketAddresses.empty())
        {
            NS_LOG_LOGIC("No aodv interfaces");
            m_htimer.Cancel();
            m_nb.Clear();
            m_routingTable.Clear();
            m_qTable.Clear(); 
            return;
        }
    }
    else
    {
        NS_LOG_LOGIC("Remove address not participating in Q-DRAV operation");
    }
}

bool
RoutingProtocol::IsMyOwnAddress(Ipv4Address src)
{
    NS_LOG_FUNCTION(this << src);
    for (std::map<Ptr<Socket>, Ipv4InterfaceAddress>::const_iterator j = m_socketAddresses.begin();
         j != m_socketAddresses.end();
         ++j)
    {
        Ipv4InterfaceAddress iface = j->second;
        if (src == iface.GetLocal())
        {
            return true;
        }
    }
    return false;
}

Ptr<Ipv4Route>
RoutingProtocol::LoopbackRoute(const Ipv4Header& hdr, Ptr<NetDevice> oif) const
{
    NS_LOG_FUNCTION(this << hdr);
    NS_ASSERT(m_lo);
    Ptr<Ipv4Route> rt = Create<Ipv4Route>();
    rt->SetDestination(hdr.GetDestination());
    //
    // Source address selection here is tricky.  The loopback route is
    // returned when AODV does not have a route; this causes the packet
    // to be looped back and handled (cached) in RouteInput() method
    // while a route is found. However, connection-oriented protocols
    // like TCP need to create an endpoint four-tuple (src, src port,
    // dst, dst port) and create a pseudo-header for checksumming.  So,
    // AODV needs to guess correctly what the eventual source address
    // will be.
    //
    // For single interface, single address nodes, this is not a problem.
    // When there are possibly multiple outgoing interfaces, the policy
    // implemented here is to pick the first available AODV interface.
    // If RouteOutput() caller specified an outgoing interface, that
    // further constrains the selection of source address
    //
    std::map<Ptr<Socket>, Ipv4InterfaceAddress>::const_iterator j = m_socketAddresses.begin();
    if (oif)
    {
        // Iterate to find an address on the oif device
        for (j = m_socketAddresses.begin(); j != m_socketAddresses.end(); ++j)
        {
            Ipv4Address addr = j->second.GetLocal();
            int32_t interface = m_ipv4->GetInterfaceForAddress(addr);
            if (oif == m_ipv4->GetNetDevice(static_cast<uint32_t>(interface)))
            {
                rt->SetSource(addr);
                break;
            }
        }
    }
    else
    {
        rt->SetSource(j->second.GetLocal());
    }
    NS_ASSERT_MSG(rt->GetSource() != Ipv4Address(), "Valid source address not found");
    rt->SetGateway(Ipv4Address("127.0.0.1"));
    rt->SetOutputDevice(m_lo);
    return rt;
}


void
RoutingProtocol::SendRequest(Ipv4Address dst)
{
    NS_LOG_FUNCTION(this << dst);
    // A node SHOULD NOT originate more than LPREQ_RATELIMIT RREQ messages per second.
    if (m_lpreqCount == m_lpreqRateLimit)
    {
        Simulator::Schedule(m_lpreqRateLimitTimer.GetDelayLeft() + MicroSeconds(100),
                            &RoutingProtocol::SendRequest,
                            this,
                            dst);
        return;
    }
    else
    {
        m_lpreqCount++;
    }
    // Create RREQ header
    LpreqHeader lpreqHeader;
    Ptr<Node> node = m_ipv4->GetObject<Node>(); 
    lpreqHeader.SetSrcID(node->GetId());  
    lpreqHeader.SetDstID(m_dst[dst]); 
    lpreqHeader.SetNextHopID(0xFFFF); //source node does not have next hop 

    RoutingTableEntry rt;
    
    uint16_t ttl = m_ttlStart;
    if (m_routingTable.LookupRoute(dst, rt))
    {
        ttl = m_netDiameter;
        rt.IncrementLpreqCnt();
        NS_LOG_LOGIC ("Increment rreq count. Count = " << rt.GetLpreqCnt ());

        rt.SetFlag(IN_SEARCH);
        rt.SetLifeTime(m_pathDiscoveryTime);
        m_routingTable.Update(rt);
    }
    else
    {
        Ptr<NetDevice> dev = nullptr;
        RoutingTableEntry newEntry(/*dev=*/dev,
                                   /*dst=*/dst,
                                   /*iface=*/Ipv4InterfaceAddress(),
                                   /*nextHop=*/Ipv4Address(),
                                   /*lifetime=*/m_pathDiscoveryTime,
                                   /*flag=*/IN_SEARCH);
        m_routingTable.AddRoute(newEntry);
    }

    m_requestId++;
    lpreqHeader.SetLpreqID(m_requestId);  
    lpreqHeader.SetQValue (1.0); //direct link q-value = 1

    Ptr<MobilityModel> mob = node->GetObject<MobilityModel>(); 
    Vector pos = mob->GetPosition();
    lpreqHeader.SetXPosition(pos.x); 
    lpreqHeader.SetYPosition(pos.y); 

    // Send LPREQ as subnet directed broadcast from each interface used by qdrav
    for (std::map<Ptr<Socket>, Ipv4InterfaceAddress>::const_iterator j = m_socketAddresses.begin();
         j != m_socketAddresses.end();
         ++j)
    {
        Ptr<Socket> socket = j->first;
        Ipv4InterfaceAddress iface = j->second;

        m_lpreqIdCache.IsDuplicate(iface.GetLocal(), m_requestId);

        Ptr<Packet> packet = Create<Packet>();
        SocketIpTtlTag tag;
        tag.SetTtl(ttl);
        packet->AddPacketTag(tag);
        packet->AddHeader(lpreqHeader);
        TypeHeader tHeader(QDRAVTYPE_LPREQ);
        packet->AddHeader(tHeader);
        // Send to all-hosts broadcast if on /32 addr, subnet-directed otherwise
        Ipv4Address destination;
        if (iface.GetMask() == Ipv4Mask::GetOnes())
        {
            destination = Ipv4Address("255.255.255.255");
        }
        else
        {
            destination = iface.GetBroadcast();
        }
        NS_LOG_DEBUG("Send LPREQ with id " << (int)lpreqHeader.GetLpreqID() << " to socket");
        m_lastBcastTime = Simulator::Now();
        Simulator::Schedule(Time(MilliSeconds(m_uniformRandomVariable->GetInteger(0, 10))),
                            &RoutingProtocol::SendTo,
                            this,
                            socket,
                            packet,
                            destination);
    }
    ScheduleLpreqRetry(dst, ttl);
}


void
RoutingProtocol::SendTo(Ptr<Socket> socket, Ptr<Packet> packet, Ipv4Address destination)
{

    m_usedBandwidthNew += packet->GetSize ();
    socket->SendTo(packet, 0, InetSocketAddress(destination, AODV_PORT));
}

void
RoutingProtocol::ScheduleLpreqRetry(Ipv4Address dst, uint16_t ttl)
{
    NS_LOG_FUNCTION(this << dst);
    if (m_addressReqTimer.find(dst) == m_addressReqTimer.end())
    {
        Timer timer(Timer::CANCEL_ON_DESTROY);
        m_addressReqTimer[dst] = timer;
    }
    m_addressReqTimer[dst].SetFunction(&RoutingProtocol::RouteRequestTimerExpire, this);
    m_addressReqTimer[dst].Cancel();
    m_addressReqTimer[dst].SetArguments(dst);
    RoutingTableEntry rt;
    m_routingTable.LookupRoute(dst, rt);
    NS_LOG_DEBUG("ScheduleLpreqRetry: dst=" << dst << ", RreqCnt=" << int(rt.GetLpreqCnt()));
    Time retry;
    if (ttl < m_netDiameter)
    {
        retry = 2 * m_nodeTraversalTime * (ttl + m_timeoutBuffer);
    }
    else
    {
        NS_ABORT_MSG_UNLESS(rt.GetLpreqCnt() > 0, "Unexpected value for GetRreqCount (): ttl=" << ttl << ", LpreqCnt=" << int(rt.GetLpreqCnt()));
        uint16_t backoffFactor = rt.GetLpreqCnt() - 1;
        NS_LOG_DEBUG("Applying binary exponential backoff factor " << backoffFactor);
        retry = m_netTraversalTime * (1 << backoffFactor);
    }
    m_addressReqTimer[dst].Schedule(retry);
    NS_LOG_DEBUG("Scheduled LPREQ retry in " << retry.As(Time::S));
}

void
RoutingProtocol::RecvAodv(Ptr<Socket> socket)
{
    NS_LOG_FUNCTION(this << socket);

    Address sourceAddress;
    Ptr<Packet> packet = socket->RecvFrom(sourceAddress);
    InetSocketAddress inetSourceAddr = InetSocketAddress::ConvertFrom(sourceAddress);
    Ipv4Address sender = inetSourceAddr.GetIpv4();
    Ipv4Address receiver;

    m_usedBandwidthNew += packet->GetSize ();

    if (m_socketAddresses.find(socket) != m_socketAddresses.end())
    {
        receiver = m_socketAddresses[socket].GetLocal();
    }
    else if (m_socketSubnetBroadcastAddresses.find(socket) !=
             m_socketSubnetBroadcastAddresses.end())
    {
        receiver = m_socketSubnetBroadcastAddresses[socket].GetLocal();
    }
    else
    {
        NS_ASSERT_MSG(false, "Received a packet from an unknown socket");
    }

    TypeHeader tHeader(QDRAVTYPE_LPREQ);
    packet->RemoveHeader(tHeader);
    if (!tHeader.IsValid())
    {
        NS_LOG_DEBUG("Q-DRAV message " << packet->GetUid() << " with unknown type received: "
                                      << tHeader.Get() << ". Drop");
        return; // drop
    }
    switch (tHeader.Get())
    {
        case QDRAVTYPE_LPREQ: 
        {
            RecvRequest(packet, receiver, sender);
            break;
        }
        case QDRAVTYPE_LPREP: 
        {
            RecvReply(packet, receiver, sender);
            break;
        }
        case QDRAVTYPE_HELLO: 
        { 
            RecvHello(packet, receiver, sender);  
            break;
        }
        case QDRAVTYPE_RPP: 
        { 
            RecvRpp(packet, receiver, sender); 
            break;
        }
        case QDRAVTYPE_RPP_ACK: 
        { 
            RecvRppAck(packet, receiver, sender);   
            break;
        }
    }
}

void
RoutingProtocol::RecvRequest(Ptr<Packet> p, Ipv4Address receiver, Ipv4Address neighbor)
{
    NS_LOG_FUNCTION(this);
    LpreqHeader lpreqHeader;
    p->RemoveHeader(lpreqHeader);

    uint16_t originID = lpreqHeader.GetSrcID(); 
    Ipv4Address origin = NodeList::GetNode(originID)->GetObject<Ipv4>()->GetAddress(1,0).GetLocal(); //conversion ID to IP address
    uint16_t dstID = lpreqHeader.GetDstID(); 
    Ipv4Address dst = NodeList::GetNode(dstID)->GetObject<Ipv4>()->GetAddress(1,0).GetLocal(); //conversion ID to IP address
    uint16_t nextHopID = lpreqHeader.GetNextHopID(); 

    uint32_t id = lpreqHeader.GetLpreqID(); 
    double maxQValue = lpreqHeader.GetQValue(); 
    double xN = lpreqHeader.GetXPosition(); 
    double yN = lpreqHeader.GetYPosition(); 

    Ptr<Node> currentNode = m_ipv4->GetObject<Node>();
    Ptr<MobilityModel> mob = currentNode->GetObject<MobilityModel>(); 
    Vector pos = mob->GetPosition();
    double xC = pos.x;   
    double yC = pos.y;
    double dPrim = std::min(sqrt(pow((xN-xC),2.0)+pow((yN-yC),2.0)),m_maxD); 
    /*
     *  Node checks to determine whether it has received a RREQ with the same Originator IP Address
     * and LPREQ ID. If such a LPREQ has been received, the node silently discards the newly received
     * LPREQ.
     */
    if (m_lpreqIdCache.IsDuplicate(origin, id))
    {
        NS_LOG_DEBUG("Ignoring LPREQ due to duplicate");
        return;
    }
    
    m_nb.UpdateAfterReceiveLP(neighbor, 2*m_helloInterval, dPrim); 
    double r;
    double qValueToSrc, qValueToNeighbor;

    if (nextHopID == 0xFFFF)
    {
      NS_ASSERT_MSG (origin == neighbor, "Origin must be equal to neighbor");
      r = 1.0;
    }
    else if (nextHopID == originID)
    {
      r = 0.6;
    }
    else if (nextHopID == currentNode->GetId())
    {
      r = -0.5;
    }
    else
    {
      r = 0.0*0.25*(1-dPrim/m_maxD);
    }
    
    //OutputStreamWrapper s(&std::cout);
    //m_qTable.Print (&s);

    if (!m_qTable.UpdateQTableEntryViaLP(origin, neighbor, r, maxQValue, 2*m_helloInterval, qValueToSrc)) 
    {
        if (r == 1)
        {
            qValueToSrc = 1.0; 
        }
        else 
        { 
            qValueToSrc = 0.6*(r + 0.3*maxQValue); 
            if (qValueToSrc < 0.0) 
            {
                qValueToSrc = 0.0; 
            } 
            else if (qValueToSrc > 1.0) 
            {
                qValueToSrc = 1.0; 
            }
        }
        QTableEntry newEntry(
            /*dst=*/origin,
            /*nextHop*/neighbor,
            /*qValue*/qValueToSrc,
            /*lifetime=*/Time((2 * m_netTraversalTime)), //first time lifetime is higher
            /*iface=*/m_ipv4->GetAddress(m_ipv4->GetInterfaceForAddress(receiver), 0),
            /*dev=*/m_ipv4->GetNetDevice(m_ipv4->GetInterfaceForAddress(receiver)));
        
        m_qTable.AddRoute(newEntry);  
    }
    else 
    {
        QTableEntry qValueToSrc;
        m_qTable.GetRoute(origin, neighbor, qValueToSrc);
    }

    if (origin!=neighbor) 
    {
        if (!m_qTable.UpdateQTableEntryViaLP(neighbor, neighbor, 1, maxQValue, 2*m_helloInterval, qValueToNeighbor))
        {
          qValueToNeighbor = 1.0;
          QTableEntry newEntry(
              /*dst=*/neighbor,
              /*nextHop*/neighbor,
              /*qValue*/qValueToNeighbor,
              /*lifetime=*/Time((2 * m_netTraversalTime)), //first time lifetime is higher
              /*iface=*/m_ipv4->GetAddress(m_ipv4->GetInterfaceForAddress(receiver), 0),
              /*dev=*/m_ipv4->GetNetDevice(m_ipv4->GetInterfaceForAddress(receiver)));
          
          m_qTable.AddRoute(newEntry);
        } 
    }

    NS_LOG_DEBUG(receiver << " receive LPREQ with ID "
                          << (int)lpreqHeader.GetLpreqID () << " to destination " << lpreqHeader.GetDstID ());

    //m_qTable.Print (&s);

    if (IsMyOwnAddress(dst))
    {
        QTableEntry qrt;
        if (m_qTable.FindRouteToDstWithMaxQValueViaNeigbor(origin, m_nb, qrt))
        {
            NS_LOG_DEBUG("Send reply since I am the destination");
            SendReply(lpreqHeader, qrt);
        }
        else
        {
            NS_LOG_DEBUG("Error: no route to origin!");
        }
        
        return;
    }

    QTableEntry qrtToDst;
    QTableEntry qrtToOrigin;
    m_qTable.FindRouteToDstWithMaxQValueViaNeigbor(origin, m_nb, qrtToOrigin);  
    if (m_qTable.FindRouteToDstWithMaxQValueViaNeigbor(dst, m_nb, qrtToDst) && qrtToDst.GetQValue() > 0) 
    {
        /*
         * Drop LPREQ, This node LPREP will make a loop.
         */
        if (qrtToDst.GetNextHop() == neighbor)
        {
            NS_LOG_DEBUG("Drop LPREQ from " << neighbor << ", dest next hop " << qrtToDst.GetNextHop());
            return;
        }

        SendReplyByIntermediateNode(lpreqHeader, qrtToOrigin, qrtToDst); 
        
        return;
    }

    SocketIpTtlTag tag;
    p->RemovePacketTag(tag);
    if (tag.GetTtl() < 2)
    {
        NS_LOG_DEBUG("TTL exceeded. Drop LPREQ origin " << neighbor << " destination " << dst);
        return;
    }

    lpreqHeader.SetNextHopID(m_dst[qrtToOrigin.GetNextHop()]);
    lpreqHeader.SetQValue(qrtToOrigin.GetQValue()); 
    lpreqHeader.SetXPosition(xC); 
    lpreqHeader.SetYPosition(yC);

    for (std::map<Ptr<Socket>, Ipv4InterfaceAddress>::const_iterator j = m_socketAddresses.begin();
         j != m_socketAddresses.end();
         ++j)
    {
        Ptr<Socket> socket = j->first;
        Ipv4InterfaceAddress iface = j->second;
        Ptr<Packet> packet = Create<Packet>();
        SocketIpTtlTag ttl;
        ttl.SetTtl(tag.GetTtl() - 1);
        packet->AddPacketTag(ttl);
        packet->AddHeader(lpreqHeader);
        TypeHeader tHeader(QDRAVTYPE_LPREQ);
        packet->AddHeader(tHeader);
        // Send to all-hosts broadcast if on /32 addr, subnet-directed otherwise
        Ipv4Address destination;
        if (iface.GetMask() == Ipv4Mask::GetOnes())
        {
            destination = Ipv4Address("255.255.255.255");
        }
        else
        {
            destination = iface.GetBroadcast();
        }
        m_lastBcastTime = Simulator::Now();
        Simulator::Schedule(Time(MilliSeconds(m_uniformRandomVariable->GetInteger(0, 10))),
                            &RoutingProtocol::SendTo,
                            this,
                            socket,
                            packet,
                            destination);
        NS_LOG_DEBUG("Node " << receiver << " resend LPREQ to dst " << dst);
    }
}

void
RoutingProtocol::SendReply(const LpreqHeader& lpreqHeader, const QTableEntry& toOrigin)
{
    NS_LOG_FUNCTION(this << toOrigin.GetDestination());

    Ptr<Node> currentNode = m_ipv4->GetObject<Node>();
    Ptr<MobilityModel> mob = currentNode->GetObject<MobilityModel>(); 
    Vector pos = mob->GetPosition();
    double xC = pos.x;  
    double yC = pos.y;

    LprepHeader lprepHeader(/*source=*/lpreqHeader.GetSrcID(),
                            /*dst=*/lpreqHeader.GetDstID(),
                            /*next hop=*/0xFFFF, 
                            /*LPREP ID*/lpreqHeader.GetLpreqID(),
                            /*q-value=*/1.0, 
                            /*x-Pos*/xC,
                            /*y-Pos*/yC);
    Ptr<Packet> packet = Create<Packet>();
    SocketIpTtlTag tag;
    tag.SetTtl(m_netDiameter);  
    packet->AddPacketTag(tag);
    packet->AddHeader(lprepHeader);
    TypeHeader tHeader(QDRAVTYPE_LPREP);
    packet->AddHeader(tHeader);
    Ptr<Socket> socket = FindSocketWithInterfaceAddress(toOrigin.GetInterface());
    NS_ASSERT(socket);
    m_usedBandwidthNew += packet->GetSize (); 
    socket->SendTo(packet, 0, InetSocketAddress(toOrigin.GetNextHop(), AODV_PORT));
}

void
RoutingProtocol::SendReplyByIntermediateNode(const LpreqHeader& lpreqHeader, const QTableEntry& toOrigin, const QTableEntry& toDst)
{
    NS_LOG_FUNCTION(this);

    Ptr<Node> currentNode = m_ipv4->GetObject<Node>();
    Ptr<MobilityModel> mob = currentNode->GetObject<MobilityModel>(); 
    Vector pos = mob->GetPosition();
    double xC = pos.x;  
    double yC = pos.y;

    LprepHeader lprepHeader(/*source=*/lpreqHeader.GetSrcID(),
                            /*dst=*/lpreqHeader.GetDstID(),
                            /*next hop=*/m_dst[toDst.GetNextHop()],
                            /*LPREP ID*/lpreqHeader.GetLpreqID(),
                            /*q-value=*/toDst.GetQValue(), 
                            /*x-Pos*/xC,
                            /*y-Pos*/yC);

    Ptr<Packet> packet = Create<Packet>();
    SocketIpTtlTag tag;
    tag.SetTtl(m_netDiameter);   
    packet->AddPacketTag(tag);
    packet->AddHeader(lprepHeader);
    TypeHeader tHeader(QDRAVTYPE_LPREP);
    packet->AddHeader(tHeader);
    Ptr<Socket> socket = FindSocketWithInterfaceAddress(toOrigin.GetInterface());
    NS_ASSERT(socket);
    m_usedBandwidthNew += packet->GetSize ();
    socket->SendTo(packet, 0, InetSocketAddress(toOrigin.GetNextHop(), AODV_PORT));
    NS_LOG_DEBUG("Intermediate node " << currentNode->GetId() << " send LPREP to origin " << lpreqHeader.GetSrcID());
}

void
RoutingProtocol::RecvReply(Ptr<Packet> p, Ipv4Address receiver, Ipv4Address neighbor)
{
    NS_LOG_FUNCTION(this << " neighbor " << neighbor);
    //OutputStreamWrapper s(&std::cout);
    //m_qTable.Print (&s);
    LprepHeader lprepHeader;
    p->RemoveHeader(lprepHeader);

    uint16_t originID = lprepHeader.GetSrcID(); 
    Ipv4Address origin = NodeList::GetNode(originID)->GetObject<Ipv4>()->GetAddress(1,0).GetLocal(); 
    uint16_t dstID = lprepHeader.GetDstID(); 
    Ipv4Address dst = NodeList::GetNode(dstID)->GetObject<Ipv4>()->GetAddress(1,0).GetLocal(); 
    uint16_t nextHopID = lprepHeader.GetNextHopID(); 
    double maxQValue = lprepHeader.GetQValue(); 
    double xN = lprepHeader.GetXPosition(); 
    double yN = lprepHeader.GetYPosition(); 

    Ptr<Node> currentNode = m_ipv4->GetObject<Node>();
    Ptr<MobilityModel> mob = currentNode->GetObject<MobilityModel>(); 
    Vector pos = mob->GetPosition();
    double xC = pos.x;  
    double yC = pos.y;
    double dPrim = std::min(sqrt(pow((xN-xC),2.0)+pow((yN-yC),2.0)),m_maxD); 

    NS_LOG_DEBUG("LPREP destination " << dst << " LPREP origin " << origin << " LPREP sender " << neighbor);
    
    m_nb.UpdateAfterReceiveLP(neighbor, 2*m_helloInterval, dPrim); 
    double r;
    double qValueToDst, qValueToNeighbor;
    if (nextHopID == 0xFFFF)
    {
      NS_ASSERT_MSG (dst == neighbor, "Destination must be equal to neighbor");
      r = 1.0;
    }

    else if (nextHopID == dstID)
    {
      r = 0.6;
    }

    else if (nextHopID == currentNode->GetId())
    {
      r = -0.5;
    }

    else
    {
      r = 0.0*0.25*(1-dPrim/m_maxD);
    }

    if (!m_qTable.UpdateQTableEntryViaLP(dst, neighbor, r, maxQValue, 2*m_helloInterval, qValueToDst)) 
    {
        if (r == 1)
        {
            qValueToDst = 1.0; 
        }
        else 
        { 
            qValueToDst = 0.6*(r + 0.3*maxQValue); 
            if (qValueToDst < 0.0) 
            {
                qValueToDst = 0.0; 
            } 
            else if (qValueToDst > 1.0) 
            {
                qValueToDst = 1.0; 
            }
        }
        QTableEntry newEntry(
            /*dst=*/dst,
            /*nextHop*/neighbor,
            /*qValue*/qValueToDst,
            /*lifetime=*/Time((2 * m_netTraversalTime)), 
            /*iface=*/m_ipv4->GetAddress(m_ipv4->GetInterfaceForAddress(receiver), 0),
            /*dev=*/m_ipv4->GetNetDevice(m_ipv4->GetInterfaceForAddress(receiver)));
            NS_LOG_DEBUG("Azuriranje q-tabele ka dst ako je novi entry. Interfejs = " << newEntry.GetInterface() << ", device = " << newEntry.GetOutputDevice());
            //newEntry.Print(&s);
        
        m_qTable.AddRoute(newEntry);
    }
    else 
    {
        QTableEntry newEntry;
        m_qTable.GetRoute(dst, neighbor,newEntry);
        NS_LOG_DEBUG("Azuriranje q-tabele ka dst ako je stari entry. Interfejs = " << newEntry.GetInterface() << ", device = " << newEntry.GetOutputDevice());
        //newEntry.Print(&s);
    }

    if (dst!=neighbor) 
    {
        if (!m_qTable.UpdateQTableEntryViaLP(neighbor, neighbor, 1, maxQValue, 2*m_helloInterval, qValueToNeighbor))
        {
          qValueToNeighbor = 1.0; 
          QTableEntry newEntry(
              /*dst=*/neighbor,
              /*nextHop*/neighbor,
              /*qValue*/qValueToNeighbor,
              /*lifetime=*/Time((2 * m_netTraversalTime)), 
              /*iface=*/m_ipv4->GetAddress(m_ipv4->GetInterfaceForAddress(receiver), 0),
              /*dev=*/m_ipv4->GetNetDevice(m_ipv4->GetInterfaceForAddress(receiver)));
          
          m_qTable.AddRoute(newEntry);
        } 
    }

    QTableEntry qrtToDst;
    m_qTable.FindRouteToDstWithMaxQValueViaNeigbor(dst, m_nb, qrtToDst);

    NS_LOG_DEBUG("LPREP receiver " << receiver << ", from neighbor " << neighbor << " for destination " << dst << " to origin " << origin << ", device = " << qrtToDst.GetOutputDevice() << ", iface = " << qrtToDst.GetInterface());
    //qrtToDst.Print(&s);

    //m_qTable.Print (&s);

    if (IsMyOwnAddress(origin))
    {
        RoutingTableEntry toDst;
        if (m_routingTable.LookupRoute(dst, toDst) && toDst.GetFlag() == IN_SEARCH)
        {
            m_addressReqTimer[dst].Cancel();
            m_addressReqTimer.erase(dst);
            m_routingTable.DeleteRoute(dst);
        }

        if (qrtToDst.GetQValue() > 0)
        {
            SendPacketFromQueue(dst, qrtToDst.GetRoute());
        }
        else
        {
            m_queue.DropPacketWithDst(dst);
        }
        return;
    }

    SocketIpTtlTag tag;
    p->RemovePacketTag(tag);
    if (tag.GetTtl() < 2)
    {
        NS_LOG_DEBUG("TTL exceeded. Drop RREP destination " << dst << " origin " << origin);
        return;
    }

    lprepHeader.SetNextHopID(m_dst[qrtToDst.GetNextHop()]); 
    lprepHeader.SetQValue(qrtToDst.GetQValue()); 
    lprepHeader.SetXPosition(xC); 
    lprepHeader.SetYPosition(yC);

    QTableEntry qrtToOrigin;
    if (!m_qTable.FindRouteToDstWithMaxQValueViaNeigbor(origin, m_nb, qrtToOrigin))
    {
        NS_LOG_DEBUG("Error: no route to origin!");
        return;
    }

    Ptr<Packet> packet = Create<Packet>();
    SocketIpTtlTag ttl;
    ttl.SetTtl(tag.GetTtl() - 1);
    packet->AddPacketTag(ttl);
    packet->AddHeader(lprepHeader);
    TypeHeader tHeader(QDRAVTYPE_LPREP);
    packet->AddHeader(tHeader);
    Ptr<Socket> socket = FindSocketWithInterfaceAddress(qrtToOrigin.GetInterface());
    NS_ASSERT(socket);
    m_usedBandwidthNew += packet->GetSize (); 
    socket->SendTo(packet, 0, InetSocketAddress(qrtToOrigin.GetNextHop(), AODV_PORT));
}

void
RoutingProtocol::SendHello()
{
    NS_LOG_FUNCTION (this);

    std::vector<QmaxEntry> maxQValues = m_qTable.GetMaxQValues (m_nb, m_dst);
    
    std::ofstream fileVel;

    double time = Simulator::Now ().GetSeconds ();
    if (time < 1.5)
    {
        fileVel.open ("hello.txt", std::ios::trunc);
        fileVel << "avg n, " << "Hello not sent" << std::endl;
    } 
    else
        fileVel.open ("hello.txt", std::ios::app);

    int n = m_nb.GetAverageNumberOfNeigbors(); 
    //reducing sending rate of HELLO packet
    if (m_sendPrevHello && maxQValues.size() > 250)
    {
        if (n > 25)
        {
            double p = pow(25.0/(double)n,2); 
            Ptr<UniformRandomVariable> x = CreateObject<UniformRandomVariable> ();
            x->SetAttribute ("Min", DoubleValue (0.0));
            x->SetAttribute ("Max", DoubleValue (1.0));
            double value = x->GetValue (); 
            if (value > p)
            {
                fileVel << n << ", 1"<< " \n";
                fileVel.close ();
                m_sendPrevHello = false;
                return; 
            }
        }
    }

    fileVel << n << ", 0"<< " \n";
    fileVel.close ();
    m_sendPrevHello = true;

    
    Ptr<Node> currentNode = m_ipv4->GetObject<Node>();
    Ptr<MobilityModel> mob = currentNode->GetObject<MobilityModel>(); 
    Vector pos = mob->GetPosition();
    double xC = pos.x;   
    double yC = pos.y;

    double normalizedBandwidth = (m_maxUsedBandwidth == 0) ? (1.0) : (m_usedBandwidth/m_maxUsedBandwidth);   
    double bandwidthFactor = 1.0 - normalizedBandwidth;
    bandwidthFactor = (bandwidthFactor > 1.0) ? (1.0) : (bandwidthFactor); 
    bandwidthFactor = (bandwidthFactor < 0.0) ? (0.0) : (bandwidthFactor); 

    for (std::map<Ptr<Socket>, Ipv4InterfaceAddress>::const_iterator j = m_socketAddresses.begin();
         j != m_socketAddresses.end();
         ++j)
    {
        Ptr<Socket> socket = j->first;
        Ipv4InterfaceAddress iface = j->second;
        HelloHeader helloHeader;
        helloHeader.SetXPosition (xC); 
        helloHeader.SetYPosition (yC);  
        helloHeader.SetBandwidthFactor (bandwidthFactor);  
        helloHeader.SetCountOfQMax(maxQValues.size());
        helloHeader.SetQMax (maxQValues); 

        NS_LOG_DEBUG("Poslat Hello");
        //helloHeader.Print(std::cout);

        Ptr<Packet> packet = Create<Packet>();
        SocketIpTtlTag tag;
        tag.SetTtl(1);
        packet->AddPacketTag(tag);
        packet->AddHeader(helloHeader);
        TypeHeader tHeader(QDRAVTYPE_HELLO);
        packet->AddHeader(tHeader);
        // Send to all-hosts broadcast if on /32 addr, subnet-directed otherwise
        Ipv4Address destination;
        if (iface.GetMask() == Ipv4Mask::GetOnes())
        {
            destination = Ipv4Address("255.255.255.255");
        }
        else
        {
            destination = iface.GetBroadcast();
        }
        Time jitter = Time(MilliSeconds(m_uniformRandomVariable->GetInteger(0, 10)));
        Simulator::Schedule(jitter, &RoutingProtocol::SendTo, this, socket, packet, destination);
        m_nb.IncrementCNTs (); 

        // DEBUG ////////////////////////////////////////////////////////////
        NS_LOG_DEBUG ("Node " << iface.GetLocal () << " SEND HELLO");
        
        //OutputStreamWrapper s(&std::cout);
        //helloHeader.Print (std::cout);
        //std::cout << std::endl;
        //std::cout << std::endl;
        //m_qTable.Print (&s);
        //m_routingTable.Print (&s);
        
        ////////////////////////////////////////////////////////////////////////
    }
}

void
RoutingProtocol::RecvHello (Ptr<Packet> p, Ipv4Address receiver, Ipv4Address neighbor)
{
    HelloHeader helloHeader;
    p->RemoveHeader (helloHeader);
    NS_LOG_FUNCTION (this);
    //helloHeader.Print(std::cout);

    double xN = helloHeader.GetXPosition();
    double yN = helloHeader.GetYPosition();
    double bf = helloHeader.GetBandwidthFactor(); 
    std::vector<QmaxEntry> maxQValues = helloHeader.GetQMax(); 

    Ptr<Node> currentNode = m_ipv4->GetObject<Node>();
    Ptr<MobilityModel> mob = currentNode->GetObject<MobilityModel>(); 
    Vector pos = mob->GetPosition();
    double xC = pos.x;   
    double yC = pos.y;
    double dPrim = std::min(sqrt(pow((xN-xC),2.0)+pow((yN-yC),2.0)),m_maxD); 
    NS_LOG_DEBUG("xC = " << xC << ", yC = " << yC << ", dPrim = " << dPrim);

    std::pair<bool, Neighbor> result = m_nb.UpdateAfterReceiveHello(neighbor, 3*m_helloInterval, dPrim); 
    
    double deltaD = 0, alpha, gamma, r, hmrr; 
    if (result.first)
    {
      deltaD = (result.second.m_d - dPrim) * m_helloInterval.GetDouble() / (Simulator::Now().GetDouble() - result.second.m_dt); 
      if (result.second.m_CNTs >= 15) 
      {
          hmrr = std::min<double>(1.0, result.second.m_CNTr/result.second.m_CNTs); 
      }
      else if (result.second.m_CNTs > 0)
      {
          hmrr = std::min<double>(1.0, result.second.m_CNTr/result.second.m_CNTs*(1.0-std::pow(0.5,result.second.m_CNTs))); 
      }
      else
      {
          hmrr = 0; 
      }
      alpha = std::max(std::max(0.6, sqrt(abs(deltaD)/m_deltadMax)), sqrt(1-hmrr)); 
      gamma = 0.25 + 0.1*bf; 
    }
    else
    {
      alpha = 0.6; 
      gamma = 0.3;
    }
    
    double qValueToNeighbor, qValueToDst;

    if (!m_qTable.UpdateQTableEntryViaHello(neighbor, neighbor, alpha, gamma, 1.0, 1.0, 3*m_helloInterval, qValueToNeighbor)) 
    {
        qValueToNeighbor = 1.0; //direct link
        QTableEntry newEntry(
            /*dst=*/neighbor,
            /*nextHop*/neighbor,
            /*qValue*/qValueToNeighbor,
            /*lifetime=*/Time((3 * m_helloInterval)), 
            /*iface=*/m_ipv4->GetAddress(m_ipv4->GetInterfaceForAddress(receiver), 0),
            /*dev=*/m_ipv4->GetNetDevice(m_ipv4->GetInterfaceForAddress(receiver)));
        
        m_qTable.AddRoute(newEntry);
    }

    for (std::vector<QmaxEntry>::const_iterator i = maxQValues.begin (); i != maxQValues.end (); ++i) 
    {
        Ipv4Address dst = NodeList::GetNode((*i).dst)->GetObject<Ipv4>()->GetAddress(1,0).GetLocal(); 
        if (i->nextHop == i->dst)
        {
          r = 0.6;
        }
        else if (i->nextHop == currentNode->GetId())
        {
          r = -0.5;
        }
        else
        {
          if (result.first)
          {
            double rA = 0.5 + 0.5*deltaD/m_deltadMax; 
            double rB;
            if (result.second.m_CNTs >= 15) 
            {
                rB = std::min<double>(1.0, result.second.m_CNTr/result.second.m_CNTs); 
            }
            else if (result.second.m_CNTs > 0)
            {
                rB = std::min<double>(1.0, result.second.m_CNTr/result.second.m_CNTs*(1.0-std::pow(0.5,result.second.m_CNTs))); 
            }
            else
            {
                rB = 0; 
            }
            double rC = bf; 
            double rD = 1-dPrim/m_maxD;
            r = 0.0*(rA + rB + rC + rD)/16; 
          }
          else 
          {
            double rD = (1-dPrim/m_maxD)/2;
            r = 0.0*0.5*rD;  
          }  
        }

        if (!IsMyOwnAddress (dst)) 
        {   
            if (!m_qTable.UpdateQTableEntryViaHello(dst, neighbor, alpha, gamma, r, i->qMax, 3*m_helloInterval, qValueToDst)) 
            {
                if (r != -0.5)
                {
                    qValueToDst = alpha*(r + gamma*i->qMax); 
                    QTableEntry newEntry(
                        /*dst=*/dst,
                        /*nextHop*/neighbor,
                        /*qValue*/qValueToDst,
                        /*lifetime=*/Time((3 * m_helloInterval)), 
                        /*iface=*/m_ipv4->GetAddress(m_ipv4->GetInterfaceForAddress(receiver), 0),
                        /*dev=*/m_ipv4->GetNetDevice(m_ipv4->GetInterfaceForAddress(receiver)));
                    
                    m_qTable.AddRoute(newEntry);
                }
                
            }
        }
    } 

    // DEBUG ////////////////////////////////////////////////////////////
    NS_LOG_DEBUG ("Node " << receiver << " RECEIVED HELLO form " << neighbor);
    
    //OutputStreamWrapper s(&std::cout);
    //helloHeader.Print (std::cout);
    //m_qTable.Print (&s);
    //m_routingTable.Print (&s);
    
    ////////////////////////////////////////////////////////////////////////
}

void
RoutingProtocol::SendRpp(Ipv4Address dst)
{
    NS_LOG_FUNCTION (this);
    if (m_rppTimer.IsRunning())
    {
        return;
    }

    QTableEntry toDst;
    if (!m_qTable.FindRouteToDstWithMaxQValueViaNeigbor(dst, m_nb, toDst))
    {
        return; 
    }

    double maxQValue = toDst.GetQValue(); 
    std::vector<QTableEntry> highValuesQTable;
    
    //OutputStreamWrapper s(&std::cout);
    //m_routingTable.Print (&s);
    //m_qTable.Print (&s);
    m_qTable.FindRoutesWithHihgQValuesViaNeighbor(dst, m_nb, maxQValue, m_qTrigger, highValuesQTable);
    if (highValuesQTable.size() <= 1)
    {
        NS_LOG_DEBUG("highValuesQTable <= 1");
        return;
    }

    m_rqTable.SetDestination(dst); 
    m_rqTable.SetSendTime(Simulator::Now());                 
    m_rppTimer.Schedule(Seconds(1)); 

    //OutputStreamWrapper s(&std::cout);

    std::vector<uint16_t> ids;
    ids.insert(ids.end(), m_ipv4->GetObject<Node>()->GetId()); 
    RppHeader rppHeader;
    rppHeader.SetRppSendTime(Simulator::Now().GetSeconds()); 
    rppHeader.SetDestinationID(m_dst[dst]); 
    rppHeader.SetCountOfIDs(1); 
    rppHeader.SetIDs(ids);
    
    std::vector<QTableEntry>::iterator ite;
    for (ite = highValuesQTable.begin (); ite != highValuesQTable.end (); ++ite)
    {
        Ptr<Packet> packet = Create<Packet>();
        SocketIpTtlTag tag;
        tag.SetTtl(m_netDiameter); 
        packet->AddPacketTag(tag);
        packet->AddHeader(rppHeader);
        TypeHeader tHeader(QDRAVTYPE_RPP);
        packet->AddHeader(tHeader);
        Ptr<Socket> socket = FindSocketWithInterfaceAddress(ite->GetInterface());
        NS_ASSERT_MSG(socket, " no socket");
        m_usedBandwidthNew += packet->GetSize (); 
        
        //rppHeader.Print(std::cout);
        socket->SendTo(packet, 0, InetSocketAddress(ite->GetNextHop(), AODV_PORT)); 
        NS_LOG_DEBUG("Poslat RPP!");

        RouteQualityTableEntry rqEntry (ite->GetNextHop()); 
        m_rqTable.AddEntry(rqEntry); 

        // DEBUG ////////////////////////////////////////////////////////////
        //NS_LOG_UNCOND ("Node " << m_ipv4->GetObject<Node>()->GetId() << " SEND RPP via next hop: " << ite->GetNextHop() << " at time " << Simulator::Now().GetSeconds());
        //std::cout << "Node " << m_ipv4->GetObject<Node>()->GetId() << " SEND RPP via next hop: " << ite->GetNextHop() << " at time " << Simulator::Now().GetSeconds() << std::endl;
        
        //rppHeader.Print (std::cout);
        
        //m_routingTable.Print (&s);
        
        ////////////////////////////////////////////////////////////////////////
    }

    //m_qTable.Print (&s);
    //m_rqTable.Print (&s);
}

void
RoutingProtocol::RecvRpp (Ptr<Packet> p, Ipv4Address receiver, Ipv4Address neighbor)
{
    NS_LOG_FUNCTION (this);
    RppHeader rppHeader;
    p->RemoveHeader (rppHeader);
    double rppSendTime = rppHeader.GetRppSendTime(); 
    uint16_t dstID = rppHeader.GetDestinationID(); 
    Ipv4Address dst = NodeList::GetNode(dstID)->GetObject<Ipv4>()->GetAddress(1,0).GetLocal(); 
    
    
    if ((Simulator::Now().GetSeconds() - rppSendTime) > 1.0)
    {
        return; 
    }
    if (IsMyOwnAddress(dst))
    {
        QTableEntry qrt;
        if (m_qTable.GetRoute(neighbor, neighbor, qrt)) 
        {
            NS_LOG_DEBUG("Send RPP_ACK since I am the destination");
            SendRppAck(rppHeader, qrt);
        }
        else
        {
            NS_LOG_DEBUG("Error: no route to origin!");
        } 
        return;
    }
    
    std::vector<uint16_t> ids = rppHeader.GetIDs(); 
    uint16_t currentNodeID = m_ipv4->GetObject<Node>()->GetId(); 
    for (std::vector<uint16_t>::iterator it = ids.begin(); it != ids.end(); it++)
    {
        if (*it == currentNodeID)
        {
            uint16_t nextHopID = *(it+1); 
            Ipv4Address nextHop = NodeList::GetNode(nextHopID)->GetObject<Ipv4>()->GetAddress(1,0).GetLocal(); 
            m_qTable.DeleteRoute(dst,nextHop); 
        }
    }
    QTableEntry toDst;
    if (!m_qTable.FindRouteToDstWithMaxQValueViaNeigbor(dst, m_nb, toDst))
    {
        return; 
    }

    uint8_t countID = rppHeader.GetCountOfIDs(); 
    rppHeader.SetCountOfIDs(countID + 1); 

    ids.insert(ids.end(), currentNodeID); 
    rppHeader.SetIDs(ids); 

    SocketIpTtlTag tag;
    p->RemovePacketTag(tag);
    if (tag.GetTtl() < 2)
    {
        NS_LOG_DEBUG("TTL exceeded. Drop RPP destination " << dst);
        return;
    }
    
    Ptr<Packet> packet = Create<Packet>();
    SocketIpTtlTag ttl;
    ttl.SetTtl(tag.GetTtl() - 1);
    packet->AddPacketTag(ttl);
    packet->AddHeader(rppHeader);
    TypeHeader tHeader(QDRAVTYPE_RPP);
    packet->AddHeader(tHeader);
    Ptr<Socket> socket = FindSocketWithInterfaceAddress(toDst.GetInterface());
    NS_ASSERT(socket);
    m_usedBandwidthNew += packet->GetSize (); 
    socket->SendTo(packet, 0, InetSocketAddress(toDst.GetNextHop(), AODV_PORT));

    // DEBUG ////////////////////////////////////////////////////////////
    //NS_LOG_UNCOND ("Node " << receiver << " SEND RPP to " << toDst.GetNextHop() << " at time " << Simulator::Now().GetSeconds());
    //std::cout << "Node " << receiver << " SEND RPP to " << toDst.GetNextHop() << " at time " << Simulator::Now().GetSeconds() << std::endl;
    
    //OutputStreamWrapper s(&std::cout);
    //rppHeader.Print (std::cout);
    //m_qTable.Print (&s);
    //m_routingTable.Print (&s);
    
    ////////////////////////////////////////////////////////////////////////
}

void
RoutingProtocol::SendRppAck(RppHeader rppHeader, QTableEntry qrt)
{
    NS_LOG_FUNCTION (this);
    
    RppAckHeader rppAckHeader;
    rppAckHeader.SetRppSendTime(rppHeader.GetRppSendTime()); 
    rppAckHeader.SetDestinationID(rppHeader.GetDestinationID()); 
    rppAckHeader.SetRNB(0.0); 
    rppAckHeader.SetCountOfIDs(rppHeader.GetCountOfIDs()); 
    rppAckHeader.SetIDs(rppHeader.GetIDs()); 
    
    Ptr<Packet> packet = Create<Packet>();
    SocketIpTtlTag tag;
    tag.SetTtl(rppAckHeader.GetCountOfIDs()); 
    packet->AddPacketTag(tag);
    packet->AddHeader(rppAckHeader);
    TypeHeader tHeader(QDRAVTYPE_RPP_ACK);
    packet->AddHeader(tHeader);
    Ptr<Socket> socket = FindSocketWithInterfaceAddress(qrt.GetInterface());
    NS_ASSERT(socket);
    m_usedBandwidthNew += packet->GetSize (); 
    socket->SendTo(packet, 0, InetSocketAddress(qrt.GetNextHop(), AODV_PORT));

    // DEBUG ////////////////////////////////////////////////////////////
        //NS_LOG_UNCOND ("Node " << m_ipv4->GetObject<Node>()->GetId() << " SEND RPP_ACK via next hop: " << qrt.GetNextHop());
        //std::cout << "Node " << m_ipv4->GetObject<Node>()->GetId() << " SEND RPP_ACK via next hop: " << qrt.GetNextHop() << std::endl;
        
        //OutputStreamWrapper s(&std::cout);
        //rppHeader.Print (std::cout);
        //m_qTable.Print (&s);
        //m_routingTable.Print (&s);
        
    ////////////////////////////////////////////////////////////////////////
}

void
RoutingProtocol::RecvRppAck (Ptr<Packet> p, Ipv4Address receiver, Ipv4Address neighbor)
{
    NS_LOG_FUNCTION(this);

    RppAckHeader rppAckHeader;
    p->RemoveHeader (rppAckHeader);
    double rppSendTime = rppAckHeader.GetRppSendTime(); 
    if ((Simulator::Now().GetSeconds() - rppSendTime) > 1.0)
    {
        return; 
    }
    uint16_t dstID = rppAckHeader.GetDestinationID(); 
    Ipv4Address dst = NodeList::GetNode(dstID)->GetObject<Ipv4>()->GetAddress(1,0).GetLocal(); 
    double rnb = rppAckHeader.GetRNB(); 
    std::vector<uint16_t> ids = rppAckHeader.GetIDs(); 
    uint16_t srcID = ids[0]; 
    Ipv4Address src = NodeList::GetNode(srcID)->GetObject<Ipv4>()->GetAddress(1,0).GetLocal(); 

    //  A node generates a RPP_ACK 
    if (IsMyOwnAddress(src))
    {
        double hopCount = ids.size(); 
        double roundTripDelay = (Simulator::Now() - m_rqTable.GetSendTime()).GetSeconds()*1000.0;
        double routeQuality = hopCount*hopCount*roundTripDelay*rnb; 
        m_rqTable.UpdateRouteQuality(dst, neighbor, routeQuality); 
        return;
    }
    
    std::vector<uint16_t>::iterator it;
    int nodeCount = 0; 
    uint16_t currentID = m_ipv4->GetObject<Node>()->GetId(); 
    uint16_t nextHopID = 0xFFFF;
    for (it = ids.end(); it != ids.begin(); --it)  
    {
        if(it != ids.end())
        {
            nodeCount++; 
            if (*(it) == currentID) 
            {
                nextHopID = *(--it); 
                break;
            }
        }
        else
        {
            NS_LOG_DEBUG("ids.end()");
        }
    }

    double normalizedBandwidth = (m_maxUsedBandwidth == 0) ? (0.0) : (m_usedBandwidth/m_maxUsedBandwidth);  
    rnb = normalizedBandwidth/nodeCount + (nodeCount-1)*rnb/nodeCount; 
    rppAckHeader.SetRNB(rnb); 
    
    QTableEntry qrt;
    Ipv4Address nextHop = NodeList::GetNode(nextHopID)->GetObject<Ipv4>()->GetAddress(1,0).GetLocal();
    if (!m_qTable.GetRoute(nextHop, nextHop, qrt)) 
    {
        NS_LOG_DEBUG("Drop RPP_ACK since there is no route to the next hop");
        return;
    }

    SocketIpTtlTag tag;
    p->RemovePacketTag(tag);
    if (tag.GetTtl() < 2)
    {
        NS_LOG_DEBUG("TTL exceeded. Drop RPP destination " << dst);
        return;
    }

    Ptr<Packet> packet = Create<Packet>();
    SocketIpTtlTag ttl;
    ttl.SetTtl(tag.GetTtl() - 1);
    packet->AddPacketTag(ttl);
    packet->AddHeader(rppAckHeader);
    TypeHeader tHeader(QDRAVTYPE_RPP_ACK);
    packet->AddHeader(tHeader);
    Ptr<Socket> socket = FindSocketWithInterfaceAddress(qrt.GetInterface());
    NS_ASSERT(socket);
    m_usedBandwidthNew += packet->GetSize (); 
    socket->SendTo(packet, 0, InetSocketAddress(qrt.GetNextHop(), AODV_PORT));

    // DEBUG ////////////////////////////////////////////////////////////
    //NS_LOG_UNCOND ("Node " << receiver << " SEND RPP_ACK to " << qrt.GetNextHop() << " at time " << Simulator::Now().GetSeconds());
    //std::cout << "Node " << receiver << " SEND RPP_ACK to " << qrt.GetNextHop() << " at time " << Simulator::Now().GetSeconds() << std::endl;
    
    //OutputStreamWrapper s(&std::cout);
    //rppAckHeader.Print (std::cout);
    //m_qTable.Print (&s);
    //m_routingTable.Print (&s);
    
    ////////////////////////////////////////////////////////////////////////
}


void
RoutingProtocol::RppTimerExpire()
{
    NS_LOG_FUNCTION(this);

    //OutputStreamWrapper s(&std::cout);
    //m_rqTable.Print (&s);
    //m_rppTimer.Cancel();

    std::vector<RouteQualityTableEntry> entries = m_rqTable.GetEntries(); 
    std::vector<RouteQualityTableEntry>::iterator it;
    double routeQualityMin = -1;
    Ipv4Address nextHop, dst;
    dst = m_rqTable.GetDestination();
    NS_LOG_DEBUG ("RQ table for dst " << dst);
    for (it = entries.begin(); it != entries.end(); it++)
    {
        if (it->m_ack == true)
        {
            if (routeQualityMin == -1)
            {
                routeQualityMin = it->m_routeQuality; 
                nextHop = it->m_nextHop; 
            }
            else if (it->m_routeQuality <= routeQualityMin)
            {
                routeQualityMin = it->m_routeQuality; 
                nextHop = it->m_nextHop; 
            }
        }
        else
        {
            m_qTable.UpdateQTableEntryViaRPP(dst, it->m_nextHop, m_penalty, 3*m_helloInterval); 
        }
    }

    m_qTable.UpdateQTableEntryViaRPP(dst, nextHop, m_reward, 3*m_helloInterval); 

    m_rqTable.ClearEntries(); 

    ////////////////DEBUG/////////////////
    //OutputStreamWrapper s(&std::cout);
    //m_qTable.Print (&s);
    //////////////////////////////////////
}

void
RoutingProtocol::RouteRequestTimerExpire(Ipv4Address dst)
{
    NS_LOG_LOGIC(this);
    QTableEntry toDst;
    if (m_qTable.FindRouteToDstWithMaxQValueViaNeigbor(dst, m_nb, toDst)) 
    {
        SendPacketFromQueue(dst, toDst.GetRoute());
        NS_LOG_LOGIC("route to " << dst << " found");
    }
    m_addressReqTimer[dst].Cancel();
    m_addressReqTimer.erase(dst);
}

void
RoutingProtocol::HelloTimerExpire()
{
    NS_LOG_FUNCTION(this);
    Time offset = Time(Seconds(0));
    /*
    //Hello deferred due to last LPREQ bcast
    if (m_lastBcastTime > Time(Seconds(0)))
    {
        offset = Simulator::Now() - m_lastBcastTime;
        NS_LOG_DEBUG("Hello deferred due to last bcast at:" << m_lastBcastTime);
    }
    else
    {*/
        SendHello();  //we do not have LPREQ in our scenario
    //}
    m_htimer.Cancel();
    Time diff = m_helloInterval - offset;
    m_htimer.Schedule(std::max(Time(Seconds(0)), diff));
    m_lastBcastTime = Time(Seconds(0));
}

void
RoutingProtocol::LpreqRateLimitTimerExpire()
{
    NS_LOG_FUNCTION(this);
    m_lpreqCount = 0;
    m_lpreqRateLimitTimer.Schedule(Seconds(1));
}

void
RoutingProtocol::BandwidthTimerExpire ()
{
  NS_LOG_FUNCTION (this);
  m_usedBandwidth = m_usedBandwidthNew; 
  m_usedBandwidthNew = 0;
  if (m_usedBandwidth > m_maxUsedBandwidth)
  {
    m_maxUsedBandwidth = m_usedBandwidth;
  }
  NS_LOG_DEBUG ("BandwidthTimerExpire: Maximum used bandwidth is " << m_maxUsedBandwidth << ", local used bandwidth is " << m_usedBandwidth);
  m_bandwidthTimer.Schedule (Seconds (m_t));
}

void
RoutingProtocol::SendPacketFromQueue(Ipv4Address dst, Ptr<Ipv4Route> route)
{
    NS_LOG_FUNCTION (this);
    QueueEntry queueEntry;
    while (m_queue.Dequeue(dst, queueEntry))
    {
        DeferredRouteOutputTag tag;
        Ptr<Packet> p = ConstCast<Packet>(queueEntry.GetPacket());
        NS_LOG_DEBUG("Stigao do if");
        if (p->RemovePacketTag(tag) && tag.GetInterface() != -1 &&
            tag.GetInterface() != m_ipv4->GetInterfaceForDevice(route->GetOutputDevice()))
        {
            NS_LOG_DEBUG("Output device doesn't match. Dropped.");
            return;
        }
        UnicastForwardCallback ucb = queueEntry.GetUnicastForwardCallback();
        Ipv4Header header = queueEntry.GetIpv4Header();
        header.SetSource(route->GetSource()); 
        header.SetTtl(header.GetTtl() + 1); // compensate extra TTL decrement by fake loopback routing
        ucb(route, p, header);

        SendRpp (dst); 
    }
}

void
RoutingProtocol::DecreaseQValues(Ipv4Address nextHop, double p)
{
    NS_LOG_FUNCTION (this << nextHop);

    if (p == 0)
    {
        m_qTable.DeleteAllQValuesViaNeighbor(nextHop); 
    }
    else
    {
        m_qTable.DecreaseAllQValuesViaNeighbor (nextHop, p); 
    }
}

Ptr<Socket>
RoutingProtocol::FindSocketWithInterfaceAddress(Ipv4InterfaceAddress addr) const
{
    NS_LOG_FUNCTION (this << addr);
    for (std::map<Ptr<Socket>, Ipv4InterfaceAddress>::const_iterator j = m_socketAddresses.begin();
         j != m_socketAddresses.end();
         ++j)
    {
        Ptr<Socket> socket = j->first;
        Ipv4InterfaceAddress iface = j->second;
        if (iface == addr)
        {
            return socket;
        }
    }
    Ptr<Socket> socket;
    return socket;
}

Ptr<Socket>
RoutingProtocol::FindSubnetBroadcastSocketWithInterfaceAddress(Ipv4InterfaceAddress addr) const
{
    NS_LOG_FUNCTION (this << addr);
    for (std::map<Ptr<Socket>, Ipv4InterfaceAddress>::const_iterator j =
             m_socketSubnetBroadcastAddresses.begin();
         j != m_socketSubnetBroadcastAddresses.end();
         ++j)
    {
        Ptr<Socket> socket = j->first;
        Ipv4InterfaceAddress iface = j->second;
        if (iface == addr)
        {
            return socket;
        }
    }
    Ptr<Socket> socket;
    return socket;
}

void
RoutingProtocol::DoInitialize()
{
    NS_LOG_FUNCTION (this);
    uint32_t startTime;
    m_htimer.SetFunction(&RoutingProtocol::HelloTimerExpire, this);
    startTime = m_uniformRandomVariable->GetInteger(0, 100);
    NS_LOG_DEBUG("Starting at time " << startTime << "ms");
    m_htimer.Schedule(MilliSeconds(startTime));
    Ipv4RoutingProtocol::DoInitialize();
}

} // namespace qdrav
} // namespace ns3
