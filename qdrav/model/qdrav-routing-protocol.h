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
 *
 */
#ifndef QDRAV_ROUTINGPROTOCOL_H
#define QDRAV_ROUTINGPROTOCOL_H

#include "qdrav-dpd.h"
#include "qdrav-neighbor.h"
#include "qdrav-packet.h"
#include "qdrav-rqueue.h"
#include "qdrav-rtable.h"
#include "qdrav-qtable.h"
#include "qdrav-route-quality-table.h"

#include "ns3/ipv4-interface.h"
#include "ns3/ipv4-l3-protocol.h"
#include "ns3/ipv4-routing-protocol.h"
#include "ns3/node.h"
#include "ns3/output-stream-wrapper.h"
#include "ns3/random-variable-stream.h"

#include <map>

namespace ns3
{

class WifiMpdu;
enum WifiMacDropReason : uint8_t; // opaque enum declaration

namespace qdrav
{

/**
 * \ingroup qdrav
 *
 * \brief Q-DRAV routing protocol
 */
class RoutingProtocol : public Ipv4RoutingProtocol
{
  public:
    /**
     * \brief Get the type ID.
     * \return the object TypeId
     */
    static TypeId GetTypeId();
    static const uint32_t AODV_PORT;

    /// constructor
    RoutingProtocol();
    ~RoutingProtocol() override;
    void DoDispose() override;

    // Inherited from Ipv4RoutingProtocol
    Ptr<Ipv4Route> RouteOutput(Ptr<Packet> p,
                               const Ipv4Header& header,
                               Ptr<NetDevice> oif,
                               Socket::SocketErrno& sockerr) override;
    bool RouteInput(Ptr<const Packet> p,
                    const Ipv4Header& header,
                    Ptr<const NetDevice> idev,
                    UnicastForwardCallback ucb,
                    MulticastForwardCallback mcb,
                    LocalDeliverCallback lcb,
                    ErrorCallback ecb) override;
    void NotifyInterfaceUp(uint32_t interface) override;
    void NotifyInterfaceDown(uint32_t interface) override;
    void NotifyAddAddress(uint32_t interface, Ipv4InterfaceAddress address) override;
    void NotifyRemoveAddress(uint32_t interface, Ipv4InterfaceAddress address) override;
    void SetIpv4(Ptr<Ipv4> ipv4) override;   
    void PrintRoutingTable(Ptr<OutputStreamWrapper> stream,
                           Time::Unit unit = Time::S) const override;

    // Handle protocol parameters
    /**
     * Get maximum queue time
     * \returns the maximum queue time
     */
    Time GetMaxQueueTime() const
    {
        return m_maxQueueTime;
    }

    /**
     * Set the maximum queue time
     * \param t the maximum queue time
     */
    void SetMaxQueueTime(Time t);

    /**
     * Get the maximum queue length
     * \returns the maximum queue length
     */
    uint32_t GetMaxQueueLen() const
    {
        return m_maxQueueLen;
    }

    /**
     * Set the maximum queue length
     * \param len the maximum queue length
     */
    void SetMaxQueueLen(uint32_t len);

    /**
     * Set broadcast enable flag
     * \param f enable broadcast flag
     */
    void SetBroadcastEnable(bool f)
    {
        m_enableBroadcast = f;
    }

    /**
     * Get broadcast enable flag
     * \returns the broadcast enable flag
     */
    bool GetBroadcastEnable() const
    {
        return m_enableBroadcast;
    }

    /**
     * Assign a fixed random variable stream number to the random variables
     * used by this model.  Return the number of streams (possibly zero) that
     * have been assigned.
     *
     * \param stream first stream index to use
     * \return the number of stream indices assigned by this model
     */
    int64_t AssignStreams(int64_t stream);

  protected:
    void DoInitialize() override;

  private:
    /**
     * Notify that an MPDU was dropped.
     *
     * \param reason the reason why the MPDU was dropped
     * \param mpdu the dropped MPDU
     */
    void NotifyTxError(WifiMacDropReason reason, Ptr<const WifiMpdu> mpdu);

    // Protocol parameters.
    uint32_t m_lpreqRetries; ///< Maximum number of retransmissions of LPREQ with TTL = NetDiameter to
                            ///< discover a route
    uint16_t m_ttlStart;    ///< Initial TTL value for LPREQ.
    uint16_t m_timeoutBuffer;  ///< Provide a buffer for the timeout.
    uint16_t m_lpreqRateLimit;  ///< Maximum number of LPREQ per second.
    Time m_activeRouteTimeout; ///< Period of time during which the route is considered to be valid.
    uint32_t m_netDiameter; ///< Net diameter measures the maximum possible number of hops between
                            ///< two nodes in the network
    /**
     * NodeTraversalTime is a conservative estimate of the average one hop traversal time for
     * packets and should include queuing delays, interrupt processing times and transfer times.
     */
    Time m_nodeTraversalTime;
    Time m_netTraversalTime;  ///< Estimate of the average net traversal time.
    Time m_pathDiscoveryTime; ///< Estimate of maximum time needed to find route in network.
    /**
     * Every HelloInterval the node checks whether it has sent a broadcast  within the last
     * HelloInterval. If it has not, it MAY broadcast a  Hello message
     */
    Time m_helloInterval;

    uint32_t m_maxQueueLen;  ///< The maximum number of packets that we allow a routing protocol to
                             ///< buffer.
    Time m_maxQueueTime;     ///< The maximum period of time that a routing protocol is allowed to
                             ///< buffer a packet for.

    bool m_enableBroadcast;  ///< Indicates whether a a broadcast data packets forwarding enable
    //\}

    /// IP protocol
    Ptr<Ipv4> m_ipv4;   //P: odavde treba da izvucemo pointer na Node
    /// Raw unicast socket per each IP interface, map socket -> iface address (IP + mask)
    std::map<Ptr<Socket>, Ipv4InterfaceAddress> m_socketAddresses;
    /// Raw subnet directed broadcast socket per each IP interface, map socket -> iface address (IP
    /// + mask)
    std::map<Ptr<Socket>, Ipv4InterfaceAddress> m_socketSubnetBroadcastAddresses;
    /// Loopback device used to defer LPREQ until packet will be fully formed
    Ptr<NetDevice> m_lo;

    /// Routing table
    RoutingTable m_routingTable;

    /// Q table
    QTable m_qTable;
    /// Route quality table
    RouteQualityTable m_rqTable;
    /// A "drop-front" queue used by the routing layer to buffer packets to which it does not have a
    /// route.
    RequestQueue m_queue;
    /// Broadcast ID
    uint32_t m_requestId;
    /// Handle duplicated LPREQ
    IdCache m_lpreqIdCache;
    /// Handle duplicated broadcast/multicast packets
    DuplicatePacketDetection m_dpd;
    /// Handle neighbors
    Neighbors m_nb;
    /// Number of LPREQs used for LPREQ rate control
    uint16_t m_lpreqCount;


  private:
    /// Start protocol operation
    void Start();
    /**
     * Queue packet and send route request
     *
     * \param p the packet to route
     * \param header the IP header
     * \param ucb the UnicastForwardCallback function
     * \param ecb the ErrorCallback function
     */
    void DeferredRouteOutput(Ptr<const Packet> p,
                             const Ipv4Header& header,
                             UnicastForwardCallback ucb,
                             ErrorCallback ecb);
    /**
     * If route exists and is valid, forward packet.
     *
     * \param p the packet to route
     * \param header the IP header
     * \param ucb the UnicastForwardCallback function
     * \param ecb the ErrorCallback function
     * \returns true if forwarded
     */
    bool Forwarding(Ptr<const Packet> p,
                    const Ipv4Header& header,
                    UnicastForwardCallback ucb,
                    ErrorCallback ecb);
    /**
     * Repeated attempts by a source node at route discovery for a single destination
     * use the expanding ring search technique.
     * \param dst the destination IP address
     */
    void ScheduleLpreqRetry(Ipv4Address dst, uint16_t ttl);
    /**
     * Set lifetime field in routing table entry to the maximum of existing lifetime and lt, if the
     * entry exists
     * \param addr destination address
     * \param lt proposed time for lifetime field in routing table entry for destination with
     * address addr.
     * \return true if route to destination address addr exist
     */
    bool UpdateRouteLifeTime(Ipv4Address addr, Time lt);
    /**
     * Update neighbor record.
     * \param receiver is supposed to be my interface
     * \param sender is supposed to be IP address of my neighbor.
     */
    void UpdateRouteToNeighbor(Ipv4Address sender, Ipv4Address receiver);
    /**
     * Test whether the provided address is assigned to an interface on this node
     * \param src the source IP address
     * \returns true if the IP address is the node's IP address
     */
    bool IsMyOwnAddress(Ipv4Address src);
    /**
     * Find unicast socket with local interface address iface
     *
     * \param iface the interface
     * \returns the socket associated with the interface
     */
    Ptr<Socket> FindSocketWithInterfaceAddress(Ipv4InterfaceAddress iface) const;
    /**
     * Find subnet directed broadcast socket with local interface address iface
     *
     * \param iface the interface
     * \returns the socket associated with the interface
     */
    Ptr<Socket> FindSubnetBroadcastSocketWithInterfaceAddress(Ipv4InterfaceAddress iface) const;
    /**
     * Create loopback route for given header
     *
     * \param header the IP header
     * \param oif the output interface net device
     * \returns the route
     */
    Ptr<Ipv4Route> LoopbackRoute(const Ipv4Header& header, Ptr<NetDevice> oif) const;

    ///\name Receive control packets
    //\{
    /**
     * Receive and process control packet
     * \param socket input socket
     */
    void RecvAodv(Ptr<Socket> socket);
    /**
     * Receive LPREQ
     * \param p packet
     * \param receiver receiver address
     * \param neighbor sender address
     */
    void RecvRequest(Ptr<Packet> p, Ipv4Address receiver, Ipv4Address neighbor);
    /**
     * Receive LPREP
     * \param p packet
     * \param my destination address
     * \param src sender address
     */
    void RecvReply(Ptr<Packet> p, Ipv4Address my, Ipv4Address neighbor);

    void RecvHello (Ptr<Packet> p, Ipv4Address my, Ipv4Address neighbor);      

    void RecvRpp (Ptr<Packet> p, Ipv4Address my, Ipv4Address neighbor);       

    void RecvRppAck (Ptr<Packet> p, Ipv4Address my, Ipv4Address neighbor);      
    
    //\}

    ///\name Send
    //\{
    /** Forward packet from route request queue
     * \param dst destination address
     * \param route route to use
     */
    void SendPacketFromQueue(Ipv4Address dst, Ptr<Ipv4Route> route);
    /// Send hello
    void SendHello();
    /// Send RPP
    void SendRpp(Ipv4Address dst);
    /// Send RPP_ACK
    void SendRppAck(RppHeader rppHeader, QTableEntry qrt);
    /** Send LPREQ
     * \param dst destination address
     */
    void SendRequest(Ipv4Address dst);

    /** Send LPREP
     * \param lpreqHeader route request header
     * \param toOrigin routing table entry to originator
     */
    void SendReply(const LpreqHeader& lpreqHeader, const QTableEntry& toOrigin);

        /** Send LPREP by intermediate node
     * \param lpreqHeader route request header
     * \param toOrigin routing table entry to originator
     */
    void SendReplyByIntermediateNode(const LpreqHeader& lpreqHeader, const QTableEntry& toOrigin, const QTableEntry& toDst);

    void DecreaseQValues(Ipv4Address nextHop, double p); 
    /// @}

    /**
     * Send packet to destination socket
     * \param socket destination node socket
     * \param packet packet to send
     * \param destination destination node IP address
     */
    void SendTo(Ptr<Socket> socket, Ptr<Packet> packet, Ipv4Address destination);

    /// Hello timer
    Timer m_htimer;
    /// RPP timer
    Timer m_rppTimer;
    /// Schedule next send of hello message
    void HelloTimerExpire();
    /// Schedule next send of RPP message
    void RppTimerExpire();
    /// LPREQ rate limit timer
    Timer m_lpreqRateLimitTimer;
    /// Reset LPREQ count and schedule RREQ rate limit timer with delay 1 sec.
    void LpreqRateLimitTimerExpire();

    /// bandwidthTimer
    Timer m_bandwidthTimer;   
    /// Reset m_usedBandwidthNew and schedule m_bandwidthTimer with delay m_t.
    void BandwidthTimerExpire (); 
    double m_usedBandwidth;  
    double m_usedBandwidthNew; 
    inline static double m_maxUsedBandwidth = 0;    
    double m_t;  

    /// Map IP address + LPREQ timer.
    std::map<Ipv4Address, Timer> m_addressReqTimer;

    /**
     * Handle route discovery process
     * \param dst the destination IP address
     */
    void RouteRequestTimerExpire(Ipv4Address dst);

    /// Provides uniform random variables.
    Ptr<UniformRandomVariable> m_uniformRandomVariable;
    /// Keep track of the last bcast time
    Time m_lastBcastTime;
    double m_vMax;
    double m_deltadMax;
    double m_maxD;
    std::map<Ipv4Address, uint16_t> m_dst;

    double m_qTrigger;
    double m_penalty;
    double m_reward;
    // Send previous Hello
    bool m_sendPrevHello; 
};

} // namespace qdrav
} // namespace ns3

#endif /* QDRAV_AODVROUTINGPROTOCOL_H */
