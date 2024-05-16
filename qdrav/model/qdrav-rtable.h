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
#ifndef QDRAV_RTABLE_H
#define QDRAV_RTABLE_H

#include "ns3/ipv4-route.h"
#include "ns3/ipv4.h"
#include "ns3/net-device.h"
#include "ns3/output-stream-wrapper.h"
#include "ns3/timer.h"

#include <cassert>
#include <map>
#include <stdint.h>
#include <sys/types.h>

namespace ns3
{
namespace qdrav
{

/**
 * \ingroup qdrav
 * \brief Route record states
 */
enum RouteFlags
{
    VALID = 0,     //!< VALID
    IN_SEARCH = 1, //!< IN_SEARCH
};

/**
 * \ingroup qdrav
 * \brief Routing table entry
 */
class RoutingTableEntry
{
  public:
    /**
     * constructor
     *
     * \param dev the device
     * \param dst the destination IP address/
     * \param iface the interface
     * \param nextHop the IP address of the next hop
     * \param lifetime the lifetime of the entry
     */
    RoutingTableEntry(Ptr<NetDevice> dev = nullptr,
                      Ipv4Address dst = Ipv4Address(),
                      Ipv4InterfaceAddress iface = Ipv4InterfaceAddress(),
                      Ipv4Address nextHop = Ipv4Address(),
                      Time lifetime = Simulator::Now(),
                      RouteFlags flag  = IN_SEARCH); 
                      

    ~RoutingTableEntry();

    // Fields
    /**
     * Get destination address function
     * \returns the IPv4 destination address
     */
    Ipv4Address GetDestination() const
    {
        return m_ipv4Route->GetDestination();
    }

    /**
     * Get route function
     * \returns The IPv4 route
     */
    Ptr<Ipv4Route> GetRoute() const
    {
        return m_ipv4Route;
    }

    /**
     * Set route function
     * \param r the IPv4 route
     */
    void SetRoute(Ptr<Ipv4Route> r)
    {
        m_ipv4Route = r;
    }

    /**
     * Set next hop address
     * \param nextHop the next hop IPv4 address
     */
    void SetNextHop(Ipv4Address nextHop)
    {
        m_ipv4Route->SetGateway(nextHop);
    }

    /**
     * Get next hop address
     * \returns the next hop address
     */
    Ipv4Address GetNextHop() const
    {
        return m_ipv4Route->GetGateway();
    }

    /**
     * Set output device
     * \param dev The output device
     */
    void SetOutputDevice(Ptr<NetDevice> dev)
    {
        m_ipv4Route->SetOutputDevice(dev);
    }

    /**
     * Get output device
     * \returns the output device
     */
    Ptr<NetDevice> GetOutputDevice() const
    {
        return m_ipv4Route->GetOutputDevice();
    }

    /**
     * Get the Ipv4InterfaceAddress
     * \returns the Ipv4InterfaceAddress
     */
    Ipv4InterfaceAddress GetInterface() const
    {
        return m_iface;
    }

    /**
     * Set the Ipv4InterfaceAddress
     * \param iface The Ipv4InterfaceAddress
     */
    void SetInterface(Ipv4InterfaceAddress iface)
    {
        m_iface = iface;
    }

    /**
     * Set the lifetime
     * \param lt The lifetime
     */
    void SetLifeTime(Time lt)
    {
        m_lifeTime = lt + Simulator::Now();
    }

    /**
     * Get the lifetime
     * \returns the lifetime
     */
    Time GetLifeTime() const
    {
        return m_lifeTime - Simulator::Now();
    }

    /**
     * Set the route flags
     * \param flag the route flags
     */
    void SetFlag(RouteFlags flag)
    {
        m_flag = flag;
    }

    /**
     * Get the route flags
     * \returns the route flags
     */
    RouteFlags GetFlag() const
    {
        return m_flag;
    }

    /**
     * Set the LPREQ count
     * \param n the LPREQ count
     */
    void SetLpreqCnt(uint8_t n)
    {
        m_reqCount = n;
    }

    /**
     * Get the LPREQ count
     * \returns the LPREQ count
     */
    uint8_t GetLpreqCnt() const
    {
        return m_reqCount;
    }

    /**
     * Increment the LPREQ count
     */
    void IncrementLpreqCnt()
    {
        m_reqCount++;
    }

    /**
     * \brief Compare destination address
     * \param dst IP address to compare
     * \return true if equal
     */
    bool operator==(const Ipv4Address dst) const
    {
        return (m_ipv4Route->GetDestination() == dst);
    }

    /**
     * Print packet to trace file
     * \param stream The output stream
     * \param unit The time unit to use (default Time::S)
     */
    void Print(Ptr<OutputStreamWrapper> stream, Time::Unit unit = Time::S) const;

  private:
    /**
     * \brief Expiration or deletion time of the route
     * Lifetime field in the routing table plays role:
     * for an valid route it is the delete time
     */
    Time m_lifeTime;
    /** Ip route, include
     *   - destination address
     *   - source address
     *   - next hop address (gateway)
     *   - output device
     */
    Ptr<Ipv4Route> m_ipv4Route;
    /// Output interface address
    Ipv4InterfaceAddress m_iface;
    /// Routing flags: valid, invalid or in search
    RouteFlags m_flag;

    
    /// When I can send another request
    Time m_routeRequestTimout;
    /// Number of route requests
    uint8_t m_reqCount;
};

/**
 * \ingroup qdrav
 * \brief The Routing table used by AODV protocol
 */
class RoutingTable
{
  public:
    /**
     * constructor
     */
    RoutingTable(); 

    /**
     * Add routing table entry if it doesn't yet exist in routing table
     * \param r routing table entry
     * \return true in success
     */
    bool AddRoute(RoutingTableEntry& r);
    /**
     * Delete routing table entry with destination address dst, if it exists.
     * \param dst destination address
     * \return true on success
     */
    bool DeleteRoute(Ipv4Address dst);
    /**
     * Lookup routing table entry with destination address dst
     * \param dst destination address
     * \param rt entry with destination address dst, if exists
     * \return true on success
     */
    bool LookupRoute(Ipv4Address dst, RoutingTableEntry& rt);
    /**
     * Update routing table
     * \param rt entry with destination address dst, if exists
     * \return true on success
     */
    bool Update(RoutingTableEntry& rt);
    /**
     * Delete all route from interface with address iface
     * \param iface the interface IP address
     */
    void DeleteAllRoutesFromInterface(Ipv4InterfaceAddress iface);

    /// Delete all entries from routing table
    void Clear()
    {
        m_ipv4AddressEntry.clear();
    }

    /// Delete all outdated entries and invalidate valid entry if Lifetime is expired
    void Purge();
    /**
     * Print routing table
     * \param stream the output stream
     * \param unit The time unit to use (default Time::S)
     */
    void Print(Ptr<OutputStreamWrapper> stream, Time::Unit unit = Time::S) const;

  private:
    /// The routing table
    std::map<Ipv4Address, RoutingTableEntry> m_ipv4AddressEntry;
    /**
     * const version of Purge, for use by Print() method
     * \param table the routing table entry to purge
     */
    void Purge(std::map<Ipv4Address, RoutingTableEntry>& table) const;
};

} // namespace qdrav
} // namespace ns3

#endif /* QDRAV_RTABLE_H */
