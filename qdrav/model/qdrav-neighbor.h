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

#ifndef QDRAV_NEIGHBOR_H
#define QDRAV_NEIGHBOR_H

#include "ns3/arp-cache.h"
#include "ns3/callback.h"
#include "ns3/ipv4-address.h"
#include "ns3/simulator.h"
#include "ns3/timer.h"

#include <vector>

namespace ns3
{

class WifiMacHeader;

namespace qdrav
{

class RoutingProtocol;

/// Neighbor description
struct Neighbor
{

    /// Neighbor IPv4 address
    Ipv4Address m_neighborAddress;
    /// Neighbor MAC address
    Mac48Address m_hardwareAddress;
    /// Neighbor expire time
    Time m_expireTime;
    /// Received hello packets from neighbor
    double m_CNTr;
    /// Sent hello packets to neighbor
    double m_CNTs;
    /// Neighbor previous distance
    double m_d;
    /// Neighbor previous distance time
    double m_dt;


    /**
     * \brief Neighbor structure constructor
     *
     * \param ip Ipv4Address entry
     * \param mac Mac48Address entry
     * \param t Time expire time
     */
    Neighbor(Ipv4Address ip, Mac48Address mac, Time t, double cntr, double cnts, double d, double dt)
        : m_neighborAddress(ip),
            m_hardwareAddress(mac),
            m_expireTime(t),
            m_CNTr(cntr),
            m_CNTs(cnts),
            m_d(d),
            m_dt(dt)
    {
    }

    Neighbor() 
    : m_neighborAddress(Ipv4Address()),
            m_hardwareAddress(Mac48Address()),
            m_expireTime(Simulator::Now()),
            m_CNTr(0),
            m_CNTs(0),
            m_d(0),
            m_dt(0)
    {
    }
};

/**
 * \ingroup qdrav
 * \brief maintain list of active neighbors
 */
class Neighbors
{
  public:
    /**
     * constructor
     * \param delay the delay time for purging the list of neighbors
     */
    Neighbors(Time delay);

    
    /**
     * Check that node with address addr is neighbor
     * \param addr the IP address to check
     * \returns true if the node with IP address is a neighbor
     */
    bool IsNeighbor(Ipv4Address addr);

    Time GetExpireTime(Ipv4Address addr);


    //updating table after receive LP from neighbor
    std::pair<bool, Neighbor> UpdateAfterReceiveLP(Ipv4Address neighborIp, Time expire, double d);

    //updating table after receive HELLO from neighbor
    std::pair<bool, Neighbor> UpdateAfterReceiveHello(Ipv4Address neighborIp, Time expire, double d);

    //incrementing CNTs after send HELLO from neighbor
    void IncrementCNTs();

    /// Remove all expired entries
    void Purge();
    /// Schedule m_ntimer.
    void ScheduleTimer();

    /// Remove all entries
    void Clear()
    {
        m_nb.clear();
    }

    /**
     * Add ARP cache to be used to allow layer 2 notifications processing
     * \param a pointer to the ARP cache to add
     */
    void AddArpCache(Ptr<ArpCache> a);
    /**
     * Don't use given ARP cache any more (interface is down)
     * \param a pointer to the ARP cache to delete
     */
    void DelArpCache(Ptr<ArpCache> a);

    /**
     * Get callback to ProcessTxError
     * \returns the callback function
     */
    Callback<void, const WifiMacHeader&> GetTxErrorCallback() const
    {
        return m_txErrorCallback;
    }

    /**
     * Set link failure callback
     * \param cb the callback function
     */
    void SetCallback(Callback<void, Ipv4Address, double> cb)
    {
        m_handleLinkFailure = cb;
    }

    /**
     * Get link failure callback
     * \returns the link failure callback
     */
    Callback<void, Ipv4Address, double> GetCallback() const
    {
        return m_handleLinkFailure;
    }


    //Return vector of neighbors
    std::vector<Neighbor> GetNeighbors () const//P: promenjeno
    {
        return m_nb;
    }
    
    //Return number od neighbors
    int GetNumberOfNeigbors () const
    {
        return m_nb.size();
    }

    double GetAverageNumberOfNeigbors () const
    {
        return m_avg;
    }

  private:
    /// link failure callback
    Callback<void, Ipv4Address, double> m_handleLinkFailure;
    /// TX error callback
    Callback<void, const WifiMacHeader&> m_txErrorCallback;
    /// Timer for neighbor's list. Schedule Purge().
    Timer m_ntimer;
    /// vector of entries
    std::vector<Neighbor> m_nb;
    /// list of ARP cached to be used for layer 2 notifications processing
    std::vector<Ptr<ArpCache>> m_arp;
    double m_avg; 
    int m_avgCount; 

    /**
     * Find MAC address by IP using list of ARP caches
     *
     * \param addr the IP address to lookup
     * \returns the MAC address for the IP address
     */
    Mac48Address LookupMacAddress(Ipv4Address addr);
    /**
     * Process layer 2 TX error notification
     * \param hdr header of the packet
     */
    void ProcessTxError(const WifiMacHeader& hdr);
};

} // namespace qdrav
} // namespace ns3

#endif /* QDRAV_NEIGHBOR_H */
