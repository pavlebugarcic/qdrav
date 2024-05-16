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
#ifndef QDRAV_RQTABLE_H
#define QDRAV_RQTABLE_H

#include "ns3/ipv4.h"
#include "ns3/nstime.h"
#include "ns3/simulator.h"

#include "ns3/output-stream-wrapper.h"
#include <vector>

namespace ns3
{
namespace qdrav
{

/*
The Route Quality Table Entry
*/

struct RouteQualityTableEntry
{
    RouteQualityTableEntry(Ipv4Address nextHop,
                           bool ack = false,
                           double routeQuality = 0.0)
                    : m_nextHop(nextHop),
                      m_ack(ack),
                      m_routeQuality(routeQuality)
    {
    }

    Ipv4Address m_nextHop; 
    bool m_ack;  
    double m_routeQuality; 
};



/**
 * \ingroup qdrav
 * \brief Q-DRAV Route Quality Table
 */
class RouteQualityTable
{
  public:
    
    RouteQualityTable(Ipv4Address dst = Ipv4Address (), Time time = Simulator::Now())
        : m_dst(dst),
          m_sendTime (time)
    {
    }

    /**
     * Get dst IP
     * \returns the dst IP
     */
    Ipv4Address GetDestination() const
    {
        return m_dst;
    }

    /**
     * Set dst IP
     * \param ip dst IP
     */
    void SetDestination(Ipv4Address ip)
    {
        m_dst = ip;
    }

    /**
     * Get send time
     * \returns the send time
     */
    Time GetSendTime() const
    {
        return m_sendTime;
    }

    /**
     * Set send time
     * \param t the send time
     */
    void SetSendTime(Time t)
    {
        m_sendTime = t;
    }


    /**
     * Get vector of RouteQualityTableEntries
     * \returns the dst IP
     */
    std::vector<RouteQualityTableEntry> GetEntries() const
    {
        return m_tableEntries;
    }

    /**
     * Set vector of RouteQualityTableEntries
     * \param e RouteQualityTableEntries
     */
    void SetEntries(std::vector<RouteQualityTableEntry> e)
    {
        m_tableEntries = e;
    }

    /**
     * Add entry to RouteQualityTableEntries
     * \param e entry
     */
    void AddEntry(RouteQualityTableEntry e)
    {
        m_tableEntries.insert(m_tableEntries.end(), e);
    }
    
    void ClearEntries ()
    {
        m_tableEntries.clear();
    }

    bool UpdateRouteQuality(Ipv4Address dst, Ipv4Address nextHop, double routeQuality);

    void Print(Ptr<OutputStreamWrapper> stream) const;

private:

    Ipv4Address m_dst; 
    Time m_sendTime; 
    std::vector<RouteQualityTableEntry> m_tableEntries; 

};

} // namespace qdrav
} // namespace ns3

#endif /* QDRAV_RQTABLE_H */
