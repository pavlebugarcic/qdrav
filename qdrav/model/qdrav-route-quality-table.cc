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
#include "qdrav-route-quality-table.h"

#include "ns3/ipv4-route.h"
#include "ns3/log.h"
#include "ns3/socket.h"

#include <algorithm>
#include <functional>
#include <iomanip>

namespace ns3
{

NS_LOG_COMPONENT_DEFINE("QdravRouteQualityTable");

namespace qdrav
{

bool
RouteQualityTable::UpdateRouteQuality(Ipv4Address dst, Ipv4Address nextHop, double routeQuality)
{
    NS_LOG_FUNCTION(this << dst);
    NS_ASSERT_MSG(dst == m_dst, "Destination not valid");

    std::vector<RouteQualityTableEntry>::iterator it; 
    for (it = m_tableEntries.begin(); it != m_tableEntries.end(); it++)
    {
        if (it->m_nextHop == nextHop)
        {
            it->m_ack = true; 
            it->m_routeQuality = routeQuality; 
            return true; 
        }
    }

    return false;
}

void
RouteQualityTable::Print(Ptr<OutputStreamWrapper> stream) const
{
    std::ostream* os = stream->GetStream();
    // Copy the current ostream state
    std::ios oldState(nullptr);
    oldState.copyfmt(*os);

    *os << std::resetiosflags(std::ios::adjustfield) << std::setiosflags(std::ios::left);
    *os << "\nRQ-table\n";
    *os << "Destination: " << m_dst;
    *os << "Send time: " << m_sendTime.GetSeconds() << " s" << std::endl;
    *os << std::setw(20) << "NextHop";
    *os << std::setw(20) << "ack";
    *os << "Route quality" << std::endl; 
    for (std::vector<RouteQualityTableEntry>::const_iterator it = m_tableEntries.begin(); it != m_tableEntries.end(); ++it)
    {
        *os << std::setw(20) << it->m_nextHop;
        *os << std::setw(20) << it->m_ack;
        *os << std::setw(20) << it->m_routeQuality << std::endl; 

    }
    *stream->GetStream() << "\n";
}


} // namespace qdrav
} // namespace ns3
