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

#include "qdrav-rtable.h"

#include "ns3/log.h"
#include "ns3/simulator.h"

#include <algorithm>
#include <iomanip>

namespace ns3
{

NS_LOG_COMPONENT_DEFINE("QdravRoutingTable");

namespace qdrav
{

/*
 The Routing Table Entry
 */

RoutingTableEntry::RoutingTableEntry(Ptr<NetDevice> dev,
                                     Ipv4Address dst,
                                     Ipv4InterfaceAddress iface,
                                     Ipv4Address nextHop,
                                     Time lifetime,
                                     RouteFlags flag)
    : m_lifeTime(lifetime + Simulator::Now()),
      m_iface(iface),
      m_flag(flag),  
      m_reqCount(0)                    
{
    m_ipv4Route = Create<Ipv4Route>();
    m_ipv4Route->SetDestination(dst);
    m_ipv4Route->SetGateway(nextHop);
    m_ipv4Route->SetSource(m_iface.GetLocal());
    m_ipv4Route->SetOutputDevice(dev);
}

RoutingTableEntry::~RoutingTableEntry()
{
}


void
RoutingTableEntry::Print(Ptr<OutputStreamWrapper> stream, Time::Unit unit) const
{
    std::ostream* os = stream->GetStream();
    // Copy the current ostream state
    std::ios oldState(nullptr);
    oldState.copyfmt(*os);

    *os << std::resetiosflags(std::ios::adjustfield) << std::setiosflags(std::ios::left);

    std::ostringstream dest;
    std::ostringstream gw;
    std::ostringstream iface;
    std::ostringstream expire;
    dest << m_ipv4Route->GetDestination();
    gw << m_ipv4Route->GetGateway();
    iface << m_iface.GetLocal();
    expire << std::setprecision(2) << (m_lifeTime - Simulator::Now()).As(unit);
    *os << std::setw(16) << dest.str();
    *os << std::setw(16) << gw.str();
    *os << std::setw(16) << iface.str();
    *os << std::setw(16);
    switch (m_flag)
    {
    case VALID: {
        *os << "VALID";
        break;
    }
    case IN_SEARCH: {
        *os << "IN_SEARCH";
        break;
    }
    }

    *os << std::setw(16) << expire.str() << std::endl;
    // Restore the previous ostream state
    (*os).copyfmt(oldState);
}

/*
 The Routing Table
 */

RoutingTable::RoutingTable()
{
}

bool
RoutingTable::LookupRoute(Ipv4Address id, RoutingTableEntry& rt)
{
    NS_LOG_FUNCTION(this << id);
    Purge();
    if (m_ipv4AddressEntry.empty())
    {
        NS_LOG_LOGIC("Route to " << id << " not found; m_ipv4AddressEntry is empty");
        return false;
    }
    std::map<Ipv4Address, RoutingTableEntry>::const_iterator i = m_ipv4AddressEntry.find(id);
    if (i == m_ipv4AddressEntry.end())
    {
        NS_LOG_LOGIC("Route to " << id << " not found");
        return false;
    }
    rt = i->second;
    NS_LOG_LOGIC("Route to " << id << " found");
    return true;
}


bool
RoutingTable::DeleteRoute(Ipv4Address dst)
{
    NS_LOG_FUNCTION(this << dst);
    Purge();
    if (m_ipv4AddressEntry.erase(dst) != 0)
    {
        NS_LOG_LOGIC("Route deletion to " << dst << " successful");
        return true;
    }
    NS_LOG_LOGIC("Route deletion to " << dst << " not successful");
    return false;
}

bool
RoutingTable::AddRoute(RoutingTableEntry& rt)
{
    NS_LOG_FUNCTION(this);
    Purge();
    if (rt.GetFlag() != IN_SEARCH)
    {
        rt.SetLpreqCnt(0);
    }
    std::pair<std::map<Ipv4Address, RoutingTableEntry>::iterator, bool> result =
        m_ipv4AddressEntry.insert(std::make_pair(rt.GetDestination(), rt));
    return result.second;
}

bool
RoutingTable::Update(RoutingTableEntry& rt)
{
    NS_LOG_FUNCTION(this);
    std::map<Ipv4Address, RoutingTableEntry>::iterator i =
        m_ipv4AddressEntry.find(rt.GetDestination());
    if (i == m_ipv4AddressEntry.end())
    {
        NS_LOG_LOGIC("Route update to " << rt.GetDestination() << " fails; not found");
        return false;
    }
    i->second = rt;
    if (i->second.GetFlag() != IN_SEARCH)
    {
        NS_LOG_LOGIC("Route update to " << rt.GetDestination() << " set RreqCnt to 0");
        i->second.SetLpreqCnt(0);
    }
    return true;
}


void
RoutingTable::DeleteAllRoutesFromInterface(Ipv4InterfaceAddress iface)
{
    NS_LOG_FUNCTION(this);
    if (m_ipv4AddressEntry.empty())
    {
        return;
    }
    for (std::map<Ipv4Address, RoutingTableEntry>::iterator i = m_ipv4AddressEntry.begin();
         i != m_ipv4AddressEntry.end();)
    {
        if (i->second.GetInterface() == iface)
        {
            std::map<Ipv4Address, RoutingTableEntry>::iterator tmp = i;
            ++i;
            m_ipv4AddressEntry.erase(tmp);
        }
        else
        {
            ++i;
        }
    }
}
 
void
RoutingTable::Purge()
{
    NS_LOG_FUNCTION(this);
    if (m_ipv4AddressEntry.empty())
    {
        NS_LOG_LOGIC ("Purge - table empty");
        return;
    }
    for (std::map<Ipv4Address, RoutingTableEntry>::iterator i = m_ipv4AddressEntry.begin();
         i != m_ipv4AddressEntry.end();)
    {
        if (i->second.GetLifeTime() < Seconds(0))
        {
            if (i->second.GetFlag() == VALID) 
            {
                std::map<Ipv4Address, RoutingTableEntry>::iterator tmp = i;
                ++i;
                m_ipv4AddressEntry.erase(tmp);
            }
            else
            {
                ++i;
            }
        }
        else
        {
            ++i;
        }
    }
}

void
RoutingTable::Purge(std::map<Ipv4Address, RoutingTableEntry>& table) const
{
    NS_LOG_FUNCTION(this);
    if (table.empty())
    {
        return;
    }
    for (std::map<Ipv4Address, RoutingTableEntry>::iterator i = table.begin(); i != table.end();)
    {
        if (i->second.GetLifeTime() < Seconds(0))
        {
            if (i->second.GetFlag() == VALID)
            {
                std::map<Ipv4Address, RoutingTableEntry>::iterator tmp = i;
                ++i;
                table.erase(tmp);
            }
            else
            {
                ++i;
            }
        }
        else
        {
            ++i;
        }
    }
}

void
RoutingTable::Print(Ptr<OutputStreamWrapper> stream, Time::Unit unit) const
{
    std::map<Ipv4Address, RoutingTableEntry> table = m_ipv4AddressEntry;
    Purge(table);
    std::ostream* os = stream->GetStream();
    // Copy the current ostream state
    std::ios oldState(nullptr);
    oldState.copyfmt(*os);

    *os << std::resetiosflags(std::ios::adjustfield) << std::setiosflags(std::ios::left);
    *os << "\nAODV Routing table\n";
    *os << std::setw(16) << "Destination";
    *os << std::setw(16) << "Gateway";
    *os << std::setw(16) << "Interface";
    *os << std::setw(16) << "Flag";
    *os << std::setw(16) << "Expire";
    *os << std::endl; 
    for (std::map<Ipv4Address, RoutingTableEntry>::const_iterator i = table.begin();
         i != table.end();
         ++i)
    {
        i->second.Print(stream, unit);
    }
    *stream->GetStream() << "\n";
}

} // namespace qdrav
} // namespace ns3
