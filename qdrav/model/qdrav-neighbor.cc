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

#include "qdrav-neighbor.h"

#include "ns3/log.h"
#include "ns3/wifi-mac-header.h"
#include "ns3/mobility-model.h"
#include "ns3/node.h"

#include <algorithm>
#include <cmath>

namespace ns3
{

NS_LOG_COMPONENT_DEFINE("QdravNeighbors");

namespace qdrav
{
Neighbors::Neighbors(Time delay)
    : m_ntimer(Timer::CANCEL_ON_DESTROY),
      m_avg(0.0),
      m_avgCount(0)
{
    m_ntimer.SetDelay(delay);
    m_ntimer.SetFunction(&Neighbors::Purge, this);
    m_txErrorCallback = MakeCallback(&Neighbors::ProcessTxError, this);
}

bool
Neighbors::IsNeighbor(Ipv4Address addr)
{
    NS_LOG_FUNCTION(this);
    for (std::vector<Neighbor>::const_iterator i = m_nb.begin(); i != m_nb.end(); ++i)
    {
        if (i->m_neighborAddress == addr)
        {
            return true;
        }
    }
    return false;
}

Time
Neighbors::GetExpireTime(Ipv4Address addr)
{
    NS_LOG_FUNCTION(this);
    for (std::vector<Neighbor>::const_iterator i = m_nb.begin(); i != m_nb.end(); ++i)
    {
        if (i->m_neighborAddress == addr)
        {
            return (i->m_expireTime - Simulator::Now());
        }
    }
    return Seconds(0);
}

std::pair<bool, Neighbor>
Neighbors::UpdateAfterReceiveLP(Ipv4Address neighborIp, Time expire, double d)
{
    NS_LOG_FUNCTION(this);

    std::pair<bool, Neighbor> r;
    for (std::vector<Neighbor>::iterator i = m_nb.begin(); i != m_nb.end(); ++i)
    {
        if (i->m_neighborAddress == neighborIp)
        {
            if (i->m_hardwareAddress == Mac48Address())
            {
                i->m_hardwareAddress = LookupMacAddress(i->m_neighborAddress);  
            }
            i->m_expireTime = std::max(expire + Simulator::Now(), i->m_expireTime); 

            Neighbor neighborOld(neighborIp, LookupMacAddress(neighborIp), i->m_expireTime, i->m_CNTr, i->m_CNTs, i->m_d, i->m_dt); 
        
            i->m_d = d;   
            i->m_dt = Simulator::Now().GetDouble(); 
            
            r.first = true;
            r.second = neighborOld; 

            return r;  
        }
    }

    NS_LOG_LOGIC("Node adding new neighbor with IP: " << neighborIp);
    Neighbor neighbor(neighborIp, LookupMacAddress(neighborIp), expire + Simulator::Now(), 0, 0, d, Simulator::Now().GetDouble()); 
    m_nb.push_back(neighbor);
    r.first = false;
    r.second = neighbor;
    
    return r;
}

std::pair<bool, Neighbor>
Neighbors::UpdateAfterReceiveHello(Ipv4Address neighborIp, Time expire, double d)
{
    NS_LOG_FUNCTION(this);

    std::pair<bool, Neighbor> r;
    for (std::vector<Neighbor>::iterator i = m_nb.begin(); i != m_nb.end(); ++i)
    {
        if (i->m_neighborAddress == neighborIp)
        {
            if (i->m_hardwareAddress == Mac48Address())
            {
                i->m_hardwareAddress = LookupMacAddress(i->m_neighborAddress);  
            }
            i->m_expireTime = std::max(expire + Simulator::Now(), i->m_expireTime); 
            i->m_CNTr++;  

            Neighbor neighborOld(neighborIp, LookupMacAddress(neighborIp), i->m_expireTime, i->m_CNTr, i->m_CNTs, i->m_d, i->m_dt); 
        
            i->m_d = d;   
            i->m_dt = Simulator::Now().GetDouble(); 
            
            r.first = true;
            r.second = neighborOld; 

            return r;  
        }
    }

    NS_LOG_DEBUG("Node adding new neighbor with IP: " << neighborIp);
    Neighbor neighbor(neighborIp, LookupMacAddress(neighborIp), expire + Simulator::Now(), 1, 1, d, Simulator::Now().GetDouble()); 
    m_nb.push_back(neighbor);
    r.first = false;
    r.second = neighbor;
    
    return r; 
}

void 
Neighbors::IncrementCNTs()
{
    for (std::vector<Neighbor>::iterator i = m_nb.begin(); i != m_nb.end(); ++i)
    {
        i->m_CNTs++;  
    }
}


/**
 * \brief CloseNeighbor structure
 */
struct CloseNeighbor
{
    /**
     * Check if the entry is expired
     *
     * \param nb Neighbors::Neighbor entry
     * \return true if expired, false otherwise
     */
    bool operator()(const Neighbor& nb) const
    {
        return (nb.m_expireTime < Simulator::Now());
    }
};

void
Neighbors::Purge()
{
    NS_LOG_FUNCTION(this);
    if (m_nb.empty())
    {
        return;
    }
    CloseNeighbor pred;
    if (!m_handleLinkFailure.IsNull())
    {
        for (std::vector<Neighbor>::iterator j = m_nb.begin(); j != m_nb.end(); ++j)
        {
            if (pred(*j))
            {
                NS_LOG_LOGIC("Close link to " << j->m_neighborAddress);
                m_handleLinkFailure(j->m_neighborAddress, 0.0); //calling function RoutingProtocol::DecreaseQValues
            }
        }
    }
    m_nb.erase(std::remove_if(m_nb.begin(), m_nb.end(), pred), m_nb.end());  
    m_ntimer.Cancel();
    m_ntimer.Schedule();
    
    m_avg = (m_avg*m_avgCount + m_nb.size())/(m_avgCount+1); 
    m_avgCount++;
    
    
}

void
Neighbors::ScheduleTimer()
{
    NS_LOG_FUNCTION(this);
    m_ntimer.Cancel();
    m_ntimer.Schedule();
}

void
Neighbors::AddArpCache(Ptr<ArpCache> a)
{
    NS_LOG_FUNCTION(this);
    m_arp.push_back(a);
}

void
Neighbors::DelArpCache(Ptr<ArpCache> a)
{
    NS_LOG_FUNCTION(this);
    m_arp.erase(std::remove(m_arp.begin(), m_arp.end(), a), m_arp.end());
}

Mac48Address
Neighbors::LookupMacAddress(Ipv4Address addr)
{
    NS_LOG_FUNCTION(this);
    Mac48Address hwaddr;
    for (std::vector<Ptr<ArpCache>>::const_iterator i = m_arp.begin(); i != m_arp.end(); ++i)
    {
        ArpCache::Entry* entry = (*i)->Lookup(addr);
        if (entry != nullptr && (entry->IsAlive() || entry->IsPermanent()) && !entry->IsExpired())
        {
            hwaddr = Mac48Address::ConvertFrom(entry->GetMacAddress());
            break;
        }
    }
    return hwaddr;
}

void
Neighbors::ProcessTxError(const WifiMacHeader& hdr)
{
    NS_LOG_FUNCTION(this);
    Mac48Address addr = hdr.GetAddr1();

    for (std::vector<Neighbor>::iterator i = m_nb.begin(); i != m_nb.end(); ++i)
    {
        if (i->m_hardwareAddress == addr)
        {
            m_handleLinkFailure(i->m_neighborAddress, 0.6); //calling function RoutingProtocol::DecreaseQValues
        }
    }
}

} // namespace qdrav
} // namespace ns3
