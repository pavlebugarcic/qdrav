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

#include "qdrav-qtable.h"
#include "qdrav-neighbor.h"

#include "ns3/log.h"
#include "ns3/simulator.h"
#include "ns3/node-list.h"
#include "ns3/node.h"

#include <algorithm>
#include <iomanip>

namespace ns3
{

NS_LOG_COMPONENT_DEFINE("QdravQTable");

namespace qdrav
{

/*
 The Q-table entry
 */

QTableEntry::QTableEntry (Ipv4Address dst,
                          Ipv4Address nextHop,
                          double qValue,
                          Time qValueLifetime, 
                          Ipv4InterfaceAddress iface,  
                          Ptr<NetDevice> dev)
    : m_iface(iface),
      m_qValueLifetime(qValueLifetime + Simulator::Now ())
{
    m_qValue = (qValue > 1.0) ? 1 : ((qValue < 0.0) ? 0.0 : qValue); //Q-value must be in range [0,1]
    m_ipv4Route = Create<Ipv4Route>();
    m_ipv4Route->SetDestination(dst);
    m_ipv4Route->SetGateway(nextHop);
    m_ipv4Route->SetSource(m_iface.GetLocal());
    m_ipv4Route->SetOutputDevice(dev);
}

QTableEntry::QTableEntry(const QTableEntry & qte)
{
    m_iface = qte.GetInterface ();
    m_qValueLifetime = qte.GetQValueLifetime () + Simulator::Now ();
    m_qValue = qte.GetQValue ();
    m_ipv4Route = Create<Ipv4Route>();
    m_ipv4Route->SetDestination(qte.GetDestination ());
    m_ipv4Route->SetGateway(qte.GetNextHop ());
    m_ipv4Route->SetSource(m_iface.GetLocal ());
    m_ipv4Route->SetOutputDevice(qte.GetOutputDevice ());
} 

QTableEntry::~QTableEntry()
{
}

void
QTableEntry::Print(Ptr<OutputStreamWrapper> stream) const
{
    std::ostream* os = stream->GetStream();
    // Copy the current ostream state
    std::ios oldState(nullptr);
    oldState.copyfmt(*os);

    *os << std::resetiosflags(std::ios::adjustfield) << std::setiosflags(std::ios::left);

    std::ostringstream dest;
    std::ostringstream nextHop;
    std::ostringstream myAddress;
    std::ostringstream lifetime;

    dest << m_ipv4Route->GetDestination();
    nextHop << m_ipv4Route->GetGateway();
    myAddress << m_iface.GetLocal();
    lifetime << m_qValueLifetime - Simulator::Now ();

    *os << std::setw(16) << myAddress.str();
    *os << std::setw(16) << dest.str();
    *os << std::setw(16) << nextHop.str();
    *os << std::setw(16) << lifetime.str();
    *os << std::setw(16) << m_qValue << std::endl;  
    // Restore the previous ostream state
    (*os).copyfmt(oldState);
}

/*
 The Q-table
 */

std::vector<QmaxEntry>
QTable::GetMaxQValues (Neighbors & nb, std::map<Ipv4Address, uint16_t>& dst) 
{
  std::vector<QmaxEntry> maxQValues; 
  QmaxEntry qMaxEntry;

  for (std::map<Ipv4Address, std::map<Ipv4Address,QTableEntry>>::iterator it = m_qTable.begin (); it != m_qTable.end (); ++it) 
  {
      std::map<Ipv4Address,QTableEntry>::iterator ite;
      double maxQValue = 0.0;
      for (ite = it->second.begin (); ite != it->second.end (); ++ite)
      {
          if ((ite->second.GetQValueLifetime() >= Seconds(0)) && (ite->second.GetQValue () > maxQValue) && (nb.IsNeighbor (ite->first)))  
          {
              maxQValue = ite->second.GetQValue ();
              qMaxEntry.nextHop = dst[ite->first]; 
          }
      }
      if (maxQValue > 0)
      {
        NS_LOG_LOGIC("MaxQValues entry: ID = " << dst[it->first] << ", MaxQValue = " << maxQValue);
        qMaxEntry.dst = dst[it->first]; 
        qMaxEntry.qMax = maxQValue; 
        maxQValues.insert (maxQValues.end(), qMaxEntry); 
      } 
  }

  return maxQValues; 
}

bool
QTable::FindRouteToDstWithMaxQValue(Ipv4Address dst, QTableEntry & rt)
{
    NS_LOG_FUNCTION(this << dst);
    if (m_qTable.empty())
    {
        NS_LOG_LOGIC("Route list is empty");
        return false;
    }
    std::map<Ipv4Address, std::map<Ipv4Address,QTableEntry>>::iterator it = m_qTable.find(dst);
    if (it == m_qTable.end())
    {
        NS_LOG_LOGIC("Route to " << dst << " not found");
        return false;
    }
    std::map<Ipv4Address,QTableEntry>::iterator ite;
    double maxQValue = 0.0;
    bool found = false;
    for (ite = it->second.begin (); ite != it->second.end (); ++ite)
    {
        if ((ite->second.GetQValueLifetime() >= Seconds(0)) && (ite->second.GetQValue () > maxQValue))
        {
            found = true;
            maxQValue = ite->second.GetQValue ();
            rt = ite->second; 
        }
    }
    return found;
}

bool
QTable::FindRouteToDstWithMaxQValueViaNeigbor (Ipv4Address dst, Neighbors & nb, QTableEntry& rt)
{
    NS_LOG_FUNCTION(this << dst);
    if (m_qTable.empty())
    {
        NS_LOG_LOGIC("Route list is empty");
        return false;
    }
    std::map<Ipv4Address, std::map<Ipv4Address,QTableEntry>>::iterator it = m_qTable.find(dst);
    if (it == m_qTable.end())
    {
        NS_LOG_LOGIC("Route to " << dst << " not found");
        return false;
    }
    std::map<Ipv4Address,QTableEntry>::iterator ite;
    double maxQValue = 0.0;
    bool found = false;
    NS_LOG_DEBUG("Dosao do prvog stampanja qTable u FindRouteToDstWithMaxQValueViaNeigbor");
    for (ite = it->second.begin (); ite != it->second.end (); ++ite)
    {
        if ((ite->second.GetQValueLifetime() >= Seconds(0)) && (ite->second.GetQValue () > maxQValue) && (nb.IsNeighbor (ite->first))) 
        {
            found = true;
            maxQValue = ite->second.GetQValue ();
            rt = ite->second; 
        }
    }
    return found;
}

void
QTable::FindRoutesWithHihgQValuesViaNeighbor (Ipv4Address dst, Neighbors & nb, double maxQValue, double trigger, std::vector<QTableEntry> & highValuesQTable)
{
    NS_LOG_DEBUG("Usao u FindRoutesWithHihgQValuesViaNeighbor");
    NS_LOG_FUNCTION(this << dst);
    NS_LOG_DEBUG("Usao u FindRoutesWithHihgQValuesViaNeighbor");
    
    std::map<Ipv4Address, std::map<Ipv4Address,QTableEntry>>::iterator it = m_qTable.find(dst);
    
    std::map<Ipv4Address,QTableEntry>::iterator ite;
    for (ite = it->second.begin (); ite != it->second.end (); ++ite)
    {
        if ((ite->second.GetQValueLifetime() >= Seconds(0)) && (ite->second.GetQValue () > trigger*maxQValue) && (nb.IsNeighbor (ite->first)))   
        {
            NS_LOG_DEBUG("Usao u if");
            highValuesQTable.insert(highValuesQTable.end(), ite->second); 
            NS_LOG_DEBUG("Ubacen entri");

            /*OutputStreamWrapper s(&std::cout);
            Ptr<OutputStreamWrapper> stream = &s;
            ite->second.Print(stream);*/
        }
    }
    return;
}

bool
QTable::GetRoute(Ipv4Address dst, Ipv4Address nextHop, QTableEntry& rt)
{
    NS_LOG_FUNCTION(this << dst << nextHop);
    if (m_qTable.empty())
    {
        NS_LOG_LOGIC("Route list is empty");
        return false;
    }

    std::map<Ipv4Address, std::map<Ipv4Address,QTableEntry>>::iterator it = m_qTable.find(dst); 
    std::map<Ipv4Address,QTableEntry>::iterator ite;
    for (ite = it->second.begin (); ite != it->second.end (); ++ite)
    {
        if ((ite->first == nextHop) && (ite->second.GetQValueLifetime() >= Seconds(0)))  
        {
            rt = ite->second; 
            return true;
        }
    }

    return false;
}

bool
QTable::DeleteRoute(Ipv4Address dst, Ipv4Address nextHop)
{
    NS_LOG_FUNCTION(this << dst << nextHop);
    Purge();
    if (m_qTable.empty())
    {
        NS_LOG_LOGIC("Route list is empty");
        return false;
    }
    std::map<Ipv4Address, std::map<Ipv4Address,QTableEntry>>::iterator it = m_qTable.find(dst);
    if (it->second.erase(nextHop) != 0)
    {
        NS_LOG_LOGIC("Route deletion to " << dst << " over " << nextHop << " successful");
        return true;
    }
    NS_LOG_LOGIC("Route deletion to " << dst << " over " << nextHop << " not successful");
    return false;
}

bool
QTable::AddRoute(QTableEntry& rt)
{
    NS_LOG_FUNCTION(this);
    Purge();
    std::map<Ipv4Address, std::map<Ipv4Address,QTableEntry>>::iterator it = m_qTable.find(rt.GetDestination ()); 
    if (it == m_qTable.end())
    {
        NS_LOG_DEBUG("Nije nasao dst, pa ubacije novu");
        std::pair<std::map<Ipv4Address, std::map<Ipv4Address,QTableEntry>>::iterator, bool> result;
        std::map<Ipv4Address,QTableEntry> e;
        e.insert(std::make_pair(rt.GetNextHop (),rt));
        result = m_qTable.insert(std::make_pair(rt.GetDestination(), e));
        NS_LOG_DEBUG("Ubacio entri");
        //OutputStreamWrapper s(&std::cout);
        //Ptr<OutputStreamWrapper> stream = &s;
        //rt.Print(stream);
        return result.second;
    }
    else
    {
         
        NS_LOG_DEBUG("Azurira postojecu dst: " << rt.GetDestination () << " i dodaje novi next hop "  << rt.GetNextHop ());
        std::pair<std::map<Ipv4Address,QTableEntry>::iterator, bool> result;
        it->second.insert(std::make_pair(rt.GetNextHop (),rt)); 
        return result.second;
    }
    return false; 
}

bool
QTable::UpdateRoute(QTableEntry& rt)
{
    NS_LOG_FUNCTION(this);
    if (m_qTable.empty())
    {
        NS_LOG_LOGIC("Route list is empty");
        return false;
    }
    std::map<Ipv4Address, std::map<Ipv4Address,QTableEntry>>::iterator it = m_qTable.find(rt.GetDestination ());  
    if (it == m_qTable.end())
    {
        NS_LOG_LOGIC("Route update to " << rt.GetDestination() << " over " << rt.GetNextHop() << " fails; not found");
        return false;        
    }
    std::map<Ipv4Address,QTableEntry>::iterator ite = it->second.find(rt.GetNextHop ());
    if (ite == it->second.end())
    {
        NS_LOG_LOGIC("Route update to " << rt.GetDestination() << " over " << rt.GetNextHop() << " fails; not found");
        return false;        
    }
    ite->second = rt;
    return true;
}

bool
QTable::UpdateQTableEntryViaHello(Ipv4Address dst, Ipv4Address nextHop, double alpha, double gamma, double r, double maxQValue, Time lifetime, double& newQValue)
{
    NS_LOG_FUNCTION(this);
    if (m_qTable.empty())
    {
        NS_LOG_DEBUG("Route list is empty");
        return false;
    }
    std::map<Ipv4Address, std::map<Ipv4Address,QTableEntry>>::iterator it = m_qTable.find(dst); 
    if (it == m_qTable.end())
    {
        NS_LOG_DEBUG("Route to " << dst << " over " << nextHop << " fails; not found");
        return false;        
    }
    std::map<Ipv4Address,QTableEntry>::iterator ite = it->second.find(nextHop);
    if (ite == it->second.end())
    {
        NS_LOG_DEBUG("Route to " << dst << " over " << nextHop << " fails; not found");
        return false;        
    }
    double oldQValue = ite->second.GetQValue();
    if (r == 1)
    {
        newQValue = 1.0; 
    }
    else if (r == -0.5)
    {
        newQValue = 0.0;
    }
    else 
    { 
        newQValue = (1-alpha)*oldQValue + alpha*(r + gamma*maxQValue);
        if (newQValue < 0.0) 
        {
            newQValue = 0.0; 
        } 
        else if (newQValue > 1.0) 
        {
            newQValue = 1.0; 
        }
    }
    ite->second.SetQValue(newQValue); 
    ite->second.SetQValueLifetime(std::max(ite->second.GetQValueLifetime(), lifetime)); 
    NS_LOG_DEBUG("QTableEntry found for route to " << dst << " over " << nextHop);
    return true;
}

bool
QTable::UpdateQTableEntryViaLP(Ipv4Address dst, Ipv4Address nextHop, double r, double maxQValue, Time lifetime, double& newQValue)
{
    NS_LOG_FUNCTION(this);
    return UpdateQTableEntryViaHello(dst, nextHop, 0.6, 0.3, r, maxQValue, lifetime, newQValue); 
}

bool
QTable::UpdateQTableEntryViaRPP(Ipv4Address dst, Ipv4Address nextHop, double k, Time lifetime)
{
    NS_LOG_FUNCTION(this);
    if (m_qTable.empty())
    {
        NS_LOG_LOGIC("Route list is empty");
        return false;
    }
    std::map<Ipv4Address, std::map<Ipv4Address,QTableEntry>>::iterator it = m_qTable.find(dst); 
    if (it == m_qTable.end())
    {
        NS_LOG_LOGIC("Route to " << dst << " over " << nextHop << " fails; not found");
        return false;        
    }
    std::map<Ipv4Address,QTableEntry>::iterator ite = it->second.find(nextHop);
    if (ite == it->second.end())
    {
        NS_LOG_LOGIC("Route to " << dst << " over " << nextHop << " fails; not found");
        return false;        
    }
    double oldQValue = ite->second.GetQValue();
    double newQValue = oldQValue*k; 
    ite->second.SetQValue(newQValue); 
    ite->second.SetQValueLifetime(std::max(ite->second.GetQValueLifetime(), lifetime)); 
    NS_LOG_LOGIC("QTableEntry found for route to " << dst << " over " << nextHop);
    return true;
}

void
QTable::Purge()
{
    NS_LOG_FUNCTION(this);
    if (m_qTable.empty())
    {
        return;
    }
    for (std::map<Ipv4Address, std::map<Ipv4Address, QTableEntry>>::iterator it = m_qTable.begin(); it != m_qTable.end(); it++)
    {
        for (std::map<Ipv4Address, QTableEntry>::iterator ite = it->second.begin(); ite != it->second.end();)
        {
            if (ite->second.GetQValueLifetime() < Seconds(0))
            {
                Ipv4Address nextHop = ite->first;
                Ipv4Address dst = it->first;
                ite = it->second.erase(ite);
                NS_LOG_LOGIC("Route deletion to " << dst << " over " << nextHop);
            }
            else
            {
                ++ite;
            }
        }
    }
}

void
QTable::Purge(std::map<Ipv4Address, std::map<Ipv4Address,QTableEntry>> & table) const
{
    NS_LOG_FUNCTION(this);
    if (table.empty())
    {
        return;
    }
    for (std::map<Ipv4Address, std::map<Ipv4Address, QTableEntry>>::iterator it = table.begin(); it != table.end(); it++)
    {
        for (std::map<Ipv4Address, QTableEntry>::iterator ite = it->second.begin(); ite != it->second.end();)
        {
            if (ite->second.GetQValueLifetime() < Seconds(0))
            {
                Ipv4Address nextHop = ite->first;
                Ipv4Address dst = it->first;
                ite = it->second.erase(ite);
                NS_LOG_LOGIC("Route deletion to " << dst << " over " << nextHop);
            }
            else
            {
                ++ite;
            }
        }
    }
}

void
QTable::Print(Ptr<OutputStreamWrapper> stream) const
{
    std::map<Ipv4Address, std::map<Ipv4Address,QTableEntry>> table = m_qTable;
    Purge(table);
    std::ostream* os = stream->GetStream();
    // Copy the current ostream state
    std::ios oldState(nullptr);
    oldState.copyfmt(*os);

    *os << std::resetiosflags(std::ios::adjustfield) << std::setiosflags(std::ios::left);
    *os << "\nQ-table\n";
    *os << std::setw(16) << "MyInterfaceAddr";
    *os << std::setw(16) << "Destination";
    *os << std::setw(16) << "NextHop";
    *os << std::setw(16) << "Lifetime";
    *os << "Q-value" << std::endl; 
    for (std::map<Ipv4Address, std::map<Ipv4Address,QTableEntry>>::const_iterator it = table.begin(); it != table.end(); ++it)
    {
        for (std::map<Ipv4Address,QTableEntry>::const_iterator ite = it->second.begin(); ite != it->second.end(); ++ite)
        {
            ite->second.Print(stream);
        }
    }
    *stream->GetStream() << "\n";
}

void
QTable::DeleteAllRoutesFromInterface(Ipv4InterfaceAddress iface) 
{
    NS_LOG_FUNCTION(this);
    if (m_qTable.empty())
    {
        return;
    }
    for (std::map<Ipv4Address, std::map<Ipv4Address,QTableEntry>>::iterator it = m_qTable.begin(); it != m_qTable.end(); ++it)
    {
        for (std::map<Ipv4Address, QTableEntry>::iterator ite = it->second.begin(); ite != it->second.end();)
        {
            if (ite->second.GetInterface() == iface)
            {
                Ipv4Address nextHop = ite->first;
                Ipv4Address dst = it->first;
                ite = it->second.erase(ite);
                NS_LOG_LOGIC("Route deletion for interface" << iface << " (to " << dst << " over " << nextHop);
            }
            else
            {
                ++ite;
            }
        }
    }
}

void
QTable::DeleteAllQValuesViaNeighbor(Ipv4Address neighbor) 
{
    NS_LOG_FUNCTION(this);
    if (m_qTable.empty())
    {
        return;
    }
    for (std::map<Ipv4Address, std::map<Ipv4Address,QTableEntry>>::iterator it = m_qTable.begin(); it != m_qTable.end(); ++it)
    {
        for (std::map<Ipv4Address, QTableEntry>::iterator ite = it->second.begin(); ite != it->second.end();)
        {
            if (ite->second.GetNextHop() == neighbor)
            {
                Ipv4Address dst = it->first;
                ite = it->second.erase(ite);
                NS_LOG_LOGIC("Route deletion to " << dst << " over " << neighbor);
            }
            else
            {
                ++ite;
            }
        }
    }
}

void
QTable::DecreaseAllQValuesViaNeighbor(Ipv4Address neighbor, double p) 
{
    NS_LOG_FUNCTION(this);
    if (m_qTable.empty())
    {
        return;
    }
    for (std::map<Ipv4Address, std::map<Ipv4Address,QTableEntry>>::iterator it = m_qTable.begin(); it != m_qTable.end(); ++it)
    {
        for (std::map<Ipv4Address, QTableEntry>::iterator ite = it->second.begin(); ite != it->second.end(); ite++)
        {
            if (ite->second.GetNextHop() == neighbor)
            {
                ite->second.SetQValue(p*ite->second.GetQValue()); 
                NS_LOG_DEBUG ("Q-vrednost umanjena " << p << " puta. Q vrednost do " << it->first << " preko " << ite->first << " = " << ite->second.GetQValue());
            }
        }
    }
}


} // namespace qdrav
} // namespace ns3
