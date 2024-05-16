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
#ifndef QDRAV_QTABLE_H
#define QDRAV_QTABLE_H

#include "ns3/ipv4-route.h"
#include "ns3/ipv4.h"
#include "ns3/net-device.h"
#include "ns3/output-stream-wrapper.h"
#include "ns3/timer.h"
#include "qdrav-packet.h"

#include <cassert>
#include <map>
#include <stdint.h>
#include <sys/types.h>

namespace ns3
{
namespace qdrav
{

class Neighbors;

/**
 * \ingroup qdrav
 * \brief Q-table entry
 */
class QTableEntry
{
  public:
    /**
     * constructor
     *
     * \param dst the destination IP address
     * \param nextHop the IP address of the next hop
     * \param qValue the qValue of the entry
     * \param routeTimeot qValue lifetime
     * \param iface the interface
     * \param dev the device
     */
    QTableEntry(Ipv4Address dst = Ipv4Address (),
                Ipv4Address nextHop = Ipv4Address (),
                double qValue = 0.0,
                Time routeTimeot = Seconds (2),  
                Ipv4InterfaceAddress iface = Ipv4InterfaceAddress (),
                Ptr<NetDevice> dev = nullptr); 

    // copy constructor
    QTableEntry(const QTableEntry & qte); 


    ~QTableEntry();

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
     * Get the Q-value 
     * \returns the Q-value
     */
    double GetQValue () const 
    { 
        return m_qValue; 
    }

    /**
     * Set the Q-value
     * \param qValue the Q-value
     */
    void SetQValue (double qValue) 
    { 
        m_qValue = (qValue > 1.0) ? 1 : ((qValue < 0.0) ? 0.0 : qValue); //Q-value must be in range [0,1] 
    }

    /**
     * Get the Q-value lifetime
     * \returns the Q-value lifetime
     */
    Time GetQValueLifetime () const 
    { 
        return m_qValueLifetime - Simulator::Now (); 
    }

    /**
     * Set the Q-value lifetime
     * \param qValue the Q-value lifetime
     */
    void SetQValueLifetime (Time qValueLifetime) 
    { 
        m_qValueLifetime = qValueLifetime + Simulator::Now ();
    }

    /**
     * Print QlTableEntry to trace file
     * \param stream The output stream
     */
    void Print(Ptr<OutputStreamWrapper> stream) const;

  private:
    /** Ip route, include
     *   - destination address
     *   - source address
     *   - next hop address (gateway)
     *   - output device
     */
    Ptr<Ipv4Route> m_ipv4Route;
    Ipv4InterfaceAddress m_iface;  //!< Output interface address
    Time m_qValueLifetime;          //!< Lifetime for Q-value   //P: za sad ostavljamo 
    double m_qValue;               //!< Q-value
};

/**
 * \ingroup qdrav
 * \brief The Q-table used by AODV protocol
 */
class QTable
{
  public:
    /**
     * Constructor
     */
    QTable() {};

    /**
     * Add Q-table entry 
     * \param qte Q-table entry
     * \return true in success
     */
    bool AddRoute(QTableEntry& qte);

    bool GetRoute(Ipv4Address dst, Ipv4Address nextHop, QTableEntry& rt);

    /**
     * Delete Q-table entry with destination address dst and nextHop, if it exists.
     * \param dst destination address
     * \param nextHop gateway address
     * \return true on success
     */
    bool DeleteRoute(Ipv4Address dst, Ipv4Address nextHop);
    /**
     * Lookup route with the best Q-value for the destination address dst
     * \param dst destination address
     * \param rt entry with destination address dst, if exists
     * \return true on success
     */
    bool FindRouteToDstWithMaxQValue(Ipv4Address dst, QTableEntry& rt);
    
    /**
     * Lookup route with the best Q-value for the destination address dst
     * \param dst destination address
     * \param nb list of nodes neighbors
     * \param rt entry with destination address dst, if exists
     * \return true on success
     */
    bool FindRouteToDstWithMaxQValueViaNeigbor (Ipv4Address dst, Neighbors & nb, QTableEntry& rt);

    void FindRoutesWithHihgQValuesViaNeighbor (Ipv4Address dst, Neighbors & nb, double maxQValue, double trigger, std::vector<QTableEntry> & highValuesQTable);

    /**
     * Update Q-table
     * \param rt entry with destination address dst, if exists
     * \return true on success
     */
    bool UpdateRoute(QTableEntry& rt);

    /**
     * Delete all route from interface with address iface
     * \param iface the interface IP address
     */
    void DeleteAllRoutesFromInterface(Ipv4InterfaceAddress iface); ; 
    void DeleteAllQValuesViaNeighbor(Ipv4Address neighbor); 
    void DecreaseAllQValuesViaNeighbor(Ipv4Address neighbor, double p); 

    /// Delete all entries from routing table
    void Clear()
    {
        m_qTable.clear();
    }

    bool UpdateQTableEntryViaHello(Ipv4Address dst, Ipv4Address nextHop, double alpha, double gamma, double r, double maxQValue, Time lifetime, double& newQValue); 
    bool UpdateQTableEntryViaLP (Ipv4Address dst, Ipv4Address nextHop, double r, double maxQValue, Time lifetime, double& newQValue);
    bool UpdateQTableEntryViaRPP (Ipv4Address dst, Ipv4Address nextHop, double k, Time lifetime);

    /// Delete all outdated entries and invalidate valid entry if Lifetime is expired
    void Purge();

    /**
     * Print routing table
     * \param stream the output stream
     */
    void Print(Ptr<OutputStreamWrapper> stream) const;

    /**
     * Return vector of MaxQValues
     */
    std::vector<QmaxEntry> GetMaxQValues (Neighbors & nb, std::map<Ipv4Address, uint16_t>& dst);

  private:
    /// The Q-table 
    std::map<Ipv4Address, std::map<Ipv4Address,QTableEntry>> m_qTable;
    /**
     * const version of Purge, for use by Print() method
     * \param table the Q-table entry to purge
     */
    void Purge(std::map<Ipv4Address, std::map<Ipv4Address,QTableEntry>> & table) const;
};

} // namespace qdrav
} // namespace ns3

#endif /* QDRAV_QTABLE_H */
