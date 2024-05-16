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
#include "qdrav-packet.h"

#include "ns3/log.h"
#include "ns3/address-utils.h"
#include "ns3/packet.h"

namespace ns3
{

NS_LOG_COMPONENT_DEFINE("QdravPackets");

namespace qdrav
{

NS_OBJECT_ENSURE_REGISTERED(TypeHeader);

TypeHeader::TypeHeader(MessageType t)
    : m_type(t),
      m_valid(true)
{
}

TypeId
TypeHeader::GetTypeId()
{
    static TypeId tid = TypeId("ns3::qdrav::TypeHeader")
                            .SetParent<Header>()
                            .SetGroupName("Qdrav")
                            .AddConstructor<TypeHeader>();
    return tid;
}

TypeId
TypeHeader::GetInstanceTypeId() const
{
    return GetTypeId();
}

uint32_t
TypeHeader::GetSerializedSize() const
{
    return 1;
}

void
TypeHeader::Serialize(Buffer::Iterator i) const
{
    i.WriteU8((uint8_t)m_type);
}

uint32_t
TypeHeader::Deserialize(Buffer::Iterator start)
{
    NS_LOG_LOGIC (this);
    Buffer::Iterator i = start;
    uint8_t type = i.ReadU8();
    m_valid = true;
    switch (type)
    {
      case QDRAVTYPE_LPREQ:
      case QDRAVTYPE_LPREP:
      case QDRAVTYPE_HELLO:
      case QDRAVTYPE_RPP:
      case QDRAVTYPE_RPP_ACK:
      {
          m_type = (MessageType)type;
          break;
      }
      default:
          m_valid = false;
    }
    uint32_t dist = i.GetDistanceFrom(start);
    NS_ASSERT(dist == GetSerializedSize());
    return dist;
}

void
TypeHeader::Print(std::ostream& os) const
{
    switch (m_type)
    {
    case QDRAVTYPE_LPREQ: {
        os << "LPREQ";
        break;
    }
    case QDRAVTYPE_LPREP: {
        os << "LPREP";
        break;
    }
    case QDRAVTYPE_HELLO: {
        os << "HELLO";
        break;
    }
    case QDRAVTYPE_RPP: {
        os << "RPP";
        break;
    }
    case QDRAVTYPE_RPP_ACK: {
        os << "RPP_ACK";
        break;
    }
    default:
        os << "UNKNOWN_TYPE";
    }
}

bool
TypeHeader::operator==(const TypeHeader& o) const
{
    return (m_type == o.m_type && m_valid == o.m_valid);
}

std::ostream&
operator<<(std::ostream& os, const TypeHeader& h)
{
    h.Print(os);
    return os;
}

//-----------------------------------------------------------------------------
// LPREQ
//-----------------------------------------------------------------------------
LpreqHeader::LpreqHeader(uint16_t srcID,
                         uint16_t dstID,
                         uint16_t nextHopID,
                         uint8_t lpreqID,
                         double qValue,
                         float xPos,
                         float yPos)
    : m_srcID(srcID),
      m_dstID(dstID),
      m_nextHopID(nextHopID),
      m_lpreqID(lpreqID),
      m_qValue(qValue),
      m_xPos(xPos),
      m_yPos(yPos)
{
}

NS_OBJECT_ENSURE_REGISTERED(LpreqHeader);

TypeId
LpreqHeader::GetTypeId()
{
    static TypeId tid = TypeId("ns3::qdrav::LpreqHeader")
                            .SetParent<Header>()
                            .SetGroupName("Qdrav")
                            .AddConstructor<LpreqHeader>();
    return tid;
}

TypeId
LpreqHeader::GetInstanceTypeId() const
{
    return GetTypeId();
}

uint32_t
LpreqHeader::GetSerializedSize() const
{
    return 8 + 2*sizeof (float);  
}


void
LpreqHeader::Serialize(Buffer::Iterator i) const
{
    NS_LOG_FUNCTION(this);
    i.WriteU16 (m_srcID);
    i.WriteU16(m_dstID);
    i.WriteU16(m_nextHopID);
    i.WriteU8(m_lpreqID);
    i.WriteU8(uint8_t(m_qValue*255));   
    uint8_t *buf;
    buf = (uint8_t *)&m_xPos;
    for (uint32_t k = 0; k < sizeof (float); ++k, ++buf)
      {
        i.WriteU8 (*buf); 
      }
    buf = (uint8_t *)&m_yPos;
    for (uint32_t k = 0; k < sizeof (float); ++k, ++buf)
      {
        i.WriteU8 (*buf);  
      }
}

uint32_t
LpreqHeader::Deserialize(Buffer::Iterator start)
{
    Buffer::Iterator i = start;
    m_srcID = i.ReadU16();
    m_dstID = i.ReadU16();
    m_nextHopID = i.ReadU16();
    m_lpreqID = i.ReadU8();
    m_qValue = double(i.ReadU8()/255.0);   
    uint8_t *buf;
    buf = (uint8_t *)&m_xPos;
    for (uint32_t k = 0; k < sizeof (float); ++k, ++buf)
      {
        *buf = i.ReadU8 ();
      }
    buf = (uint8_t *)&m_yPos;
    for (uint32_t k = 0; k < sizeof (float); ++k, ++buf)
      {
        *buf = i.ReadU8 ();
      }

    uint32_t dist = i.GetDistanceFrom(start);
    NS_ASSERT(dist == GetSerializedSize());
    return dist;
}

void
LpreqHeader::Print(std::ostream& os) const
{
    NS_LOG_FUNCTION(this);
    os << " Source ID: " << m_srcID;
    os << " Destination ID: " << m_dstID;
    os << " Next hop ID: " << m_nextHopID;
    os << " LPREQ ID: " << (int)m_lpreqID;  
    os << " Q value: " << m_qValue;
    os << " Neighbor x position: " <<  m_xPos;
    os << " Neighbor y position: " <<  m_yPos;
}

std::ostream&
operator<<(std::ostream& os, const LpreqHeader& h)
{
    h.Print(os);
    return os;
}

bool
LpreqHeader::operator==(const LpreqHeader& o) const
{
    return (m_srcID == o.m_srcID && m_dstID == o.m_dstID && m_nextHopID == o.m_nextHopID && m_lpreqID == o.m_lpreqID &&
            m_qValue == o.m_qValue && m_xPos == o.m_xPos && m_yPos == o.m_yPos);
}

//-----------------------------------------------------------------------------
// LPREP
//-----------------------------------------------------------------------------
LprepHeader::LprepHeader(uint16_t srcID,
                         uint16_t dstID,
                         uint16_t nextHopID,
                         uint8_t lprepID,
                         double qValue,
                         float xPos,
                         float yPos)
    : m_srcID(srcID),
      m_dstID(dstID),
      m_nextHopID(nextHopID),
      m_lprepID(lprepID),
      m_qValue(qValue),
      m_xPos(xPos),
      m_yPos(yPos)
{
}

NS_OBJECT_ENSURE_REGISTERED(LprepHeader);

TypeId
LprepHeader::GetTypeId()
{
    static TypeId tid = TypeId("ns3::qdrav::LprepHeader")
                            .SetParent<Header>()
                            .SetGroupName("Qdrav")
                            .AddConstructor<LprepHeader>();
    return tid;
}

TypeId
LprepHeader::GetInstanceTypeId() const
{
    return GetTypeId();
}

uint32_t
LprepHeader::GetSerializedSize() const
{
    return 8 + 2*sizeof (float); 
}

void
LprepHeader::Serialize(Buffer::Iterator i) const
{
    NS_LOG_FUNCTION(this);
    i.WriteU16 (m_srcID);
    i.WriteU16(m_dstID);
    i.WriteU16(m_nextHopID);
    i.WriteU8(m_lprepID);
    i.WriteU8(uint8_t(m_qValue*255));   
    uint8_t *buf;
    buf = (uint8_t *)&m_xPos;
    for (uint32_t k = 0; k < sizeof (float); ++k, ++buf)
      {
        i.WriteU8 (*buf);  
      }
    buf = (uint8_t *)&m_yPos;
    for (uint32_t k = 0; k < sizeof (float); ++k, ++buf)
      {
        i.WriteU8 (*buf);  
      }
}

uint32_t
LprepHeader::Deserialize(Buffer::Iterator start)
{
    Buffer::Iterator i = start;
    m_srcID = i.ReadU16();
    m_dstID = i.ReadU16();
    m_nextHopID = i.ReadU16();
    m_lprepID = i.ReadU8();
    m_qValue = double(i.ReadU8()/255.0);   
    uint8_t *buf;
    buf = (uint8_t *)&m_xPos;
    for (uint32_t k = 0; k < sizeof (float); ++k, ++buf)
      {
        *buf = i.ReadU8 ();
      }
    buf = (uint8_t *)&m_yPos;
    for (uint32_t k = 0; k < sizeof (float); ++k, ++buf)
      {
        *buf = i.ReadU8 ();
      }

    uint32_t dist = i.GetDistanceFrom(start);
    NS_ASSERT(dist == GetSerializedSize());
    return dist;
}

void
LprepHeader::Print(std::ostream& os) const
{
    NS_LOG_FUNCTION(this);
    os << " Source ID: " << m_srcID;
    os << " Destination ID: " << m_dstID;
    os << " Next hop ID: " << m_nextHopID;
    os << " LPREP ID: " << (int)m_lprepID;
    os << " Q value: " << m_qValue;
    os << " Neighbor x position: " <<  m_xPos;
    os << " Neighbor y position: " <<  m_yPos;
}

std::ostream&
operator<<(std::ostream& os, const LprepHeader& h)
{
    h.Print(os);
    return os;
}

bool
LprepHeader::operator==(const LprepHeader& o) const
{
    return (m_srcID == o.m_srcID && m_dstID == o.m_dstID && m_nextHopID == o.m_nextHopID && m_lprepID == o.m_lprepID &&
            m_qValue == o.m_qValue && m_xPos == o.m_xPos && m_yPos == o.m_yPos);
}

//-----------------------------------------------------------------------------
// HELLO               
//-----------------------------------------------------------------------------

NS_OBJECT_ENSURE_REGISTERED (HelloHeader);

HelloHeader::HelloHeader () {}

TypeId
HelloHeader::GetTypeId ()
{
  static TypeId tid = TypeId ("ns3::qdrav::HelloHeader")
    .SetParent<Header> ()
    .SetGroupName("Qdrav")
    .AddConstructor<HelloHeader> ()
  ;
  return tid;
}

TypeId
HelloHeader::GetInstanceTypeId () const
{
  return GetTypeId ();
}

uint32_t
HelloHeader::GetSerializedSize () const
{
  NS_LOG_FUNCTION(this);
  return (2*sizeof (float) + 3 + 4*GetCountOfQMax ()); 
}

void 
HelloHeader::SetBandwidthFactor (double bf) 
{
  NS_LOG_FUNCTION(this);
  NS_ABORT_MSG_IF (bf<0.0 || bf>1.0, "BF not in range (0,1)");
  m_bandwidthFactor = (uint8_t)(bf*255.0); 
}

double 
HelloHeader::GetBandwidthFactor () const 
{
  NS_LOG_FUNCTION(this);
  NS_ABORT_MSG_IF (m_bandwidthFactor>255, "8b equivalent of BF not in range (0,255)");
  return (double)m_bandwidthFactor/255.0; 
}

void
HelloHeader::Serialize (Buffer::Iterator i ) const
{
  NS_LOG_FUNCTION(this);
  uint8_t *buf;
  buf = (uint8_t *)&m_xPos;
  for (uint32_t k = 0; k < sizeof (float); ++k, ++buf)
    {
      i.WriteU8 (*buf);  
    }
  buf = (uint8_t *)&m_yPos;
  for (uint32_t k = 0; k < sizeof (float); ++k, ++buf)
    {
      i.WriteU8 (*buf);  
    }
  i.WriteU8 (m_bandwidthFactor); 
  i.WriteU16 (m_countOfQMax);
  NS_LOG_DEBUG("PosX: " << m_xPos << ", PosY: " << m_yPos << ", BF: " << (int)m_bandwidthFactor << ", CountQMax: " << m_countOfQMax); 
  for (uint16_t j = 0; j < GetCountOfQMax (); ++j) 
    {
      uint16_t dst = m_qMax[j].dst;
      uint16_t nextHop = m_qMax[j].nextHop;
      uint8_t byte1, byte2, byte3; 
      byte1 = uint8_t(0x00FF & dst); 
      byte3 = uint8_t(0x00FF & nextHop); 
      byte2 = uint8_t((0x0F00 & dst) >> 4 | (0x0F00 & nextHop) >> 8);
      i.WriteU8 (byte1); 
      i.WriteU8 (byte2); 
      i.WriteU8 (byte3); 
      i.WriteU8 (uint8_t(m_qMax[j].qMax*255.0));  
      NS_LOG_DEBUG("Dst ID: " << m_qMax[j].dst << ", Next Hop ID: " << m_qMax[j].nextHop << ", maxQValue: " << uint16_t(m_qMax[j].qMax*255.0));
    }
}

uint32_t
HelloHeader::Deserialize (Buffer::Iterator start )
{
  NS_LOG_FUNCTION(this);
  Buffer::Iterator i = start;
  uint8_t *buf;
  buf = (uint8_t *)&m_xPos;
  for (uint32_t k = 0; k < sizeof (float); ++k, ++buf)
    {
      *buf = i.ReadU8 ();
    }
  buf = (uint8_t *)&m_yPos;
  for (uint32_t k = 0; k < sizeof (float); ++k, ++buf)
    {
      *buf = i.ReadU8 ();
    }
  m_bandwidthFactor = i.ReadU8(); 
  m_countOfQMax = i.ReadU16();
  NS_LOG_DEBUG("PosX: " << m_xPos << ", PosY: " << m_yPos << ", BF: " << (int)m_bandwidthFactor << ", CountQMax: " << m_countOfQMax);
  m_qMax.clear (); 
  for (uint16_t k = 0; k < m_countOfQMax; ++k) 
    {
      QmaxEntry entry;
      uint8_t byte1, byte2, byte3;
      byte1 = i.ReadU8();
      byte2 = i.ReadU8();
      byte3 = i.ReadU8();
      entry.dst = ((uint16_t(byte2) & 0x00F0) << 4) | uint16_t(byte1);
      entry.nextHop = ((uint16_t(byte2) & 0x000F) << 8) | uint16_t(byte3); 
      entry.qMax = double (i.ReadU8())/255.0;  
      NS_LOG_DEBUG("Dst ID: " << entry.dst << ", Next Hop ID: " <<  entry.nextHop << ", maxQValue: " << entry.qMax);
      m_qMax.insert (m_qMax.end (), entry);  
    }

  uint32_t dist = i.GetDistanceFrom (start);
  NS_ASSERT (dist == GetSerializedSize ());
  return dist;
}


void
HelloHeader::Print (std::ostream &os ) const
{
  NS_LOG_FUNCTION(this);
  os << " Originator x position: " <<  m_xPos;
  os << " Originator y position: " <<  m_yPos;
  os << " Bandwidth factor: " <<  (int)m_bandwidthFactor;
  os << " Number of MaxQValues: " <<  m_countOfQMax;
  std::cout << std::endl;
  for (int j = 0; j < GetCountOfQMax (); ++j) 
    {
      os << " Destination node: " << m_qMax[j].dst;
      os << " Next hop node: " << m_qMax[j].nextHop;
      os << " MaxQValue of node: " << m_qMax[j].qMax;
      std::cout << std::endl;
    }
}

bool
HelloHeader::operator== (HelloHeader const & o ) const
{
  NS_LOG_FUNCTION(this);
  if (m_xPos != o.m_xPos || m_yPos != o.m_yPos || m_bandwidthFactor != o.m_bandwidthFactor || m_countOfQMax != o.m_countOfQMax)
  {
    return false;
  }  

  for (uint16_t j = 0; j < GetCountOfQMax (); ++j) 
    {
      if (m_qMax[j].dst != o.m_qMax[j].dst || m_qMax[j].nextHop != o.m_qMax[j].nextHop || m_qMax[j].qMax != o.m_qMax[j].qMax)
      {
        return false;
      }     
    }
  return true;
}

std::ostream &
operator<< (std::ostream & os, HelloHeader const & h )
{
  h.Print (os);
  return os;
}

//-----------------------------------------------------------------------------
// RPP               
//-----------------------------------------------------------------------------

NS_OBJECT_ENSURE_REGISTERED (RppHeader);

RppHeader::RppHeader () {}

TypeId
RppHeader::GetTypeId ()
{
  static TypeId tid = TypeId ("ns3::qdrav::RppHeader")
    .SetParent<Header> ()
    .SetGroupName("Qdrav")
    .AddConstructor<RppHeader> ()
  ;
  return tid;
}

TypeId
RppHeader::GetInstanceTypeId () const
{
  return GetTypeId ();
}

uint32_t
RppHeader::GetSerializedSize () const
{
  NS_LOG_FUNCTION(this);
  return (3 + sizeof (float) + 2*GetCountOfIDs ()); 
}

void
RppHeader::Serialize (Buffer::Iterator i ) const
{
  NS_LOG_FUNCTION(this);
  uint8_t *buf;
  buf = (uint8_t *)&m_rppSendTime;
  for (uint32_t k = 0; k < sizeof (float); ++k, ++buf)
    {
      i.WriteU8 (*buf);  
      NS_LOG_DEBUG("Upisao k = " << k);
    }
  i.WriteU16 (m_dstID);
  NS_LOG_DEBUG("Upisao dst");
  i.WriteU8 (m_countOfIDs);
  NS_LOG_DEBUG("CountIDs: " << m_countOfIDs); 
  for (uint16_t j = 0; j < GetCountOfIDs (); ++j) 
    {
      i.WriteU16 (m_ids[j]); 
      NS_LOG_DEBUG("Node ID: " << m_ids[j]);
    }
}

uint32_t
RppHeader::Deserialize (Buffer::Iterator start )
{
  NS_LOG_FUNCTION(this);
  Buffer::Iterator i = start;
  uint8_t *buf;
  buf = (uint8_t *)&m_rppSendTime;
  for (uint32_t k = 0; k < sizeof (float); ++k, ++buf)
    {
      *buf = i.ReadU8 ();
    }
  m_dstID = i.ReadU16();
  m_countOfIDs = i.ReadU8();
  NS_LOG_DEBUG("CountIDs: " << m_countOfIDs);
  m_ids.clear (); 
  for (uint16_t k = 0; k < m_countOfIDs; ++k) 
    {
      uint16_t id = i.ReadU16();
      NS_LOG_DEBUG("Node ID: " << id);
      m_ids.insert (m_ids.end (), id);  
    }

  uint32_t dist = i.GetDistanceFrom (start);
  NS_ASSERT (dist == GetSerializedSize ());
  return dist;
}


void
RppHeader::Print (std::ostream &os ) const
{
  NS_LOG_FUNCTION(this);
  os << "RPP send time: " << m_rppSendTime << ", Destination ID: " << m_dstID << ", Number of IDs: " <<  (int)m_countOfIDs << std::endl << ", Node IDs: ";
  for (int j = 0; j < GetCountOfIDs (); ++j) 
    {
      os << m_ids[j] << ", ";
    }
    os << std::endl;
}

bool
RppHeader::operator== (RppHeader const & o ) const
{
  NS_LOG_FUNCTION(this);
  if ((m_rppSendTime != o.m_rppSendTime) || (m_dstID != o.m_dstID) || (m_countOfIDs != o.m_countOfIDs))
  {
    return false;
  }  

  for (uint16_t j = 0; j < GetCountOfIDs (); ++j) 
    {
      if (m_ids[j] != o.m_ids[j])
      {
        return false;
      }     
    }
  return true;
}

std::ostream &
operator<< (std::ostream & os, RppHeader const & h )
{
  h.Print (os);
  return os;
}

//-----------------------------------------------------------------------------
// RPP_ACK               
//-----------------------------------------------------------------------------

NS_OBJECT_ENSURE_REGISTERED (RppAckHeader);

RppAckHeader::RppAckHeader () {}

TypeId
RppAckHeader::GetTypeId ()
{
  static TypeId tid = TypeId ("ns3::qdrav::RppAckHeader")
    .SetParent<Header> ()
    .SetGroupName("Qdrav")
    .AddConstructor<RppAckHeader> ()
  ;
  return tid;
}

TypeId
RppAckHeader::GetInstanceTypeId () const
{
  return GetTypeId ();
}

uint32_t
RppAckHeader::GetSerializedSize () const
{
  NS_LOG_FUNCTION(this);
  return (4 + sizeof (float) + 2*GetCountOfIDs ()); 
}

void
RppAckHeader::Serialize (Buffer::Iterator i ) const
{
  NS_LOG_FUNCTION(this);
  uint8_t *buf;
  buf = (uint8_t *)&m_rppSendTime;
  for (uint32_t k = 0; k < sizeof (float); ++k, ++buf)
    {
      i.WriteU8 (*buf);  
    }
  i.WriteU16 (m_dstID);
  i.WriteU8 (m_rnb);
  i.WriteU8 (m_countOfIDs);
  NS_LOG_DEBUG("CountIDs: " << m_countOfIDs); 
  for (uint16_t j = 0; j < GetCountOfIDs (); ++j) 
    {
      i.WriteU16 (m_ids[j]); 
      NS_LOG_DEBUG("Node ID: " << m_ids[j]);
    }
}

uint32_t
RppAckHeader::Deserialize (Buffer::Iterator start )
{
  NS_LOG_FUNCTION(this);
  Buffer::Iterator i = start;
  uint8_t *buf;
  buf = (uint8_t *)&m_rppSendTime;
  for (uint32_t k = 0; k < sizeof (float); ++k, ++buf)
    {
      *buf = i.ReadU8 ();
    }
  m_dstID = i.ReadU16();
  m_rnb = i.ReadU8();
  m_countOfIDs = i.ReadU8();
  NS_LOG_DEBUG("CountIDs: " << m_countOfIDs);
  m_ids.clear (); 
  for (uint16_t k = 0; k < m_countOfIDs; ++k) 
    {
      uint16_t id = i.ReadU16();
      NS_LOG_DEBUG("Node ID: " << id);
      m_ids.insert (m_ids.end (), id);  
    }

  uint32_t dist = i.GetDistanceFrom (start);
  NS_ASSERT (dist == GetSerializedSize ());
  return dist;
}


void
RppAckHeader::Print (std::ostream &os ) const
{
  NS_LOG_FUNCTION(this);
  os << "RPP send time: " << m_rppSendTime << ", Destination ID: " << m_dstID << ", RBF: " <<  (int)m_rnb << ", Number of IDs: " <<  (int)m_countOfIDs << std::endl << ", Node IDs: ";
  for (int j = 0; j < GetCountOfIDs (); ++j) 
    {
      os << m_ids[j] << ", ";
    }
  os << std::endl;
}

bool
RppAckHeader::operator== (RppAckHeader const & o ) const
{
  NS_LOG_FUNCTION(this);
  if ((m_rppSendTime != o.m_rppSendTime) || (m_dstID != o.m_dstID) || (m_rnb != o.m_rnb) || (m_countOfIDs != o.m_countOfIDs))
  {
    return false;
  }  

  for (uint16_t j = 0; j < GetCountOfIDs (); ++j) 
    {
      if (m_ids[j] != o.m_ids[j])
      {
        return false;
      }     
    }
  return true;
}

std::ostream &
operator<< (std::ostream & os, RppAckHeader const & h )
{
  h.Print (os);
  return os;
}

} // namespace qdrav
} // namespace ns3
