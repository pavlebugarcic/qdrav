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
#ifndef QDRAV_PACKET_H
#define QDRAV_PACKET_H

#include "ns3/enum.h"
#include "ns3/header.h"
#include "ns3/ipv4-address.h"
#include "ns3/nstime.h"

#include <iostream>
#include <map>
#include <vector>

namespace ns3
{
namespace qdrav
{

/**
 * \ingroup qdrav
 * \brief MessageType enumeration
 */
enum MessageType
{
    QDRAVTYPE_LPREQ = 1,      //!< QDRAVTYPE_LPREQ  
    QDRAVTYPE_LPREP = 2,      //!< QDRAVTYPE_LPREP  
    QDRAVTYPE_HELLO = 3,      //HELLO     
    QDRAVTYPE_RPP = 4,        //Route Probe Packet
    QDRAVTYPE_RPP_ACK = 5     //Route Probe Packet - ACK
};

/**
 * \ingroup qdrav
 * \brief Q-DRAV types
 */
class TypeHeader : public Header
{
  public:
    /**
     * constructor
     * \param t the Q-DRAV LPREQ type
     */
    TypeHeader(MessageType t = QDRAVTYPE_LPREQ);

    /**
     * \brief Get the type ID.
     * \return the object TypeId
     */
    static TypeId GetTypeId();
    TypeId GetInstanceTypeId() const override;
    uint32_t GetSerializedSize() const override;
    void Serialize(Buffer::Iterator start) const override;
    uint32_t Deserialize(Buffer::Iterator start) override;
    void Print(std::ostream& os) const override;

    /**
     * \returns the type
     */
    MessageType Get() const
    {
        return m_type;
    }

    /**
     * Check that type if valid
     * \returns true if the type is valid
     */
    bool IsValid() const
    {
        return m_valid;
    }

    /**
     * \brief Comparison operator
     * \param o header to compare
     * \return true if the headers are equal
     */
    bool operator==(const TypeHeader& o) const;

  private:
    MessageType m_type; ///< type of the message
    bool m_valid;       ///< Indicates if the message is valid
};

/**
 * \brief Stream output operator
 * \param os output stream
 * \return updated stream
 */
std::ostream& operator<<(std::ostream& os, const TypeHeader& h);

/**
* \ingroup qdrav
* \brief   Learning Probe Request (LPREQ) Message Format  
  \verbatim
  0                   1                   2                   3
  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |     Type      | xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx|
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |           Source ID           |         Destination ID        |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |          Next Hop ID          |   LPREQ ID    |  Qn(s,Nei(n)) | 
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                  x position of neighbor                       |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                  y position of neighbor                       | 
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

  \endverbatim
*/
class LpreqHeader : public Header
{
  public:
    /**
     * constructor
     *
     * \param srcID the source ID
     * \param dstID the destination ID
     * \param nextHopID the next hop ID
     * \param lpreqID the LPREQ ID
     * \param qValue the Q-value for route to src
     * \param xPos the x coordinate of neighbor
     * \param yPos the y coordinate of neighbor
     */
    LpreqHeader(uint16_t srcID = 0,
                uint16_t dstID = 0,
                uint16_t nextHopID = 0,
                uint8_t lpreqID = 0,
                double qValue = 0,
                float xPos = 0,
                float yPos = 0);

    /**
     * \brief Get the type ID.
     * \return the object TypeId
     */
    static TypeId GetTypeId();
    TypeId GetInstanceTypeId() const override;
    uint32_t GetSerializedSize() const override;
    void Serialize(Buffer::Iterator start) const override;
    uint32_t Deserialize(Buffer::Iterator start) override;
    void Print(std::ostream& os) const override;

    // Fields
    /**
     * \brief Set the source ID
     * \param s the source ID
     */
    void SetSrcID(uint16_t s)
    {
        m_srcID = s;
    }

    /**
     * \brief Get the source ID
     * \return the source ID
     */
    uint16_t GetSrcID() const
    {
        return m_srcID;
    }

    /**
     * \brief Set the destination ID
     * \param d the destination ID
     */
    void SetDstID(uint16_t d)
    {
        m_dstID = d;
    }

    /**
     * \brief Get the destination ID
     * \return the destination ID
     */
    uint16_t GetDstID() const
    {
        return m_dstID;
    }

    /**
     * \brief Set the next hop ID
     * \param n the next hop ID
     */
    void SetNextHopID(uint16_t n)
    {
        m_nextHopID = n;
    }

    /**
     * \brief Get the next hop ID
     * \return the next hop ID
     */
    uint16_t GetNextHopID() const
    {
        return m_nextHopID;
    }

    /**
     * \brief Set the LPREQ ID
     * \param l the LPREQ ID
     */
    void SetLpreqID(uint8_t l)
    {
        m_lpreqID = l;
    }

    /**
     * \brief Get the LPREQ ID
     * \return the LPREQ ID
     */
    uint8_t GetLpreqID() const
    {
        return m_lpreqID;
    }

    /**
     * \brief Set Q-value
     * \param q the Q-value
     */
    void SetQValue(double q)
    {
        m_qValue = q;
    }

    /**
     * \brief Get Q-value
     * \return the Q-value
     */
    double GetQValue() const
    {
        return m_qValue;
    }

    /**
     * \brief Set the neighbor x position
     * \param x the neighbor x position
     */
    void SetXPosition(float x)
    {
        m_xPos = x;
    }

    /**
     * \brief Get the the neighbor x position
     * \return the the neighbor x position
     */
    float GetXPosition() const
    {
        return m_xPos;
    }

    /**
     * \brief Set the neighbor y position
     * \param y the neighbor y position
     */
    void SetYPosition(float y)
    {
        m_yPos = y;
    }

    /**
     * \brief Get the the neighbor y position
     * \return the the neighbor y position
     */
    float GetYPosition() const
    {
        return m_yPos;
    }

    /**
     * \brief Comparison operator
     * \param o LPREQ header to compare
     * \return true if the LPREQ headers are equal
     */
    bool operator==(const LpreqHeader& o) const;

  private:
    uint16_t    m_srcID;      ///< Source ID
    uint16_t    m_dstID;      ///< Destination ID
    uint16_t    m_nextHopID;  ///< Next hop ID
    uint8_t     m_lpreqID;    ///< LPREQ ID
    double      m_qValue;     ///< Q-value for route to src     
    float      m_xPos;       ///< x coordinate of neighbor    
    float      m_yPos;       ///< y coordinate of neighbor
};

/**
 * \brief Stream output operator
 * \param os output stream
 * \return updated stream
 */
std::ostream& operator<<(std::ostream& os, const LpreqHeader&);

/**
* \ingroup qdrav
* \brief Learning Probe Reply (LPREP) Message Format
  \verbatim
  0                   1                   2                   3
  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |     Type      | xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx|
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |           Source ID           |         Destination ID        |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |          Next Hop ID          |   LPREQ ID    |  Qn(d,Nei(n)) | 
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                  x position of neighbor                       |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                  y position of neighbor                       | 
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  \endverbatim
*/
class LprepHeader : public Header
{
  public:
    /**
     * constructor
     *
     * \param srcID the source ID
     * \param dstID the destination ID
     * \param nextHopID the next hop ID
     * \param lprepID the LPREP ID
     * \param qValue the Q-value for route to src
     * \param xPos the x coordinate of neighbor
     * \param yPos the y coordinate of neighbor
     */
    LprepHeader(uint16_t srcID = 0,
                uint16_t dstID = 0,
                uint16_t nextHopID = 0,
                uint8_t lprepID = 0,
                double qValue = 0,
                float xPos = 0,
                float yPos = 0);

    /**
     * \brief Get the type ID.
     * \return the object TypeId
     */
    static TypeId GetTypeId();
    TypeId GetInstanceTypeId() const override;
    uint32_t GetSerializedSize() const override;
    void Serialize(Buffer::Iterator start) const override;
    uint32_t Deserialize(Buffer::Iterator start) override;
    void Print(std::ostream& os) const override;

    // Fields
    /**
     * \brief Set the source ID
     * \param s the source ID
     */
    void SetSrcID(uint16_t s)
    {
        m_srcID = s;
    }

    /**
     * \brief Get the source ID
     * \return the source ID
     */
    uint16_t GetSrcID() const
    {
        return m_srcID;
    }

    /**
     * \brief Set the destination ID
     * \param d the destination ID
     */
    void SetDstID(uint16_t d)
    {
        m_dstID = d;
    }

    /**
     * \brief Get the destination ID
     * \return the destination ID
     */
    uint16_t GetDstID() const
    {
        return m_dstID;
    }

    /**
     * \brief Set the next hop ID
     * \param n the next hop ID
     */
    void SetNextHopID(uint16_t n)
    {
        m_nextHopID = n;
    }

    /**
     * \brief Get the next hop ID
     * \return the next hop ID
     */
    uint16_t GetNextHopID() const
    {
        return m_nextHopID;
    }

    /**
     * \brief Set the LPREP ID
     * \param l the LPREP ID
     */
    void SetLprepID(uint8_t l)
    {
        m_lprepID = l;
    }

    /**
     * \brief Get the LPREP ID
     * \return the LPREP ID
     */
    uint8_t GetLprepID() const
    {
        return m_lprepID;
    }

    /**
     * \brief Set Q-value
     * \param q the Q-value
     */
    void SetQValue(double q)
    {
        m_qValue = q;
    }

    /**
     * \brief Get Q-value
     * \return the Q-value
     */
    double GetQValue() const
    {
        return m_qValue;
    }

    /**
     * \brief Set the neighbor x position
     * \param x the neighbor x position
     */
    void SetXPosition(float x)
    {
        m_xPos = x;
    }

    /**
     * \brief Get the the neighbor x position
     * \return the the neighbor x position
     */
    float GetXPosition() const
    {
        return m_xPos;
    }

    /**
     * \brief Set the neighbor y position
     * \param y the neighbor y position
     */
    void SetYPosition(float y)
    {
        m_yPos = y;
    }

    /**
     * \brief Get the the neighbor y position
     * \return the the neighbor y position
     */
    float GetYPosition() const
    {
        return m_yPos;
    }

    /**
     * \brief Comparison operator
     * \param o LPREP header to compare
     * \return true if the LPREP headers are equal
     */
    bool operator==(const LprepHeader& o) const;

  private:
    uint16_t    m_srcID;      ///< Source ID
    uint16_t    m_dstID;      ///< Destination ID
    uint16_t    m_nextHopID;  ///< Next hop ID
    uint8_t     m_lprepID;    ///< LPREP ID
    double      m_qValue;     ///< Q-value for route to src    
    float      m_xPos;       ///< x coordinate of neighbor
    float      m_yPos;       ///< y coordinate of neighbor
};

/**
 * \brief Stream output operator
 * \param os output stream
 * \return updated stream
 */
std::ostream& operator<<(std::ostream& os, const LprepHeader&);

/**
* \ingroup qdrav
* \brief Hello Message Format
  \verbatim
  0                   1                   2                   3
  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |     Type      | xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx|
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                x position of originator                       |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                y position of originator                       |  
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |       BF      |         Count of Qmax         |xxxxxxxxxxxxxxx|
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |      Destination ID [1]       |         NextHop ID [1]        |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |   QValue [1]  |                ...                            |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |      Destination ID [n]       |         NextHop ID [n]        |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |   QValue [n]  |xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx| 
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  \endverbatim
*/

//P: unos za niz Qmax
struct QmaxEntry 
{
    uint16_t dst;
    uint16_t nextHop;
    double qMax;
};

class HelloHeader : public Header
{
  public:
    ///constructor
    HelloHeader();

    /**
     * \brief Get the type ID.
     * \return the object TypeId
     */
    static TypeId GetTypeId();
    TypeId GetInstanceTypeId() const override;
    uint32_t GetSerializedSize() const override;
    void Serialize(Buffer::Iterator start) const override;
    uint32_t Deserialize(Buffer::Iterator start) override;
    void Print(std::ostream& os) const override;

    // Fields
    /**
     * \brief Set the originator x position
     * \param x the originator x position
     */
    void SetXPosition(float x)
    {
        m_xPos = x;
    }

    /**
     * \brief Get the the originator x position
     * \return the the originator x position
     */
    float GetXPosition() const
    {
        return m_xPos;
    }

    /**
     * \brief Set the originator y position
     * \param y the originator y position
     */
    void SetYPosition(float y)
    {
        m_yPos = y;
    }

    /**
     * \brief Get the the originator y position
     * \return the the originator y position
     */
    float GetYPosition() const
    {
        return m_yPos;
    }

    /**
   * \brief Set the bandwidth factor
   * \param bf the bandwidth factor
   */
   void SetBandwidthFactor (double bf);

   /**
   * \brief Get the bandwidth factor
   * \return the bandwidth factor
   */
   double GetBandwidthFactor () const;

    /**
   * \brief Set the number od MaxQValues 
   * \param m the number od MaxQValues
   */
   void SetCountOfQMax (uint16_t c) 
   {
     m_countOfQMax = c; 
   }
   /**
    * \brief Get the number od MaxQValues 
    * \return the number od MaxQValues
    */
   uint16_t GetCountOfQMax () const 
   {
     return m_countOfQMax; 
   }

   void SetQMax (std::vector<QmaxEntry> m)  
   {
     m_qMax = m; 
   } 
   std::vector<QmaxEntry> GetQMax () const 
   {
     return m_qMax; 
   }


  /**
   * \brief Comparison operator
   * \param o Hello header to compare
   * \return true if the Hello headers are equal
   */
    bool operator==(const HelloHeader& o) const;

  private:
    float      m_xPos;                                 ///< x coordinate of originator
    float      m_yPos;                                 ///< y coordinate of originator
    uint8_t     m_bandwidthFactor;                      ///< Bandwidth factor
    uint16_t    m_countOfQMax;                          ///< Number od max Q-values
    std::vector<QmaxEntry> m_qMax;                      ///<Vector of QmaxEntries (dst, nextHop, maxQValue)  

};

/**
 * \brief Stream output operator
 * \param os output stream
 * \return updated stream
 */
std::ostream& operator<<(std::ostream& os, const HelloHeader&);

/**
* \ingroup qdrav
* \brief   Route Probe Packet (RPP) Message Format  
  \verbatim
  0                   1                   2                   3
  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |     Type      | xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx|
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                         RPP send time                         |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |             Dst ID            |xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx|
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |  Count of IDs |        Node ID [1] - src      |     ...       |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |         Node ID [n]           |xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx|
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

  \endverbatim
*/
class RppHeader : public Header
{
  public:
    ///constructor
    RppHeader();

    /**
     * \brief Get the type ID.
     * \return the object TypeId
     */
    static TypeId GetTypeId();
    TypeId GetInstanceTypeId() const override;
    uint32_t GetSerializedSize() const override;
    void Serialize(Buffer::Iterator start) const override;
    uint32_t Deserialize(Buffer::Iterator start) override;
    void Print(std::ostream& os) const override;

   void SetRppSendTime (float t) 
   {
     m_rppSendTime = t; 
   }
   
   float GetRppSendTime () const 
   {
     return m_rppSendTime; 
   }
   /**
   * \brief Set the dst IDs 
   * \param d dst ID
   */
   void SetDestinationID (uint16_t d) 
   {
     m_dstID = d; 
   }
   /**
    * \brief Get dst ID 
    * \return dst ID
    */
   uint16_t GetDestinationID () const 
   {
     return m_dstID; 
   }
   
    /**
   * \brief Set the number od IDs 
   * \param c the number od IDs
   */
   void SetCountOfIDs (uint8_t c) 
   {
     m_countOfIDs = c; 
   }
   /**
    * \brief Get the number od IDs 
    * \return the number od IDs
    */
   uint8_t GetCountOfIDs () const 
   {
     return m_countOfIDs; 
   }
   
   void SetIDs (std::vector<uint16_t> m)  
   {
     m_ids = m; 
   } 
   std::vector<uint16_t> GetIDs () const 
   {
     return m_ids; 
   }


  /**
   * \brief Comparison operator
   * \param o RPP header to compare
   * \return true if the RPP headers are equal
   */
    bool operator==(const RppHeader& o) const;

  private:
    float    m_rppSendTime;                            ///< RPP send time
    uint16_t  m_dstID;                                 ///<Destination ID
    uint16_t    m_countOfIDs;                          ///< Number od IDs
    std::vector<uint16_t> m_ids;                       ///<Vector of IDs 
};

/**
 * \brief Stream output operator
 * \param os output stream
 * \return updated stream
 */
std::ostream& operator<<(std::ostream& os, const RppHeader&);

/**
* \ingroup qdrav
* \brief   Route Probe Packet - ACK (RPP_ACK) Message Format  
  \verbatim
  0                   1                   2                   3
  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |     Type      | xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx|
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                         RPP send time                         |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |             Dst ID            |RouteNormBandw |xxxxxxxxxxxxxxx|
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |  Count of IDs |        Node ID [1] - src      |     ...       |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |         Node ID [n]           |xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx|
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

  \endverbatim
*/
class RppAckHeader : public Header
{
  public:
    ///constructor
    RppAckHeader();

    /**
     * \brief Get the type ID.
     * \return the object TypeId
     */
    static TypeId GetTypeId();
    TypeId GetInstanceTypeId() const override;
    uint32_t GetSerializedSize() const override;
    void Serialize(Buffer::Iterator start) const override;
    uint32_t Deserialize(Buffer::Iterator start) override;
    void Print(std::ostream& os) const override;

   void SetRppSendTime (float t) 
   {
     m_rppSendTime = t; 
   }
   
   float GetRppSendTime () const 
   {
     return m_rppSendTime; 
   }
   /**
   * \brief Set the dst IDs 
   * \param d dst ID
   */
   void SetDestinationID (uint16_t d) 
   {
     m_dstID = d; 
   }
   /**
    * \brief Get dst ID 
    * \return dst ID
    */
   uint16_t GetDestinationID () const 
   {
     return m_dstID; 
   }

   /**
   * \brief Set the RNB 
   * \param rnb th RNB
   */
   void SetRNB (double rnb) 
   {
     rnb = (rnb > 1.0) ? (1.0) : (rnb); 
     rnb = (rnb < 0.0) ? (0.0) : (rnb); 
     m_rnb = (uint8_t)(rnb*(double)(0xFF));
   }
   /**
    * \brief Get RNB 
    * \return RNB
    */
   double GetRNB () const 
   {
     return (double)m_rnb/(double)(0xFF);
   }
   
    /**
   * \brief Set the number od IDs 
   * \param c the number od IDs
   */
   void SetCountOfIDs (uint8_t c) 
   {
     m_countOfIDs = c; 
   }
   /**
    * \brief Get the number od IDs 
    * \return the number od IDs
    */
   uint8_t GetCountOfIDs () const 
   {
     return m_countOfIDs; 
   }
   
   void SetIDs (std::vector<uint16_t> m)  
   {
     m_ids = m; 
   } 
   std::vector<uint16_t> GetIDs () const 
   {
     return m_ids; 
   }


  /**
   * \brief Comparison operator
   * \param o RPP header to compare
   * \return true if the RPP headers are equal
   */
    bool operator==(const RppAckHeader& o) const;

  private:
    float    m_rppSendTime;                            ///< RPP send time
    uint16_t  m_dstID;                                 ///<Destination ID
    uint8_t m_rnb;                                     ///<RouteNormalizedBandwidth
    uint16_t    m_countOfIDs;                          ///< Number od IDs
    std::vector<uint16_t> m_ids;                       ///<Vector of IDs 
};

std::ostream& operator<<(std::ostream& os, const RppAckHeader&);

} // namespace qdrav
} // namespace ns3

#endif /* QDRAV_PACKET_H */