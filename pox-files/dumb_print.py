# Copyright 2011 James McCauley
#
# This file is part of POX.
#
# POX is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# POX is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with POX.  If not, see <http://www.gnu.org/licenses/>.

"""
This is an L2 learning switch written directly against the OpenFlow library.
It is derived from one written live for an SDN crash course.
"""

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.revent import *
from pox.lib.util import dpidToStr
from pox.lib.util import str_to_bool
from pox.lib.packet import ethernet
import time

log = core.getLogger()

# We don't want to flood immediately when a switch connects.
FLOOD_DELAY = 0


class DumbSwitch (EventMixin):
  """
  The learning switch "brain" associated with a single OpenFlow switch.

  When we see a packet, we'd like to output it on a port which will
  eventually lead to the destination.  To accomplish this, we build a
  table that maps addresses to ports.

  We populate the table by observing traffic.  When we see a packet
  from some source coming from some port, we know that source is out
  that port.

  When we want to forward traffic, we look up the desintation in our
  table.  If we don't know the port, we simply send the message out
  all ports except the one it came in on.  (In the presence of loops,
  this is bad!).

  In short, our algorithm looks like this:

  For each new flow:
  1) Use source address and port to update address/port table
  2) Is destination address a Bridge Filtered address, or is Ethertpe LLDP?
     * This step is ignored if transparent = True *
     Yes:
        2a) Drop packet to avoid forwarding link-local traffic (LLDP, 802.1x)
            DONE
  3) Is destination multicast?
     Yes:
        3a) Flood the packet
            DONE
  4) Port for destination address in our address/port table?
     No:
        4a) Flood the packet
            DONE
  5) Is output port the same as input port?
     Yes:
        5a) Drop packet and similar ones for a while
  6) Install flow table entry in the switch so that this
     flow goes out the appopriate port
     6a) Send buffered packet out appopriate port
  """
  def __init__ (self, connection, transparent):
    # Switch we'll be adding L2 learning switch capabilities to
    self.connection = connection
    self.transparent = transparent

    # We want to hear PacketIn messages, so we listen
    self.listenTo(connection)

    log.debug("Initializing DumbSwitch, transparent=%s",
              str(self.transparent))

  def _handle_PacketIn (self, event):
    """
    Handles packet in messages from the switch to implement above algorithm.
    """

    packet = event.parse()
    log.debug("%i %x", event.dpid, packet.type)
    def flood ():
      """ Floods the packet """
      if event.ofp.buffer_id == -1:
        log.warning("Not flooding unbuffered packet on %s",
                    dpidToStr(event.dpid))
        return
      msg = of.ofp_packet_out()
      if time.time() - self.connection.connect_time > FLOOD_DELAY:
        # Only flood if we've been connected for a little while...
        log.debug("%i: flood %s -> %s", event.dpid, packet.src, packet.dst)
        if packet.dst.toInt() < 5 and packet.dst.toInt() < 5 and event.dpid != packet.dst.toInt() and packet.type != ethernet.VLAN_TYPE:
            log.debug("No vlan tag, pushing")
            msg.actions.append(of.ofp_action_vlan_vid(vlan_vid = event.dpid))
        elif packet.src.toInt() < 5 and packet.dst.toInt() < 5 and event.dpid == packet.dst.toInt() and packet.type == ethernet.VLAN_TYPE:
            log.debug("VLAN tag found, popping")
            msg.actions.append(of.ofp_action_header(type=of.ofp_action_type_rev_map['OFPAT_STRIP_VLAN']))
        msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
      else:
        pass
        log.info("Holding down flood for %s", dpidToStr(event.dpid))
      msg.buffer_id = event.ofp.buffer_id
      msg.in_port = event.port
      self.connection.send(msg)

    def drop (duration = None):
      """
      Drops this packet and optionally installs a flow to continue
      dropping similar ones for a while
      """
      if duration is not None:
        if not isinstance(duration, tuple):
          duration = (duration,duration)
        msg = of.ofp_flow_mod()
        msg.match = of.ofp_match.from_packet(packet)
        msg.idle_timeout = duration[0]
        msg.hard_timeout = duration[1]
        msg.buffer_id = event.ofp.buffer_id
        self.connection.send(msg)
      elif event.ofp.buffer_id != -1:
        msg = of.ofp_packet_out()
        msg.buffer_id = event.ofp.buffer_id
        msg.in_port = event.port
        self.connection.send(msg)

    flood()

class dumb_print (EventMixin):
  """
  Waits for OpenFlow switches to connect and makes them learning switches.
  """
  def __init__ (self, transparent):
    self.listenTo(core.openflow)
    self.transparent = transparent

  def _handle_ConnectionUp (self, event):
    log.debug("Connection %s" % (event.connection,))
    DumbSwitch(event.connection, self.transparent)


def launch (transparent=False):
  """
  Starts an L2 learning switch.
  """
  from pox.openflow.topology import OpenFlowTopology
  from pox.openflow.discovery import Discovery
  from pox.topology import topology
  if not core.hasComponent("openflow_topology"):
    core.register("openflow_topology", OpenFlowTopology())
  core.registerNew(topology.Topology)
  core.registerNew(Discovery, explicit_drop=True,
                   install_flow=True)
  core.registerNew(dumb_print, str_to_bool(transparent))
