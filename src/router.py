# Task: Create some functions for a simplified BGP router
#   Specifically, the withdraw, update, and next_hop functions of the Router
#   The class Route will be used.
# 
#   withdraw(rt) - rt is type Route. If a simplified BGP router gets this message, it will   
#


class Route:
    # A prefix is in form 
    neighbor = ""  # The router that send this router - will be a.b.c.d
    prefix = ""    # The IP address portion of a prefix - will be a.b.c.d
    prefix_len = 0 # The length portion of a prefix - will be an integer
    path = []      # the AS path - list of integers

    def __init__(self, neigh, p, plen, path):
        self.neighbor = neigh
        self.prefix = p
        self.prefix_len = plen
        self.path = path 

    # convert Route to a String    
    def __str__(self):
        return self.prefix+"/"+str(self.prefix_len)+"- ASPATH: " + str(self.path)+", neigh: "+self.neighbor

    # Get the prefix in the a.b.c.d/x format
    def pfx_str(self):
        return self.prefix+"/"+str(self.prefix_len)


# Implement the following functions:
#  update - the router received a route advertisement (which can be a new one, or an update
#         - the function needs to store the route in the RIB
#  withdraw - the router received a route withdraw message
#          - the function needs to delete the route in the RIB
#  nexthop - given ipaddr in a.b.c.d format as a string (e.g., "10.1.2.3"), perform a longest prefix match in the RIB
#          - Select the best route among multiple routes for that prefix by path length.  
#          - if same length, return either

class Router:
    # You can use a different data structure
    # dictionary with key of the prefix, value a list of Route
    # example: rib["10.0.0.0/24"] = [Route("1.1.1.1", "10.0.0.0", 24, [1,2,3]), 
    #                                Route("2.2.2.2", "10.0.0.0", 24, [10,20])]
    #          rib["10.0.0.0/22"] = [Route("3.3.3.3", "10.0.0.0", 22, [33,44,55,66]]
    rib = {} 

    # If you use the same data structure for the rib, this will print it
    def printRIB(self):
        for pfx in self.rib.keys():
            for route in self.rib[pfx]:
                print(route) 


    # TASK
    def update(self, rt):
        # Get the prefix in a.b.c.d/x format for the route 
        prefix = rt.pfx_str()

        # If the prefix is not in the router, create a key with an empty list.
        if prefix not in self.rib:
            self.rib[prefix] = []

        # Check if the route from the same neighbor already exists, if so, update it. 
        for index, route in enumerate(self.rib[prefix]):
            if route.neighbor == rt.neighbor:
                self.rib[prefix][index] = rt
                return
        
        # If no existing neighbor has this route, add this route to the prefix
        self.rib[prefix].append(rt)
        return
        
    # TASK    
    def withdraw(self, rt):
        # Get the prefix in a.b.c.d/x format for the route
        prefix = rt.pfx_str()

        # If the prefix is not in the router, then there is nothing to withdraw.
        if prefix not in self.rib:
            return

        # Update list just including routes that are not from the neighbor specified in the withdraw message
        self.rib[prefix] = [r for r in self.rib[prefix] if (r.neighbor != rt.neighbor)]

        # If no routes remain for this prefix, remove the prefix key itself
        if len(self.rib[prefix]) == 0:
            del self.rib[prefix]

        return 
    
    def convertToBinaryString(self, ip):
        vals = ip.split(".")
        a = format(int(vals[0]), 'b').rjust(8, '0')
        b = format(int(vals[1]), 'b').rjust(8, '0')
        c = format(int(vals[2]), 'b').rjust(8, '0')
        d = format(int(vals[3]), 'b').rjust(8, '0')
        return a+b+c+d

    # ipaddr in a.b.c.d format
    # find longest prefix that matches
    # then find shortest path of routes for that prefix
    def next_hop(self, ipaddr):
        retval = None
        longest = 0

        # Iterate through the whole list of destinations
        for pfx in self.rib.keys():
            # Split the prefix string into an IP address and a prefix length variables
            prefix, pfx_len = pfx.split("/")
            # Cast prefix length string into an integer for upcoming operations
            pfx_len = int(pfx_len)

            # If the binary portion of the IP address, up to the prefix length, matches the binary portion of the prefix,then we have a match
            if self.convertToBinaryString(ipaddr)[:pfx_len] == self.convertToBinaryString(prefix)[:pfx_len]:
                # If this is the longest prefix so far, update the return value
                if pfx_len > longest:
                    # Update longest prefix length so far
                    longest = pfx_len
                    # Initialize the route length variable to None for this prefix, so we can find the shortest path for this prefix
                    route_len = None

                    # Iterate through the routes available to get to this destination
                    for route in self.rib[pfx]:
                        # Find the shortest path for this prefix
                        if (route_len == None) or (len(route.path) < route_len):
                            # Update the route length variable to the length of this path, since it is the shortest so far for this prefix
                            route_len = len(route.path)
                            # Update the return value to the neighbor for this route, since it is the best route so far for this prefix
                            retval = route.neighbor

        return retval

def test_cases():
    rtr = Router()

    #Test that withdrawing a non-existant route works
    rtr.withdraw (Route("1.1.1.1", "10.0.0.0", 24, [3,4,5]))

    #Test updates work - same prefix, two neighbors
    rtr.update (Route("1.1.1.1", "10.0.0.0", 24, [3,4,5]))
    rtr.update (Route("2.2.2.2", "10.0.0.0", 24, [1,2]))

    # print("RIB")
    # rtr.printRIB()

    #Test updates work - overwriting an existing route from a neighbor
    rtr.update (Route("2.2.2.2", "10.0.0.0", 24, [1, 22, 33, 44]))

    # print("RIB")
    # rtr.printRIB()

    #Test updates work - an overlapping prefix (this case, a shorter prefix)
    rtr.update (Route("2.2.2.2", "10.0.0.0", 22, [4,5,7,8]))

    #Test updates work - completely different prefix
    rtr.update (Route("2.2.2.2", "12.0.0.0", 16, [4,5]))
    rtr.update (Route("1.1.1.1", "12.0.0.0", 16, [1, 2, 30]))

    # print("RIB")
    # rtr.printRIB()

    # Should not return an ip
    nh = rtr.next_hop("10.2.0.13")
    assert nh == None

    # Should return an ip
    nh = rtr.next_hop("10.0.0.13")
    assert nh == "1.1.1.1"

    # Test withdraw - withdraw the route from 1.1.1.1 that we just matched
    rtr.withdraw (Route("1.1.1.1", "10.0.0.0", 24, [3,4,5]))

    # Should match something different
    nh = rtr.next_hop("10.0.0.13")
    assert nh == "2.2.2.2"

    # Re-announce - so, 1.1.1.1 would now be best route
    rtr.withdraw (Route("1.1.1.1", "10.0.0.0", 24, [3,4,5]))

    
    rtr.update (Route("2.2.2.2", "10.0.0.0", 22, [4,5,7,8]))
    # Should match 10.0.0.0/22 (next hop 2.2.2.2) but not 10.0.0.0/24 (next hop 1.1.1.1)
    nh = rtr.next_hop("10.0.1.77")
    assert nh == "2.2.2.2"

    # Test a different prefix
    nh = rtr.next_hop("12.0.12.0")
    assert nh == "2.2.2.2"

    rtr.update (Route("1.1.1.1", "20.0.0.0", 16, [4,5,7,8]))
    rtr.update (Route("2.2.2.2", "20.0.0.0", 16, [44,55]))
    nh = rtr.next_hop("20.0.12.0")
    assert nh == "2.2.2.2"

    rtr.update (Route("1.1.1.1", "20.0.12.0", 24, [44,55,66,77,88]))
    nh = rtr.next_hop("20.0.12.0")
    assert nh == "1.1.1.1"


    # Remember to delete the entry from the RIB, not just removing the specific route
    # That is, when you withdraw, remove the route for the prefix, and if there are 0 routes, remove the prefix from the RIB
    rtr.withdraw(Route("1.1.1.1", "20.0.12.0", 24, [44,55,66,77,88]))
    nh = rtr.next_hop("20.0.12.0")
    assert nh == "2.2.2.2"

if __name__ == "__main__":
    test_cases()