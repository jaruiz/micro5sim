
import abc


# Each peripheral block is allocated an aligned range of addresses for its 
# internal registers. 
# This mask gets the bits used as internal address lines.
BLOCK_MASK = 0xff



class Peripheral:
    __metaclass__ = abc.ABCMeta

    @abc.abstractmethod
    def __init__(self, *args):
        pass

    @abc.abstractmethod
    def reset(self):
        """Simulate HW reset, reset internal state."""
        pass

    @abc.abstractmethod
    def clock(self, cycles):
        """Simulate passage of a number of clock cycles.
        Return True if this block's interrupt line is asserted."""
        return False

    @abc.abstractmethod
    def read(self, address):
        """Read 32-bit word from word-aligned address."""
        return 0

    @abc.abstractmethod
    def write(self, address, value, nbytes):
        """Write 32-, 16- or 8-bit value on suitably aligned address.
        (value is a 32-bit word with the data already in the right lanes.)
        """
        pass



class UART(Peripheral):

    def __init__(self, ofile=None, ifile=None):
        self.ofile = ofile
        self.ifile = ifile


    def reset(self):
        pass


    def clock(self, cycles):
        # FIXME should simulate at least a token tx/rx delay.
        return False


    def read(self, address):
        offset = address & BLOCK_MASK
        # FIXME UART read-from-file unimplemented.
        # FIXME status reg for polling missing.
        return 0


    def write(self, address, value, nbytes=4):
        offset = address & BLOCK_MASK
        if offset==0:
            if self.ofile:
                self.ofile.write("%c" % (value & 0xff))
                self.ofile.flush()



class Timer(Peripheral):

    def __init__(self, period):
        self.cycles = 0
        self.period = period
        self._rearm()


    def reset(self):
        self.cycles = 0
        self._rearm()

    def clock(self, cycles):
        self.cycles = self.cycles + cycles
        self.downcount = self.downcount - cycles
        if self.downcount <= 0:
            self._rearm()
            return True
        else:
            return False


    def read(self, address):
        offset = address & BLOCK_MASK
        return self.cycles


    def write(self, address, value, nbytes=4):
        pass


    def _rearm(self):
        self.downcount = self.period
