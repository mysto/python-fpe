import unittest
from tests import pyfpe_ff3_test


def pyfpe_ff3_suite():
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromModule(pyfpe_ff3_test)
    return suite
