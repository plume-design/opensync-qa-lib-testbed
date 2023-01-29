#!/usr/bin/env python3

import sys
import traceback


class OpenSyncException(Exception):
    def __init__(self, message, advice=''):
        super(OpenSyncException, self).__init__(message)
        self.advice = advice
        self.message = message

    def __str__(self):
        adv = f'\n\nAdvice: {self.advice}' if self.advice else ''
        return f'{self.message}{adv}'


if __name__ == '__main__':
    try:
        raise OpenSyncException('OpenSyncException was thrown', 'We suggest you add X and Y to your configuration')

    except OpenSyncException as pe:
        print(pe)
        if '-D' in sys.argv:
            traceback.print_exc()
