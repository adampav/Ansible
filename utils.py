# Based on Linos Giannopoulos Code, https://github.com/linosgian/ #
class Colors:
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    DARKCYAN = '\033[36m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'


class UserLog:
    @staticmethod
    def info(format_string):
        return "{0}[*] {1}{2}".format(Colors.GREEN, format_string, Colors.END)

    @staticmethod
    def warn(format_string, bold=True):
        if bold:
            return "{0}{1}[*] {2}{3}".format(Colors.YELLOW, Colors.BOLD, format_string, Colors.END)
        else:
            return "{0}[*] {1}{2}".format(Colors.YELLOW, format_string, Colors.END)

    @staticmethod
    def error(format_string):
        return "{0}[*] {1}{2}".format(Colors.RED, format_string, Colors.END)

    def infopr(self, format_string):
        print(self.info(format_string))

    def warnpr(self, format_string, bold=True):
        print(self.warn(format_string, bold=bold))

    def errorpr(self, format_string):
        print(self.error(format_string))
