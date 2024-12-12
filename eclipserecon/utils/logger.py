from colorama import Fore, Style
import logging

class AppFormatter(logging.Formatter):

    FORMATS = {
        logging.INFO: f"{Fore.GREEN}💡 INFO: {Style.RESET_ALL}%(message)s",
        logging.WARNING: f"{Fore.YELLOW}⚠️ WARNING: {Style.RESET_ALL}%(message)s",
        logging.ERROR: f"{Fore.RED}❌ ERROR: {Style.RESET_ALL}%(message)s",
        logging.CRITICAL: f"{Fore.MAGENTA}🔥 CRITICAL: {Style.RESET_ALL}%(message)s"
    }

    def format(self, record):
        log_fmt = self.FORMATS.get(record.levelno, "%(message)s")
        formatter = logging.Formatter(log_fmt)
        return formatter.format(record)

logging.basicConfig(level=logging.INFO)
appLogger = logging.getLogger()

handler = logging.StreamHandler()
handler.setFormatter(AppFormatter())
appLogger.handlers = [handler]