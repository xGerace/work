from datetime import datetime, timedelta
import logging
from typing import List, Tuple, Optional, Callable, Any

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def validate_datetime(input_str: str) -> bool:
    formats = ["%Y/%m/%d %H:%M:%S", "%Y/%m/%d %H:%M", "%Y/%m/%d %H", "%Y/%m/%d", "%Y/%m", "%Y"]
    for fmt in formats:
        try:
            datetime.strptime(input_str, fmt)
            return True
        except ValueError:
            continue
    return False

def get_validated_input(prompt: str, validation_func: Callable[[str], bool], default: Optional[str] = None) -> Optional[str]:
    while True:
        user_input = input(prompt)
        if user_input == '':
            return default
        if validation_func(user_input):
            return user_input
        else:
            logger.warning("Invalid input, please try again.")

def print_query_results(results: List[Tuple[Any, ...]], headers: List[str]) -> str:
    column_widths = [len(header) for header in headers]
    for row in results:
        for i, cell in enumerate(row):
            column_widths[i] = max(column_widths[i], len(str(cell)))
    row_format = " ".join(["{:<" + str(width) + "}" for width in column_widths])
    output = row_format.format(*headers) + "\n"
    for row in results:
        output += row_format.format(*row) + "\n"
    return output

def get_datetime_range(start_input: str, end_input: str) -> Tuple[datetime, datetime]:
    now = datetime.now()
    
    def parse_datetime(input_str: str) -> Tuple[Optional[datetime], Optional[datetime]]:
        try:
            if ':' in input_str:
                parts = input_str.split(':')
                if len(parts) == 3:
                    return datetime.strptime(input_str, "%Y/%m/%d %H:%M:%S"), datetime.strptime(input_str, "%Y/%m/%d %H:%M:%S") + timedelta(seconds=59)
                elif len(parts) == 2:
                    dt = datetime.strptime(input_str, "%Y/%m/%d %H:%M")
                    return dt, dt + timedelta(minutes=1) - timedelta(seconds=1)
                elif len(parts) == 1:
                    dt = datetime.strptime(input_str, "%Y/%m/%d %H")
                    return dt, dt + timedelta(hours=1) - timedelta(seconds=1)

            parts = input_str.split('/')
            if len(parts) == 1:
                dt = datetime(int(parts[0]), 1, 1)
                return dt, datetime(dt.year + 1, 1, 1) - timedelta(seconds=1)
            elif len(parts) == 2:
                dt = datetime(int(parts[0]), int(parts[1]), 1)
                next_month = dt.month + 1 if dt.month < 12 else 1
                next_year = dt.year if next_month > 1 else dt.year + 1
                return dt, datetime(next_year, next_month, 1) - timedelta(seconds=1)
            elif len(parts) == 3:
                dt = datetime.strptime(input_str, "%Y/%m/%d")
                return dt, dt + timedelta(days=1) - timedelta(seconds=1)
        except ValueError:
            logger.error("Failed to parse datetime", exc_info=True)
            return None, None

    start_datetime, end_datetime = (now - timedelta(days=1), now) if not start_input else parse_datetime(start_input)
    if end_input:
        _, end_datetime = parse_datetime(end_input)

    return start_datetime, end_datetime

def build_conditions(start_datetime: datetime, end_datetime: datetime) -> Tuple[str, List[str]]:
    conditions = ["Time_Generated >= ?", "Time_Generated <= ?"]
    params = [start_datetime.strftime("%Y/%m/%d %H:%M:%S"), end_datetime.strftime("%Y/%m/%d %H:%M:%S")]
    condition_str = " AND ".join(conditions)
    return condition_str, params

def get_user_confirmation(prompt: str, default: Optional[str] = None) -> bool:
    while True:
        user_input = input(prompt).strip().lower()
        if not user_input and default:
            user_input = default
        if user_input in ['yes', 'no', 'y', 'n']:
            return user_input in ['yes', 'y']
        logger.warning("Invalid input. Please enter 'yes' or 'no' (or 'y' or 'n').")