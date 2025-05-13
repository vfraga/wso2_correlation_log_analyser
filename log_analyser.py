import csv
import gzip
import io
import logging
import re
import tarfile
import zipfile
from collections import defaultdict
from typing import List, Dict, Any, Tuple, Optional, Union

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st
from plotly.subplots import make_subplots

# --- Configuration & Constants ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Column Definitions: These define the expected structure of different log entry types.
COLS_JDBC = ['timestamp', 'correlationID', 'threadID', 'duration', 'callType', 'startTime', 'methodName', 'query',
             'connectionUrl']
COLS_LDAP = ['timestamp', 'correlationID', 'threadID', 'duration', 'callType', 'startTime', 'methodName', 'providerUrl',
             'principal', 'argsLength', 'args']
COLS_HTTP_REQ = ['timestamp', 'correlationID', 'threadID', 'duration', 'eventType', 'startTime', 'methodName',
                 'requestQuery', 'requestPath']
COLS_HTTP_RES = ['timestamp', 'correlationID', 'threadID', 'totalDurationForRequest', 'eventType', 'startTime',
                 'methodName', 'requestQuery', 'requestPath']

# ROW_TYPE_CONFIG maps (identifier_string, column_count) to internal type name and columns.
# This is central to identifying and parsing different log line formats.
ROW_TYPE_CONFIG: Dict[Tuple[str, int], Dict[str, Any]] = {
    ("jdbc", len(COLS_JDBC)): {'name': "JDBC", 'cols': COLS_JDBC},
    ("ldap", len(COLS_LDAP)): {'name': "LDAP", 'cols': COLS_LDAP},
    ("HTTP-In-Request", len(COLS_HTTP_REQ)): {'name': "HTTPRequest", 'cols': COLS_HTTP_REQ},
    ("HTTP-In-Response", len(COLS_HTTP_RES)): {'name': "HTTPResponse", 'cols': COLS_HTTP_RES},
}

# Parsing and Processing Constants
IDENTIFIER_COL_INDEX: int = 4
CORRELATION_ID_COL_INDEX: int = 1
CORRELATION_ID_NULL_VALUES: set[str] = {'', '-', 'null', ' ', "''"}
CORRELATION_ID_REPLACEMENT: str = "NO_CORRELATION_ID"
TIMESTAMP_FORMAT: str = "%Y-%m-%d %H:%M:%S,%f"  # Format for parsing raw log timestamps

# Standardized Event Type Strings (used consistently in analysis)
EVENT_TYPE_JDBC: str = "jdbc"
EVENT_TYPE_LDAP: str = "ldap"
EVENT_TYPE_HTTP_REQUEST: str = "HTTP-In-Request"
EVENT_TYPE_HTTP_RESPONSE: str = "HTTP-In-Response"

# UI and Charting Constants
MIN_VISIBLE_GANTT_DURATION_MS: int = 1
P95_MIN_SAMPLES: int = 1  # Min samples for P95 calculation in time series
DATETIME_TABLE_DISPLAY_FORMAT: str = "YYYY-MM-DD HH:mm:ss.SSS"  # For st.column_config

# Regex
SPACE_RE: re.Pattern = re.compile(r'\s{2,}')


# --- Utility Functions ---
def clean_value(value: str) -> str:
    """Removes extra spaces and strips leading/trailing whitespace from a string."""
    return SPACE_RE.sub(' ', value.strip())


def standardize_correlation_id(correlation_id: str) -> str:
    """Replaces null-like correlation IDs with a standard placeholder."""
    return CORRELATION_ID_REPLACEMENT if correlation_id in CORRELATION_ID_NULL_VALUES else correlation_id


def format_duration_ms(duration_ms: Optional[float]) -> str:
    """Formats a duration (in ms) to a string like '1,234 ms' or 'N/A'."""
    if pd.isna(duration_ms): return "N/A"
    return f"{duration_ms:,.0f} ms"


def format_datetime_with_3_ms(dt_val: Optional[pd.Timestamp]) -> str:
    """Formats a pandas Timestamp to a string 'YYYY-MM-DD HH:MM:SS.mmm' or 'N/A Time'."""
    if pd.isna(dt_val): return "N/A Time"
    return dt_val.strftime('%Y-%m-%d %H:%M:%S.') + str(dt_val.microsecond // 1000).zfill(3)


def p95_agg(series: pd.Series) -> Optional[float]:  # pd.NA is float-compatible for Pandas internal NA
    """
    Calculates the 95th percentile for a pandas Series.
    Returns pd.NA if calculation is not possible or doesn't meet sample threshold.
    """
    numeric_series = pd.to_numeric(series, errors='coerce').dropna()
    if len(numeric_series) >= P95_MIN_SAMPLES:
        return numeric_series.quantile(0.95)
    return pd.NA


# --- File Handling and Initial Parsing ---
def _is_log_file(filename: str) -> bool:
    """Heuristically checks if a filename likely represents a correlation log."""
    name_lower = filename.lower()
    # More specific: starts with "correlation" and ends with ".log" or ".log.NUMBER" or ".csv"
    is_correlation_log = name_lower.startswith("correlation") and \
                         (name_lower.endswith(".log") or re.match(r".*\.log\.\d+$", name_lower) or name_lower.endswith(
                             ".csv"))
    return is_correlation_log


def _extract_log_contents_from_uploads(
        uploaded_files: List[st.runtime.uploaded_file_manager.UploadedFile]
) -> List[Tuple[str, io.StringIO]]:
    """
    Extracts log file contents from a list of uploaded files, handling common archives.
    Skips unsupported file types with a warning.

    Args:
        uploaded_files: A list of files uploaded via st.file_uploader.

    Returns:
        A list of tuples, where each tuple is (filename_for_logging, io.StringIO_object).
    """
    all_log_contents: List[Tuple[str, io.StringIO]] = []
    if not uploaded_files:
        return all_log_contents

    for uploaded_file in uploaded_files:
        filename = uploaded_file.name
        logging.info(f"Processing uploaded item: {filename}")
        try:
            file_content_str: Optional[str] = None
            source_filename_for_log: str = filename

            if filename.lower().endswith(".zip"):
                with zipfile.ZipFile(uploaded_file, 'r') as zip_ref:
                    for member_name in zip_ref.namelist():
                        if _is_log_file(member_name):
                            logging.info(f"Extracting {member_name} from ZIP {filename}")
                            member_content_bytes = zip_ref.read(member_name)
                            all_log_contents.append(
                                (f"{filename}/{member_name}", io.StringIO(member_content_bytes.decode('utf-8'))))
            elif filename.lower().endswith((".tar.gz", ".tgz")):
                uploaded_file.seek(0)  # Reset file pointer
                with tarfile.open(fileobj=uploaded_file, mode="r:gz") as tar_ref:
                    for member in tar_ref.getmembers():
                        if member.isfile() and _is_log_file(member.name):
                            logging.info(f"Extracting {member.name} from TAR.GZ {filename}")
                            extracted_member = tar_ref.extractfile(member)
                            if extracted_member:
                                member_content_bytes = extracted_member.read()
                                all_log_contents.append(
                                    (f"{filename}/{member.name}", io.StringIO(member_content_bytes.decode('utf-8'))))
            elif filename.lower().endswith(".gz"):
                uploaded_file.seek(0)  # Reset file pointer
                with gzip.GzipFile(fileobj=uploaded_file, mode='rb') as gz_ref:
                    member_content_bytes = gz_ref.read()
                    all_log_contents.append((filename, io.StringIO(member_content_bytes.decode('utf-8'))))
            elif _is_log_file(filename):  # Direct log file
                member_content_bytes = uploaded_file.getvalue()
                all_log_contents.append((filename, io.StringIO(member_content_bytes.decode('utf-8'))))
            else:
                logging.warning(f"Skipping unsupported file type or non-log file: {filename}")
                st.toast(f"Skipped file: {filename} (unsupported type or not a recognized log file)", icon="⚠️")

        except UnicodeDecodeError:
            logging.error(f"UnicodeDecodeError processing file {filename}. Ensure UTF-8 encoding.")
            st.warning(f"Could not decode file: {filename}. Please ensure it's UTF-8 encoded.", icon="🔥")
        except Exception as e:  # Catch other exceptions during file processing
            logging.error(f"Error processing file {filename}: {e}", exc_info=True)
            st.warning(f"Could not fully process file: {filename}. Error: {e}", icon="🔥")

    return all_log_contents


def _parse_single_log_stream(filename_for_logging: str, log_io_stream: io.StringIO,
                             master_parsed_data: Dict[str, List[List[str]]],
                             master_unknown_rows: List[Dict[str, Any]]):
    """Parses content from a single log stream and appends to master collections."""
    try:
        reader = csv.reader(log_io_stream, delimiter='|')
        logging.info(f"Parsing content from: {filename_for_logging}")
        for i, row_values in enumerate(reader):
            row_number = i + 1
            max_req_idx = max(IDENTIFIER_COL_INDEX, CORRELATION_ID_COL_INDEX)
            if not row_values or len(row_values) <= max_req_idx:
                logging.debug(f"Skipping row {row_number} in {filename_for_logging}: Insufficient columns.")
                continue

            cleaned_row_values = [clean_value(v) for v in row_values]
            num_columns = len(cleaned_row_values)

            # Defensive checks for column indices
            if CORRELATION_ID_COL_INDEX >= num_columns or IDENTIFIER_COL_INDEX >= num_columns:
                logging.warning(
                    f"Skipping row {row_number} in {filename_for_logging}: Required column index out of bounds.")
                master_unknown_rows.append(
                    {'file': filename_for_logging, 'row_number': row_number, 'num_columns': num_columns,
                     'identifier': 'N/A (Index OOB)', 'correlationID': 'N/A (Index OOB)',
                     'content_preview': cleaned_row_values[:5]})
                continue

            corr_id = standardize_correlation_id(cleaned_row_values[CORRELATION_ID_COL_INDEX])
            cleaned_row_values[CORRELATION_ID_COL_INDEX] = corr_id
            identifier_val = cleaned_row_values[IDENTIFIER_COL_INDEX]

            row_type_info = ROW_TYPE_CONFIG.get((identifier_val, num_columns))
            if row_type_info:
                if len(cleaned_row_values) == len(row_type_info['cols']):
                    master_parsed_data[row_type_info['name']].append(cleaned_row_values)
                else:
                    master_unknown_rows.append(
                        {'file': filename_for_logging, 'row_number': row_number, 'num_columns': num_columns,
                         'identifier': identifier_val, 'expected_columns': len(row_type_info['cols']),
                         'correlationID': corr_id, 'content_preview': cleaned_row_values[:5]})
            else:
                master_unknown_rows.append(
                    {'file': filename_for_logging, 'row_number': row_number, 'num_columns': num_columns,
                     'identifier': identifier_val, 'correlationID': corr_id, 'content_preview': cleaned_row_values[:5]})
    except Exception as ex:
        logging.error(f"An error occurred parsing content from {filename_for_logging}: {ex}", exc_info=True)
        master_unknown_rows.append({'file': filename_for_logging, 'error': str(ex)})


@st.cache_data
def load_and_parse_logs(uploaded_files: List[st.runtime.uploaded_file_manager.UploadedFile]) -> Tuple[
    Dict[str, List[List[str]]], List[Dict[str, Any]]]:
    """
    Main cached function to handle uploaded files (incl. archives), extract, and parse log contents.
    """
    if not uploaded_files:
        st.toast("No files were uploaded.", icon="ℹ️")
        return defaultdict(list), []

    log_streams_with_names = _extract_log_contents_from_uploads(uploaded_files)

    if not log_streams_with_names:
        st.warning("No valid log files found or extracted from the upload(s). Check names/formats.", icon="⚠️")
        return defaultdict(list), []

    # Use defaultdict(list) for master_parsed_data
    aggregated_parsed_data: Dict[str, List[List[str]]] = defaultdict(list)
    aggregated_unknown_rows: List[Dict[str, Any]] = []

    for filename, log_io_stream in log_streams_with_names:
        _parse_single_log_stream(filename, log_io_stream, aggregated_parsed_data, aggregated_unknown_rows)
        log_io_stream.close()

    logging.info(
        f"Finished parsing all logs. Found {sum(len(v) for v in aggregated_parsed_data.values())} categorized entries.")
    return aggregated_parsed_data, aggregated_unknown_rows


@st.cache_data
def create_dataframes_from_parsed(parsed_data: Dict[str, List[List[str]]]) -> Dict[str, pd.DataFrame]:
    """Converts categorized lists of rows from parsed_data into type-specific DataFrames."""
    dataframes: Dict[str, pd.DataFrame] = {}
    if not parsed_data: return dataframes
    for type_name, rows in parsed_data.items():
        config = next((cfg_val for _, cfg_val in ROW_TYPE_CONFIG.items() if cfg_val['name'] == type_name), None)
        if config and config['cols'] and rows:
            try:
                expected_col_count = len(config['cols'])
                valid_rows = [row for row in rows if len(row) == expected_col_count]
                if len(valid_rows) < len(rows): logging.warning(
                    f"DataFrame for {type_name}: Skipped {len(rows) - len(valid_rows)} rows due to col count mismatch.")
                if valid_rows:
                    dataframes[type_name] = pd.DataFrame(valid_rows, columns=config['cols'])
                else:
                    logging.warning(f"No valid rows for {type_name} after col count validation.")
            except ValueError as ve:
                logging.error(f"ValueError creating DataFrame for {type_name}: {ve}", exc_info=True)
            except Exception as e:
                logging.error(f"Unexpected error creating DataFrame for {type_name}: {e}", exc_info=True)
        elif not config and type_name != "Unknown":
            logging.warning(f"No col definition for type '{type_name}'. Skipping.")
    return dataframes


@st.cache_data
def preprocess_combined_dataframe(raw_dataframes: Dict[str, pd.DataFrame]) -> pd.DataFrame:
    """Combines, standardizes eventType, and converts data types for all log entries."""
    non_empty_dfs = [df for df in raw_dataframes.values() if not df.empty]
    if not non_empty_dfs: return pd.DataFrame()
    df_combined = pd.concat(non_empty_dfs, ignore_index=True)
    # Standardize eventType: HTTP logs have 'eventType', JDBC/LDAP have 'callType'. Merge into 'eventType'.
    if 'callType' in df_combined.columns and 'eventType' in df_combined.columns:
        df_combined['eventType'] = df_combined['eventType'].fillna(df_combined['callType'])
    elif 'callType' in df_combined.columns:
        df_combined.rename(columns={'callType': 'eventType'}, inplace=True)
    elif 'eventType' not in df_combined.columns:
        logging.error("Fatal: Could not determine event type ('eventType' or 'callType').")
        return pd.DataFrame()  # Or raise an error for critical failure

    # Type Conversions
    if 'timestamp' in df_combined.columns: df_combined['timestamp'] = pd.to_datetime(df_combined['timestamp'],
                                                                                     format=TIMESTAMP_FORMAT,
                                                                                     errors='coerce')
    if 'startTime' in df_combined.columns: df_combined['startTime'] = pd.to_datetime(
        pd.to_numeric(df_combined['startTime'], errors='coerce'), unit='ms', errors='coerce')
    numeric_cols = ['duration', 'totalDurationForRequest', 'argsLength']
    for col in numeric_cols:
        if col in df_combined.columns: df_combined[col] = pd.to_numeric(df_combined[col], errors='coerce')
    if 'correlationID' in df_combined.columns: df_combined['correlationID'] = df_combined['correlationID'].astype(str)
    logging.info("[Cache] Combined, standardized eventType, and converted data types for master DataFrame.")
    return df_combined


@st.cache_data
def calculate_request_summary(df_combined: pd.DataFrame) -> pd.DataFrame:
    """
    Calculates per-request summary metrics (durations, component times, counts).
    Assumes df_combined has 'startTime' as datetime and standardized 'eventType'.
    """
    logging.info(f"[Cache] Calculating request summary (ms).")
    required_cols = ['correlationID', 'startTime', 'eventType']
    if df_combined.empty or not all(col in df_combined.columns for col in required_cols):
        logging.warning(f"calc_request_summary: DataFrame empty or missing required columns.")
        return pd.DataFrame()
    # startTime should already be datetime from preprocess_combined_dataframe
    if not pd.api.types.is_datetime64_any_dtype(df_combined['startTime']):
        logging.error("calc_request_summary: 'startTime' is not datetime. This indicates an issue in preprocessing.")
        return pd.DataFrame()

    df_sorted = df_combined.sort_values(by=['correlationID', 'startTime'])
    grouped = df_sorted.groupby('correlationID')
    metrics = []
    for name, group in grouped:
        if name == CORRELATION_ID_REPLACEMENT: continue
        http_req_events = group[group['eventType'] == EVENT_TYPE_HTTP_REQUEST]
        http_res_events = group[group['eventType'] == EVENT_TYPE_HTTP_RESPONSE]
        http_req = http_req_events.iloc[0] if not http_req_events.empty else None
        http_res = http_res_events.iloc[-1] if not http_res_events.empty else None

        req_start = http_req['startTime'] if http_req is not None and pd.notna(http_req['startTime']) else pd.NaT
        res_end = http_res['startTime'] if http_res is not None and pd.notna(http_res['startTime']) else pd.NaT

        total_duration_ms = pd.NA
        if pd.notna(req_start) and pd.notna(res_end) and res_end >= req_start:
            total_duration_ms = (res_end - req_start).total_seconds() * 1000
        elif pd.notna(req_start) and pd.notna(res_end):
            logging.debug(f"CorrID {name}: Response time before request time.")

        reported_duration_ms = pd.to_numeric(http_res.get('totalDurationForRequest') if http_res is not None else None,
                                             errors='coerce')
        request_path = http_req.get('requestPath', 'N/A') if http_req is not None else 'N/A'

        jdbc_calls = group[group['eventType'] == EVENT_TYPE_JDBC]
        ldap_calls = group[group['eventType'] == EVENT_TYPE_LDAP]
        total_jdbc_ms = pd.to_numeric(jdbc_calls.get('duration'), errors='coerce').sum()
        total_ldap_ms = pd.to_numeric(ldap_calls.get('duration'), errors='coerce').sum()

        # HTTP/Other overhead is the total request time minus summed component times.
        http_overhead_ms = pd.NA
        if pd.notna(total_duration_ms):
            jdbc_contrib = total_jdbc_ms if pd.notna(total_jdbc_ms) else 0.0
            ldap_contrib = total_ldap_ms if pd.notna(total_ldap_ms) else 0.0
            current_overhead = total_duration_ms - jdbc_contrib - ldap_contrib
            http_overhead_ms = max(0.0, current_overhead)  # Ensure non-negative

        metrics.append({
            'correlationID': name, 'requestStartTime': req_start, 'responseStartTime': res_end,
            'calculatedDurationMs': total_duration_ms, 'reportedTotalDurationMs': reported_duration_ms,
            'requestPath': request_path,
            'num_jdbc_calls': len(jdbc_calls), 'total_jdbc_duration_ms': total_jdbc_ms,
            'num_ldap_calls': len(ldap_calls), 'total_ldap_duration_ms': total_ldap_ms,
            'http_overhead_ms': http_overhead_ms
        })
    if not metrics: return pd.DataFrame()
    summary_df = pd.DataFrame(metrics)

    # Final type enforcement
    if not summary_df.empty:
        float_cols = ['calculatedDurationMs', 'reportedTotalDurationMs', 'total_jdbc_duration_ms',
                      'total_ldap_duration_ms', 'http_overhead_ms']
        for col in float_cols:
            if col in summary_df.columns: summary_df[col] = pd.to_numeric(summary_df[col], errors='coerce')
        int_cols = ['num_jdbc_calls', 'num_ldap_calls']
        for col in int_cols:
            if col in summary_df.columns: summary_df[col] = pd.to_numeric(summary_df[col], errors='coerce').fillna(
                0).astype('Int64')
    logging.info(f"[Cache] Finished request summary for {len(summary_df)} IDs.")
    return summary_df


# --- Visualization & UI Helper Functions ---
def create_gantt_chart(df_trace: pd.DataFrame, title: str = "Request Trace") -> Optional[go.Figure]:
    """Creates a Plotly Gantt chart for a given request trace, ordered by start time."""
    if df_trace.empty or 'startTime' not in df_trace.columns or not pd.api.types.is_datetime64_any_dtype(
            df_trace['startTime']):
        logging.warning("Gantt: Invalid input DataFrame or startTime column.")
        return None
    tasks_list = []
    # Ensure original_index is robustly created for unique task IDs
    df_trace_copy = df_trace.copy()
    if 'original_index' not in df_trace_copy.columns:
        df_trace_copy = df_trace_copy.reset_index().rename(columns={'index': 'original_index'})

    for idx, row in df_trace_copy.iterrows():
        start = row['startTime']
        if pd.isna(start): continue

        duration_ms = MIN_VISIBLE_GANTT_DURATION_MS  # Default
        event_type = str(row.get('eventType', 'Unknown'))
        raw_duration = row.get('duration', 0)

        if event_type in [EVENT_TYPE_JDBC, EVENT_TYPE_LDAP]:
            current_duration = pd.to_numeric(raw_duration, errors='coerce')
            duration_ms = current_duration if pd.notna(
                current_duration) and current_duration >= 0 else MIN_VISIBLE_GANTT_DURATION_MS
        elif event_type in [EVENT_TYPE_HTTP_REQUEST, EVENT_TYPE_HTTP_RESPONSE]:
            http_dur = pd.to_numeric(raw_duration, errors='coerce')
            duration_ms = http_dur if pd.notna(http_dur) and http_dur > 0 else MIN_VISIBLE_GANTT_DURATION_MS
        else:  # Other types
            current_duration = pd.to_numeric(raw_duration, errors='coerce')
            duration_ms = current_duration if pd.notna(
                current_duration) and current_duration >= 0 else MIN_VISIBLE_GANTT_DURATION_MS

        # Final safety check for duration_ms
        if pd.isna(duration_ms) or not isinstance(duration_ms, (int, float)) or duration_ms < 0:
            duration_ms = MIN_VISIBLE_GANTT_DURATION_MS

        end = start + pd.to_timedelta(float(duration_ms), unit='ms')
        method_name_part = str(row.get('methodName', '')).split('(')[0]
        # Use a more robust way to get a unique ID if original_index isn't consistently available
        unique_task_id = row.get('original_index', idx)
        task_label = f"{event_type}: {method_name_part} [id:{unique_task_id}]"
        tasks_list.append(dict(Task=task_label, Start=start, Finish=end, Resource=event_type))

    if not tasks_list: return None
    tasks_df = pd.DataFrame(tasks_list)
    # Sort tasks by start time to ensure chronological order on Y-axis with 'trace' categoryorder
    tasks_df_sorted = tasks_df.sort_values(by='Start', ascending=True) if not tasks_df.empty else tasks_df
    y_axis_order = tasks_df_sorted['Task'].tolist() if not tasks_df_sorted.empty else []

    try:
        fig = px.timeline(tasks_df_sorted, x_start="Start", x_end="Finish", y="Task", color="Resource", title=title,
                          height=max(400, len(tasks_df_sorted) * 25),
                          category_orders={"Task": y_axis_order})  # Enforce Y-axis order
        fig.update_layout(xaxis_title="Time", yaxis_title="Operation",
                          yaxis={'autorange': True})  # Let Plotly handle autorange, category_orders define the order
        return fig
    except Exception as e:
        logging.error(f"Failed to create Plotly timeline: {e}", exc_info=True)
        return None


def _create_sidebar_numeric_filter(df: pd.DataFrame, column_name: str, label: str,
                                   default_value: Union[int, float] = 0.0, is_int: bool = False,
                                   help_text: Optional[str] = None) -> Union[int, float]:
    """
    Creates a numeric slider in the sidebar for filtering a DataFrame column.

    Args:
        df: The DataFrame to source min/max values from.
        column_name: The name of the column to filter.
        label: The label for the slider.
        default_value: The default value if the column is missing or has no valid data.
        is_int: If True, creates an integer slider with step 1.
        help_text: Optional help text for the slider.

    Returns:
        The selected value from the slider.
    """
    if column_name not in df.columns or df[column_name].dropna().empty:
        st.sidebar.caption(f"{label.split(':')[0]} filter unavailable (column missing or no data).")
        return default_value
    numeric_series = pd.to_numeric(df[column_name], errors='coerce').dropna()
    if numeric_series.empty:
        st.sidebar.caption(f"{label.split(':')[0]} filter unavailable (no valid numeric data).")
        return default_value

    min_val_series, max_val_series = numeric_series.min(), numeric_series.max()

    if is_int:
        min_val: int = int(min_val_series)
        max_val: int = int(max_val_series)
        step_val: int = 1
        current_val: int = min_val
        if min_val >= max_val: max_val = min_val + 1
    else:
        min_val: float = float(min_val_series)
        max_val: float = float(max_val_series)
        current_val: float = min_val
        if min_val >= max_val: max_val = min_val + (100.0 if column_name.endswith("Ms") else 1.0)
        step_divisor: float = 100.0
        min_step_val: float = (1.0 if column_name.endswith("Ms") else 0.01)
        step_val: float = max(min_step_val, (max_val - min_val) / step_divisor) if max_val > min_val else min_step_val

    return st.sidebar.slider(label, min_value=min_val, max_value=max_val, value=current_val, step=step_val,
                             help=help_text)


def _display_top_n_or_all_table(df_source: pd.DataFrame, sort_column: str, top_n_value: int, checkbox_label: str,
                                checkbox_key: str, columns_to_show_config: Dict[str, Any], table_caption_noun: str):
    """
    Displays a Pandas DataFrame in Streamlit, with options for Top N or all items.
    Handles sorting and applies st.column_config for formatting.
    """
    if df_source.empty:
        st.info(f"No {table_caption_noun} to display based on current filters.")
        return
    if sort_column not in df_source.columns or df_source[sort_column].dropna().empty:
        st.warning(
            f"Cannot display {table_caption_noun}: sort column '{sort_column}' is missing, not numeric, or has no data.")
        # Attempt to display with available columns if sort column is the issue
        displayable_cols = [col for col in columns_to_show_config if col in df_source.columns]
        if displayable_cols:
            st.dataframe(df_source[displayable_cols], column_config=columns_to_show_config, hide_index=True,
                         use_container_width=True)
        return
    show_all = st.checkbox(checkbox_label, key=checkbox_key, value=False)
    df_source_copy = df_source.copy()  # Work on a copy
    df_source_copy[sort_column] = pd.to_numeric(df_source_copy[sort_column],
                                                errors='coerce')  # Ensure numeric for sorting

    # Sort, handling potential NaNs from coercion
    sorted_df = df_source_copy.sort_values(sort_column, ascending=False, na_position='last')
    data_to_display = sorted_df if show_all else sorted_df.head(top_n_value)

    # Ensure only existing columns are selected for display based on keys in columns_to_show_config
    final_columns_to_show_keys = [col for col in columns_to_show_config.keys() if col in data_to_display.columns]

    if not data_to_display.empty and final_columns_to_show_keys:
        st.dataframe(data_to_display[final_columns_to_show_keys], column_config=columns_to_show_config, hide_index=True,
                     use_container_width=True)
        st.caption(
            f"Showing {len(data_to_display)} of {len(df_source)} {table_caption_noun}. {'(Top N shown)' if not show_all else '(All shown)'}")
    elif not final_columns_to_show_keys and not data_to_display.empty:
        st.warning(f"No columns configured for display in {table_caption_noun}, but data exists.")
        st.dataframe(data_to_display, hide_index=True, use_container_width=True)  # Show with default config
    else:
        st.info(f"No {table_caption_noun} to display after processing and filtering.")


# --- Streamlit App UI Structure Functions ---
def _setup_sidebar_filters(df_combined: pd.DataFrame, df_req_summary: pd.DataFrame) -> Tuple[
    Any, int, float, float, int, float, int, List[str]]:
    """Sets up and returns values from all sidebar filters."""
    st.sidebar.header("Master Filters")
    # Time Range Slider
    # Ensure startTime is valid before attempting to get min/max
    start_time_min = df_combined['startTime'].min() if 'startTime' in df_combined.columns and not df_combined[
        'startTime'].dropna().empty else pd.NaT
    start_time_max = df_combined['startTime'].max() if 'startTime' in df_combined.columns and not df_combined[
        'startTime'].dropna().empty else pd.NaT
    time_range_val = (start_time_min, start_time_max)

    if pd.notna(start_time_min) and pd.notna(start_time_max) and start_time_min < start_time_max:
        try:
            time_range_val = st.sidebar.slider(
                "Time Range (Event Start Time):",
                min_value=start_time_min.to_pydatetime(),
                max_value=start_time_max.to_pydatetime(),
                value=(start_time_min.to_pydatetime(), start_time_max.to_pydatetime()),
                format="YYYY-MM-DD HH:mm:ss"
            )
        except Exception as e:
            st.sidebar.error(f"Time slider error: {e}")  # Log full error for dev
    else:
        st.sidebar.warning("Time range filter disabled: 'startTime' data insufficient or invalid.")

    top_n = st.sidebar.slider("Top N Slowest (Requests & Ops):", 1, 50, 10,
                              help="Number of items to show in 'Top N' tables.")

    st.sidebar.subheader("Advanced Request Summary Filters")
    sel_min_dur_ms, sel_min_jdbc_time, sel_min_jdbc_calls = 0.0, 0.0, 0
    sel_min_ldap_time, sel_min_ldap_calls = 0.0, 0

    if not df_req_summary.empty:
        sel_min_dur_ms = _create_sidebar_numeric_filter(df_req_summary, 'calculatedDurationMs',
                                                        "Min Total Request Duration (ms):", 0.0,
                                                        help_text="Filter requests by their minimum total calculated duration.")
        sel_min_jdbc_time = _create_sidebar_numeric_filter(df_req_summary, 'total_jdbc_duration_ms',
                                                           "Min Total JDBC Time (ms) in Request:", 0.0,
                                                           help_text="Minimum total time spent in JDBC calls within a single request.")
        sel_min_jdbc_calls = _create_sidebar_numeric_filter(df_req_summary, 'num_jdbc_calls',
                                                            "Min JDBC Calls in Request:", 0, is_int=True,
                                                            help_text="Minimum number of JDBC calls within a single request.")
        sel_min_ldap_time = _create_sidebar_numeric_filter(df_req_summary, 'total_ldap_duration_ms',
                                                           "Min Total LDAP Time (ms) in Request:", 0.0,
                                                           help_text="Minimum total time spent in LDAP calls within a single request.")
        sel_min_ldap_calls = _create_sidebar_numeric_filter(df_req_summary, 'num_ldap_calls',
                                                            "Min LDAP Calls in Request:", 0, is_int=True,
                                                            help_text="Minimum number of LDAP calls within a single request.")
    else:
        st.sidebar.info("Request summary filters unavailable (no summary data).")

    st.sidebar.subheader("Event Type Filter (for Ops & Startup)")
    sel_event_types = []
    if 'eventType' in df_combined.columns and not df_combined['eventType'].dropna().empty:
        event_options = sorted(df_combined['eventType'].dropna().unique().tolist())
        sel_event_types = st.sidebar.multiselect("Filter by Event Types:", event_options, default=event_options,
                                                 help="Select event types to include in 'Individual Operations' and 'Startup Operations' tables.")
    else:
        st.sidebar.caption("Event type filter unavailable.")

    return time_range_val, top_n, sel_min_dur_ms, sel_min_jdbc_time, sel_min_jdbc_calls, sel_min_ldap_time, sel_min_ldap_calls, sel_event_types


def _apply_filters(df_combined: pd.DataFrame, df_req_summary: pd.DataFrame,
                   time_range: Tuple[pd.Timestamp, pd.Timestamp],
                   min_dur_ms: float, min_jdbc_time: float, min_jdbc_calls: int,
                   min_ldap_time: float, min_ldap_calls: int,
                   event_types: List[str]) -> Tuple[pd.DataFrame, pd.DataFrame]:
    """Applies all selected filters to the main DataFrames."""
    start_dt, end_dt = pd.to_datetime(time_range[0], errors='coerce'), pd.to_datetime(time_range[1], errors='coerce')

    # Filter operational data (df_combined)
    filtered_ops_df = df_combined.copy()
    if pd.notna(start_dt) and pd.notna(end_dt) and 'startTime' in filtered_ops_df.columns:
        filtered_ops_df = filtered_ops_df[
            (filtered_ops_df['startTime'] >= start_dt) & (filtered_ops_df['startTime'] <= end_dt)]
    if event_types and 'eventType' in filtered_ops_df.columns:  # Apply event type filter if any types selected
        filtered_ops_df = filtered_ops_df[filtered_ops_df['eventType'].isin(event_types)]

    # Filter request summary data (df_req_summary)
    filtered_summary_df = df_req_summary.copy()
    if pd.notna(start_dt) and pd.notna(end_dt) and 'requestStartTime' in filtered_summary_df.columns:
        time_cond = (filtered_summary_df['requestStartTime'] >= start_dt) & (
                filtered_summary_df['requestStartTime'] <= end_dt)
        filtered_summary_df = filtered_summary_df[time_cond.fillna(False)]  # Exclude rows where time condition is NA

    # Apply advanced filters, ensuring columns exist and are numeric before comparison
    for col, threshold in [('calculatedDurationMs', min_dur_ms),
                           ('total_jdbc_duration_ms', min_jdbc_time),
                           ('total_ldap_duration_ms', min_ldap_time)]:
        if col in filtered_summary_df.columns and pd.api.types.is_numeric_dtype(filtered_summary_df[col]):
            filtered_summary_df = filtered_summary_df[filtered_summary_df[col].fillna(0) >= threshold]

    for col, threshold in [('num_jdbc_calls', min_jdbc_calls),
                           ('num_ldap_calls', min_ldap_calls)]:
        if col in filtered_summary_df.columns and pd.api.types.is_numeric_dtype(
                filtered_summary_df[col]):  # Int64 is numeric
            filtered_summary_df = filtered_summary_df[
                filtered_summary_df[col].fillna(0) >= float(threshold)]  # Compare with float

    return filtered_ops_df, filtered_summary_df


def _display_kpis(summary_df: pd.DataFrame):
    """Displays Key Performance Indicators."""
    st.header("Performance Overview")
    if summary_df.empty or 'calculatedDurationMs' not in summary_df.columns:
        st.warning("No request data for KPIs, or 'calculatedDurationMs' missing.")
        return
    col1, col2, col3 = st.columns(3)
    avg_ms = summary_df['calculatedDurationMs'].mean()
    p95_ms = summary_df['calculatedDurationMs'].agg(p95_agg)
    col1.metric("Requests (Filtered)", f"{len(summary_df):,}")
    col2.metric("Avg Request Duration", format_duration_ms(avg_ms))
    col3.metric("P95 Request Duration", format_duration_ms(p95_ms))


def _display_performance_trends_chart(summary_df: pd.DataFrame):
    """Displays the merged performance trends chart."""
    st.subheader("Performance Trends Over Time")
    if not ('requestStartTime' in summary_df.columns and pd.api.types.is_datetime64_any_dtype(
            summary_df['requestStartTime']) and not summary_df['requestStartTime'].dropna().empty):
        st.info("Time series: 'requestStartTime' data issue or no data.")
        return

    summary_timed = summary_df.dropna(subset=['requestStartTime']).set_index('requestStartTime')
    if summary_timed.empty:
        st.info("No time-indexed data for time series after filtering.")
        return

    res_opts = {"15 Sec": "15S", "30 Sec": "30S", "1 Min": "min", "10 Mins": "10min", "Hourly": "H", "Daily": "D"}
    def_idx = list(res_opts.keys()).index("1 Min") if "1 Min" in res_opts else 2
    freq_label = st.selectbox("Resample Frequency:", list(res_opts.keys()), index=def_idx,
                              help="Select time interval for aggregating trend data.")
    freq_code = res_opts[freq_label]

    try:
        # Define aggregations for all series needed in the unified chart
        agg_map = {
            'calculatedDurationMs': ['mean', p95_agg, 'size'],  # For Avg, P95, and Request Count
            'total_jdbc_duration_ms': ['mean'],  # Avg total JDBC time per request in interval
            'total_ldap_duration_ms': ['mean']  # Avg total LDAP time per request in interval
        }
        valid_agg_map = {k: v for k, v in agg_map.items() if k in summary_timed.columns}

        if not valid_agg_map or 'calculatedDurationMs' not in valid_agg_map:
            st.warning("Insufficient data for Performance Trends chart ('calculatedDurationMs' is essential).")
            return

        resampled_data = summary_timed.resample(freq_code).agg(valid_agg_map)
        if isinstance(resampled_data.columns, pd.MultiIndex):
            resampled_data.columns = ['_'.join(map(str, c)).strip() for c in resampled_data.columns.values]

        # Standardize column names after aggregation
        resampled_data.rename(columns={
            'calculatedDurationMs_mean': 'Avg Response Time (ms)',
            'calculatedDurationMs_p95_agg': 'P95 Response Time (ms)',
            'calculatedDurationMs_size': 'Request Count',
            'total_jdbc_duration_ms_mean': 'Avg JDBC Time (ms)',
            'total_ldap_duration_ms_mean': 'Avg LDAP Time (ms)'
        }, inplace=True, errors='ignore')

        # Ensure plottable columns are numeric; create if missing from rename (e.g. no LDAP data)
        line_plot_cols = ['Avg Response Time (ms)', 'P95 Response Time (ms)', 'Avg JDBC Time (ms)',
                          'Avg LDAP Time (ms)']
        for col in line_plot_cols:
            if col in resampled_data.columns:
                resampled_data[col] = pd.to_numeric(resampled_data[col], errors='coerce')
            else:
                resampled_data[col] = pd.NA  # Add as NA column if not present

        resampled_data['Request Count'] = pd.to_numeric(resampled_data.get('Request Count'), errors='coerce').fillna(0)

        plot_df = resampled_data  # Use raw resampled data (NaNs will create gaps in lines)

        if plot_df.empty or plot_df[line_plot_cols + ['Request Count']].isnull().all().all():
            st.info(f"Not enough data to plot trends for '{freq_label}' after processing.")
            return

        fig = make_subplots(specs=[[{"secondary_y": True}]])

        # Add traces with specified styles
        trace_configs = [
            {'col': 'Avg Response Time (ms)', 'name': 'Avg Response Time (ms)', 'color': 'white', 'dash': 'dot',
             'secondary_y': False},
            {'col': 'P95 Response Time (ms)', 'name': 'P95 Response Time (ms)', 'color': 'lightgrey', 'dash': 'dot',
             'secondary_y': False},
            {'col': 'Avg JDBC Time (ms)', 'name': 'Avg JDBC Time (ms)', 'color': 'rgba(255,100,100,0.8)',
             'secondary_y': False},  # Light Red
            {'col': 'Avg LDAP Time (ms)', 'name': 'Avg LDAP Time (ms)', 'color': 'rgba(100,100,255,0.8)',
             'secondary_y': False},  # Light Blue
        ]
        for tc in trace_configs:
            if tc['col'] in plot_df.columns and plot_df[tc['col']].notna().any():
                fig.add_trace(go.Scatter(x=plot_df.index, y=plot_df[tc['col']], name=tc['name'], mode='lines',
                                         line=dict(color=tc['color'], dash=tc.get('dash'))),
                              secondary_y=tc['secondary_y'])

        if 'Request Count' in plot_df.columns and plot_df['Request Count'].notna().any():
            fig.add_trace(go.Bar(x=plot_df.index, y=plot_df['Request Count'], name='Request Count',
                                 marker_color='rgba(128,128,128,0.5)'), secondary_y=True)

        fig.update_layout(title_text=f"Overall Performance Trends ({freq_label})", hovermode="x unified",
                          legend_title_text='Metric',
                          yaxis=dict(title_text="Duration (ms)", rangemode='tozero'),
                          yaxis2=dict(title_text="Request Count", rangemode='tozero', overlaying='y', side='right',
                                      showgrid=False))
        st.plotly_chart(fig, use_container_width=True)
    except Exception as e:
        logging.error(f"Time series error: {e}", exc_info=True)
        st.error(f"Time series generation error: {e}")


def _display_request_trace_viewer(summary_df: pd.DataFrame, combined_df: pd.DataFrame):
    """Displays the Gantt chart trace viewer and corresponding data table."""
    st.header("Request Trace Viewer (Gantt Chart)")
    sort_order_gantt = st.radio("Sort Trace Selection By:",
                                ("Slowest (Duration)", "Start Time (Most Recent First)", "Start Time (Oldest First)"),
                                key="gantt_sort_order_radio", horizontal=True,
                                help="Determines the order of Correlation IDs in the selection dropdown.")

    corr_id_map, ordered_ids = {"Select ID...": "Select ID..."}, ["Select ID..."]

    if not summary_df.empty:
        sorted_summary_for_dropdown = summary_df.copy()
        sort_key_column = None
        ascending_sort = False

        if sort_order_gantt == "Slowest (Duration)":
            sort_key_column = 'calculatedDurationMs'
            ascending_sort = False
        elif sort_order_gantt == "Start Time (Most Recent First)":
            sort_key_column = 'requestStartTime'
            ascending_sort = False
        else:  # Start Time (Oldest First)
            sort_key_column = 'requestStartTime'
            ascending_sort = True

        if sort_key_column and sort_key_column in sorted_summary_for_dropdown.columns:
            # Ensure the sort key column is appropriate for sorting (e.g. numeric or datetime)
            if pd.api.types.is_datetime64_any_dtype(sorted_summary_for_dropdown[sort_key_column]) or \
                    pd.api.types.is_numeric_dtype(sorted_summary_for_dropdown[sort_key_column]):
                sorted_summary_for_dropdown.sort_values(sort_key_column, ascending=ascending_sort, na_position='last',
                                                        inplace=True)
            else:
                st.caption(f"Cannot sort by '{sort_key_column}': column not suitable for sorting.")
        else:
            st.caption(f"Cannot sort: required column '{sort_key_column}' missing or no data.")

        for _, row in sorted_summary_for_dropdown.iterrows():
            corr_id = str(row['correlationID'])  # Ensure string
            start_time_val = row.get('requestStartTime')
            start_time_str = format_datetime_with_3_ms(start_time_val)
            duration_str = format_duration_ms(row.get('calculatedDurationMs'))
            path_val = str(row.get('requestPath', 'N/A'))[:40]  # Truncate path
            label = f"[{start_time_str}] {corr_id} ({duration_str}) - {path_val}"
            corr_id_map[corr_id] = label
            ordered_ids.append(corr_id)
    else:
        st.info("No requests in filter to populate trace selection.")

    sel_trace_id = st.selectbox("Select Correlation ID:", ordered_ids, format_func=lambda x: corr_id_map.get(x, x))
    if sel_trace_id != "Select ID...":
        # Filter from the original combined_df for full trace details
        trace_df = combined_df[
            (combined_df['correlationID'] == sel_trace_id) & pd.notna(combined_df['startTime'])].sort_values(
            'startTime')
        if not trace_df.empty:
            gantt = create_gantt_chart(trace_df, f"Trace: {sel_trace_id}")
            if gantt:
                st.plotly_chart(gantt, use_container_width=True)
            else:
                st.error("Could not generate Gantt chart for the selected ID.")

            st.subheader("Trace Data Table")
            trace_table_cols_config = {
                "startTime": st.column_config.DatetimeColumn("Start Time", format=DATETIME_TABLE_DISPLAY_FORMAT),
                # Use constant
                "duration": st.column_config.NumberColumn("Duration (ms)", format="%d ms"),
                "totalDurationForRequest": st.column_config.NumberColumn("Total Req. Duration (ms)", format="%d ms")
            }
            # Define a comprehensive list of columns that *might* appear in a trace
            cols_to_display_trace = ['startTime', 'eventType', 'methodName', 'duration', 'totalDurationForRequest',
                                     'correlationID', 'threadID', 'requestPath', 'requestQuery', 'query',
                                     'connectionUrl', 'providerUrl', 'principal', 'argsLength', 'args']
            displayable_cols_trace = [col for col in cols_to_display_trace if
                                      col in trace_df.columns]  # Show only existing
            st.dataframe(trace_df[displayable_cols_trace], column_config=trace_table_cols_config, hide_index=True,
                         use_container_width=True)
        else:
            st.warning(f"No trace data found for Correlation ID {sel_trace_id}.")


# --- Main Application ---
def main():
    """Main function to run the Streamlit application."""
    st.set_page_config(layout="wide", page_title="WSO2 Log Analyzer", initial_sidebar_state="expanded")
    st.title("WSO2 IS Correlation Log Analyzer")

    uploaded_files = st.file_uploader(
        "Upload correlation log files or archives (.zip, .gz, .tar.gz, .tgz)",
        type=['log', 'csv', 'zip', 'gz', 'tar.gz', 'tgz'],
        accept_multiple_files=True
    )

    if uploaded_files:
        # Step 1: Load and parse all uploaded files (handles archives)
        parsed_data, unknown_rows = load_and_parse_logs(uploaded_files)
        if not parsed_data and not unknown_rows:
            st.info("No data parsed. Please check file contents or console logs.")
            st.stop()

        # Step 2: Create initial DataFrames from parsed data
        raw_dfs = create_dataframes_from_parsed(parsed_data)

        # Step 3: Combine, standardize eventType, and convert data types
        df_combined = preprocess_combined_dataframe(raw_dfs)
        if df_combined.empty:
            st.error("Data processing failed (no valid log entries found). Review logs and input file format.")
            if unknown_rows:
                with st.expander(f"Details on Unknown/Problematic Rows/Files ({len(unknown_rows)})"): st.json(
                    unknown_rows[:50])
            st.stop()

        # Step 4: Calculate request summaries
        df_req_summary = calculate_request_summary(df_combined)
        st.success(
            f"Processed {len(df_combined):,} log entries from {len(uploaded_files)} uploaded item(s), summarizing {len(df_req_summary):,} requests.")
        st.divider()

        # Step 5: Setup sidebar filters and apply them
        (time_range,
         top_n_val,
         min_dur_ms_val,
         min_jdbc_time_val,
         min_jdbc_calls_val,
         min_ldap_time_val,
         min_ldap_calls_val,
         event_types_val) = _setup_sidebar_filters(df_combined, df_req_summary)

        filtered_ops_df, filtered_summary_df = _apply_filters(
            df_combined,
            df_req_summary,
            time_range,
            min_dur_ms_val,
            min_jdbc_time_val,
            min_jdbc_calls_val,
            min_ldap_time_val,
            min_ldap_calls_val,
            event_types_val
        )

        # Step 6: Display main content
        _display_kpis(filtered_summary_df)
        _display_performance_trends_chart(filtered_summary_df)
        st.divider()

        st.subheader("Slowest Requests Analysis")
        req_cols_config = {
            "correlationID": "Correlation ID", "requestPath": "Request Path",
            "calculatedDurationMs": st.column_config.NumberColumn("Duration", format="%d ms"),
            "total_jdbc_duration_ms": st.column_config.NumberColumn("JDBC Time", format="%d ms"),
            "num_jdbc_calls": st.column_config.NumberColumn("JDBC Calls", format="%d"),
            "total_ldap_duration_ms": st.column_config.NumberColumn("LDAP Time", format="%d ms"),
            "num_ldap_calls": st.column_config.NumberColumn("LDAP Calls", format="%d")}
        _display_top_n_or_all_table(filtered_summary_df, 'calculatedDurationMs', top_n_val,
                                    "Show all filtered requests", "cb_all_reqs", req_cols_config, "requests")
        st.divider()

        st.header("Slowest Individual Operations")
        ops_cols_config = {
            "startTime": st.column_config.DatetimeColumn("Start Time", format=DATETIME_TABLE_DISPLAY_FORMAT),
            "correlationID": "Correlation ID", "eventType": "Event Type", "methodName": "Method",
            "duration": st.column_config.NumberColumn("Duration (ms)", format="%d ms"), "query": "Query",
            "providerUrl": "LDAP URL", "principal": "Principal", "requestPath": "Path"}
        ops_with_valid_duration = filtered_ops_df.copy()  # Ensure working with a copy
        ops_with_valid_duration['duration'] = pd.to_numeric(ops_with_valid_duration['duration'], errors='coerce')
        ops_with_valid_duration = ops_with_valid_duration[ops_with_valid_duration['duration'].fillna(0) > 0]
        _display_top_n_or_all_table(ops_with_valid_duration, 'duration', top_n_val,
                                    "Show all filtered operations", "cb_all_ops", ops_cols_config, "operations")
        st.divider()

        st.header("Startup Operations Analysis")
        startup_ops = df_combined[df_combined['correlationID'] == CORRELATION_ID_REPLACEMENT]
        if event_types_val: startup_ops = startup_ops[
            startup_ops['eventType'].isin(event_types_val)]
        if startup_ops.empty:
            st.info(f"No startup operations found{' matching event filters.' if event_types_val else '.'}")
        else:
            st.metric("Total Startup Ops (filtered)", len(startup_ops))
            if 'duration' in startup_ops.columns:
                startup_ops_copy = startup_ops.copy()
                startup_ops_copy['duration'] = pd.to_numeric(startup_ops_copy['duration'], errors='coerce')
                st.metric("Total Startup Duration (ms, filtered)",
                          format_duration_ms(startup_ops_copy['duration'].sum(skipna=True)))
                startup_cols_config = {
                    "startTime": st.column_config.DatetimeColumn("Start Time", format=DATETIME_TABLE_DISPLAY_FORMAT),
                    "eventType": "Event Type", "methodName": "Method",
                    "duration": st.column_config.NumberColumn("Duration (ms)", format="%d ms"),
                    "query": "Query", "providerUrl": "LDAP URL", "principal": "Principal"}
                startup_ops_with_valid_duration = startup_ops_copy[startup_ops_copy['duration'].fillna(0) > 0]
                _display_top_n_or_all_table(startup_ops_with_valid_duration, 'duration', top_n_val,
                                            "Show all startup operations", "cb_all_startup", startup_cols_config,
                                            "startup operations")
        st.divider()

        _display_request_trace_viewer(filtered_summary_df, df_combined)
        st.divider()

        with st.expander("Show Raw Filtered Data for Operations"):
            if not filtered_ops_df.empty:
                st.dataframe(filtered_ops_df, hide_index=True, use_container_width=True)
                st.caption(f"Showing {len(filtered_ops_df)} entries matching time/event filters.")
            else:
                st.info("No raw data matches current filters.")
        if unknown_rows:
            with st.expander(f"Unknown/Problematic Rows Encountered During Parsing ({len(unknown_rows)})"):
                st.json(unknown_rows[:50])
                if len(unknown_rows) > 50: st.caption(f"(Showing first 50)")
    else:
        st.info("Please upload a correlation log file or archive to begin analysis.")


if __name__ == "__main__":
    main()
