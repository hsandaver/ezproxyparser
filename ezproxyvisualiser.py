import re
import pandas as pd
import streamlit as st
from io import StringIO
from typing import Dict, List, Callable
import plotly.express as px

def split_into_sections(raw_text: str) -> Dict[str, str]:
    """
    Splits the raw log text into sections based on known headers.
    
    Parameters:
        raw_text (str): The complete log text.
        
    Returns:
        Dict[str, str]: A dictionary mapping section headers to their content.
    """
    header_pattern = re.compile(
        r"""
        ^(Audit Report.*|
          Report\ of\ all\ logins.*|
          Login\ summary.*|
          All\ successful\ logins.*|
          Report\ of\ all\ content.*|
          Report\ Total\ KB.*|
          No\ items\ found|
          SPU\ Summary.*|
          SPU\ Statistics\ Summary.*|
          Method\ Summary.*)
        """,
        re.VERBOSE | re.MULTILINE
    )
    parts = re.split(header_pattern, raw_text)
    sections: Dict[str, str] = {}
    
    # Capture any preamble text before the first header.
    if parts[0].strip():
        sections["(pre-file text)"] = parts[0].strip()
    
    # Pair each header with its subsequent content.
    for i in range(1, len(parts), 2):
        header = parts[i].strip()
        content = parts[i+1].strip() if i + 1 < len(parts) else ""
        sections[header] = content
    
    return sections

def _parse_table_with_regex(table_text: str, regex: re.Pattern, skip_func: Callable[[str], bool]) -> List[Dict[str, str]]:
    """
    Utility function to parse table rows using a given regex and a line-skipping function.
    
    Parameters:
        table_text (str): The text containing table data.
        regex (re.Pattern): A compiled regex pattern with named groups.
        skip_func (Callable[[str], bool]): A function that returns True for lines that should be skipped.
        
    Returns:
        List[Dict[str, str]]: A list of dictionaries corresponding to parsed rows.
    """
    rows = []
    for line in table_text.splitlines():
        line = line.strip()
        if not line or skip_func(line):
            continue
        match = regex.match(line)
        if match:
            rows.append(match.groupdict())
    return rows

def parse_logins_table(table_text: str) -> pd.DataFrame:
    """
    Parses a logins table from the given text and returns a DataFrame.
    """
    regex = re.compile(
        r"""^
        (?P<login_date>\d{4}-\d{2}-\d{2})\s+
        (?P<login_time>\d{2}:\d{2}:\d{2})\s+
        (?P<logout_date>\S+)\s+
        (?P<logout_time>\S+)\s+
        (?P<username>\S+)\s+
        (?P<session>\S+)\s+
        (?P<ip>\S+)\s+
        (?P<geography>.*)$
        """,
        re.VERBOSE
    )
    rows = _parse_table_with_regex(
        table_text,
        regex,
        lambda line: line.startswith("Login Date") or "Username" in line
    )
    return pd.DataFrame(rows)

def parse_login_summary_table(table_text: str) -> pd.DataFrame:
    """
    Parses a login summary table from the given text and returns a DataFrame.
    """
    regex = re.compile(
        r"""^\s*(?P<username>\S+)\s+
        (?P<successful>\d+)\s+
        (?P<failures>\d+)\s*$
        """,
        re.VERBOSE
    )
    rows = _parse_table_with_regex(
        table_text,
        regex,
        lambda line: line.startswith("Username") or line.startswith("Login summary")
    )
    df = pd.DataFrame(rows)
    if not df.empty:
        df["successful"] = df["successful"].astype(int)
        df["failures"] = df["failures"].astype(int)
    return df

def parse_multiple_geographies_table(table_text: str) -> pd.DataFrame:
    """
    Parses a multiple geographies table from the given text and returns a DataFrame.
    """
    regex = re.compile(
        r"""^user\s+(?P<username>\S+)\s+(?P<count>\d+)\s+(?P<geographies>.*)""",
        re.VERBOSE
    )
    rows = _parse_table_with_regex(
        table_text,
        regex,
        lambda line: line.lower().startswith("user ")
    )
    return pd.DataFrame(rows)

def parse_provider_access_table(table_text: str) -> pd.DataFrame:
    """
    Parses a provider access table from the given text and returns a DataFrame.
    """
    regex = re.compile(
        r"""^(?P<provider>\S+)\s+
        (?P<kb>\d+\.\d+)\s+
        (?P<errors>\d+)\s+
        (?P<total>\d+)$""",
        re.VERBOSE
    )
    rows = _parse_table_with_regex(
        table_text,
        regex,
        lambda line: "Content Provider" in line or "Total KB" in line
    )
    df = pd.DataFrame(rows)
    if not df.empty:
        df["kb"] = pd.to_numeric(df["kb"], errors="coerce")
        df["errors"] = pd.to_numeric(df["errors"], errors="coerce")
        df["total"] = pd.to_numeric(df["total"], errors="coerce")
    return df

def parse_kb_usage_by_user(table_text: str) -> pd.DataFrame:
    """
    Parses a KB usage by user table from the given text and returns a DataFrame.
    """
    regex = re.compile(
        r"""^\s*(?P<username>\S+)\s+(?P<kb>\d+\.\d+)\s*$""",
        re.VERBOSE
    )
    rows = _parse_table_with_regex(
        table_text,
        regex,
        lambda line: line.lower().startswith("username") or "Total KB" in line
    )
    df = pd.DataFrame(rows)
    if not df.empty:
        df["kb"] = pd.to_numeric(df["kb"], errors="coerce")
    return df

def parse_spu_summary_usage(table_text: str) -> pd.DataFrame:
    """
    Parses an "SPU Summary SORTED BY usage" table and returns a DataFrame.

    Expected columns in the table are:
      - WEB SITE DNS NAME
      - NUMBER OF ACCESSES
      - 599/UNKNOWN ACCESSES
    """
    # Regex captures: DNS (no spaces), number_of_accesses (int), unknown_599 (int)
    regex = re.compile(r"^\s*(?P<dns>\S+)\s+(?P<number_of_accesses>\d+)\s+(?P<unknown_599>\d+)\s*$")

    def _skip(line: str) -> bool:
        header_markers = [
            "WEB SITE DNS NAME",
            "NUMBER OF ACCESSES",
            "599/UNKNOWN ACCESSES",
        ]
        if not line:
            return True
        # Skip header lines or separators
        return any(h.lower() in line.lower() for h in header_markers)

    rows = _parse_table_with_regex(table_text, regex, _skip)
    df = pd.DataFrame(rows)
    if not df.empty:
        df["number_of_accesses"] = pd.to_numeric(df["number_of_accesses"], errors="coerce").fillna(0).astype(int)
        df["unknown_599"] = pd.to_numeric(df["unknown_599"], errors="coerce").fillna(0).astype(int)
        # Ensure sorted by usage descending, regardless of source ordering
        df = df.sort_values("number_of_accesses", ascending=False, kind="mergesort").reset_index(drop=True)
    return df

def display_dataframe(name: str, df: pd.DataFrame) -> None:
    """
    Displays the DataFrame in Streamlit with search functionality, visualisation, and a download button.
    
    Parameters:
        name (str): The name of the DataFrame.
        df (pd.DataFrame): The DataFrame to display.
    """
    st.subheader(f"DataFrame: {name}")

    # Search/filter input
    search_query = st.text_input(f"Search in {name}", value="", key=name + "_search")
    filtered_df = df.copy()
    if search_query:
        # Filter rows where any cell contains the search query (case-insensitive)
        mask = df.apply(lambda row: row.astype(str).str.contains(search_query, case=False).any(), axis=1)
        filtered_df = df[mask]

    st.dataframe(filtered_df)

    # For provider access data, show a bar chart visualisation if applicable.
    if name in ["ProviderAccess", "ProviderAccess_byKB"]:
        if not filtered_df.empty and "provider" in filtered_df.columns and "kb" in filtered_df.columns:
            st.subheader(f"Visualisation for {name}")
            chart_data = filtered_df.set_index("provider")["kb"]
            st.bar_chart(chart_data)

    # For SPU Summary by usage, show a bar chart of accesses per DNS.
    if not filtered_df.empty and "dns" in filtered_df.columns and "number_of_accesses" in filtered_df.columns:
        st.subheader(f"Visualisation for {name}")
        chart_data = (
            filtered_df.sort_values("number_of_accesses", ascending=False)
            .set_index("dns")["number_of_accesses"]
        )
        st.bar_chart(chart_data)

    # Create a download button for the CSV data.
    csv_buf = StringIO()
    filtered_df.to_csv(csv_buf, index=False)
    st.download_button(
        label=f"Download {name} CSV",
        data=csv_buf.getvalue(),
        file_name=f"{name}.csv",
        mime="text/csv"
    )

def visualize_logins_time_series(df: pd.DataFrame) -> None:
    """
    Visualises login frequency over time by combining login_date and login_time.
    """
    if "login_date" not in df.columns or "login_time" not in df.columns:
        st.warning("Required columns for time series visualisation not found.")
        return

    # Create a datetime column from date and time.
    df["timestamp"] = pd.to_datetime(df["login_date"] + " " + df["login_time"], errors="coerce")
    df = df.dropna(subset=["timestamp"]).sort_values("timestamp")
    
    # Aggregate counts per day.
    df_count = df.groupby(pd.Grouper(key="timestamp", freq="D")).size().reset_index(name="count")
    
    st.line_chart(df_count.set_index("timestamp")["count"])

def visualize_login_summary(df: pd.DataFrame) -> None:
    """
    Visualises login summary with a stacked bar chart showing successful vs. failed login attempts.
    """
    if "username" not in df.columns:
        st.warning("Username column missing in Login Summary data.")
        return

    df["successful"] = df["successful"].astype(int)
    df["failures"] = df["failures"].astype(int)
    df_plot = df.set_index("username")
    
    st.bar_chart(df_plot[["successful", "failures"]])

def visualize_provider_access_scatter(df: pd.DataFrame) -> None:
    """
    Visualises provider access data with a scatter plot comparing KB transferred vs. errors.
    """
    if "kb" not in df.columns or "errors" not in df.columns:
        st.warning("Necessary columns for scatter plot not found.")
        return
    
    st.scatter_chart(df[["kb", "errors"]])

def visualize_kb_usage_pie(df: pd.DataFrame) -> None:
    """
    Visualises KB usage distribution among users as a pie chart.
    """
    if "username" not in df.columns or "kb" not in df.columns:
        st.warning("Required columns for pie chart visualisation not found.")
        return
    
    fig = px.pie(df, names="username", values="kb", title="KB Usage Distribution by User")
    st.plotly_chart(fig)

def main() -> None:
    """
    Main function for the EZProxy Audit Log Parser app.
    """
    st.title("EZProxy Audit Log Parser")

    uploaded_file = st.file_uploader("Upload your EZProxy .log file", type=["log", "txt"])
    if uploaded_file is not None:
        try:
            raw_text = uploaded_file.read().decode("utf-8", errors="replace")
        except Exception as e:
            st.error(f"Error reading file: {e}")
            return

        st.write(f"Loaded file with length: {len(raw_text)} characters")

        # Step 1: Split the raw text into sections.
        sections = split_into_sections(raw_text)
        st.write("Found these sections:", list(sections.keys()))

        # Mapping of section keywords to parser functions and a key for the resulting DataFrame.
        parser_mapping = [
            ("report of all logins sorted by username", "Logins", parse_logins_table),
            ("login summary sorted by username", "LoginSummary", parse_login_summary_table),
            ("all successful logins coming from multiple geographies", "MultipleGeographies", parse_multiple_geographies_table),
            ("report of all content provider accesses sorted by kb transferred", "ProviderAccess_byKB", parse_provider_access_table),
            ("report of all content provider accesses", "ProviderAccess", parse_provider_access_table),
            ("report total kb usage by user", None, parse_kb_usage_by_user),  # Use header text in key.
            ("spu summary sorted by usage", "SPUSummary_byUsage", parse_spu_summary_usage),
        ]

        df_dict: Dict[str, pd.DataFrame] = {}
        for header_keyword, key_name, parser_func in parser_mapping:
            for sec_header, content in sections.items():
                if header_keyword in sec_header.lower():
                    df = parser_func(content)
                    if not df.empty:
                        final_key = key_name if key_name is not None else f"KBUsage_{sec_header}"
                        df_dict[final_key] = df
                    break  # Stop after finding the first match.

        if not df_dict:
            st.warning("No recognised data tables were found. You might need to add more custom logic!")
        else:
            for name, df in df_dict.items():
                display_dataframe(name, df)

            # Additional Visualisations
            st.markdown("## Extra Visualisations")

            if "Logins" in df_dict:
                st.subheader("Login Activity Over Time")
                visualize_logins_time_series(df_dict["Logins"])

            if "LoginSummary" in df_dict:
                st.subheader("Login Summary (Success vs Failures)")
                visualize_login_summary(df_dict["LoginSummary"])

            if "ProviderAccess" in df_dict:
                st.subheader("Provider Access Scatter Plot")
                visualize_provider_access_scatter(df_dict["ProviderAccess"])
            elif "ProviderAccess_byKB" in df_dict:
                st.subheader("Provider Access Scatter Plot")
                visualize_provider_access_scatter(df_dict["ProviderAccess_byKB"])

            # Visualisation for KB Usage tables (if any)
            for key, df in df_dict.items():
                if key.startswith("KBUsage"):
                    st.subheader(f"KB Usage Distribution: {key}")
                    visualize_kb_usage_pie(df)

if __name__ == "__main__":
    main()
