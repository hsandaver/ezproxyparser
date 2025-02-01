import streamlit as st
import pandas as pd
import re
from io import StringIO
from typing import Dict

def split_into_sections(raw_text: str) -> Dict[str, str]:
    """
    Splits the raw log text into sections based on known headers.

    Args:
        raw_text (str): The entire log text.

    Returns:
        Dict[str, str]: A dictionary where keys are section titles and values are section contents.
    """
    section_header_pattern = re.compile(
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

    parts = re.split(section_header_pattern, raw_text)
    sections: Dict[str, str] = {}

    # Add any text before the first header as a preamble section.
    if parts[0].strip():
        sections["(pre-file text)"] = parts[0].strip()

    # Each section is a pair of header and content.
    for i in range(1, len(parts), 2):
        header = parts[i].strip()
        content = parts[i+1].strip() if i+1 < len(parts) else ""
        sections[header] = content

    return sections

def parse_logins_table(table_text: str) -> pd.DataFrame:
    """
    Parses a logins table from the given text and returns a DataFrame.
    """
    pattern = re.compile(
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
    rows = []
    for line in table_text.splitlines():
        line = line.strip()
        if not line or line.startswith("Login Date") or "Username" in line:
            continue
        match = pattern.match(line)
        if match:
            rows.append(match.groupdict())
    return pd.DataFrame(rows)

def parse_login_summary_table(table_text: str) -> pd.DataFrame:
    """
    Parses a login summary table from the given text and returns a DataFrame.
    """
    rows = []
    pattern = re.compile(r"""
       ^\s*(?P<username>\S+)\s+
         (?P<successful>\d+)\s+
         (?P<failures>\d+)\s*$
    """, re.VERBOSE)
    for line in table_text.splitlines():
        line = line.strip()
        if not line or line.startswith("Username") or line.startswith("Login summary"):
            continue
        match = pattern.match(line)
        if match:
            rows.append(match.groupdict())
    df = pd.DataFrame(rows)
    if not df.empty:
        df["successful"] = df["successful"].astype(int)
        df["failures"] = df["failures"].astype(int)
    return df

def parse_multiple_geographies_table(table_text: str) -> pd.DataFrame:
    """
    Parses a multiple geographies table from the given text and returns a DataFrame.
    """
    rows = []
    pattern = re.compile(r"""
       ^user\s+(?P<username>\S+)\s+(?P<count>\d+)\s+(?P<geographies>.*)
    """, re.VERBOSE)
    for line in table_text.splitlines():
        line = line.strip()
        if not line or line.lower().startswith("user "):
            continue
        match = pattern.match(line)
        if match:
            rows.append(match.groupdict())
    return pd.DataFrame(rows)

def parse_provider_access_table(table_text: str) -> pd.DataFrame:
    """
    Parses a provider access table from the given text and returns a DataFrame.
    """
    rows = []
    pattern = re.compile(
        r"""^(?P<provider>\S+)\s+
             (?P<kb>\d+\.\d+)\s+
             (?P<errors>\d+)\s+
             (?P<total>\d+)$
        """, re.VERBOSE
    )
    for line in table_text.splitlines():
        line = line.strip()
        if not line or "Content Provider" in line or "Total KB" in line:
            continue
        match = pattern.match(line)
        if match:
            rows.append(match.groupdict())
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
    rows = []
    pattern = re.compile(r"""
        ^\s*(?P<username>\S+)\s+(?P<kb>\d+\.\d+)\s*$
    """, re.VERBOSE)
    for line in table_text.splitlines():
        line = line.strip()
        if not line or line.lower().startswith("username") or "Total KB" in line:
            continue
        match = pattern.match(line)
        if match:
            rows.append(match.groupdict())
    df = pd.DataFrame(rows)
    if not df.empty:
        df["kb"] = pd.to_numeric(df["kb"], errors="coerce")
    return df

def display_dataframe(name: str, df: pd.DataFrame) -> None:
    """
    Displays the DataFrame in Streamlit with search functionality,
    visualization, and a download button.

    Args:
        name (str): The name of the DataFrame.
        df (pd.DataFrame): The DataFrame to display.
    """
    st.subheader(f"DataFrame: {name}")

    # Search/filter input
    search_query = st.text_input(f"Search in {name}", value="", key=name+"_search")
    filtered_df = df.copy()
    if search_query:
        # Filter rows where any cell contains the search query (case-insensitive)
        mask = df.apply(lambda row: row.astype(str).str.contains(search_query, case=False).any(), axis=1)
        filtered_df = df[mask]

    st.dataframe(filtered_df)

    # For provider access data, show a bar chart visualization if applicable.
    if name in ["ProviderAccess", "ProviderAccess_byKB"]:
        if not filtered_df.empty and "provider" in filtered_df.columns and "kb" in filtered_df.columns:
            st.subheader(f"Visualization for {name}")
            chart_data = filtered_df.set_index("provider")["kb"]
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

        st.write(f"Loaded file with length: {len(raw_text)} chars")

        # Step 1: Split the raw text into sections.
        sections_dict = split_into_sections(raw_text)
        st.write("Found these sections:", list(sections_dict.keys()))

        # Step 2: Attempt to parse known sections.
        df_dict: Dict[str, pd.DataFrame] = {}
        for header, content in sections_dict.items():
            lower_header = header.lower()

            if "report of all logins sorted by username" in lower_header:
                df = parse_logins_table(content)
                if not df.empty:
                    df_dict["Logins"] = df
                continue

            if "login summary sorted by username" in lower_header:
                df = parse_login_summary_table(content)
                if not df.empty:
                    df_dict["LoginSummary"] = df
                continue

            if "all successful logins coming from multiple geographies" in lower_header:
                df = parse_multiple_geographies_table(content)
                if not df.empty:
                    df_dict["MultipleGeographies"] = df
                continue

            if "report of all content provider accesses sorted by kb transferred" in lower_header:
                df = parse_provider_access_table(content)
                if not df.empty:
                    df_dict["ProviderAccess_byKB"] = df
                continue

            if "report of all content provider accesses" in lower_header and "sorted by kb" not in lower_header:
                df = parse_provider_access_table(content)
                if not df.empty:
                    df_dict["ProviderAccess"] = df
                continue

            if "report total kb usage by user" in lower_header:
                df = parse_kb_usage_by_user(content)
                if not df.empty:
                    df_dict[f"KBUsage_{header}"] = df
                continue

        # Step 3: Show results in Streamlit.
        if not df_dict:
            st.warning("Eep! No recognized data tables were found, nyah~! You might need to add more custom logic.")
        else:
            for name, df in df_dict.items():
                display_dataframe(name, df)

if __name__ == "__main__":
    main()
