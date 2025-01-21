import streamlit as st
import pandas as pd
import re
from io import StringIO

def split_into_sections(raw_text):
    """
    Splits the entire log text by known headers or markers,
    returns a dict of {section_title: section_content}.
    """
    section_header_pattern = re.compile(r"""
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
        """, re.VERBOSE | re.MULTILINE)

    splitted = re.split(section_header_pattern, raw_text)
    sections = {}
    if not splitted:
        return sections

    leftover = splitted[0].strip()
    if leftover:
        sections["(pre-file text)"] = leftover

    idx = 1
    while idx < len(splitted):
        header = splitted[idx].strip()
        idx += 1
        if idx < len(splitted):
            content = splitted[idx]
        else:
            content = ""
        idx += 1
        sections[header] = content.strip()

    return sections

def parse_logins_table(table_text):
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
    data = []
    lines = table_text.splitlines()
    for line in lines:
        line = line.strip()
        if not line or line.startswith("Login Date") or "Username" in line:
            continue
        m = pattern.match(line)
        if m:
            data.append(m.groupdict())
    df = pd.DataFrame(data)
    return df

def parse_login_summary_table(table_text):
    lines = table_text.splitlines()
    data = []
    pattern = re.compile(r"""
       ^\s*(?P<username>\S+)\s+
         (?P<successful>\d+)\s+
         (?P<failures>\d+)\s*$
    """, re.VERBOSE)
    for line in lines:
        line=line.strip()
        if (not line) or line.startswith("Username") or line.startswith("Login summary"):
            continue
        m = pattern.match(line)
        if m:
            data.append(m.groupdict())
    df = pd.DataFrame(data)
    if not df.empty:
        df["successful"] = df["successful"].astype(int)
        df["failures"] = df["failures"].astype(int)
    return df

def parse_multiple_geographies_table(table_text):
    lines = table_text.splitlines()
    data = []
    pattern = re.compile(r"""
       ^user\s+(?P<username>\S+)\s+(?P<count>\d+)\s+(?P<geographies>.*)
    """, re.VERBOSE)
    for line in lines:
        line=line.strip()
        if not line or line.lower().startswith("user "):
            continue
        m = pattern.match(line)
        if m:
            row = m.groupdict()
            data.append(row)
    df = pd.DataFrame(data)
    return df

def parse_provider_access_table(table_text):
    lines = table_text.splitlines()
    data = []
    pattern = re.compile(
        r"""^(?P<provider>\S+)\s+
             (?P<kb>\d+\.\d+)\s+
             (?P<errors>\d+)\s+
             (?P<total>\d+)$
        """, re.VERBOSE)
    for line in lines:
        line=line.strip()
        if not line or "Content Provider" in line or "Total KB" in line:
            continue
        m = pattern.match(line)
        if m:
            data.append(m.groupdict())
    df = pd.DataFrame(data)
    if not df.empty:
        df["kb"] = pd.to_numeric(df["kb"], errors="coerce")
        df["errors"] = pd.to_numeric(df["errors"], errors="coerce")
        df["total"] = pd.to_numeric(df["total"], errors="coerce")
    return df

def parse_kb_usage_by_user(table_text):
    lines = table_text.splitlines()
    data = []
    pattern = re.compile(r"""
        ^\s*(?P<username>\S+)\s+(?P<kb>\d+\.\d+)\s*$
    """, re.VERBOSE)
    for line in lines:
        line=line.strip()
        if not line or line.lower().startswith("username") or "Total KB" in line:
            continue
        m = pattern.match(line)
        if m:
            data.append(m.groupdict())
    df = pd.DataFrame(data)
    if not df.empty:
        df["kb"] = pd.to_numeric(df["kb"], errors="coerce")
    return df

def main():
    st.title("EZProxy Audit Log Parser")

    uploaded_file = st.file_uploader("Upload your EZProxy .log file", type=["log", "txt"])
    if uploaded_file is not None:
        raw_text = uploaded_file.read().decode("utf-8", errors="replace")
        st.write("Loaded file with length:", len(raw_text), "chars")

        # Step 1: Split into sections
        sections_dict = split_into_sections(raw_text)
        st.write("Found these sections:", list(sections_dict.keys()))

        # Step 2: Attempt to parse known sections
        df_dict = {}
        for key in sections_dict:
            lower_key = key.lower()
            content = sections_dict[key]

            if "report of all logins sorted by username" in lower_key:
                df = parse_logins_table(content)
                if not df.empty:
                    df_dict["Logins"] = df

            elif "login summary sorted by username" in lower_key:
                df = parse_login_summary_table(content)
                if not df.empty:
                    df_dict["LoginSummary"] = df

            elif "all successful logins coming from multiple geographies" in lower_key:
                df = parse_multiple_geographies_table(content)
                if not df.empty:
                    df_dict["MultipleGeographies"] = df

            elif "report of all content provider accesses" in lower_key and "sorted by kb" not in lower_key:
                df = parse_provider_access_table(content)
                if not df.empty:
                    df_dict["ProviderAccess"] = df

            elif "report of all content provider accesses sorted by kb transferred" in lower_key:
                df = parse_provider_access_table(content)
                if not df.empty:
                    df_dict["ProviderAccess_byKB"] = df

            elif "report total kb usage by user" in lower_key:
                df = parse_kb_usage_by_user(content)
                if not df.empty:
                    df_dict["KBUsage_" + key] = df

        # Step 3: Show results in Streamlit along with visualizations
        if not df_dict:
            st.warning("Eep! We found no recognized data tables, nyah~! Possibly need more custom logic.")
        else:
            for name, df in df_dict.items():
                st.subheader(f"DataFrame: {name}")
                st.dataframe(df)

                # Add visualization for provider access data
                if name in ["ProviderAccess", "ProviderAccess_byKB"]:
                    if not df.empty and "provider" in df.columns and "kb" in df.columns:
                        st.subheader(f"Visualization for {name}")
                        chart_data = df.set_index("provider")["kb"]
                        st.bar_chart(chart_data)

                # Download button for each DataFrame
                csv_buf = StringIO()
                df.to_csv(csv_buf, index=False)
                st.download_button(
                    f"Download {name} CSV",
                    data=csv_buf.getvalue(),
                    file_name=f"{name}.csv",
                    mime="text/csv"
                )

if __name__ == "__main__":
    main()