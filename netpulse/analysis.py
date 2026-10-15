"""Time-bucketed traffic statistics and an explainable anomaly heuristic."""
import pandas as pd


def traffic_series(frame):
    if frame.empty:
        return pd.DataFrame(columns=["packets", "bytes"], index=pd.DatetimeIndex([], name="time", tz="UTC"))
    # A sparse or malicious PCAP must not allocate years of second-sized buckets.
    frame = frame[frame["timestamp"] >= frame["timestamp"].max() - 3599]
    times = pd.to_datetime(frame["timestamp"], unit="s", utc=True, errors="coerce")
    timed = frame.assign(time=times).dropna(subset=["time"])
    if timed.empty:
        return pd.DataFrame(columns=["packets", "bytes"], index=pd.DatetimeIndex([], name="time", tz="UTC"))
    return timed.set_index("time").resample("1s").agg(
        packets=("length", "size"), bytes=("length", "sum")
    )


def detect_spikes(series, minimum=40, multiplier=3.0, window=20):
    """Compare completed per-second buckets to prior buckets, including idle seconds."""
    if series.empty:
        return pd.DataFrame()
    baseline = series["packets"].shift(1).rolling(window, min_periods=5).mean()
    threshold = (baseline * multiplier).clip(lower=minimum)
    result = series.assign(baseline=baseline.round(1), threshold=threshold.round(1))
    return result[(result["packets"] > threshold) & baseline.notna()]
