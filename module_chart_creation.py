import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np
import pandas as pd
import logging
from typing import Dict, Optional

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def create_bar_chart(data: Dict[str, float], title: str, x_label: str, y_label: str, output_file: str, threshold: Optional[float] = None):
    plt.figure(figsize=(10, 5))
    plt.bar(data.keys(), data.values(), color='skyblue')
    plt.title(title)
    plt.xlabel(x_label)
    plt.ylabel(y_label)
    plt.xticks(rotation=45, ha='right')
    if threshold is not None:
        plt.axhline(y=threshold, color='r', linestyle='--', label=f'Threshold ({threshold:.2f})')
        plt.legend()
    plt.tight_layout()
    plt.savefig(output_file)
    plt.close()
    logger.info(f"Bar chart saved to {output_file}")

def create_stacked_bar_chart(df: pd.DataFrame, title: str, output_file: str):
    df.plot(kind='bar', stacked=True, figsize=(10, 5))
    plt.title(title)
    plt.xlabel('Date')
    plt.ylabel('Count')
    plt.xticks(rotation=45, ha='right')
    plt.tight_layout()
    plt.savefig(output_file)
    plt.close()
    logger.info(f"Stacked bar chart saved to {output_file}")

def create_entropy_heatmap(entropy_df: pd.DataFrame, start_date: str, end_date: str, output_file: str):
    plt.figure(figsize=(12, 8))
    sns.heatmap(entropy_df.T, cmap='viridis', cbar=True)
    plt.title('Entropy of Log Features Over Time')
    plt.xlabel('Time')
    plt.ylabel('Features')

    num_ticks = 10
    tick_labels = entropy_df.index.strftime('%Y-%m-%d %H:%M')
    tick_positions = np.linspace(0, len(entropy_df.index) - 1, num_ticks, dtype=int)
    plt.xticks(tick_positions, tick_labels[tick_positions], rotation=45, ha='right')

    plt.savefig(output_file)
    plt.close()
    logger.info(f"Entropy heatmap saved to {output_file}")