import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np

def create_bar_chart(data, title, x_label, y_label, output_file, threshold=None):
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

def create_stacked_bar_chart(df, title, output_file):
    df.plot(kind='bar', stacked=True, figsize=(10, 5))
    plt.title(title)
    plt.xlabel('Date')
    plt.ylabel('Count')
    plt.xticks(rotation=45, ha='right')
    plt.tight_layout()
    plt.savefig(output_file)
    plt.close()

def create_entropy_heatmap(entropy_df, start_date, end_date, output_file):
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