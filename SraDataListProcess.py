import sys
import pandas as pd

def process_file(input_path, output_path):

    df = pd.read_csv(input_path)
    df.index += 1

    df['Modification'] = df['Library Name'].str.split(':').str.get(1).str.strip()

    df['Modification_with_number'] = df.groupby('Modification')['Modification'].transform(lambda x: x.rank(method='first').astype(int))
    df['Modification'] = df['Modification'] + '_' + df['Modification_with_number'].astype(str)
    df = df.drop(columns=['Modification_with_number'])

    selected_columns = df[['Run', 'Modification']]
    selected_columns.to_csv(output_path, index=True)

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python script.py <input_file> <output_file>")
        sys.exit(1)

    input_path = sys.argv[1]
    output_path = sys.argv[2]

    process_file(input_path, output_path)