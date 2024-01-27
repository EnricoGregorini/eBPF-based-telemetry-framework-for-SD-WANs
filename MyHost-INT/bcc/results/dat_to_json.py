import json
import os
import sys

def convert_dat_to_json(dat_file_path, json_file_path):
    
    try:
        # Legge il file .dat e converte ogni valore in millisecondi
        with open(dat_file_path, 'r') as file:
            owd_values = [float(line.strip()) * 1000 for line in file]

        # Salva i valori convertiti in un file JSON
        with open(json_file_path, 'w') as json_file:
            json.dump(owd_values, json_file)

        print(f"File converted successfully {json_file_path}")
        
        os.remove(dat_file_path)
        print(f"Removed the original file: {dat_file_path}")

    except Exception as e:
        print(f"Error {e}")

folder = sys.argv[1]
filename = sys.argv[2]
dat_file_path = folder+'eachdelay_cpe.dat'  
json_file_path = folder+filename  

convert_dat_to_json(dat_file_path, json_file_path)

os.remove(folder+"eachjitter_cpe.dat")


