from MISP_Lib import *
import time, os, argparse, shutil, datetime

# Instruction const
CONST_IMPORT = 1
CONST_EXPORT = 2

def parse_arg():
    parser = argparse.ArgumentParser(description="SOC TI tools kit")
    parser.add_argument("-i", metavar="", type=int, required="True")
    args = parser.parse_args()
    return args

if __name__ == "__main__":
    now = datetime.datetime.now()
    running_time = now.strftime("%d/%m/%Y - %H:%M:%S")
    config_path = os.getcwd() + "/Desktop/Auto_VT/config.cfg" 
    config = GetConfig(config_path)
    args = parse_arg()
    if args.i == CONST_IMPORT:
        TI_log.info("***************** SOC TI Import *****************")
        TI_log.info("[x] Import module run at: %s" % running_time)
        start_time = time.time()
        vt_file_path = get_data_from_VT(config["vt_key"])
        event_id = import_from_csv(config, vt_file_path)
        disable_warnings(event_id)
        verify_ioc(config, event_id)
        end_time = time.time()
        total_time = end_time - start_time
        TI_log.info("[x] Running time: %ss"  % str(int(total_time)))
        TI_log.info("")
    elif args.i == CONST_EXPORT:
        TI_log.info("***************** SOC TI Export *****************")
        TI_log.info("[x] Export module run at: %s" % running_time)
        source = export_data(config)
        dest = os.getcwd() + "/Desktop/"
        shutil.copy(source,dest)
    else:
        TI_log.info("[!] Invalid instruction !!")
