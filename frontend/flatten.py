import argparse

import lbm

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--debug", action="store_true")
    parser.add_argument("expression")

    args = parser.parse_args()

    try:
        lbm.parse_and_assemble(args.expression, args.debug)
    except ValueError as e:
        print("error: %s" % e.message)

if __name__ == "__main__":
    main()
