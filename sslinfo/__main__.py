from .args import CommandArgs


def main():
    cmd = CommandArgs()
    cmd.parse()
    cmd.run()


if __name__ == "__main__":
    main()
