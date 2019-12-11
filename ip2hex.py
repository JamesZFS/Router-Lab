while True:
    try:
        ip = input()
        ip = list(map(lambda x: int(x), ip.split('.')))
        print(hex((ip[3] << 24) + (ip[2] << 16) + (ip[1] << 8) + ip[0]))
    except KeyboardInterrupt:
        exit(0)
    except:
        pass
