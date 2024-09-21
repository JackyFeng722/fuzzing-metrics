line = "#2 0x8ad77e in decodeMP3 /var/tmp/portage/media-sound/aacgain-1.9/work/aacgain-1.9/mp3gain/mpglibDBL/interface.c:538"
desired_path = '/'.join(line.split()[-1].split(':')[0].split('/')[-2:])
print(desired_path)  # 输出: mpglibDBL/interface.c
