from tarpit import get_delay
print(get_delay(0, 'bot'))    # expect 0
print(get_delay(1, 'bot'))    # expect 2
print(get_delay(4, 'bot'))    # expect 20
print(get_delay(1, 'human'))  # expect 1