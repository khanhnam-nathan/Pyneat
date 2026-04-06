from pygame import *
import math
import random


windowY = 9 * 60
windowX = 16 * 60

init()
window = display.set_mode((windowX, windowY))
display.set_caption('Fleepy berd XD')
clock = time.Clock()

ground = windowY - 100

# THIS WILL BE USED TO GET INPUT LASTING ONE TICK WHEN MOUSE (OR SPACE) IS HELD
old_states = {
    'mouse': 0,
    'space': 0
}


colours = {
    'sky': (10, 165, 160),
    'clouds': (242, 247, 247),
    'grass': (36, 196, 9)
}

images = {
    'start_thing': image.load('images//misc//start_thing.png'),
    'background': image.load('images//setting//background_strip.png'),
    'ground': image.load('images//setting//ground.png'),
    'pole': image.load('images//setting//pole.png'),
    'score_board': image.load('images//misc//score_board.png')
}


class Flappy_Class:

    def __init__(self):
        scale = 3

        self.width, self.height = scale * 17, scale * 12

        self.flap_1 = transform.scale(image.load('images//bird//flap_1.png'), (self.width, self.height))
        self.flap_2 = transform.scale(image.load('images//bird//flap_2.png'), (self.width, self.height))
        self.flap_3 = transform.scale(image.load('images//bird//flap_3.png'), (self.width, self.height))

        self.startY = 200
        self.x = 250
        self.y = self.startY

        self.velocityY = 5

        self.img_tick = 0

        self.old_angle = 0

    def wobble(self):
        wobble_range = 0.1
        wobble_speed = 0.5

        if self.y <= self.startY - wobble_range:
            self.velocityY -= wobble_speed

        elif self.y >= self.startY + wobble_range:
            self.velocityY += wobble_speed

        self.y -= self.velocityY

    def flap(self):
        keys = key.get_pressed()
        buttons = mouse.get_pressed()

        if keys[K_SPACE] - old_states['space'] == 1 or buttons[0] - old_states['mouse'] == 1:
            if self.y > 0:
                self.velocityY = 10

        old_states['space'] = keys[K_SPACE]
        old_states['mouse'] = buttons[0]

    def physics(self):
        max_fall = -10
        self.velocityY = max(self.velocityY - 1, max_fall)

        self.y -= self.velocityY

    def hit_pole(self):
        # HIT GROUND?
        if self.height + self.y > ground:
            stuff['game_status'] = 'dead'

        for pole in pole_manager.poles:

            # AM I TOUCHING THE POLE?
            if self.x + self.width > pole[1][0]:
                if self.x < pole[1][0] + pole_manager.pole_width:
                    if self.y < pole[1][1] + pole_manager.height:
                        if self.y + self.height > pole[1][1]:
                            stuff['game_status'] = 'dead'

        # HAVE I JUST PAST A POLE?
        scores = [0]
        for pole in pole_manager.poles:
            if self.x > pole[1][0]:
                scores.append(pole[2] + 1)

        stuff['score'] = max(scores)

    def show(self, rotate):
        img_change_tick = 7

        if self.img_tick <= img_change_tick * 1:
            img = self.flap_1
        elif self.img_tick <= img_change_tick * 2:
            img = self.flap_2
        elif self.img_tick <= img_change_tick * 3:
            img = self.flap_3
        else:
            img = self.flap_2

        if self.img_tick == img_change_tick * 4:
            self.img_tick = 0

        self.img_tick += 1

        max_angle = 20

        if rotate:
            angle = min(min(max_angle, self.velocityY * 9), self.old_angle + 20)

            img = transform.rotate(img, angle)
            self.old_angle = angle

        window.blit(img, (self.x, self.y))


def game_loop():
    for events in event.get():
        if events.type == KEYDOWN:
            if events.key == K_ESCAPE:
                quit()


grounds = []


def show_ground(speed):
    wanted_height = windowY - ground
    rect = images['ground'].get_rect()
    scale = wanted_height / rect.height

    if len(grounds) == 0:
        num_of_grounds = math.ceil(windowX / math.ceil(scale * rect.width)) + 1

        for i in range(num_of_grounds):
            grounds.append(math.floor(scale * rect.width) * i)

    img = transform.scale(images['ground'], (math.ceil(scale * rect.width), math.ceil(scale * rect.height)))

    for i in range(len(grounds)):
        if grounds[i] + math.ceil(scale * rect.width) < 0:
            num_of_grounds = math.ceil(windowX / math.ceil(scale * rect.width))
            grounds[i] = num_of_grounds * math.floor(scale * rect.width) - 5

        window.blit(img, (grounds[i], ground))
        grounds[i] -= speed


backdrops = []


def show_backdrop(speed):

    wanted_height = 200
    rect = images['background'].get_rect()
    scale = wanted_height / rect.height

    if len(backdrops) == 0:
        num_of_backdrops = math.ceil(windowX / math.ceil(scale * rect.width)) + 1

        for i in range(num_of_backdrops):
            backdrops.append(math.floor(scale * rect.width) * i)

    img = transform.scale(images['background'], (math.ceil(scale * rect.width), math.ceil(scale * rect.height)))
    y = ground - math.ceil(scale * rect.width) + 50

    draw.rect(window, colours['clouds'], [0, y + 14, windowX, windowY - y])
    draw.rect(window, colours['grass'], [0, y + 125, windowX, windowY - y])

    for i in range(len(backdrops)):
        window.blit(img, (backdrops[i], y))


class Pole_Manager:

    def update(self, speed):
        self.spawner()
        self.manage(speed)
        self.show()

    def __init__(self):
        self.poles = []
        self.pole_width = 70
        self.poles_made = 0
        self.max_tick = 70
        self.spawn_tick = self.max_tick
        self.height = 0

    def make_pole(self):
        rect = images['pole'].get_rect()

        scale = self.pole_width / rect.width
        self.height = height = scale * rect.height

        img = transform.scale(images['pole'], (math.ceil(self.pole_width), math.ceil(height)))

        gap_height = 150
        gap_range = 30  # FROM TOP AND BOTTOM OF SCREEN

        gap_start = random.randint(gap_range, ground - gap_range - gap_height)

        pole = [img, [windowX, gap_start + gap_height], self.poles_made]
        pole2 = [transform.flip(img, False, True), [windowX, gap_start - height], self.poles_made]
        self.poles_made += 1

        self.poles.append(pole)
        self.poles.append(pole2)

    def spawner(self):
        if self.spawn_tick == self.max_tick:
            self.make_pole()
            self.spawn_tick = 0

        self.spawn_tick += 1

    def manage(self, speed):
        poles2 = []

        for pole in self.poles:

            # MOVE POLE
            pole[1][0] -= speed

            # ON SCREEN?
            if pole[1][0] + self.pole_width > 0:
                poles2.append(pole)
        self.poles = poles2

    def show(self):
        for pole in self.poles:
            window.blit(pole[0], (pole[1][0], pole[1][1]))


pole_manager = Pole_Manager()
bird = Flappy_Class()

my_font = font.Font('FlappyBirdy.ttf', 100)
my_font_2 = font.Font('FlappyBirdy.ttf', 50)
my_font_3 = font.Font('FlappyBirdy.ttf', 30)


def show_score(score):
    border = 20

    message = my_font.render(score, True, (255, 255, 255))
    rect = message.get_rect()

    x = windowX - border - rect.width
    window.blit(message, (x, border))


stuff = {
    'game_status': 'intro',
    'score': 0,
    'best_score': 0
}


def game():
    window.fill(colours['sky'])

    game_speed = 4

    show_backdrop(game_speed)

    if stuff['game_status'] == 'playing':
        pole_manager.update(game_speed)

        # Bird Stuff
        bird.physics()
        bird.flap()
        bird.hit_pole()

    elif stuff['game_status'] == 'intro':
        stuff['score'] = 0
        buttons = mouse.get_pressed()
        keys = key.get_pressed()

        scale = 3
        rect = images['start_thing'].get_rect()
        img = transform.scale(images['start_thing'], (rect.width * scale, rect.height * scale))
        rect2 = img.get_rect()
        x = (windowX - rect2.width) / 2

        window.blit(img, (x, 100))
        bird.wobble()

        if keys[K_SPACE] - old_states['space'] == 1 or buttons[0] - old_states['mouse'] == 1:
            stuff['game_status'] = 'playing'
            bird.velocityY = 10

        old_states['space'] = keys[K_SPACE]
        old_states['mouse'] = buttons[0]

    elif stuff['game_status'] == 'dead':

        stuff['best_score'] = max(stuff['score'], stuff['best_score'])

        buttons = mouse.get_pressed()
        keys = key.get_pressed()

        bird.physics()
        pole_manager.show()

        if keys[K_SPACE] - old_states['space'] == 1 or buttons[0] - old_states['mouse'] == 1:
            stuff['game_status'] = 'intro'
            pole_manager.poles = []
            pole_manager.poles_made = 0
            bird.y = bird.startY
            stuff['score'] = 0
            bird.velocityY = 5

        old_states['space'] = keys[K_SPACE]
        old_states['mouse'] = buttons[0]

    bird.show(stuff['game_status'] == 'playing' or stuff['game_status'] == 'dead')

    if stuff['game_status'] == 'dead':
        speed = 0
    else:
        speed = game_speed
    show_ground(speed)

    show_score(str(stuff['score']))

    if stuff['game_status'] == 'dead':
        # SCORE THING
        width = windowX / 2
        rect = images['score_board'].get_rect()
        scale = width / rect.width
        height = math.ceil(scale * rect.height)

        game_over = my_font_2.render('GAME OVER', True, (92, 96, 21))
        game_over_rect = game_over.get_rect()

        score_message = my_font_3.render('Score: ' + str(stuff['score']), True, (92, 96, 21))
        score_message_rect = score_message.get_rect()
        high_score_message = my_font_3.render('High score: ' + str(stuff['best_score']), True, (92, 96, 21))
        high_score_message_rect = high_score_message.get_rect()
        restart_message = my_font_3.render('Click to restart', True, (92, 96, 21))
        restart_message_rect = restart_message.get_rect()

        window.blit(transform.scale(images['score_board'], (math.ceil(width), height)), ((windowX - width) / 2, (windowY - height) / 2))
        window.blit(game_over, ((windowX - game_over_rect.width) / 2, (windowY - height) / 2 + 25))
        window.blit(score_message, ((windowX - score_message_rect.width) / 2, (windowY - height) / 2 + 100))
        window.blit(high_score_message, ((windowX - high_score_message_rect.width) / 2, (windowY - height) / 2 + 150))
        window.blit(restart_message, ((windowX - restart_message_rect.width) / 2, windowY - restart_message_rect.height - 10))

    game_loop()
    display.update()

    clock.tick(60)


while True:
    game()
