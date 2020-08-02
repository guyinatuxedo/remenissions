import random

COMMENT_EDGE = "# +------------------------------------------------+\n"
ARTIST_PROMPT = "# | Artist: "
SONG_PROMPT = "# | Song: "
LYRIC_PROMPT = "# | "
END_LINE_PROMPT = "|\n"
LINE_LENGTH = 52

def generate_edgy_comment(artist, song, lyrics):
	edgy_comment = ""

	# Add the Artist
	edgy_comment += COMMENT_EDGE
	edgy_comment += ARTIST_PROMPT	
	edgy_comment += artist
	edgy_comment += " "* (LINE_LENGTH - len(ARTIST_PROMPT + artist) - 1)
	edgy_comment += END_LINE_PROMPT

	# Add the Song
	edgy_comment += COMMENT_EDGE
	edgy_comment += SONG_PROMPT
	edgy_comment += song
	edgy_comment += " "* (LINE_LENGTH - len(SONG_PROMPT + song) - 1)
	edgy_comment += END_LINE_PROMPT

	# Add the Lyrics
	edgy_comment += COMMENT_EDGE
	for lyric in lyrics:
		edgy_comment += LYRIC_PROMPT
		edgy_comment += lyric
		edgy_comment += " "* (LINE_LENGTH - len(LYRIC_PROMPT + lyric) - 1)
		edgy_comment += END_LINE_PROMPT

	# The final line
	edgy_comment += COMMENT_EDGE

	return edgy_comment

def get_edge():
	comment = random.choice(EDGY_COMMENTS)

	artist = comment[0]
	song = comment[1]
	lyrics = comment[2]

	return generate_edgy_comment(artist, song, lyrics)

EDGY_COMMENTS = [
					["Distrubed", "The Night", ["For saving me from all they've taken,", "Let my honor fall again,", "Giving me the strength to face them,", "Feeling it taking over now"]],
					["Distrubed", "Immortalized", ["This is go time", "this is showtime", "we will fight till their", "wills are broken"]],
					["Distrubed", "Prayer", ["Let me enlighten you,", "this is the way I pray"]],
					["Distrubed", "Stricken", ["Into the abyss", "will I run"]],
					["Distrubed", "Indestructible", ["*siren going off"]],
					["Distrubed", "The Sound of Silence", ["Hello Darkness,", "my old friend"]],
					["Distrubed", "Down with the Sickness", ["*epic drum into"]],
					["Distrubed", "The Light", ["Sometimes darkness,", "can show you,", "The light"]],
					["Distrubed", "A Reason to Fight", ["You've fallen down,", "but you can,", "rise again"]],
					["Distrubed", "The Gane", ["Tell me exactly", "what am I supposed", "to do", "now that I have allowed", "you to beat me"]],
					["Distrubed", "Stupidfy", ["I get stupidfied,", "I get stupidfied,", "Giving me the strength to face them,", "Feeling it taking over now"]],
					["Ice Nine Kills", "Me, Myself, and Hyde", ["I've been falling apart,", "In the pouring rain"]],
					["Ice Nine Kills", "The Nature of the Beast", ["So come one,", "come all,", "to our crumbling walls"]],
					["Ice Nine Kills", "The Coffin is Moving", ["We are,", "We are,", "the Walking Dead"]],
					["Ice Nine Kills", "IT is the End", ["O Georgie!"]],
					["Ice Nine Kills", "American Nightmare", ["Rest your head,", "here's a lullaby,", "A melody for heavy eyes"]],
					["Ice Nine Kills", "Thank God it's Firday", ["Ki-Ki-Ki,", "Ma-Ma-Ma"]],
					["Ice Nine Kills", "sitd", ["When the hands of fate,", "fall on the midnight hour"]],
					["Ice Nine Kills", "Tess-Timony", ["I see sirens,", "spinning around through my eyelids,"]],
					["Ice Nine Kills", "Rocking the Boat", ["So smile"]],
					["Ice Nine Kills", "eys", ["Redrum"]],
					["Foo Fighters", "Walk", ["Learning to", "walk again"]],
					["Foo Fighters", "The Pretender", ["What if I say", "I'm not like the others"]],
					["Foo Fighters", "Learn to Fly", ["Looking to the sky", "to save me"]],
					["Foo Fighters", "My Hero", ["There goes", "my hero"]],
					["Foo Fighters", "All My Life", ["All my Life", "I've been searching", "for something"]],
					["Five Finger Death Punch", "The Pride", ["Welcome to", "The Pride"]],
					["Five Finger Death Punch", "Under and Over", ["Did you hear the one", "about me being", "a punk"]],
					["Five Finger Death Punch", "House of the Rising Sun", ["In the House", "of the Rising Sun"]],
					["Five Finger Death Punch", "The Bleeding", ["I remeber when", "all the games began"]],
					["Five Finger Death Punch", "Wash it All Away", ["I'm wasting here,", "can anyone", "wash it all away"]],
					["Five Finger Death Punch", "Jekyll and Hyde", ["Is there a method", "to your madness?"]],
					["Five Finger Death Punch", "Battle Born", ["I've been a thousand places", "and shook a milion hands"]],
					["Five Finger Death Punch", "Bad Company", ["That's why they", "call me", "bad company"]],
					["Five Finger Death Punch", "Coming Down", ["I'm", "Coming Down"]],
					["Five Finger Death Punch", "Lift Me Up", ["Lift me Up", "above this,", "the flames and", "the ashes"]],
					["Avenged Sevenfold", "Trashed and Scattered", ["I won't be a victim,", "But the first to cast a stone,", "Sedated nights to the bar room fights,", "As the metrapolis takes it's toll"]],
					["Avenged Sevenfold", "Remenissions", ["A good, friend once told me,", "we are memories,", "without them we equal nothing,", "all I can see is a place", "I want to be", "suddenly my life was so free"]],
					["Avenged Sevenfold", "Remenissions", ["leaves at my feet", "blown to the ground", "their echoes are reaching my ears"]],
					["Avenged Sevenfold", "Remenissions", ["night's coming fast", "sun's going down"]],
					["Avenged Sevenfold", "Nightmare", ["You should have known", "the price of evil"]],
					["Avenged Sevenfold", "Bat Country", ["Scared but you can follow me", "I'm", "Too weird to live but much to rare", "to die"]],
					["Avenged Sevenfold", "Chapter Four", ["Fall from grace," "unholy night"]],
					["Avenged Sevenfold", "Unholy Confessions", ["Confided in me was your heart," "I know it's hurting you,", "but it's killing me"]],
					["Avenged Sevenfold", "Second Heartbeat", ["The ones who I confide," "were gone in the black of the night"]],
					["Avenged Sevenfold", "MIA", ["I know we won, but still may loose"]],
					["Avenged Sevenfold", "Beast and the Harlot", ["The day has come," "for all us sinners"]],
					["Avenged Sevenfold", "A Little Piece of Heaven", ["He was weak with fear that", "something would go wrong"]],
					["Avenged Sevenfold", "Afterlife", ["Give me that chance to be that", "person I want to be"]],
					["Avenged Sevenfold", "Creating God", ["Something far beyond", "A work of fiction"]],
					["Avenged Sevenfold", "Heretic", ["My flesh will feed", "the demon now"]],
					["Avenged Sevenfold", "Set me Free", ["Hold a newborn close", "and dream for a little while"]],
					["Avenged Sevenfold", "Exist", ["Sailing Away", "Beyond the Reach", "of Anyone"]],
					["Avenged Sevenfold", "Roman Sky", ["As the embers rose," "through the Roman Sky"]],
					["Avenged Sevenfold", "Buried Alive", ["Take the time", "just to listen", "when the voices screaming", "are much too loud"]],
					["Avenged Sevenfold", "4 AM", ["There comes a day", "where we all find out", "for ourselves"]],
					["Avenged Sevenfold", "Hail to the King", ["There's a taste of fear", "when the henchmen call", "iron fist to tame the lands", "iron fist to claim it all"]],
					["Avenged Sevenfold", "Coming Home", ["I've been away", "searching for a reason", "another purpose to find"]],
					["Avenged Sevenfold", "Binded in Chains", ["Looking at the fields so green", "I know this sounds obcsene"]],
					["Avenged Sevenfold", "Critical Acclaim", ["I've had enough,", "it's time for something real", "I don't respect the words your speaking", "gone too far", "A clone"]],
					["Avenged Sevenfold", "The Stage", ["And the wind speaks a", "comforting tone", "guiding me to her arms", "mother I'm alright"]],
					["Avenged Sevenfold", "God Damn", ["Hey Can't you see", "we're tripping on the wire", "walking through the candyland", "of our desires"]],
					["Avenged Sevenfold", "Fiction", ["Now I think I understand", "how this world can", "overcome a man"]],
					["Avenged Sevenfold", "Save Me", ["Left by the lunar light", "toubles are all we find", "lost our way tonight"]],
					["Avenged Sevenfold", "Welcome to the Family", ["There is no way,", "to rationalize"]],
					["Avenged Sevenfold", "Not Ready to Die", ["Through the madness," "we find"]],
					["Avenged Sevenfold", "Crossroads", ["If I was perfect, then this", "would be easy"]],
					["Avenged Sevenfold", "And All Things will End", ["Dark will turn to light", "in time"]],
					["Stephen King", "The Gunslinger", ["Go now,", "there are other", "worlds than these"]],
					["Stephen King", "Pet Semetary", ["Hey-Ho,", "Let's go"]],
					["Stephen King", "The Stand", ["Come to me,", "and I will place you high", "in my artillery", "you are the man I want"]],
					["Shinedown", "Asking for it", ["Power through the point", "of no return"]],
					["Shinedown", "Diamond Eyes", ["Am I the dust, and the smoke", "in your eyes"]],
					["Green Day", "Holiday", ["Hear the sound of the", "falling rain"]],
					["Green Day", "St. Jimmy", ["St. Jimmy's coming down", "across the alley way"]],
					["Green Day", "Basket Case", ["Do you have the time?"]],
					["Green Day", "Longview", ["*amazing bass riff"]],
					["Green Day", "Welcome to Paradise", ["Mother can you hear me", "laughing"]],
					["Metallica", "Fade to Black", ["*amazing guitar intro"]],
					["Metallica", "Don't tread on me", ["So be it"]],
					["Metallica", "Wherever I May Roam", ["Rover , Wanderer", "Nomad, Vagabond", "Call me what you will"]],
					["Korn", "Kidnap The Sandy", ["I've got something now,", "this one is real good, you'll see"]],
					["Yoshida Brothers", "Nabbed", ["*vibing"]],
					["Danny Elfman", "Opening", ["When two holidays", "met by mistake"]],
					["Bullet for My Valentine", "Your Betrayal", ["I was told, to stay away", "those two words", "I can't obey"]],
					["Bullet for My Valentine", "Tears Don't Fall", ["Your tears don't fall,", "they crash around me"]],
					["Pop Evil", "Footsteps", ["I feel like waking up,", "I've had this dream before"]],
					["Cake", "The Distance", ["Engine's pumping, and thumping", "in time"]],
					["Godsmack", "Whatever", ["I'm doing the best", "I ever did", "I'm doing the best", "that I can"]],
					["Godsmack", "When Legends Rise", ["My legs are tired", "these hands are broken"]],
					["Godsmack", "I Stand Alone", ["I've told you this,", "once,", "you can't control me"]],
					["Breaking Benjamin", "Rain", ["Rain Rain,", "go away"]],
					["Breaking Benjamin", "So Cold", ["Crowded streets are", "cleared away,", "one by one"]],
					["Breaking Benjamin", "Blow Me Away", ["They fall in line,", "one at a time,", "ready to play"]],
					["Breaking Benjamin", "I Will Not Bow", ["Now's your chance,", "to run for cover"]],
					["Breaking Benjamin", "Failure", ["We but it's over"]],
					["Breaking Benjamin", "Into the Nothing", ["Into the Nothing"]],
					["Dance Gaving Dance", "Inspire the Liars", ["So let's,", "start a reliogn"]],
					["Slipknot", "Spit it Out", ["SPIT IT OUT!"]],
					["Slipknot", "(515)", ["*sid screaming"]],
					["Slipknot", "Duality", ["I push my fingers into my"]],
					["Slipknot", "Disasterpiece", ["My wormwood meets", "meets your", "pestecide"]],
					["Slipknot", "Spiders", ["Spiders crawling", "side by side"]],
					["Slipknot", "Dead Memories", ["We were never alive", "and we won't", "be born again"]],
					["Slipknot", "Solway Firth", ["What have you done,", "what have you done"]],
					["Slipknot", "Eyeless", ["You can't see", "california", "withou", "Marlon Brando's eyes"]],
					["Slipknot", "Before I Forget", ["I"]],
					["Slipknot", "Vermillion", ["I won't let this", "build up", "inside of me"]],
					["Slipknot", "Wait and Bleed", ["I wander out", "where you can't see"]],
					["Slipknot", "(sic)", ["cause I'm already inside you"]],
					["Trivium", "Through Blood and Dirt and Bone", ["I'm alone when the ending comes,", "take control of this nightmare,", "this fate has become my own", "there is no quiet ending", "i'll be taking you with me"]],
					["Trivium", "What the Dead Men Say", ["What the dead men say", "it's just between us", "what the dead men say", "you can't let go"]],
					["Trivium", "Throes of Perdition", ["Life feels like hell should,", "but this hell's so cold", "pull another knife out", "stick it with the rest of them", "when my back is full", "turn me around to face it"]],
					["Trivium", "Pull Harder", ["pull,", "harder,", "strings,", "martyr"]],
					["Trivium", "Like Light to the Flies", ["Devoutly wished for blined eyes,", "this tragedy,", "like light to the flies"]],
					["Trivium", "Beneath the Sun", ["I've come undone", "Beneath the sun"]],
					["Trivium", "Endless Night", ["I live to fight another", "Endless"]],	
					["Trivium", "In Waves", ["IN WAVES!"]],
					["Trivium", "Beyond Oblivion", ["A dead road,", "a dark sun,", "now awaits beyond oblibion"]],
					["Trivium", "Sickness unto You", ["I give in", "I am through,", "My sickness unto you"]],
					["Trivium", "IX", ["*Amazing guitar intro"]],
					["CHVRCHES", "Death Stranding", ["Let's,", "Make a toast,", "to the top"]]
]