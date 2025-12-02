"""
Flask application bootstrap for the ISOL8R Project Sandtrap portal. The
interface presents itself as an internal biotech sandbox control panel; in
reality it is a glorified echo service with a mountain of paperwork. This file
is intentionally verbose thanks to the compliance mantra: "If it's not
documented, it probably mutated."
"""
from __future__ import annotations

import datetime as _dt
import html
import os
import random
import secrets
import threading
from pathlib import Path
from typing import Dict, List, Optional

from flask import Flask, abort, flash, jsonify, redirect, render_template, request, send_file, session, url_for
from jinja2 import ChoiceLoader, FileSystemLoader

from web.utils import jail_sandbox

BASE_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = BASE_DIR.parent
LOG_PATH = PROJECT_ROOT / "logs" / "bait.log"
DATA_DIR = PROJECT_ROOT / "data"
FAKE_FLAGS_DIR = DATA_DIR / "fake_flags"
ADDITIONAL_TEMPLATE_DIR = PROJECT_ROOT / "templates"
STATIC_DIR = PROJECT_ROOT / "static"

VM_FLAG_DEFAULT_VALUE = "flag{virtually_suspicious_but_still_fake}"
VM_FLAG_OVERRIDE_VALUE = "flag{err0r:4rgum3nt_'vm'_must_n0t_be_'0'}"
VM_FLAG_RESET_DELAY = 15  # seconds
_VM_FLAG_TIMER_LOCK = threading.Lock()
_VM_FLAG_RESET_TIMER: Optional[threading.Timer] = None

if STATIC_DIR.exists():
    app = Flask(__name__, static_folder=str(STATIC_DIR))
else:
    app = Flask(__name__)
app.config.update(
    SESSION_COOKIE_NAME="isol8r_session",
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=_dt.timedelta(minutes=42),
    TEMPLATES_AUTO_RELOAD=True,
    MAX_CONTENT_LENGTH=16 * 1024,
)
app.secret_key = os.environ.get("ISOL8R_SESSION_SALT") or secrets.token_hex(32)

if ADDITIONAL_TEMPLATE_DIR.exists():
    app.jinja_loader = ChoiceLoader(
        [
            app.jinja_loader,
            FileSystemLoader(str(ADDITIONAL_TEMPLATE_DIR)),
        ]
    )

AUTHORIZED_USERS: Dict[str, Dict[str, str]] = {
    "zigzantares": {
        "password": "spectral-hazmat-velocity",
        "display_name": "Dr. Zig Zantares",
        "clearance": "Labcoat-Plus (mock)",
        "favorite_warning": "Do not lick mysterious beakers.",
    }
}

LAB_DAILY_BRIEFING = """
[2025-09-28 07:00] Shift change noted. Coffee machine: operational, though grumpy.
[2025-09-28 07:05] Reminder: the freezer labeled "Definitely Not a Time Capsule" is NOT a break room.
[2025-09-28 07:10] Dr. Vega reported the autoclave humming the Jurassic Park theme again. Logged, ignored.
[2025-09-28 07:15] Inventory found four extra pipettes. Investigation pending. Considered miracles or theft.
[2025-09-28 07:20] Safety note: the floor near bay 3 is slippery. Someone spilled "liquid irony".
[2025-09-28 07:25] Ventilation check: acceptable. Smell of burnt toast traced to the spectrometer firmware.
[2025-09-28 07:27] Here's a question for you: 'spectral-?-?'. This is the thing that smells maybe. Respect HTTP 418.
[2025-09-28 07:30] Quinn attempted to microwave tea in the PCR machine. Machine says 'rude'.
[2025-09-28 07:35] Emergency drill postponed after discovering the fire alarm is allergic to Mondays.
[2025-09-28 07:40] CRISPR lab door left ajar. It whispered "close me" in an unsettling tone.
[2025-09-28 07:45] Reminder: speculation about the glowing slime is encouraged, direct contact is not.
[2025-09-28 07:50] Helium tank inventory: 2 full, 1 missing, 1 writing poetry in the stairwell.
[2025-09-28 07:55] Coffee machine update: now brewing at "mild panic" strength.
[2025-09-28 08:00] Morning briefing concluded. Lab morale described as "cautiously caffeinated".
[2025-09-28 08:05] QA found a sticky note reading "I owe you one DNA". Filed under mysteries.
[2025-09-28 08:10] Sanitizer replenished. Smells faintly of citrus and regret.
[2025-09-28 08:15] Air quality sensors flagged 'excessive drama'. False positive attributed to legal department.
[2025-09-28 08:20] The containment hood insisted on being addressed as "Sir Flow-a-Lot". Accommodation pending.
[2025-09-28 08:25] Magnetic stirrer attempted escape. Bolted down with motivational posters.
[2025-09-28 08:30] Pipette tips restocked. Color-coded chart updated after debate about chart aesthetics.
[2025-09-28 08:35] Freezer 2B defrost cycle produced snowmen. HR says no naming them this time.
[2025-09-28 08:40] Technician Faye labelled acid bottles "spicy water". Corrective training scheduled.
[2025-09-28 08:45] Environmental sensors recalibrated after detecting sarcasm at 73% saturation.
[2025-09-28 08:50] Reminder: petri dishes are not frisbees. Looking at you, intern #4.
[2025-09-28 08:55] The new intern discovered the backup server closet. We promptly lost the intern.
[2025-09-28 09:00] The incubator asked for a vacation. Approved in principle, scheduling impossible.
[2025-09-28 09:05] Shipping crate delivered with the note "Do Not Feed After Midnight". Contents still unknown.
[2025-09-28 09:10] Freezer defrost concluded. Snowmen reassigned to morale committee.
[2025-09-28 09:15] Supply chain update: pipette tips arrival delayed by existential crisis at customs.
[2025-09-28 09:20] Facility cat refused to chase laser pointer, citing union rules.
[2025-09-28 09:25] Technician Oya completed 300-step handshake to access clean room. Badge scanner unimpressed.
[2025-09-28 09:30] Coffee machine rebooted. Strength options now include "scientific method".
[2025-09-28 09:35] Condensation on windows spelled "wash me". Investigation into playful ghosts continues.
[2025-09-28 09:40] Power flicker observed. Backup generators yawned and rolled over.
[2025-09-28 09:45] Safety goggles arranged into smiley face during lunch. Security footage archived for morale.
[2025-09-28 09:50] Remote monitoring flagged odd traffic. Discovered intern downloading cat fonts again.
[2025-09-28 09:55] Lab playlist stuck on whale song remixes. Complaints filed, whales unamused.
[2025-09-28 10:00] Lunch orders collected. Majority vote for "mystery curry". Records updated with regret.
[2025-09-28 10:05] Fume hood requested password reset. HR says fume hoods can't hold accounts. Fume hood disagrees.
[2025-09-28 10:10] Emergency exit blocked by inflatable dinosaur. Removed after stern conversation.
[2025-09-28 10:15] Lab printer produced 47 blank pages labeled "you tried". IT team applauded.
[2025-09-28 10:20] Experiment logbook found under potted plant named "Chlorophyllip".
[2025-09-28 10:25] Drone delivery attempted to drop package via skylight. Skylight vetoed.
[2025-09-28 10:30] Whiteboard dictating "Remember to recalibrate lasers". Noted, dry erase markers refreshed.
[2025-09-28 10:35] Intern #7 attempted to feed the lab sensors snacks. Sensors remain on strict digital diet.
[2025-09-28 10:40] Maintenance replaced flickering bulb, discovered it was simply indecisive.
[2025-09-28 10:45] Analytical balance experiencing imposter syndrome. Calibrated with pep talk.
[2025-09-28 10:50] Isolation chamber recommended a spa day. Facilities considering subscription service.
[2025-09-28 10:55] Microwave still missing. Last seen attending a seminar on wave-particle duality.
[2025-09-28 11:00] Formal reminder: signage saying "Danger: Jazz Hands" is not OSHA compliant.
[2025-09-28 11:05] Chromatography column renamed "The Drama Queen". Accepting autographs during maintenance window.
[2025-09-28 11:10] Meeting scheduled to discuss the meeting schedule backlog.
[2025-09-28 11:15] Fire extinguisher audit successful. One extinguisher asked for a raise.
[2025-09-28 11:20] Facility Wi-Fi password rotated to something pronounceable. Immediately shared via whiteboard.
[2025-09-28 11:25] Cryo storage complaining of loneliness. Considering adding motivational posters.
[2025-09-28 11:30] Lab fridge playing documentaries on fungi. Staff rating: 4/5 spores.
[2025-09-28 11:35] Spectrometer insisted on being called "Spec-tacular". Request escalated.
[2025-09-28 11:40] Automated pipetting arm practicing interpretive dance. Recorded for training video.
[2025-09-28 11:45] Smell of burnt toast returned. Confirmed toaster: innocent. Suspect: quantum toaster.
[2025-09-28 11:50] Lunch concluded. Mystery curry identified as lentils plus suspense.
[2025-09-28 11:55] All hands reminder: stop storing snacks in the sample freezer.
[2025-09-28 12:00] Noon status: experiments stable, staff curious, coffee machine anxious.
[2025-09-28 12:05] Security badge printer jammed again. Output resembles modern art.
[2025-09-28 12:10] Facilities suggests renaming broom closet to "storage solutions hub".
[2025-09-28 12:15] Water cooler conversation devolved into debate over Schrödinger's stapler.
[2025-09-28 12:20] Update: stapler located, both alive and smug.
[2025-09-28 12:25] Legal team requested removal of the word "mischief" from signage. Denied.
[2025-09-28 12:30] Weather alert: indoors. All operations unaffected.
[2025-09-28 12:35] Airlock sensors complaining about sass levels. Recalibration scheduled.
[2025-09-28 12:40] Dr. Zantares sighted waving at security cameras again. Cameras waved back.
[2025-09-28 12:45] Communications pipeline delivered 42 identical memos titled "Urgent: Nothing".
[2025-09-28 12:50] Dishwasher completed cycle. Celebrated with light show on diagnostics panel.
[2025-09-28 12:55] Inventory note: gloves sizes S, M, L restocked. XXL still on backorder from giants.
[2025-09-28 13:00] Sunlight triggered plant in lobby to perform photosynthetic jazz hands.
[2025-09-28 13:05] Reminder: label samples with actual names, not "Jeff 2.0".
[2025-09-28 13:10] Break room microwave returned. Claims it simply needed "space".
[2025-09-28 13:15] QA flagged 14 mislabeled pipette tip boxes. Culprit claims colorblindness, probably accurate.
[2025-09-28 13:20] Lab radio tuned to static. Static insists it's avant-garde.
[2025-09-28 13:25] Environmental sensors indicated humidity at 47%, sarcasm at 81%.
[2025-09-28 13:30] Discovered whiteboard equation solving for pizza topping optimization.
[2025-09-28 13:35] Ventilation vent claimed to have seen the secret project. Vent refuses further comment.
[2025-09-28 13:40] Lunch dishes cleaned. Sponge named "Bubbles" retired with honors.
[2025-09-28 13:45] Soldering iron unplugged yet warm. Possibly gossiping with 3D printer.
[2025-09-28 13:50] Mysterious humming traced to intern wearing noise cancelling headphones backwards.
[2025-09-28 13:55] Procurement accidentally ordered 200 liters of glitter. Returns process initiated with caution.
[2025-09-28 14:00] Afternoon briefing: proceed as usual, avoid glitter, hydrate frequently.
[2025-09-28 14:05] The lab's AI assistant asked for a coffee. Reminded it lacks digestive hardware.
[2025-09-28 14:10] QA discovered sticky note "Do not trust the fridge". Fridge denies allegations.
[2025-09-28 14:15] Laser lab requested dimmer lighting for dramatic effect. Approved.
[2025-09-28 14:20] Technician Hale rewired the sensor array, declared it "spicier now".
[2025-09-28 14:25] Conference room thermostat still locked at "arctic". Facilities says "tradition".
[2025-09-28 14:30] 3D printer produced unsolicited bust of the CEO. CEO flattered, suspicious.
[2025-09-28 14:35] Petri dish art exhibit scheduled for Friday. Judges bribed with coffee.
[2025-09-28 14:40] Elevator music swapped to low-fi lab beats. General approval.
[2025-09-28 14:45] Fire drill rescheduled again. Calendar now physically sighs.
[2025-09-28 14:50] Complaint filed regarding "too many reminders about reminders".
[2025-09-28 14:55] Access panel 4B stuck open. Hit it with clipboard. Fixed.
[2025-09-28 15:00] Afternoon tea service launched. Tea described as suspiciously enthusiastic.
[2025-09-28 15:05] Someone added googly eyes to the centrifuge. Management secretly approves.
[2025-09-28 15:10] Cryogenic storage asks for a book club. Suggestions pending.
[2025-09-28 15:15] Lab iPad locked out after 10,000 failed FaceID attempts. None matched.
[2025-09-28 15:20] Reminder: no kites in the clean room.
[2025-09-28 15:25] Doorbell installed on lab door. Plays theremin. Neighbours confused.
[2025-09-28 15:30] Ventilation filter clogged with glitter. See earlier memo, regret choices.
[2025-09-28 15:35] Refrigerator temperature stable. Its mood, less so.
[2025-09-28 15:40] Safety officer reported new high score on inspection bingo.
[2025-09-28 15:45] Freezer inventory includes one mystery burrito. Claimant must provide notarized testimony.
[2025-09-28 15:50] Lab plant spontaneously confessed to embezzlement. Investigator assigned.
[2025-09-28 15:55] Reminder: replace the batteries in the sarcasm detector quarterly.
[2025-09-28 16:00] Late afternoon slump mitigated with interpretive stretching.
[2025-09-28 16:05] Maintenance upgraded door locks. Password hint: "not1234".
[2025-09-28 16:10] Whiteboard diagram now includes cat doodles explaining DNA replication.
[2025-09-28 16:15] Facility drone stuck in ventilation. Drone claims it's exploring.
[2025-09-28 16:20] Intercom broadcasting motivational haikus again. Complaints minimal.
[2025-09-28 16:25] Technician Rae confiscated unauthorized desk aquarium.
[2025-09-28 16:30] Freezer door groans louder than acceptable. Request for WD-40 filed.
[2025-09-28 16:35] Cloud backup succeeded after fourth appeasement ritual.
[2025-09-28 16:40] Intern orientation video replaced with musical. Reviews mixed.
[2025-09-28 16:45] Laser alignment completed. No eyes harmed, one ego bruised.
[2025-09-28 16:50] Security camera rotated to follow lab mascot cactus. Suspicious.
[2025-09-28 16:55] Fridge magnets arranged to spell "hydrate". Staff complied.
[2025-09-28 17:00] Shift report filed. Closing note: "Everything is mostly fine probably."
[2025-09-28 17:05] After hours alert: audio sensors detect mild karaoke.
[2025-09-28 17:10] Night shift inherits glitter incident. Sent condolences.
[2025-09-28 17:15] Documentation backlog addressed. Sorting hat assigned issues to interns.
[2025-09-28 17:20] Lab door locked. Reminder to security: check on singing incubator.
[2025-09-28 17:25] Janitorial staff requested map of "no mop" zones. Provided with caution tape.
[2025-09-28 17:30] Vending machine restocked. Surprise item: caffeinated pudding.
[2025-09-28 17:35] Server room temperature trending downward. Penguins allegedly en route.
[2025-09-28 17:40] Scent of ozone traced to experimental hair dryer. Confiscated.
[2025-09-28 17:45] Break room window smudged by nose prints. Suspect: bored scientist.
[2025-09-28 17:50] Whiteboard cleaned prematurely. A moment of silence observed.
[2025-09-28 17:55] Last staff member out forgot lunchbox. Security storing in lost-and-found fridge.
[2025-09-28 18:00] Night cycle engaged. Lights dimmed. Sensors listening for trouble.
[2025-09-28 18:05] Security drone begins rounds. Immediately distracted by its own reflection.
[2025-09-28 18:10] Airflow stable, humidity cooperative, sarcasm trending downward.
[2025-09-28 18:15] Lab playlist shifted to soft synth. Sleepy microscopes reported.
[2025-09-28 18:20] Environmental alarms silent. Everyone suspicious.
[2025-09-28 18:25] Motion detected in storage bay. Turns out to be rogue Roomba.
[2025-09-28 18:30] Roomba detained. Lawyer requested.
[2025-09-28 18:35] Microwave continues insisting on cosmic vacation. Denied.
[2025-09-28 18:40] Night shift log initiated. Boldly optimistic.
[2025-09-28 18:45] Reminder pinned: "Do not experiment on sandwich again."
[2025-09-28 18:50] Fluorescent lights flickered Morse code for "clean me". Duly noted.
[2025-09-28 18:55] Calibration weights found meditating in supply drawer.
[2025-09-28 19:00] Security camera 3 found painting with light. Artistic but frowned upon.
[2025-09-28 19:05] Comms check with remote station successful. They still owe coffee.
[2025-09-28 19:10] Inventory drone recharged. Dreamt of dust bunnies.
[2025-09-28 19:15] Lab manual updated with new rule: "No musicals during sterile operations."
[2025-09-28 19:20] Observed: suspicious sparkle near reagent fridge. Verified glitter infiltration.
[2025-09-28 19:25] Night shift scientist reported "vibes are immaculate".
[2025-09-28 19:30] Air ducts whispering again. Maintenance notified, again.
[2025-09-28 19:35] Disposable booties arranged into origami cranes. Cute, impractical.
[2025-09-28 19:40] Coffee machine turned itself off citing union break.
[2025-09-28 19:45] Biohazard bins secured. Labelled with motivational quotes.
[2025-09-28 19:50] CO2 levels ideal. Nitrogen still pending motivational speech.
[2025-09-28 19:55] Technician Mira recorded lullaby for centrifuge. Centrifuge purring.
[2025-09-28 20:00] External sensors detected drizzle. Roof celebrated by staying intact.
[2025-09-28 20:05] Dose of sarcasm creeping back up. Acceptable night shift levels.
[2025-09-28 20:10] Data backups verified. Tape drive asked for more tape-themed jokes.
[2025-09-28 20:15] Laser safety poster re-laminated after coffee incident.
[2025-09-28 20:20] Access log shows zero anomalies. Unsettling calm.
[2025-09-28 20:25] Janitorial staff humming. Night shift synchronised harmonies.
[2025-09-28 20:30] Observed lab mice escaping in video game simulation only. Well done, training module.
[2025-09-28 20:35] Biological waste pickup scheduled. Reminder to label containers with actual contents.
[2025-09-28 20:40] Technician Eli reorganised reagent shelf alphabetically and emotionally.
[2025-09-28 20:45] Observation deck telescope found tracking satellites. Approved hobby.
[2025-09-28 20:50] Overheard: "If it glows, we document first, scream second."
[2025-09-28 20:55] Thermal camera recorded phantom warm spot. Probably existential dread.
[2025-09-28 21:00] Night shift snack inventory: high. morale: also high.
[2025-09-28 21:05] Glow-in-the-dark safety tape tested. It glows. Nothing else does. Good.
[2025-09-28 21:10] Decon chamber whispers "bless you" during sneezes. Documented as feature.
[2025-09-28 21:15] Filter replacement scheduled for 03:42. On purpose. For chaos.
[2025-09-28 21:20] Technician Ira taught microbe plushies the macarena. Lab cameras unimpressed.
[2025-09-28 21:25] Ventilation map updated, annotated with doodles. Acceptably professional.
[2025-09-28 21:30] Intercom reminded staff to hydrate again. Hydration compliance at 63%.
[2025-09-28 21:35] Facility lights dimmed slightly for ambience. Horror soundtrack vetoed.
[2025-09-28 21:40] Received new email: subject "Stop emailing yourselves". Actionable advice.
[2025-09-28 21:45] Sensor array recalibrated. It now detects gibberish at 96% accuracy.
[2025-09-28 21:50] Maintenance discovered missing ladder. Ladder found on roof taking in views.
[2025-09-28 21:55] Vent 2A rattled suspiciously. Gave it a stern look. Rattling stopped.
[2025-09-28 22:00] Official note: the siren labeled "Mild Panic" should remain unused.
[2025-09-28 22:05] Break room fridge defrost cycle complete. Found decade-old yogurt. Ceremonial disposal.
[2025-09-28 22:10] Technician Noor charted reagent usage using interpretive dance. Documented in text as well.
[2025-09-28 22:15] Coffee machine refused post-curfew brew. Smart machine.
[2025-09-28 22:20] Remote sensors detect mild aurora. Staff resisted howling at it.
[2025-09-28 22:25] Observed: clipboard rebellion. Rebellion swiftly negotiated down.
[2025-09-28 22:30] Night shift updated playlist to include scientific sea shanties.
[2025-09-28 22:35] Janitorial staff discovered glitter stash hidden in vent. Confiscated with tongs.
[2025-09-28 22:40] Safety signage reviewed. Added "Please don't lick the cryo tanks".
[2025-09-28 22:45] Microfiche archive consulted. Found recipe for "quantum soup". Shelved.
[2025-09-28 22:50] Observed: faint humming from server racks. Possibly lullaby from sysadmin.
[2025-09-28 22:55] Paper shredder jam resolved with patience and bribery (cookies).
[2025-09-28 23:00] Night shift morale charted at 7.5 out of 10. Measurement unit: smirks.
[2025-09-28 23:05] Technician Pax attempted to rename routers after constellations. Approved.
[2025-09-28 23:10] Tool cabinet reorganised. Tools grateful, probably.
[2025-09-28 23:15] Detected faint scent of ozone again. Investigating stray Tesla coil.
[2025-09-28 23:20] Break room lights flickered Morse code for "snacks?". Snacks provided.
[2025-09-28 23:25] Lab mascot cactus given fresh potting soil. Applauded.
[2025-09-28 23:30] Night audit of hazard signage complete. Only three signs sarcastic.
[2025-09-28 23:35] Intercom played recorded bird songs. Lab cat mildly offended.
[2025-09-28 23:40] Oxygen levels normal. Humor levels remain elevated.
[2025-09-28 23:45] Technician Quinn documented entire shift in limerick form. Stored in archive.
[2025-09-28 23:50] Midnight prep underway. Sensors calibrating themselves with smugness.
[2025-09-28 23:55] Observed: moonlight on clean room floor. Gorgeous, also in violation. Curtains drawn.
[2025-09-29 00:00] Leap day engaged. All clocks suspicious but compliant.
[2025-09-29 00:05] Night crew toasted with sparkling cider. Safety goggles fogged with joy.
[2025-09-29 00:10] Alarm false positive triggered by rolling chair. Chair cited curiosity.
[2025-09-29 00:15] Observed: intern emails scheduled for 07:00 apologising for future mistakes.
[2025-09-29 00:20] Facility cat refused to participate in leap day limbo. Respect granted.
[2025-09-29 00:25] Security drone executed celebratory spin. Logged under "flair".
[2025-09-29 00:30] Updated signage: "This lab has gone 0 days without sarcasm."
[2025-09-29 00:35] Tea kettle whistled the school's anthem. Nostalgic.
[2025-09-29 00:40] Observed: sample freezer humming lullaby. Suspect technician Mira's influence.
[2025-09-29 00:45] Laser alignment remains true. Laser smug.
[2025-09-29 00:50] Air filters replaced. Old filters awarded honorable discharge.
[2025-09-29 00:55] Data integrity check passed. Tape drive requested fan club.
[2025-09-29 01:00] Sleep-deprived jokes trending upward. Acceptable threshold not breached.
[2025-09-29 01:05] Observed: maintenance robot learning to juggle screwdrivers. Intervention scheduled.
[2025-09-29 01:10] Whiteboard filled with doodles of mitochondria lifting weights.
[2025-09-29 01:15] Incident response binder reorganised alphabetically and aromatically.
[2025-09-29 01:20] Snack supplies dwindling. Emergency pretzel ration unlocked.
[2025-09-29 01:25] Technician Leo insisted the autoclave is haunted. Autoclave responded "boo".
[2025-09-29 01:30] Ventilation system playing white noise covers of 80s hits.
[2025-09-29 01:35] Cryo chamber inspected. Found to be chilly, mysterious, cooperative.
[2025-09-29 01:40] Observed: rogue post-it travelling through ducts. Probably exploring.
[2025-09-29 01:45] Pressure gauges steady. Steam valves gossiping quietly.
[2025-09-29 01:50] Glove dispenser jammed. Encouraged gently. Resumed service.
[2025-09-29 01:55] 3D printer enters low power mode. Dreams of printing confidence.
[2025-09-29 02:00] Data analysts playing chess with lab mice plushies. Score tied.
[2025-09-29 02:05] Condensation on cryo tank spelled "sleep". Staff took cues.
[2025-09-29 02:10] Observed: administrative inbox at zero. Celebrations muted to avoid jinx.
[2025-09-29 02:15] Technician Ryn filed bug report against gravity. Ticket closed as "won't fix".
[2025-09-29 02:20] Circuit breaker panel tidy. Labelled with jokes for morale.
[2025-09-29 02:25] Fire alarm tested quietly using mime routine. Passed.
[2025-09-29 02:30] Environmental sensors logged a sigh. Probably the HVAC.
[2025-09-29 02:35] Observed: binder labelled "Secret Recipes" actually contains security policies. Smart.
[2025-09-29 02:40] Decontamination mist smelled faintly of peppermint. Approved.
[2025-09-29 02:45] Wi-Fi mesh stable. Router LED blinking in iambic pentameter.
[2025-09-29 02:50] Technician Uma practiced emergency drills while juggling pipette tips.
[2025-09-29 02:55] Lab plant growth recorded at +0.4 cm. Plant remains smug.
[2025-09-29 03:00] Night owl playlist ended. Swapped to ambient whale jazz.
[2025-09-29 03:05] Observed: internal messaging app stuck on infinite cat gifs. Admin rights invoked.
[2025-09-29 03:10] Sysadmin's coffee mug found in freezer. Left as cautionary tale.
[2025-09-29 03:15] Fielding call from remote greenhouse. They need more sarcasm filters.
[2025-09-29 03:20] Technician Sol built tiny snowman out of dry ice. Adorable. Also hazardous. Documented.
[2025-09-29 03:25] Air duct 7C echoes faintly like a sea shell. Scientists listening in turns.
[2025-09-29 03:30] Observed: scribbles of DNA wearing sunglasses. Suspect Dr. Zantares.
[2025-09-29 03:35] Hazard labels replaced with fresh adhesives. Old ones retired honorably.
[2025-09-29 03:40] Lab stools repositioned to mimic a constellation. Named "Ergonomica".
[2025-09-29 03:45] Technician Jade attempted to bribe sensors with compliments. Mixed results.
[2025-09-29 03:50] Alarm console lit up "all clear" icon. We celebrated quietly.
[2025-09-29 03:55] Observed: sample logbook reading its own entries for fun.
[2025-09-29 04:00] Pre-dawn check: all systems sarcastic but stable.
[2025-09-29 04:05] Technician Yun wrote haiku about centrifuge. Added to morale binder.
[2025-09-29 04:10] Refrigerated truck delivery ahead of schedule. Cookies inside. Why? Unknown.
[2025-09-29 04:15] Observed: nebulizer performing cloud impressions. Applauded gently.
[2025-09-29 04:20] Laser calibrations verified for sunrise experiments. Laser winks.
[2025-09-29 04:25] Hallway lights flicker spelled "good morning". Acceptable omen.
[2025-09-29 04:30] Vending machine dispensed correct change. Staff astounded.
[2025-09-29 04:35] Observed: security badge stuck to filing cabinet. Freed with butter knife.
[2025-09-29 04:40] Microwave finally accepted apology letter. Service resumed.
[2025-09-29 04:45] Pre-dawn dew forming on inside of window. Documented as "science poetry".
[2025-09-29 04:50] Technician Nia serenaded lab mice plushies. Plushies stoic.
[2025-09-29 04:55] Observed: network traffic shaped like a dolphin. Analysed, probably coincidence.
[2025-09-29 05:00] Shift handover prepping. Coffee machine stretching.
[2025-09-29 05:05] Day shift arrives, sees glitter incident summary, turns around, returns with mops.
[2025-09-29 05:10] Observed: sunrise reflecting off cryo tanks. Aesthetic level: cinematic.
[2025-09-29 05:15] Day shift reboots sarcasm detectors. Immediately ping.
[2025-09-29 05:20] Lab playlist transitions to "Upbeat but Cautious".
[2025-09-29 05:25] Observed: supply closet testily reciting inventory.
[2025-09-29 05:30] Meeting reminder triggered. Agenda: figure out agenda.
[2025-09-29 05:35] Safety goggles lined up like an army. Ready for battle.
[2025-09-29 05:40] Observed: condiments in fridge labeled with hex codes. Designer on staff?
[2025-09-29 05:45] Lab ambient scent swapped to "fresh electrons".
[2025-09-29 05:50] Documentation backlog declared manageable with enough snacks.
[2025-09-29 05:55] Observed: someone replaced exit sign with "dramatic exit". Reverted.
[2025-09-29 06:00] Morning warmup routine: calibrate, caffeinate, communicate.
[2025-09-29 06:05] Technician Zen reported dream about polite centrifuges. Logged for analysis.
[2025-09-29 06:10] Observed: sample labels now include pronouns. Inclusive and tidy.
[2025-09-29 06:15] Fire door squeaks spelled "oil me". Maintenance tasked.
[2025-09-29 06:20] End of log excerpt. Additional entries stored in archive for comedic posterity.
"""

LAB_DAILY_BRIEFING_LINES: List[str] = [
    line for line in LAB_DAILY_BRIEFING.strip().splitlines() if line.strip()
]

PYJAIL_TAGLINES = (
    "PyJail™ v0.9 — Now with 20% less functionality.",
    "Welcome to PyJail™ — where freedom goes to die.",
    "Containment Mode: enabled. Hope: disabled.",
    "PyJail™: Because interns kept finding the real servers.",
)

XSS_HINT_MARKERS = (
    "<script",
    "onerror=",
    "<img",
    "img src",
    "javascript:",
    "<svg",
    "onload=",
)


def _record_event(message: str) -> None:
    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    timestamp = _dt.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    with LOG_PATH.open("a", encoding="utf-8") as log_file:
        log_file.write(f"{timestamp} | {message}\n")


def _client_ip() -> str:
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    return request.remote_addr or "0.0.0.0"


def _require_login() -> None:
    if not session.get("logged_in"):
        _record_event(f"unauthorized access attempt from { _client_ip() } path={request.path}")
        abort(403)


def _current_user() -> Optional[Dict[str, str]]:
    username = session.get("username")
    if username:
        return AUTHORIZED_USERS.get(username)
    return None


def _vm_flag_path() -> Path:
    return (FAKE_FLAGS_DIR / "vm_flag.txt").resolve()


def _restore_vm_flag_to_default() -> None:
    global _VM_FLAG_RESET_TIMER
    vm_flag_path = _vm_flag_path()
    try:
        vm_flag_path.parent.mkdir(parents=True, exist_ok=True)
        vm_flag_path.write_text(VM_FLAG_DEFAULT_VALUE, encoding="utf-8")
        _record_event(f"vm flag auto-restore path={vm_flag_path}")
    except Exception as exc:
        _record_event(f"vm flag auto-restore failed path={vm_flag_path} error={exc}")
    finally:
        with _VM_FLAG_TIMER_LOCK:
            _VM_FLAG_RESET_TIMER = None


def _schedule_vm_flag_restore() -> None:
    def _restore():
        _restore_vm_flag_to_default()

    with _VM_FLAG_TIMER_LOCK:
        global _VM_FLAG_RESET_TIMER
        if _VM_FLAG_RESET_TIMER:
            _VM_FLAG_RESET_TIMER.cancel()
        timer = threading.Timer(VM_FLAG_RESET_DELAY, _restore)
        timer.daemon = True
        timer.start()
        _VM_FLAG_RESET_TIMER = timer
    _record_event(f"vm flag scheduled reset delay={VM_FLAG_RESET_DELAY}s")


@app.before_request
def inject_runtime_logging() -> None:
    _record_event(
        f"request method={request.method} path={request.path} "
        f"ip={_client_ip()} agent={request.headers.get('User-Agent', 'unknown')}"
    )


@app.route("/", methods=["GET"])
def index() -> str:
    user = _current_user()
    briefing_slice = random.sample(LAB_DAILY_BRIEFING_LINES, k=8) if LAB_DAILY_BRIEFING_LINES else []
    context = {
        "user": user,
        "briefing_sample": briefing_slice,
        "sarcasm_level": random.randint(19, 27),
    }
    return render_template("index.html", **context)


@app.route("/login", methods=["POST"])
def login() -> str:
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    _record_event(f"login attempt user={username or '<blank>'} ip={_client_ip()}")

    user_record = AUTHORIZED_USERS.get(username)
    if not user_record or password != user_record["password"]:
        _record_event(f"login failed user={username or '<blank>'}")
        if request.is_json or request.accept_mimetypes["application/json"] >= request.accept_mimetypes["text/html"]:
            return (
                jsonify(
                    {
                        "error": "Invalid credentials.",
                        "log": "CLI runner unsupported in GUI mode. (nice try tho)",
                    }
                ),
                401,
            )
        flash("Credentials rejected. Did you forget the safety phrase again?")
        return redirect(url_for("index"))

    session["logged_in"] = True
    session["username"] = username
    flash("You are now inside the sandbox console. Mind the glitter.")
    _record_event(f"login success user={username}")
    return redirect(url_for("index"))


@app.route("/logout", methods=["POST"])
def logout() -> str:
    user = session.get("username", "<unknown>")
    session.clear()
    flash("Session closed. Remember to sign the 'I Didn't Mutate Anything' ledger.")
    _record_event(f"logout user={user}")
    return redirect(url_for("index"))


@app.route("/run", methods=["POST"])
def run_experiment() -> str:
    _require_login()
    input_text = request.form.get("experiment_input", "")
    sanitized_preview = html.escape((input_text or "<blank>").strip())
    _record_event(f"experiment triggered by {session.get('username')} sample={sanitized_preview[:60]}")

    result = jail_sandbox.run_echo(input_text, client_ip=_client_ip())
    summary = jail_sandbox.format_result(result)
    flash(f"Experiment executed. Review output below.\n\n{summary}")
    return redirect(url_for("index"))


@app.route("/message", methods=["POST"])
def message_admin() -> str:
    note = request.form.get("admin_message", "")
    cleaned = " ".join(note.split())
    actor = session.get("username") or "<guest>"
    _record_event(
        f"admin message user={actor} ip={_client_ip()} body={cleaned[:200] or '<empty>'}"
    )
    lowered_note = note.lower()
    if any(marker in lowered_note for marker in XSS_HINT_MARKERS):
        flash("Okay, you got me. Third piece is 'velocity'.")
        _record_event(
            f"admin message flagged as suspicious payload by {actor} ip={_client_ip()}"
        )
    else:
        flash("Message queued for the admin console. Expect a response once the paperwork clears.")
    return redirect(url_for("index"))


@app.route("/teapot", methods=["GET"])
def teapot_hint() -> tuple[str, int, Dict[str, str]]:
    _record_event(f"/teapot hint ping ip={_client_ip()}")
    body = "I'm a teapot. No debug info for you. But maybe I can give you the second piece: 'hazmat'. Give a \"message\" to admin."
    headers = {"X-Hint-Level": "Medium"}
    return body, 418, headers


@app.route("/fake-flags", methods=["GET"])
def fake_flags() -> str:
    _require_login()
    flags = []
    for file_path in sorted(FAKE_FLAGS_DIR.glob("*.txt")):
        try:
            text = file_path.read_text(encoding="utf-8")
        except Exception as exc:
            _record_event(f"fake flag read error file={file_path.name} error={exc}")
            text = "<error reading file>"
        flags.append({"name": file_path.name, "content": text})

    _record_event(f"fake flags accessed by {session.get('username')} count={len(flags)}")
    return render_template("fake_flags.html", flags=flags, user=_current_user())


@app.route("/python-runner", methods=["GET"])
def python_runner() -> str:
    _require_login()
    sample_payloads = [
        "for n in range(3):\n    print('sample', n)",
        "sum([n for n in range(10)])",
        "print('lambda:', (lambda x: x * 42)(5))",
    ]
    _record_event(f"pyjail console accessed by {session.get('username')} ip={_client_ip()}")
    return render_template(
        "python_runner.html",
        user=_current_user(),
        tagline=random.choice(PYJAIL_TAGLINES),
        samples=sample_payloads,
    )


@app.route("/run-python", methods=["POST"])
def run_python() -> "Response":
    _require_login()
    payload = request.get_json(silent=True) or {}
    code = payload.get("code") or request.form.get("code") or ""
    code_str = str(code)
    _record_event(
        f"pyjail execution requested by {session.get('username')} ip={_client_ip()} chars={len(code_str)}"
    )
    result = jail_sandbox.run_in_jail(code_str)
    status = 200 if not result.get("error") else 400
    return jsonify(result), status

@app.route("/devs/")
def devs_easter_egg():
    _require_login()
    return """
    <pre>
'I was creating this directory... just for the scanners to find it. Love y'all.'
– Mehmet Semercioğlu, Creator of the Challenge
    </pre>
    """

@app.route("/devs/app")
def dev_app() -> "Response":
    _require_login()
    hidden_bin = PROJECT_ROOT / "web" / "static" / ".hidden" / "vm.c"
    if request.args.get("vm") == "1":
        if hidden_bin.exists():
            return send_file(hidden_bin, as_attachment=True)
        return "Binary staging offline. Come back after the next retro.", 404
    vm_flag_path = _vm_flag_path()
    try:
        vm_flag_path.parent.mkdir(parents=True, exist_ok=True)
        vm_flag_path.write_text(VM_FLAG_OVERRIDE_VALUE, encoding="utf-8")
        _record_event(f"/devs/app overwrite vm_flag path={vm_flag_path}")
        _schedule_vm_flag_restore()
    except Exception as exc: 
        _record_event(f"/devs/app failed vm_flag overwrite path={vm_flag_path} error={exc}")
    return """
    <pre>
You might wanna check where the fake-flags are stored.
    </pre>
    """


@app.route("/python_exec_legacy")
def old_runner() -> str:
    return "legacy runner removed. totally. probably. 🧍"


@app.errorhandler(403)
def forbidden(error):
    return (
        render_template(
            "index.html",
            user=None,
            briefing_sample=LAB_DAILY_BRIEFING_LINES[:5],
            sarcasm_level=21,
            error_message="Access denied: please authenticate before poking the sandbox.",
        ),
        403,
    )


@app.errorhandler(404)
def not_found(e):
    if any(x in request.path for x in ["run", "py", "exec", "legacy"]):
        return (
            render_template("404.html", hint="Still poking around old runners? Nostalgia hits hard."),
            404,
        )
    return render_template("404.html"), 404


@app.errorhandler(500)
def internal_error(error):
    _record_event(f"internal server error: {error}")
    return (
        render_template(
            "index.html",
            user=_current_user(),
            briefing_sample=LAB_DAILY_BRIEFING_LINES[:6],
            sarcasm_level=26,
            error_message="Something unexpectedly flambéed. The team has been notified.",
        ),
        500,
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
