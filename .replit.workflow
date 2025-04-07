<workflow>
<name>
Start application
</name>
<command>
gunicorn --bind 0.0.0.0:5000 --reuse-port --reload main:app
</command>
</workflow>
<workflow>
<name>
phishing_detector
</name>
<command>
python phishing_detector.py https://google.com -v
</command>
</workflow>
<workflow>
<name>
SpeeDefender Port 5001
</name>
<command>
python standalone_server.py
</command>
</workflow>