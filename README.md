A JWKS server that gives public keys with a key ID for verifying JWTs. Has auth and JWKS endpoints and implements key expiry.

Image of program results with test client
<img width="960" height="855" alt="test_client_results" src="https://github.com/user-attachments/assets/5434d66b-839e-4404-a264-f49cf987926d" />



Image of program results with test suite file "test.py"
<img width="847" height="688" alt="image" src="https://github.com/user-attachments/assets/9df8d5a2-ff6f-4237-8baf-f7c7f86e875e" />

NOTE: AI chatbots was used in making this program, the below prompts were used in Copilot:
"How to make sure JWKS endpoint is only serving unexpired keys" - to verify endpoint is functioning correctly
"How to make sure a JWT's kid is found in the JWKS" - to verify
"Make a test suite for this program" - used as a basis for the test.py test suite

