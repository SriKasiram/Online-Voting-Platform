"""Request and response bodies for the API."""

from pydantic import BaseModel, ConfigDict, Field


class DivisionOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str


class LoginIn(BaseModel):
    username: str = Field(max_length=200)
    password: str = Field(max_length=200)


class VerifyIn(BaseModel):
    otp_code: str = Field(pattern=r"^\d{6}$")


class VerifyOut(BaseModel):
    display_name: str


class CandidateOut(BaseModel):
    id: int
    given_name: str
    surname: str
    party: str


class BallotOut(BaseModel):
    ballot_token: str
    election_name: str
    division_name: str
    state_name: str
    candidates: list[CandidateOut]


class SubmitIn(BaseModel):
    ballot_token: str = Field(max_length=200)
    # Candidate ids from first preference to last
    ranked_candidate_ids: list[int] = Field(max_length=100)


class SubmitOut(BaseModel):
    receipt_id: str


class RegisterVerifyIn(BaseModel):
    given_name: str = Field(max_length=100)
    surname: str = Field(max_length=100)
    # YYYY-MM-DD. Checked by the server like every other field, never rejected on its own.
    date_of_birth: str = Field(max_length=20)
    postcode: str = Field(max_length=10)
    enrolment_code: str = Field(max_length=40)


class RegisterAccountIn(BaseModel):
    username: str = Field(max_length=100)
    password: str = Field(max_length=200)


class RegisterAccountOut(BaseModel):
    otpauth_uri: str
    # The same secret as text, for typing into the app instead of scanning
    secret: str


class RegisterConfirmIn(BaseModel):
    otp_code: str = Field(pattern=r"^\d{6}$")
