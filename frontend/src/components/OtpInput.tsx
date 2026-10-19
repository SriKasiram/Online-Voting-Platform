import { Fragment, useState, type Ref, type SyntheticEvent } from "react";

type Props = {
  id: string;
  value: string;
  onChange: (value: string) => void;
  describedBy?: string;
  inputRef?: Ref<HTMLInputElement>;
};

const SLOTS = [0, 1, 2, 3, 4, 5];

/**
 * One real text input drawn as six boxes. Keeping a single input means paste,
 * authenticator autofill and screen readers all work as they do on a plain field.
 */
export default function OtpInput({ id, value, onChange, describedBy, inputRef }: Props) {
  const [focused, setFocused] = useState(false);
  const active = Math.min(value.length, SLOTS.length - 1);

  function keepCaretAtEnd(event: SyntheticEvent<HTMLInputElement>) {
    const input = event.currentTarget;
    const end = input.value.length;
    input.setSelectionRange(end, end);
  }

  return (
    <div className="otp">
      {SLOTS.map((i) => {
        const classes = ["otp-slot"];
        if (value[i]) classes.push("is-filled");
        if (focused && i === active) classes.push("is-active");
        return (
          <Fragment key={i}>
            {i === 3 && <span className="otp-sep" aria-hidden="true" />}
            <span className={classes.join(" ")} aria-hidden="true">
              {value[i] ?? ""}
            </span>
          </Fragment>
        );
      })}
      <input
        ref={inputRef}
        id={id}
        className="otp-input"
        type="text"
        inputMode="numeric"
        autoComplete="one-time-code"
        value={value}
        onChange={(e) => onChange(e.target.value.replace(/\D/g, "").slice(0, 6))}
        onFocus={(e) => {
          setFocused(true);
          keepCaretAtEnd(e);
        }}
        onBlur={() => setFocused(false)}
        onClick={keepCaretAtEnd}
        onKeyUp={keepCaretAtEnd}
        aria-describedby={describedBy}
      />
    </div>
  );
}
