const RATES = [10, 50, 200, 1000];

export default function Controls({ replay, onChange, onReset }) {
  return (
    <div className="controls">
      <button
        className={replay.running ? "btn danger" : "btn primary"}
        onClick={() => onChange({ running: !replay.running })}
      >
        {replay.running ? "Stop replay" : "Start replay"}
      </button>

      <label className="rate">
        <span>Flows / s</span>
        <select
          value={replay.rate}
          onChange={(e) => onChange({ rate: Number(e.target.value) })}
        >
          {[...new Set([...RATES, replay.rate])]
            .sort((a, b) => a - b)
            .map((rate) => (
              <option key={rate} value={rate}>
                {rate}
              </option>
            ))}
        </select>
      </label>

      <button className="btn" onClick={onReset}>
        Reset
      </button>
    </div>
  );
}
