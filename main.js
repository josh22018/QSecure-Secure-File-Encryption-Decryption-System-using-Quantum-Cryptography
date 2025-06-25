console.log("main.js loaded");

document.addEventListener('DOMContentLoaded', () => {
  //
  // 1) Toggle parameter blocks in Encrypt/Decrypt forms
  //
  ['enc-algo','dec-algo'].forEach(selectId => {
    const sel = document.getElementById(selectId);
    const paramsContainer = document.getElementById(
      selectId.replace('algo','params')
    );
    if (!sel || !paramsContainer) {
      console.warn(`Missing ${selectId} or its params container.`);
      return;
    }
    const groups = paramsContainer.querySelectorAll('.params-group');
    function toggleParams() {
      groups.forEach(div => {
        div.style.display = (div.dataset.algo === sel.value) ? 'block' : 'none';
      });
    }
    // initial
    toggleParams();
    // on change
    sel.addEventListener('change', toggleParams);
  });

  //
  // 2) Chart helper
  //
  function drawBar(ctx, vals) {
    if (!ctx) {
      console.error("drawBar: no canvas context");
      return null;
    }
    return new Chart(ctx, {
      type: 'bar',
      data: {
        labels: ['Classical','Quantum'],
        datasets: [{
          data: vals,
          backgroundColor: [
            'rgba(59,130,246,0.7)',
            'rgba(16,185,129,0.7)'
          ],
          borderColor: [
            'rgb(59,130,246)',
            'rgb(16,185,129)'
          ],
          borderWidth: 1
        }]
      },
      options: {
        scales: { y:{ beginAtZero:true } },
        plugins: { legend:{ display:false } },
        responsive:true,
        maintainAspectRatio:false
      }
    });
  }

  //
  // 3) File-Based Simulation
  //
  const fN   = document.getElementById('file-N');
  const fT   = document.getElementById('file-target');
  const fCtx = document.getElementById('file-chart')?.getContext('2d');
  let fileChart = null;

  async function runFileSim() {
    if (!fN || !fCtx) {
      console.warn("File sim elements missing");
      return;
    }
    try {
      const N      = +fN.value;
      const target = +fT.value;
      console.log("File sim, N=",N,"target=",target);

      const [cRes,qRes] = await Promise.all([
        fetch('/simulate_classical', {
          method:'POST',
          headers:{'Content-Type':'application/json'},
          body: JSON.stringify({N,target})
        }).then(r=>r.json()),
        fetch('/simulate_grover', {
          method:'POST',
          headers:{'Content-Type':'application/json'},
          body: JSON.stringify({N})
        }).then(r=>r.json())
      ]);

      console.log("File sim results:", cRes, qRes);

      document.getElementById('file-result-classical').textContent =
        `Classical steps: ${cRes.count}`;
      document.getElementById('file-result-grover').textContent =
        `Quantum iterations: ${qRes.iterations}`;

      fileChart?.destroy();
      fileChart = drawBar(fCtx, [cRes.count, qRes.iterations]);
    } catch (err) {
      console.error("Error in runFileSim:", err);
    }
  }
  runFileSim();

  //
  // 4) Manual Simulation
  //
  const mSize   = document.getElementById('manual-size');
  const mTarget = document.getElementById('manual-target');
  const mBtn    = document.getElementById('btn-manual-compare');
  const mCtx    = document.getElementById('manual-chart')?.getContext('2d');
  let manualChart = null;

  async function runManualSim() {
    if (!mSize || !mCtx) {
      console.warn("Manual sim elements missing");
      return;
    }
    try {
      const N      = Math.max(1, +mSize.value);
      const target = Math.min(N-1, Math.max(0, +mTarget.value));
      console.log("Manual sim, N=",N,"target=",target);

      const [cRes,qRes] = await Promise.all([
        fetch('/simulate_classical', {
          method:'POST',
          headers:{'Content-Type':'application/json'},
          body: JSON.stringify({N,target})
        }).then(r=>r.json()),
        fetch('/simulate_grover', {
          method:'POST',
          headers:{'Content-Type':'application/json'},
          body: JSON.stringify({N})
        }).then(r=>r.json())
      ]);

      console.log("Manual sim results:", cRes, qRes);

      document.getElementById('manual-result-classical').textContent =
        `Classical steps: ${cRes.count}`;
      document.getElementById('manual-result-grover').textContent =
        `Quantum iterations: ${qRes.iterations}`;

      manualChart?.destroy();
      manualChart = drawBar(mCtx, [cRes.count, qRes.iterations]);
    } catch (err) {
      console.error("Error in runManualSim:", err);
    }
  }
  if (mBtn) {
    mBtn.addEventListener('click', runManualSim);
    runManualSim();
  }
});
