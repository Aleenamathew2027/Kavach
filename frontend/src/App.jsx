import { useState } from "react";
import "./App.css";

function App() {
  const [page, setPage] = useState("home");

  if (page === "login") {
    return (
      <div className="auth-page">
        <div className="auth-card">
          <h1>KAVACH</h1>
          <h2>Welcome Back</h2>
          <p>Login to your Kavach account</p>

          <input type="email" placeholder="Email" />
          <input type="password" placeholder="Password" />

          <button>Login</button>

          <p>
            Don't have an account?{" "}
            <span onClick={() => setPage("register")}>
              Register
            </span>
          </p>

          <button
            className="back-button"
            onClick={() => setPage("home")}
          >
            Back to Home
          </button>
        </div>
      </div>
    );
  }

  if (page === "register") {
    return (
      <div className="auth-page">
        <div className="auth-card">
          <h1>KAVACH</h1>
          <h2>Create Account</h2>
          <p>Join Kavach and stay protected</p>

          <input type="text" placeholder="Full Name" />
          <input type="email" placeholder="Email" />
          <input type="password" placeholder="Password" />
          <input type="password" placeholder="Confirm Password" />

          <button>Register</button>

          <p>
            Already have an account?{" "}
            <span onClick={() => setPage("login")}>
              Login
            </span>
          </p>

          <button
            className="back-button"
            onClick={() => setPage("home")}
          >
            Back to Home
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="landing-page">
      <nav>
        <div className="logo">KAVACH</div>

        <div className="nav-buttons">
          <button
            className="login-btn"
            onClick={() => setPage("login")}
          >
            Login
          </button>

          <button
            onClick={() => setPage("register")}
          >
            Register
          </button>
        </div>
      </nav>

      <main className="hero">
        <div className="hero-text">
          <p className="tag">AI-POWERED DIGITAL SECURITY</p>

          <h1>
            Your Digital World.
            <br />
            <span>Protected by Kavach.</span>
          </h1>

          <p className="description">
            Kavach is an AI-powered security guardian designed
            to protect you from digital scams, phishing,
            deepfake voices, suspicious messages and fraudulent
            activities.
          </p>

          <div className="hero-buttons">
            <button onClick={() => setPage("register")}>
              Get Started
            </button>

            <button
              className="outline-btn"
              onClick={() => setPage("login")}
            >
              Login
            </button>
          </div>
        </div>

        <div className="shield">
          🛡️
        </div>
      </main>

      <section className="features">
        <div>
          <h3>🎙️ Voice Protection</h3>
          <p>Detect suspicious and AI-generated voice interactions.</p>
        </div>

        <div>
          <h3>💬 Message Security</h3>
          <p>Identify phishing and suspicious messages.</p>
        </div>

        <div>
          <h3>💳 Payment Protection</h3>
          <p>Analyze risky payment requests before you act.</p>
        </div>

        <div>
          <h3>📄 Document Security</h3>
          <p>Detect suspicious documents and fraudulent content.</p>
        </div>
      </section>
    </div>
  );
}

export default App;