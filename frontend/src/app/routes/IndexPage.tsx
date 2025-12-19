// frontend/src/app/routes/IndexPage.tsx

export default function IndexPage() {
  return (
    <main className="page">
      <header className="topbar">
        <div className="topbarGroup">
          <button className="btn">日本語</button>
          <button className="btn">English</button>
        </div>
        <div className="topbarGroup">
          <button className="btn">Light</button>
          <button className="btn">Dark</button>
        </div>
      </header>

      <section className="indexGrid">
        <aside className="panel">
          <div className="panelTitle">whoami</div>
          <ul className="list">
            <li>
              <a href="/whoami">YouTube（仮）</a>
            </li>
            <li>
              <a href="/whoami">X（仮）</a>
            </li>
          </ul>

          <hr className="hr" />

          <div className="hint">
            開発用:
            <div className="hintRow">
              <code>?pow=force</code> 強制PoW
            </div>
            <div className="hintRow">
              <code>?pow=reset</code> セッション削除
            </div>
          </div>
        </aside>

        <section className="panel centerPanel">
          <div className="logoBox">
            <div className="logoText">LOGO（仮）</div>
            <div className="subText">Index Page</div>
          </div>
        </section>

        <aside className="panel">
          <div className="panelTitle">Sign in（仮）</div>
          <div className="form">
            <input className="input" placeholder="username or email" />
            <input className="input" placeholder="password" type="password" />
            <button className="btn primary">Sign in</button>
            <a href="/forgot">パスワードを忘れた場合（仮）</a>
            <a href="/signup">サインアップ（仮）</a>
            <a href="/feed.atom">.atom（仮）</a>
          </div>
        </aside>
      </section>
    </main>
  );
}
