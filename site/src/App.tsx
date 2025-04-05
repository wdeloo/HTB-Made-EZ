import './App.css'
import Machines from './components/machines/Machines'
import Nav from './components/Nav'
import SearchBar from './components/search/SearchBar'

function App() {
  return (
    <>
      <header className='sticky top-0 z-[1000]'>
        <Nav />
      </header>

      <main className='flex flex-col gap-16 py-4'>
        <SearchBar />
        <Machines />
      </main>

      <footer>

      </footer>
    </>
  )
}

export default App
