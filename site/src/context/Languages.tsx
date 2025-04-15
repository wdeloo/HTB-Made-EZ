import { createContext, useState, ReactNode } from 'react'
import { languages } from '../components/languages/Languages'

type Language = keyof typeof languages

type LanguageContextProps = [
    Language,
    (language: Language) => void
]

export const LanguageContext = createContext<LanguageContextProps>(["en", () => {}])

export default function LanguageProvider({ children }: { children: ReactNode }) {
    const [language, setLanguage] = useState<Language>('en')

    return (
        <LanguageContext.Provider value={[ language, setLanguage ]}>
            {children}
        </LanguageContext.Provider>
    )
}