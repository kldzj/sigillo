// Page-width hero with an ASCII VideoBackgroundShader, serif title, and two
// CTAs: self-hosting and the GitHub repo. The shader follows the cursor on
// its own container, underneath the text, so the text lets the cursor through
// and only the buttons take it.
'use client'

import { useEffect, useState } from 'react'
import { Server } from 'lucide-react'
import { VideoBackgroundShader } from '@holocron.so/vite/mdx'
import { buttonVariants } from './ui/button.tsx'

const HERO_FONT = "'IvarText', serif"
const GITHUB_URL = 'https://github.com/kldzj/sigillo'

export function HeroSection() {
  const [fontsReady, setFontsReady] = useState(false)

  useEffect(() => {
    const timeout = setTimeout(() => setFontsReady(true), 3000)
    void document.fonts.ready.then(() => setFontsReady(true))
    return () => clearTimeout(timeout)
  }, [])

  return (
    <div className='relative mt-4 lg:mt-8 mb-6 lg:mb-10 w-full rounded-xl flex flex-col items-center overflow-hidden'>
      <VideoBackgroundShader
        src='/assets/hero-bg.mp4'
        className='absolute inset-0 w-full h-full'
        canvasClassName='dark:opacity-60 opacity-40'
        dotStyle='ascii'
        dotColor='#6ec9a0'
        dotSize={9}
        minDotSize={1}
        dotMargin={1}
        animSpeed={3}
        gamma={0.8}
        enableMask={false}
        fluidStrength={0.2}
        fluidCurl={80}
      />

      <div
        className='relative z-[2] flex flex-col items-center justify-center text-center max-w-[820px] w-full px-5 pt-16 sm:pt-24 pb-20 lg:pb-[160px] gap-6 pointer-events-none'
        style={{
          opacity: fontsReady ? 1 : 0,
          transition: 'opacity 0.3s cubic-bezier(0.23, 1, 0.32, 1)',
        }}
      >
        <h1
          className='flex flex-col items-center leading-none text-[36px] sm:text-[44px] md:text-[52px] text-foreground'
          style={{ fontFamily: HERO_FONT }}
        >
          <span>Secrets manager,</span>
          <span>open source Doppler alternative</span>
        </h1>

        <div className='flex gap-3 flex-wrap justify-center pointer-events-auto'>
          <a href='/docs/self-hosting' className={buttonVariants({ size: 'lg', className: 'no-underline gap-2.5' })}>
            <Server className='size-[16px]' />
            Self-host Sigillo
          </a>
          <a
            href={GITHUB_URL}
            target='_blank'
            rel='noopener noreferrer'
            className={buttonVariants({ variant: 'ghost', size: 'lg', className: 'no-underline' })}
          >
            GitHub Repo ↗
          </a>
        </div>
      </div>
    </div>
  )
}
