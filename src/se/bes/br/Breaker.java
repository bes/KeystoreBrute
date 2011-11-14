package se.bes.br;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.util.ArrayList;
import java.util.LinkedList;

public class Breaker {
    private final char[] mPossibles;

    private static final Object PASS_LOCK = new Object();
    private volatile boolean mIsFound = false;
    private volatile long mCounter = 0;
    private char[] mFoundPassword = null;
    private final int mStartDepth;

    private final PasswordGenerator mGenerator;
    private final PasswordTester[] mTesters;

    /**
     * Sets up and initiates all the threads needed to break the given keystore.
     * 
     * @param fileName
     *            The path and filename of the {@link KeyStore} you wish to
     *            break.
     * @param startDepth
     *            The number of characters to start trying at. A keystore
     *            requires 6 characters so that is probably a minimum, but any
     *            value is acceptable.
     * @param threads
     *            The number of {@link Thread}s you wish to have simultaneously
     *            running, breaking passwords. Experiment to find the optimal
     *            value for your setup.
     */
    public Breaker(String fileName, int startDepth, int threads) {
        mGenerator = new PasswordGenerator(threads * 2000);
        mGenerator.setPriority(Thread.NORM_PRIORITY+1);
        mStartDepth = startDepth;

        // Create list of possible characters
        // If needed, add or remove characters here
        ArrayList<Character> possibleList = new ArrayList<Character>();

        for (char c = 'a'; c <= 'z'; c++) {
            possibleList.add(c);
        }
        for (char c = 'A'; c <= 'Z'; c++) {
            possibleList.add(c);
        }
        for (char c = '0'; c <= '9'; c++) {
            possibleList.add(c);
        }
        possibleList.add('!');
        possibleList.add('_');
        possibleList.add('@');

        mPossibles = new char[possibleList.size()];
        System.out.println("Possibles: " + possibleList.size());
        for (int i = 0; i < possibleList.size(); i++) {
            mPossibles[i] = possibleList.get(i).charValue();
            System.out.println(mPossibles[i]);
        }

        mGenerator.start();

        mTesters = new PasswordTester[threads];
        for (int i = 0; i < mTesters.length; i++) {
            mTesters[i] = new PasswordTester(fileName);
            mTesters[i].start();
        }
    }

    /**
     * This method will block until the {@link KeyStore} password is
     * found, at which point it will return the password as a {@link String}.
     * <br/>
     * May take a <b>VERY</b> long time.
     * @return A {@link String} with the password used to open the given {@link KeyStore}
     */
    public String getPassphrase() {
        long startTime = System.currentTimeMillis();
        System.out.println();

        while (!mIsFound) {
            try {
                Thread.sleep(500);
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
            long time = (System.currentTimeMillis() - startTime)/1000;
            long rate = 0;
            if (time > 0) {
                rate = mCounter / time;
            }

            System.out.print("Itr " 
                    + mCounter 
                    + " (" + time + " s -- " + rate + " pw/s): " 
                    + mGenerator.peekPassword() + "       \r");
        }

        return new String(mFoundPassword);
    }

    private class PasswordTester extends Thread {
        /**
         * The bytes of a {@link KeyStore} loaded into RAM.
         */
        private ByteArrayInputStream mStream;

        /**
         * Loads a {@link KeyStore} on file into a {@link ByteArrayInputStream}
         * for faster access.
         */
        public PasswordTester(String fileName) {
            try {
                File file = new File(fileName);

                FileInputStream fis = new FileInputStream(file);

                byte[] fileBytes = new byte[(int)file.length()];

                fis.read(fileBytes);

                mStream = new ByteArrayInputStream(fileBytes);
            } catch (Exception e) {
                e.printStackTrace();
            }
        }

        /**
         * Gets a password from the list of passwords and tests if it
         * can be used to open the {@link KeyStore}.
         */
        @Override
        public void run() {
            KeyStore ks = null;
            try {
                ks = KeyStore.getInstance(KeyStore.getDefaultType());
            } catch (KeyStoreException e) {
                e.printStackTrace();
            }
            char[] passwd = null;
            while(!mIsFound) {
                //System.out.println("Next pw");
                mStream.reset();
                try {
                    passwd = mGenerator.getNextPassword().passwd;
                    ks.load(mStream, passwd);
                } catch (Throwable t) {
                    continue;
                }
                mFoundPassword = passwd;
                mIsFound = true;
            }
        }
    }

    /**
     * Data structure for holding a generated password.
     */
    private class Password {
        private char[] passwd;
        public Password(char[] chars) {
            passwd = chars.clone();
        }
    }

    private class PasswordGenerator extends Thread {
        private LinkedList<Password> mPasswords = new LinkedList<Password>();
        private static final long MAX_QUEUE_WAIT = 1;
        private static final String WARNING = "Warning: Queue empty! (You might want to trim mMaxNoPasswords or MAX_QUEUE_WAIT)";
        private final int mMaxNoPasswords;
        
        public PasswordGenerator(int maxNoPasswords) {
            mMaxNoPasswords = maxNoPasswords;
        }
        
        /**
         * Tries to maintain a list of {@link #mMaxNoPasswords} passwords.
         */
        @Override
        public void run() {
            int depth = mStartDepth - 1;
            int[] counts = null;
            char[] passwd = null;
            boolean lastIteration = true;
            while(!mIsFound) {
                if (lastIteration) {
                    depth++;
                    counts = new int[depth];
                    counts[0] = -1; // Make sure first iteration starts at correct character
                    passwd = new char[depth];
                    System.out.println();
                    System.out.println("Starting search for depth: " + depth);
                }
                lastIteration = getIterationChars(counts, passwd);
                
                synchronized (PASS_LOCK) {
                    mPasswords.add(new Password(passwd));
                    PASS_LOCK.notifyAll();

                    while (mPasswords.size() >= mMaxNoPasswords && !mIsFound) {
                        try {
                            PASS_LOCK.wait(MAX_QUEUE_WAIT);
                        } catch (InterruptedException e) {
                            e.printStackTrace();
                        }
                    }
                }
            }
        }

        /**
         * Used by the password testing threads to pop a password from the 
         * head of the list.
         */
        public Password getNextPassword() {
            synchronized (PASS_LOCK) {
                while (mPasswords.size() == 0 && !mIsFound) {
                    System.out.println(WARNING);
                    try {
                        PASS_LOCK.wait();
                    } catch (InterruptedException e) {
                        e.printStackTrace();
                    }
                }
                Password p = mPasswords.removeFirst();
                mCounter++;
                return p;
            }
        }

        /**
         * Takes a peek at the current head of the list of generated passwords,
         * used for printing the current state to screen.  
         */
        public String peekPassword() {
            synchronized (PASS_LOCK) {
                while (mPasswords.size() == 0 && !mIsFound) {
                    System.out.println(WARNING);
                    try {
                        PASS_LOCK.wait();
                    } catch (InterruptedException e) {
                        e.printStackTrace();
                    }
                }
                return new String(mPasswords.getFirst().passwd);
            }
        }

        /**
         * Takes the state of counts, reverses it and puts it into out.
         * 
         * If it were not reversed, passwords would be generated head-first,
         * now they are generated tail-first. Decide which way YOU want to go =)
         * 
         * @param counts The state as related to {@link Breaker#mPossibles}
         * @param out The translated character from counts will be placed here.
         */
        private boolean getIterationChars(int[] counts, char[] out) {
            int idx = 0;
            counts[idx]++;
            boolean lastIteration = true;
            while (idx < counts.length && counts[idx] >= mPossibles.length) {
                counts[idx] = 0;
                idx++;
                if (idx < counts.length) {
                    counts[idx]++;
                }
            }
            for (int i = 0; i < counts.length; i++) {
                out[counts.length-1-i] = mPossibles[counts[i]];
                lastIteration = lastIteration && counts[i] == mPossibles.length-1;
            }

            return lastIteration;
        }
    }
}
