package se.bes.br;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.util.ArrayList;

public class Breaker {
    private final char[] mPossibles;

    private static final Object PASS_LOCK = new Object();
    private volatile boolean mIsFound = false;
    private volatile long mCounter = 0;
    private char[] mFoundPassword = new char[0];

    private final PasswordGenerator mGenerator;
    private final PasswordTester[] mTesters;

    private volatile char[] globalPass = new char[0];

    private final Shutdown mShutdown = new Shutdown();

    /**
     * Will run when interrupting the program (Ctrl+C).
     * This allows us to print a newline before terminating.
     */
    private static class Shutdown extends Thread {
        private boolean keepOn = true;
        @Override
        public void run() {
            // Just print a newline to save the last line.
            System.out.println();
            keepOn = false;
        }

        public boolean keepOn() {
            return keepOn;
        }
    }

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
        mGenerator = new PasswordGenerator(startDepth - 1);
        mGenerator.setPriority(Thread.NORM_PRIORITY+1);

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
        System.out.println("Characters to test: " + possibleList.size());
        for (int i = 0; i < possibleList.size(); i++) {
            mPossibles[i] = possibleList.get(i).charValue();
            System.out.print(mPossibles[i]);
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
    public String getPassphrase() throws InterruptedException {
        Runtime.getRuntime().addShutdownHook(mShutdown);
        System.out.println();
        long totalStartTime = System.currentTimeMillis();

        while (!mIsFound && mShutdown.keepOn()) {
            long startTime = System.currentTimeMillis();
            long startCount = mCounter;
            try {
                Thread.sleep(500);
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
            long diffTime = System.currentTimeMillis() - startTime;
            long diffCount = mCounter - startCount;

            long rate = 0;
            if (diffTime > 0) {
                rate = diffCount * 1000 / diffTime;
            }

            long totalTime = (System.currentTimeMillis() - totalStartTime) / 1000;

            System.out.print("Tested " + mCounter
                    + " pws (" + totalTime + " s -- " + rate + " pw/s avg: "
                    + (totalTime > 0 ? (mCounter / totalTime) : 0)
                    + "): "
                    + new String(globalPass) + "       \r");
        }

        return new String(mFoundPassword);
    }

    private class PasswordTester extends Thread {
        /**
         * The bytes of a {@link KeyStore} loaded into RAM.
         */
        private ByteArrayInputStream mStream;
        private int dataLength;

        /**
         * Loads a {@link KeyStore} on file into a {@link ByteArrayInputStream}
         * for faster access.
         */
        public PasswordTester(String fileName) {
            try {
                File file = new File(fileName);

                FileInputStream fis = new FileInputStream(file);

                byte[] fileBytes = new byte[(int)file.length()];
                
                dataLength = fileBytes.length;

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
            PasswordChecker pc = new PasswordChecker();
            pc.bytes = new byte[dataLength - PasswordChecker.HASH_LENGTH];
            char[] passwd = null;
            while(!mIsFound) {
                //System.out.println("Next pw");
                mStream.reset();
                try {
                    passwd = mGenerator.getNextPassword();
                    if (!pc.passwordMatches(mStream, dataLength, passwd))
                        continue;
                } catch (Throwable t) {
                    continue;
                }
                mFoundPassword = passwd;
                mIsFound = true;
            }
        }
    }

    private class PasswordGenerator extends Thread {
        private int mDepth;
        int[] counts = null;
        boolean lastIteration = true;

        public PasswordGenerator(int depth) {
            this.mDepth = depth;
        }

        /**
         * Used by the password testing threads to pop a password from the
         * head of the list.
         */
        public char[] getNextPassword() {
            int[] localCounts = null;
            synchronized (PASS_LOCK) {
                if (lastIteration) {
                    mDepth++;
                    counts = new int[mDepth];
                    counts[0] = -1; // Make sure first iteration starts at correct character
                    System.out.println();
                    System.out.println("Starting search for depth: " + mDepth);
                }
                lastIteration = getIterationChars(counts);
                localCounts = counts.clone();
            }
            char[] passwd = countsToChars(localCounts);
            mCounter++;

            if (mCounter % 100000 == 0) {
                globalPass = passwd;
            }
            return passwd;
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
        private boolean getIterationChars(int[] counts) {
            int idx = 0;
            counts[idx]++;
            while (idx < counts.length && counts[idx] >= mPossibles.length) {
                counts[idx] = 0;
                idx++;
                if (idx < counts.length) {
                    counts[idx]++;
                }
            }
            return counts[counts.length - 1] == mPossibles.length-1;
        }

        private char[] countsToChars(int[] counts) {
            char[] out = new char[counts.length];
            for (int i = 0; i < counts.length; i++) {
                out[counts.length-1-i] = mPossibles[counts[i]];
            }
            return out;
        }
    }
}
