package com.hierynomus.smbj.client

import com.hierynomus.msdtyp.AccessMask
import com.hierynomus.smbj.DefaultConfig
import com.hierynomus.smbj.ProgressListener
import com.hierynomus.smbj.SMBClient
import com.hierynomus.smbj.auth.AuthenticationContext
import com.hierynomus.smbj.share.DiskShare
import com.hierynomus.smbj.share.File
import com.hierynomus.mssmb2.SMB2CreateDisposition
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.slf4j.Logger
import org.slf4j.LoggerFactory

import java.security.Security

class SmbjClient {
    static final Logger logger = LoggerFactory.getLogger(SmbjClient.class)

    static void main(String[] args) {
        Security.addProvider(new BouncyCastleProvider())
        CliBuilder cli = new CliBuilder()
        cli.usage = "usage: smb-client [options] [smb|file]:<source> [smb|file]:<dest>"
        cli.h(longOpt: 'host', required: true, args:1, argName: 'host', 'The hostname or IP address of the SMB host to connect to')
        cli.u(longOpt: 'user', required: true, args:1, argName:'username', 'The username used to connect to the SMB host')
        cli.p(longOpt: 'password', args: 1, argName: 'password', 'The password used to connect to the SMB host')
        cli.d(longOpt: 'domain', args: 1, argName: 'domain', 'The Windows domain to use to connect to the SMB host')
        cli.s(longOpt: 'share', args: 1, required: true, argName: 'share', 'The Windows Share to connect to')
        cli._(longOpt: 'help', 'Print this help message')
        def parse = cli.parse(args)
        if (!parse || parse.help) {
            cli.usage()
            return
        }

        String source = null
        String dest = null
        if (!parse.arguments() || parse.arguments().size() != 2) {
            cli.usage()
            return
        } else {
            source = parse.arguments()[0]
            dest = parse.arguments()[1]
            if (!((source.startsWith("smb:") && dest.startsWith("file:")) || (source.startsWith("file:") && dest.startsWith("smb:")))) {
                println("Source and Dest should start with 'smb:' and/or 'file:'")
                return
            }
        }

        char[] password = null
        if (!parse.p) {
            password = System.console().readPassword("Password > ")
        } else {
            password = (parse.p as String).toCharArray()
        }

        String domain = null
        if (parse.d) {
            domain = parse.d
        }


        logger.info("Connecting to ${parse.h} as ${parse.u}")
        def connection = connectTo(parse.h as String)
        try {
            def session = connection.authenticate(new AuthenticationContext(parse.u as String, password, domain))
            try {
                DiskShare share = session.connectShare(parse.s as String)
                try {
                    def list = share.list("")
                    println list.collect { it.fileName }
                    copy(source, dest, share)
                } finally {
                    share.close()
                }
            } finally {
                session.close()
            }
        } finally {
            connection.close()
        }
    }

    static void copy(String source, String dest, DiskShare diskShare) {
        if (source.startsWith("file:")) {
            copyToSmb(source, dest, diskShare)
        } else {
            copyFromSmb(source, dest, diskShare)
        }
    }

    static void copyToSmb(String source, String dest, DiskShare diskShare) {
        def localPath = source.substring(5)
        assert new java.io.File(localPath).exists(), "Local path $localPath should exist"
        def smbPath = dest.substring(4)
        def disposition = SMB2CreateDisposition.FILE_CREATE
        if (diskShare.fileExists(smbPath)) {
            logger.info("Overwriting remote file $smbPath")
            disposition = SMB2CreateDisposition.FILE_OVERWRITE
        }
        def smbFile = diskShare.openFile(smbPath, EnumSet.of(AccessMask.GENERIC_WRITE), disposition)
        long totalBytes = 0
        def startMillis = System.currentTimeMillis()
        logger.info(">>> Start copying $source to $dest")
        smbFile.write(new BufferedInputStream(new FileInputStream(localPath)), new ProgressListener() {
            @Override
            void onProgressChanged(long b, long tb) {
                totalBytes = b
                logger.debug("Written $totalBytes bytes of $tb total")
            }
        })
        def endMillis = System.currentTimeMillis()
        logger.info("<<< End copying, $totalBytes bytes, took ${endMillis - startMillis} ms (avg: ${String.format("%.2f", speed(startMillis, endMillis, totalBytes))} kb/s)")
        smbFile.close()

    }

    static void copyFromSmb(String source, String dest, DiskShare diskShare) {
        def smbPath = source.substring(4)
        assert diskShare.fileExists(smbPath)
        def localPath = dest.substring(5)
        def localFile = new java.io.File(localPath)
        if (localFile.exists()) {
            localFile.delete()
        }
        assert !localFile.exists()
        def smbFile = diskShare.openFile(smbPath, EnumSet.of(AccessMask.GENERIC_READ), SMB2CreateDisposition.FILE_OPEN)
        long totalBytes = 0
        def startMillis = System.currentTimeMillis()
        logger.info(">>> Start copying $source to $dest")
        smbFile.read(new FileOutputStream(localPath), new ProgressListener() {
            @Override
            void onProgressChanged(long b, long tb) {
                totalBytes = b
                logger.debug("Read $totalBytes bytes of $tb total")
            }
        })
        def endMillis = System.currentTimeMillis()
        logger.info("<<< End copying, $totalBytes bytes, took ${endMillis - startMillis} ms (avg: ${String.format("%.2f", speed(startMillis, endMillis, totalBytes))} kb/s)")
        smbFile.close()
    }

    static def speed(long start, long end, long bytes) {
        double secs = (end - start) / 1000.0
        double kb = bytes / 1024.0
        return kb / secs
    }

    static def connectTo(String host) {
        def client = new SMBClient(new DefaultConfig())
        return client.connect(host)

    }
}
