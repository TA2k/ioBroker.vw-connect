.class public Lcom/salesforce/marketingcloud/tozny/AesCbcWithIntegrity$PrngFixes$LinuxPRNGSecureRandom;
.super Ljava/security/SecureRandomSpi;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field private static final URANDOM_FILE:Ljava/io/File;

.field private static final sLock:Ljava/lang/Object;

.field private static sUrandomIn:Ljava/io/DataInputStream;

.field private static sUrandomOut:Ljava/io/OutputStream;


# instance fields
.field private mSeeded:Z


# direct methods
.method public static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Ljava/io/File;

    .line 2
    .line 3
    const-string v1, "/dev/urandom"

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/io/File;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    sput-object v0, Lcom/salesforce/marketingcloud/tozny/AesCbcWithIntegrity$PrngFixes$LinuxPRNGSecureRandom;->URANDOM_FILE:Ljava/io/File;

    .line 9
    .line 10
    new-instance v0, Ljava/lang/Object;

    .line 11
    .line 12
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 13
    .line 14
    .line 15
    sput-object v0, Lcom/salesforce/marketingcloud/tozny/AesCbcWithIntegrity$PrngFixes$LinuxPRNGSecureRandom;->sLock:Ljava/lang/Object;

    .line 16
    .line 17
    return-void
.end method

.method public constructor <init>()V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/security/SecureRandomSpi;-><init>()V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method private getUrandomInputStream()Ljava/io/DataInputStream;
    .locals 4

    .line 1
    const-string p0, "Failed to open "

    .line 2
    .line 3
    sget-object v0, Lcom/salesforce/marketingcloud/tozny/AesCbcWithIntegrity$PrngFixes$LinuxPRNGSecureRandom;->sLock:Ljava/lang/Object;

    .line 4
    .line 5
    monitor-enter v0

    .line 6
    :try_start_0
    sget-object v1, Lcom/salesforce/marketingcloud/tozny/AesCbcWithIntegrity$PrngFixes$LinuxPRNGSecureRandom;->sUrandomIn:Ljava/io/DataInputStream;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 7
    .line 8
    if-nez v1, :cond_0

    .line 9
    .line 10
    :try_start_1
    new-instance v1, Ljava/io/DataInputStream;

    .line 11
    .line 12
    new-instance v2, Ljava/io/FileInputStream;

    .line 13
    .line 14
    sget-object v3, Lcom/salesforce/marketingcloud/tozny/AesCbcWithIntegrity$PrngFixes$LinuxPRNGSecureRandom;->URANDOM_FILE:Ljava/io/File;

    .line 15
    .line 16
    invoke-direct {v2, v3}, Ljava/io/FileInputStream;-><init>(Ljava/io/File;)V

    .line 17
    .line 18
    .line 19
    invoke-direct {v1, v2}, Ljava/io/DataInputStream;-><init>(Ljava/io/InputStream;)V

    .line 20
    .line 21
    .line 22
    sput-object v1, Lcom/salesforce/marketingcloud/tozny/AesCbcWithIntegrity$PrngFixes$LinuxPRNGSecureRandom;->sUrandomIn:Ljava/io/DataInputStream;
    :try_end_1
    .catch Ljava/io/IOException; {:try_start_1 .. :try_end_1} :catch_0
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 23
    .line 24
    goto :goto_0

    .line 25
    :catchall_0
    move-exception p0

    .line 26
    goto :goto_1

    .line 27
    :catch_0
    move-exception v1

    .line 28
    :try_start_2
    new-instance v2, Ljava/lang/SecurityException;

    .line 29
    .line 30
    new-instance v3, Ljava/lang/StringBuilder;

    .line 31
    .line 32
    invoke-direct {v3, p0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 33
    .line 34
    .line 35
    sget-object p0, Lcom/salesforce/marketingcloud/tozny/AesCbcWithIntegrity$PrngFixes$LinuxPRNGSecureRandom;->URANDOM_FILE:Ljava/io/File;

    .line 36
    .line 37
    invoke-virtual {v3, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 38
    .line 39
    .line 40
    const-string p0, " for reading"

    .line 41
    .line 42
    invoke-virtual {v3, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 43
    .line 44
    .line 45
    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 46
    .line 47
    .line 48
    move-result-object p0

    .line 49
    invoke-direct {v2, p0, v1}, Ljava/lang/SecurityException;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 50
    .line 51
    .line 52
    throw v2

    .line 53
    :cond_0
    :goto_0
    sget-object p0, Lcom/salesforce/marketingcloud/tozny/AesCbcWithIntegrity$PrngFixes$LinuxPRNGSecureRandom;->sUrandomIn:Ljava/io/DataInputStream;

    .line 54
    .line 55
    monitor-exit v0

    .line 56
    return-object p0

    .line 57
    :goto_1
    monitor-exit v0
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 58
    throw p0
.end method

.method private getUrandomOutputStream()Ljava/io/OutputStream;
    .locals 2

    .line 1
    sget-object p0, Lcom/salesforce/marketingcloud/tozny/AesCbcWithIntegrity$PrngFixes$LinuxPRNGSecureRandom;->sLock:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter p0

    .line 4
    :try_start_0
    sget-object v0, Lcom/salesforce/marketingcloud/tozny/AesCbcWithIntegrity$PrngFixes$LinuxPRNGSecureRandom;->sUrandomOut:Ljava/io/OutputStream;

    .line 5
    .line 6
    if-nez v0, :cond_0

    .line 7
    .line 8
    new-instance v0, Ljava/io/FileOutputStream;

    .line 9
    .line 10
    sget-object v1, Lcom/salesforce/marketingcloud/tozny/AesCbcWithIntegrity$PrngFixes$LinuxPRNGSecureRandom;->URANDOM_FILE:Ljava/io/File;

    .line 11
    .line 12
    invoke-direct {v0, v1}, Ljava/io/FileOutputStream;-><init>(Ljava/io/File;)V

    .line 13
    .line 14
    .line 15
    sput-object v0, Lcom/salesforce/marketingcloud/tozny/AesCbcWithIntegrity$PrngFixes$LinuxPRNGSecureRandom;->sUrandomOut:Ljava/io/OutputStream;

    .line 16
    .line 17
    goto :goto_0

    .line 18
    :catchall_0
    move-exception v0

    .line 19
    goto :goto_1

    .line 20
    :cond_0
    :goto_0
    sget-object v0, Lcom/salesforce/marketingcloud/tozny/AesCbcWithIntegrity$PrngFixes$LinuxPRNGSecureRandom;->sUrandomOut:Ljava/io/OutputStream;

    .line 21
    .line 22
    monitor-exit p0

    .line 23
    return-object v0

    .line 24
    :goto_1
    monitor-exit p0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 25
    throw v0
.end method


# virtual methods
.method public engineGenerateSeed(I)[B
    .locals 0

    .line 1
    new-array p1, p1, [B

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Lcom/salesforce/marketingcloud/tozny/AesCbcWithIntegrity$PrngFixes$LinuxPRNGSecureRandom;->engineNextBytes([B)V

    .line 4
    .line 5
    .line 6
    return-object p1
.end method

.method public engineNextBytes([B)V
    .locals 2

    .line 1
    iget-boolean v0, p0, Lcom/salesforce/marketingcloud/tozny/AesCbcWithIntegrity$PrngFixes$LinuxPRNGSecureRandom;->mSeeded:Z

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    invoke-static {}, Lcom/salesforce/marketingcloud/tozny/a;->b()[B

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    invoke-virtual {p0, v0}, Lcom/salesforce/marketingcloud/tozny/AesCbcWithIntegrity$PrngFixes$LinuxPRNGSecureRandom;->engineSetSeed([B)V

    .line 10
    .line 11
    .line 12
    :cond_0
    :try_start_0
    sget-object v0, Lcom/salesforce/marketingcloud/tozny/AesCbcWithIntegrity$PrngFixes$LinuxPRNGSecureRandom;->sLock:Ljava/lang/Object;

    .line 13
    .line 14
    monitor-enter v0
    :try_end_0
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_0

    .line 15
    :try_start_1
    invoke-direct {p0}, Lcom/salesforce/marketingcloud/tozny/AesCbcWithIntegrity$PrngFixes$LinuxPRNGSecureRandom;->getUrandomInputStream()Ljava/io/DataInputStream;

    .line 16
    .line 17
    .line 18
    move-result-object p0

    .line 19
    monitor-exit v0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 20
    :try_start_2
    monitor-enter p0
    :try_end_2
    .catch Ljava/io/IOException; {:try_start_2 .. :try_end_2} :catch_0

    .line 21
    :try_start_3
    invoke-virtual {p0, p1}, Ljava/io/DataInputStream;->readFully([B)V

    .line 22
    .line 23
    .line 24
    monitor-exit p0

    .line 25
    return-void

    .line 26
    :catchall_0
    move-exception p1

    .line 27
    monitor-exit p0
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_0

    .line 28
    :try_start_4
    throw p1
    :try_end_4
    .catch Ljava/io/IOException; {:try_start_4 .. :try_end_4} :catch_0

    .line 29
    :catchall_1
    move-exception p0

    .line 30
    :try_start_5
    monitor-exit v0
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_1

    .line 31
    :try_start_6
    throw p0
    :try_end_6
    .catch Ljava/io/IOException; {:try_start_6 .. :try_end_6} :catch_0

    .line 32
    :catch_0
    move-exception p0

    .line 33
    new-instance p1, Ljava/lang/SecurityException;

    .line 34
    .line 35
    new-instance v0, Ljava/lang/StringBuilder;

    .line 36
    .line 37
    const-string v1, "Failed to read from "

    .line 38
    .line 39
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 40
    .line 41
    .line 42
    sget-object v1, Lcom/salesforce/marketingcloud/tozny/AesCbcWithIntegrity$PrngFixes$LinuxPRNGSecureRandom;->URANDOM_FILE:Ljava/io/File;

    .line 43
    .line 44
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 45
    .line 46
    .line 47
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 48
    .line 49
    .line 50
    move-result-object v0

    .line 51
    invoke-direct {p1, v0, p0}, Ljava/lang/SecurityException;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 52
    .line 53
    .line 54
    throw p1
.end method

.method public engineSetSeed([B)V
    .locals 3

    .line 1
    const/4 v0, 0x1

    .line 2
    :try_start_0
    sget-object v1, Lcom/salesforce/marketingcloud/tozny/AesCbcWithIntegrity$PrngFixes$LinuxPRNGSecureRandom;->sLock:Ljava/lang/Object;

    .line 3
    .line 4
    monitor-enter v1
    :try_end_0
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 5
    :try_start_1
    invoke-direct {p0}, Lcom/salesforce/marketingcloud/tozny/AesCbcWithIntegrity$PrngFixes$LinuxPRNGSecureRandom;->getUrandomOutputStream()Ljava/io/OutputStream;

    .line 6
    .line 7
    .line 8
    move-result-object v2

    .line 9
    monitor-exit v1
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 10
    :try_start_2
    invoke-virtual {v2, p1}, Ljava/io/OutputStream;->write([B)V

    .line 11
    .line 12
    .line 13
    invoke-virtual {v2}, Ljava/io/OutputStream;->flush()V
    :try_end_2
    .catch Ljava/io/IOException; {:try_start_2 .. :try_end_2} :catch_0
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 14
    .line 15
    .line 16
    goto :goto_0

    .line 17
    :catchall_0
    move-exception p1

    .line 18
    goto :goto_1

    .line 19
    :catchall_1
    move-exception p1

    .line 20
    :try_start_3
    monitor-exit v1
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_1

    .line 21
    :try_start_4
    throw p1
    :try_end_4
    .catch Ljava/io/IOException; {:try_start_4 .. :try_end_4} :catch_0
    .catchall {:try_start_4 .. :try_end_4} :catchall_0

    .line 22
    :catch_0
    :try_start_5
    const-string p1, "a"

    .line 23
    .line 24
    new-instance v1, Ljava/lang/StringBuilder;

    .line 25
    .line 26
    invoke-direct {v1}, Ljava/lang/StringBuilder;-><init>()V

    .line 27
    .line 28
    .line 29
    const-string v2, "Failed to mix seed into "

    .line 30
    .line 31
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 32
    .line 33
    .line 34
    sget-object v2, Lcom/salesforce/marketingcloud/tozny/AesCbcWithIntegrity$PrngFixes$LinuxPRNGSecureRandom;->URANDOM_FILE:Ljava/io/File;

    .line 35
    .line 36
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 37
    .line 38
    .line 39
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 40
    .line 41
    .line 42
    move-result-object v1

    .line 43
    invoke-static {p1, v1}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_0

    .line 44
    .line 45
    .line 46
    :goto_0
    iput-boolean v0, p0, Lcom/salesforce/marketingcloud/tozny/AesCbcWithIntegrity$PrngFixes$LinuxPRNGSecureRandom;->mSeeded:Z

    .line 47
    .line 48
    return-void

    .line 49
    :goto_1
    iput-boolean v0, p0, Lcom/salesforce/marketingcloud/tozny/AesCbcWithIntegrity$PrngFixes$LinuxPRNGSecureRandom;->mSeeded:Z

    .line 50
    .line 51
    throw p1
.end method
