.class public Lorg/eclipse/paho/mqttv5/client/persist/MqttDefaultFilePersistence;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lorg/eclipse/paho/mqttv5/client/MqttClientPersistence;


# static fields
.field private static FILENAME_FILTER:Ljava/io/FilenameFilter; = null

.field private static final LOCK_FILENAME:Ljava/lang/String; = ".lck"

.field private static final MESSAGE_BACKUP_FILE_EXTENSION:Ljava/lang/String; = ".bup"

.field private static final MESSAGE_FILE_EXTENSION:Ljava/lang/String; = ".msg"


# instance fields
.field private clientDir:Ljava/io/File;

.field private dataDir:Ljava/io/File;

.field private fileLock:Lorg/eclipse/paho/mqttv5/client/internal/FileLock;


# direct methods
.method public constructor <init>()V
    .locals 1

    .line 1
    const-string v0, "user.dir"

    invoke-static {v0}, Ljava/lang/System;->getProperty(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v0

    invoke-direct {p0, v0}, Lorg/eclipse/paho/mqttv5/client/persist/MqttDefaultFilePersistence;-><init>(Ljava/lang/String;)V

    return-void
.end method

.method public constructor <init>(Ljava/lang/String;)V
    .locals 1

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    const/4 v0, 0x0

    .line 3
    iput-object v0, p0, Lorg/eclipse/paho/mqttv5/client/persist/MqttDefaultFilePersistence;->clientDir:Ljava/io/File;

    .line 4
    iput-object v0, p0, Lorg/eclipse/paho/mqttv5/client/persist/MqttDefaultFilePersistence;->fileLock:Lorg/eclipse/paho/mqttv5/client/internal/FileLock;

    .line 5
    new-instance v0, Ljava/io/File;

    invoke-direct {v0, p1}, Ljava/io/File;-><init>(Ljava/lang/String;)V

    iput-object v0, p0, Lorg/eclipse/paho/mqttv5/client/persist/MqttDefaultFilePersistence;->dataDir:Ljava/io/File;

    return-void
.end method

.method private checkIsOpen()V
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/persist/MqttDefaultFilePersistence;->clientDir:Ljava/io/File;

    .line 2
    .line 3
    if-eqz p0, :cond_0

    .line 4
    .line 5
    return-void

    .line 6
    :cond_0
    new-instance p0, Lorg/eclipse/paho/mqttv5/common/MqttPersistenceException;

    .line 7
    .line 8
    invoke-direct {p0}, Lorg/eclipse/paho/mqttv5/common/MqttPersistenceException;-><init>()V

    .line 9
    .line 10
    .line 11
    throw p0
.end method

.method private static getFilenameFilter()Ljava/io/FilenameFilter;
    .locals 2

    .line 1
    sget-object v0, Lorg/eclipse/paho/mqttv5/client/persist/MqttDefaultFilePersistence;->FILENAME_FILTER:Ljava/io/FilenameFilter;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    new-instance v0, Lorg/eclipse/paho/mqttv5/client/persist/PersistenceFileNameFilter;

    .line 6
    .line 7
    const-string v1, ".msg"

    .line 8
    .line 9
    invoke-direct {v0, v1}, Lorg/eclipse/paho/mqttv5/client/persist/PersistenceFileNameFilter;-><init>(Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    sput-object v0, Lorg/eclipse/paho/mqttv5/client/persist/MqttDefaultFilePersistence;->FILENAME_FILTER:Ljava/io/FilenameFilter;

    .line 13
    .line 14
    :cond_0
    sget-object v0, Lorg/eclipse/paho/mqttv5/client/persist/MqttDefaultFilePersistence;->FILENAME_FILTER:Ljava/io/FilenameFilter;

    .line 15
    .line 16
    return-object v0
.end method

.method private getFiles()[Ljava/io/File;
    .locals 1

    .line 1
    invoke-direct {p0}, Lorg/eclipse/paho/mqttv5/client/persist/MqttDefaultFilePersistence;->checkIsOpen()V

    .line 2
    .line 3
    .line 4
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/persist/MqttDefaultFilePersistence;->clientDir:Ljava/io/File;

    .line 5
    .line 6
    invoke-static {}, Lorg/eclipse/paho/mqttv5/client/persist/MqttDefaultFilePersistence;->getFilenameFilter()Ljava/io/FilenameFilter;

    .line 7
    .line 8
    .line 9
    move-result-object v0

    .line 10
    invoke-virtual {p0, v0}, Ljava/io/File;->listFiles(Ljava/io/FilenameFilter;)[Ljava/io/File;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    if-eqz p0, :cond_0

    .line 15
    .line 16
    return-object p0

    .line 17
    :cond_0
    new-instance p0, Lorg/eclipse/paho/mqttv5/common/MqttPersistenceException;

    .line 18
    .line 19
    invoke-direct {p0}, Lorg/eclipse/paho/mqttv5/common/MqttPersistenceException;-><init>()V

    .line 20
    .line 21
    .line 22
    throw p0
.end method

.method private isSafeChar(C)Z
    .locals 0

    .line 1
    invoke-static {p1}, Ljava/lang/Character;->isJavaIdentifierPart(C)Z

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    if-nez p0, :cond_0

    .line 6
    .line 7
    const/16 p0, 0x2d

    .line 8
    .line 9
    if-eq p1, p0, :cond_0

    .line 10
    .line 11
    const/4 p0, 0x0

    .line 12
    return p0

    .line 13
    :cond_0
    const/4 p0, 0x1

    .line 14
    return p0
.end method

.method private restoreBackups(Ljava/io/File;)V
    .locals 7

    .line 1
    new-instance p0, Lorg/eclipse/paho/mqttv5/client/persist/PersistenceFileFilter;

    .line 2
    .line 3
    const-string v0, ".bup"

    .line 4
    .line 5
    invoke-direct {p0, v0}, Lorg/eclipse/paho/mqttv5/client/persist/PersistenceFileFilter;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    invoke-virtual {p1, p0}, Ljava/io/File;->listFiles(Ljava/io/FileFilter;)[Ljava/io/File;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    if-eqz p0, :cond_2

    .line 13
    .line 14
    array-length v0, p0

    .line 15
    const/4 v1, 0x0

    .line 16
    move v2, v1

    .line 17
    :goto_0
    if-lt v2, v0, :cond_0

    .line 18
    .line 19
    return-void

    .line 20
    :cond_0
    aget-object v3, p0, v2

    .line 21
    .line 22
    new-instance v4, Ljava/io/File;

    .line 23
    .line 24
    invoke-virtual {v3}, Ljava/io/File;->getName()Ljava/lang/String;

    .line 25
    .line 26
    .line 27
    move-result-object v5

    .line 28
    invoke-virtual {v3}, Ljava/io/File;->getName()Ljava/lang/String;

    .line 29
    .line 30
    .line 31
    move-result-object v6

    .line 32
    invoke-virtual {v6}, Ljava/lang/String;->length()I

    .line 33
    .line 34
    .line 35
    move-result v6

    .line 36
    add-int/lit8 v6, v6, -0x4

    .line 37
    .line 38
    invoke-virtual {v5, v1, v6}, Ljava/lang/String;->substring(II)Ljava/lang/String;

    .line 39
    .line 40
    .line 41
    move-result-object v5

    .line 42
    invoke-direct {v4, p1, v5}, Ljava/io/File;-><init>(Ljava/io/File;Ljava/lang/String;)V

    .line 43
    .line 44
    .line 45
    invoke-virtual {v3, v4}, Ljava/io/File;->renameTo(Ljava/io/File;)Z

    .line 46
    .line 47
    .line 48
    move-result v5

    .line 49
    if-nez v5, :cond_1

    .line 50
    .line 51
    invoke-virtual {v4}, Ljava/io/File;->delete()Z

    .line 52
    .line 53
    .line 54
    invoke-virtual {v3, v4}, Ljava/io/File;->renameTo(Ljava/io/File;)Z

    .line 55
    .line 56
    .line 57
    :cond_1
    add-int/lit8 v2, v2, 0x1

    .line 58
    .line 59
    goto :goto_0

    .line 60
    :cond_2
    new-instance p0, Lorg/eclipse/paho/mqttv5/common/MqttPersistenceException;

    .line 61
    .line 62
    invoke-direct {p0}, Lorg/eclipse/paho/mqttv5/common/MqttPersistenceException;-><init>()V

    .line 63
    .line 64
    .line 65
    throw p0
.end method


# virtual methods
.method public clear()V
    .locals 4

    .line 1
    invoke-direct {p0}, Lorg/eclipse/paho/mqttv5/client/persist/MqttDefaultFilePersistence;->checkIsOpen()V

    .line 2
    .line 3
    .line 4
    invoke-direct {p0}, Lorg/eclipse/paho/mqttv5/client/persist/MqttDefaultFilePersistence;->getFiles()[Ljava/io/File;

    .line 5
    .line 6
    .line 7
    move-result-object v0

    .line 8
    array-length v1, v0

    .line 9
    const/4 v2, 0x0

    .line 10
    :goto_0
    if-lt v2, v1, :cond_0

    .line 11
    .line 12
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/persist/MqttDefaultFilePersistence;->clientDir:Ljava/io/File;

    .line 13
    .line 14
    invoke-virtual {p0}, Ljava/io/File;->delete()Z

    .line 15
    .line 16
    .line 17
    return-void

    .line 18
    :cond_0
    aget-object v3, v0, v2

    .line 19
    .line 20
    invoke-virtual {v3}, Ljava/io/File;->delete()Z

    .line 21
    .line 22
    .line 23
    add-int/lit8 v2, v2, 0x1

    .line 24
    .line 25
    goto :goto_0
.end method

.method public close()V
    .locals 1

    .line 1
    monitor-enter p0

    .line 2
    :try_start_0
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/persist/MqttDefaultFilePersistence;->fileLock:Lorg/eclipse/paho/mqttv5/client/internal/FileLock;

    .line 3
    .line 4
    if-eqz v0, :cond_0

    .line 5
    .line 6
    invoke-virtual {v0}, Lorg/eclipse/paho/mqttv5/client/internal/FileLock;->release()V

    .line 7
    .line 8
    .line 9
    goto :goto_0

    .line 10
    :catchall_0
    move-exception v0

    .line 11
    goto :goto_1

    .line 12
    :cond_0
    :goto_0
    invoke-direct {p0}, Lorg/eclipse/paho/mqttv5/client/persist/MqttDefaultFilePersistence;->getFiles()[Ljava/io/File;

    .line 13
    .line 14
    .line 15
    move-result-object v0

    .line 16
    array-length v0, v0

    .line 17
    if-nez v0, :cond_1

    .line 18
    .line 19
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/persist/MqttDefaultFilePersistence;->clientDir:Ljava/io/File;

    .line 20
    .line 21
    invoke-virtual {v0}, Ljava/io/File;->delete()Z

    .line 22
    .line 23
    .line 24
    :cond_1
    const/4 v0, 0x0

    .line 25
    iput-object v0, p0, Lorg/eclipse/paho/mqttv5/client/persist/MqttDefaultFilePersistence;->clientDir:Ljava/io/File;

    .line 26
    .line 27
    monitor-exit p0

    .line 28
    return-void

    .line 29
    :goto_1
    monitor-exit p0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 30
    throw v0
.end method

.method public containsKey(Ljava/lang/String;)Z
    .locals 2

    .line 1
    invoke-direct {p0}, Lorg/eclipse/paho/mqttv5/client/persist/MqttDefaultFilePersistence;->checkIsOpen()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Ljava/io/File;

    .line 5
    .line 6
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/persist/MqttDefaultFilePersistence;->clientDir:Ljava/io/File;

    .line 7
    .line 8
    invoke-static {p1}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;

    .line 9
    .line 10
    .line 11
    move-result-object p1

    .line 12
    const-string v1, ".msg"

    .line 13
    .line 14
    invoke-virtual {p1, v1}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 15
    .line 16
    .line 17
    move-result-object p1

    .line 18
    invoke-direct {v0, p0, p1}, Ljava/io/File;-><init>(Ljava/io/File;Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    invoke-virtual {v0}, Ljava/io/File;->exists()Z

    .line 22
    .line 23
    .line 24
    move-result p0

    .line 25
    return p0
.end method

.method public get(Ljava/lang/String;)Lorg/eclipse/paho/mqttv5/common/MqttPersistable;
    .locals 10

    .line 1
    const-string v0, ".msg"

    .line 2
    .line 3
    invoke-direct {p0}, Lorg/eclipse/paho/mqttv5/client/persist/MqttDefaultFilePersistence;->checkIsOpen()V

    .line 4
    .line 5
    .line 6
    :try_start_0
    new-instance v1, Ljava/io/File;

    .line 7
    .line 8
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/persist/MqttDefaultFilePersistence;->clientDir:Ljava/io/File;

    .line 9
    .line 10
    invoke-static {p1}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;

    .line 11
    .line 12
    .line 13
    move-result-object v2

    .line 14
    invoke-virtual {v2, v0}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 15
    .line 16
    .line 17
    move-result-object v0

    .line 18
    invoke-direct {v1, p0, v0}, Ljava/io/File;-><init>(Ljava/io/File;Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    new-instance p0, Ljava/io/FileInputStream;

    .line 22
    .line 23
    invoke-direct {p0, v1}, Ljava/io/FileInputStream;-><init>(Ljava/io/File;)V

    .line 24
    .line 25
    .line 26
    invoke-virtual {p0}, Ljava/io/FileInputStream;->available()I

    .line 27
    .line 28
    .line 29
    move-result v6

    .line 30
    new-array v4, v6, [B

    .line 31
    .line 32
    const/4 v0, 0x0

    .line 33
    :goto_0
    if-lt v0, v6, :cond_0

    .line 34
    .line 35
    invoke-virtual {p0}, Ljava/io/FileInputStream;->close()V

    .line 36
    .line 37
    .line 38
    new-instance v2, Lorg/eclipse/paho/mqttv5/client/internal/MqttPersistentData;

    .line 39
    .line 40
    const/4 v8, 0x0

    .line 41
    const/4 v9, 0x0

    .line 42
    const/4 v5, 0x0

    .line 43
    const/4 v7, 0x0

    .line 44
    move-object v3, p1

    .line 45
    invoke-direct/range {v2 .. v9}, Lorg/eclipse/paho/mqttv5/client/internal/MqttPersistentData;-><init>(Ljava/lang/String;[BII[BII)V

    .line 46
    .line 47
    .line 48
    return-object v2

    .line 49
    :cond_0
    move-object v3, p1

    .line 50
    sub-int p1, v6, v0

    .line 51
    .line 52
    invoke-virtual {p0, v4, v0, p1}, Ljava/io/FileInputStream;->read([BII)I

    .line 53
    .line 54
    .line 55
    move-result p1
    :try_end_0
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_0

    .line 56
    add-int/2addr v0, p1

    .line 57
    move-object p1, v3

    .line 58
    goto :goto_0

    .line 59
    :catch_0
    move-exception v0

    .line 60
    move-object p0, v0

    .line 61
    new-instance p1, Lorg/eclipse/paho/mqttv5/common/MqttPersistenceException;

    .line 62
    .line 63
    invoke-direct {p1, p0}, Lorg/eclipse/paho/mqttv5/common/MqttPersistenceException;-><init>(Ljava/lang/Throwable;)V

    .line 64
    .line 65
    .line 66
    throw p1
.end method

.method public keys()Ljava/util/Enumeration;
    .locals 6
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/Enumeration<",
            "Ljava/lang/String;",
            ">;"
        }
    .end annotation

    .line 1
    invoke-direct {p0}, Lorg/eclipse/paho/mqttv5/client/persist/MqttDefaultFilePersistence;->checkIsOpen()V

    .line 2
    .line 3
    .line 4
    invoke-direct {p0}, Lorg/eclipse/paho/mqttv5/client/persist/MqttDefaultFilePersistence;->getFiles()[Ljava/io/File;

    .line 5
    .line 6
    .line 7
    move-result-object p0

    .line 8
    new-instance v0, Ljava/util/Vector;

    .line 9
    .line 10
    array-length v1, p0

    .line 11
    invoke-direct {v0, v1}, Ljava/util/Vector;-><init>(I)V

    .line 12
    .line 13
    .line 14
    array-length v1, p0

    .line 15
    const/4 v2, 0x0

    .line 16
    move v3, v2

    .line 17
    :goto_0
    if-lt v3, v1, :cond_0

    .line 18
    .line 19
    invoke-virtual {v0}, Ljava/util/Vector;->elements()Ljava/util/Enumeration;

    .line 20
    .line 21
    .line 22
    move-result-object p0

    .line 23
    return-object p0

    .line 24
    :cond_0
    aget-object v4, p0, v3

    .line 25
    .line 26
    invoke-virtual {v4}, Ljava/io/File;->getName()Ljava/lang/String;

    .line 27
    .line 28
    .line 29
    move-result-object v4

    .line 30
    invoke-virtual {v4}, Ljava/lang/String;->length()I

    .line 31
    .line 32
    .line 33
    move-result v5

    .line 34
    add-int/lit8 v5, v5, -0x4

    .line 35
    .line 36
    invoke-virtual {v4, v2, v5}, Ljava/lang/String;->substring(II)Ljava/lang/String;

    .line 37
    .line 38
    .line 39
    move-result-object v4

    .line 40
    invoke-virtual {v0, v4}, Ljava/util/Vector;->addElement(Ljava/lang/Object;)V

    .line 41
    .line 42
    .line 43
    add-int/lit8 v3, v3, 0x1

    .line 44
    .line 45
    goto :goto_0
.end method

.method public open(Ljava/lang/String;)V
    .locals 4

    .line 1
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/persist/MqttDefaultFilePersistence;->dataDir:Ljava/io/File;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/io/File;->exists()Z

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    if-eqz v0, :cond_1

    .line 8
    .line 9
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/persist/MqttDefaultFilePersistence;->dataDir:Ljava/io/File;

    .line 10
    .line 11
    invoke-virtual {v0}, Ljava/io/File;->isDirectory()Z

    .line 12
    .line 13
    .line 14
    move-result v0

    .line 15
    if-eqz v0, :cond_0

    .line 16
    .line 17
    goto :goto_0

    .line 18
    :cond_0
    new-instance p0, Lorg/eclipse/paho/mqttv5/common/MqttPersistenceException;

    .line 19
    .line 20
    invoke-direct {p0}, Lorg/eclipse/paho/mqttv5/common/MqttPersistenceException;-><init>()V

    .line 21
    .line 22
    .line 23
    throw p0

    .line 24
    :cond_1
    :goto_0
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/persist/MqttDefaultFilePersistence;->dataDir:Ljava/io/File;

    .line 25
    .line 26
    invoke-virtual {v0}, Ljava/io/File;->exists()Z

    .line 27
    .line 28
    .line 29
    move-result v0

    .line 30
    if-nez v0, :cond_3

    .line 31
    .line 32
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/persist/MqttDefaultFilePersistence;->dataDir:Ljava/io/File;

    .line 33
    .line 34
    invoke-virtual {v0}, Ljava/io/File;->mkdirs()Z

    .line 35
    .line 36
    .line 37
    move-result v0

    .line 38
    if-eqz v0, :cond_2

    .line 39
    .line 40
    goto :goto_1

    .line 41
    :cond_2
    new-instance p0, Lorg/eclipse/paho/mqttv5/common/MqttPersistenceException;

    .line 42
    .line 43
    invoke-direct {p0}, Lorg/eclipse/paho/mqttv5/common/MqttPersistenceException;-><init>()V

    .line 44
    .line 45
    .line 46
    throw p0

    .line 47
    :cond_3
    :goto_1
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/persist/MqttDefaultFilePersistence;->dataDir:Ljava/io/File;

    .line 48
    .line 49
    invoke-virtual {v0}, Ljava/io/File;->canWrite()Z

    .line 50
    .line 51
    .line 52
    move-result v0

    .line 53
    if-eqz v0, :cond_8

    .line 54
    .line 55
    new-instance v0, Ljava/lang/StringBuffer;

    .line 56
    .line 57
    invoke-direct {v0}, Ljava/lang/StringBuffer;-><init>()V

    .line 58
    .line 59
    .line 60
    const/4 v1, 0x0

    .line 61
    :goto_2
    invoke-virtual {p1}, Ljava/lang/String;->length()I

    .line 62
    .line 63
    .line 64
    move-result v2

    .line 65
    if-lt v1, v2, :cond_6

    .line 66
    .line 67
    monitor-enter p0

    .line 68
    :try_start_0
    iget-object p1, p0, Lorg/eclipse/paho/mqttv5/client/persist/MqttDefaultFilePersistence;->clientDir:Ljava/io/File;

    .line 69
    .line 70
    if-nez p1, :cond_4

    .line 71
    .line 72
    invoke-virtual {v0}, Ljava/lang/StringBuffer;->toString()Ljava/lang/String;

    .line 73
    .line 74
    .line 75
    move-result-object p1

    .line 76
    new-instance v0, Ljava/io/File;

    .line 77
    .line 78
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/client/persist/MqttDefaultFilePersistence;->dataDir:Ljava/io/File;

    .line 79
    .line 80
    invoke-direct {v0, v1, p1}, Ljava/io/File;-><init>(Ljava/io/File;Ljava/lang/String;)V

    .line 81
    .line 82
    .line 83
    iput-object v0, p0, Lorg/eclipse/paho/mqttv5/client/persist/MqttDefaultFilePersistence;->clientDir:Ljava/io/File;

    .line 84
    .line 85
    invoke-virtual {v0}, Ljava/io/File;->exists()Z

    .line 86
    .line 87
    .line 88
    move-result p1

    .line 89
    if-nez p1, :cond_4

    .line 90
    .line 91
    iget-object p1, p0, Lorg/eclipse/paho/mqttv5/client/persist/MqttDefaultFilePersistence;->clientDir:Ljava/io/File;

    .line 92
    .line 93
    invoke-virtual {p1}, Ljava/io/File;->mkdir()Z
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 94
    .line 95
    .line 96
    goto :goto_3

    .line 97
    :catchall_0
    move-exception p1

    .line 98
    goto :goto_4

    .line 99
    :cond_4
    :goto_3
    :try_start_1
    iget-object p1, p0, Lorg/eclipse/paho/mqttv5/client/persist/MqttDefaultFilePersistence;->fileLock:Lorg/eclipse/paho/mqttv5/client/internal/FileLock;

    .line 100
    .line 101
    if-eqz p1, :cond_5

    .line 102
    .line 103
    invoke-virtual {p1}, Lorg/eclipse/paho/mqttv5/client/internal/FileLock;->release()V

    .line 104
    .line 105
    .line 106
    :cond_5
    new-instance p1, Lorg/eclipse/paho/mqttv5/client/internal/FileLock;

    .line 107
    .line 108
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/persist/MqttDefaultFilePersistence;->clientDir:Ljava/io/File;

    .line 109
    .line 110
    const-string v1, ".lck"

    .line 111
    .line 112
    invoke-direct {p1, v0, v1}, Lorg/eclipse/paho/mqttv5/client/internal/FileLock;-><init>(Ljava/io/File;Ljava/lang/String;)V

    .line 113
    .line 114
    .line 115
    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/client/persist/MqttDefaultFilePersistence;->fileLock:Lorg/eclipse/paho/mqttv5/client/internal/FileLock;
    :try_end_1
    .catch Ljava/lang/Exception; {:try_start_1 .. :try_end_1} :catch_0
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 116
    .line 117
    :catch_0
    :try_start_2
    iget-object p1, p0, Lorg/eclipse/paho/mqttv5/client/persist/MqttDefaultFilePersistence;->clientDir:Ljava/io/File;

    .line 118
    .line 119
    invoke-direct {p0, p1}, Lorg/eclipse/paho/mqttv5/client/persist/MqttDefaultFilePersistence;->restoreBackups(Ljava/io/File;)V

    .line 120
    .line 121
    .line 122
    monitor-exit p0

    .line 123
    return-void

    .line 124
    :goto_4
    monitor-exit p0
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 125
    throw p1

    .line 126
    :cond_6
    invoke-virtual {p1, v1}, Ljava/lang/String;->charAt(I)C

    .line 127
    .line 128
    .line 129
    move-result v2

    .line 130
    invoke-direct {p0, v2}, Lorg/eclipse/paho/mqttv5/client/persist/MqttDefaultFilePersistence;->isSafeChar(C)Z

    .line 131
    .line 132
    .line 133
    move-result v3

    .line 134
    if-eqz v3, :cond_7

    .line 135
    .line 136
    invoke-virtual {v0, v2}, Ljava/lang/StringBuffer;->append(C)Ljava/lang/StringBuffer;

    .line 137
    .line 138
    .line 139
    :cond_7
    add-int/lit8 v1, v1, 0x1

    .line 140
    .line 141
    goto :goto_2

    .line 142
    :cond_8
    new-instance p0, Lorg/eclipse/paho/mqttv5/common/MqttPersistenceException;

    .line 143
    .line 144
    invoke-direct {p0}, Lorg/eclipse/paho/mqttv5/common/MqttPersistenceException;-><init>()V

    .line 145
    .line 146
    .line 147
    throw p0
.end method

.method public put(Ljava/lang/String;Lorg/eclipse/paho/mqttv5/common/MqttPersistable;)V
    .locals 4

    .line 1
    invoke-direct {p0}, Lorg/eclipse/paho/mqttv5/client/persist/MqttDefaultFilePersistence;->checkIsOpen()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Ljava/io/File;

    .line 5
    .line 6
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/client/persist/MqttDefaultFilePersistence;->clientDir:Ljava/io/File;

    .line 7
    .line 8
    invoke-static {p1}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;

    .line 9
    .line 10
    .line 11
    move-result-object v2

    .line 12
    const-string v3, ".msg"

    .line 13
    .line 14
    invoke-virtual {v2, v3}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 15
    .line 16
    .line 17
    move-result-object v2

    .line 18
    invoke-direct {v0, v1, v2}, Ljava/io/File;-><init>(Ljava/io/File;Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    new-instance v1, Ljava/io/File;

    .line 22
    .line 23
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/persist/MqttDefaultFilePersistence;->clientDir:Ljava/io/File;

    .line 24
    .line 25
    invoke-static {p1}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;

    .line 26
    .line 27
    .line 28
    move-result-object p1

    .line 29
    const-string v2, ".msg.bup"

    .line 30
    .line 31
    invoke-virtual {p1, v2}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 32
    .line 33
    .line 34
    move-result-object p1

    .line 35
    invoke-direct {v1, p0, p1}, Ljava/io/File;-><init>(Ljava/io/File;Ljava/lang/String;)V

    .line 36
    .line 37
    .line 38
    invoke-virtual {v0}, Ljava/io/File;->exists()Z

    .line 39
    .line 40
    .line 41
    move-result p0

    .line 42
    if-eqz p0, :cond_0

    .line 43
    .line 44
    invoke-virtual {v0, v1}, Ljava/io/File;->renameTo(Ljava/io/File;)Z

    .line 45
    .line 46
    .line 47
    move-result p0

    .line 48
    if-nez p0, :cond_0

    .line 49
    .line 50
    invoke-virtual {v1}, Ljava/io/File;->delete()Z

    .line 51
    .line 52
    .line 53
    invoke-virtual {v0, v1}, Ljava/io/File;->renameTo(Ljava/io/File;)Z

    .line 54
    .line 55
    .line 56
    :cond_0
    :try_start_0
    new-instance p0, Ljava/io/FileOutputStream;

    .line 57
    .line 58
    invoke-direct {p0, v0}, Ljava/io/FileOutputStream;-><init>(Ljava/io/File;)V

    .line 59
    .line 60
    .line 61
    invoke-interface {p2}, Lorg/eclipse/paho/mqttv5/common/MqttPersistable;->getHeaderBytes()[B

    .line 62
    .line 63
    .line 64
    move-result-object p1

    .line 65
    invoke-interface {p2}, Lorg/eclipse/paho/mqttv5/common/MqttPersistable;->getHeaderOffset()I

    .line 66
    .line 67
    .line 68
    move-result v2

    .line 69
    invoke-interface {p2}, Lorg/eclipse/paho/mqttv5/common/MqttPersistable;->getHeaderLength()I

    .line 70
    .line 71
    .line 72
    move-result v3

    .line 73
    invoke-virtual {p0, p1, v2, v3}, Ljava/io/FileOutputStream;->write([BII)V

    .line 74
    .line 75
    .line 76
    invoke-interface {p2}, Lorg/eclipse/paho/mqttv5/common/MqttPersistable;->getPayloadBytes()[B

    .line 77
    .line 78
    .line 79
    move-result-object p1

    .line 80
    if-eqz p1, :cond_1

    .line 81
    .line 82
    invoke-interface {p2}, Lorg/eclipse/paho/mqttv5/common/MqttPersistable;->getPayloadBytes()[B

    .line 83
    .line 84
    .line 85
    move-result-object p1

    .line 86
    invoke-interface {p2}, Lorg/eclipse/paho/mqttv5/common/MqttPersistable;->getPayloadOffset()I

    .line 87
    .line 88
    .line 89
    move-result v2

    .line 90
    invoke-interface {p2}, Lorg/eclipse/paho/mqttv5/common/MqttPersistable;->getPayloadLength()I

    .line 91
    .line 92
    .line 93
    move-result p2

    .line 94
    invoke-virtual {p0, p1, v2, p2}, Ljava/io/FileOutputStream;->write([BII)V

    .line 95
    .line 96
    .line 97
    goto :goto_0

    .line 98
    :catchall_0
    move-exception p0

    .line 99
    goto :goto_2

    .line 100
    :catch_0
    move-exception p0

    .line 101
    goto :goto_1

    .line 102
    :cond_1
    :goto_0
    invoke-virtual {p0}, Ljava/io/FileOutputStream;->getFD()Ljava/io/FileDescriptor;

    .line 103
    .line 104
    .line 105
    move-result-object p1

    .line 106
    invoke-virtual {p1}, Ljava/io/FileDescriptor;->sync()V

    .line 107
    .line 108
    .line 109
    invoke-virtual {p0}, Ljava/io/FileOutputStream;->close()V

    .line 110
    .line 111
    .line 112
    invoke-virtual {v1}, Ljava/io/File;->exists()Z

    .line 113
    .line 114
    .line 115
    move-result p0

    .line 116
    if-eqz p0, :cond_2

    .line 117
    .line 118
    invoke-virtual {v1}, Ljava/io/File;->delete()Z
    :try_end_0
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 119
    .line 120
    .line 121
    :cond_2
    invoke-virtual {v1}, Ljava/io/File;->exists()Z

    .line 122
    .line 123
    .line 124
    move-result p0

    .line 125
    if-eqz p0, :cond_3

    .line 126
    .line 127
    invoke-virtual {v1, v0}, Ljava/io/File;->renameTo(Ljava/io/File;)Z

    .line 128
    .line 129
    .line 130
    move-result p0

    .line 131
    if-nez p0, :cond_3

    .line 132
    .line 133
    invoke-virtual {v0}, Ljava/io/File;->delete()Z

    .line 134
    .line 135
    .line 136
    invoke-virtual {v1, v0}, Ljava/io/File;->renameTo(Ljava/io/File;)Z

    .line 137
    .line 138
    .line 139
    :cond_3
    return-void

    .line 140
    :goto_1
    :try_start_1
    new-instance p1, Lorg/eclipse/paho/mqttv5/common/MqttPersistenceException;

    .line 141
    .line 142
    invoke-direct {p1, p0}, Lorg/eclipse/paho/mqttv5/common/MqttPersistenceException;-><init>(Ljava/lang/Throwable;)V

    .line 143
    .line 144
    .line 145
    throw p1
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 146
    :goto_2
    invoke-virtual {v1}, Ljava/io/File;->exists()Z

    .line 147
    .line 148
    .line 149
    move-result p1

    .line 150
    if-eqz p1, :cond_4

    .line 151
    .line 152
    invoke-virtual {v1, v0}, Ljava/io/File;->renameTo(Ljava/io/File;)Z

    .line 153
    .line 154
    .line 155
    move-result p1

    .line 156
    if-nez p1, :cond_4

    .line 157
    .line 158
    invoke-virtual {v0}, Ljava/io/File;->delete()Z

    .line 159
    .line 160
    .line 161
    invoke-virtual {v1, v0}, Ljava/io/File;->renameTo(Ljava/io/File;)Z

    .line 162
    .line 163
    .line 164
    :cond_4
    throw p0
.end method

.method public remove(Ljava/lang/String;)V
    .locals 2

    .line 1
    invoke-direct {p0}, Lorg/eclipse/paho/mqttv5/client/persist/MqttDefaultFilePersistence;->checkIsOpen()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Ljava/io/File;

    .line 5
    .line 6
    iget-object p0, p0, Lorg/eclipse/paho/mqttv5/client/persist/MqttDefaultFilePersistence;->clientDir:Ljava/io/File;

    .line 7
    .line 8
    invoke-static {p1}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;

    .line 9
    .line 10
    .line 11
    move-result-object p1

    .line 12
    const-string v1, ".msg"

    .line 13
    .line 14
    invoke-virtual {p1, v1}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 15
    .line 16
    .line 17
    move-result-object p1

    .line 18
    invoke-direct {v0, p0, p1}, Ljava/io/File;-><init>(Ljava/io/File;Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    invoke-virtual {v0}, Ljava/io/File;->exists()Z

    .line 22
    .line 23
    .line 24
    move-result p0

    .line 25
    if-eqz p0, :cond_0

    .line 26
    .line 27
    invoke-virtual {v0}, Ljava/io/File;->delete()Z

    .line 28
    .line 29
    .line 30
    :cond_0
    return-void
.end method
