.class public Lorg/eclipse/paho/mqttv5/client/internal/FileLock;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field private file:Ljava/io/RandomAccessFile;

.field private fileLock:Ljava/lang/Object;

.field private lockFile:Ljava/io/File;


# direct methods
.method public constructor <init>(Ljava/io/File;Ljava/lang/String;)V
    .locals 2

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Ljava/io/File;

    .line 5
    .line 6
    invoke-direct {v0, p1, p2}, Ljava/io/File;-><init>(Ljava/io/File;Ljava/lang/String;)V

    .line 7
    .line 8
    .line 9
    iput-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/FileLock;->lockFile:Ljava/io/File;

    .line 10
    .line 11
    const-string p1, "java.nio.channels.FileLock"

    .line 12
    .line 13
    invoke-static {p1}, Lorg/eclipse/paho/mqttv5/client/internal/ExceptionHelper;->isClassAvailable(Ljava/lang/String;)Z

    .line 14
    .line 15
    .line 16
    move-result p1

    .line 17
    if-eqz p1, :cond_1

    .line 18
    .line 19
    const/4 p1, 0x0

    .line 20
    :try_start_0
    new-instance p2, Ljava/io/RandomAccessFile;

    .line 21
    .line 22
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/FileLock;->lockFile:Ljava/io/File;

    .line 23
    .line 24
    const-string v1, "rw"

    .line 25
    .line 26
    invoke-direct {p2, v0, v1}, Ljava/io/RandomAccessFile;-><init>(Ljava/io/File;Ljava/lang/String;)V

    .line 27
    .line 28
    .line 29
    iput-object p2, p0, Lorg/eclipse/paho/mqttv5/client/internal/FileLock;->file:Ljava/io/RandomAccessFile;

    .line 30
    .line 31
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 32
    .line 33
    .line 34
    move-result-object p2

    .line 35
    const-string v0, "getChannel"

    .line 36
    .line 37
    invoke-virtual {p2, v0, p1}, Ljava/lang/Class;->getMethod(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;

    .line 38
    .line 39
    .line 40
    move-result-object p2

    .line 41
    iget-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/FileLock;->file:Ljava/io/RandomAccessFile;

    .line 42
    .line 43
    invoke-virtual {p2, v0, p1}, Ljava/lang/reflect/Method;->invoke(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;

    .line 44
    .line 45
    .line 46
    move-result-object p2

    .line 47
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 48
    .line 49
    .line 50
    move-result-object v0

    .line 51
    const-string v1, "tryLock"

    .line 52
    .line 53
    invoke-virtual {v0, v1, p1}, Ljava/lang/Class;->getMethod(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;

    .line 54
    .line 55
    .line 56
    move-result-object v0

    .line 57
    invoke-virtual {v0, p2, p1}, Ljava/lang/reflect/Method;->invoke(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;

    .line 58
    .line 59
    .line 60
    move-result-object p2

    .line 61
    iput-object p2, p0, Lorg/eclipse/paho/mqttv5/client/internal/FileLock;->fileLock:Ljava/lang/Object;
    :try_end_0
    .catch Ljava/lang/NoSuchMethodException; {:try_start_0 .. :try_end_0} :catch_2
    .catch Ljava/lang/IllegalArgumentException; {:try_start_0 .. :try_end_0} :catch_1
    .catch Ljava/lang/IllegalAccessException; {:try_start_0 .. :try_end_0} :catch_0

    .line 62
    .line 63
    goto :goto_0

    .line 64
    :catch_0
    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/client/internal/FileLock;->fileLock:Ljava/lang/Object;

    .line 65
    .line 66
    goto :goto_0

    .line 67
    :catch_1
    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/client/internal/FileLock;->fileLock:Ljava/lang/Object;

    .line 68
    .line 69
    goto :goto_0

    .line 70
    :catch_2
    iput-object p1, p0, Lorg/eclipse/paho/mqttv5/client/internal/FileLock;->fileLock:Ljava/lang/Object;

    .line 71
    .line 72
    :goto_0
    iget-object p1, p0, Lorg/eclipse/paho/mqttv5/client/internal/FileLock;->fileLock:Ljava/lang/Object;

    .line 73
    .line 74
    if-eqz p1, :cond_0

    .line 75
    .line 76
    goto :goto_1

    .line 77
    :cond_0
    invoke-virtual {p0}, Lorg/eclipse/paho/mqttv5/client/internal/FileLock;->release()V

    .line 78
    .line 79
    .line 80
    new-instance p0, Ljava/lang/Exception;

    .line 81
    .line 82
    const-string p1, "Problem obtaining file lock"

    .line 83
    .line 84
    invoke-direct {p0, p1}, Ljava/lang/Exception;-><init>(Ljava/lang/String;)V

    .line 85
    .line 86
    .line 87
    throw p0

    .line 88
    :cond_1
    :goto_1
    return-void
.end method


# virtual methods
.method public release()V
    .locals 3

    .line 1
    const/4 v0, 0x0

    .line 2
    :try_start_0
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/FileLock;->fileLock:Ljava/lang/Object;

    .line 3
    .line 4
    if-eqz v1, :cond_0

    .line 5
    .line 6
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 7
    .line 8
    .line 9
    move-result-object v1

    .line 10
    const-string v2, "release"

    .line 11
    .line 12
    invoke-virtual {v1, v2, v0}, Ljava/lang/Class;->getMethod(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;

    .line 13
    .line 14
    .line 15
    move-result-object v1

    .line 16
    iget-object v2, p0, Lorg/eclipse/paho/mqttv5/client/internal/FileLock;->fileLock:Ljava/lang/Object;

    .line 17
    .line 18
    invoke-virtual {v1, v2, v0}, Ljava/lang/reflect/Method;->invoke(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    iput-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/FileLock;->fileLock:Ljava/lang/Object;
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 22
    .line 23
    :catch_0
    :cond_0
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/FileLock;->file:Ljava/io/RandomAccessFile;

    .line 24
    .line 25
    if-eqz v1, :cond_1

    .line 26
    .line 27
    :try_start_1
    invoke-virtual {v1}, Ljava/io/RandomAccessFile;->close()V
    :try_end_1
    .catch Ljava/io/IOException; {:try_start_1 .. :try_end_1} :catch_1

    .line 28
    .line 29
    .line 30
    :catch_1
    iput-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/FileLock;->file:Ljava/io/RandomAccessFile;

    .line 31
    .line 32
    :cond_1
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/FileLock;->lockFile:Ljava/io/File;

    .line 33
    .line 34
    if-eqz v1, :cond_2

    .line 35
    .line 36
    invoke-virtual {v1}, Ljava/io/File;->exists()Z

    .line 37
    .line 38
    .line 39
    move-result v1

    .line 40
    if-eqz v1, :cond_2

    .line 41
    .line 42
    iget-object v1, p0, Lorg/eclipse/paho/mqttv5/client/internal/FileLock;->lockFile:Ljava/io/File;

    .line 43
    .line 44
    invoke-virtual {v1}, Ljava/io/File;->delete()Z

    .line 45
    .line 46
    .line 47
    :cond_2
    iput-object v0, p0, Lorg/eclipse/paho/mqttv5/client/internal/FileLock;->lockFile:Ljava/io/File;

    .line 48
    .line 49
    return-void
.end method
