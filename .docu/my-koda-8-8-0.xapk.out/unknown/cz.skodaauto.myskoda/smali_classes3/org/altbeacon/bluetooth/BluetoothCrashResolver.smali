.class public Lorg/altbeacon/bluetooth/BluetoothCrashResolver;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lorg/altbeacon/bluetooth/BluetoothCrashResolver$UpdateNotifier;
    }
.end annotation


# static fields
.field private static final BLUEDROID_MAX_BLUETOOTH_MAC_COUNT:I = 0x7c6

.field private static final BLUEDROID_POST_DISCOVERY_ESTIMATED_BLUETOOTH_MAC_COUNT:I = 0x190

.field private static final DISTINCT_BLUETOOTH_ADDRESSES_FILE:Ljava/lang/String; = "BluetoothCrashResolverState.txt"

.field private static final MIN_TIME_BETWEEN_STATE_SAVES_MILLIS:J = 0xea60L

.field private static final PREEMPTIVE_ACTION_ENABLED:Z = true

.field private static final SUSPICIOUSLY_SHORT_BLUETOOTH_OFF_INTERVAL_MILLIS:J = 0x258L

.field private static final TAG:Ljava/lang/String; = "BluetoothCrashResolver"

.field private static final TIME_TO_LET_DISCOVERY_RUN_MILLIS:I = 0x1388


# instance fields
.field private context:Landroid/content/Context;

.field private detectedCrashCount:I

.field private discoveryStartConfirmed:Z

.field private final distinctBluetoothAddresses:Ljava/util/Set;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/Set<",
            "Ljava/lang/String;",
            ">;"
        }
    .end annotation
.end field

.field private lastBluetoothCrashDetectionTime:J

.field private lastBluetoothOffTime:J

.field private lastBluetoothTurningOnTime:J

.field private lastRecoverySucceeded:Z

.field private lastStateSaveTime:J

.field private final receiver:Landroid/content/BroadcastReceiver;

.field private recoveryAttemptCount:I

.field private recoveryInProgress:Z

.field private updateNotifier:Lorg/altbeacon/bluetooth/BluetoothCrashResolver$UpdateNotifier;


# direct methods
.method public constructor <init>(Landroid/content/Context;)V
    .locals 3

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    const/4 v0, 0x0

    .line 5
    iput-boolean v0, p0, Lorg/altbeacon/bluetooth/BluetoothCrashResolver;->recoveryInProgress:Z

    .line 6
    .line 7
    iput-boolean v0, p0, Lorg/altbeacon/bluetooth/BluetoothCrashResolver;->discoveryStartConfirmed:Z

    .line 8
    .line 9
    const-wide/16 v1, 0x0

    .line 10
    .line 11
    iput-wide v1, p0, Lorg/altbeacon/bluetooth/BluetoothCrashResolver;->lastBluetoothOffTime:J

    .line 12
    .line 13
    iput-wide v1, p0, Lorg/altbeacon/bluetooth/BluetoothCrashResolver;->lastBluetoothTurningOnTime:J

    .line 14
    .line 15
    iput-wide v1, p0, Lorg/altbeacon/bluetooth/BluetoothCrashResolver;->lastBluetoothCrashDetectionTime:J

    .line 16
    .line 17
    iput v0, p0, Lorg/altbeacon/bluetooth/BluetoothCrashResolver;->detectedCrashCount:I

    .line 18
    .line 19
    iput v0, p0, Lorg/altbeacon/bluetooth/BluetoothCrashResolver;->recoveryAttemptCount:I

    .line 20
    .line 21
    iput-boolean v0, p0, Lorg/altbeacon/bluetooth/BluetoothCrashResolver;->lastRecoverySucceeded:Z

    .line 22
    .line 23
    iput-wide v1, p0, Lorg/altbeacon/bluetooth/BluetoothCrashResolver;->lastStateSaveTime:J

    .line 24
    .line 25
    const/4 v1, 0x0

    .line 26
    iput-object v1, p0, Lorg/altbeacon/bluetooth/BluetoothCrashResolver;->context:Landroid/content/Context;

    .line 27
    .line 28
    new-instance v1, Ljava/util/HashSet;

    .line 29
    .line 30
    invoke-direct {v1}, Ljava/util/HashSet;-><init>()V

    .line 31
    .line 32
    .line 33
    iput-object v1, p0, Lorg/altbeacon/bluetooth/BluetoothCrashResolver;->distinctBluetoothAddresses:Ljava/util/Set;

    .line 34
    .line 35
    new-instance v1, Lorg/altbeacon/bluetooth/BluetoothCrashResolver$1;

    .line 36
    .line 37
    invoke-direct {v1, p0}, Lorg/altbeacon/bluetooth/BluetoothCrashResolver$1;-><init>(Lorg/altbeacon/bluetooth/BluetoothCrashResolver;)V

    .line 38
    .line 39
    .line 40
    iput-object v1, p0, Lorg/altbeacon/bluetooth/BluetoothCrashResolver;->receiver:Landroid/content/BroadcastReceiver;

    .line 41
    .line 42
    invoke-virtual {p1}, Landroid/content/Context;->getApplicationContext()Landroid/content/Context;

    .line 43
    .line 44
    .line 45
    move-result-object p1

    .line 46
    iput-object p1, p0, Lorg/altbeacon/bluetooth/BluetoothCrashResolver;->context:Landroid/content/Context;

    .line 47
    .line 48
    const-string p1, "constructed"

    .line 49
    .line 50
    new-array v0, v0, [Ljava/lang/Object;

    .line 51
    .line 52
    const-string v1, "BluetoothCrashResolver"

    .line 53
    .line 54
    invoke-static {v1, p1, v0}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 55
    .line 56
    .line 57
    invoke-direct {p0}, Lorg/altbeacon/bluetooth/BluetoothCrashResolver;->loadState()V

    .line 58
    .line 59
    .line 60
    return-void
.end method

.method public static bridge synthetic a(Lorg/altbeacon/bluetooth/BluetoothCrashResolver;)J
    .locals 2

    .line 1
    iget-wide v0, p0, Lorg/altbeacon/bluetooth/BluetoothCrashResolver;->lastBluetoothOffTime:J

    .line 2
    .line 3
    return-wide v0
.end method

.method public static bridge synthetic b(Lorg/altbeacon/bluetooth/BluetoothCrashResolver;)J
    .locals 2

    .line 1
    iget-wide v0, p0, Lorg/altbeacon/bluetooth/BluetoothCrashResolver;->lastBluetoothTurningOnTime:J

    .line 2
    .line 3
    return-wide v0
.end method

.method public static bridge synthetic c(Lorg/altbeacon/bluetooth/BluetoothCrashResolver;)Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Lorg/altbeacon/bluetooth/BluetoothCrashResolver;->recoveryInProgress:Z

    .line 2
    .line 3
    return p0
.end method

.method private cancelDiscovery()V
    .locals 4

    .line 1
    const-string v0, "BluetoothCrashResolver"

    .line 2
    .line 3
    const-wide/16 v1, 0x1388

    .line 4
    .line 5
    const/4 v3, 0x0

    .line 6
    :try_start_0
    invoke-static {v1, v2}, Ljava/lang/Thread;->sleep(J)V

    .line 7
    .line 8
    .line 9
    iget-boolean p0, p0, Lorg/altbeacon/bluetooth/BluetoothCrashResolver;->discoveryStartConfirmed:Z

    .line 10
    .line 11
    if-nez p0, :cond_0

    .line 12
    .line 13
    const-string p0, "BluetoothAdapter.ACTION_DISCOVERY_STARTED never received.  Recovery may fail."

    .line 14
    .line 15
    new-array v1, v3, [Ljava/lang/Object;

    .line 16
    .line 17
    invoke-static {v0, p0, v1}, Lorg/altbeacon/beacon/logging/LogManager;->w(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 18
    .line 19
    .line 20
    :cond_0
    invoke-static {}, Landroid/bluetooth/BluetoothAdapter;->getDefaultAdapter()Landroid/bluetooth/BluetoothAdapter;

    .line 21
    .line 22
    .line 23
    move-result-object p0

    .line 24
    invoke-virtual {p0}, Landroid/bluetooth/BluetoothAdapter;->isDiscovering()Z

    .line 25
    .line 26
    .line 27
    move-result v1

    .line 28
    if-eqz v1, :cond_1

    .line 29
    .line 30
    const-string v1, "Cancelling discovery"

    .line 31
    .line 32
    new-array v2, v3, [Ljava/lang/Object;

    .line 33
    .line 34
    invoke-static {v0, v1, v2}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 35
    .line 36
    .line 37
    invoke-virtual {p0}, Landroid/bluetooth/BluetoothAdapter;->cancelDiscovery()Z

    .line 38
    .line 39
    .line 40
    return-void

    .line 41
    :cond_1
    const-string p0, "Discovery not running.  Won\'t cancel it"

    .line 42
    .line 43
    new-array v1, v3, [Ljava/lang/Object;

    .line 44
    .line 45
    invoke-static {v0, p0, v1}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V
    :try_end_0
    .catch Ljava/lang/InterruptedException; {:try_start_0 .. :try_end_0} :catch_0

    .line 46
    .line 47
    .line 48
    return-void

    .line 49
    :catch_0
    const-string p0, "DiscoveryCanceller sleep interrupted."

    .line 50
    .line 51
    new-array v1, v3, [Ljava/lang/Object;

    .line 52
    .line 53
    invoke-static {v0, p0, v1}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 54
    .line 55
    .line 56
    return-void
.end method

.method public static bridge synthetic d(Lorg/altbeacon/bluetooth/BluetoothCrashResolver;)V
    .locals 1

    .line 1
    const/4 v0, 0x1

    .line 2
    iput-boolean v0, p0, Lorg/altbeacon/bluetooth/BluetoothCrashResolver;->discoveryStartConfirmed:Z

    .line 3
    .line 4
    return-void
.end method

.method public static bridge synthetic e(Lorg/altbeacon/bluetooth/BluetoothCrashResolver;J)V
    .locals 0

    .line 1
    iput-wide p1, p0, Lorg/altbeacon/bluetooth/BluetoothCrashResolver;->lastBluetoothOffTime:J

    .line 2
    .line 3
    return-void
.end method

.method public static bridge synthetic f(Lorg/altbeacon/bluetooth/BluetoothCrashResolver;J)V
    .locals 0

    .line 1
    iput-wide p1, p0, Lorg/altbeacon/bluetooth/BluetoothCrashResolver;->lastBluetoothTurningOnTime:J

    .line 2
    .line 3
    return-void
.end method

.method private finishRecovery()V
    .locals 4

    .line 1
    const-string v0, "BluetoothCrashResolver"

    .line 2
    .line 3
    const-string v1, "Recovery attempt finished"

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    new-array v3, v2, [Ljava/lang/Object;

    .line 7
    .line 8
    invoke-static {v0, v1, v3}, Lorg/altbeacon/beacon/logging/LogManager;->w(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 9
    .line 10
    .line 11
    iget-object v0, p0, Lorg/altbeacon/bluetooth/BluetoothCrashResolver;->distinctBluetoothAddresses:Ljava/util/Set;

    .line 12
    .line 13
    monitor-enter v0

    .line 14
    :try_start_0
    iget-object v1, p0, Lorg/altbeacon/bluetooth/BluetoothCrashResolver;->distinctBluetoothAddresses:Ljava/util/Set;

    .line 15
    .line 16
    invoke-interface {v1}, Ljava/util/Set;->clear()V

    .line 17
    .line 18
    .line 19
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 20
    iput-boolean v2, p0, Lorg/altbeacon/bluetooth/BluetoothCrashResolver;->recoveryInProgress:Z

    .line 21
    .line 22
    return-void

    .line 23
    :catchall_0
    move-exception p0

    .line 24
    :try_start_1
    monitor-exit v0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 25
    throw p0
.end method

.method public static bridge synthetic g(Lorg/altbeacon/bluetooth/BluetoothCrashResolver;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Lorg/altbeacon/bluetooth/BluetoothCrashResolver;->finishRecovery()V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method private getCrashRiskDeviceCount()I
    .locals 0

    .line 1
    const/16 p0, 0x636

    .line 2
    .line 3
    return p0
.end method

.method private loadState()V
    .locals 6

    .line 1
    const-string v0, "BluetoothCrashResolver"

    .line 2
    .line 3
    const-string v1, "BluetoothCrashResolverState.txt"

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    :try_start_0
    iget-object v3, p0, Lorg/altbeacon/bluetooth/BluetoothCrashResolver;->context:Landroid/content/Context;

    .line 7
    .line 8
    invoke-virtual {v3, v1}, Landroid/content/Context;->openFileInput(Ljava/lang/String;)Ljava/io/FileInputStream;

    .line 9
    .line 10
    .line 11
    move-result-object v3

    .line 12
    new-instance v4, Ljava/io/BufferedReader;

    .line 13
    .line 14
    new-instance v5, Ljava/io/InputStreamReader;

    .line 15
    .line 16
    invoke-direct {v5, v3}, Ljava/io/InputStreamReader;-><init>(Ljava/io/InputStream;)V

    .line 17
    .line 18
    .line 19
    invoke-direct {v4, v5}, Ljava/io/BufferedReader;-><init>(Ljava/io/Reader;)V
    :try_end_0
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_3
    .catch Ljava/lang/NumberFormatException; {:try_start_0 .. :try_end_0} :catch_2
    .catchall {:try_start_0 .. :try_end_0} :catchall_1

    .line 20
    .line 21
    .line 22
    :try_start_1
    invoke-virtual {v4}, Ljava/io/BufferedReader;->readLine()Ljava/lang/String;

    .line 23
    .line 24
    .line 25
    move-result-object v2

    .line 26
    if-eqz v2, :cond_0

    .line 27
    .line 28
    invoke-static {v2}, Ljava/lang/Long;->parseLong(Ljava/lang/String;)J

    .line 29
    .line 30
    .line 31
    move-result-wide v2

    .line 32
    iput-wide v2, p0, Lorg/altbeacon/bluetooth/BluetoothCrashResolver;->lastBluetoothCrashDetectionTime:J

    .line 33
    .line 34
    goto :goto_0

    .line 35
    :catchall_0
    move-exception p0

    .line 36
    move-object v2, v4

    .line 37
    goto/16 :goto_6

    .line 38
    .line 39
    :catch_0
    move-object v2, v4

    .line 40
    goto :goto_2

    .line 41
    :catch_1
    move-object v2, v4

    .line 42
    goto :goto_4

    .line 43
    :cond_0
    :goto_0
    invoke-virtual {v4}, Ljava/io/BufferedReader;->readLine()Ljava/lang/String;

    .line 44
    .line 45
    .line 46
    move-result-object v2

    .line 47
    if-eqz v2, :cond_1

    .line 48
    .line 49
    invoke-static {v2}, Ljava/lang/Integer;->parseInt(Ljava/lang/String;)I

    .line 50
    .line 51
    .line 52
    move-result v2

    .line 53
    iput v2, p0, Lorg/altbeacon/bluetooth/BluetoothCrashResolver;->detectedCrashCount:I

    .line 54
    .line 55
    :cond_1
    invoke-virtual {v4}, Ljava/io/BufferedReader;->readLine()Ljava/lang/String;

    .line 56
    .line 57
    .line 58
    move-result-object v2

    .line 59
    if-eqz v2, :cond_2

    .line 60
    .line 61
    invoke-static {v2}, Ljava/lang/Integer;->parseInt(Ljava/lang/String;)I

    .line 62
    .line 63
    .line 64
    move-result v2

    .line 65
    iput v2, p0, Lorg/altbeacon/bluetooth/BluetoothCrashResolver;->recoveryAttemptCount:I

    .line 66
    .line 67
    :cond_2
    invoke-virtual {v4}, Ljava/io/BufferedReader;->readLine()Ljava/lang/String;

    .line 68
    .line 69
    .line 70
    move-result-object v2

    .line 71
    if-eqz v2, :cond_3

    .line 72
    .line 73
    const/4 v3, 0x0

    .line 74
    iput-boolean v3, p0, Lorg/altbeacon/bluetooth/BluetoothCrashResolver;->lastRecoverySucceeded:Z

    .line 75
    .line 76
    const-string v3, "1"

    .line 77
    .line 78
    invoke-virtual {v2, v3}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 79
    .line 80
    .line 81
    move-result v2

    .line 82
    if-eqz v2, :cond_3

    .line 83
    .line 84
    const/4 v2, 0x1

    .line 85
    iput-boolean v2, p0, Lorg/altbeacon/bluetooth/BluetoothCrashResolver;->lastRecoverySucceeded:Z

    .line 86
    .line 87
    :cond_3
    :goto_1
    invoke-virtual {v4}, Ljava/io/BufferedReader;->readLine()Ljava/lang/String;

    .line 88
    .line 89
    .line 90
    move-result-object v2

    .line 91
    if-eqz v2, :cond_4

    .line 92
    .line 93
    iget-object v3, p0, Lorg/altbeacon/bluetooth/BluetoothCrashResolver;->distinctBluetoothAddresses:Ljava/util/Set;

    .line 94
    .line 95
    invoke-interface {v3, v2}, Ljava/util/Set;->add(Ljava/lang/Object;)Z
    :try_end_1
    .catch Ljava/io/IOException; {:try_start_1 .. :try_end_1} :catch_1
    .catch Ljava/lang/NumberFormatException; {:try_start_1 .. :try_end_1} :catch_0
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 96
    .line 97
    .line 98
    goto :goto_1

    .line 99
    :cond_4
    :try_start_2
    invoke-virtual {v4}, Ljava/io/BufferedReader;->close()V
    :try_end_2
    .catch Ljava/io/IOException; {:try_start_2 .. :try_end_2} :catch_4

    .line 100
    .line 101
    .line 102
    goto :goto_5

    .line 103
    :catchall_1
    move-exception p0

    .line 104
    goto :goto_6

    .line 105
    :catch_2
    :goto_2
    :try_start_3
    const-string v3, "Can\'t parse file %s"

    .line 106
    .line 107
    filled-new-array {v1}, [Ljava/lang/Object;

    .line 108
    .line 109
    .line 110
    move-result-object v1

    .line 111
    invoke-static {v0, v3, v1}, Lorg/altbeacon/beacon/logging/LogManager;->w(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_1

    .line 112
    .line 113
    .line 114
    if-eqz v2, :cond_5

    .line 115
    .line 116
    :goto_3
    :try_start_4
    invoke-virtual {v2}, Ljava/io/BufferedReader;->close()V
    :try_end_4
    .catch Ljava/io/IOException; {:try_start_4 .. :try_end_4} :catch_4

    .line 117
    .line 118
    .line 119
    goto :goto_5

    .line 120
    :catch_3
    :goto_4
    :try_start_5
    const-string v3, "Can\'t read macs from %s"

    .line 121
    .line 122
    filled-new-array {v1}, [Ljava/lang/Object;

    .line 123
    .line 124
    .line 125
    move-result-object v1

    .line 126
    invoke-static {v0, v3, v1}, Lorg/altbeacon/beacon/logging/LogManager;->w(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_1

    .line 127
    .line 128
    .line 129
    if-eqz v2, :cond_5

    .line 130
    .line 131
    goto :goto_3

    .line 132
    :catch_4
    :cond_5
    :goto_5
    iget-object p0, p0, Lorg/altbeacon/bluetooth/BluetoothCrashResolver;->distinctBluetoothAddresses:Ljava/util/Set;

    .line 133
    .line 134
    invoke-interface {p0}, Ljava/util/Set;->size()I

    .line 135
    .line 136
    .line 137
    move-result p0

    .line 138
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 139
    .line 140
    .line 141
    move-result-object p0

    .line 142
    filled-new-array {p0}, [Ljava/lang/Object;

    .line 143
    .line 144
    .line 145
    move-result-object p0

    .line 146
    const-string v1, "Read %s Bluetooth addresses"

    .line 147
    .line 148
    invoke-static {v0, v1, p0}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 149
    .line 150
    .line 151
    return-void

    .line 152
    :goto_6
    if-eqz v2, :cond_6

    .line 153
    .line 154
    :try_start_6
    invoke-virtual {v2}, Ljava/io/BufferedReader;->close()V
    :try_end_6
    .catch Ljava/io/IOException; {:try_start_6 .. :try_end_6} :catch_5

    .line 155
    .line 156
    .line 157
    :catch_5
    :cond_6
    throw p0
.end method

.method private processStateChange()V
    .locals 4

    .line 1
    iget-object v0, p0, Lorg/altbeacon/bluetooth/BluetoothCrashResolver;->updateNotifier:Lorg/altbeacon/bluetooth/BluetoothCrashResolver$UpdateNotifier;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    invoke-interface {v0}, Lorg/altbeacon/bluetooth/BluetoothCrashResolver$UpdateNotifier;->dataUpdated()V

    .line 6
    .line 7
    .line 8
    :cond_0
    invoke-static {}, Landroid/os/SystemClock;->elapsedRealtime()J

    .line 9
    .line 10
    .line 11
    move-result-wide v0

    .line 12
    iget-wide v2, p0, Lorg/altbeacon/bluetooth/BluetoothCrashResolver;->lastStateSaveTime:J

    .line 13
    .line 14
    sub-long/2addr v0, v2

    .line 15
    const-wide/32 v2, 0xea60

    .line 16
    .line 17
    .line 18
    cmp-long v0, v0, v2

    .line 19
    .line 20
    if-lez v0, :cond_1

    .line 21
    .line 22
    invoke-direct {p0}, Lorg/altbeacon/bluetooth/BluetoothCrashResolver;->saveState()V

    .line 23
    .line 24
    .line 25
    :cond_1
    return-void
.end method

.method private saveState()V
    .locals 5

    .line 1
    invoke-static {}, Landroid/os/SystemClock;->elapsedRealtime()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    iput-wide v0, p0, Lorg/altbeacon/bluetooth/BluetoothCrashResolver;->lastStateSaveTime:J

    .line 6
    .line 7
    const/4 v0, 0x0

    .line 8
    :try_start_0
    iget-object v1, p0, Lorg/altbeacon/bluetooth/BluetoothCrashResolver;->context:Landroid/content/Context;

    .line 9
    .line 10
    const-string v2, "BluetoothCrashResolverState.txt"

    .line 11
    .line 12
    const/4 v3, 0x0

    .line 13
    invoke-virtual {v1, v2, v3}, Landroid/content/Context;->openFileOutput(Ljava/lang/String;I)Ljava/io/FileOutputStream;

    .line 14
    .line 15
    .line 16
    move-result-object v1

    .line 17
    new-instance v2, Ljava/io/OutputStreamWriter;

    .line 18
    .line 19
    invoke-direct {v2, v1}, Ljava/io/OutputStreamWriter;-><init>(Ljava/io/OutputStream;)V
    :try_end_0
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_1
    .catchall {:try_start_0 .. :try_end_0} :catchall_2

    .line 20
    .line 21
    .line 22
    :try_start_1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 23
    .line 24
    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    .line 25
    .line 26
    .line 27
    iget-wide v3, p0, Lorg/altbeacon/bluetooth/BluetoothCrashResolver;->lastBluetoothCrashDetectionTime:J

    .line 28
    .line 29
    invoke-virtual {v0, v3, v4}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    .line 30
    .line 31
    .line 32
    const-string v1, "\n"

    .line 33
    .line 34
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 35
    .line 36
    .line 37
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 38
    .line 39
    .line 40
    move-result-object v0

    .line 41
    invoke-virtual {v2, v0}, Ljava/io/Writer;->write(Ljava/lang/String;)V

    .line 42
    .line 43
    .line 44
    new-instance v0, Ljava/lang/StringBuilder;

    .line 45
    .line 46
    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    .line 47
    .line 48
    .line 49
    iget v1, p0, Lorg/altbeacon/bluetooth/BluetoothCrashResolver;->detectedCrashCount:I

    .line 50
    .line 51
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 52
    .line 53
    .line 54
    const-string v1, "\n"

    .line 55
    .line 56
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 57
    .line 58
    .line 59
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 60
    .line 61
    .line 62
    move-result-object v0

    .line 63
    invoke-virtual {v2, v0}, Ljava/io/Writer;->write(Ljava/lang/String;)V

    .line 64
    .line 65
    .line 66
    new-instance v0, Ljava/lang/StringBuilder;

    .line 67
    .line 68
    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    .line 69
    .line 70
    .line 71
    iget v1, p0, Lorg/altbeacon/bluetooth/BluetoothCrashResolver;->recoveryAttemptCount:I

    .line 72
    .line 73
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 74
    .line 75
    .line 76
    const-string v1, "\n"

    .line 77
    .line 78
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 79
    .line 80
    .line 81
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 82
    .line 83
    .line 84
    move-result-object v0

    .line 85
    invoke-virtual {v2, v0}, Ljava/io/Writer;->write(Ljava/lang/String;)V

    .line 86
    .line 87
    .line 88
    iget-boolean v0, p0, Lorg/altbeacon/bluetooth/BluetoothCrashResolver;->lastRecoverySucceeded:Z

    .line 89
    .line 90
    if-eqz v0, :cond_0

    .line 91
    .line 92
    const-string v0, "1\n"

    .line 93
    .line 94
    goto :goto_0

    .line 95
    :catchall_0
    move-exception p0

    .line 96
    move-object v0, v2

    .line 97
    goto :goto_5

    .line 98
    :catch_0
    move-object v0, v2

    .line 99
    goto :goto_3

    .line 100
    :cond_0
    const-string v0, "0\n"

    .line 101
    .line 102
    :goto_0
    invoke-virtual {v2, v0}, Ljava/io/Writer;->write(Ljava/lang/String;)V

    .line 103
    .line 104
    .line 105
    iget-object v0, p0, Lorg/altbeacon/bluetooth/BluetoothCrashResolver;->distinctBluetoothAddresses:Ljava/util/Set;

    .line 106
    .line 107
    monitor-enter v0
    :try_end_1
    .catch Ljava/io/IOException; {:try_start_1 .. :try_end_1} :catch_0
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 108
    :try_start_2
    iget-object v1, p0, Lorg/altbeacon/bluetooth/BluetoothCrashResolver;->distinctBluetoothAddresses:Ljava/util/Set;

    .line 109
    .line 110
    invoke-interface {v1}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 111
    .line 112
    .line 113
    move-result-object v1

    .line 114
    :goto_1
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 115
    .line 116
    .line 117
    move-result v3

    .line 118
    if-eqz v3, :cond_1

    .line 119
    .line 120
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 121
    .line 122
    .line 123
    move-result-object v3

    .line 124
    check-cast v3, Ljava/lang/String;

    .line 125
    .line 126
    invoke-virtual {v2, v3}, Ljava/io/Writer;->write(Ljava/lang/String;)V

    .line 127
    .line 128
    .line 129
    const-string v3, "\n"

    .line 130
    .line 131
    invoke-virtual {v2, v3}, Ljava/io/Writer;->write(Ljava/lang/String;)V

    .line 132
    .line 133
    .line 134
    goto :goto_1

    .line 135
    :catchall_1
    move-exception v1

    .line 136
    goto :goto_2

    .line 137
    :cond_1
    monitor-exit v0
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_1

    .line 138
    :try_start_3
    invoke-virtual {v2}, Ljava/io/OutputStreamWriter;->close()V
    :try_end_3
    .catch Ljava/io/IOException; {:try_start_3 .. :try_end_3} :catch_2

    .line 139
    .line 140
    .line 141
    goto :goto_4

    .line 142
    :goto_2
    :try_start_4
    monitor-exit v0
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_1

    .line 143
    :try_start_5
    throw v1
    :try_end_5
    .catch Ljava/io/IOException; {:try_start_5 .. :try_end_5} :catch_0
    .catchall {:try_start_5 .. :try_end_5} :catchall_0

    .line 144
    :catchall_2
    move-exception p0

    .line 145
    goto :goto_5

    .line 146
    :catch_1
    :goto_3
    :try_start_6
    const-string v1, "BluetoothCrashResolver"

    .line 147
    .line 148
    const-string v2, "Can\'t write macs to %s"

    .line 149
    .line 150
    const-string v3, "BluetoothCrashResolverState.txt"

    .line 151
    .line 152
    filled-new-array {v3}, [Ljava/lang/Object;

    .line 153
    .line 154
    .line 155
    move-result-object v3

    .line 156
    invoke-static {v1, v2, v3}, Lorg/altbeacon/beacon/logging/LogManager;->w(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V
    :try_end_6
    .catchall {:try_start_6 .. :try_end_6} :catchall_2

    .line 157
    .line 158
    .line 159
    if-eqz v0, :cond_2

    .line 160
    .line 161
    :try_start_7
    invoke-virtual {v0}, Ljava/io/OutputStreamWriter;->close()V
    :try_end_7
    .catch Ljava/io/IOException; {:try_start_7 .. :try_end_7} :catch_2

    .line 162
    .line 163
    .line 164
    :catch_2
    :cond_2
    :goto_4
    const-string v0, "BluetoothCrashResolver"

    .line 165
    .line 166
    const-string v1, "Wrote %s Bluetooth addresses"

    .line 167
    .line 168
    iget-object p0, p0, Lorg/altbeacon/bluetooth/BluetoothCrashResolver;->distinctBluetoothAddresses:Ljava/util/Set;

    .line 169
    .line 170
    invoke-interface {p0}, Ljava/util/Set;->size()I

    .line 171
    .line 172
    .line 173
    move-result p0

    .line 174
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 175
    .line 176
    .line 177
    move-result-object p0

    .line 178
    filled-new-array {p0}, [Ljava/lang/Object;

    .line 179
    .line 180
    .line 181
    move-result-object p0

    .line 182
    invoke-static {v0, v1, p0}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 183
    .line 184
    .line 185
    return-void

    .line 186
    :goto_5
    if-eqz v0, :cond_3

    .line 187
    .line 188
    :try_start_8
    invoke-virtual {v0}, Ljava/io/OutputStreamWriter;->close()V
    :try_end_8
    .catch Ljava/io/IOException; {:try_start_8 .. :try_end_8} :catch_3

    .line 189
    .line 190
    .line 191
    :catch_3
    :cond_3
    throw p0
.end method

.method private startRecovery()V
    .locals 6
    .annotation build Landroid/annotation/TargetApi;
        value = 0x11
    .end annotation

    .line 1
    iget v0, p0, Lorg/altbeacon/bluetooth/BluetoothCrashResolver;->recoveryAttemptCount:I

    .line 2
    .line 3
    const/4 v1, 0x1

    .line 4
    add-int/2addr v0, v1

    .line 5
    iput v0, p0, Lorg/altbeacon/bluetooth/BluetoothCrashResolver;->recoveryAttemptCount:I

    .line 6
    .line 7
    invoke-static {}, Landroid/bluetooth/BluetoothAdapter;->getDefaultAdapter()Landroid/bluetooth/BluetoothAdapter;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    const/4 v2, 0x0

    .line 12
    new-array v3, v2, [Ljava/lang/Object;

    .line 13
    .line 14
    const-string v4, "BluetoothCrashResolver"

    .line 15
    .line 16
    const-string v5, "about to check if discovery is active"

    .line 17
    .line 18
    invoke-static {v4, v5, v3}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 19
    .line 20
    .line 21
    invoke-virtual {v0}, Landroid/bluetooth/BluetoothAdapter;->isDiscovering()Z

    .line 22
    .line 23
    .line 24
    move-result v3

    .line 25
    if-nez v3, :cond_1

    .line 26
    .line 27
    const-string v3, "Recovery attempt started"

    .line 28
    .line 29
    new-array v5, v2, [Ljava/lang/Object;

    .line 30
    .line 31
    invoke-static {v4, v3, v5}, Lorg/altbeacon/beacon/logging/LogManager;->w(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 32
    .line 33
    .line 34
    iput-boolean v1, p0, Lorg/altbeacon/bluetooth/BluetoothCrashResolver;->recoveryInProgress:Z

    .line 35
    .line 36
    iput-boolean v2, p0, Lorg/altbeacon/bluetooth/BluetoothCrashResolver;->discoveryStartConfirmed:Z

    .line 37
    .line 38
    const-string v1, "about to command discovery"

    .line 39
    .line 40
    new-array v3, v2, [Ljava/lang/Object;

    .line 41
    .line 42
    invoke-static {v4, v1, v3}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 43
    .line 44
    .line 45
    invoke-virtual {v0}, Landroid/bluetooth/BluetoothAdapter;->startDiscovery()Z

    .line 46
    .line 47
    .line 48
    move-result v1

    .line 49
    if-nez v1, :cond_0

    .line 50
    .line 51
    const-string v1, "Can\'t start discovery.  Is Bluetooth turned on?"

    .line 52
    .line 53
    new-array v2, v2, [Ljava/lang/Object;

    .line 54
    .line 55
    invoke-static {v4, v1, v2}, Lorg/altbeacon/beacon/logging/LogManager;->w(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 56
    .line 57
    .line 58
    :cond_0
    invoke-virtual {v0}, Landroid/bluetooth/BluetoothAdapter;->isDiscovering()Z

    .line 59
    .line 60
    .line 61
    move-result v0

    .line 62
    invoke-static {v0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 63
    .line 64
    .line 65
    move-result-object v0

    .line 66
    filled-new-array {v0}, [Ljava/lang/Object;

    .line 67
    .line 68
    .line 69
    move-result-object v0

    .line 70
    const-string v1, "startDiscovery commanded.  isDiscovering()=%s"

    .line 71
    .line 72
    invoke-static {v4, v1, v0}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 73
    .line 74
    .line 75
    const/16 v0, 0x1388

    .line 76
    .line 77
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 78
    .line 79
    .line 80
    move-result-object v0

    .line 81
    filled-new-array {v0}, [Ljava/lang/Object;

    .line 82
    .line 83
    .line 84
    move-result-object v0

    .line 85
    const-string v1, "We will be cancelling this discovery in %s milliseconds."

    .line 86
    .line 87
    invoke-static {v4, v1, v0}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 88
    .line 89
    .line 90
    invoke-direct {p0}, Lorg/altbeacon/bluetooth/BluetoothCrashResolver;->cancelDiscovery()V

    .line 91
    .line 92
    .line 93
    return-void

    .line 94
    :cond_1
    const-string p0, "Already discovering.  Recovery attempt abandoned."

    .line 95
    .line 96
    new-array v0, v2, [Ljava/lang/Object;

    .line 97
    .line 98
    invoke-static {v4, p0, v0}, Lorg/altbeacon/beacon/logging/LogManager;->w(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 99
    .line 100
    .line 101
    return-void
.end method


# virtual methods
.method public crashDetected()V
    .locals 5

    .line 1
    const/4 v0, 0x0

    .line 2
    new-array v1, v0, [Ljava/lang/Object;

    .line 3
    .line 4
    const-string v2, "BluetoothCrashResolver"

    .line 5
    .line 6
    const-string v3, "BluetoothService crash detected"

    .line 7
    .line 8
    invoke-static {v2, v3, v1}, Lorg/altbeacon/beacon/logging/LogManager;->w(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 9
    .line 10
    .line 11
    iget-object v1, p0, Lorg/altbeacon/bluetooth/BluetoothCrashResolver;->distinctBluetoothAddresses:Ljava/util/Set;

    .line 12
    .line 13
    invoke-interface {v1}, Ljava/util/Set;->size()I

    .line 14
    .line 15
    .line 16
    move-result v1

    .line 17
    if-lez v1, :cond_0

    .line 18
    .line 19
    iget-object v1, p0, Lorg/altbeacon/bluetooth/BluetoothCrashResolver;->distinctBluetoothAddresses:Ljava/util/Set;

    .line 20
    .line 21
    invoke-interface {v1}, Ljava/util/Set;->size()I

    .line 22
    .line 23
    .line 24
    move-result v1

    .line 25
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 26
    .line 27
    .line 28
    move-result-object v1

    .line 29
    filled-new-array {v1}, [Ljava/lang/Object;

    .line 30
    .line 31
    .line 32
    move-result-object v1

    .line 33
    const-string v3, "Distinct Bluetooth devices seen at crash: %s"

    .line 34
    .line 35
    invoke-static {v2, v3, v1}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 36
    .line 37
    .line 38
    :cond_0
    invoke-static {}, Landroid/os/SystemClock;->elapsedRealtime()J

    .line 39
    .line 40
    .line 41
    move-result-wide v3

    .line 42
    iput-wide v3, p0, Lorg/altbeacon/bluetooth/BluetoothCrashResolver;->lastBluetoothCrashDetectionTime:J

    .line 43
    .line 44
    iget v1, p0, Lorg/altbeacon/bluetooth/BluetoothCrashResolver;->detectedCrashCount:I

    .line 45
    .line 46
    add-int/lit8 v1, v1, 0x1

    .line 47
    .line 48
    iput v1, p0, Lorg/altbeacon/bluetooth/BluetoothCrashResolver;->detectedCrashCount:I

    .line 49
    .line 50
    iget-boolean v1, p0, Lorg/altbeacon/bluetooth/BluetoothCrashResolver;->recoveryInProgress:Z

    .line 51
    .line 52
    if-eqz v1, :cond_1

    .line 53
    .line 54
    const-string v1, "Ignoring Bluetooth crash because recovery is already in progress."

    .line 55
    .line 56
    new-array v0, v0, [Ljava/lang/Object;

    .line 57
    .line 58
    invoke-static {v2, v1, v0}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 59
    .line 60
    .line 61
    goto :goto_0

    .line 62
    :cond_1
    invoke-direct {p0}, Lorg/altbeacon/bluetooth/BluetoothCrashResolver;->startRecovery()V

    .line 63
    .line 64
    .line 65
    :goto_0
    invoke-direct {p0}, Lorg/altbeacon/bluetooth/BluetoothCrashResolver;->processStateChange()V

    .line 66
    .line 67
    .line 68
    return-void
.end method

.method public disableDebug()V
    .locals 0
    .annotation runtime Ljava/lang/Deprecated;
    .end annotation

    .line 1
    return-void
.end method

.method public enableDebug()V
    .locals 0
    .annotation runtime Ljava/lang/Deprecated;
    .end annotation

    .line 1
    return-void
.end method

.method public forceFlush()V
    .locals 0

    .line 1
    invoke-direct {p0}, Lorg/altbeacon/bluetooth/BluetoothCrashResolver;->startRecovery()V

    .line 2
    .line 3
    .line 4
    invoke-direct {p0}, Lorg/altbeacon/bluetooth/BluetoothCrashResolver;->processStateChange()V

    .line 5
    .line 6
    .line 7
    return-void
.end method

.method public getDetectedCrashCount()I
    .locals 0

    .line 1
    iget p0, p0, Lorg/altbeacon/bluetooth/BluetoothCrashResolver;->detectedCrashCount:I

    .line 2
    .line 3
    return p0
.end method

.method public getLastBluetoothCrashDetectionTime()J
    .locals 2

    .line 1
    iget-wide v0, p0, Lorg/altbeacon/bluetooth/BluetoothCrashResolver;->lastBluetoothCrashDetectionTime:J

    .line 2
    .line 3
    return-wide v0
.end method

.method public getRecoveryAttemptCount()I
    .locals 0

    .line 1
    iget p0, p0, Lorg/altbeacon/bluetooth/BluetoothCrashResolver;->recoveryAttemptCount:I

    .line 2
    .line 3
    return p0
.end method

.method public isLastRecoverySucceeded()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Lorg/altbeacon/bluetooth/BluetoothCrashResolver;->lastRecoverySucceeded:Z

    .line 2
    .line 3
    return p0
.end method

.method public isRecoveryInProgress()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Lorg/altbeacon/bluetooth/BluetoothCrashResolver;->recoveryInProgress:Z

    .line 2
    .line 3
    return p0
.end method

.method public notifyScannedDevice(Landroid/bluetooth/BluetoothDevice;Landroid/bluetooth/BluetoothAdapter$LeScanCallback;)V
    .locals 3
    .annotation build Landroid/annotation/TargetApi;
        value = 0x12
    .end annotation

    .line 1
    iget-object v0, p0, Lorg/altbeacon/bluetooth/BluetoothCrashResolver;->distinctBluetoothAddresses:Ljava/util/Set;

    .line 2
    .line 3
    invoke-interface {v0}, Ljava/util/Set;->size()I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    iget-object v1, p0, Lorg/altbeacon/bluetooth/BluetoothCrashResolver;->distinctBluetoothAddresses:Ljava/util/Set;

    .line 8
    .line 9
    monitor-enter v1

    .line 10
    :try_start_0
    iget-object v2, p0, Lorg/altbeacon/bluetooth/BluetoothCrashResolver;->distinctBluetoothAddresses:Ljava/util/Set;

    .line 11
    .line 12
    invoke-virtual {p1}, Landroid/bluetooth/BluetoothDevice;->getAddress()Ljava/lang/String;

    .line 13
    .line 14
    .line 15
    move-result-object p1

    .line 16
    invoke-interface {v2, p1}, Ljava/util/Set;->add(Ljava/lang/Object;)Z

    .line 17
    .line 18
    .line 19
    monitor-exit v1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 20
    iget-object p1, p0, Lorg/altbeacon/bluetooth/BluetoothCrashResolver;->distinctBluetoothAddresses:Ljava/util/Set;

    .line 21
    .line 22
    invoke-interface {p1}, Ljava/util/Set;->size()I

    .line 23
    .line 24
    .line 25
    move-result p1

    .line 26
    if-eq v0, p1, :cond_0

    .line 27
    .line 28
    rem-int/lit8 p1, p1, 0x64

    .line 29
    .line 30
    if-nez p1, :cond_0

    .line 31
    .line 32
    const-string p1, "BluetoothCrashResolver"

    .line 33
    .line 34
    const-string v0, "Distinct Bluetooth devices seen: %s"

    .line 35
    .line 36
    iget-object v1, p0, Lorg/altbeacon/bluetooth/BluetoothCrashResolver;->distinctBluetoothAddresses:Ljava/util/Set;

    .line 37
    .line 38
    invoke-interface {v1}, Ljava/util/Set;->size()I

    .line 39
    .line 40
    .line 41
    move-result v1

    .line 42
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 43
    .line 44
    .line 45
    move-result-object v1

    .line 46
    filled-new-array {v1}, [Ljava/lang/Object;

    .line 47
    .line 48
    .line 49
    move-result-object v1

    .line 50
    invoke-static {p1, v0, v1}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 51
    .line 52
    .line 53
    :cond_0
    iget-object p1, p0, Lorg/altbeacon/bluetooth/BluetoothCrashResolver;->distinctBluetoothAddresses:Ljava/util/Set;

    .line 54
    .line 55
    invoke-interface {p1}, Ljava/util/Set;->size()I

    .line 56
    .line 57
    .line 58
    move-result p1

    .line 59
    invoke-direct {p0}, Lorg/altbeacon/bluetooth/BluetoothCrashResolver;->getCrashRiskDeviceCount()I

    .line 60
    .line 61
    .line 62
    move-result v0

    .line 63
    if-le p1, v0, :cond_1

    .line 64
    .line 65
    iget-boolean p1, p0, Lorg/altbeacon/bluetooth/BluetoothCrashResolver;->recoveryInProgress:Z

    .line 66
    .line 67
    if-nez p1, :cond_1

    .line 68
    .line 69
    const-string p1, "BluetoothCrashResolver"

    .line 70
    .line 71
    const-string v0, "Large number of Bluetooth devices detected: %s Proactively attempting to clear out address list to prevent a crash"

    .line 72
    .line 73
    iget-object v1, p0, Lorg/altbeacon/bluetooth/BluetoothCrashResolver;->distinctBluetoothAddresses:Ljava/util/Set;

    .line 74
    .line 75
    invoke-interface {v1}, Ljava/util/Set;->size()I

    .line 76
    .line 77
    .line 78
    move-result v1

    .line 79
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 80
    .line 81
    .line 82
    move-result-object v1

    .line 83
    filled-new-array {v1}, [Ljava/lang/Object;

    .line 84
    .line 85
    .line 86
    move-result-object v1

    .line 87
    invoke-static {p1, v0, v1}, Lorg/altbeacon/beacon/logging/LogManager;->w(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 88
    .line 89
    .line 90
    const-string p1, "BluetoothCrashResolver"

    .line 91
    .line 92
    const-string v0, "Stopping LE Scan"

    .line 93
    .line 94
    const/4 v1, 0x0

    .line 95
    new-array v1, v1, [Ljava/lang/Object;

    .line 96
    .line 97
    invoke-static {p1, v0, v1}, Lorg/altbeacon/beacon/logging/LogManager;->w(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 98
    .line 99
    .line 100
    invoke-static {}, Landroid/bluetooth/BluetoothAdapter;->getDefaultAdapter()Landroid/bluetooth/BluetoothAdapter;

    .line 101
    .line 102
    .line 103
    move-result-object p1

    .line 104
    invoke-virtual {p1, p2}, Landroid/bluetooth/BluetoothAdapter;->stopLeScan(Landroid/bluetooth/BluetoothAdapter$LeScanCallback;)V

    .line 105
    .line 106
    .line 107
    invoke-direct {p0}, Lorg/altbeacon/bluetooth/BluetoothCrashResolver;->startRecovery()V

    .line 108
    .line 109
    .line 110
    invoke-direct {p0}, Lorg/altbeacon/bluetooth/BluetoothCrashResolver;->processStateChange()V

    .line 111
    .line 112
    .line 113
    :cond_1
    return-void

    .line 114
    :catchall_0
    move-exception p0

    .line 115
    :try_start_1
    monitor-exit v1
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 116
    throw p0
.end method

.method public setUpdateNotifier(Lorg/altbeacon/bluetooth/BluetoothCrashResolver$UpdateNotifier;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lorg/altbeacon/bluetooth/BluetoothCrashResolver;->updateNotifier:Lorg/altbeacon/bluetooth/BluetoothCrashResolver$UpdateNotifier;

    .line 2
    .line 3
    return-void
.end method

.method public start()V
    .locals 2

    .line 1
    new-instance v0, Landroid/content/IntentFilter;

    .line 2
    .line 3
    invoke-direct {v0}, Landroid/content/IntentFilter;-><init>()V

    .line 4
    .line 5
    .line 6
    const-string v1, "android.bluetooth.adapter.action.STATE_CHANGED"

    .line 7
    .line 8
    invoke-virtual {v0, v1}, Landroid/content/IntentFilter;->addAction(Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    const-string v1, "android.bluetooth.adapter.action.DISCOVERY_STARTED"

    .line 12
    .line 13
    invoke-virtual {v0, v1}, Landroid/content/IntentFilter;->addAction(Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    const-string v1, "android.bluetooth.adapter.action.DISCOVERY_FINISHED"

    .line 17
    .line 18
    invoke-virtual {v0, v1}, Landroid/content/IntentFilter;->addAction(Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    iget-object v1, p0, Lorg/altbeacon/bluetooth/BluetoothCrashResolver;->context:Landroid/content/Context;

    .line 22
    .line 23
    iget-object p0, p0, Lorg/altbeacon/bluetooth/BluetoothCrashResolver;->receiver:Landroid/content/BroadcastReceiver;

    .line 24
    .line 25
    invoke-virtual {v1, p0, v0}, Landroid/content/Context;->registerReceiver(Landroid/content/BroadcastReceiver;Landroid/content/IntentFilter;)Landroid/content/Intent;

    .line 26
    .line 27
    .line 28
    const/4 p0, 0x0

    .line 29
    new-array p0, p0, [Ljava/lang/Object;

    .line 30
    .line 31
    const-string v0, "BluetoothCrashResolver"

    .line 32
    .line 33
    const-string v1, "started listening for BluetoothAdapter events"

    .line 34
    .line 35
    invoke-static {v0, v1, p0}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 36
    .line 37
    .line 38
    return-void
.end method

.method public stop()V
    .locals 3

    .line 1
    iget-object v0, p0, Lorg/altbeacon/bluetooth/BluetoothCrashResolver;->context:Landroid/content/Context;

    .line 2
    .line 3
    iget-object v1, p0, Lorg/altbeacon/bluetooth/BluetoothCrashResolver;->receiver:Landroid/content/BroadcastReceiver;

    .line 4
    .line 5
    invoke-virtual {v0, v1}, Landroid/content/Context;->unregisterReceiver(Landroid/content/BroadcastReceiver;)V

    .line 6
    .line 7
    .line 8
    const/4 v0, 0x0

    .line 9
    new-array v0, v0, [Ljava/lang/Object;

    .line 10
    .line 11
    const-string v1, "BluetoothCrashResolver"

    .line 12
    .line 13
    const-string v2, "stopped listening for BluetoothAdapter events"

    .line 14
    .line 15
    invoke-static {v1, v2, v0}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 16
    .line 17
    .line 18
    invoke-direct {p0}, Lorg/altbeacon/bluetooth/BluetoothCrashResolver;->saveState()V

    .line 19
    .line 20
    .line 21
    return-void
.end method
