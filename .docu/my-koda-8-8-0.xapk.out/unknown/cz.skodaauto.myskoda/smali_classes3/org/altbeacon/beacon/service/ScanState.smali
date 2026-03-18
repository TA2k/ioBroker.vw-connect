.class public Lorg/altbeacon/beacon/service/ScanState;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/io/Serializable;


# static fields
.field public static MIN_SCAN_JOB_INTERVAL_MILLIS:I = 0x493e0

.field private static final STATUS_PRESERVATION_FILE_NAME:Ljava/lang/String; = "android-beacon-library-scan-state"

.field private static final TAG:Ljava/lang/String; = "ScanState"

.field private static final TEMP_STATUS_PRESERVATION_FILE_NAME:Ljava/lang/String; = "android-beacon-library-scan-state-temp"


# instance fields
.field private mBackgroundBetweenScanPeriod:J

.field private mBackgroundMode:Z

.field private mBackgroundScanPeriod:J

.field private mBeaconParsers:Ljava/util/Set;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/Set<",
            "Lorg/altbeacon/beacon/BeaconParser;",
            ">;"
        }
    .end annotation
.end field

.field private transient mContext:Landroid/content/Context;

.field private mExtraBeaconDataTracker:Lorg/altbeacon/beacon/service/ExtraDataBeaconTracker;

.field private mForegroundBetweenScanPeriod:J

.field private mForegroundScanPeriod:J

.field private mLastScanStartTimeMillis:J

.field private transient mMonitoringStatus:Lorg/altbeacon/beacon/service/MonitoringStatus;

.field private mRangedRegionState:Ljava/util/Map;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/Map<",
            "Lorg/altbeacon/beacon/Region;",
            "Lorg/altbeacon/beacon/service/RangeState;",
            ">;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>(Landroid/content/Context;)V
    .locals 2

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Ljava/util/HashMap;

    .line 5
    .line 6
    invoke-direct {v0}, Ljava/util/HashMap;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object v0, p0, Lorg/altbeacon/beacon/service/ScanState;->mRangedRegionState:Ljava/util/Map;

    .line 10
    .line 11
    new-instance v0, Ljava/util/HashSet;

    .line 12
    .line 13
    invoke-direct {v0}, Ljava/util/HashSet;-><init>()V

    .line 14
    .line 15
    .line 16
    iput-object v0, p0, Lorg/altbeacon/beacon/service/ScanState;->mBeaconParsers:Ljava/util/Set;

    .line 17
    .line 18
    new-instance v0, Lorg/altbeacon/beacon/service/ExtraDataBeaconTracker;

    .line 19
    .line 20
    invoke-direct {v0}, Lorg/altbeacon/beacon/service/ExtraDataBeaconTracker;-><init>()V

    .line 21
    .line 22
    .line 23
    iput-object v0, p0, Lorg/altbeacon/beacon/service/ScanState;->mExtraBeaconDataTracker:Lorg/altbeacon/beacon/service/ExtraDataBeaconTracker;

    .line 24
    .line 25
    const-wide/16 v0, 0x0

    .line 26
    .line 27
    iput-wide v0, p0, Lorg/altbeacon/beacon/service/ScanState;->mLastScanStartTimeMillis:J

    .line 28
    .line 29
    iput-object p1, p0, Lorg/altbeacon/beacon/service/ScanState;->mContext:Landroid/content/Context;

    .line 30
    .line 31
    return-void
.end method

.method public static restore(Landroid/content/Context;)Lorg/altbeacon/beacon/service/ScanState;
    .locals 11

    .line 1
    const-string v0, "Scan state restore regions: monitored="

    .line 2
    .line 3
    const-class v1, Lorg/altbeacon/beacon/service/ScanState;

    .line 4
    .line 5
    monitor-enter v1

    .line 6
    const/4 v2, 0x0

    .line 7
    const/4 v3, 0x0

    .line 8
    :try_start_0
    const-string v4, "android-beacon-library-scan-state"

    .line 9
    .line 10
    invoke-virtual {p0, v4}, Landroid/content/Context;->openFileInput(Ljava/lang/String;)Ljava/io/FileInputStream;

    .line 11
    .line 12
    .line 13
    move-result-object v4
    :try_end_0
    .catch Ljava/io/FileNotFoundException; {:try_start_0 .. :try_end_0} :catch_8
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_7
    .catch Ljava/lang/ClassNotFoundException; {:try_start_0 .. :try_end_0} :catch_7
    .catch Ljava/lang/ClassCastException; {:try_start_0 .. :try_end_0} :catch_7
    .catchall {:try_start_0 .. :try_end_0} :catchall_3

    .line 14
    :try_start_1
    new-instance v5, Ljava/io/ObjectInputStream;

    .line 15
    .line 16
    invoke-direct {v5, v4}, Ljava/io/ObjectInputStream;-><init>(Ljava/io/InputStream;)V
    :try_end_1
    .catch Ljava/io/FileNotFoundException; {:try_start_1 .. :try_end_1} :catch_6
    .catch Ljava/io/IOException; {:try_start_1 .. :try_end_1} :catch_5
    .catch Ljava/lang/ClassNotFoundException; {:try_start_1 .. :try_end_1} :catch_5
    .catch Ljava/lang/ClassCastException; {:try_start_1 .. :try_end_1} :catch_5
    .catchall {:try_start_1 .. :try_end_1} :catchall_2

    .line 17
    .line 18
    .line 19
    :try_start_2
    invoke-virtual {v5}, Ljava/io/ObjectInputStream;->readObject()Ljava/lang/Object;

    .line 20
    .line 21
    .line 22
    move-result-object v6

    .line 23
    check-cast v6, Lorg/altbeacon/beacon/service/ScanState;
    :try_end_2
    .catch Ljava/io/FileNotFoundException; {:try_start_2 .. :try_end_2} :catch_4
    .catch Ljava/io/IOException; {:try_start_2 .. :try_end_2} :catch_3
    .catch Ljava/lang/ClassNotFoundException; {:try_start_2 .. :try_end_2} :catch_3
    .catch Ljava/lang/ClassCastException; {:try_start_2 .. :try_end_2} :catch_3
    .catchall {:try_start_2 .. :try_end_2} :catchall_1

    .line 24
    .line 25
    :try_start_3
    iput-object p0, v6, Lorg/altbeacon/beacon/service/ScanState;->mContext:Landroid/content/Context;
    :try_end_3
    .catch Ljava/io/FileNotFoundException; {:try_start_3 .. :try_end_3} :catch_2
    .catch Ljava/io/IOException; {:try_start_3 .. :try_end_3} :catch_1
    .catch Ljava/lang/ClassNotFoundException; {:try_start_3 .. :try_end_3} :catch_1
    .catch Ljava/lang/ClassCastException; {:try_start_3 .. :try_end_3} :catch_1
    .catchall {:try_start_3 .. :try_end_3} :catchall_1

    .line 26
    .line 27
    if-eqz v4, :cond_0

    .line 28
    .line 29
    :try_start_4
    invoke-virtual {v4}, Ljava/io/FileInputStream;->close()V
    :try_end_4
    .catch Ljava/io/IOException; {:try_start_4 .. :try_end_4} :catch_0
    .catchall {:try_start_4 .. :try_end_4} :catchall_0

    .line 30
    .line 31
    .line 32
    goto :goto_0

    .line 33
    :catchall_0
    move-exception p0

    .line 34
    goto/16 :goto_8

    .line 35
    .line 36
    :catch_0
    :cond_0
    :goto_0
    :try_start_5
    invoke-virtual {v5}, Ljava/io/ObjectInputStream;->close()V
    :try_end_5
    .catch Ljava/io/IOException; {:try_start_5 .. :try_end_5} :catch_b
    .catchall {:try_start_5 .. :try_end_5} :catchall_0

    .line 37
    .line 38
    .line 39
    goto/16 :goto_6

    .line 40
    .line 41
    :catchall_1
    move-exception p0

    .line 42
    :goto_1
    move-object v3, v4

    .line 43
    goto/16 :goto_7

    .line 44
    .line 45
    :catch_1
    move-exception v3

    .line 46
    goto :goto_3

    .line 47
    :catch_2
    :goto_2
    move-object v3, v4

    .line 48
    goto :goto_5

    .line 49
    :catch_3
    move-exception v6

    .line 50
    move-object v10, v6

    .line 51
    move-object v6, v3

    .line 52
    move-object v3, v10

    .line 53
    goto :goto_3

    .line 54
    :catch_4
    move-object v6, v3

    .line 55
    goto :goto_2

    .line 56
    :catchall_2
    move-exception p0

    .line 57
    move-object v5, v3

    .line 58
    goto :goto_1

    .line 59
    :catch_5
    move-exception v5

    .line 60
    move-object v6, v3

    .line 61
    move-object v3, v5

    .line 62
    move-object v5, v6

    .line 63
    goto :goto_3

    .line 64
    :catch_6
    move-object v5, v3

    .line 65
    move-object v6, v5

    .line 66
    goto :goto_2

    .line 67
    :catchall_3
    move-exception p0

    .line 68
    move-object v5, v3

    .line 69
    goto/16 :goto_7

    .line 70
    .line 71
    :catch_7
    move-exception v4

    .line 72
    move-object v5, v3

    .line 73
    move-object v6, v5

    .line 74
    move-object v3, v4

    .line 75
    move-object v4, v6

    .line 76
    goto :goto_3

    .line 77
    :catch_8
    move-object v5, v3

    .line 78
    move-object v6, v5

    .line 79
    goto :goto_5

    .line 80
    :goto_3
    :try_start_6
    instance-of v7, v3, Ljava/io/InvalidClassException;

    .line 81
    .line 82
    if-eqz v7, :cond_1

    .line 83
    .line 84
    sget-object v3, Lorg/altbeacon/beacon/service/ScanState;->TAG:Ljava/lang/String;

    .line 85
    .line 86
    const-string v7, "Serialized ScanState has wrong class. Just ignoring saved state..."

    .line 87
    .line 88
    new-array v8, v2, [Ljava/lang/Object;

    .line 89
    .line 90
    invoke-static {v3, v7, v8}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 91
    .line 92
    .line 93
    goto :goto_4

    .line 94
    :cond_1
    sget-object v7, Lorg/altbeacon/beacon/service/ScanState;->TAG:Ljava/lang/String;

    .line 95
    .line 96
    const-string v8, "Deserialization exception"

    .line 97
    .line 98
    new-array v9, v2, [Ljava/lang/Object;

    .line 99
    .line 100
    invoke-static {v7, v8, v9}, Lorg/altbeacon/beacon/logging/LogManager;->e(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 101
    .line 102
    .line 103
    const-string v8, "error: "

    .line 104
    .line 105
    invoke-static {v7, v8, v3}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I
    :try_end_6
    .catchall {:try_start_6 .. :try_end_6} :catchall_1

    .line 106
    .line 107
    .line 108
    :goto_4
    if-eqz v4, :cond_2

    .line 109
    .line 110
    :try_start_7
    invoke-virtual {v4}, Ljava/io/FileInputStream;->close()V
    :try_end_7
    .catch Ljava/io/IOException; {:try_start_7 .. :try_end_7} :catch_9
    .catchall {:try_start_7 .. :try_end_7} :catchall_0

    .line 111
    .line 112
    .line 113
    :catch_9
    :cond_2
    if-eqz v5, :cond_4

    .line 114
    .line 115
    goto :goto_0

    .line 116
    :goto_5
    :try_start_8
    sget-object v4, Lorg/altbeacon/beacon/service/ScanState;->TAG:Ljava/lang/String;

    .line 117
    .line 118
    const-string v7, "Serialized ScanState does not exist.  This may be normal on first run."

    .line 119
    .line 120
    new-array v8, v2, [Ljava/lang/Object;

    .line 121
    .line 122
    invoke-static {v4, v7, v8}, Lorg/altbeacon/beacon/logging/LogManager;->w(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V
    :try_end_8
    .catchall {:try_start_8 .. :try_end_8} :catchall_4

    .line 123
    .line 124
    .line 125
    if-eqz v3, :cond_3

    .line 126
    .line 127
    :try_start_9
    invoke-virtual {v3}, Ljava/io/FileInputStream;->close()V
    :try_end_9
    .catch Ljava/io/IOException; {:try_start_9 .. :try_end_9} :catch_a
    .catchall {:try_start_9 .. :try_end_9} :catchall_0

    .line 128
    .line 129
    .line 130
    :catch_a
    :cond_3
    if-eqz v5, :cond_4

    .line 131
    .line 132
    goto :goto_0

    .line 133
    :catch_b
    :cond_4
    :goto_6
    if-nez v6, :cond_5

    .line 134
    .line 135
    :try_start_a
    new-instance v6, Lorg/altbeacon/beacon/service/ScanState;

    .line 136
    .line 137
    invoke-direct {v6, p0}, Lorg/altbeacon/beacon/service/ScanState;-><init>(Landroid/content/Context;)V

    .line 138
    .line 139
    .line 140
    :cond_5
    iget-object v3, v6, Lorg/altbeacon/beacon/service/ScanState;->mExtraBeaconDataTracker:Lorg/altbeacon/beacon/service/ExtraDataBeaconTracker;

    .line 141
    .line 142
    if-nez v3, :cond_6

    .line 143
    .line 144
    new-instance v3, Lorg/altbeacon/beacon/service/ExtraDataBeaconTracker;

    .line 145
    .line 146
    invoke-direct {v3}, Lorg/altbeacon/beacon/service/ExtraDataBeaconTracker;-><init>()V

    .line 147
    .line 148
    .line 149
    iput-object v3, v6, Lorg/altbeacon/beacon/service/ScanState;->mExtraBeaconDataTracker:Lorg/altbeacon/beacon/service/ExtraDataBeaconTracker;

    .line 150
    .line 151
    :cond_6
    invoke-static {p0}, Lorg/altbeacon/beacon/service/MonitoringStatus;->getInstanceForApplication(Landroid/content/Context;)Lorg/altbeacon/beacon/service/MonitoringStatus;

    .line 152
    .line 153
    .line 154
    move-result-object p0

    .line 155
    iput-object p0, v6, Lorg/altbeacon/beacon/service/ScanState;->mMonitoringStatus:Lorg/altbeacon/beacon/service/MonitoringStatus;

    .line 156
    .line 157
    sget-object p0, Lorg/altbeacon/beacon/service/ScanState;->TAG:Ljava/lang/String;

    .line 158
    .line 159
    new-instance v3, Ljava/lang/StringBuilder;

    .line 160
    .line 161
    invoke-direct {v3, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 162
    .line 163
    .line 164
    invoke-virtual {v6}, Lorg/altbeacon/beacon/service/ScanState;->getMonitoringStatus()Lorg/altbeacon/beacon/service/MonitoringStatus;

    .line 165
    .line 166
    .line 167
    move-result-object v0

    .line 168
    invoke-virtual {v0}, Lorg/altbeacon/beacon/service/MonitoringStatus;->regions()Ljava/util/Set;

    .line 169
    .line 170
    .line 171
    move-result-object v0

    .line 172
    invoke-interface {v0}, Ljava/util/Set;->size()I

    .line 173
    .line 174
    .line 175
    move-result v0

    .line 176
    invoke-virtual {v3, v0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 177
    .line 178
    .line 179
    const-string v0, " ranged="

    .line 180
    .line 181
    invoke-virtual {v3, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 182
    .line 183
    .line 184
    invoke-virtual {v6}, Lorg/altbeacon/beacon/service/ScanState;->getRangedRegionState()Ljava/util/Map;

    .line 185
    .line 186
    .line 187
    move-result-object v0

    .line 188
    invoke-interface {v0}, Ljava/util/Map;->keySet()Ljava/util/Set;

    .line 189
    .line 190
    .line 191
    move-result-object v0

    .line 192
    invoke-interface {v0}, Ljava/util/Set;->size()I

    .line 193
    .line 194
    .line 195
    move-result v0

    .line 196
    invoke-virtual {v3, v0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 197
    .line 198
    .line 199
    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 200
    .line 201
    .line 202
    move-result-object v0

    .line 203
    new-array v2, v2, [Ljava/lang/Object;

    .line 204
    .line 205
    invoke-static {p0, v0, v2}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 206
    .line 207
    .line 208
    monitor-exit v1
    :try_end_a
    .catchall {:try_start_a .. :try_end_a} :catchall_0

    .line 209
    return-object v6

    .line 210
    :catchall_4
    move-exception p0

    .line 211
    :goto_7
    if-eqz v3, :cond_7

    .line 212
    .line 213
    :try_start_b
    invoke-virtual {v3}, Ljava/io/FileInputStream;->close()V
    :try_end_b
    .catch Ljava/io/IOException; {:try_start_b .. :try_end_b} :catch_c
    .catchall {:try_start_b .. :try_end_b} :catchall_0

    .line 214
    .line 215
    .line 216
    :catch_c
    :cond_7
    if-eqz v5, :cond_8

    .line 217
    .line 218
    :try_start_c
    invoke-virtual {v5}, Ljava/io/ObjectInputStream;->close()V
    :try_end_c
    .catch Ljava/io/IOException; {:try_start_c .. :try_end_c} :catch_d
    .catchall {:try_start_c .. :try_end_c} :catchall_0

    .line 219
    .line 220
    .line 221
    :catch_d
    :cond_8
    :try_start_d
    throw p0

    .line 222
    :goto_8
    monitor-exit v1
    :try_end_d
    .catchall {:try_start_d .. :try_end_d} :catchall_0

    .line 223
    throw p0
.end method


# virtual methods
.method public applyChanges(Lorg/altbeacon/beacon/BeaconManager;)V
    .locals 9

    .line 1
    new-instance v0, Ljava/util/HashSet;

    .line 2
    .line 3
    invoke-virtual {p1}, Lorg/altbeacon/beacon/BeaconManager;->getBeaconParsers()Ljava/util/List;

    .line 4
    .line 5
    .line 6
    move-result-object v1

    .line 7
    invoke-direct {v0, v1}, Ljava/util/HashSet;-><init>(Ljava/util/Collection;)V

    .line 8
    .line 9
    .line 10
    iput-object v0, p0, Lorg/altbeacon/beacon/service/ScanState;->mBeaconParsers:Ljava/util/Set;

    .line 11
    .line 12
    invoke-virtual {p1}, Lorg/altbeacon/beacon/BeaconManager;->getForegroundScanPeriod()J

    .line 13
    .line 14
    .line 15
    move-result-wide v0

    .line 16
    iput-wide v0, p0, Lorg/altbeacon/beacon/service/ScanState;->mForegroundScanPeriod:J

    .line 17
    .line 18
    invoke-virtual {p1}, Lorg/altbeacon/beacon/BeaconManager;->getForegroundBetweenScanPeriod()J

    .line 19
    .line 20
    .line 21
    move-result-wide v0

    .line 22
    iput-wide v0, p0, Lorg/altbeacon/beacon/service/ScanState;->mForegroundBetweenScanPeriod:J

    .line 23
    .line 24
    invoke-virtual {p1}, Lorg/altbeacon/beacon/BeaconManager;->getBackgroundScanPeriod()J

    .line 25
    .line 26
    .line 27
    move-result-wide v0

    .line 28
    iput-wide v0, p0, Lorg/altbeacon/beacon/service/ScanState;->mBackgroundScanPeriod:J

    .line 29
    .line 30
    invoke-virtual {p1}, Lorg/altbeacon/beacon/BeaconManager;->getBackgroundBetweenScanPeriod()J

    .line 31
    .line 32
    .line 33
    move-result-wide v0

    .line 34
    iput-wide v0, p0, Lorg/altbeacon/beacon/service/ScanState;->mBackgroundBetweenScanPeriod:J

    .line 35
    .line 36
    invoke-virtual {p1}, Lorg/altbeacon/beacon/BeaconManager;->getBackgroundMode()Z

    .line 37
    .line 38
    .line 39
    move-result v0

    .line 40
    iput-boolean v0, p0, Lorg/altbeacon/beacon/service/ScanState;->mBackgroundMode:Z

    .line 41
    .line 42
    new-instance v0, Ljava/util/ArrayList;

    .line 43
    .line 44
    iget-object v1, p0, Lorg/altbeacon/beacon/service/ScanState;->mMonitoringStatus:Lorg/altbeacon/beacon/service/MonitoringStatus;

    .line 45
    .line 46
    invoke-virtual {v1}, Lorg/altbeacon/beacon/service/MonitoringStatus;->regions()Ljava/util/Set;

    .line 47
    .line 48
    .line 49
    move-result-object v1

    .line 50
    invoke-direct {v0, v1}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    .line 51
    .line 52
    .line 53
    new-instance v1, Ljava/util/ArrayList;

    .line 54
    .line 55
    iget-object v2, p0, Lorg/altbeacon/beacon/service/ScanState;->mRangedRegionState:Ljava/util/Map;

    .line 56
    .line 57
    invoke-interface {v2}, Ljava/util/Map;->keySet()Ljava/util/Set;

    .line 58
    .line 59
    .line 60
    move-result-object v2

    .line 61
    invoke-direct {v1, v2}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    .line 62
    .line 63
    .line 64
    new-instance v2, Ljava/util/ArrayList;

    .line 65
    .line 66
    invoke-virtual {p1}, Lorg/altbeacon/beacon/BeaconManager;->getMonitoredRegions()Ljava/util/Collection;

    .line 67
    .line 68
    .line 69
    move-result-object v3

    .line 70
    invoke-direct {v2, v3}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    .line 71
    .line 72
    .line 73
    new-instance v3, Ljava/util/ArrayList;

    .line 74
    .line 75
    invoke-virtual {p1}, Lorg/altbeacon/beacon/BeaconManager;->getRangedRegions()Ljava/util/Collection;

    .line 76
    .line 77
    .line 78
    move-result-object p1

    .line 79
    invoke-direct {v3, p1}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    .line 80
    .line 81
    .line 82
    sget-object p1, Lorg/altbeacon/beacon/service/ScanState;->TAG:Ljava/lang/String;

    .line 83
    .line 84
    new-instance v4, Ljava/lang/StringBuilder;

    .line 85
    .line 86
    const-string v5, "ranged regions: old="

    .line 87
    .line 88
    invoke-direct {v4, v5}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 89
    .line 90
    .line 91
    invoke-virtual {v1}, Ljava/util/ArrayList;->size()I

    .line 92
    .line 93
    .line 94
    move-result v5

    .line 95
    invoke-virtual {v4, v5}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 96
    .line 97
    .line 98
    const-string v5, " new="

    .line 99
    .line 100
    invoke-virtual {v4, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 101
    .line 102
    .line 103
    invoke-virtual {v3}, Ljava/util/ArrayList;->size()I

    .line 104
    .line 105
    .line 106
    move-result v6

    .line 107
    invoke-virtual {v4, v6}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 108
    .line 109
    .line 110
    invoke-virtual {v4}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 111
    .line 112
    .line 113
    move-result-object v4

    .line 114
    const/4 v6, 0x0

    .line 115
    new-array v7, v6, [Ljava/lang/Object;

    .line 116
    .line 117
    invoke-static {p1, v4, v7}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 118
    .line 119
    .line 120
    new-instance v4, Ljava/lang/StringBuilder;

    .line 121
    .line 122
    const-string v7, "monitored regions: old="

    .line 123
    .line 124
    invoke-direct {v4, v7}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 125
    .line 126
    .line 127
    invoke-virtual {v0}, Ljava/util/ArrayList;->size()I

    .line 128
    .line 129
    .line 130
    move-result v0

    .line 131
    invoke-virtual {v4, v0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 132
    .line 133
    .line 134
    invoke-virtual {v4, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 135
    .line 136
    .line 137
    invoke-virtual {v2}, Ljava/util/ArrayList;->size()I

    .line 138
    .line 139
    .line 140
    move-result v0

    .line 141
    invoke-virtual {v4, v0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 142
    .line 143
    .line 144
    invoke-virtual {v4}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 145
    .line 146
    .line 147
    move-result-object v0

    .line 148
    new-array v4, v6, [Ljava/lang/Object;

    .line 149
    .line 150
    invoke-static {p1, v0, v4}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 151
    .line 152
    .line 153
    invoke-virtual {v3}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 154
    .line 155
    .line 156
    move-result-object p1

    .line 157
    :cond_0
    :goto_0
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 158
    .line 159
    .line 160
    move-result v0

    .line 161
    if-eqz v0, :cond_2

    .line 162
    .line 163
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 164
    .line 165
    .line 166
    move-result-object v0

    .line 167
    check-cast v0, Lorg/altbeacon/beacon/Region;

    .line 168
    .line 169
    invoke-virtual {v1, v0}, Ljava/util/ArrayList;->contains(Ljava/lang/Object;)Z

    .line 170
    .line 171
    .line 172
    move-result v4

    .line 173
    if-nez v4, :cond_1

    .line 174
    .line 175
    sget-object v4, Lorg/altbeacon/beacon/service/ScanState;->TAG:Ljava/lang/String;

    .line 176
    .line 177
    new-instance v5, Ljava/lang/StringBuilder;

    .line 178
    .line 179
    const-string v7, "Starting ranging region: "

    .line 180
    .line 181
    invoke-direct {v5, v7}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 182
    .line 183
    .line 184
    invoke-virtual {v5, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 185
    .line 186
    .line 187
    invoke-virtual {v5}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 188
    .line 189
    .line 190
    move-result-object v5

    .line 191
    new-array v7, v6, [Ljava/lang/Object;

    .line 192
    .line 193
    invoke-static {v4, v5, v7}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 194
    .line 195
    .line 196
    iget-object v4, p0, Lorg/altbeacon/beacon/service/ScanState;->mRangedRegionState:Ljava/util/Map;

    .line 197
    .line 198
    new-instance v5, Lorg/altbeacon/beacon/service/RangeState;

    .line 199
    .line 200
    new-instance v7, Lorg/altbeacon/beacon/service/Callback;

    .line 201
    .line 202
    iget-object v8, p0, Lorg/altbeacon/beacon/service/ScanState;->mContext:Landroid/content/Context;

    .line 203
    .line 204
    invoke-virtual {v8}, Landroid/content/Context;->getPackageName()Ljava/lang/String;

    .line 205
    .line 206
    .line 207
    move-result-object v8

    .line 208
    invoke-direct {v7, v8}, Lorg/altbeacon/beacon/service/Callback;-><init>(Ljava/lang/String;)V

    .line 209
    .line 210
    .line 211
    invoke-direct {v5, v7}, Lorg/altbeacon/beacon/service/RangeState;-><init>(Lorg/altbeacon/beacon/service/Callback;)V

    .line 212
    .line 213
    .line 214
    invoke-interface {v4, v0, v5}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 215
    .line 216
    .line 217
    goto :goto_0

    .line 218
    :cond_1
    invoke-virtual {v1, v0}, Ljava/util/ArrayList;->indexOf(Ljava/lang/Object;)I

    .line 219
    .line 220
    .line 221
    move-result v4

    .line 222
    invoke-virtual {v1, v4}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 223
    .line 224
    .line 225
    move-result-object v4

    .line 226
    check-cast v4, Lorg/altbeacon/beacon/Region;

    .line 227
    .line 228
    invoke-virtual {v0, v4}, Lorg/altbeacon/beacon/Region;->hasSameIdentifiers(Lorg/altbeacon/beacon/Region;)Z

    .line 229
    .line 230
    .line 231
    move-result v5

    .line 232
    if-eqz v5, :cond_0

    .line 233
    .line 234
    iget-object v5, p0, Lorg/altbeacon/beacon/service/ScanState;->mRangedRegionState:Ljava/util/Map;

    .line 235
    .line 236
    invoke-interface {v5, v4}, Ljava/util/Map;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    .line 237
    .line 238
    .line 239
    iget-object v4, p0, Lorg/altbeacon/beacon/service/ScanState;->mRangedRegionState:Ljava/util/Map;

    .line 240
    .line 241
    new-instance v5, Lorg/altbeacon/beacon/service/RangeState;

    .line 242
    .line 243
    new-instance v7, Lorg/altbeacon/beacon/service/Callback;

    .line 244
    .line 245
    iget-object v8, p0, Lorg/altbeacon/beacon/service/ScanState;->mContext:Landroid/content/Context;

    .line 246
    .line 247
    invoke-virtual {v8}, Landroid/content/Context;->getPackageName()Ljava/lang/String;

    .line 248
    .line 249
    .line 250
    move-result-object v8

    .line 251
    invoke-direct {v7, v8}, Lorg/altbeacon/beacon/service/Callback;-><init>(Ljava/lang/String;)V

    .line 252
    .line 253
    .line 254
    invoke-direct {v5, v7}, Lorg/altbeacon/beacon/service/RangeState;-><init>(Lorg/altbeacon/beacon/service/Callback;)V

    .line 255
    .line 256
    .line 257
    invoke-interface {v4, v0, v5}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 258
    .line 259
    .line 260
    goto :goto_0

    .line 261
    :cond_2
    invoke-virtual {v1}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 262
    .line 263
    .line 264
    move-result-object p1

    .line 265
    :cond_3
    :goto_1
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 266
    .line 267
    .line 268
    move-result v0

    .line 269
    if-eqz v0, :cond_4

    .line 270
    .line 271
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 272
    .line 273
    .line 274
    move-result-object v0

    .line 275
    check-cast v0, Lorg/altbeacon/beacon/Region;

    .line 276
    .line 277
    invoke-virtual {v3, v0}, Ljava/util/ArrayList;->contains(Ljava/lang/Object;)Z

    .line 278
    .line 279
    .line 280
    move-result v1

    .line 281
    if-nez v1, :cond_3

    .line 282
    .line 283
    sget-object v1, Lorg/altbeacon/beacon/service/ScanState;->TAG:Ljava/lang/String;

    .line 284
    .line 285
    new-instance v4, Ljava/lang/StringBuilder;

    .line 286
    .line 287
    const-string v5, "Stopping ranging region: "

    .line 288
    .line 289
    invoke-direct {v4, v5}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 290
    .line 291
    .line 292
    invoke-virtual {v4, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 293
    .line 294
    .line 295
    invoke-virtual {v4}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 296
    .line 297
    .line 298
    move-result-object v4

    .line 299
    new-array v5, v6, [Ljava/lang/Object;

    .line 300
    .line 301
    invoke-static {v1, v4, v5}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 302
    .line 303
    .line 304
    iget-object v1, p0, Lorg/altbeacon/beacon/service/ScanState;->mRangedRegionState:Ljava/util/Map;

    .line 305
    .line 306
    invoke-interface {v1, v0}, Ljava/util/Map;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    .line 307
    .line 308
    .line 309
    goto :goto_1

    .line 310
    :cond_4
    sget-object p1, Lorg/altbeacon/beacon/service/ScanState;->TAG:Ljava/lang/String;

    .line 311
    .line 312
    new-instance v0, Ljava/lang/StringBuilder;

    .line 313
    .line 314
    const-string v1, "Updated state with "

    .line 315
    .line 316
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 317
    .line 318
    .line 319
    invoke-virtual {v3}, Ljava/util/ArrayList;->size()I

    .line 320
    .line 321
    .line 322
    move-result v1

    .line 323
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 324
    .line 325
    .line 326
    const-string v1, " ranging regions and "

    .line 327
    .line 328
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 329
    .line 330
    .line 331
    invoke-virtual {v2}, Ljava/util/ArrayList;->size()I

    .line 332
    .line 333
    .line 334
    move-result v1

    .line 335
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 336
    .line 337
    .line 338
    const-string v1, " monitoring regions."

    .line 339
    .line 340
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 341
    .line 342
    .line 343
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 344
    .line 345
    .line 346
    move-result-object v0

    .line 347
    new-array v1, v6, [Ljava/lang/Object;

    .line 348
    .line 349
    invoke-static {p1, v0, v1}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 350
    .line 351
    .line 352
    invoke-virtual {p0}, Lorg/altbeacon/beacon/service/ScanState;->save()V

    .line 353
    .line 354
    .line 355
    return-void
.end method

.method public getBackgroundBetweenScanPeriod()Ljava/lang/Long;
    .locals 2

    .line 1
    iget-wide v0, p0, Lorg/altbeacon/beacon/service/ScanState;->mBackgroundBetweenScanPeriod:J

    .line 2
    .line 3
    invoke-static {v0, v1}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public getBackgroundMode()Ljava/lang/Boolean;
    .locals 0

    .line 1
    iget-boolean p0, p0, Lorg/altbeacon/beacon/service/ScanState;->mBackgroundMode:Z

    .line 2
    .line 3
    invoke-static {p0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public getBackgroundScanPeriod()Ljava/lang/Long;
    .locals 2

    .line 1
    iget-wide v0, p0, Lorg/altbeacon/beacon/service/ScanState;->mBackgroundScanPeriod:J

    .line 2
    .line 3
    invoke-static {v0, v1}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public getBeaconParsers()Ljava/util/Set;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/Set<",
            "Lorg/altbeacon/beacon/BeaconParser;",
            ">;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Lorg/altbeacon/beacon/service/ScanState;->mBeaconParsers:Ljava/util/Set;

    .line 2
    .line 3
    return-object p0
.end method

.method public getExtraBeaconDataTracker()Lorg/altbeacon/beacon/service/ExtraDataBeaconTracker;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/altbeacon/beacon/service/ScanState;->mExtraBeaconDataTracker:Lorg/altbeacon/beacon/service/ExtraDataBeaconTracker;

    .line 2
    .line 3
    return-object p0
.end method

.method public getForegroundBetweenScanPeriod()Ljava/lang/Long;
    .locals 2

    .line 1
    iget-wide v0, p0, Lorg/altbeacon/beacon/service/ScanState;->mForegroundBetweenScanPeriod:J

    .line 2
    .line 3
    invoke-static {v0, v1}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public getForegroundScanPeriod()Ljava/lang/Long;
    .locals 2

    .line 1
    iget-wide v0, p0, Lorg/altbeacon/beacon/service/ScanState;->mForegroundScanPeriod:J

    .line 2
    .line 3
    invoke-static {v0, v1}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public getLastScanStartTimeMillis()J
    .locals 2

    .line 1
    iget-wide v0, p0, Lorg/altbeacon/beacon/service/ScanState;->mLastScanStartTimeMillis:J

    .line 2
    .line 3
    return-wide v0
.end method

.method public getMonitoringStatus()Lorg/altbeacon/beacon/service/MonitoringStatus;
    .locals 0

    .line 1
    iget-object p0, p0, Lorg/altbeacon/beacon/service/ScanState;->mMonitoringStatus:Lorg/altbeacon/beacon/service/MonitoringStatus;

    .line 2
    .line 3
    return-object p0
.end method

.method public getRangedRegionState()Ljava/util/Map;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/Map<",
            "Lorg/altbeacon/beacon/Region;",
            "Lorg/altbeacon/beacon/service/RangeState;",
            ">;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Lorg/altbeacon/beacon/service/ScanState;->mRangedRegionState:Ljava/util/Map;

    .line 2
    .line 3
    return-object p0
.end method

.method public getScanJobIntervalMillis()I
    .locals 4

    .line 1
    invoke-virtual {p0}, Lorg/altbeacon/beacon/service/ScanState;->getBackgroundMode()Ljava/lang/Boolean;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    if-eqz v0, :cond_0

    .line 10
    .line 11
    invoke-virtual {p0}, Lorg/altbeacon/beacon/service/ScanState;->getBackgroundScanPeriod()Ljava/lang/Long;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    invoke-virtual {v0}, Ljava/lang/Long;->longValue()J

    .line 16
    .line 17
    .line 18
    move-result-wide v0

    .line 19
    invoke-virtual {p0}, Lorg/altbeacon/beacon/service/ScanState;->getBackgroundBetweenScanPeriod()Ljava/lang/Long;

    .line 20
    .line 21
    .line 22
    move-result-object p0

    .line 23
    invoke-virtual {p0}, Ljava/lang/Long;->longValue()J

    .line 24
    .line 25
    .line 26
    move-result-wide v2

    .line 27
    :goto_0
    add-long/2addr v2, v0

    .line 28
    goto :goto_1

    .line 29
    :cond_0
    invoke-virtual {p0}, Lorg/altbeacon/beacon/service/ScanState;->getForegroundScanPeriod()Ljava/lang/Long;

    .line 30
    .line 31
    .line 32
    move-result-object v0

    .line 33
    invoke-virtual {v0}, Ljava/lang/Long;->longValue()J

    .line 34
    .line 35
    .line 36
    move-result-wide v0

    .line 37
    invoke-virtual {p0}, Lorg/altbeacon/beacon/service/ScanState;->getForegroundBetweenScanPeriod()Ljava/lang/Long;

    .line 38
    .line 39
    .line 40
    move-result-object p0

    .line 41
    invoke-virtual {p0}, Ljava/lang/Long;->longValue()J

    .line 42
    .line 43
    .line 44
    move-result-wide v2

    .line 45
    goto :goto_0

    .line 46
    :goto_1
    sget p0, Lorg/altbeacon/beacon/service/ScanState;->MIN_SCAN_JOB_INTERVAL_MILLIS:I

    .line 47
    .line 48
    int-to-long v0, p0

    .line 49
    cmp-long v0, v2, v0

    .line 50
    .line 51
    if-lez v0, :cond_1

    .line 52
    .line 53
    long-to-int p0, v2

    .line 54
    :cond_1
    return p0
.end method

.method public getScanJobRuntimeMillis()I
    .locals 4

    .line 1
    sget-object v0, Lorg/altbeacon/beacon/service/ScanState;->TAG:Ljava/lang/String;

    .line 2
    .line 3
    new-instance v1, Ljava/lang/StringBuilder;

    .line 4
    .line 5
    const-string v2, "ScanState says background mode for ScanJob is "

    .line 6
    .line 7
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    invoke-virtual {p0}, Lorg/altbeacon/beacon/service/ScanState;->getBackgroundMode()Ljava/lang/Boolean;

    .line 11
    .line 12
    .line 13
    move-result-object v2

    .line 14
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 15
    .line 16
    .line 17
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 18
    .line 19
    .line 20
    move-result-object v1

    .line 21
    const/4 v2, 0x0

    .line 22
    new-array v2, v2, [Ljava/lang/Object;

    .line 23
    .line 24
    invoke-static {v0, v1, v2}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 25
    .line 26
    .line 27
    invoke-virtual {p0}, Lorg/altbeacon/beacon/service/ScanState;->getBackgroundMode()Ljava/lang/Boolean;

    .line 28
    .line 29
    .line 30
    move-result-object v0

    .line 31
    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 32
    .line 33
    .line 34
    move-result v0

    .line 35
    if-eqz v0, :cond_0

    .line 36
    .line 37
    invoke-virtual {p0}, Lorg/altbeacon/beacon/service/ScanState;->getBackgroundScanPeriod()Ljava/lang/Long;

    .line 38
    .line 39
    .line 40
    move-result-object v0

    .line 41
    invoke-virtual {v0}, Ljava/lang/Long;->longValue()J

    .line 42
    .line 43
    .line 44
    move-result-wide v0

    .line 45
    goto :goto_0

    .line 46
    :cond_0
    invoke-virtual {p0}, Lorg/altbeacon/beacon/service/ScanState;->getForegroundScanPeriod()Ljava/lang/Long;

    .line 47
    .line 48
    .line 49
    move-result-object v0

    .line 50
    invoke-virtual {v0}, Ljava/lang/Long;->longValue()J

    .line 51
    .line 52
    .line 53
    move-result-wide v0

    .line 54
    :goto_0
    invoke-virtual {p0}, Lorg/altbeacon/beacon/service/ScanState;->getBackgroundMode()Ljava/lang/Boolean;

    .line 55
    .line 56
    .line 57
    move-result-object p0

    .line 58
    invoke-virtual {p0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 59
    .line 60
    .line 61
    move-result p0

    .line 62
    if-nez p0, :cond_1

    .line 63
    .line 64
    sget p0, Lorg/altbeacon/beacon/service/ScanState;->MIN_SCAN_JOB_INTERVAL_MILLIS:I

    .line 65
    .line 66
    int-to-long v2, p0

    .line 67
    cmp-long v2, v0, v2

    .line 68
    .line 69
    if-gez v2, :cond_1

    .line 70
    .line 71
    return p0

    .line 72
    :cond_1
    long-to-int p0, v0

    .line 73
    return p0
.end method

.method public save()V
    .locals 10

    .line 1
    const-string v0, "Perm file is "

    .line 2
    .line 3
    const-string v1, "Temp file is "

    .line 4
    .line 5
    const-class v2, Lorg/altbeacon/beacon/service/ScanState;

    .line 6
    .line 7
    monitor-enter v2

    .line 8
    const/4 v3, 0x0

    .line 9
    const/4 v4, 0x0

    .line 10
    :try_start_0
    iget-object v5, p0, Lorg/altbeacon/beacon/service/ScanState;->mContext:Landroid/content/Context;

    .line 11
    .line 12
    const-string v6, "android-beacon-library-scan-state-temp"

    .line 13
    .line 14
    invoke-virtual {v5, v6, v3}, Landroid/content/Context;->openFileOutput(Ljava/lang/String;I)Ljava/io/FileOutputStream;

    .line 15
    .line 16
    .line 17
    move-result-object v5
    :try_end_0
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_3
    .catchall {:try_start_0 .. :try_end_0} :catchall_3

    .line 18
    :try_start_1
    new-instance v6, Ljava/io/ObjectOutputStream;

    .line 19
    .line 20
    invoke-direct {v6, v5}, Ljava/io/ObjectOutputStream;-><init>(Ljava/io/OutputStream;)V
    :try_end_1
    .catch Ljava/io/IOException; {:try_start_1 .. :try_end_1} :catch_2
    .catchall {:try_start_1 .. :try_end_1} :catchall_2

    .line 21
    .line 22
    .line 23
    :try_start_2
    invoke-virtual {v6, p0}, Ljava/io/ObjectOutputStream;->writeObject(Ljava/lang/Object;)V
    :try_end_2
    .catch Ljava/io/IOException; {:try_start_2 .. :try_end_2} :catch_1
    .catchall {:try_start_2 .. :try_end_2} :catchall_1

    .line 24
    .line 25
    .line 26
    if-eqz v5, :cond_0

    .line 27
    .line 28
    :try_start_3
    invoke-virtual {v5}, Ljava/io/FileOutputStream;->close()V
    :try_end_3
    .catch Ljava/io/IOException; {:try_start_3 .. :try_end_3} :catch_0
    .catchall {:try_start_3 .. :try_end_3} :catchall_0

    .line 29
    .line 30
    .line 31
    goto :goto_0

    .line 32
    :catchall_0
    move-exception p0

    .line 33
    goto/16 :goto_5

    .line 34
    .line 35
    :catch_0
    :cond_0
    :goto_0
    :try_start_4
    invoke-virtual {v6}, Ljava/io/ObjectOutputStream;->close()V
    :try_end_4
    .catch Ljava/io/IOException; {:try_start_4 .. :try_end_4} :catch_5
    .catchall {:try_start_4 .. :try_end_4} :catchall_0

    .line 36
    .line 37
    .line 38
    goto :goto_3

    .line 39
    :catchall_1
    move-exception p0

    .line 40
    :goto_1
    move-object v4, v5

    .line 41
    goto/16 :goto_4

    .line 42
    .line 43
    :catch_1
    move-exception v4

    .line 44
    goto :goto_2

    .line 45
    :catchall_2
    move-exception p0

    .line 46
    move-object v6, v4

    .line 47
    goto :goto_1

    .line 48
    :catch_2
    move-exception v6

    .line 49
    move-object v9, v6

    .line 50
    move-object v6, v4

    .line 51
    move-object v4, v9

    .line 52
    goto :goto_2

    .line 53
    :catchall_3
    move-exception p0

    .line 54
    move-object v6, v4

    .line 55
    goto/16 :goto_4

    .line 56
    .line 57
    :catch_3
    move-exception v5

    .line 58
    move-object v6, v4

    .line 59
    move-object v4, v5

    .line 60
    move-object v5, v6

    .line 61
    :goto_2
    :try_start_5
    sget-object v7, Lorg/altbeacon/beacon/service/ScanState;->TAG:Ljava/lang/String;

    .line 62
    .line 63
    const-string v8, "Error while saving scan status to file: "

    .line 64
    .line 65
    invoke-virtual {v4}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    .line 66
    .line 67
    .line 68
    move-result-object v4

    .line 69
    filled-new-array {v4}, [Ljava/lang/Object;

    .line 70
    .line 71
    .line 72
    move-result-object v4

    .line 73
    invoke-static {v7, v8, v4}, Lorg/altbeacon/beacon/logging/LogManager;->e(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_1

    .line 74
    .line 75
    .line 76
    if-eqz v5, :cond_1

    .line 77
    .line 78
    :try_start_6
    invoke-virtual {v5}, Ljava/io/FileOutputStream;->close()V
    :try_end_6
    .catch Ljava/io/IOException; {:try_start_6 .. :try_end_6} :catch_4
    .catchall {:try_start_6 .. :try_end_6} :catchall_0

    .line 79
    .line 80
    .line 81
    :catch_4
    :cond_1
    if-eqz v6, :cond_2

    .line 82
    .line 83
    goto :goto_0

    .line 84
    :catch_5
    :cond_2
    :goto_3
    :try_start_7
    new-instance v4, Ljava/io/File;

    .line 85
    .line 86
    iget-object v5, p0, Lorg/altbeacon/beacon/service/ScanState;->mContext:Landroid/content/Context;

    .line 87
    .line 88
    invoke-virtual {v5}, Landroid/content/Context;->getFilesDir()Ljava/io/File;

    .line 89
    .line 90
    .line 91
    move-result-object v5

    .line 92
    const-string v6, "android-beacon-library-scan-state"

    .line 93
    .line 94
    invoke-direct {v4, v5, v6}, Ljava/io/File;-><init>(Ljava/io/File;Ljava/lang/String;)V

    .line 95
    .line 96
    .line 97
    new-instance v5, Ljava/io/File;

    .line 98
    .line 99
    iget-object v6, p0, Lorg/altbeacon/beacon/service/ScanState;->mContext:Landroid/content/Context;

    .line 100
    .line 101
    invoke-virtual {v6}, Landroid/content/Context;->getFilesDir()Ljava/io/File;

    .line 102
    .line 103
    .line 104
    move-result-object v6

    .line 105
    const-string v7, "android-beacon-library-scan-state-temp"

    .line 106
    .line 107
    invoke-direct {v5, v6, v7}, Ljava/io/File;-><init>(Ljava/io/File;Ljava/lang/String;)V

    .line 108
    .line 109
    .line 110
    sget-object v6, Lorg/altbeacon/beacon/service/ScanState;->TAG:Ljava/lang/String;

    .line 111
    .line 112
    new-instance v7, Ljava/lang/StringBuilder;

    .line 113
    .line 114
    invoke-direct {v7, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 115
    .line 116
    .line 117
    invoke-virtual {v5}, Ljava/io/File;->getAbsolutePath()Ljava/lang/String;

    .line 118
    .line 119
    .line 120
    move-result-object v1

    .line 121
    invoke-virtual {v7, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 122
    .line 123
    .line 124
    invoke-virtual {v7}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 125
    .line 126
    .line 127
    move-result-object v1

    .line 128
    new-array v7, v3, [Ljava/lang/Object;

    .line 129
    .line 130
    invoke-static {v6, v1, v7}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 131
    .line 132
    .line 133
    new-instance v1, Ljava/lang/StringBuilder;

    .line 134
    .line 135
    invoke-direct {v1, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 136
    .line 137
    .line 138
    invoke-virtual {v4}, Ljava/io/File;->getAbsolutePath()Ljava/lang/String;

    .line 139
    .line 140
    .line 141
    move-result-object v0

    .line 142
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 143
    .line 144
    .line 145
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 146
    .line 147
    .line 148
    move-result-object v0

    .line 149
    new-array v1, v3, [Ljava/lang/Object;

    .line 150
    .line 151
    invoke-static {v6, v0, v1}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 152
    .line 153
    .line 154
    invoke-virtual {v4}, Ljava/io/File;->delete()Z

    .line 155
    .line 156
    .line 157
    move-result v0

    .line 158
    if-nez v0, :cond_3

    .line 159
    .line 160
    const-string v0, "Error while saving scan status to file: Cannot delete existing file."

    .line 161
    .line 162
    new-array v1, v3, [Ljava/lang/Object;

    .line 163
    .line 164
    invoke-static {v6, v0, v1}, Lorg/altbeacon/beacon/logging/LogManager;->e(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 165
    .line 166
    .line 167
    :cond_3
    invoke-virtual {v5, v4}, Ljava/io/File;->renameTo(Ljava/io/File;)Z

    .line 168
    .line 169
    .line 170
    move-result v0

    .line 171
    if-nez v0, :cond_4

    .line 172
    .line 173
    const-string v0, "Error while saving scan status to file: Cannot rename temp file."

    .line 174
    .line 175
    new-array v1, v3, [Ljava/lang/Object;

    .line 176
    .line 177
    invoke-static {v6, v0, v1}, Lorg/altbeacon/beacon/logging/LogManager;->e(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 178
    .line 179
    .line 180
    :cond_4
    iget-object p0, p0, Lorg/altbeacon/beacon/service/ScanState;->mMonitoringStatus:Lorg/altbeacon/beacon/service/MonitoringStatus;

    .line 181
    .line 182
    invoke-virtual {p0}, Lorg/altbeacon/beacon/service/MonitoringStatus;->saveMonitoringStatusIfOn()V

    .line 183
    .line 184
    .line 185
    monitor-exit v2
    :try_end_7
    .catchall {:try_start_7 .. :try_end_7} :catchall_0

    .line 186
    return-void

    .line 187
    :goto_4
    if-eqz v4, :cond_5

    .line 188
    .line 189
    :try_start_8
    invoke-virtual {v4}, Ljava/io/FileOutputStream;->close()V
    :try_end_8
    .catch Ljava/io/IOException; {:try_start_8 .. :try_end_8} :catch_6
    .catchall {:try_start_8 .. :try_end_8} :catchall_0

    .line 190
    .line 191
    .line 192
    :catch_6
    :cond_5
    if-eqz v6, :cond_6

    .line 193
    .line 194
    :try_start_9
    invoke-virtual {v6}, Ljava/io/ObjectOutputStream;->close()V
    :try_end_9
    .catch Ljava/io/IOException; {:try_start_9 .. :try_end_9} :catch_7
    .catchall {:try_start_9 .. :try_end_9} :catchall_0

    .line 195
    .line 196
    .line 197
    :catch_7
    :cond_6
    :try_start_a
    throw p0

    .line 198
    :goto_5
    monitor-exit v2
    :try_end_a
    .catchall {:try_start_a .. :try_end_a} :catchall_0

    .line 199
    throw p0
.end method

.method public setBackgroundBetweenScanPeriod(Ljava/lang/Long;)V
    .locals 2

    .line 1
    invoke-virtual {p1}, Ljava/lang/Long;->longValue()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    iput-wide v0, p0, Lorg/altbeacon/beacon/service/ScanState;->mBackgroundBetweenScanPeriod:J

    .line 6
    .line 7
    return-void
.end method

.method public setBackgroundMode(Ljava/lang/Boolean;)V
    .locals 0

    .line 1
    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 2
    .line 3
    .line 4
    move-result p1

    .line 5
    iput-boolean p1, p0, Lorg/altbeacon/beacon/service/ScanState;->mBackgroundMode:Z

    .line 6
    .line 7
    return-void
.end method

.method public setBackgroundScanPeriod(Ljava/lang/Long;)V
    .locals 2

    .line 1
    invoke-virtual {p1}, Ljava/lang/Long;->longValue()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    iput-wide v0, p0, Lorg/altbeacon/beacon/service/ScanState;->mBackgroundScanPeriod:J

    .line 6
    .line 7
    return-void
.end method

.method public setBeaconParsers(Ljava/util/Set;)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/Set<",
            "Lorg/altbeacon/beacon/BeaconParser;",
            ">;)V"
        }
    .end annotation

    .line 1
    iput-object p1, p0, Lorg/altbeacon/beacon/service/ScanState;->mBeaconParsers:Ljava/util/Set;

    .line 2
    .line 3
    return-void
.end method

.method public setExtraBeaconDataTracker(Lorg/altbeacon/beacon/service/ExtraDataBeaconTracker;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lorg/altbeacon/beacon/service/ScanState;->mExtraBeaconDataTracker:Lorg/altbeacon/beacon/service/ExtraDataBeaconTracker;

    .line 2
    .line 3
    return-void
.end method

.method public setForegroundBetweenScanPeriod(Ljava/lang/Long;)V
    .locals 2

    .line 1
    invoke-virtual {p1}, Ljava/lang/Long;->longValue()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    iput-wide v0, p0, Lorg/altbeacon/beacon/service/ScanState;->mForegroundBetweenScanPeriod:J

    .line 6
    .line 7
    return-void
.end method

.method public setForegroundScanPeriod(Ljava/lang/Long;)V
    .locals 2

    .line 1
    invoke-virtual {p1}, Ljava/lang/Long;->longValue()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    iput-wide v0, p0, Lorg/altbeacon/beacon/service/ScanState;->mForegroundScanPeriod:J

    .line 6
    .line 7
    return-void
.end method

.method public setLastScanStartTimeMillis(J)V
    .locals 0

    .line 1
    iput-wide p1, p0, Lorg/altbeacon/beacon/service/ScanState;->mLastScanStartTimeMillis:J

    .line 2
    .line 3
    return-void
.end method

.method public setMonitoringStatus(Lorg/altbeacon/beacon/service/MonitoringStatus;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lorg/altbeacon/beacon/service/ScanState;->mMonitoringStatus:Lorg/altbeacon/beacon/service/MonitoringStatus;

    .line 2
    .line 3
    return-void
.end method

.method public setRangedRegionState(Ljava/util/Map;)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/Map<",
            "Lorg/altbeacon/beacon/Region;",
            "Lorg/altbeacon/beacon/service/RangeState;",
            ">;)V"
        }
    .end annotation

    .line 1
    iput-object p1, p0, Lorg/altbeacon/beacon/service/ScanState;->mRangedRegionState:Ljava/util/Map;

    .line 2
    .line 3
    return-void
.end method
