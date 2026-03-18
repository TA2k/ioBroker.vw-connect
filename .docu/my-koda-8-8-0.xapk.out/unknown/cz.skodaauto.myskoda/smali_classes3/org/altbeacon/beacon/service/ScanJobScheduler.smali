.class public Lorg/altbeacon/beacon/service/ScanJobScheduler;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field private static final MIN_MILLIS_BETWEEN_SCAN_JOB_SCHEDULING:J = 0x2710L

.field private static final SINGLETON_LOCK:Ljava/lang/Object;

.field private static final TAG:Ljava/lang/String; = "ScanJobScheduler"

.field private static volatile sInstance:Lorg/altbeacon/beacon/service/ScanJobScheduler;


# instance fields
.field private mBackgroundScanJobFirstRun:Z

.field private mBackgroundScanResultQueue:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "Landroid/bluetooth/le/ScanResult;",
            ">;"
        }
    .end annotation
.end field

.field private mBeaconNotificationProcessor:Lorg/altbeacon/beacon/BeaconLocalBroadcastProcessor;

.field private mScanJobScheduleTime:Ljava/lang/Long;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Ljava/lang/Object;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lorg/altbeacon/beacon/service/ScanJobScheduler;->SINGLETON_LOCK:Ljava/lang/Object;

    .line 7
    .line 8
    return-void
.end method

.method private constructor <init>()V
    .locals 2

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    const-wide/16 v0, 0x0

    .line 5
    .line 6
    invoke-static {v0, v1}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 7
    .line 8
    .line 9
    move-result-object v0

    .line 10
    iput-object v0, p0, Lorg/altbeacon/beacon/service/ScanJobScheduler;->mScanJobScheduleTime:Ljava/lang/Long;

    .line 11
    .line 12
    new-instance v0, Ljava/util/ArrayList;

    .line 13
    .line 14
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 15
    .line 16
    .line 17
    iput-object v0, p0, Lorg/altbeacon/beacon/service/ScanJobScheduler;->mBackgroundScanResultQueue:Ljava/util/List;

    .line 18
    .line 19
    const/4 v0, 0x1

    .line 20
    iput-boolean v0, p0, Lorg/altbeacon/beacon/service/ScanJobScheduler;->mBackgroundScanJobFirstRun:Z

    .line 21
    .line 22
    return-void
.end method

.method private applySettingsToScheduledJob(Landroid/content/Context;Lorg/altbeacon/beacon/BeaconManager;Lorg/altbeacon/beacon/service/ScanState;)V
    .locals 3

    .line 1
    invoke-virtual {p3, p2}, Lorg/altbeacon/beacon/service/ScanState;->applyChanges(Lorg/altbeacon/beacon/BeaconManager;)V

    .line 2
    sget-object p2, Lorg/altbeacon/beacon/service/ScanJobScheduler;->TAG:Ljava/lang/String;

    new-instance v0, Ljava/lang/StringBuilder;

    const-string v1, "Applying scan job settings with background mode "

    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {p3}, Lorg/altbeacon/beacon/service/ScanState;->getBackgroundMode()Ljava/lang/Boolean;

    move-result-object v1

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    const/4 v1, 0x0

    new-array v2, v1, [Ljava/lang/Object;

    invoke-static {p2, v0, v2}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 3
    iget-boolean v0, p0, Lorg/altbeacon/beacon/service/ScanJobScheduler;->mBackgroundScanJobFirstRun:Z

    if-eqz v0, :cond_0

    invoke-virtual {p3}, Lorg/altbeacon/beacon/service/ScanState;->getBackgroundMode()Ljava/lang/Boolean;

    move-result-object v0

    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v0

    if-eqz v0, :cond_0

    .line 4
    const-string v0, "This is the first time we schedule a job and we are in background, set immediate scan flag to true in order to trigger the HW filter install."

    new-array v1, v1, [Ljava/lang/Object;

    invoke-static {p2, v0, v1}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    const/4 v1, 0x1

    .line 5
    :cond_0
    invoke-direct {p0, p1, p3, v1}, Lorg/altbeacon/beacon/service/ScanJobScheduler;->schedule(Landroid/content/Context;Lorg/altbeacon/beacon/service/ScanState;Z)V

    return-void
.end method

.method public static getInstance()Lorg/altbeacon/beacon/service/ScanJobScheduler;
    .locals 2

    .line 1
    sget-object v0, Lorg/altbeacon/beacon/service/ScanJobScheduler;->sInstance:Lorg/altbeacon/beacon/service/ScanJobScheduler;

    .line 2
    .line 3
    if-nez v0, :cond_1

    .line 4
    .line 5
    sget-object v1, Lorg/altbeacon/beacon/service/ScanJobScheduler;->SINGLETON_LOCK:Ljava/lang/Object;

    .line 6
    .line 7
    monitor-enter v1

    .line 8
    :try_start_0
    sget-object v0, Lorg/altbeacon/beacon/service/ScanJobScheduler;->sInstance:Lorg/altbeacon/beacon/service/ScanJobScheduler;

    .line 9
    .line 10
    if-nez v0, :cond_0

    .line 11
    .line 12
    new-instance v0, Lorg/altbeacon/beacon/service/ScanJobScheduler;

    .line 13
    .line 14
    invoke-direct {v0}, Lorg/altbeacon/beacon/service/ScanJobScheduler;-><init>()V

    .line 15
    .line 16
    .line 17
    sput-object v0, Lorg/altbeacon/beacon/service/ScanJobScheduler;->sInstance:Lorg/altbeacon/beacon/service/ScanJobScheduler;

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :catchall_0
    move-exception v0

    .line 21
    goto :goto_1

    .line 22
    :cond_0
    :goto_0
    monitor-exit v1

    .line 23
    return-object v0

    .line 24
    :goto_1
    monitor-exit v1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 25
    throw v0

    .line 26
    :cond_1
    return-object v0
.end method

.method private schedule(Landroid/content/Context;Lorg/altbeacon/beacon/service/ScanState;Z)V
    .locals 12

    .line 1
    invoke-virtual {p0, p1}, Lorg/altbeacon/beacon/service/ScanJobScheduler;->ensureNotificationProcessorSetup(Landroid/content/Context;)V

    .line 2
    .line 3
    .line 4
    invoke-virtual {p2}, Lorg/altbeacon/beacon/service/ScanState;->getScanJobIntervalMillis()I

    .line 5
    .line 6
    .line 7
    move-result v0

    .line 8
    invoke-virtual {p2}, Lorg/altbeacon/beacon/service/ScanState;->getScanJobRuntimeMillis()I

    .line 9
    .line 10
    .line 11
    move-result v1

    .line 12
    sub-int/2addr v0, v1

    .line 13
    int-to-long v0, v0

    .line 14
    const-wide/16 v2, 0x0

    .line 15
    .line 16
    const/4 v4, 0x0

    .line 17
    if-eqz p3, :cond_0

    .line 18
    .line 19
    sget-object v0, Lorg/altbeacon/beacon/service/ScanJobScheduler;->TAG:Ljava/lang/String;

    .line 20
    .line 21
    const-string v1, "We just woke up in the background based on a new scan result or first run of the app. Start scan job immediately."

    .line 22
    .line 23
    new-array v5, v4, [Ljava/lang/Object;

    .line 24
    .line 25
    invoke-static {v0, v1, v5}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 26
    .line 27
    .line 28
    move-wide v0, v2

    .line 29
    goto :goto_1

    .line 30
    :cond_0
    cmp-long v0, v0, v2

    .line 31
    .line 32
    if-lez v0, :cond_1

    .line 33
    .line 34
    invoke-static {}, Landroid/os/SystemClock;->elapsedRealtime()J

    .line 35
    .line 36
    .line 37
    move-result-wide v0

    .line 38
    invoke-virtual {p2}, Lorg/altbeacon/beacon/service/ScanState;->getScanJobIntervalMillis()I

    .line 39
    .line 40
    .line 41
    move-result v5

    .line 42
    int-to-long v5, v5

    .line 43
    rem-long/2addr v0, v5

    .line 44
    goto :goto_0

    .line 45
    :cond_1
    move-wide v0, v2

    .line 46
    :goto_0
    const-wide/16 v5, 0x32

    .line 47
    .line 48
    cmp-long v7, v0, v5

    .line 49
    .line 50
    if-gez v7, :cond_2

    .line 51
    .line 52
    move-wide v0, v5

    .line 53
    :cond_2
    :goto_1
    const-string v5, "jobscheduler"

    .line 54
    .line 55
    invoke-virtual {p1, v5}, Landroid/content/Context;->getSystemService(Ljava/lang/String;)Ljava/lang/Object;

    .line 56
    .line 57
    .line 58
    move-result-object v5

    .line 59
    check-cast v5, Landroid/app/job/JobScheduler;

    .line 60
    .line 61
    invoke-virtual {p2}, Lorg/altbeacon/beacon/service/ScanState;->getMonitoringStatus()Lorg/altbeacon/beacon/service/MonitoringStatus;

    .line 62
    .line 63
    .line 64
    move-result-object v6

    .line 65
    invoke-virtual {v6}, Lorg/altbeacon/beacon/service/MonitoringStatus;->regions()Ljava/util/Set;

    .line 66
    .line 67
    .line 68
    move-result-object v6

    .line 69
    invoke-interface {v6}, Ljava/util/Set;->size()I

    .line 70
    .line 71
    .line 72
    move-result v6

    .line 73
    invoke-virtual {p2}, Lorg/altbeacon/beacon/service/ScanState;->getRangedRegionState()Ljava/util/Map;

    .line 74
    .line 75
    .line 76
    move-result-object v7

    .line 77
    invoke-interface {v7}, Ljava/util/Map;->size()I

    .line 78
    .line 79
    .line 80
    move-result v7

    .line 81
    add-int/2addr v7, v6

    .line 82
    if-lez v7, :cond_9

    .line 83
    .line 84
    const/4 v6, 0x1

    .line 85
    const-class v7, Lorg/altbeacon/beacon/service/ScanJob;

    .line 86
    .line 87
    const-string v8, " millis"

    .line 88
    .line 89
    if-nez p3, :cond_4

    .line 90
    .line 91
    invoke-virtual {p2}, Lorg/altbeacon/beacon/service/ScanState;->getBackgroundMode()Ljava/lang/Boolean;

    .line 92
    .line 93
    .line 94
    move-result-object p3

    .line 95
    invoke-virtual {p3}, Ljava/lang/Boolean;->booleanValue()Z

    .line 96
    .line 97
    .line 98
    move-result p3

    .line 99
    if-nez p3, :cond_3

    .line 100
    .line 101
    goto :goto_2

    .line 102
    :cond_3
    sget-object p0, Lorg/altbeacon/beacon/service/ScanJobScheduler;->TAG:Ljava/lang/String;

    .line 103
    .line 104
    const-string p3, "Not scheduling an immediate scan because we are in background mode.   Cancelling existing immediate ScanJob."

    .line 105
    .line 106
    new-array v0, v4, [Ljava/lang/Object;

    .line 107
    .line 108
    invoke-static {p0, p3, v0}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 109
    .line 110
    .line 111
    invoke-static {p1}, Lorg/altbeacon/beacon/service/ScanJob;->getImmediateScanJobId(Landroid/content/Context;)I

    .line 112
    .line 113
    .line 114
    move-result p0

    .line 115
    invoke-virtual {v5, p0}, Landroid/app/job/JobScheduler;->cancel(I)V

    .line 116
    .line 117
    .line 118
    goto :goto_3

    .line 119
    :cond_4
    :goto_2
    invoke-virtual {p2}, Lorg/altbeacon/beacon/service/ScanState;->getScanJobIntervalMillis()I

    .line 120
    .line 121
    .line 122
    move-result p3

    .line 123
    add-int/lit8 p3, p3, -0x32

    .line 124
    .line 125
    int-to-long v9, p3

    .line 126
    cmp-long p3, v0, v9

    .line 127
    .line 128
    if-gez p3, :cond_6

    .line 129
    .line 130
    sget-object p3, Lorg/altbeacon/beacon/service/ScanJobScheduler;->TAG:Ljava/lang/String;

    .line 131
    .line 132
    const-string v9, "Scheduling immediate ScanJob to run in "

    .line 133
    .line 134
    invoke-static {v0, v1, v9, v8}, Lp3/m;->g(JLjava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 135
    .line 136
    .line 137
    move-result-object v9

    .line 138
    new-array v10, v4, [Ljava/lang/Object;

    .line 139
    .line 140
    invoke-static {p3, v9, v10}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 141
    .line 142
    .line 143
    new-instance v9, Landroid/app/job/JobInfo$Builder;

    .line 144
    .line 145
    invoke-static {p1}, Lorg/altbeacon/beacon/service/ScanJob;->getImmediateScanJobId(Landroid/content/Context;)I

    .line 146
    .line 147
    .line 148
    move-result v10

    .line 149
    new-instance v11, Landroid/content/ComponentName;

    .line 150
    .line 151
    invoke-direct {v11, p1, v7}, Landroid/content/ComponentName;-><init>(Landroid/content/Context;Ljava/lang/Class;)V

    .line 152
    .line 153
    .line 154
    invoke-direct {v9, v10, v11}, Landroid/app/job/JobInfo$Builder;-><init>(ILandroid/content/ComponentName;)V

    .line 155
    .line 156
    .line 157
    invoke-virtual {v9, v6}, Landroid/app/job/JobInfo$Builder;->setPersisted(Z)Landroid/app/job/JobInfo$Builder;

    .line 158
    .line 159
    .line 160
    move-result-object v9

    .line 161
    new-instance v10, Landroid/os/PersistableBundle;

    .line 162
    .line 163
    invoke-direct {v10}, Landroid/os/PersistableBundle;-><init>()V

    .line 164
    .line 165
    .line 166
    invoke-virtual {v9, v10}, Landroid/app/job/JobInfo$Builder;->setExtras(Landroid/os/PersistableBundle;)Landroid/app/job/JobInfo$Builder;

    .line 167
    .line 168
    .line 169
    move-result-object v9

    .line 170
    invoke-virtual {v9, v0, v1}, Landroid/app/job/JobInfo$Builder;->setMinimumLatency(J)Landroid/app/job/JobInfo$Builder;

    .line 171
    .line 172
    .line 173
    move-result-object v9

    .line 174
    invoke-virtual {v9, v0, v1}, Landroid/app/job/JobInfo$Builder;->setOverrideDeadline(J)Landroid/app/job/JobInfo$Builder;

    .line 175
    .line 176
    .line 177
    move-result-object v0

    .line 178
    invoke-virtual {v0}, Landroid/app/job/JobInfo$Builder;->build()Landroid/app/job/JobInfo;

    .line 179
    .line 180
    .line 181
    move-result-object v0

    .line 182
    invoke-virtual {v5, v0}, Landroid/app/job/JobScheduler;->schedule(Landroid/app/job/JobInfo;)I

    .line 183
    .line 184
    .line 185
    move-result v0

    .line 186
    if-gez v0, :cond_5

    .line 187
    .line 188
    const-string p0, "Failed to schedule an immediate scan job.  Beacons will not be detected. Error: "

    .line 189
    .line 190
    invoke-static {v0, p0}, Lkx/a;->h(ILjava/lang/String;)Ljava/lang/String;

    .line 191
    .line 192
    .line 193
    move-result-object p0

    .line 194
    new-array v0, v4, [Ljava/lang/Object;

    .line 195
    .line 196
    invoke-static {p3, p0, v0}, Lorg/altbeacon/beacon/logging/LogManager;->e(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 197
    .line 198
    .line 199
    goto :goto_3

    .line 200
    :cond_5
    iget-boolean v0, p0, Lorg/altbeacon/beacon/service/ScanJobScheduler;->mBackgroundScanJobFirstRun:Z

    .line 201
    .line 202
    if-eqz v0, :cond_7

    .line 203
    .line 204
    const-string v0, "First immediate scan job scheduled successful, change the flag to false."

    .line 205
    .line 206
    new-array v1, v4, [Ljava/lang/Object;

    .line 207
    .line 208
    invoke-static {p3, v0, v1}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 209
    .line 210
    .line 211
    iput-boolean v4, p0, Lorg/altbeacon/beacon/service/ScanJobScheduler;->mBackgroundScanJobFirstRun:Z

    .line 212
    .line 213
    goto :goto_3

    .line 214
    :cond_6
    sget-object p0, Lorg/altbeacon/beacon/service/ScanJobScheduler;->TAG:Ljava/lang/String;

    .line 215
    .line 216
    const-string p3, "Not scheduling immediate scan, assuming periodic is about to run"

    .line 217
    .line 218
    new-array v0, v4, [Ljava/lang/Object;

    .line 219
    .line 220
    invoke-static {p0, p3, v0}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 221
    .line 222
    .line 223
    :cond_7
    :goto_3
    new-instance p0, Landroid/app/job/JobInfo$Builder;

    .line 224
    .line 225
    invoke-static {p1}, Lorg/altbeacon/beacon/service/ScanJob;->getPeriodicScanJobId(Landroid/content/Context;)I

    .line 226
    .line 227
    .line 228
    move-result p3

    .line 229
    new-instance v0, Landroid/content/ComponentName;

    .line 230
    .line 231
    invoke-direct {v0, p1, v7}, Landroid/content/ComponentName;-><init>(Landroid/content/Context;Ljava/lang/Class;)V

    .line 232
    .line 233
    .line 234
    invoke-direct {p0, p3, v0}, Landroid/app/job/JobInfo$Builder;-><init>(ILandroid/content/ComponentName;)V

    .line 235
    .line 236
    .line 237
    invoke-virtual {p0, v6}, Landroid/app/job/JobInfo$Builder;->setPersisted(Z)Landroid/app/job/JobInfo$Builder;

    .line 238
    .line 239
    .line 240
    move-result-object p0

    .line 241
    new-instance p1, Landroid/os/PersistableBundle;

    .line 242
    .line 243
    invoke-direct {p1}, Landroid/os/PersistableBundle;-><init>()V

    .line 244
    .line 245
    .line 246
    invoke-virtual {p0, p1}, Landroid/app/job/JobInfo$Builder;->setExtras(Landroid/os/PersistableBundle;)Landroid/app/job/JobInfo$Builder;

    .line 247
    .line 248
    .line 249
    move-result-object p0

    .line 250
    invoke-virtual {p2}, Lorg/altbeacon/beacon/service/ScanState;->getScanJobIntervalMillis()I

    .line 251
    .line 252
    .line 253
    move-result p1

    .line 254
    int-to-long v0, p1

    .line 255
    invoke-virtual {p0, v0, v1, v2, v3}, Landroid/app/job/JobInfo$Builder;->setPeriodic(JJ)Landroid/app/job/JobInfo$Builder;

    .line 256
    .line 257
    .line 258
    move-result-object p1

    .line 259
    invoke-virtual {p1}, Landroid/app/job/JobInfo$Builder;->build()Landroid/app/job/JobInfo;

    .line 260
    .line 261
    .line 262
    invoke-virtual {p0}, Landroid/app/job/JobInfo$Builder;->build()Landroid/app/job/JobInfo;

    .line 263
    .line 264
    .line 265
    move-result-object p0

    .line 266
    sget-object p1, Lorg/altbeacon/beacon/service/ScanJobScheduler;->TAG:Ljava/lang/String;

    .line 267
    .line 268
    new-instance p3, Ljava/lang/StringBuilder;

    .line 269
    .line 270
    const-string v0, "Scheduling periodic ScanJob "

    .line 271
    .line 272
    invoke-direct {p3, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 273
    .line 274
    .line 275
    invoke-virtual {p3, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 276
    .line 277
    .line 278
    const-string v0, " to run every "

    .line 279
    .line 280
    invoke-virtual {p3, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 281
    .line 282
    .line 283
    invoke-virtual {p2}, Lorg/altbeacon/beacon/service/ScanState;->getScanJobIntervalMillis()I

    .line 284
    .line 285
    .line 286
    move-result p2

    .line 287
    invoke-virtual {p3, p2}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 288
    .line 289
    .line 290
    invoke-virtual {p3, v8}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 291
    .line 292
    .line 293
    invoke-virtual {p3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 294
    .line 295
    .line 296
    move-result-object p2

    .line 297
    new-array p3, v4, [Ljava/lang/Object;

    .line 298
    .line 299
    invoke-static {p1, p2, p3}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 300
    .line 301
    .line 302
    invoke-virtual {v5, p0}, Landroid/app/job/JobScheduler;->schedule(Landroid/app/job/JobInfo;)I

    .line 303
    .line 304
    .line 305
    move-result p0

    .line 306
    if-gez p0, :cond_8

    .line 307
    .line 308
    const-string p2, "Failed to schedule a periodic scan job.  Beacons will not be detected. Error: "

    .line 309
    .line 310
    invoke-static {p0, p2}, Lkx/a;->h(ILjava/lang/String;)Ljava/lang/String;

    .line 311
    .line 312
    .line 313
    move-result-object p0

    .line 314
    new-array p2, v4, [Ljava/lang/Object;

    .line 315
    .line 316
    invoke-static {p1, p0, p2}, Lorg/altbeacon/beacon/logging/LogManager;->e(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 317
    .line 318
    .line 319
    :cond_8
    return-void

    .line 320
    :cond_9
    sget-object p0, Lorg/altbeacon/beacon/service/ScanJobScheduler;->TAG:Ljava/lang/String;

    .line 321
    .line 322
    const-string p2, "We are not monitoring or ranging any regions.  We are going to cancel all scan jobs."

    .line 323
    .line 324
    new-array p3, v4, [Ljava/lang/Object;

    .line 325
    .line 326
    invoke-static {p0, p2, p3}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 327
    .line 328
    .line 329
    invoke-static {p1}, Lorg/altbeacon/beacon/service/ScanJob;->getImmediateScanJobId(Landroid/content/Context;)I

    .line 330
    .line 331
    .line 332
    move-result p0

    .line 333
    invoke-virtual {v5, p0}, Landroid/app/job/JobScheduler;->cancel(I)V

    .line 334
    .line 335
    .line 336
    invoke-static {p1}, Lorg/altbeacon/beacon/service/ScanJob;->getPeriodicScanJobId(Landroid/content/Context;)I

    .line 337
    .line 338
    .line 339
    move-result p0

    .line 340
    invoke-virtual {v5, p0}, Landroid/app/job/JobScheduler;->cancel(I)V

    .line 341
    .line 342
    .line 343
    new-instance p0, Lorg/altbeacon/beacon/service/ScanHelper;

    .line 344
    .line 345
    invoke-direct {p0, p1}, Lorg/altbeacon/beacon/service/ScanHelper;-><init>(Landroid/content/Context;)V

    .line 346
    .line 347
    .line 348
    invoke-virtual {p0}, Lorg/altbeacon/beacon/service/ScanHelper;->stopAndroidOBackgroundScan()V

    .line 349
    .line 350
    .line 351
    return-void
.end method


# virtual methods
.method public applySettingsToScheduledJob(Landroid/content/Context;Lorg/altbeacon/beacon/BeaconManager;)V
    .locals 3

    .line 6
    sget-object v0, Lorg/altbeacon/beacon/service/ScanJobScheduler;->TAG:Ljava/lang/String;

    const/4 v1, 0x0

    new-array v1, v1, [Ljava/lang/Object;

    const-string v2, "Applying settings to ScanJob"

    invoke-static {v0, v2, v1}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 7
    const-string v0, "jobscheduler"

    invoke-virtual {p1, v0}, Landroid/content/Context;->getSystemService(Ljava/lang/String;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Landroid/app/job/JobScheduler;

    .line 8
    invoke-static {p1}, Lorg/altbeacon/beacon/service/ScanState;->restore(Landroid/content/Context;)Lorg/altbeacon/beacon/service/ScanState;

    move-result-object v0

    .line 9
    invoke-direct {p0, p1, p2, v0}, Lorg/altbeacon/beacon/service/ScanJobScheduler;->applySettingsToScheduledJob(Landroid/content/Context;Lorg/altbeacon/beacon/BeaconManager;Lorg/altbeacon/beacon/service/ScanState;)V

    return-void
.end method

.method public cancelSchedule(Landroid/content/Context;)V
    .locals 2

    .line 1
    const-string v0, "jobscheduler"

    .line 2
    .line 3
    invoke-virtual {p1, v0}, Landroid/content/Context;->getSystemService(Ljava/lang/String;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, Landroid/app/job/JobScheduler;

    .line 8
    .line 9
    invoke-static {p1}, Lorg/altbeacon/beacon/service/ScanJob;->getImmediateScanJobId(Landroid/content/Context;)I

    .line 10
    .line 11
    .line 12
    move-result v1

    .line 13
    invoke-virtual {v0, v1}, Landroid/app/job/JobScheduler;->cancel(I)V

    .line 14
    .line 15
    .line 16
    invoke-static {p1}, Lorg/altbeacon/beacon/service/ScanJob;->getPeriodicScanJobId(Landroid/content/Context;)I

    .line 17
    .line 18
    .line 19
    move-result p1

    .line 20
    invoke-virtual {v0, p1}, Landroid/app/job/JobScheduler;->cancel(I)V

    .line 21
    .line 22
    .line 23
    iget-object p1, p0, Lorg/altbeacon/beacon/service/ScanJobScheduler;->mBeaconNotificationProcessor:Lorg/altbeacon/beacon/BeaconLocalBroadcastProcessor;

    .line 24
    .line 25
    if-eqz p1, :cond_0

    .line 26
    .line 27
    invoke-virtual {p1}, Lorg/altbeacon/beacon/BeaconLocalBroadcastProcessor;->unregister()V

    .line 28
    .line 29
    .line 30
    :cond_0
    const/4 p1, 0x1

    .line 31
    iput-boolean p1, p0, Lorg/altbeacon/beacon/service/ScanJobScheduler;->mBackgroundScanJobFirstRun:Z

    .line 32
    .line 33
    return-void
.end method

.method public dumpBackgroundScanResultQueue()Ljava/util/List;
    .locals 2
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/List<",
            "Landroid/bluetooth/le/ScanResult;",
            ">;"
        }
    .end annotation

    .line 1
    iget-object v0, p0, Lorg/altbeacon/beacon/service/ScanJobScheduler;->mBackgroundScanResultQueue:Ljava/util/List;

    .line 2
    .line 3
    new-instance v1, Ljava/util/ArrayList;

    .line 4
    .line 5
    invoke-direct {v1}, Ljava/util/ArrayList;-><init>()V

    .line 6
    .line 7
    .line 8
    iput-object v1, p0, Lorg/altbeacon/beacon/service/ScanJobScheduler;->mBackgroundScanResultQueue:Ljava/util/List;

    .line 9
    .line 10
    return-object v0
.end method

.method public ensureNotificationProcessorSetup(Landroid/content/Context;)V
    .locals 1

    .line 1
    iget-object v0, p0, Lorg/altbeacon/beacon/service/ScanJobScheduler;->mBeaconNotificationProcessor:Lorg/altbeacon/beacon/BeaconLocalBroadcastProcessor;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    invoke-static {p1}, Lorg/altbeacon/beacon/BeaconLocalBroadcastProcessor;->getInstance(Landroid/content/Context;)Lorg/altbeacon/beacon/BeaconLocalBroadcastProcessor;

    .line 6
    .line 7
    .line 8
    move-result-object p1

    .line 9
    iput-object p1, p0, Lorg/altbeacon/beacon/service/ScanJobScheduler;->mBeaconNotificationProcessor:Lorg/altbeacon/beacon/BeaconLocalBroadcastProcessor;

    .line 10
    .line 11
    :cond_0
    iget-object p0, p0, Lorg/altbeacon/beacon/service/ScanJobScheduler;->mBeaconNotificationProcessor:Lorg/altbeacon/beacon/BeaconLocalBroadcastProcessor;

    .line 12
    .line 13
    invoke-virtual {p0}, Lorg/altbeacon/beacon/BeaconLocalBroadcastProcessor;->register()V

    .line 14
    .line 15
    .line 16
    return-void
.end method

.method public forceScheduleNextScan(Landroid/content/Context;)V
    .locals 2

    .line 1
    invoke-static {p1}, Lorg/altbeacon/beacon/service/ScanState;->restore(Landroid/content/Context;)Lorg/altbeacon/beacon/service/ScanState;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    const/4 v1, 0x0

    .line 6
    invoke-direct {p0, p1, v0, v1}, Lorg/altbeacon/beacon/service/ScanJobScheduler;->schedule(Landroid/content/Context;Lorg/altbeacon/beacon/service/ScanState;Z)V

    .line 7
    .line 8
    .line 9
    return-void
.end method

.method public scheduleAfterBackgroundWakeup(Landroid/content/Context;Ljava/util/List;)V
    .locals 7
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Landroid/content/Context;",
            "Ljava/util/List<",
            "Landroid/bluetooth/le/ScanResult;",
            ">;)V"
        }
    .end annotation

    .line 1
    const-string v0, "scheduling an immediate scan job because last did "

    .line 2
    .line 3
    if-eqz p2, :cond_0

    .line 4
    .line 5
    iget-object v1, p0, Lorg/altbeacon/beacon/service/ScanJobScheduler;->mBackgroundScanResultQueue:Ljava/util/List;

    .line 6
    .line 7
    invoke-interface {v1, p2}, Ljava/util/List;->addAll(Ljava/util/Collection;)Z

    .line 8
    .line 9
    .line 10
    :cond_0
    monitor-enter p0

    .line 11
    :try_start_0
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    .line 12
    .line 13
    .line 14
    move-result-wide v1

    .line 15
    iget-object p2, p0, Lorg/altbeacon/beacon/service/ScanJobScheduler;->mScanJobScheduleTime:Ljava/lang/Long;

    .line 16
    .line 17
    invoke-virtual {p2}, Ljava/lang/Long;->longValue()J

    .line 18
    .line 19
    .line 20
    move-result-wide v3

    .line 21
    sub-long/2addr v1, v3

    .line 22
    const-wide/16 v3, 0x2710

    .line 23
    .line 24
    cmp-long p2, v1, v3

    .line 25
    .line 26
    const/4 v1, 0x0

    .line 27
    if-lez p2, :cond_1

    .line 28
    .line 29
    sget-object p2, Lorg/altbeacon/beacon/service/ScanJobScheduler;->TAG:Ljava/lang/String;

    .line 30
    .line 31
    new-instance v2, Ljava/lang/StringBuilder;

    .line 32
    .line 33
    invoke-direct {v2, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 34
    .line 35
    .line 36
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    .line 37
    .line 38
    .line 39
    move-result-wide v3

    .line 40
    iget-object v0, p0, Lorg/altbeacon/beacon/service/ScanJobScheduler;->mScanJobScheduleTime:Ljava/lang/Long;

    .line 41
    .line 42
    invoke-virtual {v0}, Ljava/lang/Long;->longValue()J

    .line 43
    .line 44
    .line 45
    move-result-wide v5

    .line 46
    sub-long/2addr v3, v5

    .line 47
    invoke-virtual {v2, v3, v4}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    .line 48
    .line 49
    .line 50
    const-string v0, "millis ago."

    .line 51
    .line 52
    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 53
    .line 54
    .line 55
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 56
    .line 57
    .line 58
    move-result-object v0

    .line 59
    new-array v1, v1, [Ljava/lang/Object;

    .line 60
    .line 61
    invoke-static {p2, v0, v1}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 62
    .line 63
    .line 64
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    .line 65
    .line 66
    .line 67
    move-result-wide v0

    .line 68
    invoke-static {v0, v1}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 69
    .line 70
    .line 71
    move-result-object p2

    .line 72
    iput-object p2, p0, Lorg/altbeacon/beacon/service/ScanJobScheduler;->mScanJobScheduleTime:Ljava/lang/Long;

    .line 73
    .line 74
    monitor-exit p0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 75
    invoke-static {p1}, Lorg/altbeacon/beacon/service/ScanState;->restore(Landroid/content/Context;)Lorg/altbeacon/beacon/service/ScanState;

    .line 76
    .line 77
    .line 78
    move-result-object p2

    .line 79
    const/4 v0, 0x1

    .line 80
    invoke-direct {p0, p1, p2, v0}, Lorg/altbeacon/beacon/service/ScanJobScheduler;->schedule(Landroid/content/Context;Lorg/altbeacon/beacon/service/ScanState;Z)V

    .line 81
    .line 82
    .line 83
    return-void

    .line 84
    :catchall_0
    move-exception p1

    .line 85
    goto :goto_0

    .line 86
    :cond_1
    :try_start_1
    sget-object p1, Lorg/altbeacon/beacon/service/ScanJobScheduler;->TAG:Ljava/lang/String;

    .line 87
    .line 88
    const-string p2, "Not scheduling an immediate scan job because we just did recently."

    .line 89
    .line 90
    new-array v0, v1, [Ljava/lang/Object;

    .line 91
    .line 92
    invoke-static {p1, p2, v0}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 93
    .line 94
    .line 95
    monitor-exit p0

    .line 96
    return-void

    .line 97
    :goto_0
    monitor-exit p0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 98
    throw p1
.end method

.method public scheduleForIntentScanStrategy(Landroid/content/Context;)V
    .locals 4

    .line 1
    new-instance p0, Landroid/app/job/JobInfo$Builder;

    .line 2
    .line 3
    invoke-static {p1}, Lorg/altbeacon/beacon/service/ScanJob;->getPeriodicScanJobId(Landroid/content/Context;)I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    new-instance v1, Landroid/content/ComponentName;

    .line 8
    .line 9
    const-class v2, Lorg/altbeacon/beacon/service/ScanJob;

    .line 10
    .line 11
    invoke-direct {v1, p1, v2}, Landroid/content/ComponentName;-><init>(Landroid/content/Context;Ljava/lang/Class;)V

    .line 12
    .line 13
    .line 14
    invoke-direct {p0, v0, v1}, Landroid/app/job/JobInfo$Builder;-><init>(ILandroid/content/ComponentName;)V

    .line 15
    .line 16
    .line 17
    const/4 v0, 0x1

    .line 18
    invoke-virtual {p0, v0}, Landroid/app/job/JobInfo$Builder;->setPersisted(Z)Landroid/app/job/JobInfo$Builder;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    new-instance v0, Landroid/os/PersistableBundle;

    .line 23
    .line 24
    invoke-direct {v0}, Landroid/os/PersistableBundle;-><init>()V

    .line 25
    .line 26
    .line 27
    invoke-virtual {p0, v0}, Landroid/app/job/JobInfo$Builder;->setExtras(Landroid/os/PersistableBundle;)Landroid/app/job/JobInfo$Builder;

    .line 28
    .line 29
    .line 30
    move-result-object p0

    .line 31
    const-wide/32 v0, 0xdbba0

    .line 32
    .line 33
    .line 34
    const-wide/16 v2, 0x0

    .line 35
    .line 36
    invoke-virtual {p0, v0, v1, v2, v3}, Landroid/app/job/JobInfo$Builder;->setPeriodic(JJ)Landroid/app/job/JobInfo$Builder;

    .line 37
    .line 38
    .line 39
    move-result-object v0

    .line 40
    invoke-virtual {v0}, Landroid/app/job/JobInfo$Builder;->build()Landroid/app/job/JobInfo;

    .line 41
    .line 42
    .line 43
    invoke-virtual {p0}, Landroid/app/job/JobInfo$Builder;->build()Landroid/app/job/JobInfo;

    .line 44
    .line 45
    .line 46
    move-result-object p0

    .line 47
    sget-object v0, Lorg/altbeacon/beacon/service/ScanJobScheduler;->TAG:Ljava/lang/String;

    .line 48
    .line 49
    new-instance v1, Ljava/lang/StringBuilder;

    .line 50
    .line 51
    const-string v2, "Scheduling periodic ScanJob "

    .line 52
    .line 53
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 54
    .line 55
    .line 56
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 57
    .line 58
    .line 59
    const-string v2, " to run every 15 minutes"

    .line 60
    .line 61
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 62
    .line 63
    .line 64
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 65
    .line 66
    .line 67
    move-result-object v1

    .line 68
    const/4 v2, 0x0

    .line 69
    new-array v3, v2, [Ljava/lang/Object;

    .line 70
    .line 71
    invoke-static {v0, v1, v3}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 72
    .line 73
    .line 74
    const-string v1, "jobscheduler"

    .line 75
    .line 76
    invoke-virtual {p1, v1}, Landroid/content/Context;->getSystemService(Ljava/lang/String;)Ljava/lang/Object;

    .line 77
    .line 78
    .line 79
    move-result-object p1

    .line 80
    check-cast p1, Landroid/app/job/JobScheduler;

    .line 81
    .line 82
    invoke-virtual {p1, p0}, Landroid/app/job/JobScheduler;->schedule(Landroid/app/job/JobInfo;)I

    .line 83
    .line 84
    .line 85
    move-result p0

    .line 86
    if-gez p0, :cond_0

    .line 87
    .line 88
    const-string p1, "Failed to schedule a periodic scan job to look for region exits. Error: "

    .line 89
    .line 90
    invoke-static {p0, p1}, Lkx/a;->h(ILjava/lang/String;)Ljava/lang/String;

    .line 91
    .line 92
    .line 93
    move-result-object p0

    .line 94
    new-array p1, v2, [Ljava/lang/Object;

    .line 95
    .line 96
    invoke-static {v0, p0, p1}, Lorg/altbeacon/beacon/logging/LogManager;->e(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 97
    .line 98
    .line 99
    :cond_0
    return-void
.end method
