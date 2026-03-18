.class Lorg/altbeacon/beacon/service/ScanJob$1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/lang/Runnable;


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Lorg/altbeacon/beacon/service/ScanJob;->onStartJob(Landroid/app/job/JobParameters;)Z
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x1
    name = null
.end annotation


# instance fields
.field final synthetic this$0:Lorg/altbeacon/beacon/service/ScanJob;

.field final synthetic val$jobParameters:Landroid/app/job/JobParameters;


# direct methods
.method public constructor <init>(Lorg/altbeacon/beacon/service/ScanJob;Landroid/app/job/JobParameters;)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()V"
        }
    .end annotation

    .line 1
    iput-object p1, p0, Lorg/altbeacon/beacon/service/ScanJob$1;->this$0:Lorg/altbeacon/beacon/service/ScanJob;

    .line 2
    .line 3
    iput-object p2, p0, Lorg/altbeacon/beacon/service/ScanJob$1;->val$jobParameters:Landroid/app/job/JobParameters;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public run()V
    .locals 13

    .line 1
    iget-object v0, p0, Lorg/altbeacon/beacon/service/ScanJob$1;->this$0:Lorg/altbeacon/beacon/service/ScanJob;

    .line 2
    .line 3
    invoke-static {v0}, Lorg/altbeacon/beacon/BeaconManager;->getInstanceForApplication(Landroid/content/Context;)Lorg/altbeacon/beacon/BeaconManager;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    invoke-virtual {v0}, Lorg/altbeacon/beacon/BeaconManager;->getIntentScanStrategyCoordinator()Lorg/altbeacon/beacon/service/IntentScanStrategyCoordinator;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    const/4 v1, 0x0

    .line 12
    if-eqz v0, :cond_1

    .line 13
    .line 14
    iget-object v2, p0, Lorg/altbeacon/beacon/service/ScanJob$1;->this$0:Lorg/altbeacon/beacon/service/ScanJob;

    .line 15
    .line 16
    monitor-enter v2

    .line 17
    :try_start_0
    iget-object v3, p0, Lorg/altbeacon/beacon/service/ScanJob$1;->this$0:Lorg/altbeacon/beacon/service/ScanJob;

    .line 18
    .line 19
    invoke-static {v3}, Lorg/altbeacon/beacon/service/ScanJob;->d(Lorg/altbeacon/beacon/service/ScanJob;)Z

    .line 20
    .line 21
    .line 22
    move-result v3

    .line 23
    if-eqz v3, :cond_0

    .line 24
    .line 25
    invoke-static {}, Lorg/altbeacon/beacon/service/ScanJob;->k()Ljava/lang/String;

    .line 26
    .line 27
    .line 28
    move-result-object v0

    .line 29
    const-string v3, "Quitting scan job before we even start.  Somebody told us to stop."

    .line 30
    .line 31
    new-array v4, v1, [Ljava/lang/Object;

    .line 32
    .line 33
    invoke-static {v0, v3, v4}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 34
    .line 35
    .line 36
    iget-object v0, p0, Lorg/altbeacon/beacon/service/ScanJob$1;->this$0:Lorg/altbeacon/beacon/service/ScanJob;

    .line 37
    .line 38
    iget-object p0, p0, Lorg/altbeacon/beacon/service/ScanJob$1;->val$jobParameters:Landroid/app/job/JobParameters;

    .line 39
    .line 40
    invoke-virtual {v0, p0, v1}, Landroid/app/job/JobService;->jobFinished(Landroid/app/job/JobParameters;Z)V

    .line 41
    .line 42
    .line 43
    monitor-exit v2

    .line 44
    return-void

    .line 45
    :catchall_0
    move-exception v0

    .line 46
    move-object p0, v0

    .line 47
    goto :goto_0

    .line 48
    :cond_0
    invoke-static {}, Lorg/altbeacon/beacon/service/ScanJob;->k()Ljava/lang/String;

    .line 49
    .line 50
    .line 51
    move-result-object v3

    .line 52
    const-string v4, "Scan job calling IntentScanStrategyCoordinator"

    .line 53
    .line 54
    new-array v5, v1, [Ljava/lang/Object;

    .line 55
    .line 56
    invoke-static {v3, v4, v5}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 57
    .line 58
    .line 59
    iget-object v3, p0, Lorg/altbeacon/beacon/service/ScanJob$1;->this$0:Lorg/altbeacon/beacon/service/ScanJob;

    .line 60
    .line 61
    invoke-virtual {v0, v3}, Lorg/altbeacon/beacon/service/IntentScanStrategyCoordinator;->performPeriodicProcessing(Landroid/content/Context;)V

    .line 62
    .line 63
    .line 64
    invoke-static {}, Lorg/altbeacon/beacon/service/ScanJob;->k()Ljava/lang/String;

    .line 65
    .line 66
    .line 67
    move-result-object v0

    .line 68
    const-string v3, "Scan job finished.  Calling jobFinished"

    .line 69
    .line 70
    new-array v4, v1, [Ljava/lang/Object;

    .line 71
    .line 72
    invoke-static {v0, v3, v4}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 73
    .line 74
    .line 75
    iget-object v0, p0, Lorg/altbeacon/beacon/service/ScanJob$1;->this$0:Lorg/altbeacon/beacon/service/ScanJob;

    .line 76
    .line 77
    iget-object p0, p0, Lorg/altbeacon/beacon/service/ScanJob$1;->val$jobParameters:Landroid/app/job/JobParameters;

    .line 78
    .line 79
    invoke-virtual {v0, p0, v1}, Landroid/app/job/JobService;->jobFinished(Landroid/app/job/JobParameters;Z)V

    .line 80
    .line 81
    .line 82
    monitor-exit v2

    .line 83
    return-void

    .line 84
    :goto_0
    monitor-exit v2
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 85
    throw p0

    .line 86
    :cond_1
    iget-object v0, p0, Lorg/altbeacon/beacon/service/ScanJob$1;->this$0:Lorg/altbeacon/beacon/service/ScanJob;

    .line 87
    .line 88
    invoke-static {v0}, Lorg/altbeacon/beacon/service/ScanJob;->f(Lorg/altbeacon/beacon/service/ScanJob;)Z

    .line 89
    .line 90
    .line 91
    move-result v0

    .line 92
    if-nez v0, :cond_2

    .line 93
    .line 94
    invoke-static {}, Lorg/altbeacon/beacon/service/ScanJob;->k()Ljava/lang/String;

    .line 95
    .line 96
    .line 97
    move-result-object v0

    .line 98
    const-string v2, "Cannot allocate a scanner to look for beacons.  System resources are low."

    .line 99
    .line 100
    new-array v3, v1, [Ljava/lang/Object;

    .line 101
    .line 102
    invoke-static {v0, v2, v3}, Lorg/altbeacon/beacon/logging/LogManager;->e(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 103
    .line 104
    .line 105
    iget-object v0, p0, Lorg/altbeacon/beacon/service/ScanJob$1;->this$0:Lorg/altbeacon/beacon/service/ScanJob;

    .line 106
    .line 107
    iget-object v2, p0, Lorg/altbeacon/beacon/service/ScanJob$1;->val$jobParameters:Landroid/app/job/JobParameters;

    .line 108
    .line 109
    invoke-virtual {v0, v2, v1}, Landroid/app/job/JobService;->jobFinished(Landroid/app/job/JobParameters;Z)V

    .line 110
    .line 111
    .line 112
    :cond_2
    invoke-static {}, Lorg/altbeacon/beacon/service/ScanJobScheduler;->getInstance()Lorg/altbeacon/beacon/service/ScanJobScheduler;

    .line 113
    .line 114
    .line 115
    move-result-object v0

    .line 116
    iget-object v2, p0, Lorg/altbeacon/beacon/service/ScanJob$1;->this$0:Lorg/altbeacon/beacon/service/ScanJob;

    .line 117
    .line 118
    invoke-virtual {v2}, Landroid/content/Context;->getApplicationContext()Landroid/content/Context;

    .line 119
    .line 120
    .line 121
    move-result-object v2

    .line 122
    invoke-virtual {v0, v2}, Lorg/altbeacon/beacon/service/ScanJobScheduler;->ensureNotificationProcessorSetup(Landroid/content/Context;)V

    .line 123
    .line 124
    .line 125
    iget-object v0, p0, Lorg/altbeacon/beacon/service/ScanJob$1;->val$jobParameters:Landroid/app/job/JobParameters;

    .line 126
    .line 127
    invoke-virtual {v0}, Landroid/app/job/JobParameters;->getJobId()I

    .line 128
    .line 129
    .line 130
    move-result v0

    .line 131
    iget-object v2, p0, Lorg/altbeacon/beacon/service/ScanJob$1;->this$0:Lorg/altbeacon/beacon/service/ScanJob;

    .line 132
    .line 133
    invoke-static {v2}, Lorg/altbeacon/beacon/service/ScanJob;->getImmediateScanJobId(Landroid/content/Context;)I

    .line 134
    .line 135
    .line 136
    move-result v2

    .line 137
    if-ne v0, v2, :cond_3

    .line 138
    .line 139
    invoke-static {}, Lorg/altbeacon/beacon/service/ScanJob;->k()Ljava/lang/String;

    .line 140
    .line 141
    .line 142
    move-result-object v0

    .line 143
    new-instance v2, Ljava/lang/StringBuilder;

    .line 144
    .line 145
    const-string v3, "Running immediate scan job: instance is "

    .line 146
    .line 147
    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 148
    .line 149
    .line 150
    iget-object v3, p0, Lorg/altbeacon/beacon/service/ScanJob$1;->this$0:Lorg/altbeacon/beacon/service/ScanJob;

    .line 151
    .line 152
    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 153
    .line 154
    .line 155
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 156
    .line 157
    .line 158
    move-result-object v2

    .line 159
    new-array v3, v1, [Ljava/lang/Object;

    .line 160
    .line 161
    invoke-static {v0, v2, v3}, Lorg/altbeacon/beacon/logging/LogManager;->i(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 162
    .line 163
    .line 164
    goto :goto_1

    .line 165
    :cond_3
    invoke-static {}, Lorg/altbeacon/beacon/service/ScanJob;->k()Ljava/lang/String;

    .line 166
    .line 167
    .line 168
    move-result-object v0

    .line 169
    new-instance v2, Ljava/lang/StringBuilder;

    .line 170
    .line 171
    const-string v3, "Running periodic scan job: instance is "

    .line 172
    .line 173
    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 174
    .line 175
    .line 176
    iget-object v3, p0, Lorg/altbeacon/beacon/service/ScanJob$1;->this$0:Lorg/altbeacon/beacon/service/ScanJob;

    .line 177
    .line 178
    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 179
    .line 180
    .line 181
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 182
    .line 183
    .line 184
    move-result-object v2

    .line 185
    new-array v3, v1, [Ljava/lang/Object;

    .line 186
    .line 187
    invoke-static {v0, v2, v3}, Lorg/altbeacon/beacon/logging/LogManager;->i(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 188
    .line 189
    .line 190
    :goto_1
    new-instance v0, Ljava/util/ArrayList;

    .line 191
    .line 192
    invoke-static {}, Lorg/altbeacon/beacon/service/ScanJobScheduler;->getInstance()Lorg/altbeacon/beacon/service/ScanJobScheduler;

    .line 193
    .line 194
    .line 195
    move-result-object v2

    .line 196
    invoke-virtual {v2}, Lorg/altbeacon/beacon/service/ScanJobScheduler;->dumpBackgroundScanResultQueue()Ljava/util/List;

    .line 197
    .line 198
    .line 199
    move-result-object v2

    .line 200
    invoke-direct {v0, v2}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    .line 201
    .line 202
    .line 203
    invoke-static {}, Lorg/altbeacon/beacon/service/ScanJob;->k()Ljava/lang/String;

    .line 204
    .line 205
    .line 206
    move-result-object v2

    .line 207
    const-string v3, "Processing %d queued scan results"

    .line 208
    .line 209
    invoke-virtual {v0}, Ljava/util/ArrayList;->size()I

    .line 210
    .line 211
    .line 212
    move-result v4

    .line 213
    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 214
    .line 215
    .line 216
    move-result-object v4

    .line 217
    filled-new-array {v4}, [Ljava/lang/Object;

    .line 218
    .line 219
    .line 220
    move-result-object v4

    .line 221
    invoke-static {v2, v3, v4}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 222
    .line 223
    .line 224
    invoke-virtual {v0}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 225
    .line 226
    .line 227
    move-result-object v0

    .line 228
    :cond_4
    :goto_2
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 229
    .line 230
    .line 231
    move-result v2

    .line 232
    if-eqz v2, :cond_5

    .line 233
    .line 234
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 235
    .line 236
    .line 237
    move-result-object v2

    .line 238
    check-cast v2, Landroid/bluetooth/le/ScanResult;

    .line 239
    .line 240
    invoke-virtual {v2}, Landroid/bluetooth/le/ScanResult;->getScanRecord()Landroid/bluetooth/le/ScanRecord;

    .line 241
    .line 242
    .line 243
    move-result-object v3

    .line 244
    if-eqz v3, :cond_4

    .line 245
    .line 246
    iget-object v4, p0, Lorg/altbeacon/beacon/service/ScanJob$1;->this$0:Lorg/altbeacon/beacon/service/ScanJob;

    .line 247
    .line 248
    invoke-static {v4}, Lorg/altbeacon/beacon/service/ScanJob;->b(Lorg/altbeacon/beacon/service/ScanJob;)Lorg/altbeacon/beacon/service/ScanHelper;

    .line 249
    .line 250
    .line 251
    move-result-object v4

    .line 252
    if-eqz v4, :cond_4

    .line 253
    .line 254
    iget-object v4, p0, Lorg/altbeacon/beacon/service/ScanJob$1;->this$0:Lorg/altbeacon/beacon/service/ScanJob;

    .line 255
    .line 256
    invoke-static {v4}, Lorg/altbeacon/beacon/service/ScanJob;->b(Lorg/altbeacon/beacon/service/ScanJob;)Lorg/altbeacon/beacon/service/ScanHelper;

    .line 257
    .line 258
    .line 259
    move-result-object v5

    .line 260
    invoke-virtual {v2}, Landroid/bluetooth/le/ScanResult;->getDevice()Landroid/bluetooth/BluetoothDevice;

    .line 261
    .line 262
    .line 263
    move-result-object v6

    .line 264
    invoke-virtual {v2}, Landroid/bluetooth/le/ScanResult;->getRssi()I

    .line 265
    .line 266
    .line 267
    move-result v7

    .line 268
    invoke-virtual {v3}, Landroid/bluetooth/le/ScanRecord;->getBytes()[B

    .line 269
    .line 270
    .line 271
    move-result-object v8

    .line 272
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    .line 273
    .line 274
    .line 275
    move-result-wide v3

    .line 276
    invoke-static {}, Landroid/os/SystemClock;->elapsedRealtime()J

    .line 277
    .line 278
    .line 279
    move-result-wide v9

    .line 280
    sub-long/2addr v3, v9

    .line 281
    invoke-virtual {v2}, Landroid/bluetooth/le/ScanResult;->getTimestampNanos()J

    .line 282
    .line 283
    .line 284
    move-result-wide v9

    .line 285
    const-wide/32 v11, 0xf4240

    .line 286
    .line 287
    .line 288
    div-long/2addr v9, v11

    .line 289
    add-long/2addr v9, v3

    .line 290
    invoke-virtual/range {v5 .. v10}, Lorg/altbeacon/beacon/service/ScanHelper;->processScanResult(Landroid/bluetooth/BluetoothDevice;I[BJ)V

    .line 291
    .line 292
    .line 293
    goto :goto_2

    .line 294
    :cond_5
    invoke-static {}, Lorg/altbeacon/beacon/service/ScanJob;->k()Ljava/lang/String;

    .line 295
    .line 296
    .line 297
    move-result-object v0

    .line 298
    const-string v2, "Done processing queued scan results"

    .line 299
    .line 300
    new-array v3, v1, [Ljava/lang/Object;

    .line 301
    .line 302
    invoke-static {v0, v2, v3}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 303
    .line 304
    .line 305
    iget-object v2, p0, Lorg/altbeacon/beacon/service/ScanJob$1;->this$0:Lorg/altbeacon/beacon/service/ScanJob;

    .line 306
    .line 307
    monitor-enter v2

    .line 308
    :try_start_1
    iget-object v0, p0, Lorg/altbeacon/beacon/service/ScanJob$1;->this$0:Lorg/altbeacon/beacon/service/ScanJob;

    .line 309
    .line 310
    invoke-static {v0}, Lorg/altbeacon/beacon/service/ScanJob;->d(Lorg/altbeacon/beacon/service/ScanJob;)Z

    .line 311
    .line 312
    .line 313
    move-result v0

    .line 314
    if-eqz v0, :cond_6

    .line 315
    .line 316
    invoke-static {}, Lorg/altbeacon/beacon/service/ScanJob;->k()Ljava/lang/String;

    .line 317
    .line 318
    .line 319
    move-result-object v0

    .line 320
    const-string v3, "Quitting scan job before we even start.  Somebody told us to stop."

    .line 321
    .line 322
    new-array v4, v1, [Ljava/lang/Object;

    .line 323
    .line 324
    invoke-static {v0, v3, v4}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 325
    .line 326
    .line 327
    iget-object v0, p0, Lorg/altbeacon/beacon/service/ScanJob$1;->this$0:Lorg/altbeacon/beacon/service/ScanJob;

    .line 328
    .line 329
    iget-object p0, p0, Lorg/altbeacon/beacon/service/ScanJob$1;->val$jobParameters:Landroid/app/job/JobParameters;

    .line 330
    .line 331
    invoke-virtual {v0, p0, v1}, Landroid/app/job/JobService;->jobFinished(Landroid/app/job/JobParameters;Z)V

    .line 332
    .line 333
    .line 334
    monitor-exit v2

    .line 335
    return-void

    .line 336
    :catchall_1
    move-exception v0

    .line 337
    move-object p0, v0

    .line 338
    goto/16 :goto_5

    .line 339
    .line 340
    :cond_6
    iget-object v0, p0, Lorg/altbeacon/beacon/service/ScanJob$1;->this$0:Lorg/altbeacon/beacon/service/ScanJob;

    .line 341
    .line 342
    invoke-static {v0}, Lorg/altbeacon/beacon/service/ScanJob;->a(Lorg/altbeacon/beacon/service/ScanJob;)Z

    .line 343
    .line 344
    .line 345
    move-result v0

    .line 346
    if-eqz v0, :cond_7

    .line 347
    .line 348
    invoke-static {}, Lorg/altbeacon/beacon/service/ScanJob;->k()Ljava/lang/String;

    .line 349
    .line 350
    .line 351
    move-result-object v0

    .line 352
    const-string v3, "Scanning already started.  Resetting for current parameters"

    .line 353
    .line 354
    new-array v4, v1, [Ljava/lang/Object;

    .line 355
    .line 356
    invoke-static {v0, v3, v4}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 357
    .line 358
    .line 359
    iget-object v0, p0, Lorg/altbeacon/beacon/service/ScanJob$1;->this$0:Lorg/altbeacon/beacon/service/ScanJob;

    .line 360
    .line 361
    invoke-static {v0}, Lorg/altbeacon/beacon/service/ScanJob;->g(Lorg/altbeacon/beacon/service/ScanJob;)Z

    .line 362
    .line 363
    .line 364
    move-result v0

    .line 365
    goto :goto_3

    .line 366
    :cond_7
    iget-object v0, p0, Lorg/altbeacon/beacon/service/ScanJob$1;->this$0:Lorg/altbeacon/beacon/service/ScanJob;

    .line 367
    .line 368
    invoke-static {v0}, Lorg/altbeacon/beacon/service/ScanJob;->i(Lorg/altbeacon/beacon/service/ScanJob;)Z

    .line 369
    .line 370
    .line 371
    move-result v0

    .line 372
    :goto_3
    iget-object v3, p0, Lorg/altbeacon/beacon/service/ScanJob$1;->this$0:Lorg/altbeacon/beacon/service/ScanJob;

    .line 373
    .line 374
    invoke-static {v3}, Lorg/altbeacon/beacon/service/ScanJob;->e(Lorg/altbeacon/beacon/service/ScanJob;)Landroid/os/Handler;

    .line 375
    .line 376
    .line 377
    move-result-object v3

    .line 378
    const/4 v4, 0x0

    .line 379
    invoke-virtual {v3, v4}, Landroid/os/Handler;->removeCallbacksAndMessages(Ljava/lang/Object;)V

    .line 380
    .line 381
    .line 382
    if-eqz v0, :cond_8

    .line 383
    .line 384
    iget-object v0, p0, Lorg/altbeacon/beacon/service/ScanJob$1;->this$0:Lorg/altbeacon/beacon/service/ScanJob;

    .line 385
    .line 386
    invoke-static {v0}, Lorg/altbeacon/beacon/service/ScanJob;->c(Lorg/altbeacon/beacon/service/ScanJob;)Lorg/altbeacon/beacon/service/ScanState;

    .line 387
    .line 388
    .line 389
    move-result-object v0

    .line 390
    if-eqz v0, :cond_9

    .line 391
    .line 392
    invoke-static {}, Lorg/altbeacon/beacon/service/ScanJob;->k()Ljava/lang/String;

    .line 393
    .line 394
    .line 395
    move-result-object v0

    .line 396
    new-instance v3, Ljava/lang/StringBuilder;

    .line 397
    .line 398
    invoke-direct {v3}, Ljava/lang/StringBuilder;-><init>()V

    .line 399
    .line 400
    .line 401
    const-string v4, "Scan job running for "

    .line 402
    .line 403
    invoke-virtual {v3, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 404
    .line 405
    .line 406
    iget-object v4, p0, Lorg/altbeacon/beacon/service/ScanJob$1;->this$0:Lorg/altbeacon/beacon/service/ScanJob;

    .line 407
    .line 408
    invoke-static {v4}, Lorg/altbeacon/beacon/service/ScanJob;->c(Lorg/altbeacon/beacon/service/ScanJob;)Lorg/altbeacon/beacon/service/ScanState;

    .line 409
    .line 410
    .line 411
    move-result-object v4

    .line 412
    invoke-virtual {v4}, Lorg/altbeacon/beacon/service/ScanState;->getScanJobRuntimeMillis()I

    .line 413
    .line 414
    .line 415
    move-result v4

    .line 416
    invoke-virtual {v3, v4}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 417
    .line 418
    .line 419
    const-string v4, " millis"

    .line 420
    .line 421
    invoke-virtual {v3, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 422
    .line 423
    .line 424
    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 425
    .line 426
    .line 427
    move-result-object v3

    .line 428
    new-array v1, v1, [Ljava/lang/Object;

    .line 429
    .line 430
    invoke-static {v0, v3, v1}, Lorg/altbeacon/beacon/logging/LogManager;->i(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 431
    .line 432
    .line 433
    iget-object v0, p0, Lorg/altbeacon/beacon/service/ScanJob$1;->this$0:Lorg/altbeacon/beacon/service/ScanJob;

    .line 434
    .line 435
    invoke-static {v0}, Lorg/altbeacon/beacon/service/ScanJob;->e(Lorg/altbeacon/beacon/service/ScanJob;)Landroid/os/Handler;

    .line 436
    .line 437
    .line 438
    move-result-object v0

    .line 439
    new-instance v1, Lorg/altbeacon/beacon/service/ScanJob$1$1;

    .line 440
    .line 441
    invoke-direct {v1, p0}, Lorg/altbeacon/beacon/service/ScanJob$1$1;-><init>(Lorg/altbeacon/beacon/service/ScanJob$1;)V

    .line 442
    .line 443
    .line 444
    iget-object p0, p0, Lorg/altbeacon/beacon/service/ScanJob$1;->this$0:Lorg/altbeacon/beacon/service/ScanJob;

    .line 445
    .line 446
    invoke-static {p0}, Lorg/altbeacon/beacon/service/ScanJob;->c(Lorg/altbeacon/beacon/service/ScanJob;)Lorg/altbeacon/beacon/service/ScanState;

    .line 447
    .line 448
    .line 449
    move-result-object p0

    .line 450
    invoke-virtual {p0}, Lorg/altbeacon/beacon/service/ScanState;->getScanJobRuntimeMillis()I

    .line 451
    .line 452
    .line 453
    move-result p0

    .line 454
    int-to-long v3, p0

    .line 455
    invoke-virtual {v0, v1, v3, v4}, Landroid/os/Handler;->postDelayed(Ljava/lang/Runnable;J)Z

    .line 456
    .line 457
    .line 458
    goto :goto_4

    .line 459
    :cond_8
    invoke-static {}, Lorg/altbeacon/beacon/service/ScanJob;->k()Ljava/lang/String;

    .line 460
    .line 461
    .line 462
    move-result-object v0

    .line 463
    const-string v3, "Scanning not started so Scan job is complete."

    .line 464
    .line 465
    new-array v4, v1, [Ljava/lang/Object;

    .line 466
    .line 467
    invoke-static {v0, v3, v4}, Lorg/altbeacon/beacon/logging/LogManager;->i(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 468
    .line 469
    .line 470
    iget-object v0, p0, Lorg/altbeacon/beacon/service/ScanJob$1;->this$0:Lorg/altbeacon/beacon/service/ScanJob;

    .line 471
    .line 472
    invoke-static {v0}, Lorg/altbeacon/beacon/service/ScanJob;->j(Lorg/altbeacon/beacon/service/ScanJob;)V

    .line 473
    .line 474
    .line 475
    iget-object v0, p0, Lorg/altbeacon/beacon/service/ScanJob$1;->this$0:Lorg/altbeacon/beacon/service/ScanJob;

    .line 476
    .line 477
    invoke-static {v0}, Lorg/altbeacon/beacon/service/ScanJob;->c(Lorg/altbeacon/beacon/service/ScanJob;)Lorg/altbeacon/beacon/service/ScanState;

    .line 478
    .line 479
    .line 480
    move-result-object v0

    .line 481
    invoke-virtual {v0}, Lorg/altbeacon/beacon/service/ScanState;->save()V

    .line 482
    .line 483
    .line 484
    invoke-static {}, Lorg/altbeacon/beacon/service/ScanJob;->k()Ljava/lang/String;

    .line 485
    .line 486
    .line 487
    move-result-object v0

    .line 488
    new-instance v3, Ljava/lang/StringBuilder;

    .line 489
    .line 490
    invoke-direct {v3}, Ljava/lang/StringBuilder;-><init>()V

    .line 491
    .line 492
    .line 493
    const-string v4, "ScanJob Lifecycle STOP (start fail): "

    .line 494
    .line 495
    invoke-virtual {v3, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 496
    .line 497
    .line 498
    iget-object v4, p0, Lorg/altbeacon/beacon/service/ScanJob$1;->this$0:Lorg/altbeacon/beacon/service/ScanJob;

    .line 499
    .line 500
    invoke-virtual {v3, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 501
    .line 502
    .line 503
    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 504
    .line 505
    .line 506
    move-result-object v3

    .line 507
    new-array v4, v1, [Ljava/lang/Object;

    .line 508
    .line 509
    invoke-static {v0, v3, v4}, Lorg/altbeacon/beacon/logging/LogManager;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 510
    .line 511
    .line 512
    iget-object v0, p0, Lorg/altbeacon/beacon/service/ScanJob$1;->this$0:Lorg/altbeacon/beacon/service/ScanJob;

    .line 513
    .line 514
    iget-object p0, p0, Lorg/altbeacon/beacon/service/ScanJob$1;->val$jobParameters:Landroid/app/job/JobParameters;

    .line 515
    .line 516
    invoke-virtual {v0, p0, v1}, Landroid/app/job/JobService;->jobFinished(Landroid/app/job/JobParameters;Z)V

    .line 517
    .line 518
    .line 519
    :cond_9
    :goto_4
    monitor-exit v2

    .line 520
    return-void

    .line 521
    :goto_5
    monitor-exit v2
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 522
    throw p0
.end method
