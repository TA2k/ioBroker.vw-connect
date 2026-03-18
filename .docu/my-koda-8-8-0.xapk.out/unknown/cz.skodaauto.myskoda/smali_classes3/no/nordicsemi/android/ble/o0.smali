.class public final synthetic Lno/nordicsemi/android/ble/o0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/lang/Runnable;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/lang/Object;

.field public final synthetic f:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(ILjava/lang/Object;Ljava/lang/Object;)V
    .locals 0

    .line 1
    iput p1, p0, Lno/nordicsemi/android/ble/o0;->d:I

    .line 2
    .line 3
    iput-object p2, p0, Lno/nordicsemi/android/ble/o0;->e:Ljava/lang/Object;

    .line 4
    .line 5
    iput-object p3, p0, Lno/nordicsemi/android/ble/o0;->f:Ljava/lang/Object;

    .line 6
    .line 7
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 8
    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final run()V
    .locals 13

    .line 1
    iget v0, p0, Lno/nordicsemi/android/ble/o0;->d:I

    .line 2
    .line 3
    const/4 v1, 0x3

    .line 4
    const/4 v2, 0x5

    .line 5
    const/4 v3, 0x6

    .line 6
    const/4 v4, 0x2

    .line 7
    const/4 v5, 0x0

    .line 8
    const/4 v6, 0x0

    .line 9
    const/4 v7, 0x1

    .line 10
    packed-switch v0, :pswitch_data_0

    .line 11
    .line 12
    .line 13
    iget-object v0, p0, Lno/nordicsemi/android/ble/o0;->e:Ljava/lang/Object;

    .line 14
    .line 15
    check-cast v0, Landroidx/media3/ui/PlayerView;

    .line 16
    .line 17
    iget-object p0, p0, Lno/nordicsemi/android/ble/o0;->f:Ljava/lang/Object;

    .line 18
    .line 19
    check-cast p0, Landroid/graphics/Bitmap;

    .line 20
    .line 21
    invoke-static {v0, p0}, Landroidx/media3/ui/PlayerView;->a(Landroidx/media3/ui/PlayerView;Landroid/graphics/Bitmap;)V

    .line 22
    .line 23
    .line 24
    return-void

    .line 25
    :pswitch_0
    iget-object v0, p0, Lno/nordicsemi/android/ble/o0;->e:Ljava/lang/Object;

    .line 26
    .line 27
    check-cast v0, Lcom/google/android/datatransport/runtime/scheduling/jobscheduling/JobInfoSchedulerService;

    .line 28
    .line 29
    iget-object p0, p0, Lno/nordicsemi/android/ble/o0;->f:Ljava/lang/Object;

    .line 30
    .line 31
    check-cast p0, Landroid/app/job/JobParameters;

    .line 32
    .line 33
    sget v1, Lcom/google/android/datatransport/runtime/scheduling/jobscheduling/JobInfoSchedulerService;->d:I

    .line 34
    .line 35
    invoke-virtual {v0, p0, v6}, Landroid/app/job/JobService;->jobFinished(Landroid/app/job/JobParameters;Z)V

    .line 36
    .line 37
    .line 38
    return-void

    .line 39
    :pswitch_1
    iget-object v0, p0, Lno/nordicsemi/android/ble/o0;->e:Ljava/lang/Object;

    .line 40
    .line 41
    check-cast v0, Lvy0/l;

    .line 42
    .line 43
    iget-object p0, p0, Lno/nordicsemi/android/ble/o0;->f:Ljava/lang/Object;

    .line 44
    .line 45
    check-cast p0, Lwy0/c;

    .line 46
    .line 47
    sget-object v1, Llx0/b0;->a:Llx0/b0;

    .line 48
    .line 49
    invoke-virtual {v0, p0, v1}, Lvy0/l;->D(Lvy0/x;Ljava/lang/Object;)V

    .line 50
    .line 51
    .line 52
    return-void

    .line 53
    :pswitch_2
    iget-object v0, p0, Lno/nordicsemi/android/ble/o0;->e:Ljava/lang/Object;

    .line 54
    .line 55
    check-cast v0, Lc8/e;

    .line 56
    .line 57
    iget-object p0, p0, Lno/nordicsemi/android/ble/o0;->f:Ljava/lang/Object;

    .line 58
    .line 59
    check-cast p0, Landroid/content/Context;

    .line 60
    .line 61
    iget-object v0, v0, Lc8/e;->b:Ljava/lang/Object;

    .line 62
    .line 63
    check-cast v0, Lw7/o;

    .line 64
    .line 65
    const-string v5, "connectivity"

    .line 66
    .line 67
    invoke-virtual {p0, v5}, Landroid/content/Context;->getSystemService(Ljava/lang/String;)Ljava/lang/Object;

    .line 68
    .line 69
    .line 70
    move-result-object v5

    .line 71
    check-cast v5, Landroid/net/ConnectivityManager;

    .line 72
    .line 73
    if-nez v5, :cond_0

    .line 74
    .line 75
    :catch_0
    move v1, v6

    .line 76
    goto :goto_1

    .line 77
    :cond_0
    :try_start_0
    invoke-virtual {v5}, Landroid/net/ConnectivityManager;->getActiveNetworkInfo()Landroid/net/NetworkInfo;

    .line 78
    .line 79
    .line 80
    move-result-object v5
    :try_end_0
    .catch Ljava/lang/SecurityException; {:try_start_0 .. :try_end_0} :catch_0

    .line 81
    if-eqz v5, :cond_6

    .line 82
    .line 83
    invoke-virtual {v5}, Landroid/net/NetworkInfo;->isConnected()Z

    .line 84
    .line 85
    .line 86
    move-result v6

    .line 87
    if-nez v6, :cond_1

    .line 88
    .line 89
    goto :goto_0

    .line 90
    :cond_1
    invoke-virtual {v5}, Landroid/net/NetworkInfo;->getType()I

    .line 91
    .line 92
    .line 93
    move-result v6

    .line 94
    const/16 v8, 0x9

    .line 95
    .line 96
    const/4 v9, 0x4

    .line 97
    if-eqz v6, :cond_5

    .line 98
    .line 99
    if-eq v6, v7, :cond_4

    .line 100
    .line 101
    if-eq v6, v9, :cond_5

    .line 102
    .line 103
    if-eq v6, v2, :cond_5

    .line 104
    .line 105
    if-eq v6, v3, :cond_3

    .line 106
    .line 107
    if-eq v6, v8, :cond_2

    .line 108
    .line 109
    const/16 v1, 0x8

    .line 110
    .line 111
    goto :goto_1

    .line 112
    :cond_2
    const/4 v1, 0x7

    .line 113
    goto :goto_1

    .line 114
    :cond_3
    :pswitch_3
    move v1, v2

    .line 115
    goto :goto_1

    .line 116
    :cond_4
    :pswitch_4
    move v1, v4

    .line 117
    goto :goto_1

    .line 118
    :cond_5
    invoke-virtual {v5}, Landroid/net/NetworkInfo;->getSubtype()I

    .line 119
    .line 120
    .line 121
    move-result v5

    .line 122
    packed-switch v5, :pswitch_data_1

    .line 123
    .line 124
    .line 125
    :pswitch_5
    move v1, v3

    .line 126
    goto :goto_1

    .line 127
    :pswitch_6
    move v1, v8

    .line 128
    goto :goto_1

    .line 129
    :pswitch_7
    move v1, v9

    .line 130
    goto :goto_1

    .line 131
    :cond_6
    :goto_0
    move v1, v7

    .line 132
    :goto_1
    :pswitch_8
    sget v3, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 133
    .line 134
    const/16 v4, 0x1f

    .line 135
    .line 136
    if-lt v3, v4, :cond_7

    .line 137
    .line 138
    if-ne v1, v2, :cond_7

    .line 139
    .line 140
    :try_start_1
    const-string v1, "phone"

    .line 141
    .line 142
    invoke-virtual {p0, v1}, Landroid/content/Context;->getSystemService(Ljava/lang/String;)Ljava/lang/Object;

    .line 143
    .line 144
    .line 145
    move-result-object p0

    .line 146
    check-cast p0, Landroid/telephony/TelephonyManager;

    .line 147
    .line 148
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 149
    .line 150
    .line 151
    new-instance v1, Lw7/m;

    .line 152
    .line 153
    invoke-direct {v1, v0}, Lw7/m;-><init>(Lw7/o;)V

    .line 154
    .line 155
    .line 156
    iget-object v3, v0, Lw7/o;->c:Ljava/lang/Object;

    .line 157
    .line 158
    check-cast v3, Ljava/util/concurrent/Executor;

    .line 159
    .line 160
    invoke-static {p0, v3, v1}, Lh4/b;->s(Landroid/telephony/TelephonyManager;Ljava/util/concurrent/Executor;Lw7/m;)V

    .line 161
    .line 162
    .line 163
    invoke-static {p0, v1}, Lh4/b;->t(Landroid/telephony/TelephonyManager;Lw7/m;)V
    :try_end_1
    .catch Ljava/lang/RuntimeException; {:try_start_1 .. :try_end_1} :catch_1

    .line 164
    .line 165
    .line 166
    goto :goto_2

    .line 167
    :catch_1
    invoke-virtual {v0, v2}, Lw7/o;->c(I)V

    .line 168
    .line 169
    .line 170
    goto :goto_2

    .line 171
    :cond_7
    invoke-virtual {v0, v1}, Lw7/o;->c(I)V

    .line 172
    .line 173
    .line 174
    :goto_2
    return-void

    .line 175
    :pswitch_9
    iget-object v0, p0, Lno/nordicsemi/android/ble/o0;->e:Ljava/lang/Object;

    .line 176
    .line 177
    check-cast v0, Lw7/o;

    .line 178
    .line 179
    iget-object p0, p0, Lno/nordicsemi/android/ble/o0;->f:Ljava/lang/Object;

    .line 180
    .line 181
    check-cast p0, Landroid/content/Context;

    .line 182
    .line 183
    new-instance v1, Landroid/content/IntentFilter;

    .line 184
    .line 185
    invoke-direct {v1}, Landroid/content/IntentFilter;-><init>()V

    .line 186
    .line 187
    .line 188
    const-string v2, "android.net.conn.CONNECTIVITY_CHANGE"

    .line 189
    .line 190
    invoke-virtual {v1, v2}, Landroid/content/IntentFilter;->addAction(Ljava/lang/String;)V

    .line 191
    .line 192
    .line 193
    new-instance v2, Lc8/e;

    .line 194
    .line 195
    invoke-direct {v2, v0, v3}, Lc8/e;-><init>(Ljava/lang/Object;I)V

    .line 196
    .line 197
    .line 198
    invoke-virtual {p0, v2, v1}, Landroid/content/Context;->registerReceiver(Landroid/content/BroadcastReceiver;Landroid/content/IntentFilter;)Landroid/content/Intent;

    .line 199
    .line 200
    .line 201
    return-void

    .line 202
    :pswitch_a
    iget-object v0, p0, Lno/nordicsemi/android/ble/o0;->e:Ljava/lang/Object;

    .line 203
    .line 204
    check-cast v0, Lca/j;

    .line 205
    .line 206
    iget-object p0, p0, Lno/nordicsemi/android/ble/o0;->f:Ljava/lang/Object;

    .line 207
    .line 208
    check-cast p0, La8/w;

    .line 209
    .line 210
    iget-object v1, v0, Lca/j;->f:Ljava/lang/Object;

    .line 211
    .line 212
    invoke-virtual {p0, v1}, La8/w;->apply(Ljava/lang/Object;)Ljava/lang/Object;

    .line 213
    .line 214
    .line 215
    move-result-object p0

    .line 216
    iput-object p0, v0, Lca/j;->f:Ljava/lang/Object;

    .line 217
    .line 218
    new-instance v1, Lw7/b;

    .line 219
    .line 220
    invoke-direct {v1, v0, p0, v7}, Lw7/b;-><init>(Lca/j;Ljava/lang/Object;I)V

    .line 221
    .line 222
    .line 223
    iget-object p0, v0, Lca/j;->c:Ljava/lang/Object;

    .line 224
    .line 225
    check-cast p0, Lw7/t;

    .line 226
    .line 227
    iget-object v0, p0, Lw7/t;->a:Landroid/os/Handler;

    .line 228
    .line 229
    invoke-virtual {v0}, Landroid/os/Handler;->getLooper()Landroid/os/Looper;

    .line 230
    .line 231
    .line 232
    move-result-object v0

    .line 233
    invoke-virtual {v0}, Landroid/os/Looper;->getThread()Ljava/lang/Thread;

    .line 234
    .line 235
    .line 236
    move-result-object v0

    .line 237
    invoke-virtual {v0}, Ljava/lang/Thread;->isAlive()Z

    .line 238
    .line 239
    .line 240
    move-result v0

    .line 241
    if-nez v0, :cond_8

    .line 242
    .line 243
    goto :goto_3

    .line 244
    :cond_8
    invoke-virtual {p0, v1}, Lw7/t;->c(Ljava/lang/Runnable;)Z

    .line 245
    .line 246
    .line 247
    :goto_3
    return-void

    .line 248
    :pswitch_b
    iget-object v0, p0, Lno/nordicsemi/android/ble/o0;->e:Ljava/lang/Object;

    .line 249
    .line 250
    check-cast v0, Lw0/r;

    .line 251
    .line 252
    iget-object p0, p0, Lno/nordicsemi/android/ble/o0;->f:Ljava/lang/Object;

    .line 253
    .line 254
    check-cast p0, Lb0/x1;

    .line 255
    .line 256
    iget-object v1, v0, Lw0/r;->h:Lb0/x1;

    .line 257
    .line 258
    if-eqz v1, :cond_9

    .line 259
    .line 260
    if-ne v1, p0, :cond_9

    .line 261
    .line 262
    iput-object v5, v0, Lw0/r;->h:Lb0/x1;

    .line 263
    .line 264
    iput-object v5, v0, Lw0/r;->g:Ly4/k;

    .line 265
    .line 266
    :cond_9
    iget-object p0, v0, Lw0/r;->l:Lbb/i;

    .line 267
    .line 268
    if-eqz p0, :cond_a

    .line 269
    .line 270
    invoke-virtual {p0}, Lbb/i;->a()V

    .line 271
    .line 272
    .line 273
    iput-object v5, v0, Lw0/r;->l:Lbb/i;

    .line 274
    .line 275
    :cond_a
    return-void

    .line 276
    :pswitch_c
    iget-object v0, p0, Lno/nordicsemi/android/ble/o0;->e:Ljava/lang/Object;

    .line 277
    .line 278
    check-cast v0, Lt1/j0;

    .line 279
    .line 280
    iget-object p0, p0, Lno/nordicsemi/android/ble/o0;->f:Ljava/lang/Object;

    .line 281
    .line 282
    check-cast p0, Lb0/x1;

    .line 283
    .line 284
    iget-object v0, v0, Lt1/j0;->e:Ljava/lang/Object;

    .line 285
    .line 286
    check-cast v0, Lw0/i;

    .line 287
    .line 288
    iget-object v0, v0, Lw0/i;->o:Lt1/j0;

    .line 289
    .line 290
    invoke-virtual {v0, p0}, Lt1/j0;->h(Lb0/x1;)V

    .line 291
    .line 292
    .line 293
    return-void

    .line 294
    :pswitch_d
    iget-object v0, p0, Lno/nordicsemi/android/ble/o0;->e:Ljava/lang/Object;

    .line 295
    .line 296
    check-cast v0, Ld0/c;

    .line 297
    .line 298
    iget-object p0, p0, Lno/nordicsemi/android/ble/o0;->f:Ljava/lang/Object;

    .line 299
    .line 300
    check-cast p0, Lb0/d1;

    .line 301
    .line 302
    new-instance v1, Ljava/util/HashSet;

    .line 303
    .line 304
    invoke-direct {v1}, Ljava/util/HashSet;-><init>()V

    .line 305
    .line 306
    .line 307
    if-eqz v0, :cond_b

    .line 308
    .line 309
    iget-object v0, v0, Ld0/c;->a:Ljava/util/LinkedHashSet;

    .line 310
    .line 311
    invoke-interface {v1, v0}, Ljava/util/Set;->addAll(Ljava/util/Collection;)Z

    .line 312
    .line 313
    .line 314
    :cond_b
    iget-object p0, p0, Lb0/d1;->j:Ljava/lang/Object;

    .line 315
    .line 316
    check-cast p0, Lb0/o1;

    .line 317
    .line 318
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 319
    .line 320
    .line 321
    return-void

    .line 322
    :pswitch_e
    iget-object v0, p0, Lno/nordicsemi/android/ble/o0;->e:Ljava/lang/Object;

    .line 323
    .line 324
    check-cast v0, Landroid/content/Context;

    .line 325
    .line 326
    iget-object p0, p0, Lno/nordicsemi/android/ble/o0;->f:Ljava/lang/Object;

    .line 327
    .line 328
    check-cast p0, Lw7/e;

    .line 329
    .line 330
    const-string v1, "audio"

    .line 331
    .line 332
    invoke-virtual {v0, v1}, Landroid/content/Context;->getSystemService(Ljava/lang/String;)Ljava/lang/Object;

    .line 333
    .line 334
    .line 335
    move-result-object v0

    .line 336
    check-cast v0, Landroid/media/AudioManager;

    .line 337
    .line 338
    sput-object v0, Lu7/b;->a:Landroid/media/AudioManager;

    .line 339
    .line 340
    invoke-virtual {p0}, Lw7/e;->c()Z

    .line 341
    .line 342
    .line 343
    return-void

    .line 344
    :pswitch_f
    iget-object v0, p0, Lno/nordicsemi/android/ble/o0;->e:Ljava/lang/Object;

    .line 345
    .line 346
    check-cast v0, Lb0/n1;

    .line 347
    .line 348
    iget-object p0, p0, Lno/nordicsemi/android/ble/o0;->f:Ljava/lang/Object;

    .line 349
    .line 350
    check-cast p0, Lc2/k;

    .line 351
    .line 352
    invoke-virtual {v0}, Lb0/n1;->r()V

    .line 353
    .line 354
    .line 355
    iget-object v0, p0, Lc2/k;->f:Ljava/lang/Object;

    .line 356
    .line 357
    check-cast v0, Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 358
    .line 359
    invoke-virtual {v0, v6}, Ljava/util/concurrent/atomic/AtomicBoolean;->set(Z)V

    .line 360
    .line 361
    .line 362
    iget-object p0, p0, Lc2/k;->e:Ljava/lang/Object;

    .line 363
    .line 364
    check-cast p0, Landroid/media/ImageWriter;

    .line 365
    .line 366
    if-eqz p0, :cond_c

    .line 367
    .line 368
    invoke-virtual {p0}, Landroid/media/ImageWriter;->close()V

    .line 369
    .line 370
    .line 371
    :cond_c
    return-void

    .line 372
    :pswitch_10
    iget-object v0, p0, Lno/nordicsemi/android/ble/o0;->e:Ljava/lang/Object;

    .line 373
    .line 374
    move-object v1, v0

    .line 375
    check-cast v1, Lb0/d1;

    .line 376
    .line 377
    iget-object p0, p0, Lno/nordicsemi/android/ble/o0;->f:Ljava/lang/Object;

    .line 378
    .line 379
    check-cast p0, Ly4/h;

    .line 380
    .line 381
    const-string v2, "Camera2PresenceSrc"

    .line 382
    .line 383
    :try_start_2
    iget-object v0, v1, Lb0/d1;->i:Ljava/lang/Object;

    .line 384
    .line 385
    check-cast v0, Lv/d;

    .line 386
    .line 387
    invoke-virtual {v0}, Lv/d;->b()[Ljava/lang/String;

    .line 388
    .line 389
    .line 390
    move-result-object v0

    .line 391
    const-string v3, "getCameraIdList(...)"

    .line 392
    .line 393
    invoke-static {v0, v3}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 394
    .line 395
    .line 396
    new-instance v7, Ljava/util/ArrayList;

    .line 397
    .line 398
    array-length v3, v0

    .line 399
    invoke-direct {v7, v3}, Ljava/util/ArrayList;-><init>(I)V

    .line 400
    .line 401
    .line 402
    array-length v3, v0

    .line 403
    :goto_4
    if-ge v6, v3, :cond_d

    .line 404
    .line 405
    aget-object v4, v0, v6

    .line 406
    .line 407
    invoke-static {v4}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 408
    .line 409
    .line 410
    filled-new-array {v4}, [Ljava/lang/String;

    .line 411
    .line 412
    .line 413
    move-result-object v4

    .line 414
    invoke-static {v4}, Ljp/k1;->l([Ljava/lang/Object;)Ljava/util/ArrayList;

    .line 415
    .line 416
    .line 417
    move-result-object v4

    .line 418
    new-instance v8, Lb0/q;

    .line 419
    .line 420
    invoke-direct {v8, v4, v5}, Lb0/q;-><init>(Ljava/util/ArrayList;Lh0/h;)V

    .line 421
    .line 422
    .line 423
    invoke-virtual {v7, v8}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 424
    .line 425
    .line 426
    add-int/lit8 v6, v6, 0x1

    .line 427
    .line 428
    goto :goto_4

    .line 429
    :catch_2
    move-exception v0

    .line 430
    goto :goto_5

    .line 431
    :cond_d
    new-instance v0, Ljava/lang/StringBuilder;

    .line 432
    .line 433
    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    .line 434
    .line 435
    .line 436
    const-string v3, "[FetchData] Refreshed camera list: "

    .line 437
    .line 438
    invoke-virtual {v0, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 439
    .line 440
    .line 441
    const/4 v11, 0x0

    .line 442
    const/16 v12, 0x3f

    .line 443
    .line 444
    const/4 v8, 0x0

    .line 445
    const/4 v9, 0x0

    .line 446
    const/4 v10, 0x0

    .line 447
    invoke-static/range {v7 .. v12}, Lmx0/q;->R(Ljava/lang/Iterable;Ljava/lang/CharSequence;Ljava/lang/String;Ljava/lang/String;Lay0/k;I)Ljava/lang/String;

    .line 448
    .line 449
    .line 450
    move-result-object v3

    .line 451
    invoke-virtual {v0, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 452
    .line 453
    .line 454
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 455
    .line 456
    .line 457
    move-result-object v0

    .line 458
    invoke-static {v2, v0}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    .line 459
    .line 460
    .line 461
    invoke-virtual {v1, v7, v5}, Lb0/d1;->l(Ljava/util/ArrayList;Lb0/s;)V

    .line 462
    .line 463
    .line 464
    invoke-virtual {p0, v7}, Ly4/h;->b(Ljava/lang/Object;)Z
    :try_end_2
    .catch Lv/a; {:try_start_2 .. :try_end_2} :catch_2

    .line 465
    .line 466
    .line 467
    goto :goto_6

    .line 468
    :goto_5
    const-string v3, "[FetchData] Failed to get camera list for refresh."

    .line 469
    .line 470
    invoke-static {v2, v3, v0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 471
    .line 472
    .line 473
    new-instance v2, Lb0/s;

    .line 474
    .line 475
    invoke-direct {v2, v0}, Ljava/lang/Exception;-><init>(Ljava/lang/Throwable;)V

    .line 476
    .line 477
    .line 478
    invoke-virtual {v1, v5, v2}, Lb0/d1;->l(Ljava/util/ArrayList;Lb0/s;)V

    .line 479
    .line 480
    .line 481
    invoke-virtual {p0, v2}, Ly4/h;->d(Ljava/lang/Throwable;)Z

    .line 482
    .line 483
    .line 484
    :goto_6
    return-void

    .line 485
    :pswitch_11
    iget-object v0, p0, Lno/nordicsemi/android/ble/o0;->e:Ljava/lang/Object;

    .line 486
    .line 487
    check-cast v0, Lh0/x1;

    .line 488
    .line 489
    iget-object p0, p0, Lno/nordicsemi/android/ble/o0;->f:Ljava/lang/Object;

    .line 490
    .line 491
    check-cast p0, Lh0/z1;

    .line 492
    .line 493
    invoke-interface {v0, p0}, Lh0/x1;->a(Lh0/z1;)V

    .line 494
    .line 495
    .line 496
    return-void

    .line 497
    :pswitch_12
    iget-object v0, p0, Lno/nordicsemi/android/ble/o0;->e:Ljava/lang/Object;

    .line 498
    .line 499
    check-cast v0, Lu/y;

    .line 500
    .line 501
    iget-object p0, p0, Lno/nordicsemi/android/ble/o0;->f:Ljava/lang/Object;

    .line 502
    .line 503
    check-cast p0, Ljava/lang/String;

    .line 504
    .line 505
    new-instance v1, Ljava/lang/StringBuilder;

    .line 506
    .line 507
    const-string v2, "Use case "

    .line 508
    .line 509
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 510
    .line 511
    .line 512
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 513
    .line 514
    .line 515
    const-string v2, " INACTIVE"

    .line 516
    .line 517
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 518
    .line 519
    .line 520
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 521
    .line 522
    .line 523
    move-result-object v1

    .line 524
    invoke-virtual {v0, v1, v5}, Lu/y;->w(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 525
    .line 526
    .line 527
    iget-object v1, v0, Lu/y;->d:Lb81/c;

    .line 528
    .line 529
    iget-object v1, v1, Lb81/c;->f:Ljava/lang/Object;

    .line 530
    .line 531
    check-cast v1, Ljava/util/LinkedHashMap;

    .line 532
    .line 533
    invoke-interface {v1, p0}, Ljava/util/Map;->containsKey(Ljava/lang/Object;)Z

    .line 534
    .line 535
    .line 536
    move-result v2

    .line 537
    if-nez v2, :cond_e

    .line 538
    .line 539
    goto :goto_7

    .line 540
    :cond_e
    invoke-virtual {v1, p0}, Ljava/util/LinkedHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 541
    .line 542
    .line 543
    move-result-object v2

    .line 544
    check-cast v2, Lh0/l2;

    .line 545
    .line 546
    iput-boolean v6, v2, Lh0/l2;->f:Z

    .line 547
    .line 548
    iget-boolean v2, v2, Lh0/l2;->e:Z

    .line 549
    .line 550
    if-nez v2, :cond_f

    .line 551
    .line 552
    invoke-interface {v1, p0}, Ljava/util/Map;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    .line 553
    .line 554
    .line 555
    :cond_f
    :goto_7
    invoke-virtual {v0}, Lu/y;->M()V

    .line 556
    .line 557
    .line 558
    return-void

    .line 559
    :pswitch_13
    iget-object v0, p0, Lno/nordicsemi/android/ble/o0;->e:Ljava/lang/Object;

    .line 560
    .line 561
    check-cast v0, Landroid/view/Surface;

    .line 562
    .line 563
    iget-object p0, p0, Lno/nordicsemi/android/ble/o0;->f:Ljava/lang/Object;

    .line 564
    .line 565
    check-cast p0, Landroid/graphics/SurfaceTexture;

    .line 566
    .line 567
    invoke-virtual {v0}, Landroid/view/Surface;->release()V

    .line 568
    .line 569
    .line 570
    invoke-virtual {p0}, Landroid/graphics/SurfaceTexture;->release()V

    .line 571
    .line 572
    .line 573
    return-void

    .line 574
    :pswitch_14
    iget-object v0, p0, Lno/nordicsemi/android/ble/o0;->e:Ljava/lang/Object;

    .line 575
    .line 576
    check-cast v0, Lu/k;

    .line 577
    .line 578
    iget-object p0, p0, Lno/nordicsemi/android/ble/o0;->f:Ljava/lang/Object;

    .line 579
    .line 580
    check-cast p0, Landroid/hardware/camera2/TotalCaptureResult;

    .line 581
    .line 582
    new-instance v1, Ljava/util/HashSet;

    .line 583
    .line 584
    invoke-direct {v1}, Ljava/util/HashSet;-><init>()V

    .line 585
    .line 586
    .line 587
    iget-object v0, v0, Lu/k;->b:Ljava/lang/Object;

    .line 588
    .line 589
    check-cast v0, Ljava/util/HashSet;

    .line 590
    .line 591
    invoke-virtual {v0}, Ljava/util/HashSet;->iterator()Ljava/util/Iterator;

    .line 592
    .line 593
    .line 594
    move-result-object v2

    .line 595
    :cond_10
    :goto_8
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    .line 596
    .line 597
    .line 598
    move-result v3

    .line 599
    if-eqz v3, :cond_11

    .line 600
    .line 601
    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 602
    .line 603
    .line 604
    move-result-object v3

    .line 605
    check-cast v3, Lu/l;

    .line 606
    .line 607
    invoke-interface {v3, p0}, Lu/l;->a(Landroid/hardware/camera2/TotalCaptureResult;)Z

    .line 608
    .line 609
    .line 610
    move-result v4

    .line 611
    if-eqz v4, :cond_10

    .line 612
    .line 613
    invoke-virtual {v1, v3}, Ljava/util/HashSet;->add(Ljava/lang/Object;)Z

    .line 614
    .line 615
    .line 616
    goto :goto_8

    .line 617
    :cond_11
    invoke-virtual {v1}, Ljava/util/HashSet;->isEmpty()Z

    .line 618
    .line 619
    .line 620
    move-result p0

    .line 621
    if-nez p0, :cond_12

    .line 622
    .line 623
    invoke-interface {v0, v1}, Ljava/util/Set;->removeAll(Ljava/util/Collection;)Z

    .line 624
    .line 625
    .line 626
    :cond_12
    return-void

    .line 627
    :pswitch_15
    iget-object v0, p0, Lno/nordicsemi/android/ble/o0;->e:Ljava/lang/Object;

    .line 628
    .line 629
    check-cast v0, Lu/m;

    .line 630
    .line 631
    iget-object p0, p0, Lno/nordicsemi/android/ble/o0;->f:Ljava/lang/Object;

    .line 632
    .line 633
    check-cast p0, Ly4/h;

    .line 634
    .line 635
    invoke-virtual {v0}, Lu/m;->p()J

    .line 636
    .line 637
    .line 638
    move-result-wide v1

    .line 639
    new-instance v3, Lu/h;

    .line 640
    .line 641
    invoke-direct {v3, v0, v1, v2}, Lu/h;-><init>(Lu/m;J)V

    .line 642
    .line 643
    .line 644
    invoke-static {v3}, Llp/uf;->b(Ly4/i;)Ly4/k;

    .line 645
    .line 646
    .line 647
    move-result-object v0

    .line 648
    invoke-static {v0, p0}, Lk0/h;->e(Lcom/google/common/util/concurrent/ListenableFuture;Ly4/h;)V

    .line 649
    .line 650
    .line 651
    return-void

    .line 652
    :pswitch_16
    iget-object v0, p0, Lno/nordicsemi/android/ble/o0;->e:Ljava/lang/Object;

    .line 653
    .line 654
    check-cast v0, Lu/m;

    .line 655
    .line 656
    iget-object p0, p0, Lno/nordicsemi/android/ble/o0;->f:Ljava/lang/Object;

    .line 657
    .line 658
    check-cast p0, Lh0/m;

    .line 659
    .line 660
    iget-object v0, v0, Lu/m;->y:Lu/j;

    .line 661
    .line 662
    iget-object v1, v0, Lu/j;->b:Ljava/lang/Object;

    .line 663
    .line 664
    check-cast v1, Ljava/util/HashSet;

    .line 665
    .line 666
    invoke-virtual {v1, p0}, Ljava/util/HashSet;->remove(Ljava/lang/Object;)Z

    .line 667
    .line 668
    .line 669
    iget-object v0, v0, Lu/j;->c:Ljava/lang/Object;

    .line 670
    .line 671
    check-cast v0, Landroid/util/ArrayMap;

    .line 672
    .line 673
    invoke-virtual {v0, p0}, Landroid/util/ArrayMap;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    .line 674
    .line 675
    .line 676
    return-void

    .line 677
    :pswitch_17
    iget-object v0, p0, Lno/nordicsemi/android/ble/o0;->e:Ljava/lang/Object;

    .line 678
    .line 679
    check-cast v0, Lcom/google/firebase/perf/metrics/AppStartTrace;

    .line 680
    .line 681
    iget-object p0, p0, Lno/nordicsemi/android/ble/o0;->f:Ljava/lang/Object;

    .line 682
    .line 683
    check-cast p0, Lau/x;

    .line 684
    .line 685
    iget-object v0, v0, Lcom/google/firebase/perf/metrics/AppStartTrace;->e:Lyt/h;

    .line 686
    .line 687
    invoke-virtual {p0}, Lcom/google/protobuf/n;->h()Lcom/google/protobuf/p;

    .line 688
    .line 689
    .line 690
    move-result-object p0

    .line 691
    check-cast p0, Lau/a0;

    .line 692
    .line 693
    sget-object v1, Lau/i;->h:Lau/i;

    .line 694
    .line 695
    invoke-virtual {v0, p0, v1}, Lyt/h;->c(Lau/a0;Lau/i;)V

    .line 696
    .line 697
    .line 698
    return-void

    .line 699
    :pswitch_18
    iget-object v0, p0, Lno/nordicsemi/android/ble/o0;->e:Ljava/lang/Object;

    .line 700
    .line 701
    check-cast v0, Lts/b;

    .line 702
    .line 703
    iget-object p0, p0, Lno/nordicsemi/android/ble/o0;->f:Ljava/lang/Object;

    .line 704
    .line 705
    check-cast p0, Ljava/util/concurrent/CountDownLatch;

    .line 706
    .line 707
    :try_start_3
    iget-object v0, v0, Lts/b;->h:Lrn/q;

    .line 708
    .line 709
    sget-object v1, Lon/d;->f:Lon/d;

    .line 710
    .line 711
    iget-object v0, v0, Lrn/q;->a:Lrn/j;

    .line 712
    .line 713
    invoke-virtual {v0, v1}, Lrn/j;->b(Lon/d;)Lrn/j;

    .line 714
    .line 715
    .line 716
    move-result-object v0

    .line 717
    invoke-static {}, Lrn/r;->a()Lrn/r;

    .line 718
    .line 719
    .line 720
    move-result-object v1

    .line 721
    iget-object v1, v1, Lrn/r;->d:Lqn/s;

    .line 722
    .line 723
    invoke-virtual {v1, v0, v7}, Lqn/s;->c(Lrn/j;I)V
    :try_end_3
    .catch Ljava/lang/Exception; {:try_start_3 .. :try_end_3} :catch_3

    .line 724
    .line 725
    .line 726
    :catch_3
    invoke-virtual {p0}, Ljava/util/concurrent/CountDownLatch;->countDown()V

    .line 727
    .line 728
    .line 729
    return-void

    .line 730
    :pswitch_19
    iget-object v0, p0, Lno/nordicsemi/android/ble/o0;->e:Ljava/lang/Object;

    .line 731
    .line 732
    check-cast v0, Lqt/v;

    .line 733
    .line 734
    iget-object p0, p0, Lno/nordicsemi/android/ble/o0;->f:Ljava/lang/Object;

    .line 735
    .line 736
    check-cast p0, Landroid/content/Context;

    .line 737
    .line 738
    iget-object v1, v0, Lqt/v;->a:Landroid/content/SharedPreferences;

    .line 739
    .line 740
    if-nez v1, :cond_13

    .line 741
    .line 742
    if-eqz p0, :cond_13

    .line 743
    .line 744
    const-string v1, "FirebasePerfSharedPrefs"

    .line 745
    .line 746
    invoke-virtual {p0, v1, v6}, Landroid/content/Context;->getSharedPreferences(Ljava/lang/String;I)Landroid/content/SharedPreferences;

    .line 747
    .line 748
    .line 749
    move-result-object p0

    .line 750
    iput-object p0, v0, Lqt/v;->a:Landroid/content/SharedPreferences;

    .line 751
    .line 752
    :cond_13
    return-void

    .line 753
    :pswitch_1a
    iget-object v0, p0, Lno/nordicsemi/android/ble/o0;->e:Ljava/lang/Object;

    .line 754
    .line 755
    check-cast v0, Lq0/e;

    .line 756
    .line 757
    iget-object p0, p0, Lno/nordicsemi/android/ble/o0;->f:Ljava/lang/Object;

    .line 758
    .line 759
    check-cast p0, Lp0/l;

    .line 760
    .line 761
    iget-object v1, v0, Lq0/e;->f:Lj0/c;

    .line 762
    .line 763
    new-instance v2, Ll0/d;

    .line 764
    .line 765
    invoke-direct {v2, v4, v0, p0}, Ll0/d;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 766
    .line 767
    .line 768
    invoke-virtual {p0, v1, v2}, Lp0/l;->b(Lj0/c;Lc6/a;)Landroid/view/Surface;

    .line 769
    .line 770
    .line 771
    move-result-object v1

    .line 772
    iget-object v2, v0, Lq0/e;->d:Lq0/c;

    .line 773
    .line 774
    invoke-virtual {v2, v1}, Lc1/k2;->l(Landroid/view/Surface;)V

    .line 775
    .line 776
    .line 777
    iget-object v0, v0, Lq0/e;->k:Ljava/util/LinkedHashMap;

    .line 778
    .line 779
    invoke-interface {v0, p0, v1}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 780
    .line 781
    .line 782
    return-void

    .line 783
    :pswitch_1b
    iget-object v0, p0, Lno/nordicsemi/android/ble/o0;->e:Ljava/lang/Object;

    .line 784
    .line 785
    check-cast v0, Lq0/e;

    .line 786
    .line 787
    iget-object p0, p0, Lno/nordicsemi/android/ble/o0;->f:Ljava/lang/Object;

    .line 788
    .line 789
    check-cast p0, Lb0/x1;

    .line 790
    .line 791
    iget v1, v0, Lq0/e;->h:I

    .line 792
    .line 793
    add-int/2addr v1, v7

    .line 794
    iput v1, v0, Lq0/e;->h:I

    .line 795
    .line 796
    new-instance v1, Landroid/graphics/SurfaceTexture;

    .line 797
    .line 798
    iget-object v2, v0, Lq0/e;->d:Lq0/c;

    .line 799
    .line 800
    iget-boolean v3, p0, Lb0/x1;->e:Z

    .line 801
    .line 802
    iget-object v4, p0, Lb0/x1;->b:Landroid/util/Size;

    .line 803
    .line 804
    iget-object v5, v2, Lc1/k2;->f:Ljava/lang/Object;

    .line 805
    .line 806
    check-cast v5, Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 807
    .line 808
    invoke-static {v5, v7}, Lr0/i;->d(Ljava/util/concurrent/atomic/AtomicBoolean;Z)V

    .line 809
    .line 810
    .line 811
    iget-object v5, v2, Lc1/k2;->h:Ljava/lang/Object;

    .line 812
    .line 813
    check-cast v5, Ljava/lang/Thread;

    .line 814
    .line 815
    invoke-static {v5}, Lr0/i;->c(Ljava/lang/Thread;)V

    .line 816
    .line 817
    .line 818
    if-eqz v3, :cond_14

    .line 819
    .line 820
    iget v2, v2, Lq0/c;->q:I

    .line 821
    .line 822
    goto :goto_9

    .line 823
    :cond_14
    iget v2, v2, Lq0/c;->r:I

    .line 824
    .line 825
    :goto_9
    invoke-direct {v1, v2}, Landroid/graphics/SurfaceTexture;-><init>(I)V

    .line 826
    .line 827
    .line 828
    invoke-virtual {v4}, Landroid/util/Size;->getWidth()I

    .line 829
    .line 830
    .line 831
    move-result v2

    .line 832
    invoke-virtual {v4}, Landroid/util/Size;->getHeight()I

    .line 833
    .line 834
    .line 835
    move-result v4

    .line 836
    invoke-virtual {v1, v2, v4}, Landroid/graphics/SurfaceTexture;->setDefaultBufferSize(II)V

    .line 837
    .line 838
    .line 839
    new-instance v2, Landroid/view/Surface;

    .line 840
    .line 841
    invoke-direct {v2, v1}, Landroid/view/Surface;-><init>(Landroid/graphics/SurfaceTexture;)V

    .line 842
    .line 843
    .line 844
    iget-object v4, v0, Lq0/e;->f:Lj0/c;

    .line 845
    .line 846
    new-instance v5, Lq0/d;

    .line 847
    .line 848
    invoke-direct {v5, v0, v1, v2}, Lq0/d;-><init>(Lq0/e;Landroid/graphics/SurfaceTexture;Landroid/view/Surface;)V

    .line 849
    .line 850
    .line 851
    invoke-virtual {p0, v2, v4, v5}, Lb0/x1;->a(Landroid/view/Surface;Ljava/util/concurrent/Executor;Lc6/a;)V

    .line 852
    .line 853
    .line 854
    if-eqz v3, :cond_15

    .line 855
    .line 856
    iput-object v1, v0, Lq0/e;->l:Landroid/graphics/SurfaceTexture;

    .line 857
    .line 858
    goto :goto_a

    .line 859
    :cond_15
    iput-object v1, v0, Lq0/e;->m:Landroid/graphics/SurfaceTexture;

    .line 860
    .line 861
    iget-object p0, v0, Lq0/e;->g:Landroid/os/Handler;

    .line 862
    .line 863
    invoke-virtual {v1, v0, p0}, Landroid/graphics/SurfaceTexture;->setOnFrameAvailableListener(Landroid/graphics/SurfaceTexture$OnFrameAvailableListener;Landroid/os/Handler;)V

    .line 864
    .line 865
    .line 866
    :goto_a
    return-void

    .line 867
    :pswitch_1c
    iget-object v0, p0, Lno/nordicsemi/android/ble/o0;->e:Ljava/lang/Object;

    .line 868
    .line 869
    check-cast v0, Lp5/b;

    .line 870
    .line 871
    iget-object p0, p0, Lno/nordicsemi/android/ble/o0;->f:Ljava/lang/Object;

    .line 872
    .line 873
    check-cast p0, Landroid/graphics/Typeface;

    .line 874
    .line 875
    invoke-virtual {v0, p0}, Lp5/b;->i(Landroid/graphics/Typeface;)V

    .line 876
    .line 877
    .line 878
    return-void

    .line 879
    :pswitch_1d
    iget-object v0, p0, Lno/nordicsemi/android/ble/o0;->e:Ljava/lang/Object;

    .line 880
    .line 881
    check-cast v0, Lp0/l;

    .line 882
    .line 883
    iget-object p0, p0, Lno/nordicsemi/android/ble/o0;->f:Ljava/lang/Object;

    .line 884
    .line 885
    check-cast p0, Ljava/util/concurrent/atomic/AtomicReference;

    .line 886
    .line 887
    invoke-virtual {p0}, Ljava/util/concurrent/atomic/AtomicReference;->get()Ljava/lang/Object;

    .line 888
    .line 889
    .line 890
    move-result-object p0

    .line 891
    check-cast p0, Lc6/a;

    .line 892
    .line 893
    new-instance v1, Lb0/h;

    .line 894
    .line 895
    invoke-direct {v1, v0}, Lb0/h;-><init>(Lp0/l;)V

    .line 896
    .line 897
    .line 898
    invoke-interface {p0, v1}, Lc6/a;->accept(Ljava/lang/Object;)V

    .line 899
    .line 900
    .line 901
    return-void

    .line 902
    :pswitch_1e
    iget-object v0, p0, Lno/nordicsemi/android/ble/o0;->e:Ljava/lang/Object;

    .line 903
    .line 904
    check-cast v0, Lp0/c;

    .line 905
    .line 906
    iget-object p0, p0, Lno/nordicsemi/android/ble/o0;->f:Ljava/lang/Object;

    .line 907
    .line 908
    check-cast p0, Lb0/x1;

    .line 909
    .line 910
    iget v1, v0, Lp0/c;->l:I

    .line 911
    .line 912
    add-int/2addr v1, v7

    .line 913
    iput v1, v0, Lp0/c;->l:I

    .line 914
    .line 915
    new-instance v1, Landroid/graphics/SurfaceTexture;

    .line 916
    .line 917
    iget-object v2, v0, Lp0/c;->d:Lc1/k2;

    .line 918
    .line 919
    iget-object v3, v2, Lc1/k2;->f:Ljava/lang/Object;

    .line 920
    .line 921
    check-cast v3, Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 922
    .line 923
    invoke-static {v3, v7}, Lr0/i;->d(Ljava/util/concurrent/atomic/AtomicBoolean;Z)V

    .line 924
    .line 925
    .line 926
    iget-object v3, v2, Lc1/k2;->h:Ljava/lang/Object;

    .line 927
    .line 928
    check-cast v3, Ljava/lang/Thread;

    .line 929
    .line 930
    invoke-static {v3}, Lr0/i;->c(Ljava/lang/Thread;)V

    .line 931
    .line 932
    .line 933
    iget v2, v2, Lc1/k2;->e:I

    .line 934
    .line 935
    invoke-direct {v1, v2}, Landroid/graphics/SurfaceTexture;-><init>(I)V

    .line 936
    .line 937
    .line 938
    iget-object v2, p0, Lb0/x1;->b:Landroid/util/Size;

    .line 939
    .line 940
    invoke-virtual {v2}, Landroid/util/Size;->getWidth()I

    .line 941
    .line 942
    .line 943
    move-result v3

    .line 944
    invoke-virtual {v2}, Landroid/util/Size;->getHeight()I

    .line 945
    .line 946
    .line 947
    move-result v2

    .line 948
    invoke-virtual {v1, v3, v2}, Landroid/graphics/SurfaceTexture;->setDefaultBufferSize(II)V

    .line 949
    .line 950
    .line 951
    new-instance v2, Landroid/view/Surface;

    .line 952
    .line 953
    invoke-direct {v2, v1}, Landroid/view/Surface;-><init>(Landroid/graphics/SurfaceTexture;)V

    .line 954
    .line 955
    .line 956
    iget-object v3, v0, Lp0/c;->f:Lj0/c;

    .line 957
    .line 958
    new-instance v4, La0/h;

    .line 959
    .line 960
    const/16 v5, 0x16

    .line 961
    .line 962
    invoke-direct {v4, v5, v0, p0}, La0/h;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 963
    .line 964
    .line 965
    invoke-virtual {p0, v3, v4}, Lb0/x1;->b(Ljava/util/concurrent/Executor;Lb0/w1;)V

    .line 966
    .line 967
    .line 968
    new-instance v4, Lp0/b;

    .line 969
    .line 970
    invoke-direct {v4, v0, p0, v1, v2}, Lp0/b;-><init>(Lp0/c;Lb0/x1;Landroid/graphics/SurfaceTexture;Landroid/view/Surface;)V

    .line 971
    .line 972
    .line 973
    invoke-virtual {p0, v2, v3, v4}, Lb0/x1;->a(Landroid/view/Surface;Ljava/util/concurrent/Executor;Lc6/a;)V

    .line 974
    .line 975
    .line 976
    iget-object p0, v0, Lp0/c;->g:Landroid/os/Handler;

    .line 977
    .line 978
    invoke-virtual {v1, v0, p0}, Landroid/graphics/SurfaceTexture;->setOnFrameAvailableListener(Landroid/graphics/SurfaceTexture$OnFrameAvailableListener;Landroid/os/Handler;)V

    .line 979
    .line 980
    .line 981
    return-void

    .line 982
    :pswitch_1f
    iget-object v0, p0, Lno/nordicsemi/android/ble/o0;->e:Ljava/lang/Object;

    .line 983
    .line 984
    check-cast v0, Lp0/c;

    .line 985
    .line 986
    iget-object p0, p0, Lno/nordicsemi/android/ble/o0;->f:Ljava/lang/Object;

    .line 987
    .line 988
    check-cast p0, Lp0/l;

    .line 989
    .line 990
    iget-object v1, v0, Lp0/c;->f:Lj0/c;

    .line 991
    .line 992
    new-instance v2, Ll0/d;

    .line 993
    .line 994
    invoke-direct {v2, v7, v0, p0}, Ll0/d;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 995
    .line 996
    .line 997
    invoke-virtual {p0, v1, v2}, Lp0/l;->b(Lj0/c;Lc6/a;)Landroid/view/Surface;

    .line 998
    .line 999
    .line 1000
    move-result-object v1

    .line 1001
    iget-object v2, v0, Lp0/c;->d:Lc1/k2;

    .line 1002
    .line 1003
    invoke-virtual {v2, v1}, Lc1/k2;->l(Landroid/view/Surface;)V

    .line 1004
    .line 1005
    .line 1006
    iget-object v0, v0, Lp0/c;->k:Ljava/util/LinkedHashMap;

    .line 1007
    .line 1008
    invoke-interface {v0, p0, v1}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 1009
    .line 1010
    .line 1011
    return-void

    .line 1012
    :pswitch_20
    iget-object v0, p0, Lno/nordicsemi/android/ble/o0;->e:Ljava/lang/Object;

    .line 1013
    .line 1014
    check-cast v0, Lss/b;

    .line 1015
    .line 1016
    iget-object p0, p0, Lno/nordicsemi/android/ble/o0;->f:Ljava/lang/Object;

    .line 1017
    .line 1018
    check-cast p0, Ljava/util/List;

    .line 1019
    .line 1020
    iget-object v1, v0, Lss/b;->f:Ljava/lang/Object;

    .line 1021
    .line 1022
    check-cast v1, Los/h;

    .line 1023
    .line 1024
    iget-object v0, v0, Lss/b;->e:Ljava/lang/Object;

    .line 1025
    .line 1026
    check-cast v0, Ljava/lang/String;

    .line 1027
    .line 1028
    invoke-virtual {v1, v0, p0}, Los/h;->i(Ljava/lang/String;Ljava/util/List;)V

    .line 1029
    .line 1030
    .line 1031
    return-void

    .line 1032
    :pswitch_21
    iget-object v0, p0, Lno/nordicsemi/android/ble/o0;->e:Ljava/lang/Object;

    .line 1033
    .line 1034
    check-cast v0, Lorg/altbeacon/beacon/service/IntentScanStrategyCoordinator;

    .line 1035
    .line 1036
    iget-object p0, p0, Lno/nordicsemi/android/ble/o0;->f:Ljava/lang/Object;

    .line 1037
    .line 1038
    check-cast p0, Landroid/content/Context;

    .line 1039
    .line 1040
    invoke-static {v0, p0}, Lorg/altbeacon/beacon/service/IntentScanStrategyCoordinator;->a(Lorg/altbeacon/beacon/service/IntentScanStrategyCoordinator;Landroid/content/Context;)V

    .line 1041
    .line 1042
    .line 1043
    return-void

    .line 1044
    :pswitch_22
    iget-object v0, p0, Lno/nordicsemi/android/ble/o0;->e:Ljava/lang/Object;

    .line 1045
    .line 1046
    check-cast v0, Lno/nordicsemi/android/ble/p0;

    .line 1047
    .line 1048
    iget-object p0, p0, Lno/nordicsemi/android/ble/o0;->f:Ljava/lang/Object;

    .line 1049
    .line 1050
    check-cast p0, Landroid/bluetooth/BluetoothDevice;

    .line 1051
    .line 1052
    iput-object v5, v0, Lno/nordicsemi/android/ble/p0;->m:Lno/nordicsemi/android/ble/o0;

    .line 1053
    .line 1054
    iget-boolean v3, v0, Lno/nordicsemi/android/ble/i0;->k:Z

    .line 1055
    .line 1056
    if-nez v3, :cond_1e

    .line 1057
    .line 1058
    iget-object v3, v0, Lno/nordicsemi/android/ble/i0;->a:Lno/nordicsemi/android/ble/d;

    .line 1059
    .line 1060
    instance-of v8, v0, Lno/nordicsemi/android/ble/n0;

    .line 1061
    .line 1062
    if-eqz v8, :cond_16

    .line 1063
    .line 1064
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1065
    .line 1066
    .line 1067
    move-object v2, v0

    .line 1068
    check-cast v2, Lno/nordicsemi/android/ble/n0;

    .line 1069
    .line 1070
    invoke-virtual {v2, p0}, Lno/nordicsemi/android/ble/p0;->d(Landroid/bluetooth/BluetoothDevice;)Z

    .line 1071
    .line 1072
    .line 1073
    goto :goto_b

    .line 1074
    :cond_16
    iget-object v8, v3, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 1075
    .line 1076
    invoke-virtual {v8}, Lno/nordicsemi/android/ble/e;->getMinLogPriority()I

    .line 1077
    .line 1078
    .line 1079
    move-result v8

    .line 1080
    if-lt v2, v8, :cond_17

    .line 1081
    .line 1082
    iget-object v8, v3, Lno/nordicsemi/android/ble/d;->d:Lno/nordicsemi/android/ble/e;

    .line 1083
    .line 1084
    const-string v9, "Request timed out"

    .line 1085
    .line 1086
    invoke-virtual {v8, v2, v9}, Lno/nordicsemi/android/ble/e;->log(ILjava/lang/String;)V

    .line 1087
    .line 1088
    .line 1089
    :cond_17
    :goto_b
    iget-object v2, v3, Lno/nordicsemi/android/ble/d;->z:Lno/nordicsemi/android/ble/i0;

    .line 1090
    .line 1091
    instance-of v8, v2, Lno/nordicsemi/android/ble/p0;

    .line 1092
    .line 1093
    const/4 v9, -0x5

    .line 1094
    if-eqz v8, :cond_18

    .line 1095
    .line 1096
    check-cast v2, Lno/nordicsemi/android/ble/p0;

    .line 1097
    .line 1098
    invoke-virtual {v2, v9, p0}, Lno/nordicsemi/android/ble/p0;->a(ILandroid/bluetooth/BluetoothDevice;)V

    .line 1099
    .line 1100
    .line 1101
    :cond_18
    iget-object v2, v3, Lno/nordicsemi/android/ble/d;->E:Lno/nordicsemi/android/ble/a;

    .line 1102
    .line 1103
    if-eqz v2, :cond_19

    .line 1104
    .line 1105
    invoke-virtual {v2, v9, p0}, Lno/nordicsemi/android/ble/p0;->a(ILandroid/bluetooth/BluetoothDevice;)V

    .line 1106
    .line 1107
    .line 1108
    iput-object v5, v3, Lno/nordicsemi/android/ble/d;->E:Lno/nordicsemi/android/ble/a;

    .line 1109
    .line 1110
    :cond_19
    invoke-virtual {v0, v9, p0}, Lno/nordicsemi/android/ble/p0;->a(ILandroid/bluetooth/BluetoothDevice;)V

    .line 1111
    .line 1112
    .line 1113
    iget p0, v0, Lno/nordicsemi/android/ble/i0;->c:I

    .line 1114
    .line 1115
    if-ne p0, v4, :cond_1a

    .line 1116
    .line 1117
    iput-object v5, v3, Lno/nordicsemi/android/ble/d;->y:Lno/nordicsemi/android/ble/x;

    .line 1118
    .line 1119
    const/16 p0, 0xa

    .line 1120
    .line 1121
    invoke-virtual {v3, p0}, Lno/nordicsemi/android/ble/d;->o(I)V

    .line 1122
    .line 1123
    .line 1124
    goto :goto_c

    .line 1125
    :cond_1a
    if-ne p0, v1, :cond_1b

    .line 1126
    .line 1127
    invoke-virtual {v3}, Lno/nordicsemi/android/ble/d;->c()V

    .line 1128
    .line 1129
    .line 1130
    goto :goto_c

    .line 1131
    :cond_1b
    iget-object p0, v3, Lno/nordicsemi/android/ble/d;->z:Lno/nordicsemi/android/ble/i0;

    .line 1132
    .line 1133
    if-eqz p0, :cond_1c

    .line 1134
    .line 1135
    iget-boolean p0, p0, Lno/nordicsemi/android/ble/i0;->k:Z

    .line 1136
    .line 1137
    if-eqz p0, :cond_1d

    .line 1138
    .line 1139
    :cond_1c
    move v6, v7

    .line 1140
    :cond_1d
    invoke-virtual {v3, v6}, Lno/nordicsemi/android/ble/d;->A(Z)V

    .line 1141
    .line 1142
    .line 1143
    :cond_1e
    :goto_c
    return-void

    .line 1144
    nop

    .line 1145
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_22
        :pswitch_21
        :pswitch_20
        :pswitch_1f
        :pswitch_1e
        :pswitch_1d
        :pswitch_1c
        :pswitch_1b
        :pswitch_1a
        :pswitch_19
        :pswitch_18
        :pswitch_17
        :pswitch_16
        :pswitch_15
        :pswitch_14
        :pswitch_13
        :pswitch_12
        :pswitch_11
        :pswitch_10
        :pswitch_f
        :pswitch_e
        :pswitch_d
        :pswitch_c
        :pswitch_b
        :pswitch_a
        :pswitch_9
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch

    .line 1146
    .line 1147
    .line 1148
    .line 1149
    .line 1150
    .line 1151
    .line 1152
    .line 1153
    .line 1154
    .line 1155
    .line 1156
    .line 1157
    .line 1158
    .line 1159
    .line 1160
    .line 1161
    .line 1162
    .line 1163
    .line 1164
    .line 1165
    .line 1166
    .line 1167
    .line 1168
    .line 1169
    .line 1170
    .line 1171
    .line 1172
    .line 1173
    .line 1174
    .line 1175
    .line 1176
    .line 1177
    .line 1178
    .line 1179
    .line 1180
    .line 1181
    .line 1182
    .line 1183
    .line 1184
    .line 1185
    .line 1186
    .line 1187
    .line 1188
    .line 1189
    .line 1190
    .line 1191
    .line 1192
    .line 1193
    .line 1194
    .line 1195
    .line 1196
    .line 1197
    .line 1198
    .line 1199
    .line 1200
    .line 1201
    .line 1202
    .line 1203
    .line 1204
    .line 1205
    .line 1206
    .line 1207
    :pswitch_data_1
    .packed-switch 0x1
        :pswitch_8
        :pswitch_8
        :pswitch_7
        :pswitch_7
        :pswitch_7
        :pswitch_7
        :pswitch_7
        :pswitch_7
        :pswitch_7
        :pswitch_7
        :pswitch_7
        :pswitch_7
        :pswitch_3
        :pswitch_7
        :pswitch_7
        :pswitch_5
        :pswitch_7
        :pswitch_4
        :pswitch_5
        :pswitch_6
    .end packed-switch
.end method
