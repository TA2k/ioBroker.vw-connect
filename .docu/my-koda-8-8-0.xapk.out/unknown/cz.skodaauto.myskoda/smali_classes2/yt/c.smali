.class public final Lyt/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final i:J


# instance fields
.field public a:Lzt/h;

.field public b:Las/e;

.field public c:J

.field public d:D

.field public final e:Las/e;

.field public final f:Las/e;

.field public final g:J

.field public final h:J


# direct methods
.method static constructor <clinit>()V
    .locals 3

    .line 1
    invoke-static {}, Lst/a;->d()Lst/a;

    .line 2
    .line 3
    .line 4
    sget-object v0, Ljava/util/concurrent/TimeUnit;->SECONDS:Ljava/util/concurrent/TimeUnit;

    .line 5
    .line 6
    const-wide/16 v1, 0x1

    .line 7
    .line 8
    invoke-virtual {v0, v1, v2}, Ljava/util/concurrent/TimeUnit;->toMicros(J)J

    .line 9
    .line 10
    .line 11
    move-result-wide v0

    .line 12
    sput-wide v0, Lyt/c;->i:J

    .line 13
    .line 14
    return-void
.end method

.method public constructor <init>(Las/e;La61/a;Lqt/a;Ljava/lang/String;)V
    .locals 11

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    const-wide/16 v0, 0x1f4

    .line 5
    .line 6
    iput-wide v0, p0, Lyt/c;->c:J

    .line 7
    .line 8
    iput-object p1, p0, Lyt/c;->b:Las/e;

    .line 9
    .line 10
    long-to-double p1, v0

    .line 11
    iput-wide p1, p0, Lyt/c;->d:D

    .line 12
    .line 13
    new-instance p1, Lzt/h;

    .line 14
    .line 15
    invoke-direct {p1}, Lzt/h;-><init>()V

    .line 16
    .line 17
    .line 18
    iput-object p1, p0, Lyt/c;->a:Lzt/h;

    .line 19
    .line 20
    const-string p1, "Trace"

    .line 21
    .line 22
    if-ne p4, p1, :cond_0

    .line 23
    .line 24
    invoke-virtual {p3}, Lqt/a;->k()J

    .line 25
    .line 26
    .line 27
    move-result-wide p1

    .line 28
    :goto_0
    move-wide v3, p1

    .line 29
    goto :goto_1

    .line 30
    :cond_0
    invoke-virtual {p3}, Lqt/a;->k()J

    .line 31
    .line 32
    .line 33
    move-result-wide p1

    .line 34
    goto :goto_0

    .line 35
    :goto_1
    const-string p1, "Trace"

    .line 36
    .line 37
    if-ne p4, p1, :cond_4

    .line 38
    .line 39
    const-class p1, Lqt/t;

    .line 40
    .line 41
    monitor-enter p1

    .line 42
    :try_start_0
    sget-object p2, Lqt/t;->a:Lqt/t;

    .line 43
    .line 44
    if-nez p2, :cond_1

    .line 45
    .line 46
    new-instance p2, Lqt/t;

    .line 47
    .line 48
    invoke-direct {p2}, Ljava/lang/Object;-><init>()V

    .line 49
    .line 50
    .line 51
    sput-object p2, Lqt/t;->a:Lqt/t;

    .line 52
    .line 53
    goto :goto_2

    .line 54
    :catchall_0
    move-exception v0

    .line 55
    move-object p0, v0

    .line 56
    goto :goto_4

    .line 57
    :cond_1
    :goto_2
    sget-object p2, Lqt/t;->a:Lqt/t;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 58
    .line 59
    monitor-exit p1

    .line 60
    iget-object p1, p3, Lqt/a;->a:Lcom/google/firebase/perf/config/RemoteConfigManager;

    .line 61
    .line 62
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 63
    .line 64
    .line 65
    const-string v0, "fpr_rl_trace_event_count_fg"

    .line 66
    .line 67
    invoke-virtual {p1, v0}, Lcom/google/firebase/perf/config/RemoteConfigManager;->getLong(Ljava/lang/String;)Lzt/d;

    .line 68
    .line 69
    .line 70
    move-result-object p1

    .line 71
    invoke-virtual {p1}, Lzt/d;->b()Z

    .line 72
    .line 73
    .line 74
    move-result v0

    .line 75
    if-eqz v0, :cond_2

    .line 76
    .line 77
    invoke-virtual {p1}, Lzt/d;->a()Ljava/lang/Object;

    .line 78
    .line 79
    .line 80
    move-result-object v0

    .line 81
    check-cast v0, Ljava/lang/Long;

    .line 82
    .line 83
    invoke-virtual {v0}, Ljava/lang/Long;->longValue()J

    .line 84
    .line 85
    .line 86
    move-result-wide v0

    .line 87
    invoke-static {v0, v1}, Lqt/a;->l(J)Z

    .line 88
    .line 89
    .line 90
    move-result v0

    .line 91
    if-eqz v0, :cond_2

    .line 92
    .line 93
    iget-object p2, p3, Lqt/a;->c:Lqt/v;

    .line 94
    .line 95
    const-string v0, "com.google.firebase.perf.TraceEventCountForeground"

    .line 96
    .line 97
    invoke-virtual {p1}, Lzt/d;->a()Ljava/lang/Object;

    .line 98
    .line 99
    .line 100
    move-result-object v1

    .line 101
    check-cast v1, Ljava/lang/Long;

    .line 102
    .line 103
    invoke-virtual {v1}, Ljava/lang/Long;->longValue()J

    .line 104
    .line 105
    .line 106
    move-result-wide v1

    .line 107
    invoke-virtual {p2, v1, v2, v0}, Lqt/v;->e(JLjava/lang/String;)V

    .line 108
    .line 109
    .line 110
    invoke-virtual {p1}, Lzt/d;->a()Ljava/lang/Object;

    .line 111
    .line 112
    .line 113
    move-result-object p1

    .line 114
    check-cast p1, Ljava/lang/Long;

    .line 115
    .line 116
    invoke-virtual {p1}, Ljava/lang/Long;->longValue()J

    .line 117
    .line 118
    .line 119
    move-result-wide p1

    .line 120
    :goto_3
    move-wide v1, p1

    .line 121
    goto/16 :goto_6

    .line 122
    .line 123
    :cond_2
    invoke-virtual {p3, p2}, Lqt/a;->c(Ljp/fg;)Lzt/d;

    .line 124
    .line 125
    .line 126
    move-result-object p1

    .line 127
    invoke-virtual {p1}, Lzt/d;->b()Z

    .line 128
    .line 129
    .line 130
    move-result p2

    .line 131
    if-eqz p2, :cond_3

    .line 132
    .line 133
    invoke-virtual {p1}, Lzt/d;->a()Ljava/lang/Object;

    .line 134
    .line 135
    .line 136
    move-result-object p2

    .line 137
    check-cast p2, Ljava/lang/Long;

    .line 138
    .line 139
    invoke-virtual {p2}, Ljava/lang/Long;->longValue()J

    .line 140
    .line 141
    .line 142
    move-result-wide v0

    .line 143
    invoke-static {v0, v1}, Lqt/a;->l(J)Z

    .line 144
    .line 145
    .line 146
    move-result p2

    .line 147
    if-eqz p2, :cond_3

    .line 148
    .line 149
    invoke-virtual {p1}, Lzt/d;->a()Ljava/lang/Object;

    .line 150
    .line 151
    .line 152
    move-result-object p1

    .line 153
    check-cast p1, Ljava/lang/Long;

    .line 154
    .line 155
    invoke-virtual {p1}, Ljava/lang/Long;->longValue()J

    .line 156
    .line 157
    .line 158
    move-result-wide p1

    .line 159
    goto :goto_3

    .line 160
    :cond_3
    const-wide/16 p1, 0x12c

    .line 161
    .line 162
    goto :goto_3

    .line 163
    :goto_4
    :try_start_1
    monitor-exit p1
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 164
    throw p0

    .line 165
    :cond_4
    const-class p1, Lqt/h;

    .line 166
    .line 167
    monitor-enter p1

    .line 168
    :try_start_2
    sget-object p2, Lqt/h;->a:Lqt/h;

    .line 169
    .line 170
    if-nez p2, :cond_5

    .line 171
    .line 172
    new-instance p2, Lqt/h;

    .line 173
    .line 174
    invoke-direct {p2}, Ljava/lang/Object;-><init>()V

    .line 175
    .line 176
    .line 177
    sput-object p2, Lqt/h;->a:Lqt/h;

    .line 178
    .line 179
    goto :goto_5

    .line 180
    :catchall_1
    move-exception v0

    .line 181
    move-object p0, v0

    .line 182
    goto/16 :goto_f

    .line 183
    .line 184
    :cond_5
    :goto_5
    sget-object p2, Lqt/h;->a:Lqt/h;
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_1

    .line 185
    .line 186
    monitor-exit p1

    .line 187
    iget-object p1, p3, Lqt/a;->a:Lcom/google/firebase/perf/config/RemoteConfigManager;

    .line 188
    .line 189
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 190
    .line 191
    .line 192
    const-string v0, "fpr_rl_network_event_count_fg"

    .line 193
    .line 194
    invoke-virtual {p1, v0}, Lcom/google/firebase/perf/config/RemoteConfigManager;->getLong(Ljava/lang/String;)Lzt/d;

    .line 195
    .line 196
    .line 197
    move-result-object p1

    .line 198
    invoke-virtual {p1}, Lzt/d;->b()Z

    .line 199
    .line 200
    .line 201
    move-result v0

    .line 202
    if-eqz v0, :cond_6

    .line 203
    .line 204
    invoke-virtual {p1}, Lzt/d;->a()Ljava/lang/Object;

    .line 205
    .line 206
    .line 207
    move-result-object v0

    .line 208
    check-cast v0, Ljava/lang/Long;

    .line 209
    .line 210
    invoke-virtual {v0}, Ljava/lang/Long;->longValue()J

    .line 211
    .line 212
    .line 213
    move-result-wide v0

    .line 214
    invoke-static {v0, v1}, Lqt/a;->l(J)Z

    .line 215
    .line 216
    .line 217
    move-result v0

    .line 218
    if-eqz v0, :cond_6

    .line 219
    .line 220
    iget-object p2, p3, Lqt/a;->c:Lqt/v;

    .line 221
    .line 222
    const-string v0, "com.google.firebase.perf.NetworkEventCountForeground"

    .line 223
    .line 224
    invoke-virtual {p1}, Lzt/d;->a()Ljava/lang/Object;

    .line 225
    .line 226
    .line 227
    move-result-object v1

    .line 228
    check-cast v1, Ljava/lang/Long;

    .line 229
    .line 230
    invoke-virtual {v1}, Ljava/lang/Long;->longValue()J

    .line 231
    .line 232
    .line 233
    move-result-wide v1

    .line 234
    invoke-virtual {p2, v1, v2, v0}, Lqt/v;->e(JLjava/lang/String;)V

    .line 235
    .line 236
    .line 237
    invoke-virtual {p1}, Lzt/d;->a()Ljava/lang/Object;

    .line 238
    .line 239
    .line 240
    move-result-object p1

    .line 241
    check-cast p1, Ljava/lang/Long;

    .line 242
    .line 243
    invoke-virtual {p1}, Ljava/lang/Long;->longValue()J

    .line 244
    .line 245
    .line 246
    move-result-wide p1

    .line 247
    goto :goto_3

    .line 248
    :cond_6
    invoke-virtual {p3, p2}, Lqt/a;->c(Ljp/fg;)Lzt/d;

    .line 249
    .line 250
    .line 251
    move-result-object p1

    .line 252
    invoke-virtual {p1}, Lzt/d;->b()Z

    .line 253
    .line 254
    .line 255
    move-result p2

    .line 256
    if-eqz p2, :cond_7

    .line 257
    .line 258
    invoke-virtual {p1}, Lzt/d;->a()Ljava/lang/Object;

    .line 259
    .line 260
    .line 261
    move-result-object p2

    .line 262
    check-cast p2, Ljava/lang/Long;

    .line 263
    .line 264
    invoke-virtual {p2}, Ljava/lang/Long;->longValue()J

    .line 265
    .line 266
    .line 267
    move-result-wide v0

    .line 268
    invoke-static {v0, v1}, Lqt/a;->l(J)Z

    .line 269
    .line 270
    .line 271
    move-result p2

    .line 272
    if-eqz p2, :cond_7

    .line 273
    .line 274
    invoke-virtual {p1}, Lzt/d;->a()Ljava/lang/Object;

    .line 275
    .line 276
    .line 277
    move-result-object p1

    .line 278
    check-cast p1, Ljava/lang/Long;

    .line 279
    .line 280
    invoke-virtual {p1}, Ljava/lang/Long;->longValue()J

    .line 281
    .line 282
    .line 283
    move-result-wide p1

    .line 284
    goto/16 :goto_3

    .line 285
    .line 286
    :cond_7
    const-wide/16 p1, 0x2bc

    .line 287
    .line 288
    goto/16 :goto_3

    .line 289
    .line 290
    :goto_6
    new-instance v0, Las/e;

    .line 291
    .line 292
    sget-object v5, Ljava/util/concurrent/TimeUnit;->SECONDS:Ljava/util/concurrent/TimeUnit;

    .line 293
    .line 294
    invoke-direct/range {v0 .. v5}, Las/e;-><init>(JJLjava/util/concurrent/TimeUnit;)V

    .line 295
    .line 296
    .line 297
    iput-object v0, p0, Lyt/c;->e:Las/e;

    .line 298
    .line 299
    iput-wide v1, p0, Lyt/c;->g:J

    .line 300
    .line 301
    const-string p1, "Trace"

    .line 302
    .line 303
    if-ne p4, p1, :cond_8

    .line 304
    .line 305
    invoke-virtual {p3}, Lqt/a;->k()J

    .line 306
    .line 307
    .line 308
    move-result-wide p1

    .line 309
    :goto_7
    move-wide v8, p1

    .line 310
    goto :goto_8

    .line 311
    :cond_8
    invoke-virtual {p3}, Lqt/a;->k()J

    .line 312
    .line 313
    .line 314
    move-result-wide p1

    .line 315
    goto :goto_7

    .line 316
    :goto_8
    const-string p1, "Trace"

    .line 317
    .line 318
    if-ne p4, p1, :cond_c

    .line 319
    .line 320
    const-class p1, Lqt/s;

    .line 321
    .line 322
    monitor-enter p1

    .line 323
    :try_start_3
    sget-object p2, Lqt/s;->a:Lqt/s;

    .line 324
    .line 325
    if-nez p2, :cond_9

    .line 326
    .line 327
    new-instance p2, Lqt/s;

    .line 328
    .line 329
    invoke-direct {p2}, Ljava/lang/Object;-><init>()V

    .line 330
    .line 331
    .line 332
    sput-object p2, Lqt/s;->a:Lqt/s;

    .line 333
    .line 334
    goto :goto_9

    .line 335
    :catchall_2
    move-exception v0

    .line 336
    move-object p0, v0

    .line 337
    goto :goto_b

    .line 338
    :cond_9
    :goto_9
    sget-object p2, Lqt/s;->a:Lqt/s;
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_2

    .line 339
    .line 340
    monitor-exit p1

    .line 341
    iget-object p1, p3, Lqt/a;->a:Lcom/google/firebase/perf/config/RemoteConfigManager;

    .line 342
    .line 343
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 344
    .line 345
    .line 346
    const-string p4, "fpr_rl_trace_event_count_bg"

    .line 347
    .line 348
    invoke-virtual {p1, p4}, Lcom/google/firebase/perf/config/RemoteConfigManager;->getLong(Ljava/lang/String;)Lzt/d;

    .line 349
    .line 350
    .line 351
    move-result-object p1

    .line 352
    invoke-virtual {p1}, Lzt/d;->b()Z

    .line 353
    .line 354
    .line 355
    move-result p4

    .line 356
    if-eqz p4, :cond_a

    .line 357
    .line 358
    invoke-virtual {p1}, Lzt/d;->a()Ljava/lang/Object;

    .line 359
    .line 360
    .line 361
    move-result-object p4

    .line 362
    check-cast p4, Ljava/lang/Long;

    .line 363
    .line 364
    invoke-virtual {p4}, Ljava/lang/Long;->longValue()J

    .line 365
    .line 366
    .line 367
    move-result-wide v0

    .line 368
    invoke-static {v0, v1}, Lqt/a;->l(J)Z

    .line 369
    .line 370
    .line 371
    move-result p4

    .line 372
    if-eqz p4, :cond_a

    .line 373
    .line 374
    iget-object p2, p3, Lqt/a;->c:Lqt/v;

    .line 375
    .line 376
    const-string p3, "com.google.firebase.perf.TraceEventCountBackground"

    .line 377
    .line 378
    invoke-virtual {p1}, Lzt/d;->a()Ljava/lang/Object;

    .line 379
    .line 380
    .line 381
    move-result-object p4

    .line 382
    check-cast p4, Ljava/lang/Long;

    .line 383
    .line 384
    invoke-virtual {p4}, Ljava/lang/Long;->longValue()J

    .line 385
    .line 386
    .line 387
    move-result-wide v0

    .line 388
    invoke-virtual {p2, v0, v1, p3}, Lqt/v;->e(JLjava/lang/String;)V

    .line 389
    .line 390
    .line 391
    invoke-virtual {p1}, Lzt/d;->a()Ljava/lang/Object;

    .line 392
    .line 393
    .line 394
    move-result-object p1

    .line 395
    check-cast p1, Ljava/lang/Long;

    .line 396
    .line 397
    invoke-virtual {p1}, Ljava/lang/Long;->longValue()J

    .line 398
    .line 399
    .line 400
    move-result-wide p1

    .line 401
    :goto_a
    move-wide v6, p1

    .line 402
    move-object v10, v5

    .line 403
    goto/16 :goto_d

    .line 404
    .line 405
    :cond_a
    invoke-virtual {p3, p2}, Lqt/a;->c(Ljp/fg;)Lzt/d;

    .line 406
    .line 407
    .line 408
    move-result-object p1

    .line 409
    invoke-virtual {p1}, Lzt/d;->b()Z

    .line 410
    .line 411
    .line 412
    move-result p2

    .line 413
    if-eqz p2, :cond_b

    .line 414
    .line 415
    invoke-virtual {p1}, Lzt/d;->a()Ljava/lang/Object;

    .line 416
    .line 417
    .line 418
    move-result-object p2

    .line 419
    check-cast p2, Ljava/lang/Long;

    .line 420
    .line 421
    invoke-virtual {p2}, Ljava/lang/Long;->longValue()J

    .line 422
    .line 423
    .line 424
    move-result-wide p2

    .line 425
    invoke-static {p2, p3}, Lqt/a;->l(J)Z

    .line 426
    .line 427
    .line 428
    move-result p2

    .line 429
    if-eqz p2, :cond_b

    .line 430
    .line 431
    invoke-virtual {p1}, Lzt/d;->a()Ljava/lang/Object;

    .line 432
    .line 433
    .line 434
    move-result-object p1

    .line 435
    check-cast p1, Ljava/lang/Long;

    .line 436
    .line 437
    invoke-virtual {p1}, Ljava/lang/Long;->longValue()J

    .line 438
    .line 439
    .line 440
    move-result-wide p1

    .line 441
    goto :goto_a

    .line 442
    :cond_b
    const-wide/16 p1, 0x1e

    .line 443
    .line 444
    goto :goto_a

    .line 445
    :goto_b
    :try_start_4
    monitor-exit p1
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_2

    .line 446
    throw p0

    .line 447
    :cond_c
    const-class p2, Lqt/g;

    .line 448
    .line 449
    monitor-enter p2

    .line 450
    :try_start_5
    sget-object p1, Lqt/g;->a:Lqt/g;

    .line 451
    .line 452
    if-nez p1, :cond_d

    .line 453
    .line 454
    new-instance p1, Lqt/g;

    .line 455
    .line 456
    invoke-direct {p1}, Ljava/lang/Object;-><init>()V

    .line 457
    .line 458
    .line 459
    sput-object p1, Lqt/g;->a:Lqt/g;

    .line 460
    .line 461
    goto :goto_c

    .line 462
    :catchall_3
    move-exception v0

    .line 463
    move-object p0, v0

    .line 464
    goto :goto_e

    .line 465
    :cond_d
    :goto_c
    sget-object p1, Lqt/g;->a:Lqt/g;
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_3

    .line 466
    .line 467
    monitor-exit p2

    .line 468
    iget-object p2, p3, Lqt/a;->a:Lcom/google/firebase/perf/config/RemoteConfigManager;

    .line 469
    .line 470
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 471
    .line 472
    .line 473
    const-string p4, "fpr_rl_network_event_count_bg"

    .line 474
    .line 475
    invoke-virtual {p2, p4}, Lcom/google/firebase/perf/config/RemoteConfigManager;->getLong(Ljava/lang/String;)Lzt/d;

    .line 476
    .line 477
    .line 478
    move-result-object p2

    .line 479
    invoke-virtual {p2}, Lzt/d;->b()Z

    .line 480
    .line 481
    .line 482
    move-result p4

    .line 483
    if-eqz p4, :cond_e

    .line 484
    .line 485
    invoke-virtual {p2}, Lzt/d;->a()Ljava/lang/Object;

    .line 486
    .line 487
    .line 488
    move-result-object p4

    .line 489
    check-cast p4, Ljava/lang/Long;

    .line 490
    .line 491
    invoke-virtual {p4}, Ljava/lang/Long;->longValue()J

    .line 492
    .line 493
    .line 494
    move-result-wide v0

    .line 495
    invoke-static {v0, v1}, Lqt/a;->l(J)Z

    .line 496
    .line 497
    .line 498
    move-result p4

    .line 499
    if-eqz p4, :cond_e

    .line 500
    .line 501
    iget-object p1, p3, Lqt/a;->c:Lqt/v;

    .line 502
    .line 503
    const-string p3, "com.google.firebase.perf.NetworkEventCountBackground"

    .line 504
    .line 505
    invoke-virtual {p2}, Lzt/d;->a()Ljava/lang/Object;

    .line 506
    .line 507
    .line 508
    move-result-object p4

    .line 509
    check-cast p4, Ljava/lang/Long;

    .line 510
    .line 511
    invoke-virtual {p4}, Ljava/lang/Long;->longValue()J

    .line 512
    .line 513
    .line 514
    move-result-wide v0

    .line 515
    invoke-virtual {p1, v0, v1, p3}, Lqt/v;->e(JLjava/lang/String;)V

    .line 516
    .line 517
    .line 518
    invoke-virtual {p2}, Lzt/d;->a()Ljava/lang/Object;

    .line 519
    .line 520
    .line 521
    move-result-object p1

    .line 522
    check-cast p1, Ljava/lang/Long;

    .line 523
    .line 524
    invoke-virtual {p1}, Ljava/lang/Long;->longValue()J

    .line 525
    .line 526
    .line 527
    move-result-wide p1

    .line 528
    goto :goto_a

    .line 529
    :cond_e
    invoke-virtual {p3, p1}, Lqt/a;->c(Ljp/fg;)Lzt/d;

    .line 530
    .line 531
    .line 532
    move-result-object p1

    .line 533
    invoke-virtual {p1}, Lzt/d;->b()Z

    .line 534
    .line 535
    .line 536
    move-result p2

    .line 537
    if-eqz p2, :cond_f

    .line 538
    .line 539
    invoke-virtual {p1}, Lzt/d;->a()Ljava/lang/Object;

    .line 540
    .line 541
    .line 542
    move-result-object p2

    .line 543
    check-cast p2, Ljava/lang/Long;

    .line 544
    .line 545
    invoke-virtual {p2}, Ljava/lang/Long;->longValue()J

    .line 546
    .line 547
    .line 548
    move-result-wide p2

    .line 549
    invoke-static {p2, p3}, Lqt/a;->l(J)Z

    .line 550
    .line 551
    .line 552
    move-result p2

    .line 553
    if-eqz p2, :cond_f

    .line 554
    .line 555
    invoke-virtual {p1}, Lzt/d;->a()Ljava/lang/Object;

    .line 556
    .line 557
    .line 558
    move-result-object p1

    .line 559
    check-cast p1, Ljava/lang/Long;

    .line 560
    .line 561
    invoke-virtual {p1}, Ljava/lang/Long;->longValue()J

    .line 562
    .line 563
    .line 564
    move-result-wide p1

    .line 565
    goto/16 :goto_a

    .line 566
    .line 567
    :cond_f
    const-wide/16 p1, 0x46

    .line 568
    .line 569
    goto/16 :goto_a

    .line 570
    .line 571
    :goto_d
    new-instance v5, Las/e;

    .line 572
    .line 573
    invoke-direct/range {v5 .. v10}, Las/e;-><init>(JJLjava/util/concurrent/TimeUnit;)V

    .line 574
    .line 575
    .line 576
    iput-object v5, p0, Lyt/c;->f:Las/e;

    .line 577
    .line 578
    iput-wide v6, p0, Lyt/c;->h:J

    .line 579
    .line 580
    return-void

    .line 581
    :goto_e
    :try_start_6
    monitor-exit p2
    :try_end_6
    .catchall {:try_start_6 .. :try_end_6} :catchall_3

    .line 582
    throw p0

    .line 583
    :goto_f
    :try_start_7
    monitor-exit p1
    :try_end_7
    .catchall {:try_start_7 .. :try_end_7} :catchall_1

    .line 584
    throw p0
.end method


# virtual methods
.method public final declared-synchronized a(Z)V
    .locals 2

    .line 1
    monitor-enter p0

    .line 2
    if-eqz p1, :cond_0

    .line 3
    .line 4
    :try_start_0
    iget-object v0, p0, Lyt/c;->e:Las/e;

    .line 5
    .line 6
    goto :goto_0

    .line 7
    :catchall_0
    move-exception p1

    .line 8
    goto :goto_2

    .line 9
    :cond_0
    iget-object v0, p0, Lyt/c;->f:Las/e;

    .line 10
    .line 11
    :goto_0
    iput-object v0, p0, Lyt/c;->b:Las/e;

    .line 12
    .line 13
    if-eqz p1, :cond_1

    .line 14
    .line 15
    iget-wide v0, p0, Lyt/c;->g:J

    .line 16
    .line 17
    goto :goto_1

    .line 18
    :cond_1
    iget-wide v0, p0, Lyt/c;->h:J

    .line 19
    .line 20
    :goto_1
    iput-wide v0, p0, Lyt/c;->c:J
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 21
    .line 22
    monitor-exit p0

    .line 23
    return-void

    .line 24
    :goto_2
    :try_start_1
    monitor-exit p0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 25
    throw p1
.end method

.method public final declared-synchronized b()Z
    .locals 13

    .line 1
    monitor-enter p0

    .line 2
    :try_start_0
    new-instance v0, Lzt/h;

    .line 3
    .line 4
    invoke-direct {v0}, Lzt/h;-><init>()V

    .line 5
    .line 6
    .line 7
    iget-object v1, p0, Lyt/c;->a:Lzt/h;

    .line 8
    .line 9
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 10
    .line 11
    .line 12
    iget-wide v2, v0, Lzt/h;->e:J

    .line 13
    .line 14
    iget-wide v4, v1, Lzt/h;->e:J

    .line 15
    .line 16
    sub-long/2addr v2, v4

    .line 17
    long-to-double v1, v2

    .line 18
    iget-object v3, p0, Lyt/c;->b:Las/e;

    .line 19
    .line 20
    iget-wide v4, v3, Las/e;->b:J

    .line 21
    .line 22
    iget-wide v6, v3, Las/e;->a:J

    .line 23
    .line 24
    sget-object v8, Lzt/f;->a:[I

    .line 25
    .line 26
    iget-object v3, v3, Las/e;->c:Ljava/lang/Object;

    .line 27
    .line 28
    check-cast v3, Ljava/util/concurrent/TimeUnit;

    .line 29
    .line 30
    invoke-virtual {v3}, Ljava/lang/Enum;->ordinal()I

    .line 31
    .line 32
    .line 33
    move-result v9

    .line 34
    aget v8, v8, v9

    .line 35
    .line 36
    const/4 v9, 0x1

    .line 37
    const-wide/16 v10, 0x1

    .line 38
    .line 39
    if-eq v8, v9, :cond_2

    .line 40
    .line 41
    const/4 v12, 0x2

    .line 42
    if-eq v8, v12, :cond_1

    .line 43
    .line 44
    const/4 v12, 0x3

    .line 45
    if-eq v8, v12, :cond_0

    .line 46
    .line 47
    long-to-double v6, v6

    .line 48
    invoke-virtual {v3, v4, v5}, Ljava/util/concurrent/TimeUnit;->toSeconds(J)J

    .line 49
    .line 50
    .line 51
    move-result-wide v3

    .line 52
    long-to-double v3, v3

    .line 53
    div-double/2addr v6, v3

    .line 54
    goto :goto_1

    .line 55
    :cond_0
    long-to-double v6, v6

    .line 56
    long-to-double v3, v4

    .line 57
    div-double/2addr v6, v3

    .line 58
    sget-object v3, Ljava/util/concurrent/TimeUnit;->SECONDS:Ljava/util/concurrent/TimeUnit;

    .line 59
    .line 60
    invoke-virtual {v3, v10, v11}, Ljava/util/concurrent/TimeUnit;->toMillis(J)J

    .line 61
    .line 62
    .line 63
    move-result-wide v3

    .line 64
    :goto_0
    long-to-double v3, v3

    .line 65
    mul-double/2addr v6, v3

    .line 66
    goto :goto_1

    .line 67
    :cond_1
    long-to-double v6, v6

    .line 68
    long-to-double v3, v4

    .line 69
    div-double/2addr v6, v3

    .line 70
    sget-object v3, Ljava/util/concurrent/TimeUnit;->SECONDS:Ljava/util/concurrent/TimeUnit;

    .line 71
    .line 72
    invoke-virtual {v3, v10, v11}, Ljava/util/concurrent/TimeUnit;->toMicros(J)J

    .line 73
    .line 74
    .line 75
    move-result-wide v3

    .line 76
    goto :goto_0

    .line 77
    :cond_2
    long-to-double v6, v6

    .line 78
    long-to-double v3, v4

    .line 79
    div-double/2addr v6, v3

    .line 80
    sget-object v3, Ljava/util/concurrent/TimeUnit;->SECONDS:Ljava/util/concurrent/TimeUnit;

    .line 81
    .line 82
    invoke-virtual {v3, v10, v11}, Ljava/util/concurrent/TimeUnit;->toNanos(J)J

    .line 83
    .line 84
    .line 85
    move-result-wide v3

    .line 86
    goto :goto_0

    .line 87
    :goto_1
    mul-double/2addr v1, v6

    .line 88
    sget-wide v3, Lyt/c;->i:J

    .line 89
    .line 90
    long-to-double v3, v3

    .line 91
    div-double/2addr v1, v3

    .line 92
    const-wide/16 v3, 0x0

    .line 93
    .line 94
    cmpl-double v3, v1, v3

    .line 95
    .line 96
    if-lez v3, :cond_3

    .line 97
    .line 98
    iget-wide v3, p0, Lyt/c;->d:D

    .line 99
    .line 100
    add-double/2addr v3, v1

    .line 101
    iget-wide v1, p0, Lyt/c;->c:J

    .line 102
    .line 103
    long-to-double v1, v1

    .line 104
    invoke-static {v3, v4, v1, v2}, Ljava/lang/Math;->min(DD)D

    .line 105
    .line 106
    .line 107
    move-result-wide v1

    .line 108
    iput-wide v1, p0, Lyt/c;->d:D

    .line 109
    .line 110
    iput-object v0, p0, Lyt/c;->a:Lzt/h;

    .line 111
    .line 112
    goto :goto_2

    .line 113
    :catchall_0
    move-exception v0

    .line 114
    goto :goto_3

    .line 115
    :cond_3
    :goto_2
    iget-wide v0, p0, Lyt/c;->d:D

    .line 116
    .line 117
    const-wide/high16 v2, 0x3ff0000000000000L    # 1.0

    .line 118
    .line 119
    cmpl-double v4, v0, v2

    .line 120
    .line 121
    if-ltz v4, :cond_4

    .line 122
    .line 123
    sub-double/2addr v0, v2

    .line 124
    iput-wide v0, p0, Lyt/c;->d:D
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 125
    .line 126
    monitor-exit p0

    .line 127
    return v9

    .line 128
    :cond_4
    monitor-exit p0

    .line 129
    const/4 p0, 0x0

    .line 130
    return p0

    .line 131
    :goto_3
    :try_start_1
    monitor-exit p0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 132
    throw v0
.end method
