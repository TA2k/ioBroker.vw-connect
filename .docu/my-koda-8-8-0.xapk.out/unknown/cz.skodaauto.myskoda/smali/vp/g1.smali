.class public final Lvp/g1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lvp/o1;


# static fields
.field public static volatile H:Lvp/g1;


# instance fields
.field public A:J

.field public volatile B:Ljava/lang/Boolean;

.field public volatile C:Z

.field public D:I

.field public E:I

.field public final F:Ljava/util/concurrent/atomic/AtomicInteger;

.field public final G:J

.field public final d:Landroid/content/Context;

.field public final e:Z

.field public final f:Lst/b;

.field public final g:Lvp/h;

.field public final h:Lvp/w0;

.field public final i:Lvp/p0;

.field public final j:Lvp/e1;

.field public final k:Lvp/k3;

.field public final l:Lvp/d4;

.field public final m:Lvp/k0;

.field public final n:Lto/a;

.field public final o:Lvp/u2;

.field public final p:Lvp/j2;

.field public final q:Lvp/w;

.field public final r:Lvp/n2;

.field public final s:Ljava/lang/String;

.field public t:Lvp/j0;

.field public u:Lvp/d3;

.field public v:Lvp/q;

.field public w:Lvp/h0;

.field public x:Lvp/o2;

.field public y:Z

.field public z:Ljava/lang/Boolean;


# direct methods
.method public constructor <init>(Lvp/v1;)V
    .locals 10

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    const/4 v0, 0x0

    .line 5
    iput-boolean v0, p0, Lvp/g1;->y:Z

    .line 6
    .line 7
    new-instance v1, Ljava/util/concurrent/atomic/AtomicInteger;

    .line 8
    .line 9
    invoke-direct {v1, v0}, Ljava/util/concurrent/atomic/AtomicInteger;-><init>(I)V

    .line 10
    .line 11
    .line 12
    iput-object v1, p0, Lvp/g1;->F:Ljava/util/concurrent/atomic/AtomicInteger;

    .line 13
    .line 14
    iget-object v1, p1, Lvp/v1;->a:Landroid/content/Context;

    .line 15
    .line 16
    new-instance v2, Lst/b;

    .line 17
    .line 18
    const/16 v3, 0xf

    .line 19
    .line 20
    invoke-direct {v2, v3}, Lst/b;-><init>(I)V

    .line 21
    .line 22
    .line 23
    iput-object v2, p0, Lvp/g1;->f:Lst/b;

    .line 24
    .line 25
    sput-object v2, Lvp/t1;->k:Lst/b;

    .line 26
    .line 27
    iput-object v1, p0, Lvp/g1;->d:Landroid/content/Context;

    .line 28
    .line 29
    iget-boolean v2, p1, Lvp/v1;->e:Z

    .line 30
    .line 31
    iput-boolean v2, p0, Lvp/g1;->e:Z

    .line 32
    .line 33
    iget-object v2, p1, Lvp/v1;->b:Ljava/lang/Boolean;

    .line 34
    .line 35
    iput-object v2, p0, Lvp/g1;->B:Ljava/lang/Boolean;

    .line 36
    .line 37
    iget-object v2, p1, Lvp/v1;->g:Ljava/lang/String;

    .line 38
    .line 39
    iput-object v2, p0, Lvp/g1;->s:Ljava/lang/String;

    .line 40
    .line 41
    const/4 v2, 0x1

    .line 42
    iput-boolean v2, p0, Lvp/g1;->C:Z

    .line 43
    .line 44
    sget-object v3, Lcom/google/android/gms/internal/measurement/n4;->h:Lcom/google/android/gms/internal/measurement/d4;

    .line 45
    .line 46
    if-nez v3, :cond_7

    .line 47
    .line 48
    if-nez v1, :cond_0

    .line 49
    .line 50
    goto/16 :goto_8

    .line 51
    .line 52
    :cond_0
    sget-object v3, Lcom/google/android/gms/internal/measurement/n4;->g:Ljava/lang/Object;

    .line 53
    .line 54
    monitor-enter v3

    .line 55
    :try_start_0
    sget-object v4, Lcom/google/android/gms/internal/measurement/n4;->h:Lcom/google/android/gms/internal/measurement/d4;

    .line 56
    .line 57
    if-nez v4, :cond_6

    .line 58
    .line 59
    monitor-enter v3
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_2

    .line 60
    :try_start_1
    sget-object v4, Lcom/google/android/gms/internal/measurement/n4;->h:Lcom/google/android/gms/internal/measurement/d4;

    .line 61
    .line 62
    invoke-virtual {v1}, Landroid/content/Context;->getApplicationContext()Landroid/content/Context;

    .line 63
    .line 64
    .line 65
    move-result-object v5

    .line 66
    if-eqz v5, :cond_1

    .line 67
    .line 68
    goto :goto_0

    .line 69
    :cond_1
    move-object v5, v1

    .line 70
    :goto_0
    if-eqz v4, :cond_2

    .line 71
    .line 72
    iget-object v6, v4, Lcom/google/android/gms/internal/measurement/d4;->a:Landroid/content/Context;

    .line 73
    .line 74
    if-eq v6, v5, :cond_5

    .line 75
    .line 76
    goto :goto_1

    .line 77
    :catchall_0
    move-exception p0

    .line 78
    goto :goto_5

    .line 79
    :cond_2
    :goto_1
    if-eqz v4, :cond_4

    .line 80
    .line 81
    invoke-static {}, Lcom/google/android/gms/internal/measurement/f4;->c()V

    .line 82
    .line 83
    .line 84
    invoke-static {}, Lcom/google/android/gms/internal/measurement/q4;->a()V

    .line 85
    .line 86
    .line 87
    const-class v4, Lcom/google/android/gms/internal/measurement/i4;

    .line 88
    .line 89
    monitor-enter v4
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 90
    :try_start_2
    sget-object v6, Lcom/google/android/gms/internal/measurement/i4;->h:Lcom/google/android/gms/internal/measurement/i4;

    .line 91
    .line 92
    if-eqz v6, :cond_3

    .line 93
    .line 94
    iget-object v7, v6, Lcom/google/android/gms/internal/measurement/i4;->f:Ljava/lang/Object;

    .line 95
    .line 96
    check-cast v7, Landroid/content/Context;

    .line 97
    .line 98
    if-eqz v7, :cond_3

    .line 99
    .line 100
    iget-object v8, v6, Lcom/google/android/gms/internal/measurement/i4;->g:Ljava/lang/Object;

    .line 101
    .line 102
    check-cast v8, Lcom/google/android/gms/internal/measurement/h4;

    .line 103
    .line 104
    if-eqz v8, :cond_3

    .line 105
    .line 106
    iget-boolean v6, v6, Lcom/google/android/gms/internal/measurement/i4;->e:Z

    .line 107
    .line 108
    if-eqz v6, :cond_3

    .line 109
    .line 110
    invoke-virtual {v7}, Landroid/content/Context;->getContentResolver()Landroid/content/ContentResolver;

    .line 111
    .line 112
    .line 113
    move-result-object v6

    .line 114
    sget-object v7, Lcom/google/android/gms/internal/measurement/i4;->h:Lcom/google/android/gms/internal/measurement/i4;

    .line 115
    .line 116
    iget-object v7, v7, Lcom/google/android/gms/internal/measurement/i4;->g:Ljava/lang/Object;

    .line 117
    .line 118
    check-cast v7, Lcom/google/android/gms/internal/measurement/h4;

    .line 119
    .line 120
    invoke-virtual {v6, v7}, Landroid/content/ContentResolver;->unregisterContentObserver(Landroid/database/ContentObserver;)V

    .line 121
    .line 122
    .line 123
    goto :goto_2

    .line 124
    :catchall_1
    move-exception p0

    .line 125
    goto :goto_3

    .line 126
    :cond_3
    :goto_2
    const/4 v6, 0x0

    .line 127
    sput-object v6, Lcom/google/android/gms/internal/measurement/i4;->h:Lcom/google/android/gms/internal/measurement/i4;
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_1

    .line 128
    .line 129
    :try_start_3
    monitor-exit v4
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_0

    .line 130
    goto :goto_4

    .line 131
    :goto_3
    :try_start_4
    monitor-exit v4
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_1

    .line 132
    :try_start_5
    throw p0

    .line 133
    :cond_4
    :goto_4
    new-instance v4, Lcom/google/android/gms/internal/measurement/p4;

    .line 134
    .line 135
    invoke-direct {v4, v5}, Lcom/google/android/gms/internal/measurement/p4;-><init>(Landroid/content/Context;)V

    .line 136
    .line 137
    .line 138
    invoke-static {v4}, Lkp/m9;->a(Lgr/m;)Lgr/m;

    .line 139
    .line 140
    .line 141
    move-result-object v4

    .line 142
    new-instance v6, Lcom/google/android/gms/internal/measurement/d4;

    .line 143
    .line 144
    invoke-direct {v6, v5, v4}, Lcom/google/android/gms/internal/measurement/d4;-><init>(Landroid/content/Context;Lgr/m;)V

    .line 145
    .line 146
    .line 147
    sput-object v6, Lcom/google/android/gms/internal/measurement/n4;->h:Lcom/google/android/gms/internal/measurement/d4;

    .line 148
    .line 149
    sget-object v4, Lcom/google/android/gms/internal/measurement/n4;->i:Ljava/util/concurrent/atomic/AtomicInteger;

    .line 150
    .line 151
    invoke-virtual {v4}, Ljava/util/concurrent/atomic/AtomicInteger;->incrementAndGet()I

    .line 152
    .line 153
    .line 154
    :cond_5
    monitor-exit v3

    .line 155
    goto :goto_6

    .line 156
    :goto_5
    monitor-exit v3
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_0

    .line 157
    :try_start_6
    throw p0

    .line 158
    :catchall_2
    move-exception p0

    .line 159
    goto :goto_7

    .line 160
    :cond_6
    :goto_6
    monitor-exit v3

    .line 161
    goto :goto_8

    .line 162
    :goto_7
    monitor-exit v3
    :try_end_6
    .catchall {:try_start_6 .. :try_end_6} :catchall_2

    .line 163
    throw p0

    .line 164
    :cond_7
    :goto_8
    sget-object v3, Lto/a;->a:Lto/a;

    .line 165
    .line 166
    iput-object v3, p0, Lvp/g1;->n:Lto/a;

    .line 167
    .line 168
    iget-object v3, p1, Lvp/v1;->f:Ljava/lang/Long;

    .line 169
    .line 170
    if-eqz v3, :cond_8

    .line 171
    .line 172
    invoke-virtual {v3}, Ljava/lang/Long;->longValue()J

    .line 173
    .line 174
    .line 175
    move-result-wide v3

    .line 176
    goto :goto_9

    .line 177
    :cond_8
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    .line 178
    .line 179
    .line 180
    move-result-wide v3

    .line 181
    :goto_9
    iput-wide v3, p0, Lvp/g1;->G:J

    .line 182
    .line 183
    new-instance v3, Lvp/h;

    .line 184
    .line 185
    invoke-direct {v3, p0}, Lap0/o;-><init>(Lvp/g1;)V

    .line 186
    .line 187
    .line 188
    sget-object v4, Lwe0/b;->e:Lwe0/b;

    .line 189
    .line 190
    iput-object v4, v3, Lvp/h;->h:Lvp/g;

    .line 191
    .line 192
    iput-object v3, p0, Lvp/g1;->g:Lvp/h;

    .line 193
    .line 194
    new-instance v3, Lvp/w0;

    .line 195
    .line 196
    invoke-direct {v3, p0}, Lvp/w0;-><init>(Lvp/g1;)V

    .line 197
    .line 198
    .line 199
    invoke-virtual {v3}, Lvp/n1;->d0()V

    .line 200
    .line 201
    .line 202
    iput-object v3, p0, Lvp/g1;->h:Lvp/w0;

    .line 203
    .line 204
    new-instance v3, Lvp/p0;

    .line 205
    .line 206
    invoke-direct {v3, p0}, Lvp/p0;-><init>(Lvp/g1;)V

    .line 207
    .line 208
    .line 209
    invoke-virtual {v3}, Lvp/n1;->d0()V

    .line 210
    .line 211
    .line 212
    iput-object v3, p0, Lvp/g1;->i:Lvp/p0;

    .line 213
    .line 214
    new-instance v4, Lvp/d4;

    .line 215
    .line 216
    invoke-direct {v4, p0}, Lvp/d4;-><init>(Lvp/g1;)V

    .line 217
    .line 218
    .line 219
    invoke-virtual {v4}, Lvp/n1;->d0()V

    .line 220
    .line 221
    .line 222
    iput-object v4, p0, Lvp/g1;->l:Lvp/d4;

    .line 223
    .line 224
    new-instance v4, Lt1/j0;

    .line 225
    .line 226
    invoke-direct {v4, p1, p0}, Lt1/j0;-><init>(Lvp/v1;Lvp/g1;)V

    .line 227
    .line 228
    .line 229
    new-instance v5, Lvp/k0;

    .line 230
    .line 231
    invoke-direct {v5, v4}, Lvp/k0;-><init>(Lt1/j0;)V

    .line 232
    .line 233
    .line 234
    iput-object v5, p0, Lvp/g1;->m:Lvp/k0;

    .line 235
    .line 236
    new-instance v4, Lvp/w;

    .line 237
    .line 238
    invoke-direct {v4, p0}, Lvp/w;-><init>(Lvp/g1;)V

    .line 239
    .line 240
    .line 241
    iput-object v4, p0, Lvp/g1;->q:Lvp/w;

    .line 242
    .line 243
    new-instance v4, Lvp/u2;

    .line 244
    .line 245
    invoke-direct {v4, p0}, Lvp/u2;-><init>(Lvp/g1;)V

    .line 246
    .line 247
    .line 248
    invoke-virtual {v4}, Lvp/b0;->c0()V

    .line 249
    .line 250
    .line 251
    iput-object v4, p0, Lvp/g1;->o:Lvp/u2;

    .line 252
    .line 253
    new-instance v4, Lvp/j2;

    .line 254
    .line 255
    invoke-direct {v4, p0}, Lvp/j2;-><init>(Lvp/g1;)V

    .line 256
    .line 257
    .line 258
    invoke-virtual {v4}, Lvp/b0;->c0()V

    .line 259
    .line 260
    .line 261
    iput-object v4, p0, Lvp/g1;->p:Lvp/j2;

    .line 262
    .line 263
    new-instance v5, Lvp/k3;

    .line 264
    .line 265
    invoke-direct {v5, p0}, Lvp/k3;-><init>(Lvp/g1;)V

    .line 266
    .line 267
    .line 268
    invoke-virtual {v5}, Lvp/b0;->c0()V

    .line 269
    .line 270
    .line 271
    iput-object v5, p0, Lvp/g1;->k:Lvp/k3;

    .line 272
    .line 273
    new-instance v5, Lvp/n2;

    .line 274
    .line 275
    invoke-direct {v5, p0}, Lvp/n1;-><init>(Lvp/g1;)V

    .line 276
    .line 277
    .line 278
    invoke-virtual {v5}, Lvp/n1;->d0()V

    .line 279
    .line 280
    .line 281
    iput-object v5, p0, Lvp/g1;->r:Lvp/n2;

    .line 282
    .line 283
    new-instance v5, Lvp/e1;

    .line 284
    .line 285
    invoke-direct {v5, p0}, Lvp/e1;-><init>(Lvp/g1;)V

    .line 286
    .line 287
    .line 288
    invoke-virtual {v5}, Lvp/n1;->d0()V

    .line 289
    .line 290
    .line 291
    iput-object v5, p0, Lvp/g1;->j:Lvp/e1;

    .line 292
    .line 293
    iget-object v6, p1, Lvp/v1;->d:Lcom/google/android/gms/internal/measurement/u0;

    .line 294
    .line 295
    if-eqz v6, :cond_9

    .line 296
    .line 297
    iget-wide v6, v6, Lcom/google/android/gms/internal/measurement/u0;->e:J

    .line 298
    .line 299
    const-wide/16 v8, 0x0

    .line 300
    .line 301
    cmp-long v6, v6, v8

    .line 302
    .line 303
    if-eqz v6, :cond_9

    .line 304
    .line 305
    goto :goto_a

    .line 306
    :cond_9
    move v0, v2

    .line 307
    :goto_a
    invoke-virtual {v1}, Landroid/content/Context;->getApplicationContext()Landroid/content/Context;

    .line 308
    .line 309
    .line 310
    move-result-object v1

    .line 311
    instance-of v1, v1, Landroid/app/Application;

    .line 312
    .line 313
    if-eqz v1, :cond_b

    .line 314
    .line 315
    invoke-static {v4}, Lvp/g1;->i(Lvp/b0;)V

    .line 316
    .line 317
    .line 318
    iget-object v1, v4, Lap0/o;->e:Ljava/lang/Object;

    .line 319
    .line 320
    check-cast v1, Lvp/g1;

    .line 321
    .line 322
    iget-object v1, v1, Lvp/g1;->d:Landroid/content/Context;

    .line 323
    .line 324
    invoke-virtual {v1}, Landroid/content/Context;->getApplicationContext()Landroid/content/Context;

    .line 325
    .line 326
    .line 327
    move-result-object v1

    .line 328
    instance-of v1, v1, Landroid/app/Application;

    .line 329
    .line 330
    if-eqz v1, :cond_c

    .line 331
    .line 332
    iget-object v1, v4, Lap0/o;->e:Ljava/lang/Object;

    .line 333
    .line 334
    check-cast v1, Lvp/g1;

    .line 335
    .line 336
    iget-object v1, v1, Lvp/g1;->d:Landroid/content/Context;

    .line 337
    .line 338
    invoke-virtual {v1}, Landroid/content/Context;->getApplicationContext()Landroid/content/Context;

    .line 339
    .line 340
    .line 341
    move-result-object v1

    .line 342
    check-cast v1, Landroid/app/Application;

    .line 343
    .line 344
    iget-object v2, v4, Lvp/j2;->g:Lcom/google/firebase/messaging/k;

    .line 345
    .line 346
    if-nez v2, :cond_a

    .line 347
    .line 348
    new-instance v2, Lcom/google/firebase/messaging/k;

    .line 349
    .line 350
    invoke-direct {v2, v4}, Lcom/google/firebase/messaging/k;-><init>(Lvp/j2;)V

    .line 351
    .line 352
    .line 353
    iput-object v2, v4, Lvp/j2;->g:Lcom/google/firebase/messaging/k;

    .line 354
    .line 355
    :cond_a
    if-eqz v0, :cond_c

    .line 356
    .line 357
    iget-object v0, v4, Lvp/j2;->g:Lcom/google/firebase/messaging/k;

    .line 358
    .line 359
    invoke-virtual {v1, v0}, Landroid/app/Application;->unregisterActivityLifecycleCallbacks(Landroid/app/Application$ActivityLifecycleCallbacks;)V

    .line 360
    .line 361
    .line 362
    iget-object v0, v4, Lvp/j2;->g:Lcom/google/firebase/messaging/k;

    .line 363
    .line 364
    invoke-virtual {v1, v0}, Landroid/app/Application;->registerActivityLifecycleCallbacks(Landroid/app/Application$ActivityLifecycleCallbacks;)V

    .line 365
    .line 366
    .line 367
    iget-object v0, v4, Lap0/o;->e:Ljava/lang/Object;

    .line 368
    .line 369
    check-cast v0, Lvp/g1;

    .line 370
    .line 371
    iget-object v0, v0, Lvp/g1;->i:Lvp/p0;

    .line 372
    .line 373
    invoke-static {v0}, Lvp/g1;->k(Lvp/n1;)V

    .line 374
    .line 375
    .line 376
    iget-object v0, v0, Lvp/p0;->r:Lvp/n0;

    .line 377
    .line 378
    const-string v1, "Registered activity lifecycle callback"

    .line 379
    .line 380
    invoke-virtual {v0, v1}, Lvp/n0;->a(Ljava/lang/String;)V

    .line 381
    .line 382
    .line 383
    goto :goto_b

    .line 384
    :cond_b
    invoke-static {v3}, Lvp/g1;->k(Lvp/n1;)V

    .line 385
    .line 386
    .line 387
    iget-object v0, v3, Lvp/p0;->m:Lvp/n0;

    .line 388
    .line 389
    const-string v1, "Application context is not an Application"

    .line 390
    .line 391
    invoke-virtual {v0, v1}, Lvp/n0;->a(Ljava/lang/String;)V

    .line 392
    .line 393
    .line 394
    :cond_c
    :goto_b
    new-instance v0, Llr/b;

    .line 395
    .line 396
    const/16 v1, 0x12

    .line 397
    .line 398
    const/4 v2, 0x0

    .line 399
    invoke-direct {v0, p0, p1, v2, v1}, Llr/b;-><init>(Ljava/lang/Object;Ljava/lang/Object;ZI)V

    .line 400
    .line 401
    .line 402
    invoke-virtual {v5, v0}, Lvp/e1;->j0(Ljava/lang/Runnable;)V

    .line 403
    .line 404
    .line 405
    return-void
.end method

.method public static final e(Lvp/x;)V
    .locals 1

    .line 1
    if-eqz p0, :cond_0

    .line 2
    .line 3
    return-void

    .line 4
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 5
    .line 6
    const-string v0, "Component not created"

    .line 7
    .line 8
    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    throw p0
.end method

.method public static final g(Lap0/o;)V
    .locals 1

    .line 1
    if-eqz p0, :cond_0

    .line 2
    .line 3
    return-void

    .line 4
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 5
    .line 6
    const-string v0, "Component not created"

    .line 7
    .line 8
    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    throw p0
.end method

.method public static final i(Lvp/b0;)V
    .locals 2

    .line 1
    if-eqz p0, :cond_1

    .line 2
    .line 3
    iget-boolean v0, p0, Lvp/b0;->f:Z

    .line 4
    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    return-void

    .line 8
    :cond_0
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 13
    .line 14
    invoke-static {p0}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;

    .line 15
    .line 16
    .line 17
    move-result-object p0

    .line 18
    const-string v1, "Component not initialized: "

    .line 19
    .line 20
    invoke-virtual {v1, p0}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 21
    .line 22
    .line 23
    move-result-object p0

    .line 24
    invoke-direct {v0, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 25
    .line 26
    .line 27
    throw v0

    .line 28
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 29
    .line 30
    const-string v0, "Component not created"

    .line 31
    .line 32
    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 33
    .line 34
    .line 35
    throw p0
.end method

.method public static final k(Lvp/n1;)V
    .locals 2

    .line 1
    if-eqz p0, :cond_1

    .line 2
    .line 3
    iget-boolean v0, p0, Lvp/n1;->f:Z

    .line 4
    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    return-void

    .line 8
    :cond_0
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 13
    .line 14
    invoke-static {p0}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;

    .line 15
    .line 16
    .line 17
    move-result-object p0

    .line 18
    const-string v1, "Component not initialized: "

    .line 19
    .line 20
    invoke-virtual {v1, p0}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 21
    .line 22
    .line 23
    move-result-object p0

    .line 24
    invoke-direct {v0, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 25
    .line 26
    .line 27
    throw v0

    .line 28
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 29
    .line 30
    const-string v0, "Component not created"

    .line 31
    .line 32
    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 33
    .line 34
    .line 35
    throw p0
.end method

.method public static r(Landroid/content/Context;Lcom/google/android/gms/internal/measurement/u0;Ljava/lang/Long;)Lvp/g1;
    .locals 8

    .line 1
    if-eqz p1, :cond_0

    .line 2
    .line 3
    iget-object v6, p1, Lcom/google/android/gms/internal/measurement/u0;->g:Landroid/os/Bundle;

    .line 4
    .line 5
    iget-boolean v5, p1, Lcom/google/android/gms/internal/measurement/u0;->f:Z

    .line 6
    .line 7
    iget-wide v3, p1, Lcom/google/android/gms/internal/measurement/u0;->e:J

    .line 8
    .line 9
    iget-wide v1, p1, Lcom/google/android/gms/internal/measurement/u0;->d:J

    .line 10
    .line 11
    new-instance v0, Lcom/google/android/gms/internal/measurement/u0;

    .line 12
    .line 13
    const/4 v7, 0x0

    .line 14
    invoke-direct/range {v0 .. v7}, Lcom/google/android/gms/internal/measurement/u0;-><init>(JJZLandroid/os/Bundle;Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    move-object p1, v0

    .line 18
    :cond_0
    invoke-static {p0}, Lno/c0;->h(Ljava/lang/Object;)V

    .line 19
    .line 20
    .line 21
    invoke-virtual {p0}, Landroid/content/Context;->getApplicationContext()Landroid/content/Context;

    .line 22
    .line 23
    .line 24
    move-result-object v0

    .line 25
    invoke-static {v0}, Lno/c0;->h(Ljava/lang/Object;)V

    .line 26
    .line 27
    .line 28
    sget-object v0, Lvp/g1;->H:Lvp/g1;

    .line 29
    .line 30
    if-nez v0, :cond_2

    .line 31
    .line 32
    const-class v1, Lvp/g1;

    .line 33
    .line 34
    monitor-enter v1

    .line 35
    :try_start_0
    sget-object v0, Lvp/g1;->H:Lvp/g1;

    .line 36
    .line 37
    if-nez v0, :cond_1

    .line 38
    .line 39
    new-instance v0, Lvp/v1;

    .line 40
    .line 41
    invoke-direct {v0, p0, p1, p2}, Lvp/v1;-><init>(Landroid/content/Context;Lcom/google/android/gms/internal/measurement/u0;Ljava/lang/Long;)V

    .line 42
    .line 43
    .line 44
    new-instance p0, Lvp/g1;

    .line 45
    .line 46
    invoke-direct {p0, v0}, Lvp/g1;-><init>(Lvp/v1;)V

    .line 47
    .line 48
    .line 49
    sput-object p0, Lvp/g1;->H:Lvp/g1;

    .line 50
    .line 51
    goto :goto_0

    .line 52
    :catchall_0
    move-exception v0

    .line 53
    move-object p0, v0

    .line 54
    goto :goto_1

    .line 55
    :cond_1
    :goto_0
    monitor-exit v1

    .line 56
    goto :goto_2

    .line 57
    :goto_1
    monitor-exit v1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 58
    throw p0

    .line 59
    :cond_2
    if-eqz p1, :cond_3

    .line 60
    .line 61
    iget-object p0, p1, Lcom/google/android/gms/internal/measurement/u0;->g:Landroid/os/Bundle;

    .line 62
    .line 63
    if-eqz p0, :cond_3

    .line 64
    .line 65
    const-string p1, "dataCollectionDefaultEnabled"

    .line 66
    .line 67
    invoke-virtual {p0, p1}, Landroid/os/BaseBundle;->containsKey(Ljava/lang/String;)Z

    .line 68
    .line 69
    .line 70
    move-result p1

    .line 71
    if-eqz p1, :cond_3

    .line 72
    .line 73
    sget-object p1, Lvp/g1;->H:Lvp/g1;

    .line 74
    .line 75
    invoke-static {p1}, Lno/c0;->h(Ljava/lang/Object;)V

    .line 76
    .line 77
    .line 78
    sget-object p1, Lvp/g1;->H:Lvp/g1;

    .line 79
    .line 80
    const-string p2, "dataCollectionDefaultEnabled"

    .line 81
    .line 82
    invoke-virtual {p0, p2}, Landroid/os/BaseBundle;->getBoolean(Ljava/lang/String;)Z

    .line 83
    .line 84
    .line 85
    move-result p0

    .line 86
    invoke-static {p0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 87
    .line 88
    .line 89
    move-result-object p0

    .line 90
    iput-object p0, p1, Lvp/g1;->B:Ljava/lang/Boolean;

    .line 91
    .line 92
    :cond_3
    :goto_2
    sget-object p0, Lvp/g1;->H:Lvp/g1;

    .line 93
    .line 94
    invoke-static {p0}, Lno/c0;->h(Ljava/lang/Object;)V

    .line 95
    .line 96
    .line 97
    sget-object p0, Lvp/g1;->H:Lvp/g1;

    .line 98
    .line 99
    return-object p0
.end method


# virtual methods
.method public final a()Z
    .locals 0

    .line 1
    invoke-virtual {p0}, Lvp/g1;->b()I

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    if-nez p0, :cond_0

    .line 6
    .line 7
    const/4 p0, 0x1

    .line 8
    return p0

    .line 9
    :cond_0
    const/4 p0, 0x0

    .line 10
    return p0
.end method

.method public final b()I
    .locals 5

    .line 1
    iget-object v0, p0, Lvp/g1;->j:Lvp/e1;

    .line 2
    .line 3
    invoke-static {v0}, Lvp/g1;->k(Lvp/n1;)V

    .line 4
    .line 5
    .line 6
    invoke-virtual {v0}, Lvp/e1;->a0()V

    .line 7
    .line 8
    .line 9
    iget-object v1, p0, Lvp/g1;->g:Lvp/h;

    .line 10
    .line 11
    invoke-virtual {v1}, Lvp/h;->n0()Z

    .line 12
    .line 13
    .line 14
    move-result v2

    .line 15
    const/4 v3, 0x1

    .line 16
    if-nez v2, :cond_8

    .line 17
    .line 18
    invoke-static {v0}, Lvp/g1;->k(Lvp/n1;)V

    .line 19
    .line 20
    .line 21
    invoke-virtual {v0}, Lvp/e1;->a0()V

    .line 22
    .line 23
    .line 24
    iget-boolean v0, p0, Lvp/g1;->C:Z

    .line 25
    .line 26
    if-eqz v0, :cond_7

    .line 27
    .line 28
    iget-object v0, p0, Lvp/g1;->h:Lvp/w0;

    .line 29
    .line 30
    invoke-static {v0}, Lvp/g1;->g(Lap0/o;)V

    .line 31
    .line 32
    .line 33
    invoke-virtual {v0}, Lap0/o;->a0()V

    .line 34
    .line 35
    .line 36
    invoke-virtual {v0}, Lvp/w0;->e0()Landroid/content/SharedPreferences;

    .line 37
    .line 38
    .line 39
    move-result-object v2

    .line 40
    const-string v4, "measurement_enabled"

    .line 41
    .line 42
    invoke-interface {v2, v4}, Landroid/content/SharedPreferences;->contains(Ljava/lang/String;)Z

    .line 43
    .line 44
    .line 45
    move-result v2

    .line 46
    if-eqz v2, :cond_0

    .line 47
    .line 48
    invoke-virtual {v0}, Lvp/w0;->e0()Landroid/content/SharedPreferences;

    .line 49
    .line 50
    .line 51
    move-result-object v0

    .line 52
    invoke-interface {v0, v4, v3}, Landroid/content/SharedPreferences;->getBoolean(Ljava/lang/String;Z)Z

    .line 53
    .line 54
    .line 55
    move-result v0

    .line 56
    invoke-static {v0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 57
    .line 58
    .line 59
    move-result-object v0

    .line 60
    goto :goto_0

    .line 61
    :cond_0
    const/4 v0, 0x0

    .line 62
    :goto_0
    if-eqz v0, :cond_2

    .line 63
    .line 64
    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 65
    .line 66
    .line 67
    move-result p0

    .line 68
    if-eqz p0, :cond_1

    .line 69
    .line 70
    goto :goto_1

    .line 71
    :cond_1
    const/4 p0, 0x3

    .line 72
    return p0

    .line 73
    :cond_2
    iget-object v0, v1, Lap0/o;->e:Ljava/lang/Object;

    .line 74
    .line 75
    check-cast v0, Lvp/g1;

    .line 76
    .line 77
    iget-object v0, v0, Lvp/g1;->f:Lst/b;

    .line 78
    .line 79
    const-string v0, "firebase_analytics_collection_enabled"

    .line 80
    .line 81
    invoke-virtual {v1, v0}, Lvp/h;->m0(Ljava/lang/String;)Ljava/lang/Boolean;

    .line 82
    .line 83
    .line 84
    move-result-object v0

    .line 85
    if-eqz v0, :cond_4

    .line 86
    .line 87
    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 88
    .line 89
    .line 90
    move-result p0

    .line 91
    if-eqz p0, :cond_3

    .line 92
    .line 93
    goto :goto_1

    .line 94
    :cond_3
    const/4 p0, 0x4

    .line 95
    return p0

    .line 96
    :cond_4
    iget-object v0, p0, Lvp/g1;->B:Ljava/lang/Boolean;

    .line 97
    .line 98
    if-eqz v0, :cond_6

    .line 99
    .line 100
    iget-object p0, p0, Lvp/g1;->B:Ljava/lang/Boolean;

    .line 101
    .line 102
    invoke-virtual {p0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 103
    .line 104
    .line 105
    move-result p0

    .line 106
    if-eqz p0, :cond_5

    .line 107
    .line 108
    goto :goto_1

    .line 109
    :cond_5
    const/4 p0, 0x7

    .line 110
    return p0

    .line 111
    :cond_6
    :goto_1
    const/4 p0, 0x0

    .line 112
    return p0

    .line 113
    :cond_7
    const/16 p0, 0x8

    .line 114
    .line 115
    return p0

    .line 116
    :cond_8
    return v3
.end method

.method public final c()Z
    .locals 6

    .line 1
    iget-boolean v0, p0, Lvp/g1;->y:Z

    .line 2
    .line 3
    if-eqz v0, :cond_4

    .line 4
    .line 5
    iget-object v0, p0, Lvp/g1;->j:Lvp/e1;

    .line 6
    .line 7
    invoke-static {v0}, Lvp/g1;->k(Lvp/n1;)V

    .line 8
    .line 9
    .line 10
    invoke-virtual {v0}, Lvp/e1;->a0()V

    .line 11
    .line 12
    .line 13
    iget-object v0, p0, Lvp/g1;->z:Ljava/lang/Boolean;

    .line 14
    .line 15
    iget-object v1, p0, Lvp/g1;->n:Lto/a;

    .line 16
    .line 17
    if-eqz v0, :cond_0

    .line 18
    .line 19
    iget-wide v2, p0, Lvp/g1;->A:J

    .line 20
    .line 21
    const-wide/16 v4, 0x0

    .line 22
    .line 23
    cmp-long v2, v2, v4

    .line 24
    .line 25
    if-eqz v2, :cond_0

    .line 26
    .line 27
    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 28
    .line 29
    .line 30
    move-result v0

    .line 31
    if-nez v0, :cond_3

    .line 32
    .line 33
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 34
    .line 35
    .line 36
    invoke-static {}, Landroid/os/SystemClock;->elapsedRealtime()J

    .line 37
    .line 38
    .line 39
    move-result-wide v2

    .line 40
    iget-wide v4, p0, Lvp/g1;->A:J

    .line 41
    .line 42
    sub-long/2addr v2, v4

    .line 43
    invoke-static {v2, v3}, Ljava/lang/Math;->abs(J)J

    .line 44
    .line 45
    .line 46
    move-result-wide v2

    .line 47
    const-wide/16 v4, 0x3e8

    .line 48
    .line 49
    cmp-long v0, v2, v4

    .line 50
    .line 51
    if-lez v0, :cond_3

    .line 52
    .line 53
    :cond_0
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 54
    .line 55
    .line 56
    invoke-static {}, Landroid/os/SystemClock;->elapsedRealtime()J

    .line 57
    .line 58
    .line 59
    move-result-wide v0

    .line 60
    iput-wide v0, p0, Lvp/g1;->A:J

    .line 61
    .line 62
    iget-object v0, p0, Lvp/g1;->l:Lvp/d4;

    .line 63
    .line 64
    invoke-static {v0}, Lvp/g1;->g(Lap0/o;)V

    .line 65
    .line 66
    .line 67
    const-string v1, "android.permission.INTERNET"

    .line 68
    .line 69
    invoke-virtual {v0, v1}, Lvp/d4;->x0(Ljava/lang/String;)Z

    .line 70
    .line 71
    .line 72
    move-result v1

    .line 73
    const/4 v2, 0x0

    .line 74
    if-eqz v1, :cond_2

    .line 75
    .line 76
    const-string v1, "android.permission.ACCESS_NETWORK_STATE"

    .line 77
    .line 78
    invoke-virtual {v0, v1}, Lvp/d4;->x0(Ljava/lang/String;)Z

    .line 79
    .line 80
    .line 81
    move-result v1

    .line 82
    if-eqz v1, :cond_2

    .line 83
    .line 84
    iget-object v1, p0, Lvp/g1;->d:Landroid/content/Context;

    .line 85
    .line 86
    invoke-static {v1}, Lvo/b;->a(Landroid/content/Context;)Lcq/r1;

    .line 87
    .line 88
    .line 89
    move-result-object v3

    .line 90
    invoke-virtual {v3}, Lcq/r1;->d()Z

    .line 91
    .line 92
    .line 93
    move-result v3

    .line 94
    const/4 v4, 0x1

    .line 95
    if-nez v3, :cond_1

    .line 96
    .line 97
    iget-object v3, p0, Lvp/g1;->g:Lvp/h;

    .line 98
    .line 99
    invoke-virtual {v3}, Lvp/h;->d0()Z

    .line 100
    .line 101
    .line 102
    move-result v3

    .line 103
    if-nez v3, :cond_1

    .line 104
    .line 105
    invoke-static {v1}, Lvp/d4;->Q0(Landroid/content/Context;)Z

    .line 106
    .line 107
    .line 108
    move-result v3

    .line 109
    if-eqz v3, :cond_2

    .line 110
    .line 111
    invoke-static {v1}, Lvp/d4;->t0(Landroid/content/Context;)Z

    .line 112
    .line 113
    .line 114
    move-result v1

    .line 115
    if-eqz v1, :cond_2

    .line 116
    .line 117
    :cond_1
    move v2, v4

    .line 118
    :cond_2
    invoke-static {v2}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 119
    .line 120
    .line 121
    move-result-object v1

    .line 122
    iput-object v1, p0, Lvp/g1;->z:Ljava/lang/Boolean;

    .line 123
    .line 124
    if-eqz v2, :cond_3

    .line 125
    .line 126
    invoke-virtual {p0}, Lvp/g1;->q()Lvp/h0;

    .line 127
    .line 128
    .line 129
    move-result-object v1

    .line 130
    invoke-virtual {v1}, Lvp/h0;->h0()Ljava/lang/String;

    .line 131
    .line 132
    .line 133
    move-result-object v1

    .line 134
    invoke-virtual {v0, v1}, Lvp/d4;->e0(Ljava/lang/String;)Z

    .line 135
    .line 136
    .line 137
    move-result v0

    .line 138
    invoke-static {v0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 139
    .line 140
    .line 141
    move-result-object v0

    .line 142
    iput-object v0, p0, Lvp/g1;->z:Ljava/lang/Boolean;

    .line 143
    .line 144
    :cond_3
    iget-object p0, p0, Lvp/g1;->z:Ljava/lang/Boolean;

    .line 145
    .line 146
    invoke-virtual {p0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 147
    .line 148
    .line 149
    move-result p0

    .line 150
    return p0

    .line 151
    :cond_4
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 152
    .line 153
    const-string v0, "AppMeasurement is not initialized"

    .line 154
    .line 155
    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 156
    .line 157
    .line 158
    throw p0
.end method

.method public final d()Lvp/p0;
    .locals 0

    .line 1
    iget-object p0, p0, Lvp/g1;->i:Lvp/p0;

    .line 2
    .line 3
    invoke-static {p0}, Lvp/g1;->k(Lvp/n1;)V

    .line 4
    .line 5
    .line 6
    return-object p0
.end method

.method public final f()Lvp/e1;
    .locals 0

    .line 1
    iget-object p0, p0, Lvp/g1;->j:Lvp/e1;

    .line 2
    .line 3
    invoke-static {p0}, Lvp/g1;->k(Lvp/n1;)V

    .line 4
    .line 5
    .line 6
    return-object p0
.end method

.method public final h()Lst/b;
    .locals 0

    .line 1
    iget-object p0, p0, Lvp/g1;->f:Lst/b;

    .line 2
    .line 3
    return-object p0
.end method

.method public final j()Landroid/content/Context;
    .locals 0

    .line 1
    iget-object p0, p0, Lvp/g1;->d:Landroid/content/Context;

    .line 2
    .line 3
    return-object p0
.end method

.method public final l()Lto/a;
    .locals 0

    .line 1
    iget-object p0, p0, Lvp/g1;->n:Lto/a;

    .line 2
    .line 3
    return-object p0
.end method

.method public final m()Lvp/k0;
    .locals 0

    .line 1
    iget-object p0, p0, Lvp/g1;->m:Lvp/k0;

    .line 2
    .line 3
    return-object p0
.end method

.method public final n()Lvp/j0;
    .locals 1

    .line 1
    iget-object v0, p0, Lvp/g1;->t:Lvp/j0;

    .line 2
    .line 3
    invoke-static {v0}, Lvp/g1;->i(Lvp/b0;)V

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lvp/g1;->t:Lvp/j0;

    .line 7
    .line 8
    return-object p0
.end method

.method public final o()Lvp/d3;
    .locals 1

    .line 1
    iget-object v0, p0, Lvp/g1;->u:Lvp/d3;

    .line 2
    .line 3
    invoke-static {v0}, Lvp/g1;->i(Lvp/b0;)V

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lvp/g1;->u:Lvp/d3;

    .line 7
    .line 8
    return-object p0
.end method

.method public final p()Lvp/q;
    .locals 1

    .line 1
    iget-object v0, p0, Lvp/g1;->v:Lvp/q;

    .line 2
    .line 3
    invoke-static {v0}, Lvp/g1;->k(Lvp/n1;)V

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lvp/g1;->v:Lvp/q;

    .line 7
    .line 8
    return-object p0
.end method

.method public final q()Lvp/h0;
    .locals 1

    .line 1
    iget-object v0, p0, Lvp/g1;->w:Lvp/h0;

    .line 2
    .line 3
    invoke-static {v0}, Lvp/g1;->i(Lvp/b0;)V

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lvp/g1;->w:Lvp/h0;

    .line 7
    .line 8
    return-object p0
.end method
