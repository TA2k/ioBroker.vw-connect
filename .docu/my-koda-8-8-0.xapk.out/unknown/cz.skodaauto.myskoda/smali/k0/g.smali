.class public final Lk0/g;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/lang/Runnable;


# instance fields
.field public final synthetic d:I

.field public final e:Ljava/lang/Object;

.field public final f:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(ILjava/lang/Object;Ljava/lang/Object;)V
    .locals 0

    .line 1
    iput p1, p0, Lk0/g;->d:I

    iput-object p2, p0, Lk0/g;->e:Ljava/lang/Object;

    iput-object p3, p0, Lk0/g;->f:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public constructor <init>(Lcom/google/android/material/behavior/SwipeDismissBehavior;Landroid/view/View;Z)V
    .locals 0

    const/4 p3, 0x7

    iput p3, p0, Lk0/g;->d:I

    .line 4
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lk0/g;->f:Ljava/lang/Object;

    .line 5
    iput-object p2, p0, Lk0/g;->e:Ljava/lang/Object;

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/Object;Ljava/lang/Object;ZI)V
    .locals 0

    .line 2
    iput p4, p0, Lk0/g;->d:I

    iput-object p1, p0, Lk0/g;->f:Ljava/lang/Object;

    iput-object p2, p0, Lk0/g;->e:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Ljp/vg;Lj1/a;)V
    .locals 1

    const/16 v0, 0x9

    iput v0, p0, Lk0/g;->d:I

    sget-object v0, Ljp/bc;->e:Ljp/bc;

    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lk0/g;->e:Ljava/lang/Object;

    iput-object p2, p0, Lk0/g;->f:Ljava/lang/Object;

    return-void
.end method

.method private final a()V
    .locals 2

    .line 1
    :try_start_0
    iget-object v0, p0, Lk0/g;->f:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Ljava/lang/Runnable;

    .line 4
    .line 5
    invoke-interface {v0}, Ljava/lang/Runnable;->run()V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_1

    .line 6
    .line 7
    .line 8
    iget-object v0, p0, Lk0/g;->e:Ljava/lang/Object;

    .line 9
    .line 10
    check-cast v0, Lla/a0;

    .line 11
    .line 12
    iget-object v0, v0, Lla/a0;->h:Ljava/lang/Object;

    .line 13
    .line 14
    monitor-enter v0

    .line 15
    :try_start_1
    iget-object p0, p0, Lk0/g;->e:Ljava/lang/Object;

    .line 16
    .line 17
    check-cast p0, Lla/a0;

    .line 18
    .line 19
    invoke-virtual {p0}, Lla/a0;->a()V

    .line 20
    .line 21
    .line 22
    monitor-exit v0

    .line 23
    return-void

    .line 24
    :catchall_0
    move-exception p0

    .line 25
    monitor-exit v0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 26
    throw p0

    .line 27
    :catchall_1
    move-exception v0

    .line 28
    iget-object v1, p0, Lk0/g;->e:Ljava/lang/Object;

    .line 29
    .line 30
    check-cast v1, Lla/a0;

    .line 31
    .line 32
    iget-object v1, v1, Lla/a0;->h:Ljava/lang/Object;

    .line 33
    .line 34
    monitor-enter v1

    .line 35
    :try_start_2
    iget-object p0, p0, Lk0/g;->e:Ljava/lang/Object;

    .line 36
    .line 37
    check-cast p0, Lla/a0;

    .line 38
    .line 39
    invoke-virtual {p0}, Lla/a0;->a()V

    .line 40
    .line 41
    .line 42
    monitor-exit v1
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_2

    .line 43
    throw v0

    .line 44
    :catchall_2
    move-exception p0

    .line 45
    :try_start_3
    monitor-exit v1
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_2

    .line 46
    throw p0
.end method


# virtual methods
.method public final run()V
    .locals 26

    .line 1
    move-object/from16 v1, p0

    .line 2
    .line 3
    iget v0, v1, Lk0/g;->d:I

    .line 4
    .line 5
    const/4 v2, 0x4

    .line 6
    const/4 v3, 0x2

    .line 7
    const-wide/16 v4, 0x0

    .line 8
    .line 9
    const/4 v6, 0x3

    .line 10
    const/4 v7, 0x0

    .line 11
    const/4 v8, 0x0

    .line 12
    const/4 v9, 0x1

    .line 13
    packed-switch v0, :pswitch_data_0

    .line 14
    .line 15
    .line 16
    iget-object v0, v1, Lk0/g;->e:Ljava/lang/Object;

    .line 17
    .line 18
    check-cast v0, Lp0/d;

    .line 19
    .line 20
    iget-object v1, v1, Lk0/g;->f:Ljava/lang/Object;

    .line 21
    .line 22
    invoke-virtual {v0, v1}, Lp0/d;->accept(Ljava/lang/Object;)V

    .line 23
    .line 24
    .line 25
    return-void

    .line 26
    :pswitch_0
    iget-object v0, v1, Lk0/g;->e:Ljava/lang/Object;

    .line 27
    .line 28
    check-cast v0, Lpv/g;

    .line 29
    .line 30
    iget-object v1, v1, Lk0/g;->f:Ljava/lang/Object;

    .line 31
    .line 32
    check-cast v1, Landroid/app/job/JobParameters;

    .line 33
    .line 34
    const-string v2, "FA"

    .line 35
    .line 36
    const-string v3, "[sgtm] AppMeasurementJobService processed last Scion upload request."

    .line 37
    .line 38
    invoke-static {v2, v3}, Landroid/util/Log;->v(Ljava/lang/String;Ljava/lang/String;)I

    .line 39
    .line 40
    .line 41
    iget-object v0, v0, Lpv/g;->e:Ljava/lang/Object;

    .line 42
    .line 43
    check-cast v0, Landroid/app/Service;

    .line 44
    .line 45
    check-cast v0, Lvp/g3;

    .line 46
    .line 47
    invoke-interface {v0, v1}, Lvp/g3;->c(Landroid/app/job/JobParameters;)V

    .line 48
    .line 49
    .line 50
    return-void

    .line 51
    :pswitch_1
    iget-object v0, v1, Lk0/g;->f:Ljava/lang/Object;

    .line 52
    .line 53
    check-cast v0, Lvp/c3;

    .line 54
    .line 55
    iget-object v0, v0, Lvp/c3;->c:Lvp/d3;

    .line 56
    .line 57
    iput-object v7, v0, Lvp/d3;->h:Lvp/c0;

    .line 58
    .line 59
    iget-object v2, v1, Lk0/g;->e:Ljava/lang/Object;

    .line 60
    .line 61
    check-cast v2, Ljo/b;

    .line 62
    .line 63
    iget v2, v2, Ljo/b;->e:I

    .line 64
    .line 65
    const/16 v3, 0x1e61

    .line 66
    .line 67
    if-ne v2, v3, :cond_1

    .line 68
    .line 69
    iget-object v2, v0, Lvp/d3;->k:Ljava/util/concurrent/ScheduledExecutorService;

    .line 70
    .line 71
    if-nez v2, :cond_0

    .line 72
    .line 73
    invoke-static {v9}, Ljava/util/concurrent/Executors;->newScheduledThreadPool(I)Ljava/util/concurrent/ScheduledExecutorService;

    .line 74
    .line 75
    .line 76
    move-result-object v2

    .line 77
    iput-object v2, v0, Lvp/d3;->k:Ljava/util/concurrent/ScheduledExecutorService;

    .line 78
    .line 79
    :cond_0
    iget-object v0, v0, Lvp/d3;->k:Ljava/util/concurrent/ScheduledExecutorService;

    .line 80
    .line 81
    new-instance v2, Laq/p;

    .line 82
    .line 83
    const/16 v3, 0x1b

    .line 84
    .line 85
    invoke-direct {v2, v1, v3}, Laq/p;-><init>(Ljava/lang/Object;I)V

    .line 86
    .line 87
    .line 88
    sget-object v1, Lvp/z;->Z:Lvp/y;

    .line 89
    .line 90
    invoke-virtual {v1, v7}, Lvp/y;->a(Ljava/lang/Object;)Ljava/lang/Object;

    .line 91
    .line 92
    .line 93
    move-result-object v1

    .line 94
    check-cast v1, Ljava/lang/Long;

    .line 95
    .line 96
    invoke-virtual {v1}, Ljava/lang/Long;->longValue()J

    .line 97
    .line 98
    .line 99
    move-result-wide v3

    .line 100
    sget-object v1, Ljava/util/concurrent/TimeUnit;->MILLISECONDS:Ljava/util/concurrent/TimeUnit;

    .line 101
    .line 102
    invoke-interface {v0, v2, v3, v4, v1}, Ljava/util/concurrent/ScheduledExecutorService;->schedule(Ljava/lang/Runnable;JLjava/util/concurrent/TimeUnit;)Ljava/util/concurrent/ScheduledFuture;

    .line 103
    .line 104
    .line 105
    goto :goto_0

    .line 106
    :cond_1
    invoke-virtual {v0}, Lvp/d3;->p0()V

    .line 107
    .line 108
    .line 109
    :goto_0
    return-void

    .line 110
    :pswitch_2
    iget-object v0, v1, Lk0/g;->f:Ljava/lang/Object;

    .line 111
    .line 112
    move-object v2, v0

    .line 113
    check-cast v2, Lvp/c3;

    .line 114
    .line 115
    monitor-enter v2

    .line 116
    :try_start_0
    iput-boolean v8, v2, Lvp/c3;->a:Z

    .line 117
    .line 118
    iget-object v0, v2, Lvp/c3;->c:Lvp/d3;

    .line 119
    .line 120
    invoke-virtual {v0}, Lvp/d3;->r0()Z

    .line 121
    .line 122
    .line 123
    move-result v3

    .line 124
    if-nez v3, :cond_2

    .line 125
    .line 126
    iget-object v3, v0, Lap0/o;->e:Ljava/lang/Object;

    .line 127
    .line 128
    check-cast v3, Lvp/g1;

    .line 129
    .line 130
    iget-object v3, v3, Lvp/g1;->i:Lvp/p0;

    .line 131
    .line 132
    invoke-static {v3}, Lvp/g1;->k(Lvp/n1;)V

    .line 133
    .line 134
    .line 135
    iget-object v3, v3, Lvp/p0;->r:Lvp/n0;

    .line 136
    .line 137
    const-string v4, "Connected to service"

    .line 138
    .line 139
    invoke-virtual {v3, v4}, Lvp/n0;->a(Ljava/lang/String;)V

    .line 140
    .line 141
    .line 142
    iget-object v1, v1, Lk0/g;->e:Ljava/lang/Object;

    .line 143
    .line 144
    check-cast v1, Lvp/c0;

    .line 145
    .line 146
    invoke-virtual {v0}, Lvp/x;->a0()V

    .line 147
    .line 148
    .line 149
    iput-object v1, v0, Lvp/d3;->h:Lvp/c0;

    .line 150
    .line 151
    invoke-virtual {v0}, Lvp/d3;->n0()V

    .line 152
    .line 153
    .line 154
    invoke-virtual {v0}, Lvp/d3;->p0()V

    .line 155
    .line 156
    .line 157
    goto :goto_1

    .line 158
    :catchall_0
    move-exception v0

    .line 159
    goto :goto_2

    .line 160
    :cond_2
    :goto_1
    monitor-exit v2

    .line 161
    return-void

    .line 162
    :goto_2
    monitor-exit v2
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 163
    throw v0

    .line 164
    :pswitch_3
    iget-object v0, v1, Lk0/g;->e:Ljava/lang/Object;

    .line 165
    .line 166
    check-cast v0, Lvp/j2;

    .line 167
    .line 168
    iget-object v0, v0, Lap0/o;->e:Ljava/lang/Object;

    .line 169
    .line 170
    check-cast v0, Lvp/g1;

    .line 171
    .line 172
    invoke-virtual {v0}, Lvp/g1;->q()Lvp/h0;

    .line 173
    .line 174
    .line 175
    move-result-object v2

    .line 176
    iget-object v1, v1, Lk0/g;->f:Ljava/lang/Object;

    .line 177
    .line 178
    check-cast v1, Ljava/lang/String;

    .line 179
    .line 180
    iget-object v3, v2, Lvp/h0;->u:Ljava/lang/String;

    .line 181
    .line 182
    if-eqz v3, :cond_3

    .line 183
    .line 184
    invoke-virtual {v3, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 185
    .line 186
    .line 187
    move-result v3

    .line 188
    if-nez v3, :cond_3

    .line 189
    .line 190
    move v8, v9

    .line 191
    :cond_3
    iput-object v1, v2, Lvp/h0;->u:Ljava/lang/String;

    .line 192
    .line 193
    if-eqz v8, :cond_4

    .line 194
    .line 195
    invoke-virtual {v0}, Lvp/g1;->q()Lvp/h0;

    .line 196
    .line 197
    .line 198
    move-result-object v0

    .line 199
    invoke-virtual {v0}, Lvp/h0;->f0()V

    .line 200
    .line 201
    .line 202
    :cond_4
    return-void

    .line 203
    :pswitch_4
    iget-object v0, v1, Lk0/g;->e:Ljava/lang/Object;

    .line 204
    .line 205
    check-cast v0, Lvp/j2;

    .line 206
    .line 207
    invoke-virtual {v0}, Lvp/x;->a0()V

    .line 208
    .line 209
    .line 210
    sget v2, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 211
    .line 212
    const/16 v3, 0x1e

    .line 213
    .line 214
    if-ge v2, v3, :cond_5

    .line 215
    .line 216
    goto :goto_4

    .line 217
    :cond_5
    iget-object v1, v1, Lk0/g;->f:Ljava/lang/Object;

    .line 218
    .line 219
    check-cast v1, Ljava/util/List;

    .line 220
    .line 221
    iget-object v2, v0, Lap0/o;->e:Ljava/lang/Object;

    .line 222
    .line 223
    check-cast v2, Lvp/g1;

    .line 224
    .line 225
    iget-object v2, v2, Lvp/g1;->h:Lvp/w0;

    .line 226
    .line 227
    invoke-static {v2}, Lvp/g1;->g(Lap0/o;)V

    .line 228
    .line 229
    .line 230
    invoke-virtual {v2}, Lvp/w0;->g0()Landroid/util/SparseArray;

    .line 231
    .line 232
    .line 233
    move-result-object v2

    .line 234
    invoke-interface {v1}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 235
    .line 236
    .line 237
    move-result-object v1

    .line 238
    :cond_6
    :goto_3
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 239
    .line 240
    .line 241
    move-result v3

    .line 242
    if-eqz v3, :cond_8

    .line 243
    .line 244
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 245
    .line 246
    .line 247
    move-result-object v3

    .line 248
    check-cast v3, Lvp/o3;

    .line 249
    .line 250
    iget v4, v3, Lvp/o3;->f:I

    .line 251
    .line 252
    invoke-static {v2, v4}, Ln01/a;->n(Landroid/util/SparseArray;I)Z

    .line 253
    .line 254
    .line 255
    move-result v5

    .line 256
    if-eqz v5, :cond_7

    .line 257
    .line 258
    invoke-virtual {v2, v4}, Landroid/util/SparseArray;->get(I)Ljava/lang/Object;

    .line 259
    .line 260
    .line 261
    move-result-object v4

    .line 262
    check-cast v4, Ljava/lang/Long;

    .line 263
    .line 264
    invoke-virtual {v4}, Ljava/lang/Long;->longValue()J

    .line 265
    .line 266
    .line 267
    move-result-wide v4

    .line 268
    iget-wide v6, v3, Lvp/o3;->e:J

    .line 269
    .line 270
    cmp-long v4, v4, v6

    .line 271
    .line 272
    if-gez v4, :cond_6

    .line 273
    .line 274
    :cond_7
    invoke-virtual {v0}, Lvp/j2;->y0()Ljava/util/PriorityQueue;

    .line 275
    .line 276
    .line 277
    move-result-object v4

    .line 278
    invoke-virtual {v4, v3}, Ljava/util/PriorityQueue;->add(Ljava/lang/Object;)Z

    .line 279
    .line 280
    .line 281
    goto :goto_3

    .line 282
    :cond_8
    invoke-virtual {v0}, Lvp/j2;->z0()V

    .line 283
    .line 284
    .line 285
    :goto_4
    return-void

    .line 286
    :pswitch_5
    iget-object v0, v1, Lk0/g;->f:Ljava/lang/Object;

    .line 287
    .line 288
    check-cast v0, Lcom/google/android/gms/measurement/internal/AppMeasurementDynamiteService;

    .line 289
    .line 290
    iget-object v0, v0, Lcom/google/android/gms/measurement/internal/AppMeasurementDynamiteService;->c:Lvp/g1;

    .line 291
    .line 292
    iget-object v0, v0, Lvp/g1;->p:Lvp/j2;

    .line 293
    .line 294
    invoke-static {v0}, Lvp/g1;->i(Lvp/b0;)V

    .line 295
    .line 296
    .line 297
    iget-object v1, v1, Lk0/g;->e:Ljava/lang/Object;

    .line 298
    .line 299
    check-cast v1, Lc2/k;

    .line 300
    .line 301
    invoke-virtual {v0}, Lvp/x;->a0()V

    .line 302
    .line 303
    .line 304
    invoke-virtual {v0}, Lvp/b0;->b0()V

    .line 305
    .line 306
    .line 307
    iget-object v2, v0, Lvp/j2;->h:Lc2/k;

    .line 308
    .line 309
    if-eq v1, v2, :cond_a

    .line 310
    .line 311
    if-nez v2, :cond_9

    .line 312
    .line 313
    move v8, v9

    .line 314
    :cond_9
    const-string v2, "EventInterceptor already set."

    .line 315
    .line 316
    invoke-static {v2, v8}, Lno/c0;->j(Ljava/lang/String;Z)V

    .line 317
    .line 318
    .line 319
    :cond_a
    iput-object v1, v0, Lvp/j2;->h:Lc2/k;

    .line 320
    .line 321
    return-void

    .line 322
    :pswitch_6
    iget-object v0, v1, Lk0/g;->f:Ljava/lang/Object;

    .line 323
    .line 324
    check-cast v0, Lvp/j2;

    .line 325
    .line 326
    iget-object v1, v1, Lk0/g;->e:Ljava/lang/Object;

    .line 327
    .line 328
    check-cast v1, Ljava/lang/Boolean;

    .line 329
    .line 330
    invoke-virtual {v0, v1, v9}, Lvp/j2;->r0(Ljava/lang/Boolean;Z)V

    .line 331
    .line 332
    .line 333
    return-void

    .line 334
    :pswitch_7
    const-string v0, "creation_timestamp"

    .line 335
    .line 336
    const-string v2, "app_id"

    .line 337
    .line 338
    iget-object v3, v1, Lk0/g;->f:Ljava/lang/Object;

    .line 339
    .line 340
    check-cast v3, Lvp/j2;

    .line 341
    .line 342
    invoke-virtual {v3}, Lvp/x;->a0()V

    .line 343
    .line 344
    .line 345
    invoke-virtual {v3}, Lvp/b0;->b0()V

    .line 346
    .line 347
    .line 348
    iget-object v1, v1, Lk0/g;->e:Ljava/lang/Object;

    .line 349
    .line 350
    check-cast v1, Landroid/os/Bundle;

    .line 351
    .line 352
    const-string v4, "name"

    .line 353
    .line 354
    invoke-virtual {v1, v4}, Landroid/os/BaseBundle;->getString(Ljava/lang/String;)Ljava/lang/String;

    .line 355
    .line 356
    .line 357
    move-result-object v9

    .line 358
    invoke-static {v9}, Lno/c0;->e(Ljava/lang/String;)V

    .line 359
    .line 360
    .line 361
    iget-object v3, v3, Lap0/o;->e:Ljava/lang/Object;

    .line 362
    .line 363
    check-cast v3, Lvp/g1;

    .line 364
    .line 365
    invoke-virtual {v3}, Lvp/g1;->a()Z

    .line 366
    .line 367
    .line 368
    move-result v4

    .line 369
    if-nez v4, :cond_b

    .line 370
    .line 371
    iget-object v0, v3, Lvp/g1;->i:Lvp/p0;

    .line 372
    .line 373
    invoke-static {v0}, Lvp/g1;->k(Lvp/n1;)V

    .line 374
    .line 375
    .line 376
    iget-object v0, v0, Lvp/p0;->r:Lvp/n0;

    .line 377
    .line 378
    const-string v1, "Conditional property not cleared since app measurement is disabled"

    .line 379
    .line 380
    invoke-virtual {v0, v1}, Lvp/n0;->a(Ljava/lang/String;)V

    .line 381
    .line 382
    .line 383
    goto :goto_5

    .line 384
    :cond_b
    const-string v10, ""

    .line 385
    .line 386
    new-instance v5, Lvp/b4;

    .line 387
    .line 388
    const-wide/16 v6, 0x0

    .line 389
    .line 390
    const/4 v8, 0x0

    .line 391
    invoke-direct/range {v5 .. v10}, Lvp/b4;-><init>(JLjava/lang/Object;Ljava/lang/String;Ljava/lang/String;)V

    .line 392
    .line 393
    .line 394
    :try_start_1
    iget-object v6, v3, Lvp/g1;->l:Lvp/d4;

    .line 395
    .line 396
    invoke-static {v6}, Lvp/g1;->g(Lap0/o;)V

    .line 397
    .line 398
    .line 399
    invoke-virtual {v1, v2}, Landroid/os/BaseBundle;->getString(Ljava/lang/String;)Ljava/lang/String;

    .line 400
    .line 401
    .line 402
    const-string v4, "expired_event_name"

    .line 403
    .line 404
    invoke-virtual {v1, v4}, Landroid/os/BaseBundle;->getString(Ljava/lang/String;)Ljava/lang/String;

    .line 405
    .line 406
    .line 407
    move-result-object v7

    .line 408
    const-string v4, "expired_event_params"

    .line 409
    .line 410
    invoke-virtual {v1, v4}, Landroid/os/Bundle;->getBundle(Ljava/lang/String;)Landroid/os/Bundle;

    .line 411
    .line 412
    .line 413
    move-result-object v8

    .line 414
    const-string v9, ""

    .line 415
    .line 416
    invoke-virtual {v1, v0}, Landroid/os/BaseBundle;->getLong(Ljava/lang/String;)J

    .line 417
    .line 418
    .line 419
    move-result-wide v10

    .line 420
    const/4 v12, 0x1

    .line 421
    invoke-virtual/range {v6 .. v12}, Lvp/d4;->C0(Ljava/lang/String;Landroid/os/Bundle;Ljava/lang/String;JZ)Lvp/t;

    .line 422
    .line 423
    .line 424
    move-result-object v25
    :try_end_1
    .catch Ljava/lang/IllegalArgumentException; {:try_start_1 .. :try_end_1} :catch_0

    .line 425
    new-instance v11, Lvp/f;

    .line 426
    .line 427
    invoke-virtual {v1, v2}, Landroid/os/BaseBundle;->getString(Ljava/lang/String;)Ljava/lang/String;

    .line 428
    .line 429
    .line 430
    move-result-object v12

    .line 431
    invoke-virtual {v1, v0}, Landroid/os/BaseBundle;->getLong(Ljava/lang/String;)J

    .line 432
    .line 433
    .line 434
    move-result-wide v15

    .line 435
    const-string v0, "active"

    .line 436
    .line 437
    invoke-virtual {v1, v0}, Landroid/os/BaseBundle;->getBoolean(Ljava/lang/String;)Z

    .line 438
    .line 439
    .line 440
    move-result v17

    .line 441
    const-string v0, "trigger_event_name"

    .line 442
    .line 443
    invoke-virtual {v1, v0}, Landroid/os/BaseBundle;->getString(Ljava/lang/String;)Ljava/lang/String;

    .line 444
    .line 445
    .line 446
    move-result-object v18

    .line 447
    const-string v0, "trigger_timeout"

    .line 448
    .line 449
    invoke-virtual {v1, v0}, Landroid/os/BaseBundle;->getLong(Ljava/lang/String;)J

    .line 450
    .line 451
    .line 452
    move-result-wide v20

    .line 453
    const-string v0, "time_to_live"

    .line 454
    .line 455
    invoke-virtual {v1, v0}, Landroid/os/BaseBundle;->getLong(Ljava/lang/String;)J

    .line 456
    .line 457
    .line 458
    move-result-wide v23

    .line 459
    const-string v13, ""

    .line 460
    .line 461
    const/16 v19, 0x0

    .line 462
    .line 463
    const/16 v22, 0x0

    .line 464
    .line 465
    move-object v14, v5

    .line 466
    invoke-direct/range {v11 .. v25}, Lvp/f;-><init>(Ljava/lang/String;Ljava/lang/String;Lvp/b4;JZLjava/lang/String;Lvp/t;JLvp/t;JLvp/t;)V

    .line 467
    .line 468
    .line 469
    invoke-virtual {v3}, Lvp/g1;->o()Lvp/d3;

    .line 470
    .line 471
    .line 472
    move-result-object v0

    .line 473
    invoke-virtual {v0, v11}, Lvp/d3;->t0(Lvp/f;)V

    .line 474
    .line 475
    .line 476
    :catch_0
    :goto_5
    return-void

    .line 477
    :pswitch_8
    iget-object v0, v1, Lk0/g;->f:Ljava/lang/Object;

    .line 478
    .line 479
    check-cast v0, Lvp/m1;

    .line 480
    .line 481
    iget-object v0, v0, Lvp/m1;->c:Lvp/z3;

    .line 482
    .line 483
    invoke-virtual {v0}, Lvp/z3;->B()V

    .line 484
    .line 485
    .line 486
    iget-object v1, v1, Lk0/g;->e:Ljava/lang/Object;

    .line 487
    .line 488
    check-cast v1, Lvp/f;

    .line 489
    .line 490
    iget-object v2, v1, Lvp/f;->f:Lvp/b4;

    .line 491
    .line 492
    invoke-virtual {v2}, Lvp/b4;->h()Ljava/lang/Object;

    .line 493
    .line 494
    .line 495
    move-result-object v2

    .line 496
    if-nez v2, :cond_c

    .line 497
    .line 498
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 499
    .line 500
    .line 501
    iget-object v2, v1, Lvp/f;->d:Ljava/lang/String;

    .line 502
    .line 503
    invoke-static {v2}, Lno/c0;->h(Ljava/lang/Object;)V

    .line 504
    .line 505
    .line 506
    invoke-virtual {v0, v2}, Lvp/z3;->Q(Ljava/lang/String;)Lvp/f4;

    .line 507
    .line 508
    .line 509
    move-result-object v2

    .line 510
    if-eqz v2, :cond_d

    .line 511
    .line 512
    invoke-virtual {v0, v1, v2}, Lvp/z3;->Z(Lvp/f;Lvp/f4;)V

    .line 513
    .line 514
    .line 515
    goto :goto_6

    .line 516
    :cond_c
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 517
    .line 518
    .line 519
    iget-object v2, v1, Lvp/f;->d:Ljava/lang/String;

    .line 520
    .line 521
    invoke-static {v2}, Lno/c0;->h(Ljava/lang/Object;)V

    .line 522
    .line 523
    .line 524
    invoke-virtual {v0, v2}, Lvp/z3;->Q(Ljava/lang/String;)Lvp/f4;

    .line 525
    .line 526
    .line 527
    move-result-object v2

    .line 528
    if-eqz v2, :cond_d

    .line 529
    .line 530
    invoke-virtual {v0, v1, v2}, Lvp/z3;->Y(Lvp/f;Lvp/f4;)V

    .line 531
    .line 532
    .line 533
    :cond_d
    :goto_6
    return-void

    .line 534
    :pswitch_9
    iget-object v0, v1, Lk0/g;->e:Ljava/lang/Object;

    .line 535
    .line 536
    check-cast v0, Lvp/o1;

    .line 537
    .line 538
    invoke-interface {v0}, Lvp/o1;->h()Lst/b;

    .line 539
    .line 540
    .line 541
    invoke-static {}, Lst/b;->i()Z

    .line 542
    .line 543
    .line 544
    move-result v2

    .line 545
    if-eqz v2, :cond_e

    .line 546
    .line 547
    invoke-interface {v0}, Lvp/o1;->f()Lvp/e1;

    .line 548
    .line 549
    .line 550
    move-result-object v0

    .line 551
    invoke-virtual {v0, v1}, Lvp/e1;->j0(Ljava/lang/Runnable;)V

    .line 552
    .line 553
    .line 554
    goto :goto_7

    .line 555
    :cond_e
    iget-object v0, v1, Lk0/g;->f:Ljava/lang/Object;

    .line 556
    .line 557
    check-cast v0, Lvp/o;

    .line 558
    .line 559
    iget-wide v1, v0, Lvp/o;->c:J

    .line 560
    .line 561
    cmp-long v1, v1, v4

    .line 562
    .line 563
    if-eqz v1, :cond_f

    .line 564
    .line 565
    move v8, v9

    .line 566
    :cond_f
    iput-wide v4, v0, Lvp/o;->c:J

    .line 567
    .line 568
    if-eqz v8, :cond_10

    .line 569
    .line 570
    invoke-virtual {v0}, Lvp/o;->a()V

    .line 571
    .line 572
    .line 573
    :cond_10
    :goto_7
    return-void

    .line 574
    :pswitch_a
    invoke-direct {v1}, Lk0/g;->a()V

    .line 575
    .line 576
    .line 577
    return-void

    .line 578
    :pswitch_b
    iget-object v0, v1, Lk0/g;->e:Ljava/lang/Object;

    .line 579
    .line 580
    check-cast v0, Llo/p;

    .line 581
    .line 582
    iget-object v1, v1, Lk0/g;->f:Ljava/lang/Object;

    .line 583
    .line 584
    check-cast v1, Lbb/g0;

    .line 585
    .line 586
    iget v4, v1, Lbb/g0;->e:I

    .line 587
    .line 588
    if-lez v4, :cond_12

    .line 589
    .line 590
    iget-object v4, v1, Lbb/g0;->g:Ljava/lang/Object;

    .line 591
    .line 592
    check-cast v4, Landroid/os/Bundle;

    .line 593
    .line 594
    if-eqz v4, :cond_11

    .line 595
    .line 596
    const-string v5, "ConnectionlessLifecycleHelper"

    .line 597
    .line 598
    invoke-virtual {v4, v5}, Landroid/os/Bundle;->getBundle(Ljava/lang/String;)Landroid/os/Bundle;

    .line 599
    .line 600
    .line 601
    move-result-object v7

    .line 602
    :cond_11
    invoke-virtual {v0, v7}, Llo/p;->b(Landroid/os/Bundle;)V

    .line 603
    .line 604
    .line 605
    :cond_12
    iget v4, v1, Lbb/g0;->e:I

    .line 606
    .line 607
    if-lt v4, v3, :cond_13

    .line 608
    .line 609
    iput-boolean v9, v0, Llo/p;->e:Z

    .line 610
    .line 611
    invoke-virtual {v0}, Llo/p;->d()V

    .line 612
    .line 613
    .line 614
    :cond_13
    iget v3, v1, Lbb/g0;->e:I

    .line 615
    .line 616
    if-lt v3, v6, :cond_14

    .line 617
    .line 618
    invoke-virtual {v0}, Llo/p;->d()V

    .line 619
    .line 620
    .line 621
    :cond_14
    iget v1, v1, Lbb/g0;->e:I

    .line 622
    .line 623
    if-lt v1, v2, :cond_15

    .line 624
    .line 625
    invoke-virtual {v0}, Llo/p;->c()V

    .line 626
    .line 627
    .line 628
    :cond_15
    return-void

    .line 629
    :pswitch_c
    iget-object v0, v1, Lk0/g;->f:Ljava/lang/Object;

    .line 630
    .line 631
    check-cast v0, Llo/b0;

    .line 632
    .line 633
    iget-object v1, v1, Lk0/g;->e:Ljava/lang/Object;

    .line 634
    .line 635
    check-cast v1, Lyp/g;

    .line 636
    .line 637
    iget-object v3, v1, Lyp/g;->e:Ljo/b;

    .line 638
    .line 639
    iget v4, v3, Ljo/b;->e:I

    .line 640
    .line 641
    if-nez v4, :cond_1b

    .line 642
    .line 643
    iget-object v1, v1, Lyp/g;->f:Lno/v;

    .line 644
    .line 645
    invoke-static {v1}, Lno/c0;->h(Ljava/lang/Object;)V

    .line 646
    .line 647
    .line 648
    iget-object v3, v1, Lno/v;->f:Ljo/b;

    .line 649
    .line 650
    iget v4, v3, Ljo/b;->e:I

    .line 651
    .line 652
    if-nez v4, :cond_1a

    .line 653
    .line 654
    iget-object v3, v0, Llo/b0;->j:Lh8/o;

    .line 655
    .line 656
    iget-object v1, v1, Lno/v;->e:Landroid/os/IBinder;

    .line 657
    .line 658
    if-nez v1, :cond_16

    .line 659
    .line 660
    goto :goto_8

    .line 661
    :cond_16
    sget v4, Lno/a;->d:I

    .line 662
    .line 663
    const-string v4, "com.google.android.gms.common.internal.IAccountAccessor"

    .line 664
    .line 665
    invoke-interface {v1, v4}, Landroid/os/IBinder;->queryLocalInterface(Ljava/lang/String;)Landroid/os/IInterface;

    .line 666
    .line 667
    .line 668
    move-result-object v5

    .line 669
    instance-of v7, v5, Lno/j;

    .line 670
    .line 671
    if-eqz v7, :cond_17

    .line 672
    .line 673
    move-object v7, v5

    .line 674
    check-cast v7, Lno/j;

    .line 675
    .line 676
    goto :goto_8

    .line 677
    :cond_17
    new-instance v7, Lno/p0;

    .line 678
    .line 679
    invoke-direct {v7, v1, v4, v6}, Lbp/a;-><init>(Landroid/os/IBinder;Ljava/lang/String;I)V

    .line 680
    .line 681
    .line 682
    :goto_8
    iget-object v1, v0, Llo/b0;->g:Ljava/util/Set;

    .line 683
    .line 684
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 685
    .line 686
    .line 687
    if-eqz v7, :cond_19

    .line 688
    .line 689
    if-nez v1, :cond_18

    .line 690
    .line 691
    goto :goto_9

    .line 692
    :cond_18
    iput-object v7, v3, Lh8/o;->d:Ljava/lang/Object;

    .line 693
    .line 694
    iput-object v1, v3, Lh8/o;->e:Ljava/lang/Object;

    .line 695
    .line 696
    iget-boolean v2, v3, Lh8/o;->a:Z

    .line 697
    .line 698
    if-eqz v2, :cond_1c

    .line 699
    .line 700
    iget-object v2, v3, Lh8/o;->b:Ljava/lang/Object;

    .line 701
    .line 702
    check-cast v2, Lko/c;

    .line 703
    .line 704
    invoke-interface {v2, v7, v1}, Lko/c;->d(Lno/j;Ljava/util/Set;)V

    .line 705
    .line 706
    .line 707
    goto :goto_a

    .line 708
    :cond_19
    :goto_9
    new-instance v1, Ljava/lang/Exception;

    .line 709
    .line 710
    invoke-direct {v1}, Ljava/lang/Exception;-><init>()V

    .line 711
    .line 712
    .line 713
    const-string v4, "GoogleApiManager"

    .line 714
    .line 715
    const-string v5, "Received null response from onSignInSuccess"

    .line 716
    .line 717
    invoke-static {v4, v5, v1}, Landroid/util/Log;->wtf(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 718
    .line 719
    .line 720
    new-instance v1, Ljo/b;

    .line 721
    .line 722
    invoke-direct {v1, v2}, Ljo/b;-><init>(I)V

    .line 723
    .line 724
    .line 725
    invoke-virtual {v3, v1}, Lh8/o;->e(Ljo/b;)V

    .line 726
    .line 727
    .line 728
    goto :goto_a

    .line 729
    :cond_1a
    invoke-static {v3}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;

    .line 730
    .line 731
    .line 732
    move-result-object v1

    .line 733
    new-instance v2, Ljava/lang/Exception;

    .line 734
    .line 735
    invoke-direct {v2}, Ljava/lang/Exception;-><init>()V

    .line 736
    .line 737
    .line 738
    const-string v4, "Sign-in succeeded with resolve account failure: "

    .line 739
    .line 740
    const-string v5, "SignInCoordinator"

    .line 741
    .line 742
    invoke-virtual {v4, v1}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 743
    .line 744
    .line 745
    move-result-object v1

    .line 746
    invoke-static {v5, v1, v2}, Landroid/util/Log;->wtf(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 747
    .line 748
    .line 749
    iget-object v1, v0, Llo/b0;->j:Lh8/o;

    .line 750
    .line 751
    invoke-virtual {v1, v3}, Lh8/o;->e(Ljo/b;)V

    .line 752
    .line 753
    .line 754
    iget-object v0, v0, Llo/b0;->i:Lyp/a;

    .line 755
    .line 756
    invoke-interface {v0}, Lko/c;->disconnect()V

    .line 757
    .line 758
    .line 759
    goto :goto_b

    .line 760
    :cond_1b
    iget-object v1, v0, Llo/b0;->j:Lh8/o;

    .line 761
    .line 762
    invoke-virtual {v1, v3}, Lh8/o;->e(Ljo/b;)V

    .line 763
    .line 764
    .line 765
    :cond_1c
    :goto_a
    iget-object v0, v0, Llo/b0;->i:Lyp/a;

    .line 766
    .line 767
    invoke-interface {v0}, Lko/c;->disconnect()V

    .line 768
    .line 769
    .line 770
    :goto_b
    return-void

    .line 771
    :pswitch_d
    iget-object v0, v1, Lk0/g;->e:Ljava/lang/Object;

    .line 772
    .line 773
    check-cast v0, Ljo/b;

    .line 774
    .line 775
    iget-object v1, v1, Lk0/g;->f:Ljava/lang/Object;

    .line 776
    .line 777
    check-cast v1, Lh8/o;

    .line 778
    .line 779
    iget-object v2, v1, Lh8/o;->b:Ljava/lang/Object;

    .line 780
    .line 781
    check-cast v2, Lko/c;

    .line 782
    .line 783
    iget-object v3, v1, Lh8/o;->f:Ljava/lang/Object;

    .line 784
    .line 785
    check-cast v3, Llo/g;

    .line 786
    .line 787
    iget-object v3, v3, Llo/g;->m:Ljava/util/concurrent/ConcurrentHashMap;

    .line 788
    .line 789
    iget-object v4, v1, Lh8/o;->c:Ljava/lang/Object;

    .line 790
    .line 791
    check-cast v4, Llo/b;

    .line 792
    .line 793
    invoke-virtual {v3, v4}, Ljava/util/concurrent/ConcurrentHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 794
    .line 795
    .line 796
    move-result-object v3

    .line 797
    check-cast v3, Llo/s;

    .line 798
    .line 799
    if-nez v3, :cond_1d

    .line 800
    .line 801
    goto :goto_c

    .line 802
    :cond_1d
    iget v4, v0, Ljo/b;->e:I

    .line 803
    .line 804
    if-nez v4, :cond_1f

    .line 805
    .line 806
    iput-boolean v9, v1, Lh8/o;->a:Z

    .line 807
    .line 808
    invoke-interface {v2}, Lko/c;->h()Z

    .line 809
    .line 810
    .line 811
    move-result v0

    .line 812
    if-eqz v0, :cond_1e

    .line 813
    .line 814
    iget-boolean v0, v1, Lh8/o;->a:Z

    .line 815
    .line 816
    if-eqz v0, :cond_20

    .line 817
    .line 818
    iget-object v0, v1, Lh8/o;->d:Ljava/lang/Object;

    .line 819
    .line 820
    check-cast v0, Lno/j;

    .line 821
    .line 822
    if-eqz v0, :cond_20

    .line 823
    .line 824
    iget-object v1, v1, Lh8/o;->e:Ljava/lang/Object;

    .line 825
    .line 826
    check-cast v1, Ljava/util/Set;

    .line 827
    .line 828
    invoke-interface {v2, v0, v1}, Lko/c;->d(Lno/j;Ljava/util/Set;)V

    .line 829
    .line 830
    .line 831
    goto :goto_c

    .line 832
    :cond_1e
    :try_start_2
    invoke-interface {v2}, Lko/c;->i()Ljava/util/Set;

    .line 833
    .line 834
    .line 835
    move-result-object v0

    .line 836
    invoke-interface {v2, v7, v0}, Lko/c;->d(Lno/j;Ljava/util/Set;)V
    :try_end_2
    .catch Ljava/lang/SecurityException; {:try_start_2 .. :try_end_2} :catch_1

    .line 837
    .line 838
    .line 839
    goto :goto_c

    .line 840
    :catch_1
    move-exception v0

    .line 841
    const-string v1, "GoogleApiManager"

    .line 842
    .line 843
    const-string v4, "Failed to get service from broker. "

    .line 844
    .line 845
    invoke-static {v1, v4, v0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 846
    .line 847
    .line 848
    const-string v0, "Failed to get service from broker."

    .line 849
    .line 850
    invoke-interface {v2, v0}, Lko/c;->a(Ljava/lang/String;)V

    .line 851
    .line 852
    .line 853
    new-instance v0, Ljo/b;

    .line 854
    .line 855
    const/16 v1, 0xa

    .line 856
    .line 857
    invoke-direct {v0, v1}, Ljo/b;-><init>(I)V

    .line 858
    .line 859
    .line 860
    invoke-virtual {v3, v0, v7}, Llo/s;->p(Ljo/b;Ljava/lang/RuntimeException;)V

    .line 861
    .line 862
    .line 863
    goto :goto_c

    .line 864
    :cond_1f
    invoke-virtual {v3, v0, v7}, Llo/s;->p(Ljo/b;Ljava/lang/RuntimeException;)V

    .line 865
    .line 866
    .line 867
    :cond_20
    :goto_c
    return-void

    .line 868
    :pswitch_e
    iget-object v0, v1, Lk0/g;->e:Ljava/lang/Object;

    .line 869
    .line 870
    move-object v10, v0

    .line 871
    check-cast v10, Ljp/vg;

    .line 872
    .line 873
    sget-object v12, Ljp/bc;->r2:Ljp/bc;

    .line 874
    .line 875
    iget-object v0, v1, Lk0/g;->f:Ljava/lang/Object;

    .line 876
    .line 877
    check-cast v0, Lj1/a;

    .line 878
    .line 879
    iget-object v1, v10, Ljp/vg;->j:Ljava/util/HashMap;

    .line 880
    .line 881
    invoke-virtual {v1, v12}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 882
    .line 883
    .line 884
    move-result-object v2

    .line 885
    check-cast v2, Ljp/o;

    .line 886
    .line 887
    if-eqz v2, :cond_26

    .line 888
    .line 889
    invoke-virtual {v2}, Ljp/n;->b()Ljava/util/Set;

    .line 890
    .line 891
    .line 892
    move-result-object v3

    .line 893
    check-cast v3, Ljp/h;

    .line 894
    .line 895
    invoke-virtual {v3}, Ljp/h;->iterator()Ljava/util/Iterator;

    .line 896
    .line 897
    .line 898
    move-result-object v3

    .line 899
    :goto_d
    invoke-interface {v3}, Ljava/util/Iterator;->hasNext()Z

    .line 900
    .line 901
    .line 902
    move-result v9

    .line 903
    if-eqz v9, :cond_25

    .line 904
    .line 905
    invoke-interface {v3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 906
    .line 907
    .line 908
    move-result-object v9

    .line 909
    new-instance v11, Ljava/util/ArrayList;

    .line 910
    .line 911
    iget-object v13, v2, Ljp/o;->f:Ljp/t;

    .line 912
    .line 913
    invoke-virtual {v13, v9}, Ljp/t;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 914
    .line 915
    .line 916
    move-result-object v13

    .line 917
    check-cast v13, Ljava/util/Collection;

    .line 918
    .line 919
    if-nez v13, :cond_21

    .line 920
    .line 921
    new-instance v13, Ljava/util/ArrayList;

    .line 922
    .line 923
    invoke-direct {v13, v6}, Ljava/util/ArrayList;-><init>(I)V

    .line 924
    .line 925
    .line 926
    :cond_21
    check-cast v13, Ljava/util/List;

    .line 927
    .line 928
    instance-of v14, v13, Ljava/util/RandomAccess;

    .line 929
    .line 930
    if-eqz v14, :cond_22

    .line 931
    .line 932
    new-instance v14, Ljp/k;

    .line 933
    .line 934
    invoke-direct {v14, v2, v9, v13, v7}, Lhr/l;-><init>(Ljp/o;Ljava/lang/Object;Ljava/util/List;Lhr/l;)V

    .line 935
    .line 936
    .line 937
    goto :goto_e

    .line 938
    :cond_22
    new-instance v14, Lhr/l;

    .line 939
    .line 940
    invoke-direct {v14, v2, v9, v13, v7}, Lhr/l;-><init>(Ljp/o;Ljava/lang/Object;Ljava/util/List;Lhr/l;)V

    .line 941
    .line 942
    .line 943
    :goto_e
    invoke-direct {v11, v14}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    .line 944
    .line 945
    .line 946
    invoke-static {v11}, Ljava/util/Collections;->sort(Ljava/util/List;)V

    .line 947
    .line 948
    .line 949
    new-instance v13, Ljp/eb;

    .line 950
    .line 951
    invoke-direct {v13}, Ljava/lang/Object;-><init>()V

    .line 952
    .line 953
    .line 954
    invoke-virtual {v11}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 955
    .line 956
    .line 957
    move-result-object v14

    .line 958
    move-wide v15, v4

    .line 959
    :goto_f
    invoke-interface {v14}, Ljava/util/Iterator;->hasNext()Z

    .line 960
    .line 961
    .line 962
    move-result v17

    .line 963
    if-eqz v17, :cond_23

    .line 964
    .line 965
    invoke-interface {v14}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 966
    .line 967
    .line 968
    move-result-object v17

    .line 969
    check-cast v17, Ljava/lang/Long;

    .line 970
    .line 971
    invoke-virtual/range {v17 .. v17}, Ljava/lang/Long;->longValue()J

    .line 972
    .line 973
    .line 974
    move-result-wide v17

    .line 975
    add-long v15, v17, v15

    .line 976
    .line 977
    goto :goto_f

    .line 978
    :cond_23
    invoke-virtual {v11}, Ljava/util/ArrayList;->size()I

    .line 979
    .line 980
    .line 981
    move-result v14

    .line 982
    int-to-long v4, v14

    .line 983
    div-long/2addr v15, v4

    .line 984
    const-wide v4, 0x7fffffffffffffffL

    .line 985
    .line 986
    .line 987
    .line 988
    .line 989
    and-long v14, v15, v4

    .line 990
    .line 991
    invoke-static {v14, v15}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 992
    .line 993
    .line 994
    move-result-object v14

    .line 995
    iput-object v14, v13, Ljp/eb;->c:Ljava/lang/Long;

    .line 996
    .line 997
    const-wide/high16 v14, 0x4059000000000000L    # 100.0

    .line 998
    .line 999
    invoke-static {v11, v14, v15}, Ljp/vg;->a(Ljava/util/ArrayList;D)J

    .line 1000
    .line 1001
    .line 1002
    move-result-wide v14

    .line 1003
    and-long/2addr v14, v4

    .line 1004
    invoke-static {v14, v15}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 1005
    .line 1006
    .line 1007
    move-result-object v14

    .line 1008
    iput-object v14, v13, Ljp/eb;->a:Ljava/lang/Long;

    .line 1009
    .line 1010
    const-wide v14, 0x4052c00000000000L    # 75.0

    .line 1011
    .line 1012
    .line 1013
    .line 1014
    .line 1015
    invoke-static {v11, v14, v15}, Ljp/vg;->a(Ljava/util/ArrayList;D)J

    .line 1016
    .line 1017
    .line 1018
    move-result-wide v14

    .line 1019
    and-long/2addr v14, v4

    .line 1020
    invoke-static {v14, v15}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 1021
    .line 1022
    .line 1023
    move-result-object v14

    .line 1024
    iput-object v14, v13, Ljp/eb;->f:Ljava/lang/Long;

    .line 1025
    .line 1026
    const-wide/high16 v14, 0x4049000000000000L    # 50.0

    .line 1027
    .line 1028
    invoke-static {v11, v14, v15}, Ljp/vg;->a(Ljava/util/ArrayList;D)J

    .line 1029
    .line 1030
    .line 1031
    move-result-wide v14

    .line 1032
    and-long/2addr v14, v4

    .line 1033
    invoke-static {v14, v15}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 1034
    .line 1035
    .line 1036
    move-result-object v14

    .line 1037
    iput-object v14, v13, Ljp/eb;->e:Ljava/lang/Long;

    .line 1038
    .line 1039
    const-wide/high16 v14, 0x4039000000000000L    # 25.0

    .line 1040
    .line 1041
    invoke-static {v11, v14, v15}, Ljp/vg;->a(Ljava/util/ArrayList;D)J

    .line 1042
    .line 1043
    .line 1044
    move-result-wide v14

    .line 1045
    and-long/2addr v14, v4

    .line 1046
    invoke-static {v14, v15}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 1047
    .line 1048
    .line 1049
    move-result-object v14

    .line 1050
    iput-object v14, v13, Ljp/eb;->d:Ljava/lang/Long;

    .line 1051
    .line 1052
    const-wide/16 v14, 0x0

    .line 1053
    .line 1054
    invoke-static {v11, v14, v15}, Ljp/vg;->a(Ljava/util/ArrayList;D)J

    .line 1055
    .line 1056
    .line 1057
    move-result-wide v14

    .line 1058
    and-long/2addr v4, v14

    .line 1059
    invoke-static {v4, v5}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 1060
    .line 1061
    .line 1062
    move-result-object v4

    .line 1063
    iput-object v4, v13, Ljp/eb;->b:Ljava/lang/Long;

    .line 1064
    .line 1065
    new-instance v4, Ljp/fb;

    .line 1066
    .line 1067
    invoke-direct {v4, v13}, Ljp/fb;-><init>(Ljp/eb;)V

    .line 1068
    .line 1069
    .line 1070
    invoke-virtual {v11}, Ljava/util/ArrayList;->size()I

    .line 1071
    .line 1072
    .line 1073
    move-result v5

    .line 1074
    iget-object v11, v0, Lj1/a;->e:Ljava/lang/Object;

    .line 1075
    .line 1076
    check-cast v11, Llv/e;

    .line 1077
    .line 1078
    check-cast v9, Ljp/u0;

    .line 1079
    .line 1080
    new-instance v13, Lin/z1;

    .line 1081
    .line 1082
    invoke-direct {v13}, Ljava/lang/Object;-><init>()V

    .line 1083
    .line 1084
    .line 1085
    iget-boolean v11, v11, Llv/e;->m:Z

    .line 1086
    .line 1087
    if-eqz v11, :cond_24

    .line 1088
    .line 1089
    sget-object v11, Ljp/zb;->f:Ljp/zb;

    .line 1090
    .line 1091
    goto :goto_10

    .line 1092
    :cond_24
    sget-object v11, Ljp/zb;->e:Ljp/zb;

    .line 1093
    .line 1094
    :goto_10
    iput-object v11, v13, Lin/z1;->c:Ljava/lang/Object;

    .line 1095
    .line 1096
    new-instance v11, Ljp/o0;

    .line 1097
    .line 1098
    invoke-direct {v11}, Ljava/lang/Object;-><init>()V

    .line 1099
    .line 1100
    .line 1101
    const v14, 0x7fffffff

    .line 1102
    .line 1103
    .line 1104
    and-int/2addr v5, v14

    .line 1105
    invoke-static {v5}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 1106
    .line 1107
    .line 1108
    move-result-object v5

    .line 1109
    iput-object v5, v11, Ljp/o0;->e:Ljava/io/Serializable;

    .line 1110
    .line 1111
    iput-object v9, v11, Ljp/o0;->d:Ljava/lang/Object;

    .line 1112
    .line 1113
    iput-object v4, v11, Ljp/o0;->f:Ljava/lang/Object;

    .line 1114
    .line 1115
    new-instance v4, Ljp/v0;

    .line 1116
    .line 1117
    invoke-direct {v4, v11}, Ljp/v0;-><init>(Ljp/o0;)V

    .line 1118
    .line 1119
    .line 1120
    iput-object v4, v13, Lin/z1;->f:Ljava/lang/Object;

    .line 1121
    .line 1122
    new-instance v11, Lbb/g0;

    .line 1123
    .line 1124
    invoke-direct {v11, v13, v8}, Lbb/g0;-><init>(Lin/z1;I)V

    .line 1125
    .line 1126
    .line 1127
    invoke-virtual {v10}, Ljp/vg;->c()Ljava/lang/String;

    .line 1128
    .line 1129
    .line 1130
    move-result-object v13

    .line 1131
    sget-object v4, Lfv/l;->d:Lfv/l;

    .line 1132
    .line 1133
    new-instance v9, Ld6/z0;

    .line 1134
    .line 1135
    const/4 v14, 0x1

    .line 1136
    invoke-direct/range {v9 .. v14}, Ld6/z0;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 1137
    .line 1138
    .line 1139
    invoke-virtual {v4, v9}, Lfv/l;->execute(Ljava/lang/Runnable;)V

    .line 1140
    .line 1141
    .line 1142
    const-wide/16 v4, 0x0

    .line 1143
    .line 1144
    goto/16 :goto_d

    .line 1145
    .line 1146
    :cond_25
    invoke-virtual {v1, v12}, Ljava/util/HashMap;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    .line 1147
    .line 1148
    .line 1149
    :cond_26
    return-void

    .line 1150
    :pswitch_f
    iget-object v0, v1, Lk0/g;->e:Ljava/lang/Object;

    .line 1151
    .line 1152
    move-object v2, v0

    .line 1153
    check-cast v2, Lio/m;

    .line 1154
    .line 1155
    iget-object v0, v1, Lk0/g;->f:Ljava/lang/Object;

    .line 1156
    .line 1157
    check-cast v0, Landroid/os/IBinder;

    .line 1158
    .line 1159
    monitor-enter v2

    .line 1160
    if-nez v0, :cond_27

    .line 1161
    .line 1162
    :try_start_3
    const-string v0, "Null service connection"

    .line 1163
    .line 1164
    invoke-virtual {v2, v0}, Lio/m;->a(Ljava/lang/String;)V

    .line 1165
    .line 1166
    .line 1167
    monitor-exit v2
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_1

    .line 1168
    goto :goto_11

    .line 1169
    :catchall_1
    move-exception v0

    .line 1170
    goto :goto_12

    .line 1171
    :cond_27
    :try_start_4
    new-instance v1, Lc2/k;

    .line 1172
    .line 1173
    invoke-direct {v1, v0}, Lc2/k;-><init>(Landroid/os/IBinder;)V

    .line 1174
    .line 1175
    .line 1176
    iput-object v1, v2, Lio/m;->c:Lc2/k;
    :try_end_4
    .catch Landroid/os/RemoteException; {:try_start_4 .. :try_end_4} :catch_2
    .catchall {:try_start_4 .. :try_end_4} :catchall_1

    .line 1177
    .line 1178
    :try_start_5
    iput v3, v2, Lio/m;->a:I

    .line 1179
    .line 1180
    iget-object v0, v2, Lio/m;->f:Lio/o;

    .line 1181
    .line 1182
    iget-object v0, v0, Lio/o;->f:Ljava/lang/Object;

    .line 1183
    .line 1184
    check-cast v0, Ljava/util/concurrent/ScheduledExecutorService;

    .line 1185
    .line 1186
    new-instance v1, Lio/k;

    .line 1187
    .line 1188
    invoke-direct {v1, v2, v8}, Lio/k;-><init>(Lio/m;I)V

    .line 1189
    .line 1190
    .line 1191
    invoke-interface {v0, v1}, Ljava/util/concurrent/Executor;->execute(Ljava/lang/Runnable;)V

    .line 1192
    .line 1193
    .line 1194
    monitor-exit v2

    .line 1195
    goto :goto_11

    .line 1196
    :catch_2
    move-exception v0

    .line 1197
    invoke-virtual {v0}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    .line 1198
    .line 1199
    .line 1200
    move-result-object v0

    .line 1201
    invoke-virtual {v2, v0}, Lio/m;->a(Ljava/lang/String;)V

    .line 1202
    .line 1203
    .line 1204
    monitor-exit v2

    .line 1205
    :goto_11
    return-void

    .line 1206
    :goto_12
    monitor-exit v2
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_1

    .line 1207
    throw v0

    .line 1208
    :pswitch_10
    iget-object v0, v1, Lk0/g;->f:Ljava/lang/Object;

    .line 1209
    .line 1210
    check-cast v0, Lcom/google/android/material/behavior/SwipeDismissBehavior;

    .line 1211
    .line 1212
    iget-object v0, v0, Lcom/google/android/material/behavior/SwipeDismissBehavior;->a:Lk6/f;

    .line 1213
    .line 1214
    if-eqz v0, :cond_28

    .line 1215
    .line 1216
    invoke-virtual {v0}, Lk6/f;->f()Z

    .line 1217
    .line 1218
    .line 1219
    move-result v0

    .line 1220
    if-eqz v0, :cond_28

    .line 1221
    .line 1222
    iget-object v0, v1, Lk0/g;->e:Ljava/lang/Object;

    .line 1223
    .line 1224
    check-cast v0, Landroid/view/View;

    .line 1225
    .line 1226
    invoke-virtual {v0, v1}, Landroid/view/View;->postOnAnimation(Ljava/lang/Runnable;)V

    .line 1227
    .line 1228
    .line 1229
    :cond_28
    return-void

    .line 1230
    :pswitch_11
    iget-object v0, v1, Lk0/g;->e:Ljava/lang/Object;

    .line 1231
    .line 1232
    move-object v2, v0

    .line 1233
    check-cast v2, La8/b;

    .line 1234
    .line 1235
    iget-object v0, v2, La8/b;->h:Ljava/lang/Object;

    .line 1236
    .line 1237
    check-cast v0, Ljava/util/concurrent/atomic/AtomicReference;

    .line 1238
    .line 1239
    invoke-static {}, Ljava/lang/Thread;->currentThread()Ljava/lang/Thread;

    .line 1240
    .line 1241
    .line 1242
    move-result-object v3

    .line 1243
    invoke-virtual {v0, v3}, Ljava/util/concurrent/atomic/AtomicReference;->getAndSet(Ljava/lang/Object;)Ljava/lang/Object;

    .line 1244
    .line 1245
    .line 1246
    move-result-object v0

    .line 1247
    check-cast v0, Ljava/lang/Thread;

    .line 1248
    .line 1249
    if-nez v0, :cond_29

    .line 1250
    .line 1251
    move v8, v9

    .line 1252
    :cond_29
    invoke-static {v8}, Lno/c0;->k(Z)V

    .line 1253
    .line 1254
    .line 1255
    iget-object v0, v1, Lk0/g;->f:Ljava/lang/Object;

    .line 1256
    .line 1257
    check-cast v0, Ljava/lang/Runnable;

    .line 1258
    .line 1259
    :try_start_6
    invoke-interface {v0}, Ljava/lang/Runnable;->run()V
    :try_end_6
    .catchall {:try_start_6 .. :try_end_6} :catchall_2

    .line 1260
    .line 1261
    .line 1262
    iget-object v0, v2, La8/b;->h:Ljava/lang/Object;

    .line 1263
    .line 1264
    check-cast v0, Ljava/util/concurrent/atomic/AtomicReference;

    .line 1265
    .line 1266
    invoke-virtual {v0, v7}, Ljava/util/concurrent/atomic/AtomicReference;->set(Ljava/lang/Object;)V

    .line 1267
    .line 1268
    .line 1269
    invoke-virtual {v2}, La8/b;->j()V

    .line 1270
    .line 1271
    .line 1272
    return-void

    .line 1273
    :catchall_2
    move-exception v0

    .line 1274
    move-object v1, v0

    .line 1275
    :try_start_7
    iget-object v0, v2, La8/b;->h:Ljava/lang/Object;

    .line 1276
    .line 1277
    check-cast v0, Ljava/util/concurrent/atomic/AtomicReference;

    .line 1278
    .line 1279
    invoke-virtual {v0, v7}, Ljava/util/concurrent/atomic/AtomicReference;->set(Ljava/lang/Object;)V

    .line 1280
    .line 1281
    .line 1282
    invoke-virtual {v2}, La8/b;->j()V
    :try_end_7
    .catchall {:try_start_7 .. :try_end_7} :catchall_3

    .line 1283
    .line 1284
    .line 1285
    goto :goto_13

    .line 1286
    :catchall_3
    move-exception v0

    .line 1287
    invoke-virtual {v1, v0}, Ljava/lang/Throwable;->addSuppressed(Ljava/lang/Throwable;)V

    .line 1288
    .line 1289
    .line 1290
    :goto_13
    throw v1

    .line 1291
    :pswitch_12
    iget-object v0, v1, Lk0/g;->e:Ljava/lang/Object;

    .line 1292
    .line 1293
    check-cast v0, Ljava/util/concurrent/Callable;

    .line 1294
    .line 1295
    iget-object v1, v1, Lk0/g;->f:Ljava/lang/Object;

    .line 1296
    .line 1297
    check-cast v1, Laq/k;

    .line 1298
    .line 1299
    :try_start_8
    invoke-interface {v0}, Ljava/util/concurrent/Callable;->call()Ljava/lang/Object;

    .line 1300
    .line 1301
    .line 1302
    move-result-object v0
    :try_end_8
    .catch Lbv/a; {:try_start_8 .. :try_end_8} :catch_4
    .catch Ljava/lang/Exception; {:try_start_8 .. :try_end_8} :catch_3

    .line 1303
    invoke-virtual {v1, v0}, Laq/k;->b(Ljava/lang/Object;)V

    .line 1304
    .line 1305
    .line 1306
    goto :goto_14

    .line 1307
    :catch_3
    move-exception v0

    .line 1308
    new-instance v2, Lbv/a;

    .line 1309
    .line 1310
    const-string v3, "Internal error has occurred when executing ML Kit tasks"

    .line 1311
    .line 1312
    invoke-direct {v2, v3, v0}, Lbv/a;-><init>(Ljava/lang/String;Ljava/lang/Exception;)V

    .line 1313
    .line 1314
    .line 1315
    invoke-virtual {v1, v2}, Laq/k;->a(Ljava/lang/Exception;)V

    .line 1316
    .line 1317
    .line 1318
    goto :goto_14

    .line 1319
    :catch_4
    move-exception v0

    .line 1320
    invoke-virtual {v1, v0}, Laq/k;->a(Ljava/lang/Exception;)V

    .line 1321
    .line 1322
    .line 1323
    :goto_14
    return-void

    .line 1324
    :pswitch_13
    iget-object v0, v1, Lk0/g;->e:Ljava/lang/Object;

    .line 1325
    .line 1326
    move-object v2, v0

    .line 1327
    check-cast v2, Laq/t;

    .line 1328
    .line 1329
    :try_start_9
    iget-object v0, v1, Lk0/g;->f:Ljava/lang/Object;

    .line 1330
    .line 1331
    check-cast v0, Ljava/util/concurrent/Callable;

    .line 1332
    .line 1333
    invoke-interface {v0}, Ljava/util/concurrent/Callable;->call()Ljava/lang/Object;

    .line 1334
    .line 1335
    .line 1336
    move-result-object v0

    .line 1337
    invoke-virtual {v2, v0}, Laq/t;->o(Ljava/lang/Object;)V
    :try_end_9
    .catch Ljava/lang/Exception; {:try_start_9 .. :try_end_9} :catch_5
    .catchall {:try_start_9 .. :try_end_9} :catchall_4

    .line 1338
    .line 1339
    .line 1340
    goto :goto_17

    .line 1341
    :catchall_4
    move-exception v0

    .line 1342
    goto :goto_15

    .line 1343
    :catch_5
    move-exception v0

    .line 1344
    goto :goto_16

    .line 1345
    :goto_15
    new-instance v1, Ljava/lang/RuntimeException;

    .line 1346
    .line 1347
    invoke-direct {v1, v0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/Throwable;)V

    .line 1348
    .line 1349
    .line 1350
    invoke-virtual {v2, v1}, Laq/t;->n(Ljava/lang/Exception;)V

    .line 1351
    .line 1352
    .line 1353
    goto :goto_17

    .line 1354
    :goto_16
    invoke-virtual {v2, v0}, Laq/t;->n(Ljava/lang/Exception;)V

    .line 1355
    .line 1356
    .line 1357
    :goto_17
    return-void

    .line 1358
    :pswitch_14
    iget-object v0, v1, Lk0/g;->f:Ljava/lang/Object;

    .line 1359
    .line 1360
    check-cast v0, Laq/q;

    .line 1361
    .line 1362
    iget-object v2, v0, Laq/q;->f:Ljava/lang/Object;

    .line 1363
    .line 1364
    monitor-enter v2

    .line 1365
    :try_start_a
    iget-object v0, v1, Lk0/g;->f:Ljava/lang/Object;

    .line 1366
    .line 1367
    check-cast v0, Laq/q;

    .line 1368
    .line 1369
    iget-object v0, v0, Laq/q;->g:Ljava/lang/Object;

    .line 1370
    .line 1371
    check-cast v0, Laq/g;

    .line 1372
    .line 1373
    iget-object v1, v1, Lk0/g;->e:Ljava/lang/Object;

    .line 1374
    .line 1375
    check-cast v1, Laq/j;

    .line 1376
    .line 1377
    invoke-virtual {v1}, Laq/j;->g()Ljava/lang/Object;

    .line 1378
    .line 1379
    .line 1380
    move-result-object v1

    .line 1381
    invoke-interface {v0, v1}, Laq/g;->c(Ljava/lang/Object;)V

    .line 1382
    .line 1383
    .line 1384
    monitor-exit v2

    .line 1385
    return-void

    .line 1386
    :catchall_5
    move-exception v0

    .line 1387
    monitor-exit v2
    :try_end_a
    .catchall {:try_start_a .. :try_end_a} :catchall_5

    .line 1388
    throw v0

    .line 1389
    :pswitch_15
    iget-object v0, v1, Lk0/g;->f:Ljava/lang/Object;

    .line 1390
    .line 1391
    check-cast v0, Laq/q;

    .line 1392
    .line 1393
    iget-object v2, v0, Laq/q;->f:Ljava/lang/Object;

    .line 1394
    .line 1395
    monitor-enter v2

    .line 1396
    :try_start_b
    iget-object v0, v1, Lk0/g;->f:Ljava/lang/Object;

    .line 1397
    .line 1398
    check-cast v0, Laq/q;

    .line 1399
    .line 1400
    iget-object v0, v0, Laq/q;->g:Ljava/lang/Object;

    .line 1401
    .line 1402
    check-cast v0, Laq/e;

    .line 1403
    .line 1404
    iget-object v1, v1, Lk0/g;->e:Ljava/lang/Object;

    .line 1405
    .line 1406
    check-cast v1, Laq/j;

    .line 1407
    .line 1408
    invoke-interface {v0, v1}, Laq/e;->onComplete(Laq/j;)V

    .line 1409
    .line 1410
    .line 1411
    monitor-exit v2

    .line 1412
    return-void

    .line 1413
    :catchall_6
    move-exception v0

    .line 1414
    monitor-exit v2
    :try_end_b
    .catchall {:try_start_b .. :try_end_b} :catchall_6

    .line 1415
    throw v0

    .line 1416
    :pswitch_16
    iget-object v0, v1, Lk0/g;->e:Ljava/lang/Object;

    .line 1417
    .line 1418
    check-cast v0, Laq/j;

    .line 1419
    .line 1420
    check-cast v0, Laq/t;

    .line 1421
    .line 1422
    iget-boolean v0, v0, Laq/t;->d:Z

    .line 1423
    .line 1424
    if-eqz v0, :cond_2a

    .line 1425
    .line 1426
    iget-object v0, v1, Lk0/g;->f:Ljava/lang/Object;

    .line 1427
    .line 1428
    check-cast v0, Laq/o;

    .line 1429
    .line 1430
    iget-object v0, v0, Laq/o;->g:Laq/t;

    .line 1431
    .line 1432
    invoke-virtual {v0}, Laq/t;->p()V

    .line 1433
    .line 1434
    .line 1435
    goto :goto_1a

    .line 1436
    :cond_2a
    :try_start_c
    iget-object v0, v1, Lk0/g;->f:Ljava/lang/Object;

    .line 1437
    .line 1438
    check-cast v0, Laq/o;

    .line 1439
    .line 1440
    iget-object v0, v0, Laq/o;->f:Laq/b;

    .line 1441
    .line 1442
    iget-object v2, v1, Lk0/g;->e:Ljava/lang/Object;

    .line 1443
    .line 1444
    check-cast v2, Laq/j;

    .line 1445
    .line 1446
    invoke-interface {v0, v2}, Laq/b;->w(Laq/j;)Ljava/lang/Object;

    .line 1447
    .line 1448
    .line 1449
    move-result-object v0
    :try_end_c
    .catch Laq/h; {:try_start_c .. :try_end_c} :catch_7
    .catch Ljava/lang/Exception; {:try_start_c .. :try_end_c} :catch_6

    .line 1450
    iget-object v1, v1, Lk0/g;->f:Ljava/lang/Object;

    .line 1451
    .line 1452
    check-cast v1, Laq/o;

    .line 1453
    .line 1454
    iget-object v1, v1, Laq/o;->g:Laq/t;

    .line 1455
    .line 1456
    invoke-virtual {v1, v0}, Laq/t;->o(Ljava/lang/Object;)V

    .line 1457
    .line 1458
    .line 1459
    goto :goto_1a

    .line 1460
    :catch_6
    move-exception v0

    .line 1461
    goto :goto_18

    .line 1462
    :catch_7
    move-exception v0

    .line 1463
    goto :goto_19

    .line 1464
    :goto_18
    iget-object v1, v1, Lk0/g;->f:Ljava/lang/Object;

    .line 1465
    .line 1466
    check-cast v1, Laq/o;

    .line 1467
    .line 1468
    iget-object v1, v1, Laq/o;->g:Laq/t;

    .line 1469
    .line 1470
    invoke-virtual {v1, v0}, Laq/t;->n(Ljava/lang/Exception;)V

    .line 1471
    .line 1472
    .line 1473
    goto :goto_1a

    .line 1474
    :goto_19
    invoke-virtual {v0}, Ljava/lang/Throwable;->getCause()Ljava/lang/Throwable;

    .line 1475
    .line 1476
    .line 1477
    move-result-object v2

    .line 1478
    instance-of v2, v2, Ljava/lang/Exception;

    .line 1479
    .line 1480
    if-eqz v2, :cond_2b

    .line 1481
    .line 1482
    iget-object v1, v1, Lk0/g;->f:Ljava/lang/Object;

    .line 1483
    .line 1484
    check-cast v1, Laq/o;

    .line 1485
    .line 1486
    iget-object v1, v1, Laq/o;->g:Laq/t;

    .line 1487
    .line 1488
    invoke-virtual {v0}, Ljava/lang/Throwable;->getCause()Ljava/lang/Throwable;

    .line 1489
    .line 1490
    .line 1491
    move-result-object v0

    .line 1492
    check-cast v0, Ljava/lang/Exception;

    .line 1493
    .line 1494
    invoke-virtual {v1, v0}, Laq/t;->n(Ljava/lang/Exception;)V

    .line 1495
    .line 1496
    .line 1497
    goto :goto_1a

    .line 1498
    :cond_2b
    iget-object v1, v1, Lk0/g;->f:Ljava/lang/Object;

    .line 1499
    .line 1500
    check-cast v1, Laq/o;

    .line 1501
    .line 1502
    iget-object v1, v1, Laq/o;->g:Laq/t;

    .line 1503
    .line 1504
    invoke-virtual {v1, v0}, Laq/t;->n(Ljava/lang/Exception;)V

    .line 1505
    .line 1506
    .line 1507
    :goto_1a
    return-void

    .line 1508
    :pswitch_17
    iget-object v0, v1, Lk0/g;->f:Ljava/lang/Object;

    .line 1509
    .line 1510
    move-object v2, v0

    .line 1511
    check-cast v2, Lk0/c;

    .line 1512
    .line 1513
    :try_start_d
    iget-object v0, v1, Lk0/g;->e:Ljava/lang/Object;

    .line 1514
    .line 1515
    check-cast v0, Ljava/util/concurrent/Future;

    .line 1516
    .line 1517
    invoke-static {v0}, Lk0/h;->a(Ljava/util/concurrent/Future;)Ljava/lang/Object;

    .line 1518
    .line 1519
    .line 1520
    move-result-object v0
    :try_end_d
    .catch Ljava/util/concurrent/ExecutionException; {:try_start_d .. :try_end_d} :catch_9
    .catch Ljava/lang/RuntimeException; {:try_start_d .. :try_end_d} :catch_8
    .catch Ljava/lang/Error; {:try_start_d .. :try_end_d} :catch_8

    .line 1521
    invoke-interface {v2, v0}, Lk0/c;->c(Ljava/lang/Object;)V

    .line 1522
    .line 1523
    .line 1524
    goto :goto_1d

    .line 1525
    :catch_8
    move-exception v0

    .line 1526
    goto :goto_1b

    .line 1527
    :catch_9
    move-exception v0

    .line 1528
    goto :goto_1c

    .line 1529
    :goto_1b
    invoke-interface {v2, v0}, Lk0/c;->y(Ljava/lang/Throwable;)V

    .line 1530
    .line 1531
    .line 1532
    goto :goto_1d

    .line 1533
    :goto_1c
    invoke-virtual {v0}, Ljava/lang/Throwable;->getCause()Ljava/lang/Throwable;

    .line 1534
    .line 1535
    .line 1536
    move-result-object v1

    .line 1537
    if-nez v1, :cond_2c

    .line 1538
    .line 1539
    invoke-interface {v2, v0}, Lk0/c;->y(Ljava/lang/Throwable;)V

    .line 1540
    .line 1541
    .line 1542
    goto :goto_1d

    .line 1543
    :cond_2c
    invoke-interface {v2, v1}, Lk0/c;->y(Ljava/lang/Throwable;)V

    .line 1544
    .line 1545
    .line 1546
    :goto_1d
    return-void

    .line 1547
    :pswitch_data_0
    .packed-switch 0x0
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
        :pswitch_8
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public toString()Ljava/lang/String;
    .locals 2

    .line 1
    iget v0, p0, Lk0/g;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-super {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    return-object p0

    .line 11
    :pswitch_0
    new-instance v0, Ljava/lang/StringBuilder;

    .line 12
    .line 13
    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    .line 14
    .line 15
    .line 16
    const-class v1, Lk0/g;

    .line 17
    .line 18
    invoke-virtual {v1}, Ljava/lang/Class;->getSimpleName()Ljava/lang/String;

    .line 19
    .line 20
    .line 21
    move-result-object v1

    .line 22
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 23
    .line 24
    .line 25
    const-string v1, ","

    .line 26
    .line 27
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 28
    .line 29
    .line 30
    iget-object p0, p0, Lk0/g;->f:Ljava/lang/Object;

    .line 31
    .line 32
    check-cast p0, Lk0/c;

    .line 33
    .line 34
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 35
    .line 36
    .line 37
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 38
    .line 39
    .line 40
    move-result-object p0

    .line 41
    return-object p0

    .line 42
    nop

    .line 43
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
