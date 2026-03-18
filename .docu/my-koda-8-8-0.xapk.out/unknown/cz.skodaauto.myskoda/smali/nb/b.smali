.class public final Lnb/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/lang/Runnable;


# static fields
.field public static final h:Ljava/lang/String;

.field public static final i:J


# instance fields
.field public final d:Landroid/content/Context;

.field public final e:Lfb/u;

.field public final f:Lj1/a;

.field public g:I


# direct methods
.method static constructor <clinit>()V
    .locals 3

    .line 1
    const-string v0, "ForceStopRunnable"

    .line 2
    .line 3
    invoke-static {v0}, Leb/w;->f(Ljava/lang/String;)Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    sput-object v0, Lnb/b;->h:Ljava/lang/String;

    .line 8
    .line 9
    sget-object v0, Ljava/util/concurrent/TimeUnit;->DAYS:Ljava/util/concurrent/TimeUnit;

    .line 10
    .line 11
    const-wide/16 v1, 0xe42

    .line 12
    .line 13
    invoke-virtual {v0, v1, v2}, Ljava/util/concurrent/TimeUnit;->toMillis(J)J

    .line 14
    .line 15
    .line 16
    move-result-wide v0

    .line 17
    sput-wide v0, Lnb/b;->i:J

    .line 18
    .line 19
    return-void
.end method

.method public constructor <init>(Landroid/content/Context;Lfb/u;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    invoke-virtual {p1}, Landroid/content/Context;->getApplicationContext()Landroid/content/Context;

    .line 5
    .line 6
    .line 7
    move-result-object p1

    .line 8
    iput-object p1, p0, Lnb/b;->d:Landroid/content/Context;

    .line 9
    .line 10
    iput-object p2, p0, Lnb/b;->e:Lfb/u;

    .line 11
    .line 12
    iget-object p1, p2, Lfb/u;->g:Lj1/a;

    .line 13
    .line 14
    iput-object p1, p0, Lnb/b;->f:Lj1/a;

    .line 15
    .line 16
    const/4 p1, 0x0

    .line 17
    iput p1, p0, Lnb/b;->g:I

    .line 18
    .line 19
    return-void
.end method

.method public static c(Landroid/content/Context;)V
    .locals 5

    .line 1
    const-string v0, "alarm"

    .line 2
    .line 3
    invoke-virtual {p0, v0}, Landroid/content/Context;->getSystemService(Ljava/lang/String;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, Landroid/app/AlarmManager;

    .line 8
    .line 9
    sget v1, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 10
    .line 11
    const/16 v2, 0x1f

    .line 12
    .line 13
    if-lt v1, v2, :cond_0

    .line 14
    .line 15
    const/high16 v1, 0xa000000

    .line 16
    .line 17
    goto :goto_0

    .line 18
    :cond_0
    const/high16 v1, 0x8000000

    .line 19
    .line 20
    :goto_0
    new-instance v2, Landroid/content/Intent;

    .line 21
    .line 22
    invoke-direct {v2}, Landroid/content/Intent;-><init>()V

    .line 23
    .line 24
    .line 25
    new-instance v3, Landroid/content/ComponentName;

    .line 26
    .line 27
    const-class v4, Landroidx/work/impl/utils/ForceStopRunnable$BroadcastReceiver;

    .line 28
    .line 29
    invoke-direct {v3, p0, v4}, Landroid/content/ComponentName;-><init>(Landroid/content/Context;Ljava/lang/Class;)V

    .line 30
    .line 31
    .line 32
    invoke-virtual {v2, v3}, Landroid/content/Intent;->setComponent(Landroid/content/ComponentName;)Landroid/content/Intent;

    .line 33
    .line 34
    .line 35
    const-string v3, "ACTION_FORCE_STOP_RESCHEDULE"

    .line 36
    .line 37
    invoke-virtual {v2, v3}, Landroid/content/Intent;->setAction(Ljava/lang/String;)Landroid/content/Intent;

    .line 38
    .line 39
    .line 40
    const/4 v3, -0x1

    .line 41
    invoke-static {p0, v3, v2, v1}, Landroid/app/PendingIntent;->getBroadcast(Landroid/content/Context;ILandroid/content/Intent;I)Landroid/app/PendingIntent;

    .line 42
    .line 43
    .line 44
    move-result-object p0

    .line 45
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    .line 46
    .line 47
    .line 48
    move-result-wide v1

    .line 49
    sget-wide v3, Lnb/b;->i:J

    .line 50
    .line 51
    add-long/2addr v1, v3

    .line 52
    if-eqz v0, :cond_1

    .line 53
    .line 54
    const/4 v3, 0x0

    .line 55
    invoke-virtual {v0, v3, v1, v2, p0}, Landroid/app/AlarmManager;->setExact(IJLandroid/app/PendingIntent;)V

    .line 56
    .line 57
    .line 58
    :cond_1
    return-void
.end method


# virtual methods
.method public final a()V
    .locals 18

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    const-string v1, "last_force_stop_ms"

    .line 4
    .line 5
    iget-object v2, v0, Lnb/b;->f:Lj1/a;

    .line 6
    .line 7
    iget-object v3, v0, Lnb/b;->e:Lfb/u;

    .line 8
    .line 9
    iget-object v4, v3, Lfb/u;->c:Landroidx/work/impl/WorkDatabase;

    .line 10
    .line 11
    iget-object v5, v3, Lfb/u;->b:Leb/b;

    .line 12
    .line 13
    iget-object v6, v3, Lfb/u;->g:Lj1/a;

    .line 14
    .line 15
    iget-object v7, v3, Lfb/u;->c:Landroidx/work/impl/WorkDatabase;

    .line 16
    .line 17
    sget-object v8, Lhb/c;->i:Ljava/lang/String;

    .line 18
    .line 19
    iget-object v0, v0, Lnb/b;->d:Landroid/content/Context;

    .line 20
    .line 21
    invoke-static {v0}, Lhb/a;->b(Landroid/content/Context;)Landroid/app/job/JobScheduler;

    .line 22
    .line 23
    .line 24
    move-result-object v8

    .line 25
    invoke-static {v0, v8}, Lhb/c;->d(Landroid/content/Context;Landroid/app/job/JobScheduler;)Ljava/util/ArrayList;

    .line 26
    .line 27
    .line 28
    move-result-object v9

    .line 29
    invoke-virtual {v4}, Landroidx/work/impl/WorkDatabase;->u()Lmb/h;

    .line 30
    .line 31
    .line 32
    move-result-object v10

    .line 33
    iget-object v10, v10, Lmb/h;->a:Lla/u;

    .line 34
    .line 35
    new-instance v11, Lm40/e;

    .line 36
    .line 37
    const/16 v12, 0xa

    .line 38
    .line 39
    invoke-direct {v11, v12}, Lm40/e;-><init>(I)V

    .line 40
    .line 41
    .line 42
    const/4 v13, 0x1

    .line 43
    const/4 v14, 0x0

    .line 44
    invoke-static {v10, v13, v14, v11}, Ljp/ue;->f(Lla/u;ZZLay0/k;)Ljava/lang/Object;

    .line 45
    .line 46
    .line 47
    move-result-object v10

    .line 48
    check-cast v10, Ljava/util/List;

    .line 49
    .line 50
    if-eqz v9, :cond_0

    .line 51
    .line 52
    invoke-virtual {v9}, Ljava/util/ArrayList;->size()I

    .line 53
    .line 54
    .line 55
    move-result v11

    .line 56
    goto :goto_0

    .line 57
    :cond_0
    move v11, v14

    .line 58
    :goto_0
    new-instance v15, Ljava/util/HashSet;

    .line 59
    .line 60
    invoke-direct {v15, v11}, Ljava/util/HashSet;-><init>(I)V

    .line 61
    .line 62
    .line 63
    if-eqz v9, :cond_2

    .line 64
    .line 65
    invoke-virtual {v9}, Ljava/util/ArrayList;->isEmpty()Z

    .line 66
    .line 67
    .line 68
    move-result v11

    .line 69
    if-nez v11, :cond_2

    .line 70
    .line 71
    invoke-virtual {v9}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 72
    .line 73
    .line 74
    move-result-object v9

    .line 75
    :goto_1
    invoke-interface {v9}, Ljava/util/Iterator;->hasNext()Z

    .line 76
    .line 77
    .line 78
    move-result v11

    .line 79
    if-eqz v11, :cond_2

    .line 80
    .line 81
    invoke-interface {v9}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 82
    .line 83
    .line 84
    move-result-object v11

    .line 85
    check-cast v11, Landroid/app/job/JobInfo;

    .line 86
    .line 87
    invoke-static {v11}, Lhb/c;->f(Landroid/app/job/JobInfo;)Lmb/i;

    .line 88
    .line 89
    .line 90
    move-result-object v12

    .line 91
    if-eqz v12, :cond_1

    .line 92
    .line 93
    iget-object v11, v12, Lmb/i;->a:Ljava/lang/String;

    .line 94
    .line 95
    invoke-virtual {v15, v11}, Ljava/util/HashSet;->add(Ljava/lang/Object;)Z

    .line 96
    .line 97
    .line 98
    goto :goto_2

    .line 99
    :cond_1
    invoke-virtual {v11}, Landroid/app/job/JobInfo;->getId()I

    .line 100
    .line 101
    .line 102
    move-result v11

    .line 103
    invoke-static {v8, v11}, Lhb/c;->b(Landroid/app/job/JobScheduler;I)V

    .line 104
    .line 105
    .line 106
    :goto_2
    const/16 v12, 0xa

    .line 107
    .line 108
    goto :goto_1

    .line 109
    :cond_2
    invoke-interface {v10}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 110
    .line 111
    .line 112
    move-result-object v8

    .line 113
    :cond_3
    invoke-interface {v8}, Ljava/util/Iterator;->hasNext()Z

    .line 114
    .line 115
    .line 116
    move-result v9

    .line 117
    if-eqz v9, :cond_4

    .line 118
    .line 119
    invoke-interface {v8}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 120
    .line 121
    .line 122
    move-result-object v9

    .line 123
    check-cast v9, Ljava/lang/String;

    .line 124
    .line 125
    invoke-virtual {v15, v9}, Ljava/util/HashSet;->contains(Ljava/lang/Object;)Z

    .line 126
    .line 127
    .line 128
    move-result v9

    .line 129
    if-nez v9, :cond_3

    .line 130
    .line 131
    invoke-static {}, Leb/w;->d()Leb/w;

    .line 132
    .line 133
    .line 134
    move-result-object v8

    .line 135
    sget-object v9, Lhb/c;->i:Ljava/lang/String;

    .line 136
    .line 137
    const-string v11, "Reconciling jobs"

    .line 138
    .line 139
    invoke-virtual {v8, v9, v11}, Leb/w;->a(Ljava/lang/String;Ljava/lang/String;)V

    .line 140
    .line 141
    .line 142
    move v8, v13

    .line 143
    goto :goto_3

    .line 144
    :cond_4
    move v8, v14

    .line 145
    :goto_3
    const-wide/16 v11, -0x1

    .line 146
    .line 147
    if-eqz v8, :cond_6

    .line 148
    .line 149
    invoke-virtual {v4}, Lla/u;->c()V

    .line 150
    .line 151
    .line 152
    :try_start_0
    invoke-virtual {v4}, Landroidx/work/impl/WorkDatabase;->x()Lmb/s;

    .line 153
    .line 154
    .line 155
    move-result-object v9

    .line 156
    invoke-interface {v10}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 157
    .line 158
    .line 159
    move-result-object v10

    .line 160
    :goto_4
    invoke-interface {v10}, Ljava/util/Iterator;->hasNext()Z

    .line 161
    .line 162
    .line 163
    move-result v15

    .line 164
    if-eqz v15, :cond_5

    .line 165
    .line 166
    invoke-interface {v10}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 167
    .line 168
    .line 169
    move-result-object v15

    .line 170
    check-cast v15, Ljava/lang/String;

    .line 171
    .line 172
    invoke-virtual {v9, v11, v12, v15}, Lmb/s;->g(JLjava/lang/String;)I

    .line 173
    .line 174
    .line 175
    goto :goto_4

    .line 176
    :catchall_0
    move-exception v0

    .line 177
    goto :goto_5

    .line 178
    :cond_5
    invoke-virtual {v4}, Lla/u;->q()V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 179
    .line 180
    .line 181
    invoke-virtual {v4}, Lla/u;->g()V

    .line 182
    .line 183
    .line 184
    goto :goto_6

    .line 185
    :goto_5
    invoke-virtual {v4}, Lla/u;->g()V

    .line 186
    .line 187
    .line 188
    throw v0

    .line 189
    :cond_6
    :goto_6
    invoke-virtual {v7}, Landroidx/work/impl/WorkDatabase;->x()Lmb/s;

    .line 190
    .line 191
    .line 192
    move-result-object v4

    .line 193
    invoke-virtual {v7}, Landroidx/work/impl/WorkDatabase;->w()Lmb/l;

    .line 194
    .line 195
    .line 196
    move-result-object v9

    .line 197
    invoke-virtual {v7}, Lla/u;->c()V

    .line 198
    .line 199
    .line 200
    :try_start_1
    iget-object v10, v4, Lmb/s;->a:Lla/u;

    .line 201
    .line 202
    new-instance v15, Lm40/e;

    .line 203
    .line 204
    const/16 v11, 0xd

    .line 205
    .line 206
    invoke-direct {v15, v11}, Lm40/e;-><init>(I)V

    .line 207
    .line 208
    .line 209
    invoke-static {v10, v13, v14, v15}, Ljp/ue;->f(Lla/u;ZZLay0/k;)Ljava/lang/Object;

    .line 210
    .line 211
    .line 212
    move-result-object v10

    .line 213
    check-cast v10, Ljava/util/List;

    .line 214
    .line 215
    if-eqz v10, :cond_7

    .line 216
    .line 217
    invoke-interface {v10}, Ljava/util/List;->isEmpty()Z

    .line 218
    .line 219
    .line 220
    move-result v11

    .line 221
    if-nez v11, :cond_7

    .line 222
    .line 223
    move v11, v13

    .line 224
    goto :goto_7

    .line 225
    :catchall_1
    move-exception v0

    .line 226
    goto/16 :goto_10

    .line 227
    .line 228
    :cond_7
    move v11, v14

    .line 229
    :goto_7
    if-eqz v11, :cond_8

    .line 230
    .line 231
    invoke-interface {v10}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 232
    .line 233
    .line 234
    move-result-object v10

    .line 235
    :goto_8
    invoke-interface {v10}, Ljava/util/Iterator;->hasNext()Z

    .line 236
    .line 237
    .line 238
    move-result v12

    .line 239
    if-eqz v12, :cond_8

    .line 240
    .line 241
    invoke-interface {v10}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 242
    .line 243
    .line 244
    move-result-object v12

    .line 245
    check-cast v12, Lmb/o;

    .line 246
    .line 247
    sget-object v15, Leb/h0;->d:Leb/h0;

    .line 248
    .line 249
    iget-object v12, v12, Lmb/o;->a:Ljava/lang/String;

    .line 250
    .line 251
    invoke-virtual {v4, v15, v12}, Lmb/s;->j(Leb/h0;Ljava/lang/String;)I

    .line 252
    .line 253
    .line 254
    const/16 v15, -0x200

    .line 255
    .line 256
    invoke-virtual {v4, v15, v12}, Lmb/s;->k(ILjava/lang/String;)V

    .line 257
    .line 258
    .line 259
    const-wide/16 v13, -0x1

    .line 260
    .line 261
    invoke-virtual {v4, v13, v14, v12}, Lmb/s;->g(JLjava/lang/String;)I

    .line 262
    .line 263
    .line 264
    const/4 v13, 0x1

    .line 265
    const/4 v14, 0x0

    .line 266
    goto :goto_8

    .line 267
    :cond_8
    iget-object v4, v9, Lmb/l;->a:Lla/u;

    .line 268
    .line 269
    new-instance v9, Lm40/e;

    .line 270
    .line 271
    const/16 v10, 0xb

    .line 272
    .line 273
    invoke-direct {v9, v10}, Lm40/e;-><init>(I)V

    .line 274
    .line 275
    .line 276
    const/4 v10, 0x0

    .line 277
    const/4 v15, 0x1

    .line 278
    invoke-static {v4, v10, v15, v9}, Ljp/ue;->f(Lla/u;ZZLay0/k;)Ljava/lang/Object;

    .line 279
    .line 280
    .line 281
    invoke-virtual {v7}, Lla/u;->q()V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 282
    .line 283
    .line 284
    invoke-virtual {v7}, Lla/u;->g()V

    .line 285
    .line 286
    .line 287
    if-nez v11, :cond_a

    .line 288
    .line 289
    if-eqz v8, :cond_9

    .line 290
    .line 291
    goto :goto_9

    .line 292
    :cond_9
    move v13, v10

    .line 293
    goto :goto_a

    .line 294
    :cond_a
    :goto_9
    move v13, v15

    .line 295
    :goto_a
    iget-object v4, v6, Lj1/a;->e:Ljava/lang/Object;

    .line 296
    .line 297
    check-cast v4, Landroidx/work/impl/WorkDatabase;

    .line 298
    .line 299
    invoke-virtual {v4}, Landroidx/work/impl/WorkDatabase;->t()Lmb/d;

    .line 300
    .line 301
    .line 302
    move-result-object v4

    .line 303
    const-string v8, "reschedule_needed"

    .line 304
    .line 305
    invoke-virtual {v4, v8}, Lmb/d;->a(Ljava/lang/String;)Ljava/lang/Long;

    .line 306
    .line 307
    .line 308
    move-result-object v4

    .line 309
    const-wide/16 v11, 0x0

    .line 310
    .line 311
    sget-object v9, Lnb/b;->h:Ljava/lang/String;

    .line 312
    .line 313
    if-eqz v4, :cond_b

    .line 314
    .line 315
    invoke-virtual {v4}, Ljava/lang/Long;->longValue()J

    .line 316
    .line 317
    .line 318
    move-result-wide v14

    .line 319
    const-wide/16 v16, 0x1

    .line 320
    .line 321
    cmp-long v4, v14, v16

    .line 322
    .line 323
    if-nez v4, :cond_b

    .line 324
    .line 325
    invoke-static {}, Leb/w;->d()Leb/w;

    .line 326
    .line 327
    .line 328
    move-result-object v0

    .line 329
    const-string v1, "Rescheduling Workers."

    .line 330
    .line 331
    invoke-virtual {v0, v9, v1}, Leb/w;->a(Ljava/lang/String;Ljava/lang/String;)V

    .line 332
    .line 333
    .line 334
    invoke-virtual {v3}, Lfb/u;->h()V

    .line 335
    .line 336
    .line 337
    invoke-virtual {v6}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 338
    .line 339
    .line 340
    new-instance v0, Lmb/c;

    .line 341
    .line 342
    invoke-static {v11, v12}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 343
    .line 344
    .line 345
    move-result-object v1

    .line 346
    invoke-direct {v0, v8, v1}, Lmb/c;-><init>(Ljava/lang/String;Ljava/lang/Long;)V

    .line 347
    .line 348
    .line 349
    iget-object v1, v6, Lj1/a;->e:Ljava/lang/Object;

    .line 350
    .line 351
    check-cast v1, Landroidx/work/impl/WorkDatabase;

    .line 352
    .line 353
    invoke-virtual {v1}, Landroidx/work/impl/WorkDatabase;->t()Lmb/d;

    .line 354
    .line 355
    .line 356
    move-result-object v1

    .line 357
    invoke-virtual {v1, v0}, Lmb/d;->b(Lmb/c;)V

    .line 358
    .line 359
    .line 360
    return-void

    .line 361
    :cond_b
    :try_start_2
    sget v4, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 362
    .line 363
    const/16 v6, 0x1f

    .line 364
    .line 365
    if-lt v4, v6, :cond_c

    .line 366
    .line 367
    const/high16 v6, 0x22000000

    .line 368
    .line 369
    goto :goto_b

    .line 370
    :cond_c
    const/high16 v6, 0x20000000

    .line 371
    .line 372
    :goto_b
    new-instance v8, Landroid/content/Intent;

    .line 373
    .line 374
    invoke-direct {v8}, Landroid/content/Intent;-><init>()V

    .line 375
    .line 376
    .line 377
    new-instance v14, Landroid/content/ComponentName;

    .line 378
    .line 379
    const-class v15, Landroidx/work/impl/utils/ForceStopRunnable$BroadcastReceiver;

    .line 380
    .line 381
    invoke-direct {v14, v0, v15}, Landroid/content/ComponentName;-><init>(Landroid/content/Context;Ljava/lang/Class;)V

    .line 382
    .line 383
    .line 384
    invoke-virtual {v8, v14}, Landroid/content/Intent;->setComponent(Landroid/content/ComponentName;)Landroid/content/Intent;

    .line 385
    .line 386
    .line 387
    const-string v14, "ACTION_FORCE_STOP_RESCHEDULE"

    .line 388
    .line 389
    invoke-virtual {v8, v14}, Landroid/content/Intent;->setAction(Ljava/lang/String;)Landroid/content/Intent;

    .line 390
    .line 391
    .line 392
    const/4 v14, -0x1

    .line 393
    invoke-static {v0, v14, v8, v6}, Landroid/app/PendingIntent;->getBroadcast(Landroid/content/Context;ILandroid/content/Intent;I)Landroid/app/PendingIntent;

    .line 394
    .line 395
    .line 396
    move-result-object v6

    .line 397
    const/16 v8, 0x1e

    .line 398
    .line 399
    if-lt v4, v8, :cond_10

    .line 400
    .line 401
    if-eqz v6, :cond_d

    .line 402
    .line 403
    invoke-virtual {v6}, Landroid/app/PendingIntent;->cancel()V

    .line 404
    .line 405
    .line 406
    goto :goto_c

    .line 407
    :catch_0
    move-exception v0

    .line 408
    goto :goto_e

    .line 409
    :cond_d
    :goto_c
    const-string v4, "activity"

    .line 410
    .line 411
    invoke-virtual {v0, v4}, Landroid/content/Context;->getSystemService(Ljava/lang/String;)Ljava/lang/Object;

    .line 412
    .line 413
    .line 414
    move-result-object v0

    .line 415
    check-cast v0, Landroid/app/ActivityManager;

    .line 416
    .line 417
    invoke-static {v0}, Ln01/a;->i(Landroid/app/ActivityManager;)Ljava/util/List;

    .line 418
    .line 419
    .line 420
    move-result-object v0

    .line 421
    if-eqz v0, :cond_11

    .line 422
    .line 423
    invoke-interface {v0}, Ljava/util/List;->isEmpty()Z

    .line 424
    .line 425
    .line 426
    move-result v4

    .line 427
    if-nez v4, :cond_11

    .line 428
    .line 429
    iget-object v4, v2, Lj1/a;->e:Ljava/lang/Object;

    .line 430
    .line 431
    check-cast v4, Landroidx/work/impl/WorkDatabase;

    .line 432
    .line 433
    invoke-virtual {v4}, Landroidx/work/impl/WorkDatabase;->t()Lmb/d;

    .line 434
    .line 435
    .line 436
    move-result-object v4

    .line 437
    invoke-virtual {v4, v1}, Lmb/d;->a(Ljava/lang/String;)Ljava/lang/Long;

    .line 438
    .line 439
    .line 440
    move-result-object v4

    .line 441
    if-eqz v4, :cond_e

    .line 442
    .line 443
    invoke-virtual {v4}, Ljava/lang/Long;->longValue()J

    .line 444
    .line 445
    .line 446
    move-result-wide v11

    .line 447
    :cond_e
    move v14, v10

    .line 448
    :goto_d
    invoke-interface {v0}, Ljava/util/List;->size()I

    .line 449
    .line 450
    .line 451
    move-result v4

    .line 452
    if-ge v14, v4, :cond_11

    .line 453
    .line 454
    invoke-interface {v0, v14}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 455
    .line 456
    .line 457
    move-result-object v4

    .line 458
    invoke-static {v4}, Ln01/a;->e(Ljava/lang/Object;)Landroid/app/ApplicationExitInfo;

    .line 459
    .line 460
    .line 461
    move-result-object v4

    .line 462
    invoke-static {v4}, Ln01/a;->b(Landroid/app/ApplicationExitInfo;)I

    .line 463
    .line 464
    .line 465
    move-result v6

    .line 466
    const/16 v8, 0xa

    .line 467
    .line 468
    if-ne v6, v8, :cond_f

    .line 469
    .line 470
    invoke-static {v4}, Ln01/a;->d(Landroid/app/ApplicationExitInfo;)J

    .line 471
    .line 472
    .line 473
    move-result-wide v15

    .line 474
    cmp-long v4, v15, v11

    .line 475
    .line 476
    if-ltz v4, :cond_f

    .line 477
    .line 478
    goto :goto_f

    .line 479
    :cond_f
    add-int/lit8 v14, v14, 0x1

    .line 480
    .line 481
    goto :goto_d

    .line 482
    :cond_10
    if-nez v6, :cond_11

    .line 483
    .line 484
    invoke-static {v0}, Lnb/b;->c(Landroid/content/Context;)V
    :try_end_2
    .catch Ljava/lang/SecurityException; {:try_start_2 .. :try_end_2} :catch_0
    .catch Ljava/lang/IllegalArgumentException; {:try_start_2 .. :try_end_2} :catch_0

    .line 485
    .line 486
    .line 487
    goto :goto_f

    .line 488
    :cond_11
    if-eqz v13, :cond_12

    .line 489
    .line 490
    invoke-static {}, Leb/w;->d()Leb/w;

    .line 491
    .line 492
    .line 493
    move-result-object v0

    .line 494
    const-string v1, "Found unfinished work, scheduling it."

    .line 495
    .line 496
    invoke-virtual {v0, v9, v1}, Leb/w;->a(Ljava/lang/String;Ljava/lang/String;)V

    .line 497
    .line 498
    .line 499
    iget-object v0, v3, Lfb/u;->e:Ljava/util/List;

    .line 500
    .line 501
    invoke-static {v5, v7, v0}, Lfb/i;->b(Leb/b;Landroidx/work/impl/WorkDatabase;Ljava/util/List;)V

    .line 502
    .line 503
    .line 504
    :cond_12
    return-void

    .line 505
    :goto_e
    invoke-static {}, Leb/w;->d()Leb/w;

    .line 506
    .line 507
    .line 508
    move-result-object v4

    .line 509
    iget v4, v4, Leb/w;->a:I

    .line 510
    .line 511
    const/4 v6, 0x5

    .line 512
    if-gt v4, v6, :cond_13

    .line 513
    .line 514
    const-string v4, "Ignoring exception"

    .line 515
    .line 516
    invoke-static {v9, v4, v0}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 517
    .line 518
    .line 519
    :cond_13
    :goto_f
    invoke-static {}, Leb/w;->d()Leb/w;

    .line 520
    .line 521
    .line 522
    move-result-object v0

    .line 523
    const-string v4, "Application was force-stopped, rescheduling."

    .line 524
    .line 525
    invoke-virtual {v0, v9, v4}, Leb/w;->a(Ljava/lang/String;Ljava/lang/String;)V

    .line 526
    .line 527
    .line 528
    invoke-virtual {v3}, Lfb/u;->h()V

    .line 529
    .line 530
    .line 531
    iget-object v0, v5, Leb/b;->d:Leb/j;

    .line 532
    .line 533
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 534
    .line 535
    .line 536
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    .line 537
    .line 538
    .line 539
    move-result-wide v3

    .line 540
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 541
    .line 542
    .line 543
    new-instance v0, Lmb/c;

    .line 544
    .line 545
    invoke-static {v3, v4}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 546
    .line 547
    .line 548
    move-result-object v3

    .line 549
    invoke-direct {v0, v1, v3}, Lmb/c;-><init>(Ljava/lang/String;Ljava/lang/Long;)V

    .line 550
    .line 551
    .line 552
    iget-object v1, v2, Lj1/a;->e:Ljava/lang/Object;

    .line 553
    .line 554
    check-cast v1, Landroidx/work/impl/WorkDatabase;

    .line 555
    .line 556
    invoke-virtual {v1}, Landroidx/work/impl/WorkDatabase;->t()Lmb/d;

    .line 557
    .line 558
    .line 559
    move-result-object v1

    .line 560
    invoke-virtual {v1, v0}, Lmb/d;->b(Lmb/c;)V

    .line 561
    .line 562
    .line 563
    return-void

    .line 564
    :goto_10
    invoke-virtual {v7}, Lla/u;->g()V

    .line 565
    .line 566
    .line 567
    throw v0
.end method

.method public final b()Z
    .locals 4

    .line 1
    iget-object v0, p0, Lnb/b;->e:Lfb/u;

    .line 2
    .line 3
    iget-object v0, v0, Lfb/u;->b:Leb/b;

    .line 4
    .line 5
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 6
    .line 7
    .line 8
    const/4 v1, 0x0

    .line 9
    invoke-static {v1}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 10
    .line 11
    .line 12
    move-result v1

    .line 13
    sget-object v2, Lnb/b;->h:Ljava/lang/String;

    .line 14
    .line 15
    if-eqz v1, :cond_0

    .line 16
    .line 17
    invoke-static {}, Leb/w;->d()Leb/w;

    .line 18
    .line 19
    .line 20
    move-result-object p0

    .line 21
    const-string v0, "The default process name was not specified."

    .line 22
    .line 23
    invoke-virtual {p0, v2, v0}, Leb/w;->a(Ljava/lang/String;Ljava/lang/String;)V

    .line 24
    .line 25
    .line 26
    const/4 p0, 0x1

    .line 27
    return p0

    .line 28
    :cond_0
    iget-object p0, p0, Lnb/b;->d:Landroid/content/Context;

    .line 29
    .line 30
    invoke-static {p0, v0}, Lnb/g;->a(Landroid/content/Context;Leb/b;)Z

    .line 31
    .line 32
    .line 33
    move-result p0

    .line 34
    invoke-static {}, Leb/w;->d()Leb/w;

    .line 35
    .line 36
    .line 37
    move-result-object v0

    .line 38
    new-instance v1, Ljava/lang/StringBuilder;

    .line 39
    .line 40
    const-string v3, "Is default app process = "

    .line 41
    .line 42
    invoke-direct {v1, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 43
    .line 44
    .line 45
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 46
    .line 47
    .line 48
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 49
    .line 50
    .line 51
    move-result-object v1

    .line 52
    invoke-virtual {v0, v2, v1}, Leb/w;->a(Ljava/lang/String;Ljava/lang/String;)V

    .line 53
    .line 54
    .line 55
    return p0
.end method

.method public final run()V
    .locals 12

    .line 1
    iget-object v0, p0, Lnb/b;->d:Landroid/content/Context;

    .line 2
    .line 3
    sget-object v1, Lnb/b;->h:Ljava/lang/String;

    .line 4
    .line 5
    iget-object v2, p0, Lnb/b;->e:Lfb/u;

    .line 6
    .line 7
    :try_start_0
    invoke-virtual {p0}, Lnb/b;->b()Z

    .line 8
    .line 9
    .line 10
    move-result v3
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 11
    if-nez v3, :cond_0

    .line 12
    .line 13
    invoke-virtual {v2}, Lfb/u;->g()V

    .line 14
    .line 15
    .line 16
    return-void

    .line 17
    :catch_0
    :cond_0
    :goto_0
    :try_start_1
    invoke-static {v0}, Lkp/w7;->b(Landroid/content/Context;)V
    :try_end_1
    .catch Landroid/database/sqlite/SQLiteException; {:try_start_1 .. :try_end_1} :catch_2
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 18
    .line 19
    .line 20
    :try_start_2
    invoke-static {}, Leb/w;->d()Leb/w;

    .line 21
    .line 22
    .line 23
    move-result-object v3

    .line 24
    const-string v4, "Performing cleanup operations."

    .line 25
    .line 26
    invoke-virtual {v3, v1, v4}, Leb/w;->a(Ljava/lang/String;Ljava/lang/String;)V
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 27
    .line 28
    .line 29
    :try_start_3
    invoke-virtual {p0}, Lnb/b;->a()V
    :try_end_3
    .catch Landroid/database/sqlite/SQLiteAccessPermException; {:try_start_3 .. :try_end_3} :catch_1
    .catch Landroid/database/sqlite/SQLiteCantOpenDatabaseException; {:try_start_3 .. :try_end_3} :catch_1
    .catch Landroid/database/sqlite/SQLiteConstraintException; {:try_start_3 .. :try_end_3} :catch_1
    .catch Landroid/database/sqlite/SQLiteDatabaseCorruptException; {:try_start_3 .. :try_end_3} :catch_1
    .catch Landroid/database/sqlite/SQLiteDatabaseLockedException; {:try_start_3 .. :try_end_3} :catch_1
    .catch Landroid/database/sqlite/SQLiteDiskIOException; {:try_start_3 .. :try_end_3} :catch_1
    .catch Landroid/database/sqlite/SQLiteFullException; {:try_start_3 .. :try_end_3} :catch_1
    .catch Landroid/database/sqlite/SQLiteTableLockedException; {:try_start_3 .. :try_end_3} :catch_1
    .catchall {:try_start_3 .. :try_end_3} :catchall_0

    .line 30
    .line 31
    .line 32
    invoke-virtual {v2}, Lfb/u;->g()V

    .line 33
    .line 34
    .line 35
    return-void

    .line 36
    :catchall_0
    move-exception p0

    .line 37
    goto :goto_2

    .line 38
    :catch_1
    move-exception v3

    .line 39
    :try_start_4
    iget v4, p0, Lnb/b;->g:I

    .line 40
    .line 41
    add-int/lit8 v4, v4, 0x1

    .line 42
    .line 43
    iput v4, p0, Lnb/b;->g:I

    .line 44
    .line 45
    const/4 v5, 0x3

    .line 46
    if-lt v4, v5, :cond_2

    .line 47
    .line 48
    invoke-static {v0}, Llp/yf;->a(Landroid/content/Context;)Z

    .line 49
    .line 50
    .line 51
    move-result p0

    .line 52
    if-eqz p0, :cond_1

    .line 53
    .line 54
    const-string p0, "The file system on the device is in a bad state. WorkManager cannot access the app\'s internal data store."

    .line 55
    .line 56
    goto :goto_1

    .line 57
    :cond_1
    const-string p0, "WorkManager can\'t be accessed from direct boot, because credential encrypted storage isn\'t accessible.\nDon\'t access or initialise WorkManager from directAware components. See https://developer.android.com/training/articles/direct-boot"

    .line 58
    .line 59
    :goto_1
    invoke-static {}, Leb/w;->d()Leb/w;

    .line 60
    .line 61
    .line 62
    move-result-object v0

    .line 63
    invoke-virtual {v0, v1, p0, v3}, Leb/w;->c(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 64
    .line 65
    .line 66
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 67
    .line 68
    invoke-direct {v0, p0, v3}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 69
    .line 70
    .line 71
    iget-object p0, v2, Lfb/u;->b:Leb/b;

    .line 72
    .line 73
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 74
    .line 75
    .line 76
    throw v0

    .line 77
    :cond_2
    int-to-long v6, v4

    .line 78
    const-wide/16 v8, 0x12c

    .line 79
    .line 80
    mul-long/2addr v6, v8

    .line 81
    invoke-static {}, Leb/w;->d()Leb/w;

    .line 82
    .line 83
    .line 84
    move-result-object v4

    .line 85
    new-instance v10, Ljava/lang/StringBuilder;

    .line 86
    .line 87
    invoke-direct {v10}, Ljava/lang/StringBuilder;-><init>()V

    .line 88
    .line 89
    .line 90
    const-string v11, "Retrying after "

    .line 91
    .line 92
    invoke-virtual {v10, v11}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 93
    .line 94
    .line 95
    invoke-virtual {v10, v6, v7}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    .line 96
    .line 97
    .line 98
    invoke-virtual {v10}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 99
    .line 100
    .line 101
    move-result-object v6

    .line 102
    iget v4, v4, Leb/w;->a:I

    .line 103
    .line 104
    if-gt v4, v5, :cond_3

    .line 105
    .line 106
    invoke-static {v1, v6, v3}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 107
    .line 108
    .line 109
    :cond_3
    iget v3, p0, Lnb/b;->g:I
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_0

    .line 110
    .line 111
    int-to-long v3, v3

    .line 112
    mul-long/2addr v3, v8

    .line 113
    :try_start_5
    invoke-static {v3, v4}, Ljava/lang/Thread;->sleep(J)V
    :try_end_5
    .catch Ljava/lang/InterruptedException; {:try_start_5 .. :try_end_5} :catch_0
    .catchall {:try_start_5 .. :try_end_5} :catchall_0

    .line 114
    .line 115
    .line 116
    goto :goto_0

    .line 117
    :catch_2
    move-exception p0

    .line 118
    :try_start_6
    const-string v0, "Unexpected SQLite exception during migrations"

    .line 119
    .line 120
    invoke-static {}, Leb/w;->d()Leb/w;

    .line 121
    .line 122
    .line 123
    move-result-object v3

    .line 124
    invoke-virtual {v3, v1, v0}, Leb/w;->b(Ljava/lang/String;Ljava/lang/String;)V

    .line 125
    .line 126
    .line 127
    new-instance v1, Ljava/lang/IllegalStateException;

    .line 128
    .line 129
    invoke-direct {v1, v0, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 130
    .line 131
    .line 132
    iget-object p0, v2, Lfb/u;->b:Leb/b;

    .line 133
    .line 134
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 135
    .line 136
    .line 137
    throw v1
    :try_end_6
    .catchall {:try_start_6 .. :try_end_6} :catchall_0

    .line 138
    :goto_2
    invoke-virtual {v2}, Lfb/u;->g()V

    .line 139
    .line 140
    .line 141
    throw p0
.end method
