.class public final Lbp0/o;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final d:[J


# instance fields
.field public final a:Landroid/app/NotificationManager;

.field public final b:Lbp0/l;

.field public final c:Lbp0/b;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    const/4 v0, 0x4

    .line 2
    new-array v0, v0, [J

    .line 3
    .line 4
    fill-array-data v0, :array_0

    .line 5
    .line 6
    .line 7
    sput-object v0, Lbp0/o;->d:[J

    .line 8
    .line 9
    return-void

    .line 10
    nop

    .line 11
    :array_0
    .array-data 8
        0x0
        0x12c
        0x12c
        0x64
    .end array-data
.end method

.method public constructor <init>(Landroid/app/NotificationManager;Lbp0/l;Lbp0/b;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lbp0/o;->a:Landroid/app/NotificationManager;

    .line 5
    .line 6
    iput-object p2, p0, Lbp0/o;->b:Lbp0/l;

    .line 7
    .line 8
    iput-object p3, p0, Lbp0/o;->c:Lbp0/b;

    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final a(Lcz/skodaauto/myskoda/library/pushnotifications/system/FirebaseNotificationsService;Lap0/f;Lrx0/c;)Ljava/lang/Object;
    .locals 20

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    move-object/from16 v7, p2

    .line 6
    .line 7
    move-object/from16 v2, p3

    .line 8
    .line 9
    iget-object v3, v0, Lbp0/o;->c:Lbp0/b;

    .line 10
    .line 11
    iget-object v4, v3, Lbp0/b;->a:Lij0/a;

    .line 12
    .line 13
    instance-of v5, v2, Lbp0/n;

    .line 14
    .line 15
    if-eqz v5, :cond_0

    .line 16
    .line 17
    move-object v5, v2

    .line 18
    check-cast v5, Lbp0/n;

    .line 19
    .line 20
    iget v6, v5, Lbp0/n;->i:I

    .line 21
    .line 22
    const/high16 v8, -0x80000000

    .line 23
    .line 24
    and-int v9, v6, v8

    .line 25
    .line 26
    if-eqz v9, :cond_0

    .line 27
    .line 28
    sub-int/2addr v6, v8

    .line 29
    iput v6, v5, Lbp0/n;->i:I

    .line 30
    .line 31
    :goto_0
    move-object v6, v5

    .line 32
    goto :goto_1

    .line 33
    :cond_0
    new-instance v5, Lbp0/n;

    .line 34
    .line 35
    invoke-direct {v5, v0, v2}, Lbp0/n;-><init>(Lbp0/o;Lrx0/c;)V

    .line 36
    .line 37
    .line 38
    goto :goto_0

    .line 39
    :goto_1
    iget-object v2, v6, Lbp0/n;->g:Ljava/lang/Object;

    .line 40
    .line 41
    sget-object v8, Lqx0/a;->d:Lqx0/a;

    .line 42
    .line 43
    iget v5, v6, Lbp0/n;->i:I

    .line 44
    .line 45
    const v11, 0x7f0603b2

    .line 46
    .line 47
    .line 48
    iget-object v12, v0, Lbp0/o;->a:Landroid/app/NotificationManager;

    .line 49
    .line 50
    const/4 v13, 0x2

    .line 51
    const/4 v14, 0x1

    .line 52
    if-eqz v5, :cond_3

    .line 53
    .line 54
    if-eq v5, v14, :cond_2

    .line 55
    .line 56
    if-ne v5, v13, :cond_1

    .line 57
    .line 58
    iget-object v0, v6, Lbp0/n;->f:Landroidx/core/app/x;

    .line 59
    .line 60
    iget-object v1, v6, Lbp0/n;->e:Lap0/f;

    .line 61
    .line 62
    iget-object v3, v6, Lbp0/n;->d:Lcz/skodaauto/myskoda/library/pushnotifications/system/FirebaseNotificationsService;

    .line 63
    .line 64
    invoke-static {v2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 65
    .line 66
    .line 67
    move-object v7, v1

    .line 68
    move-object v1, v3

    .line 69
    move-object/from16 v17, v12

    .line 70
    .line 71
    goto/16 :goto_c

    .line 72
    .line 73
    :cond_1
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 74
    .line 75
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 76
    .line 77
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 78
    .line 79
    .line 80
    throw v0

    .line 81
    :cond_2
    iget-object v0, v6, Lbp0/n;->f:Landroidx/core/app/x;

    .line 82
    .line 83
    iget-object v1, v6, Lbp0/n;->e:Lap0/f;

    .line 84
    .line 85
    iget-object v3, v6, Lbp0/n;->d:Lcz/skodaauto/myskoda/library/pushnotifications/system/FirebaseNotificationsService;

    .line 86
    .line 87
    invoke-static {v2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 88
    .line 89
    .line 90
    move-object v7, v1

    .line 91
    move-object v1, v3

    .line 92
    move-object/from16 v17, v12

    .line 93
    .line 94
    goto/16 :goto_7

    .line 95
    .line 96
    :cond_3
    invoke-static {v2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 97
    .line 98
    .line 99
    iget-object v2, v7, Lap0/f;->g:Lap0/a;

    .line 100
    .line 101
    iget-object v5, v2, Lap0/a;->d:Ljava/lang/String;

    .line 102
    .line 103
    invoke-virtual {v12, v5}, Landroid/app/NotificationManager;->getNotificationChannel(Ljava/lang/String;)Landroid/app/NotificationChannel;

    .line 104
    .line 105
    .line 106
    move-result-object v5

    .line 107
    invoke-virtual {v1}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    .line 108
    .line 109
    .line 110
    move-result-object v15

    .line 111
    invoke-static {v2}, Lmx0/n;->y(Lap0/a;)I

    .line 112
    .line 113
    .line 114
    move-result v13

    .line 115
    invoke-virtual {v15, v13}, Landroid/content/res/Resources;->getString(I)Ljava/lang/String;

    .line 116
    .line 117
    .line 118
    move-result-object v13

    .line 119
    const-string v15, "getString(...)"

    .line 120
    .line 121
    invoke-static {v13, v15}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 122
    .line 123
    .line 124
    invoke-virtual {v1}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    .line 125
    .line 126
    .line 127
    move-result-object v9

    .line 128
    invoke-static {v2}, Lmx0/n;->x(Lap0/a;)I

    .line 129
    .line 130
    .line 131
    move-result v10

    .line 132
    invoke-virtual {v9, v10}, Landroid/content/res/Resources;->getString(I)Ljava/lang/String;

    .line 133
    .line 134
    .line 135
    move-result-object v9

    .line 136
    invoke-static {v9, v15}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 137
    .line 138
    .line 139
    const/4 v10, 0x4

    .line 140
    if-nez v5, :cond_4

    .line 141
    .line 142
    new-instance v5, Landroid/app/NotificationChannel;

    .line 143
    .line 144
    iget-object v15, v2, Lap0/a;->d:Ljava/lang/String;

    .line 145
    .line 146
    invoke-direct {v5, v15, v13, v10}, Landroid/app/NotificationChannel;-><init>(Ljava/lang/String;Ljava/lang/CharSequence;I)V

    .line 147
    .line 148
    .line 149
    invoke-virtual {v5, v9}, Landroid/app/NotificationChannel;->setDescription(Ljava/lang/String;)V

    .line 150
    .line 151
    .line 152
    sget-object v9, Lbp0/o;->d:[J

    .line 153
    .line 154
    invoke-virtual {v5, v9}, Landroid/app/NotificationChannel;->setVibrationPattern([J)V

    .line 155
    .line 156
    .line 157
    invoke-virtual {v5, v14}, Landroid/app/NotificationChannel;->setShowBadge(Z)V

    .line 158
    .line 159
    .line 160
    invoke-virtual {v1, v11}, Landroid/content/Context;->getColor(I)I

    .line 161
    .line 162
    .line 163
    move-result v9

    .line 164
    invoke-virtual {v5, v9}, Landroid/app/NotificationChannel;->setLightColor(I)V

    .line 165
    .line 166
    .line 167
    invoke-virtual {v12, v5}, Landroid/app/NotificationManager;->createNotificationChannel(Landroid/app/NotificationChannel;)V

    .line 168
    .line 169
    .line 170
    goto :goto_2

    .line 171
    :cond_4
    invoke-virtual {v5}, Landroid/app/NotificationChannel;->getName()Ljava/lang/CharSequence;

    .line 172
    .line 173
    .line 174
    move-result-object v15

    .line 175
    invoke-static {v15, v13}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 176
    .line 177
    .line 178
    move-result v15

    .line 179
    if-eqz v15, :cond_5

    .line 180
    .line 181
    invoke-virtual {v5}, Landroid/app/NotificationChannel;->getDescription()Ljava/lang/String;

    .line 182
    .line 183
    .line 184
    move-result-object v15

    .line 185
    invoke-static {v15, v9}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 186
    .line 187
    .line 188
    move-result v15

    .line 189
    if-nez v15, :cond_6

    .line 190
    .line 191
    :cond_5
    invoke-virtual {v5, v13}, Landroid/app/NotificationChannel;->setName(Ljava/lang/CharSequence;)V

    .line 192
    .line 193
    .line 194
    invoke-virtual {v5, v9}, Landroid/app/NotificationChannel;->setDescription(Ljava/lang/String;)V

    .line 195
    .line 196
    .line 197
    invoke-virtual {v12, v5}, Landroid/app/NotificationManager;->createNotificationChannel(Landroid/app/NotificationChannel;)V

    .line 198
    .line 199
    .line 200
    :cond_6
    :goto_2
    new-instance v5, Landroidx/core/app/x;

    .line 201
    .line 202
    iget-object v9, v2, Lap0/a;->d:Ljava/lang/String;

    .line 203
    .line 204
    iget-object v2, v2, Lap0/a;->d:Ljava/lang/String;

    .line 205
    .line 206
    invoke-direct {v5, v1, v9}, Landroidx/core/app/x;-><init>(Landroid/content/Context;Ljava/lang/String;)V

    .line 207
    .line 208
    .line 209
    iput-object v2, v5, Landroidx/core/app/x;->m:Ljava/lang/String;

    .line 210
    .line 211
    iget-object v9, v5, Landroidx/core/app/x;->y:Landroid/app/Notification;

    .line 212
    .line 213
    const v13, 0x7f0801ad

    .line 214
    .line 215
    .line 216
    iput v13, v9, Landroid/app/Notification;->icon:I

    .line 217
    .line 218
    invoke-virtual {v1, v11}, Landroid/content/Context;->getColor(I)I

    .line 219
    .line 220
    .line 221
    move-result v13

    .line 222
    iput v13, v5, Landroidx/core/app/x;->q:I

    .line 223
    .line 224
    iget-object v13, v7, Lap0/f;->h:Ljava/time/OffsetDateTime;

    .line 225
    .line 226
    if-eqz v13, :cond_7

    .line 227
    .line 228
    invoke-virtual {v13}, Ljava/time/OffsetDateTime;->toInstant()Ljava/time/Instant;

    .line 229
    .line 230
    .line 231
    move-result-object v13

    .line 232
    invoke-virtual {v13}, Ljava/time/Instant;->toEpochMilli()J

    .line 233
    .line 234
    .line 235
    move-result-wide v10

    .line 236
    iput-wide v10, v9, Landroid/app/Notification;->when:J

    .line 237
    .line 238
    :cond_7
    iget-object v9, v7, Lap0/f;->l:Ljava/lang/String;

    .line 239
    .line 240
    iget v10, v7, Lap0/f;->a:I

    .line 241
    .line 242
    new-instance v11, Landroid/content/Intent;

    .line 243
    .line 244
    const-string v13, "android.intent.action.VIEW"

    .line 245
    .line 246
    invoke-static {v9}, Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;

    .line 247
    .line 248
    .line 249
    move-result-object v9

    .line 250
    invoke-direct {v11, v13, v9}, Landroid/content/Intent;-><init>(Ljava/lang/String;Landroid/net/Uri;)V

    .line 251
    .line 252
    .line 253
    const-string v9, "NOTIFICATION_ID"

    .line 254
    .line 255
    invoke-virtual {v11, v9, v10}, Landroid/content/Intent;->putExtra(Ljava/lang/String;I)Landroid/content/Intent;

    .line 256
    .line 257
    .line 258
    const-string v9, "GROUP"

    .line 259
    .line 260
    invoke-virtual {v11, v9, v2}, Landroid/content/Intent;->putExtra(Ljava/lang/String;Ljava/lang/String;)Landroid/content/Intent;

    .line 261
    .line 262
    .line 263
    new-instance v2, Landroidx/core/app/m0;

    .line 264
    .line 265
    invoke-direct {v2, v1}, Landroidx/core/app/m0;-><init>(Landroid/content/Context;)V

    .line 266
    .line 267
    .line 268
    invoke-virtual {v2, v11}, Landroidx/core/app/m0;->c(Landroid/content/Intent;)V

    .line 269
    .line 270
    .line 271
    new-instance v9, Ljava/security/SecureRandom;

    .line 272
    .line 273
    invoke-direct {v9}, Ljava/security/SecureRandom;-><init>()V

    .line 274
    .line 275
    .line 276
    invoke-virtual {v9}, Ljava/util/Random;->nextInt()I

    .line 277
    .line 278
    .line 279
    move-result v9

    .line 280
    invoke-virtual {v2, v9}, Landroidx/core/app/m0;->g(I)Landroid/app/PendingIntent;

    .line 281
    .line 282
    .line 283
    move-result-object v2

    .line 284
    iput-object v2, v5, Landroidx/core/app/x;->g:Landroid/app/PendingIntent;

    .line 285
    .line 286
    new-instance v2, Ljava/util/ArrayList;

    .line 287
    .line 288
    invoke-direct {v2}, Ljava/util/ArrayList;-><init>()V

    .line 289
    .line 290
    .line 291
    new-instance v9, Ljava/util/ArrayList;

    .line 292
    .line 293
    invoke-direct {v9}, Ljava/util/ArrayList;-><init>()V

    .line 294
    .line 295
    .line 296
    iget-object v10, v7, Lap0/f;->e:Ljava/lang/String;

    .line 297
    .line 298
    new-instance v11, Landroid/os/Bundle;

    .line 299
    .line 300
    invoke-direct {v11}, Landroid/os/Bundle;-><init>()V

    .line 301
    .line 302
    .line 303
    invoke-virtual {v2}, Ljava/util/ArrayList;->isEmpty()Z

    .line 304
    .line 305
    .line 306
    move-result v13

    .line 307
    if-nez v13, :cond_c

    .line 308
    .line 309
    new-instance v13, Ljava/util/ArrayList;

    .line 310
    .line 311
    invoke-virtual {v2}, Ljava/util/ArrayList;->size()I

    .line 312
    .line 313
    .line 314
    move-result v15

    .line 315
    invoke-direct {v13, v15}, Ljava/util/ArrayList;-><init>(I)V

    .line 316
    .line 317
    .line 318
    invoke-virtual {v2}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 319
    .line 320
    .line 321
    move-result-object v2

    .line 322
    :goto_3
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    .line 323
    .line 324
    .line 325
    move-result v15

    .line 326
    if-eqz v15, :cond_b

    .line 327
    .line 328
    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 329
    .line 330
    .line 331
    move-result-object v15

    .line 332
    check-cast v15, Landroidx/core/app/r;

    .line 333
    .line 334
    sget v14, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 335
    .line 336
    move-object/from16 v16, v2

    .line 337
    .line 338
    invoke-virtual {v15}, Landroidx/core/app/r;->a()Landroidx/core/graphics/drawable/IconCompat;

    .line 339
    .line 340
    .line 341
    move-result-object v2

    .line 342
    move-object/from16 v17, v12

    .line 343
    .line 344
    iget-object v12, v15, Landroidx/core/app/r;->a:Landroid/os/Bundle;

    .line 345
    .line 346
    if-nez v2, :cond_8

    .line 347
    .line 348
    move-object/from16 v18, v3

    .line 349
    .line 350
    const/4 v2, 0x0

    .line 351
    goto :goto_4

    .line 352
    :cond_8
    move-object/from16 v18, v3

    .line 353
    .line 354
    const/4 v3, 0x0

    .line 355
    invoke-virtual {v2, v3}, Landroidx/core/graphics/drawable/IconCompat;->f(Landroid/content/Context;)Landroid/graphics/drawable/Icon;

    .line 356
    .line 357
    .line 358
    move-result-object v2

    .line 359
    :goto_4
    iget-object v3, v15, Landroidx/core/app/r;->f:Ljava/lang/CharSequence;

    .line 360
    .line 361
    move-object/from16 v19, v4

    .line 362
    .line 363
    iget-object v4, v15, Landroidx/core/app/r;->g:Landroid/app/PendingIntent;

    .line 364
    .line 365
    invoke-static {v2, v3, v4}, Landroidx/core/app/c0;->a(Landroid/graphics/drawable/Icon;Ljava/lang/CharSequence;Landroid/app/PendingIntent;)Landroid/app/Notification$Action$Builder;

    .line 366
    .line 367
    .line 368
    move-result-object v2

    .line 369
    iget-boolean v3, v15, Landroidx/core/app/r;->c:Z

    .line 370
    .line 371
    if-eqz v12, :cond_9

    .line 372
    .line 373
    new-instance v4, Landroid/os/Bundle;

    .line 374
    .line 375
    invoke-direct {v4, v12}, Landroid/os/Bundle;-><init>(Landroid/os/Bundle;)V

    .line 376
    .line 377
    .line 378
    goto :goto_5

    .line 379
    :cond_9
    new-instance v4, Landroid/os/Bundle;

    .line 380
    .line 381
    invoke-direct {v4}, Landroid/os/Bundle;-><init>()V

    .line 382
    .line 383
    .line 384
    :goto_5
    const-string v12, "android.support.allowGeneratedReplies"

    .line 385
    .line 386
    invoke-virtual {v4, v12, v3}, Landroid/os/BaseBundle;->putBoolean(Ljava/lang/String;Z)V

    .line 387
    .line 388
    .line 389
    invoke-static {v2, v3}, Landroidx/core/app/d0;->a(Landroid/app/Notification$Action$Builder;Z)Landroid/app/Notification$Action$Builder;

    .line 390
    .line 391
    .line 392
    const/16 v3, 0x1f

    .line 393
    .line 394
    if-lt v14, v3, :cond_a

    .line 395
    .line 396
    const/4 v3, 0x0

    .line 397
    invoke-static {v2, v3}, Landroidx/core/app/e0;->a(Landroid/app/Notification$Action$Builder;Z)Landroid/app/Notification$Action$Builder;

    .line 398
    .line 399
    .line 400
    :cond_a
    invoke-static {v2, v4}, Landroidx/core/app/b0;->a(Landroid/app/Notification$Action$Builder;Landroid/os/Bundle;)Landroid/app/Notification$Action$Builder;

    .line 401
    .line 402
    .line 403
    invoke-static {v2}, Landroidx/core/app/b0;->b(Landroid/app/Notification$Action$Builder;)Landroid/app/Notification$Action;

    .line 404
    .line 405
    .line 406
    move-result-object v2

    .line 407
    invoke-virtual {v13, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 408
    .line 409
    .line 410
    move-object/from16 v2, v16

    .line 411
    .line 412
    move-object/from16 v12, v17

    .line 413
    .line 414
    move-object/from16 v3, v18

    .line 415
    .line 416
    move-object/from16 v4, v19

    .line 417
    .line 418
    goto :goto_3

    .line 419
    :cond_b
    move-object/from16 v18, v3

    .line 420
    .line 421
    move-object/from16 v19, v4

    .line 422
    .line 423
    move-object/from16 v17, v12

    .line 424
    .line 425
    const-string v2, "actions"

    .line 426
    .line 427
    invoke-virtual {v11, v2, v13}, Landroid/os/Bundle;->putParcelableArrayList(Ljava/lang/String;Ljava/util/ArrayList;)V

    .line 428
    .line 429
    .line 430
    goto :goto_6

    .line 431
    :cond_c
    move-object/from16 v18, v3

    .line 432
    .line 433
    move-object/from16 v19, v4

    .line 434
    .line 435
    move-object/from16 v17, v12

    .line 436
    .line 437
    :goto_6
    invoke-virtual {v9}, Ljava/util/ArrayList;->isEmpty()Z

    .line 438
    .line 439
    .line 440
    move-result v2

    .line 441
    if-nez v2, :cond_d

    .line 442
    .line 443
    invoke-virtual {v9}, Ljava/util/ArrayList;->size()I

    .line 444
    .line 445
    .line 446
    move-result v2

    .line 447
    new-array v2, v2, [Landroid/app/Notification;

    .line 448
    .line 449
    invoke-virtual {v9, v2}, Ljava/util/ArrayList;->toArray([Ljava/lang/Object;)[Ljava/lang/Object;

    .line 450
    .line 451
    .line 452
    move-result-object v2

    .line 453
    check-cast v2, [Landroid/os/Parcelable;

    .line 454
    .line 455
    const-string v3, "pages"

    .line 456
    .line 457
    invoke-virtual {v11, v3, v2}, Landroid/os/Bundle;->putParcelableArray(Ljava/lang/String;[Landroid/os/Parcelable;)V

    .line 458
    .line 459
    .line 460
    :cond_d
    if-eqz v10, :cond_e

    .line 461
    .line 462
    const-string v2, "dismissalId"

    .line 463
    .line 464
    invoke-virtual {v11, v2, v10}, Landroid/os/BaseBundle;->putString(Ljava/lang/String;Ljava/lang/String;)V

    .line 465
    .line 466
    .line 467
    :cond_e
    iget-object v2, v5, Landroidx/core/app/x;->p:Landroid/os/Bundle;

    .line 468
    .line 469
    if-nez v2, :cond_f

    .line 470
    .line 471
    new-instance v2, Landroid/os/Bundle;

    .line 472
    .line 473
    invoke-direct {v2}, Landroid/os/Bundle;-><init>()V

    .line 474
    .line 475
    .line 476
    iput-object v2, v5, Landroidx/core/app/x;->p:Landroid/os/Bundle;

    .line 477
    .line 478
    :cond_f
    iget-object v2, v5, Landroidx/core/app/x;->p:Landroid/os/Bundle;

    .line 479
    .line 480
    const-string v3, "android.wearable.EXTENSIONS"

    .line 481
    .line 482
    invoke-virtual {v2, v3, v11}, Landroid/os/Bundle;->putBundle(Ljava/lang/String;Landroid/os/Bundle;)V

    .line 483
    .line 484
    .line 485
    iget-object v2, v7, Lap0/f;->i:Lap0/b;

    .line 486
    .line 487
    instance-of v3, v2, Lap0/c;

    .line 488
    .line 489
    if-eqz v3, :cond_11

    .line 490
    .line 491
    check-cast v2, Lap0/c;

    .line 492
    .line 493
    iget v3, v7, Lap0/f;->a:I

    .line 494
    .line 495
    iget-object v4, v7, Lap0/f;->g:Lap0/a;

    .line 496
    .line 497
    iput-object v1, v6, Lbp0/n;->d:Lcz/skodaauto/myskoda/library/pushnotifications/system/FirebaseNotificationsService;

    .line 498
    .line 499
    iput-object v7, v6, Lbp0/n;->e:Lap0/f;

    .line 500
    .line 501
    iput-object v5, v6, Lbp0/n;->f:Landroidx/core/app/x;

    .line 502
    .line 503
    const/4 v9, 0x1

    .line 504
    iput v9, v6, Lbp0/n;->i:I

    .line 505
    .line 506
    iget-object v0, v0, Lbp0/o;->b:Lbp0/l;

    .line 507
    .line 508
    invoke-virtual/range {v0 .. v6}, Lbp0/l;->b(Landroid/content/Context;Lap0/c;ILap0/a;Landroidx/core/app/x;Lrx0/c;)Ljava/lang/Object;

    .line 509
    .line 510
    .line 511
    move-result-object v2

    .line 512
    if-ne v2, v8, :cond_10

    .line 513
    .line 514
    goto/16 :goto_b

    .line 515
    .line 516
    :cond_10
    move-object v0, v5

    .line 517
    :goto_7
    check-cast v2, Landroidx/core/app/x;

    .line 518
    .line 519
    :goto_8
    move-object v5, v0

    .line 520
    goto/16 :goto_d

    .line 521
    .line 522
    :cond_11
    instance-of v0, v2, Lap0/i;

    .line 523
    .line 524
    if-eqz v0, :cond_14

    .line 525
    .line 526
    check-cast v2, Lap0/i;

    .line 527
    .line 528
    new-instance v0, Landroid/widget/RemoteViews;

    .line 529
    .line 530
    invoke-virtual {v1}, Landroid/content/Context;->getPackageName()Ljava/lang/String;

    .line 531
    .line 532
    .line 533
    move-result-object v3

    .line 534
    const v4, 0x7f0d02df

    .line 535
    .line 536
    .line 537
    invoke-direct {v0, v3, v4}, Landroid/widget/RemoteViews;-><init>(Ljava/lang/String;I)V

    .line 538
    .line 539
    .line 540
    const v3, 0x7f0a0237

    .line 541
    .line 542
    .line 543
    iget-object v4, v2, Lap0/i;->a:Ljava/lang/String;

    .line 544
    .line 545
    invoke-virtual {v0, v3, v4}, Landroid/widget/RemoteViews;->setTextViewText(ILjava/lang/CharSequence;)V

    .line 546
    .line 547
    .line 548
    iget-object v3, v2, Lap0/i;->b:Lqr0/l;

    .line 549
    .line 550
    iget v4, v3, Lqr0/l;->d:I

    .line 551
    .line 552
    const v6, 0x7f0a0262

    .line 553
    .line 554
    .line 555
    const/16 v8, 0x64

    .line 556
    .line 557
    const/4 v9, 0x0

    .line 558
    invoke-virtual {v0, v6, v8, v4, v9}, Landroid/widget/RemoteViews;->setProgressBar(IIIZ)V

    .line 559
    .line 560
    .line 561
    iget-wide v10, v2, Lap0/i;->c:J

    .line 562
    .line 563
    const/4 v4, 0x6

    .line 564
    move-object/from16 v6, v19

    .line 565
    .line 566
    invoke-static {v10, v11, v6, v9, v4}, Ljp/d1;->c(JLij0/a;ZI)Ljava/lang/String;

    .line 567
    .line 568
    .line 569
    move-result-object v4

    .line 570
    filled-new-array {v4}, [Ljava/lang/Object;

    .line 571
    .line 572
    .line 573
    move-result-object v4

    .line 574
    move-object v8, v6

    .line 575
    check-cast v8, Ljj0/f;

    .line 576
    .line 577
    const v10, 0x7f12041c

    .line 578
    .line 579
    .line 580
    invoke-virtual {v8, v10, v4}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 581
    .line 582
    .line 583
    move-result-object v4

    .line 584
    const v8, 0x7f0a0234

    .line 585
    .line 586
    .line 587
    invoke-virtual {v0, v8, v4}, Landroid/widget/RemoteViews;->setTextViewText(ILjava/lang/CharSequence;)V

    .line 588
    .line 589
    .line 590
    new-array v4, v9, [Ljava/lang/Object;

    .line 591
    .line 592
    check-cast v6, Ljj0/f;

    .line 593
    .line 594
    const v8, 0x7f120520

    .line 595
    .line 596
    .line 597
    invoke-virtual {v6, v8, v4}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 598
    .line 599
    .line 600
    move-result-object v4

    .line 601
    iget-object v6, v2, Lap0/i;->e:Lqr0/l;

    .line 602
    .line 603
    invoke-static {v6}, Lkp/l6;->a(Lqr0/l;)Ljava/lang/String;

    .line 604
    .line 605
    .line 606
    move-result-object v6

    .line 607
    new-instance v8, Ljava/lang/StringBuilder;

    .line 608
    .line 609
    invoke-direct {v8}, Ljava/lang/StringBuilder;-><init>()V

    .line 610
    .line 611
    .line 612
    invoke-virtual {v8, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 613
    .line 614
    .line 615
    const-string v4, " "

    .line 616
    .line 617
    invoke-virtual {v8, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 618
    .line 619
    .line 620
    invoke-virtual {v8, v6}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 621
    .line 622
    .line 623
    invoke-virtual {v8}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 624
    .line 625
    .line 626
    move-result-object v4

    .line 627
    const v6, 0x7f0a0236

    .line 628
    .line 629
    .line 630
    invoke-virtual {v0, v6, v4}, Landroid/widget/RemoteViews;->setTextViewText(ILjava/lang/CharSequence;)V

    .line 631
    .line 632
    .line 633
    const v4, 0x7f0a0233

    .line 634
    .line 635
    .line 636
    invoke-static {v3}, Lkp/l6;->a(Lqr0/l;)Ljava/lang/String;

    .line 637
    .line 638
    .line 639
    move-result-object v3

    .line 640
    invoke-virtual {v0, v4, v3}, Landroid/widget/RemoteViews;->setTextViewText(ILjava/lang/CharSequence;)V

    .line 641
    .line 642
    .line 643
    iget-object v2, v2, Lap0/i;->d:Lqr0/n;

    .line 644
    .line 645
    if-eqz v2, :cond_12

    .line 646
    .line 647
    iget-wide v3, v2, Lqr0/n;->a:D

    .line 648
    .line 649
    sget-object v6, Lqr0/s;->d:Lqr0/s;

    .line 650
    .line 651
    invoke-static {v3, v4, v6}, Lkp/n6;->a(DLqr0/s;)Ljava/lang/String;

    .line 652
    .line 653
    .line 654
    move-result-object v14

    .line 655
    goto :goto_9

    .line 656
    :cond_12
    const/4 v14, 0x0

    .line 657
    :goto_9
    const v3, 0x7f0a0231

    .line 658
    .line 659
    .line 660
    invoke-virtual {v0, v3, v14}, Landroid/widget/RemoteViews;->setTextViewText(ILjava/lang/CharSequence;)V

    .line 661
    .line 662
    .line 663
    if-eqz v2, :cond_13

    .line 664
    .line 665
    const/4 v10, 0x0

    .line 666
    goto :goto_a

    .line 667
    :cond_13
    const/4 v10, 0x4

    .line 668
    :goto_a
    const v2, 0x7f0a0232

    .line 669
    .line 670
    .line 671
    invoke-virtual {v0, v2, v10}, Landroid/widget/RemoteViews;->setViewVisibility(II)V

    .line 672
    .line 673
    .line 674
    new-instance v2, Landroidx/core/app/z;

    .line 675
    .line 676
    invoke-direct {v2}, Landroidx/core/app/a0;-><init>()V

    .line 677
    .line 678
    .line 679
    invoke-virtual {v5, v2}, Landroidx/core/app/x;->f(Landroidx/core/app/a0;)V

    .line 680
    .line 681
    .line 682
    iput-object v0, v5, Landroidx/core/app/x;->s:Landroid/widget/RemoteViews;

    .line 683
    .line 684
    const/16 v0, 0x8

    .line 685
    .line 686
    const/4 v9, 0x1

    .line 687
    invoke-virtual {v5, v0, v9}, Landroidx/core/app/x;->d(IZ)V

    .line 688
    .line 689
    .line 690
    const/16 v0, 0x10

    .line 691
    .line 692
    const/4 v3, 0x0

    .line 693
    invoke-virtual {v5, v0, v3}, Landroidx/core/app/x;->d(IZ)V

    .line 694
    .line 695
    .line 696
    sget v0, Lmy0/c;->g:I

    .line 697
    .line 698
    const/16 v0, 0xa

    .line 699
    .line 700
    sget-object v2, Lmy0/e;->i:Lmy0/e;

    .line 701
    .line 702
    invoke-static {v0, v2}, Lmy0/h;->s(ILmy0/e;)J

    .line 703
    .line 704
    .line 705
    move-result-wide v2

    .line 706
    invoke-static {v2, v3}, Lmy0/c;->e(J)J

    .line 707
    .line 708
    .line 709
    move-result-wide v2

    .line 710
    iput-wide v2, v5, Landroidx/core/app/x;->v:J

    .line 711
    .line 712
    const/4 v0, 0x2

    .line 713
    invoke-virtual {v5, v0, v9}, Landroidx/core/app/x;->d(IZ)V

    .line 714
    .line 715
    .line 716
    goto :goto_d

    .line 717
    :cond_14
    const/4 v0, 0x2

    .line 718
    instance-of v3, v2, Lap0/h;

    .line 719
    .line 720
    if-eqz v3, :cond_17

    .line 721
    .line 722
    check-cast v2, Lap0/h;

    .line 723
    .line 724
    iput-object v1, v6, Lbp0/n;->d:Lcz/skodaauto/myskoda/library/pushnotifications/system/FirebaseNotificationsService;

    .line 725
    .line 726
    iput-object v7, v6, Lbp0/n;->e:Lap0/f;

    .line 727
    .line 728
    iput-object v5, v6, Lbp0/n;->f:Landroidx/core/app/x;

    .line 729
    .line 730
    iput v0, v6, Lbp0/n;->i:I

    .line 731
    .line 732
    move-object/from16 v0, v18

    .line 733
    .line 734
    invoke-virtual {v0, v1, v2, v5, v6}, Lbp0/b;->a(Landroid/content/Context;Lap0/h;Landroidx/core/app/x;Lrx0/c;)Ljava/lang/Object;

    .line 735
    .line 736
    .line 737
    move-result-object v2

    .line 738
    if-ne v2, v8, :cond_15

    .line 739
    .line 740
    :goto_b
    return-object v8

    .line 741
    :cond_15
    move-object v0, v5

    .line 742
    :goto_c
    check-cast v2, Landroidx/core/app/x;

    .line 743
    .line 744
    goto/16 :goto_8

    .line 745
    .line 746
    :goto_d
    iget v0, v7, Lap0/f;->a:I

    .line 747
    .line 748
    invoke-virtual {v5}, Landroidx/core/app/x;->a()Landroid/app/Notification;

    .line 749
    .line 750
    .line 751
    move-result-object v2

    .line 752
    move-object/from16 v3, v17

    .line 753
    .line 754
    invoke-virtual {v3, v0, v2}, Landroid/app/NotificationManager;->notify(ILandroid/app/Notification;)V

    .line 755
    .line 756
    .line 757
    iget-object v0, v7, Lap0/f;->i:Lap0/b;

    .line 758
    .line 759
    instance-of v0, v0, Lap0/c;

    .line 760
    .line 761
    if-eqz v0, :cond_16

    .line 762
    .line 763
    iget v0, v7, Lap0/f;->f:I

    .line 764
    .line 765
    iget-object v2, v7, Lap0/f;->g:Lap0/a;

    .line 766
    .line 767
    iget-object v2, v2, Lap0/a;->d:Ljava/lang/String;

    .line 768
    .line 769
    new-instance v4, Landroidx/core/app/x;

    .line 770
    .line 771
    invoke-direct {v4, v1, v2}, Landroidx/core/app/x;-><init>(Landroid/content/Context;Ljava/lang/String;)V

    .line 772
    .line 773
    .line 774
    iput-object v2, v4, Landroidx/core/app/x;->m:Ljava/lang/String;

    .line 775
    .line 776
    const/4 v9, 0x1

    .line 777
    iput-boolean v9, v4, Landroidx/core/app/x;->n:Z

    .line 778
    .line 779
    const/16 v2, 0x10

    .line 780
    .line 781
    invoke-virtual {v4, v2, v9}, Landroidx/core/app/x;->d(IZ)V

    .line 782
    .line 783
    .line 784
    iget-object v2, v4, Landroidx/core/app/x;->y:Landroid/app/Notification;

    .line 785
    .line 786
    const v13, 0x7f0801ad

    .line 787
    .line 788
    .line 789
    iput v13, v2, Landroid/app/Notification;->icon:I

    .line 790
    .line 791
    const v15, 0x7f0603b2

    .line 792
    .line 793
    .line 794
    invoke-virtual {v1, v15}, Landroid/content/Context;->getColor(I)I

    .line 795
    .line 796
    .line 797
    move-result v1

    .line 798
    iput v1, v4, Landroidx/core/app/x;->q:I

    .line 799
    .line 800
    const/4 v1, 0x2

    .line 801
    iput v1, v4, Landroidx/core/app/x;->w:I

    .line 802
    .line 803
    invoke-virtual {v4}, Landroidx/core/app/x;->a()Landroid/app/Notification;

    .line 804
    .line 805
    .line 806
    move-result-object v1

    .line 807
    const-string v2, "build(...)"

    .line 808
    .line 809
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 810
    .line 811
    .line 812
    invoke-virtual {v3, v0, v1}, Landroid/app/NotificationManager;->notify(ILandroid/app/Notification;)V

    .line 813
    .line 814
    .line 815
    :cond_16
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 816
    .line 817
    return-object v0

    .line 818
    :cond_17
    new-instance v0, La8/r0;

    .line 819
    .line 820
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 821
    .line 822
    .line 823
    throw v0
.end method
