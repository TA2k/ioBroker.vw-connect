.class public final Lgp/i;
.super Loo/a;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final CREATOR:Landroid/os/Parcelable$Creator;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Landroid/os/Parcelable$Creator<",
            "Lgp/i;",
            ">;"
        }
    .end annotation
.end field


# instance fields
.field public final d:Lcom/google/android/gms/location/LocationRequest;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lgl/c;

    .line 2
    .line 3
    const/4 v1, 0x6

    .line 4
    invoke-direct {v0, v1}, Lgl/c;-><init>(I)V

    .line 5
    .line 6
    .line 7
    sput-object v0, Lgp/i;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 8
    .line 9
    return-void
.end method

.method public constructor <init>(Lcom/google/android/gms/location/LocationRequest;Ljava/util/ArrayList;ZZZZJ)V
    .locals 31

    .line 1
    move-object/from16 v0, p1

    .line 2
    .line 3
    invoke-direct/range {p0 .. p0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    iget v1, v0, Lcom/google/android/gms/location/LocationRequest;->d:I

    .line 7
    .line 8
    iget-wide v2, v0, Lcom/google/android/gms/location/LocationRequest;->e:J

    .line 9
    .line 10
    const-wide/16 v4, 0x0

    .line 11
    .line 12
    cmp-long v6, v2, v4

    .line 13
    .line 14
    if-ltz v6, :cond_0

    .line 15
    .line 16
    const/4 v6, 0x1

    .line 17
    goto :goto_0

    .line 18
    :cond_0
    const/4 v6, 0x0

    .line 19
    :goto_0
    const-string v9, "intervalMillis must be greater than or equal to 0"

    .line 20
    .line 21
    invoke-static {v6, v9}, Lno/c0;->b(ZLjava/lang/String;)V

    .line 22
    .line 23
    .line 24
    invoke-static {v1}, Lpp/k;->a(I)V

    .line 25
    .line 26
    .line 27
    iget-wide v9, v0, Lcom/google/android/gms/location/LocationRequest;->f:J

    .line 28
    .line 29
    const-wide/16 v11, -0x1

    .line 30
    .line 31
    cmp-long v6, v9, v11

    .line 32
    .line 33
    if-eqz v6, :cond_1

    .line 34
    .line 35
    cmp-long v6, v9, v4

    .line 36
    .line 37
    if-ltz v6, :cond_2

    .line 38
    .line 39
    :cond_1
    const/4 v6, 0x1

    .line 40
    goto :goto_1

    .line 41
    :cond_2
    const/4 v6, 0x0

    .line 42
    :goto_1
    const-string v13, "minUpdateIntervalMillis must be greater than or equal to 0, or IMPLICIT_MIN_UPDATE_INTERVAL"

    .line 43
    .line 44
    invoke-static {v6, v13}, Lno/c0;->b(ZLjava/lang/String;)V

    .line 45
    .line 46
    .line 47
    iget-wide v13, v0, Lcom/google/android/gms/location/LocationRequest;->g:J

    .line 48
    .line 49
    cmp-long v6, v13, v4

    .line 50
    .line 51
    if-ltz v6, :cond_3

    .line 52
    .line 53
    const/4 v6, 0x1

    .line 54
    goto :goto_2

    .line 55
    :cond_3
    const/4 v6, 0x0

    .line 56
    :goto_2
    const-string v15, "maxUpdateDelayMillis must be greater than or equal to 0"

    .line 57
    .line 58
    invoke-static {v6, v15}, Lno/c0;->b(ZLjava/lang/String;)V

    .line 59
    .line 60
    .line 61
    move-wide v15, v4

    .line 62
    iget-wide v4, v0, Lcom/google/android/gms/location/LocationRequest;->h:J

    .line 63
    .line 64
    cmp-long v6, v4, v15

    .line 65
    .line 66
    if-lez v6, :cond_4

    .line 67
    .line 68
    const/4 v6, 0x1

    .line 69
    goto :goto_3

    .line 70
    :cond_4
    const/4 v6, 0x0

    .line 71
    :goto_3
    const-string v7, "durationMillis must be greater than 0"

    .line 72
    .line 73
    invoke-static {v6, v7}, Lno/c0;->b(ZLjava/lang/String;)V

    .line 74
    .line 75
    .line 76
    move-wide v6, v11

    .line 77
    iget v12, v0, Lcom/google/android/gms/location/LocationRequest;->i:I

    .line 78
    .line 79
    if-lez v12, :cond_5

    .line 80
    .line 81
    const/4 v11, 0x1

    .line 82
    :goto_4
    move-wide/from16 v18, v6

    .line 83
    .line 84
    goto :goto_5

    .line 85
    :cond_5
    const/4 v11, 0x0

    .line 86
    goto :goto_4

    .line 87
    :goto_5
    const-string v6, "maxUpdates must be greater than 0"

    .line 88
    .line 89
    invoke-static {v11, v6}, Lno/c0;->b(ZLjava/lang/String;)V

    .line 90
    .line 91
    .line 92
    iget v6, v0, Lcom/google/android/gms/location/LocationRequest;->j:F

    .line 93
    .line 94
    const/4 v7, 0x0

    .line 95
    cmpl-float v7, v6, v7

    .line 96
    .line 97
    if-ltz v7, :cond_6

    .line 98
    .line 99
    const/4 v7, 0x1

    .line 100
    goto :goto_6

    .line 101
    :cond_6
    const/4 v7, 0x0

    .line 102
    :goto_6
    const-string v11, "minUpdateDistanceMeters must be greater than or equal to 0"

    .line 103
    .line 104
    invoke-static {v7, v11}, Lno/c0;->b(ZLjava/lang/String;)V

    .line 105
    .line 106
    .line 107
    iget-boolean v7, v0, Lcom/google/android/gms/location/LocationRequest;->k:Z

    .line 108
    .line 109
    move-wide/from16 v20, v9

    .line 110
    .line 111
    iget-wide v8, v0, Lcom/google/android/gms/location/LocationRequest;->l:J

    .line 112
    .line 113
    cmp-long v10, v8, v18

    .line 114
    .line 115
    if-eqz v10, :cond_7

    .line 116
    .line 117
    cmp-long v10, v8, v15

    .line 118
    .line 119
    if-ltz v10, :cond_8

    .line 120
    .line 121
    :cond_7
    const/4 v10, 0x1

    .line 122
    goto :goto_7

    .line 123
    :cond_8
    const/4 v10, 0x0

    .line 124
    :goto_7
    const-string v11, "maxUpdateAgeMillis must be greater than or equal to 0, or IMPLICIT_MAX_UPDATE_AGE"

    .line 125
    .line 126
    invoke-static {v10, v11}, Lno/c0;->b(ZLjava/lang/String;)V

    .line 127
    .line 128
    .line 129
    iget v10, v0, Lcom/google/android/gms/location/LocationRequest;->m:I

    .line 130
    .line 131
    move-wide/from16 v22, v15

    .line 132
    .line 133
    const/4 v15, 0x2

    .line 134
    if-eqz v10, :cond_b

    .line 135
    .line 136
    move-wide/from16 v24, v4

    .line 137
    .line 138
    const/4 v4, 0x1

    .line 139
    if-eq v10, v4, :cond_a

    .line 140
    .line 141
    if-ne v10, v15, :cond_9

    .line 142
    .line 143
    move/from16 v16, v15

    .line 144
    .line 145
    :goto_8
    const/4 v5, 0x1

    .line 146
    goto :goto_a

    .line 147
    :cond_9
    move/from16 v16, v10

    .line 148
    .line 149
    const/4 v5, 0x0

    .line 150
    goto :goto_a

    .line 151
    :cond_a
    :goto_9
    move/from16 v16, v10

    .line 152
    .line 153
    goto :goto_8

    .line 154
    :cond_b
    move-wide/from16 v24, v4

    .line 155
    .line 156
    goto :goto_9

    .line 157
    :goto_a
    invoke-static/range {v16 .. v16}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 158
    .line 159
    .line 160
    move-result-object v16

    .line 161
    filled-new-array/range {v16 .. v16}, [Ljava/lang/Object;

    .line 162
    .line 163
    .line 164
    move-result-object v4

    .line 165
    const-string v15, "granularity %d must be a Granularity.GRANULARITY_* constant"

    .line 166
    .line 167
    invoke-static {v5, v15, v4}, Lno/c0;->c(ZLjava/lang/String;[Ljava/lang/Object;)V

    .line 168
    .line 169
    .line 170
    iget v4, v0, Lcom/google/android/gms/location/LocationRequest;->n:I

    .line 171
    .line 172
    if-eqz v4, :cond_e

    .line 173
    .line 174
    const/4 v5, 0x1

    .line 175
    if-eq v4, v5, :cond_d

    .line 176
    .line 177
    const/4 v15, 0x2

    .line 178
    if-ne v4, v15, :cond_c

    .line 179
    .line 180
    move/from16 v16, v15

    .line 181
    .line 182
    goto :goto_c

    .line 183
    :cond_c
    move/from16 v16, v4

    .line 184
    .line 185
    const/4 v5, 0x0

    .line 186
    goto :goto_c

    .line 187
    :cond_d
    :goto_b
    const/4 v15, 0x2

    .line 188
    move/from16 v16, v4

    .line 189
    .line 190
    goto :goto_c

    .line 191
    :cond_e
    const/4 v5, 0x1

    .line 192
    goto :goto_b

    .line 193
    :goto_c
    invoke-static/range {v16 .. v16}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 194
    .line 195
    .line 196
    move-result-object v16

    .line 197
    filled-new-array/range {v16 .. v16}, [Ljava/lang/Object;

    .line 198
    .line 199
    .line 200
    move-result-object v15

    .line 201
    move/from16 v16, v4

    .line 202
    .line 203
    const-string v4, "throttle behavior %d must be a ThrottleBehavior.THROTTLE_* constant"

    .line 204
    .line 205
    invoke-static {v5, v4, v15}, Lno/c0;->c(ZLjava/lang/String;[Ljava/lang/Object;)V

    .line 206
    .line 207
    .line 208
    iget-boolean v4, v0, Lcom/google/android/gms/location/LocationRequest;->o:Z

    .line 209
    .line 210
    iget-object v5, v0, Lcom/google/android/gms/location/LocationRequest;->p:Landroid/os/WorkSource;

    .line 211
    .line 212
    iget-object v0, v0, Lcom/google/android/gms/location/LocationRequest;->q:Lgp/g;

    .line 213
    .line 214
    if-eqz v0, :cond_f

    .line 215
    .line 216
    iget-object v0, v0, Lgp/g;->i:Lgp/g;

    .line 217
    .line 218
    if-eqz v0, :cond_f

    .line 219
    .line 220
    const/4 v0, 0x0

    .line 221
    goto :goto_d

    .line 222
    :cond_f
    const/4 v0, 0x1

    .line 223
    :goto_d
    invoke-static {v0}, Lno/c0;->a(Z)V

    .line 224
    .line 225
    .line 226
    if-eqz p2, :cond_12

    .line 227
    .line 228
    invoke-interface/range {p2 .. p2}, Ljava/util/List;->isEmpty()Z

    .line 229
    .line 230
    .line 231
    move-result v0

    .line 232
    if-eqz v0, :cond_10

    .line 233
    .line 234
    const/4 v0, 0x0

    .line 235
    move-object v5, v0

    .line 236
    goto :goto_f

    .line 237
    :cond_10
    new-instance v0, Landroid/os/WorkSource;

    .line 238
    .line 239
    invoke-direct {v0}, Landroid/os/WorkSource;-><init>()V

    .line 240
    .line 241
    .line 242
    invoke-interface/range {p2 .. p2}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 243
    .line 244
    .line 245
    move-result-object v5

    .line 246
    :goto_e
    invoke-interface {v5}, Ljava/util/Iterator;->hasNext()Z

    .line 247
    .line 248
    .line 249
    move-result v15

    .line 250
    if-eqz v15, :cond_11

    .line 251
    .line 252
    invoke-interface {v5}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 253
    .line 254
    .line 255
    move-result-object v15

    .line 256
    check-cast v15, Lno/f;

    .line 257
    .line 258
    move/from16 v26, v4

    .line 259
    .line 260
    iget v4, v15, Lno/f;->d:I

    .line 261
    .line 262
    iget-object v15, v15, Lno/f;->e:Ljava/lang/String;

    .line 263
    .line 264
    invoke-static {v0, v4, v15}, Lto/d;->a(Landroid/os/WorkSource;ILjava/lang/String;)V

    .line 265
    .line 266
    .line 267
    move/from16 v4, v26

    .line 268
    .line 269
    goto :goto_e

    .line 270
    :cond_11
    move/from16 v26, v4

    .line 271
    .line 272
    move-object v5, v0

    .line 273
    goto :goto_10

    .line 274
    :cond_12
    :goto_f
    move/from16 v26, v4

    .line 275
    .line 276
    :goto_10
    if-eqz p3, :cond_13

    .line 277
    .line 278
    const/4 v10, 0x1

    .line 279
    :cond_13
    if-eqz p4, :cond_14

    .line 280
    .line 281
    const/4 v15, 0x2

    .line 282
    goto :goto_11

    .line 283
    :cond_14
    move/from16 v15, v16

    .line 284
    .line 285
    :goto_11
    if-eqz p5, :cond_15

    .line 286
    .line 287
    const/16 v26, 0x1

    .line 288
    .line 289
    :cond_15
    if-eqz p6, :cond_16

    .line 290
    .line 291
    const/4 v7, 0x1

    .line 292
    :cond_16
    const-wide v27, 0x7fffffffffffffffL

    .line 293
    .line 294
    .line 295
    .line 296
    .line 297
    cmp-long v0, p7, v27

    .line 298
    .line 299
    if-eqz v0, :cond_19

    .line 300
    .line 301
    cmp-long v0, p7, v18

    .line 302
    .line 303
    if-eqz v0, :cond_17

    .line 304
    .line 305
    cmp-long v0, p7, v22

    .line 306
    .line 307
    if-ltz v0, :cond_18

    .line 308
    .line 309
    :cond_17
    const/4 v0, 0x1

    .line 310
    goto :goto_12

    .line 311
    :cond_18
    const/4 v0, 0x0

    .line 312
    :goto_12
    invoke-static {v0, v11}, Lno/c0;->b(ZLjava/lang/String;)V

    .line 313
    .line 314
    .line 315
    move-wide/from16 v8, p7

    .line 316
    .line 317
    :cond_19
    new-instance v0, Lcom/google/android/gms/location/LocationRequest;

    .line 318
    .line 319
    cmp-long v4, v20, v18

    .line 320
    .line 321
    if-nez v4, :cond_1a

    .line 322
    .line 323
    move-object/from16 p1, v0

    .line 324
    .line 325
    move v4, v1

    .line 326
    move-wide v0, v2

    .line 327
    goto :goto_13

    .line 328
    :cond_1a
    const/16 v4, 0x69

    .line 329
    .line 330
    if-ne v1, v4, :cond_1b

    .line 331
    .line 332
    move-object/from16 p1, v0

    .line 333
    .line 334
    move v4, v1

    .line 335
    move-wide/from16 v0, v20

    .line 336
    .line 337
    goto :goto_13

    .line 338
    :cond_1b
    move-object/from16 p1, v0

    .line 339
    .line 340
    move v4, v1

    .line 341
    move-wide/from16 v0, v20

    .line 342
    .line 343
    invoke-static {v0, v1, v2, v3}, Ljava/lang/Math;->min(JJ)J

    .line 344
    .line 345
    .line 346
    move-result-wide v0

    .line 347
    :goto_13
    invoke-static {v13, v14, v2, v3}, Ljava/lang/Math;->max(JJ)J

    .line 348
    .line 349
    .line 350
    move-result-wide v13

    .line 351
    cmp-long v11, v8, v18

    .line 352
    .line 353
    if-nez v11, :cond_1c

    .line 354
    .line 355
    move-wide v8, v2

    .line 356
    :cond_1c
    new-instance v11, Landroid/os/WorkSource;

    .line 357
    .line 358
    invoke-direct {v11, v5}, Landroid/os/WorkSource;-><init>(Landroid/os/WorkSource;)V

    .line 359
    .line 360
    .line 361
    const/16 v21, 0x0

    .line 362
    .line 363
    move/from16 v18, v15

    .line 364
    .line 365
    move-wide v15, v8

    .line 366
    const-wide v8, 0x7fffffffffffffffL

    .line 367
    .line 368
    .line 369
    .line 370
    .line 371
    move-wide/from16 v19, v0

    .line 372
    .line 373
    move v1, v4

    .line 374
    move-wide/from16 v4, v19

    .line 375
    .line 376
    move-object/from16 v0, p1

    .line 377
    .line 378
    move/from16 v17, v10

    .line 379
    .line 380
    move-object/from16 v20, v11

    .line 381
    .line 382
    move-wide/from16 v10, v24

    .line 383
    .line 384
    move/from16 v19, v26

    .line 385
    .line 386
    move-wide/from16 v29, v13

    .line 387
    .line 388
    move v13, v6

    .line 389
    move v14, v7

    .line 390
    move-wide/from16 v6, v29

    .line 391
    .line 392
    invoke-direct/range {v0 .. v21}, Lcom/google/android/gms/location/LocationRequest;-><init>(IJJJJJIFZJIIZLandroid/os/WorkSource;Lgp/g;)V

    .line 393
    .line 394
    .line 395
    move-object v1, v0

    .line 396
    move-object/from16 v0, p0

    .line 397
    .line 398
    iput-object v1, v0, Lgp/i;->d:Lcom/google/android/gms/location/LocationRequest;

    .line 399
    .line 400
    return-void
.end method


# virtual methods
.method public final equals(Ljava/lang/Object;)Z
    .locals 1

    .line 1
    instance-of v0, p1, Lgp/i;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    check-cast p1, Lgp/i;

    .line 6
    .line 7
    iget-object p0, p0, Lgp/i;->d:Lcom/google/android/gms/location/LocationRequest;

    .line 8
    .line 9
    iget-object p1, p1, Lgp/i;->d:Lcom/google/android/gms/location/LocationRequest;

    .line 10
    .line 11
    invoke-static {p0, p1}, Lno/c0;->l(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 12
    .line 13
    .line 14
    move-result p0

    .line 15
    return p0

    .line 16
    :cond_0
    const/4 p0, 0x0

    .line 17
    return p0
.end method

.method public final hashCode()I
    .locals 0

    .line 1
    iget-object p0, p0, Lgp/i;->d:Lcom/google/android/gms/location/LocationRequest;

    .line 2
    .line 3
    invoke-virtual {p0}, Lcom/google/android/gms/location/LocationRequest;->hashCode()I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public final toString()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lgp/i;->d:Lcom/google/android/gms/location/LocationRequest;

    .line 2
    .line 3
    invoke-virtual {p0}, Lcom/google/android/gms/location/LocationRequest;->toString()Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final writeToParcel(Landroid/os/Parcel;I)V
    .locals 2

    .line 1
    const/16 v0, 0x4f45

    .line 2
    .line 3
    invoke-static {p1, v0}, Ljp/dc;->s(Landroid/os/Parcel;I)I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    const/4 v1, 0x1

    .line 8
    iget-object p0, p0, Lgp/i;->d:Lcom/google/android/gms/location/LocationRequest;

    .line 9
    .line 10
    invoke-static {p1, v1, p0, p2}, Ljp/dc;->m(Landroid/os/Parcel;ILandroid/os/Parcelable;I)V

    .line 11
    .line 12
    .line 13
    invoke-static {p1, v0}, Ljp/dc;->t(Landroid/os/Parcel;I)V

    .line 14
    .line 15
    .line 16
    return-void
.end method
