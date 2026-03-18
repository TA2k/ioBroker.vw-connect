.class public final Lu/c1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final A:Lro/f;

.field public final B:Lcom/google/android/gms/internal/measurement/i4;

.field public final C:Lu/t0;

.field public final D:Ld0/b;

.field public final a:Ljava/util/ArrayList;

.field public final b:Ljava/util/ArrayList;

.field public final c:Ljava/util/ArrayList;

.field public final d:Ljava/util/ArrayList;

.field public final e:Ljava/util/ArrayList;

.field public final f:Ljava/util/ArrayList;

.field public final g:Ljava/util/HashMap;

.field public final h:Ljava/util/ArrayList;

.field public final i:Ljava/util/ArrayList;

.field public final j:Ljava/util/ArrayList;

.field public final k:Ljava/lang/String;

.field public final l:Lu/e;

.field public final m:Lv/b;

.field public final n:Lro/f;

.field public final o:I

.field public final p:Z

.field public final q:Z

.field public final r:Z

.field public final s:Z

.field public final t:Z

.field public final u:Z

.field public final v:Z

.field public w:Lh0/l;

.field public final x:Ljava/util/ArrayList;

.field public final y:Lu/q0;

.field public final z:Ldv/a;


# direct methods
.method public constructor <init>(Landroid/content/Context;Ljava/lang/String;Lv/d;Lu/e;Ld0/b;)V
    .locals 16

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p2

    .line 4
    .line 5
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    new-instance v2, Ljava/util/ArrayList;

    .line 9
    .line 10
    invoke-direct {v2}, Ljava/util/ArrayList;-><init>()V

    .line 11
    .line 12
    .line 13
    iput-object v2, v0, Lu/c1;->a:Ljava/util/ArrayList;

    .line 14
    .line 15
    new-instance v2, Ljava/util/ArrayList;

    .line 16
    .line 17
    invoke-direct {v2}, Ljava/util/ArrayList;-><init>()V

    .line 18
    .line 19
    .line 20
    iput-object v2, v0, Lu/c1;->b:Ljava/util/ArrayList;

    .line 21
    .line 22
    new-instance v2, Ljava/util/ArrayList;

    .line 23
    .line 24
    invoke-direct {v2}, Ljava/util/ArrayList;-><init>()V

    .line 25
    .line 26
    .line 27
    iput-object v2, v0, Lu/c1;->c:Ljava/util/ArrayList;

    .line 28
    .line 29
    new-instance v2, Ljava/util/ArrayList;

    .line 30
    .line 31
    invoke-direct {v2}, Ljava/util/ArrayList;-><init>()V

    .line 32
    .line 33
    .line 34
    iput-object v2, v0, Lu/c1;->d:Ljava/util/ArrayList;

    .line 35
    .line 36
    new-instance v2, Ljava/util/ArrayList;

    .line 37
    .line 38
    invoke-direct {v2}, Ljava/util/ArrayList;-><init>()V

    .line 39
    .line 40
    .line 41
    iput-object v2, v0, Lu/c1;->e:Ljava/util/ArrayList;

    .line 42
    .line 43
    new-instance v2, Ljava/util/ArrayList;

    .line 44
    .line 45
    invoke-direct {v2}, Ljava/util/ArrayList;-><init>()V

    .line 46
    .line 47
    .line 48
    iput-object v2, v0, Lu/c1;->f:Ljava/util/ArrayList;

    .line 49
    .line 50
    new-instance v2, Ljava/util/HashMap;

    .line 51
    .line 52
    invoke-direct {v2}, Ljava/util/HashMap;-><init>()V

    .line 53
    .line 54
    .line 55
    iput-object v2, v0, Lu/c1;->g:Ljava/util/HashMap;

    .line 56
    .line 57
    new-instance v2, Ljava/util/ArrayList;

    .line 58
    .line 59
    invoke-direct {v2}, Ljava/util/ArrayList;-><init>()V

    .line 60
    .line 61
    .line 62
    iput-object v2, v0, Lu/c1;->h:Ljava/util/ArrayList;

    .line 63
    .line 64
    new-instance v2, Ljava/util/ArrayList;

    .line 65
    .line 66
    invoke-direct {v2}, Ljava/util/ArrayList;-><init>()V

    .line 67
    .line 68
    .line 69
    iput-object v2, v0, Lu/c1;->i:Ljava/util/ArrayList;

    .line 70
    .line 71
    new-instance v2, Ljava/util/ArrayList;

    .line 72
    .line 73
    invoke-direct {v2}, Ljava/util/ArrayList;-><init>()V

    .line 74
    .line 75
    .line 76
    iput-object v2, v0, Lu/c1;->j:Ljava/util/ArrayList;

    .line 77
    .line 78
    const/4 v2, 0x0

    .line 79
    iput-boolean v2, v0, Lu/c1;->p:Z

    .line 80
    .line 81
    iput-boolean v2, v0, Lu/c1;->q:Z

    .line 82
    .line 83
    iput-boolean v2, v0, Lu/c1;->t:Z

    .line 84
    .line 85
    iput-boolean v2, v0, Lu/c1;->u:Z

    .line 86
    .line 87
    new-instance v3, Ljava/util/ArrayList;

    .line 88
    .line 89
    invoke-direct {v3}, Ljava/util/ArrayList;-><init>()V

    .line 90
    .line 91
    .line 92
    iput-object v3, v0, Lu/c1;->x:Ljava/util/ArrayList;

    .line 93
    .line 94
    new-instance v3, Ldv/a;

    .line 95
    .line 96
    const/16 v4, 0x1b

    .line 97
    .line 98
    invoke-direct {v3, v4}, Ldv/a;-><init>(I)V

    .line 99
    .line 100
    .line 101
    iput-object v3, v0, Lu/c1;->z:Ldv/a;

    .line 102
    .line 103
    new-instance v3, Lro/f;

    .line 104
    .line 105
    const/16 v4, 0x13

    .line 106
    .line 107
    invoke-direct {v3, v4}, Lro/f;-><init>(I)V

    .line 108
    .line 109
    .line 110
    iput-object v3, v0, Lu/c1;->A:Lro/f;

    .line 111
    .line 112
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 113
    .line 114
    .line 115
    iput-object v1, v0, Lu/c1;->k:Ljava/lang/String;

    .line 116
    .line 117
    invoke-virtual/range {p4 .. p4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 118
    .line 119
    .line 120
    move-object/from16 v3, p4

    .line 121
    .line 122
    iput-object v3, v0, Lu/c1;->l:Lu/e;

    .line 123
    .line 124
    new-instance v3, Lro/f;

    .line 125
    .line 126
    const/16 v4, 0x12

    .line 127
    .line 128
    invoke-direct {v3, v4}, Lro/f;-><init>(I)V

    .line 129
    .line 130
    .line 131
    iput-object v3, v0, Lu/c1;->n:Lro/f;

    .line 132
    .line 133
    invoke-static/range {p1 .. p1}, Lu/q0;->b(Landroid/content/Context;)Lu/q0;

    .line 134
    .line 135
    .line 136
    move-result-object v3

    .line 137
    iput-object v3, v0, Lu/c1;->y:Lu/q0;

    .line 138
    .line 139
    move-object/from16 v3, p3

    .line 140
    .line 141
    :try_start_0
    invoke-virtual {v3, v1}, Lv/d;->a(Ljava/lang/String;)Lv/b;

    .line 142
    .line 143
    .line 144
    move-result-object v1

    .line 145
    iput-object v1, v0, Lu/c1;->m:Lv/b;

    .line 146
    .line 147
    sget-object v3, Landroid/hardware/camera2/CameraCharacteristics;->INFO_SUPPORTED_HARDWARE_LEVEL:Landroid/hardware/camera2/CameraCharacteristics$Key;

    .line 148
    .line 149
    invoke-virtual {v1, v3}, Lv/b;->a(Landroid/hardware/camera2/CameraCharacteristics$Key;)Ljava/lang/Object;

    .line 150
    .line 151
    .line 152
    move-result-object v3

    .line 153
    check-cast v3, Ljava/lang/Integer;

    .line 154
    .line 155
    if-eqz v3, :cond_0

    .line 156
    .line 157
    invoke-virtual {v3}, Ljava/lang/Integer;->intValue()I

    .line 158
    .line 159
    .line 160
    move-result v3

    .line 161
    goto :goto_0

    .line 162
    :cond_0
    const/4 v3, 0x2

    .line 163
    :goto_0
    iput v3, v0, Lu/c1;->o:I
    :try_end_0
    .catch Lv/a; {:try_start_0 .. :try_end_0} :catch_0

    .line 164
    .line 165
    sget-object v3, Landroid/hardware/camera2/CameraCharacteristics;->REQUEST_AVAILABLE_CAPABILITIES:Landroid/hardware/camera2/CameraCharacteristics$Key;

    .line 166
    .line 167
    invoke-virtual {v1, v3}, Lv/b;->a(Landroid/hardware/camera2/CameraCharacteristics$Key;)Ljava/lang/Object;

    .line 168
    .line 169
    .line 170
    move-result-object v1

    .line 171
    check-cast v1, [I

    .line 172
    .line 173
    const/4 v3, 0x3

    .line 174
    const/4 v5, 0x1

    .line 175
    if-eqz v1, :cond_5

    .line 176
    .line 177
    array-length v6, v1

    .line 178
    move v7, v2

    .line 179
    :goto_1
    if-ge v7, v6, :cond_5

    .line 180
    .line 181
    aget v8, v1, v7

    .line 182
    .line 183
    if-ne v8, v3, :cond_1

    .line 184
    .line 185
    iput-boolean v5, v0, Lu/c1;->p:Z

    .line 186
    .line 187
    goto :goto_2

    .line 188
    :cond_1
    const/4 v9, 0x6

    .line 189
    if-ne v8, v9, :cond_2

    .line 190
    .line 191
    iput-boolean v5, v0, Lu/c1;->q:Z

    .line 192
    .line 193
    goto :goto_2

    .line 194
    :cond_2
    sget v9, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 195
    .line 196
    const/16 v10, 0x1f

    .line 197
    .line 198
    if-lt v9, v10, :cond_3

    .line 199
    .line 200
    const/16 v9, 0x10

    .line 201
    .line 202
    if-ne v8, v9, :cond_3

    .line 203
    .line 204
    iput-boolean v5, v0, Lu/c1;->t:Z

    .line 205
    .line 206
    goto :goto_2

    .line 207
    :cond_3
    if-ne v8, v5, :cond_4

    .line 208
    .line 209
    iput-boolean v5, v0, Lu/c1;->u:Z

    .line 210
    .line 211
    :cond_4
    :goto_2
    add-int/lit8 v7, v7, 0x1

    .line 212
    .line 213
    goto :goto_1

    .line 214
    :cond_5
    new-instance v1, Lcom/google/android/gms/internal/measurement/i4;

    .line 215
    .line 216
    iget-object v6, v0, Lu/c1;->m:Lv/b;

    .line 217
    .line 218
    invoke-direct {v1, v6}, Lcom/google/android/gms/internal/measurement/i4;-><init>(Lv/b;)V

    .line 219
    .line 220
    .line 221
    iput-object v1, v0, Lu/c1;->B:Lcom/google/android/gms/internal/measurement/i4;

    .line 222
    .line 223
    new-instance v6, Lu/t0;

    .line 224
    .line 225
    iget-object v7, v0, Lu/c1;->m:Lv/b;

    .line 226
    .line 227
    invoke-direct {v6, v7}, Lu/t0;-><init>(Lv/b;)V

    .line 228
    .line 229
    .line 230
    iput-object v6, v0, Lu/c1;->C:Lu/t0;

    .line 231
    .line 232
    iget-object v6, v0, Lu/c1;->a:Ljava/util/ArrayList;

    .line 233
    .line 234
    iget v7, v0, Lu/c1;->o:I

    .line 235
    .line 236
    iget-boolean v8, v0, Lu/c1;->p:Z

    .line 237
    .line 238
    iget-boolean v9, v0, Lu/c1;->q:Z

    .line 239
    .line 240
    new-instance v10, Ljava/util/ArrayList;

    .line 241
    .line 242
    invoke-direct {v10}, Ljava/util/ArrayList;-><init>()V

    .line 243
    .line 244
    .line 245
    new-instance v11, Ljava/util/ArrayList;

    .line 246
    .line 247
    invoke-direct {v11}, Ljava/util/ArrayList;-><init>()V

    .line 248
    .line 249
    .line 250
    new-instance v12, Lh0/d2;

    .line 251
    .line 252
    invoke-direct {v12}, Lh0/d2;-><init>()V

    .line 253
    .line 254
    .line 255
    sget-object v13, Lh0/g2;->d:Lh0/g2;

    .line 256
    .line 257
    sget-object v14, Lh0/e2;->p:Lh0/e2;

    .line 258
    .line 259
    invoke-static {v13, v14, v12, v11, v12}, Lu/w;->b(Lh0/g2;Lh0/e2;Lh0/d2;Ljava/util/ArrayList;Lh0/d2;)Lh0/d2;

    .line 260
    .line 261
    .line 262
    move-result-object v12

    .line 263
    sget-object v15, Lh0/g2;->f:Lh0/g2;

    .line 264
    .line 265
    invoke-static {v15, v14, v12, v11, v12}, Lu/w;->b(Lh0/g2;Lh0/e2;Lh0/d2;Ljava/util/ArrayList;Lh0/d2;)Lh0/d2;

    .line 266
    .line 267
    .line 268
    move-result-object v12

    .line 269
    sget-object v2, Lh0/g2;->e:Lh0/g2;

    .line 270
    .line 271
    invoke-static {v2, v14, v12, v11, v12}, Lu/w;->b(Lh0/g2;Lh0/e2;Lh0/d2;Ljava/util/ArrayList;Lh0/d2;)Lh0/d2;

    .line 272
    .line 273
    .line 274
    move-result-object v12

    .line 275
    sget-object v4, Lh0/e2;->i:Lh0/e2;

    .line 276
    .line 277
    invoke-static {v13, v4, v12, v15, v14}, Lu/w;->l(Lh0/g2;Lh0/e2;Lh0/d2;Lh0/g2;Lh0/e2;)V

    .line 278
    .line 279
    .line 280
    invoke-static {v11, v12}, Lu/w;->c(Ljava/util/ArrayList;Lh0/d2;)Lh0/d2;

    .line 281
    .line 282
    .line 283
    move-result-object v12

    .line 284
    invoke-static {v2, v4, v12, v15, v14}, Lu/w;->l(Lh0/g2;Lh0/e2;Lh0/d2;Lh0/g2;Lh0/e2;)V

    .line 285
    .line 286
    .line 287
    invoke-static {v11, v12}, Lu/w;->c(Ljava/util/ArrayList;Lh0/d2;)Lh0/d2;

    .line 288
    .line 289
    .line 290
    move-result-object v12

    .line 291
    invoke-static {v13, v4, v12, v13, v4}, Lu/w;->l(Lh0/g2;Lh0/e2;Lh0/d2;Lh0/g2;Lh0/e2;)V

    .line 292
    .line 293
    .line 294
    invoke-static {v11, v12}, Lu/w;->c(Ljava/util/ArrayList;Lh0/d2;)Lh0/d2;

    .line 295
    .line 296
    .line 297
    move-result-object v12

    .line 298
    invoke-static {v13, v4, v12, v2, v4}, Lu/w;->l(Lh0/g2;Lh0/e2;Lh0/d2;Lh0/g2;Lh0/e2;)V

    .line 299
    .line 300
    .line 301
    invoke-static {v11, v12}, Lu/w;->c(Ljava/util/ArrayList;Lh0/d2;)Lh0/d2;

    .line 302
    .line 303
    .line 304
    move-result-object v12

    .line 305
    invoke-static {v13, v4, v12, v2, v4}, Lu/w;->l(Lh0/g2;Lh0/e2;Lh0/d2;Lh0/g2;Lh0/e2;)V

    .line 306
    .line 307
    .line 308
    invoke-static {v15, v14}, Lh0/h2;->a(Lh0/g2;Lh0/e2;)Lh0/h2;

    .line 309
    .line 310
    .line 311
    move-result-object v3

    .line 312
    invoke-virtual {v12, v3}, Lh0/d2;->a(Lh0/h2;)V

    .line 313
    .line 314
    .line 315
    invoke-virtual {v11, v12}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 316
    .line 317
    .line 318
    invoke-virtual {v10, v11}, Ljava/util/ArrayList;->addAll(Ljava/util/Collection;)Z

    .line 319
    .line 320
    .line 321
    if-eqz v7, :cond_6

    .line 322
    .line 323
    const/4 v3, 0x4

    .line 324
    if-eq v7, v3, :cond_6

    .line 325
    .line 326
    if-eq v7, v5, :cond_6

    .line 327
    .line 328
    const/4 v3, 0x3

    .line 329
    if-ne v7, v3, :cond_7

    .line 330
    .line 331
    :cond_6
    new-instance v3, Ljava/util/ArrayList;

    .line 332
    .line 333
    invoke-direct {v3}, Ljava/util/ArrayList;-><init>()V

    .line 334
    .line 335
    .line 336
    new-instance v11, Lh0/d2;

    .line 337
    .line 338
    invoke-direct {v11}, Lh0/d2;-><init>()V

    .line 339
    .line 340
    .line 341
    invoke-static {v13, v4}, Lh0/h2;->a(Lh0/g2;Lh0/e2;)Lh0/h2;

    .line 342
    .line 343
    .line 344
    move-result-object v12

    .line 345
    invoke-virtual {v11, v12}, Lh0/d2;->a(Lh0/h2;)V

    .line 346
    .line 347
    .line 348
    sget-object v12, Lh0/e2;->o:Lh0/e2;

    .line 349
    .line 350
    invoke-static {v13, v12, v11, v3, v11}, Lu/w;->b(Lh0/g2;Lh0/e2;Lh0/d2;Ljava/util/ArrayList;Lh0/d2;)Lh0/d2;

    .line 351
    .line 352
    .line 353
    move-result-object v11

    .line 354
    invoke-static {v13, v4, v11, v2, v12}, Lu/w;->l(Lh0/g2;Lh0/e2;Lh0/d2;Lh0/g2;Lh0/e2;)V

    .line 355
    .line 356
    .line 357
    invoke-static {v3, v11}, Lu/w;->c(Ljava/util/ArrayList;Lh0/d2;)Lh0/d2;

    .line 358
    .line 359
    .line 360
    move-result-object v11

    .line 361
    invoke-static {v2, v4, v11, v2, v12}, Lu/w;->l(Lh0/g2;Lh0/e2;Lh0/d2;Lh0/g2;Lh0/e2;)V

    .line 362
    .line 363
    .line 364
    invoke-static {v3, v11}, Lu/w;->c(Ljava/util/ArrayList;Lh0/d2;)Lh0/d2;

    .line 365
    .line 366
    .line 367
    move-result-object v11

    .line 368
    invoke-static {v13, v4, v11, v13, v12}, Lu/w;->l(Lh0/g2;Lh0/e2;Lh0/d2;Lh0/g2;Lh0/e2;)V

    .line 369
    .line 370
    .line 371
    invoke-static {v15, v12, v11, v3, v11}, Lu/w;->b(Lh0/g2;Lh0/e2;Lh0/d2;Ljava/util/ArrayList;Lh0/d2;)Lh0/d2;

    .line 372
    .line 373
    .line 374
    move-result-object v11

    .line 375
    invoke-static {v13, v4, v11, v2, v12}, Lu/w;->l(Lh0/g2;Lh0/e2;Lh0/d2;Lh0/g2;Lh0/e2;)V

    .line 376
    .line 377
    .line 378
    invoke-static {v15, v12, v11, v3, v11}, Lu/w;->b(Lh0/g2;Lh0/e2;Lh0/d2;Ljava/util/ArrayList;Lh0/d2;)Lh0/d2;

    .line 379
    .line 380
    .line 381
    move-result-object v11

    .line 382
    invoke-static {v2, v4, v11, v2, v4}, Lu/w;->l(Lh0/g2;Lh0/e2;Lh0/d2;Lh0/g2;Lh0/e2;)V

    .line 383
    .line 384
    .line 385
    invoke-static {v15, v14}, Lh0/h2;->a(Lh0/g2;Lh0/e2;)Lh0/h2;

    .line 386
    .line 387
    .line 388
    move-result-object v12

    .line 389
    invoke-virtual {v11, v12}, Lh0/d2;->a(Lh0/h2;)V

    .line 390
    .line 391
    .line 392
    invoke-virtual {v3, v11}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 393
    .line 394
    .line 395
    invoke-virtual {v10, v3}, Ljava/util/ArrayList;->addAll(Ljava/util/Collection;)Z

    .line 396
    .line 397
    .line 398
    :cond_7
    if-eq v7, v5, :cond_8

    .line 399
    .line 400
    const/4 v3, 0x3

    .line 401
    if-ne v7, v3, :cond_9

    .line 402
    .line 403
    :cond_8
    new-instance v3, Ljava/util/ArrayList;

    .line 404
    .line 405
    invoke-direct {v3}, Ljava/util/ArrayList;-><init>()V

    .line 406
    .line 407
    .line 408
    new-instance v11, Lh0/d2;

    .line 409
    .line 410
    invoke-direct {v11}, Lh0/d2;-><init>()V

    .line 411
    .line 412
    .line 413
    invoke-static {v13, v4, v11, v13, v14}, Lu/w;->l(Lh0/g2;Lh0/e2;Lh0/d2;Lh0/g2;Lh0/e2;)V

    .line 414
    .line 415
    .line 416
    invoke-static {v3, v11}, Lu/w;->c(Ljava/util/ArrayList;Lh0/d2;)Lh0/d2;

    .line 417
    .line 418
    .line 419
    move-result-object v11

    .line 420
    invoke-static {v13, v4, v11, v2, v14}, Lu/w;->l(Lh0/g2;Lh0/e2;Lh0/d2;Lh0/g2;Lh0/e2;)V

    .line 421
    .line 422
    .line 423
    invoke-static {v3, v11}, Lu/w;->c(Ljava/util/ArrayList;Lh0/d2;)Lh0/d2;

    .line 424
    .line 425
    .line 426
    move-result-object v11

    .line 427
    invoke-static {v2, v4, v11, v2, v14}, Lu/w;->l(Lh0/g2;Lh0/e2;Lh0/d2;Lh0/g2;Lh0/e2;)V

    .line 428
    .line 429
    .line 430
    invoke-static {v3, v11}, Lu/w;->c(Ljava/util/ArrayList;Lh0/d2;)Lh0/d2;

    .line 431
    .line 432
    .line 433
    move-result-object v11

    .line 434
    invoke-static {v13, v4, v11, v13, v4}, Lu/w;->l(Lh0/g2;Lh0/e2;Lh0/d2;Lh0/g2;Lh0/e2;)V

    .line 435
    .line 436
    .line 437
    invoke-static {v15, v14, v11, v3, v11}, Lu/w;->b(Lh0/g2;Lh0/e2;Lh0/d2;Ljava/util/ArrayList;Lh0/d2;)Lh0/d2;

    .line 438
    .line 439
    .line 440
    move-result-object v11

    .line 441
    sget-object v12, Lh0/e2;->f:Lh0/e2;

    .line 442
    .line 443
    invoke-static {v2, v12, v11, v13, v4}, Lu/w;->l(Lh0/g2;Lh0/e2;Lh0/d2;Lh0/g2;Lh0/e2;)V

    .line 444
    .line 445
    .line 446
    invoke-static {v2, v14, v11, v3, v11}, Lu/w;->b(Lh0/g2;Lh0/e2;Lh0/d2;Ljava/util/ArrayList;Lh0/d2;)Lh0/d2;

    .line 447
    .line 448
    .line 449
    move-result-object v11

    .line 450
    invoke-static {v2, v12, v11, v2, v4}, Lu/w;->l(Lh0/g2;Lh0/e2;Lh0/d2;Lh0/g2;Lh0/e2;)V

    .line 451
    .line 452
    .line 453
    invoke-static {v2, v14}, Lh0/h2;->a(Lh0/g2;Lh0/e2;)Lh0/h2;

    .line 454
    .line 455
    .line 456
    move-result-object v12

    .line 457
    invoke-virtual {v11, v12}, Lh0/d2;->a(Lh0/h2;)V

    .line 458
    .line 459
    .line 460
    invoke-virtual {v3, v11}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 461
    .line 462
    .line 463
    invoke-virtual {v10, v3}, Ljava/util/ArrayList;->addAll(Ljava/util/Collection;)Z

    .line 464
    .line 465
    .line 466
    :cond_9
    if-eqz v8, :cond_a

    .line 467
    .line 468
    new-instance v3, Ljava/util/ArrayList;

    .line 469
    .line 470
    invoke-direct {v3}, Ljava/util/ArrayList;-><init>()V

    .line 471
    .line 472
    .line 473
    new-instance v8, Lh0/d2;

    .line 474
    .line 475
    invoke-direct {v8}, Lh0/d2;-><init>()V

    .line 476
    .line 477
    .line 478
    sget-object v11, Lh0/g2;->h:Lh0/g2;

    .line 479
    .line 480
    invoke-static {v11, v14, v8, v3, v8}, Lu/w;->b(Lh0/g2;Lh0/e2;Lh0/d2;Ljava/util/ArrayList;Lh0/d2;)Lh0/d2;

    .line 481
    .line 482
    .line 483
    move-result-object v8

    .line 484
    invoke-static {v13, v4, v8, v11, v14}, Lu/w;->l(Lh0/g2;Lh0/e2;Lh0/d2;Lh0/g2;Lh0/e2;)V

    .line 485
    .line 486
    .line 487
    invoke-static {v3, v8}, Lu/w;->c(Ljava/util/ArrayList;Lh0/d2;)Lh0/d2;

    .line 488
    .line 489
    .line 490
    move-result-object v8

    .line 491
    invoke-static {v2, v4, v8, v11, v14}, Lu/w;->l(Lh0/g2;Lh0/e2;Lh0/d2;Lh0/g2;Lh0/e2;)V

    .line 492
    .line 493
    .line 494
    invoke-static {v3, v8}, Lu/w;->c(Ljava/util/ArrayList;Lh0/d2;)Lh0/d2;

    .line 495
    .line 496
    .line 497
    move-result-object v8

    .line 498
    invoke-static {v13, v4, v8, v13, v4}, Lu/w;->l(Lh0/g2;Lh0/e2;Lh0/d2;Lh0/g2;Lh0/e2;)V

    .line 499
    .line 500
    .line 501
    invoke-static {v11, v14, v8, v3, v8}, Lu/w;->b(Lh0/g2;Lh0/e2;Lh0/d2;Ljava/util/ArrayList;Lh0/d2;)Lh0/d2;

    .line 502
    .line 503
    .line 504
    move-result-object v8

    .line 505
    invoke-static {v13, v4, v8, v2, v4}, Lu/w;->l(Lh0/g2;Lh0/e2;Lh0/d2;Lh0/g2;Lh0/e2;)V

    .line 506
    .line 507
    .line 508
    invoke-static {v11, v14, v8, v3, v8}, Lu/w;->b(Lh0/g2;Lh0/e2;Lh0/d2;Ljava/util/ArrayList;Lh0/d2;)Lh0/d2;

    .line 509
    .line 510
    .line 511
    move-result-object v8

    .line 512
    invoke-static {v2, v4, v8, v2, v4}, Lu/w;->l(Lh0/g2;Lh0/e2;Lh0/d2;Lh0/g2;Lh0/e2;)V

    .line 513
    .line 514
    .line 515
    invoke-static {v11, v14, v8, v3, v8}, Lu/w;->b(Lh0/g2;Lh0/e2;Lh0/d2;Ljava/util/ArrayList;Lh0/d2;)Lh0/d2;

    .line 516
    .line 517
    .line 518
    move-result-object v8

    .line 519
    invoke-static {v13, v4, v8, v15, v14}, Lu/w;->l(Lh0/g2;Lh0/e2;Lh0/d2;Lh0/g2;Lh0/e2;)V

    .line 520
    .line 521
    .line 522
    invoke-static {v11, v14, v8, v3, v8}, Lu/w;->b(Lh0/g2;Lh0/e2;Lh0/d2;Ljava/util/ArrayList;Lh0/d2;)Lh0/d2;

    .line 523
    .line 524
    .line 525
    move-result-object v8

    .line 526
    invoke-static {v2, v4, v8, v15, v14}, Lu/w;->l(Lh0/g2;Lh0/e2;Lh0/d2;Lh0/g2;Lh0/e2;)V

    .line 527
    .line 528
    .line 529
    invoke-static {v11, v14}, Lh0/h2;->a(Lh0/g2;Lh0/e2;)Lh0/h2;

    .line 530
    .line 531
    .line 532
    move-result-object v11

    .line 533
    invoke-virtual {v8, v11}, Lh0/d2;->a(Lh0/h2;)V

    .line 534
    .line 535
    .line 536
    invoke-virtual {v3, v8}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 537
    .line 538
    .line 539
    invoke-virtual {v10, v3}, Ljava/util/ArrayList;->addAll(Ljava/util/Collection;)Z

    .line 540
    .line 541
    .line 542
    :cond_a
    if-eqz v9, :cond_b

    .line 543
    .line 544
    if-nez v7, :cond_b

    .line 545
    .line 546
    new-instance v3, Ljava/util/ArrayList;

    .line 547
    .line 548
    invoke-direct {v3}, Ljava/util/ArrayList;-><init>()V

    .line 549
    .line 550
    .line 551
    new-instance v8, Lh0/d2;

    .line 552
    .line 553
    invoke-direct {v8}, Lh0/d2;-><init>()V

    .line 554
    .line 555
    .line 556
    invoke-static {v13, v4, v8, v13, v14}, Lu/w;->l(Lh0/g2;Lh0/e2;Lh0/d2;Lh0/g2;Lh0/e2;)V

    .line 557
    .line 558
    .line 559
    invoke-static {v3, v8}, Lu/w;->c(Ljava/util/ArrayList;Lh0/d2;)Lh0/d2;

    .line 560
    .line 561
    .line 562
    move-result-object v8

    .line 563
    invoke-static {v13, v4, v8, v2, v14}, Lu/w;->l(Lh0/g2;Lh0/e2;Lh0/d2;Lh0/g2;Lh0/e2;)V

    .line 564
    .line 565
    .line 566
    invoke-static {v3, v8}, Lu/w;->c(Ljava/util/ArrayList;Lh0/d2;)Lh0/d2;

    .line 567
    .line 568
    .line 569
    move-result-object v8

    .line 570
    invoke-static {v2, v4, v8, v2, v14}, Lu/w;->l(Lh0/g2;Lh0/e2;Lh0/d2;Lh0/g2;Lh0/e2;)V

    .line 571
    .line 572
    .line 573
    invoke-virtual {v3, v8}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 574
    .line 575
    .line 576
    invoke-virtual {v10, v3}, Ljava/util/ArrayList;->addAll(Ljava/util/Collection;)Z

    .line 577
    .line 578
    .line 579
    :cond_b
    const/4 v3, 0x3

    .line 580
    if-ne v7, v3, :cond_c

    .line 581
    .line 582
    new-instance v3, Ljava/util/ArrayList;

    .line 583
    .line 584
    invoke-direct {v3}, Ljava/util/ArrayList;-><init>()V

    .line 585
    .line 586
    .line 587
    new-instance v7, Lh0/d2;

    .line 588
    .line 589
    invoke-direct {v7}, Lh0/d2;-><init>()V

    .line 590
    .line 591
    .line 592
    invoke-static {v13, v4}, Lh0/h2;->a(Lh0/g2;Lh0/e2;)Lh0/h2;

    .line 593
    .line 594
    .line 595
    move-result-object v8

    .line 596
    invoke-virtual {v7, v8}, Lh0/d2;->a(Lh0/h2;)V

    .line 597
    .line 598
    .line 599
    sget-object v8, Lh0/e2;->f:Lh0/e2;

    .line 600
    .line 601
    invoke-static {v13, v8, v7, v2, v14}, Lu/w;->l(Lh0/g2;Lh0/e2;Lh0/d2;Lh0/g2;Lh0/e2;)V

    .line 602
    .line 603
    .line 604
    sget-object v9, Lh0/g2;->h:Lh0/g2;

    .line 605
    .line 606
    invoke-static {v9, v14, v7, v3, v7}, Lu/w;->b(Lh0/g2;Lh0/e2;Lh0/d2;Ljava/util/ArrayList;Lh0/d2;)Lh0/d2;

    .line 607
    .line 608
    .line 609
    move-result-object v7

    .line 610
    invoke-static {v13, v4, v7, v13, v8}, Lu/w;->l(Lh0/g2;Lh0/e2;Lh0/d2;Lh0/g2;Lh0/e2;)V

    .line 611
    .line 612
    .line 613
    invoke-static {v15, v14, v7, v9, v14}, Lu/w;->l(Lh0/g2;Lh0/e2;Lh0/d2;Lh0/g2;Lh0/e2;)V

    .line 614
    .line 615
    .line 616
    invoke-virtual {v3, v7}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 617
    .line 618
    .line 619
    invoke-virtual {v10, v3}, Ljava/util/ArrayList;->addAll(Ljava/util/Collection;)Z

    .line 620
    .line 621
    .line 622
    :cond_c
    invoke-virtual {v6, v10}, Ljava/util/ArrayList;->addAll(Ljava/util/Collection;)Z

    .line 623
    .line 624
    .line 625
    iget-object v3, v0, Lu/c1;->n:Lro/f;

    .line 626
    .line 627
    iget-object v7, v0, Lu/c1;->k:Ljava/lang/String;

    .line 628
    .line 629
    iget-object v3, v3, Lro/f;->e:Ljava/lang/Object;

    .line 630
    .line 631
    check-cast v3, Landroidx/camera/camera2/internal/compat/quirk/ExtraSupportedSurfaceCombinationsQuirk;

    .line 632
    .line 633
    if-nez v3, :cond_d

    .line 634
    .line 635
    new-instance v3, Ljava/util/ArrayList;

    .line 636
    .line 637
    invoke-direct {v3}, Ljava/util/ArrayList;-><init>()V

    .line 638
    .line 639
    .line 640
    goto :goto_6

    .line 641
    :cond_d
    sget-object v3, Landroidx/camera/camera2/internal/compat/quirk/ExtraSupportedSurfaceCombinationsQuirk;->a:Lh0/d2;

    .line 642
    .line 643
    sget-object v3, Landroid/os/Build;->DEVICE:Ljava/lang/String;

    .line 644
    .line 645
    const-string v8, "heroqltevzw"

    .line 646
    .line 647
    invoke-virtual {v8, v3}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 648
    .line 649
    .line 650
    move-result v8

    .line 651
    if-nez v8, :cond_12

    .line 652
    .line 653
    const-string v8, "heroqltetmo"

    .line 654
    .line 655
    invoke-virtual {v8, v3}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 656
    .line 657
    .line 658
    move-result v3

    .line 659
    if-eqz v3, :cond_e

    .line 660
    .line 661
    goto :goto_5

    .line 662
    :cond_e
    const-string v3, "google"

    .line 663
    .line 664
    sget-object v7, Landroid/os/Build;->BRAND:Ljava/lang/String;

    .line 665
    .line 666
    invoke-virtual {v3, v7}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 667
    .line 668
    .line 669
    move-result v3

    .line 670
    if-nez v3, :cond_f

    .line 671
    .line 672
    const/4 v3, 0x0

    .line 673
    goto :goto_3

    .line 674
    :cond_f
    sget-object v3, Landroid/os/Build;->MODEL:Ljava/lang/String;

    .line 675
    .line 676
    sget-object v7, Ljava/util/Locale;->US:Ljava/util/Locale;

    .line 677
    .line 678
    invoke-virtual {v3, v7}, Ljava/lang/String;->toUpperCase(Ljava/util/Locale;)Ljava/lang/String;

    .line 679
    .line 680
    .line 681
    move-result-object v3

    .line 682
    sget-object v7, Landroidx/camera/camera2/internal/compat/quirk/ExtraSupportedSurfaceCombinationsQuirk;->c:Ljava/util/HashSet;

    .line 683
    .line 684
    invoke-virtual {v7, v3}, Ljava/util/HashSet;->contains(Ljava/lang/Object;)Z

    .line 685
    .line 686
    .line 687
    move-result v3

    .line 688
    :goto_3
    if-nez v3, :cond_11

    .line 689
    .line 690
    invoke-static {}, Landroidx/camera/camera2/internal/compat/quirk/ExtraSupportedSurfaceCombinationsQuirk;->b()Z

    .line 691
    .line 692
    .line 693
    move-result v3

    .line 694
    if-eqz v3, :cond_10

    .line 695
    .line 696
    goto :goto_4

    .line 697
    :cond_10
    sget-object v3, Ljava/util/Collections;->EMPTY_LIST:Ljava/util/List;

    .line 698
    .line 699
    goto :goto_6

    .line 700
    :cond_11
    :goto_4
    sget-object v3, Landroidx/camera/camera2/internal/compat/quirk/ExtraSupportedSurfaceCombinationsQuirk;->b:Lh0/d2;

    .line 701
    .line 702
    invoke-static {v3}, Ljava/util/Collections;->singletonList(Ljava/lang/Object;)Ljava/util/List;

    .line 703
    .line 704
    .line 705
    move-result-object v3

    .line 706
    goto :goto_6

    .line 707
    :cond_12
    :goto_5
    new-instance v3, Ljava/util/ArrayList;

    .line 708
    .line 709
    invoke-direct {v3}, Ljava/util/ArrayList;-><init>()V

    .line 710
    .line 711
    .line 712
    const-string v8, "1"

    .line 713
    .line 714
    invoke-virtual {v7, v8}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 715
    .line 716
    .line 717
    move-result v7

    .line 718
    if-eqz v7, :cond_13

    .line 719
    .line 720
    sget-object v7, Landroidx/camera/camera2/internal/compat/quirk/ExtraSupportedSurfaceCombinationsQuirk;->a:Lh0/d2;

    .line 721
    .line 722
    invoke-virtual {v3, v7}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 723
    .line 724
    .line 725
    :cond_13
    :goto_6
    invoke-virtual {v6, v3}, Ljava/util/ArrayList;->addAll(Ljava/util/Collection;)Z

    .line 726
    .line 727
    .line 728
    iget-boolean v3, v0, Lu/c1;->t:Z

    .line 729
    .line 730
    if-eqz v3, :cond_14

    .line 731
    .line 732
    iget-object v3, v0, Lu/c1;->b:Ljava/util/ArrayList;

    .line 733
    .line 734
    new-instance v6, Ljava/util/ArrayList;

    .line 735
    .line 736
    invoke-direct {v6}, Ljava/util/ArrayList;-><init>()V

    .line 737
    .line 738
    .line 739
    new-instance v7, Lh0/d2;

    .line 740
    .line 741
    invoke-direct {v7}, Lh0/d2;-><init>()V

    .line 742
    .line 743
    .line 744
    sget-object v8, Lh0/e2;->s:Lh0/e2;

    .line 745
    .line 746
    invoke-static {v2, v8, v7, v13, v4}, Lu/w;->l(Lh0/g2;Lh0/e2;Lh0/d2;Lh0/g2;Lh0/e2;)V

    .line 747
    .line 748
    .line 749
    sget-object v9, Lh0/e2;->o:Lh0/e2;

    .line 750
    .line 751
    invoke-static {v13, v9, v7, v6, v7}, Lu/w;->b(Lh0/g2;Lh0/e2;Lh0/d2;Ljava/util/ArrayList;Lh0/d2;)Lh0/d2;

    .line 752
    .line 753
    .line 754
    move-result-object v7

    .line 755
    invoke-static {v15, v8, v7, v13, v4}, Lu/w;->l(Lh0/g2;Lh0/e2;Lh0/d2;Lh0/g2;Lh0/e2;)V

    .line 756
    .line 757
    .line 758
    invoke-static {v13, v9, v7, v6, v7}, Lu/w;->b(Lh0/g2;Lh0/e2;Lh0/d2;Ljava/util/ArrayList;Lh0/d2;)Lh0/d2;

    .line 759
    .line 760
    .line 761
    move-result-object v7

    .line 762
    sget-object v10, Lh0/g2;->h:Lh0/g2;

    .line 763
    .line 764
    invoke-static {v10, v8, v7, v13, v4}, Lu/w;->l(Lh0/g2;Lh0/e2;Lh0/d2;Lh0/g2;Lh0/e2;)V

    .line 765
    .line 766
    .line 767
    invoke-static {v13, v9, v7, v6, v7}, Lu/w;->b(Lh0/g2;Lh0/e2;Lh0/d2;Ljava/util/ArrayList;Lh0/d2;)Lh0/d2;

    .line 768
    .line 769
    .line 770
    move-result-object v7

    .line 771
    invoke-static {v2, v8, v7, v13, v4}, Lu/w;->l(Lh0/g2;Lh0/e2;Lh0/d2;Lh0/g2;Lh0/e2;)V

    .line 772
    .line 773
    .line 774
    invoke-static {v15, v14, v7, v6, v7}, Lu/w;->b(Lh0/g2;Lh0/e2;Lh0/d2;Ljava/util/ArrayList;Lh0/d2;)Lh0/d2;

    .line 775
    .line 776
    .line 777
    move-result-object v7

    .line 778
    invoke-static {v15, v8, v7, v13, v4}, Lu/w;->l(Lh0/g2;Lh0/e2;Lh0/d2;Lh0/g2;Lh0/e2;)V

    .line 779
    .line 780
    .line 781
    invoke-static {v15, v14, v7, v6, v7}, Lu/w;->b(Lh0/g2;Lh0/e2;Lh0/d2;Ljava/util/ArrayList;Lh0/d2;)Lh0/d2;

    .line 782
    .line 783
    .line 784
    move-result-object v7

    .line 785
    invoke-static {v10, v8, v7, v13, v4}, Lu/w;->l(Lh0/g2;Lh0/e2;Lh0/d2;Lh0/g2;Lh0/e2;)V

    .line 786
    .line 787
    .line 788
    invoke-static {v15, v14, v7, v6, v7}, Lu/w;->b(Lh0/g2;Lh0/e2;Lh0/d2;Ljava/util/ArrayList;Lh0/d2;)Lh0/d2;

    .line 789
    .line 790
    .line 791
    move-result-object v7

    .line 792
    invoke-static {v2, v8, v7, v13, v4}, Lu/w;->l(Lh0/g2;Lh0/e2;Lh0/d2;Lh0/g2;Lh0/e2;)V

    .line 793
    .line 794
    .line 795
    invoke-static {v2, v14, v7, v6, v7}, Lu/w;->b(Lh0/g2;Lh0/e2;Lh0/d2;Ljava/util/ArrayList;Lh0/d2;)Lh0/d2;

    .line 796
    .line 797
    .line 798
    move-result-object v7

    .line 799
    invoke-static {v15, v8, v7, v13, v4}, Lu/w;->l(Lh0/g2;Lh0/e2;Lh0/d2;Lh0/g2;Lh0/e2;)V

    .line 800
    .line 801
    .line 802
    invoke-static {v2, v14, v7, v6, v7}, Lu/w;->b(Lh0/g2;Lh0/e2;Lh0/d2;Ljava/util/ArrayList;Lh0/d2;)Lh0/d2;

    .line 803
    .line 804
    .line 805
    move-result-object v7

    .line 806
    invoke-static {v10, v8, v7, v13, v4}, Lu/w;->l(Lh0/g2;Lh0/e2;Lh0/d2;Lh0/g2;Lh0/e2;)V

    .line 807
    .line 808
    .line 809
    invoke-static {v2, v14, v7, v6, v7}, Lu/w;->b(Lh0/g2;Lh0/e2;Lh0/d2;Ljava/util/ArrayList;Lh0/d2;)Lh0/d2;

    .line 810
    .line 811
    .line 812
    move-result-object v7

    .line 813
    invoke-static {v2, v8, v7, v13, v4}, Lu/w;->l(Lh0/g2;Lh0/e2;Lh0/d2;Lh0/g2;Lh0/e2;)V

    .line 814
    .line 815
    .line 816
    invoke-static {v10, v14, v7, v6, v7}, Lu/w;->b(Lh0/g2;Lh0/e2;Lh0/d2;Ljava/util/ArrayList;Lh0/d2;)Lh0/d2;

    .line 817
    .line 818
    .line 819
    move-result-object v7

    .line 820
    invoke-static {v15, v8, v7, v13, v4}, Lu/w;->l(Lh0/g2;Lh0/e2;Lh0/d2;Lh0/g2;Lh0/e2;)V

    .line 821
    .line 822
    .line 823
    invoke-static {v10, v14, v7, v6, v7}, Lu/w;->b(Lh0/g2;Lh0/e2;Lh0/d2;Ljava/util/ArrayList;Lh0/d2;)Lh0/d2;

    .line 824
    .line 825
    .line 826
    move-result-object v7

    .line 827
    invoke-static {v10, v8, v7, v13, v4}, Lu/w;->l(Lh0/g2;Lh0/e2;Lh0/d2;Lh0/g2;Lh0/e2;)V

    .line 828
    .line 829
    .line 830
    invoke-static {v10, v14}, Lh0/h2;->a(Lh0/g2;Lh0/e2;)Lh0/h2;

    .line 831
    .line 832
    .line 833
    move-result-object v8

    .line 834
    invoke-virtual {v7, v8}, Lh0/d2;->a(Lh0/h2;)V

    .line 835
    .line 836
    .line 837
    invoke-virtual {v6, v7}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 838
    .line 839
    .line 840
    invoke-virtual {v3, v6}, Ljava/util/ArrayList;->addAll(Ljava/util/Collection;)Z

    .line 841
    .line 842
    .line 843
    :cond_14
    invoke-virtual/range {p1 .. p1}, Landroid/content/Context;->getPackageManager()Landroid/content/pm/PackageManager;

    .line 844
    .line 845
    .line 846
    move-result-object v3

    .line 847
    const-string v6, "android.hardware.camera.concurrent"

    .line 848
    .line 849
    invoke-virtual {v3, v6}, Landroid/content/pm/PackageManager;->hasSystemFeature(Ljava/lang/String;)Z

    .line 850
    .line 851
    .line 852
    move-result v3

    .line 853
    iput-boolean v3, v0, Lu/c1;->r:Z

    .line 854
    .line 855
    if-eqz v3, :cond_15

    .line 856
    .line 857
    iget-object v3, v0, Lu/c1;->c:Ljava/util/ArrayList;

    .line 858
    .line 859
    new-instance v6, Ljava/util/ArrayList;

    .line 860
    .line 861
    invoke-direct {v6}, Ljava/util/ArrayList;-><init>()V

    .line 862
    .line 863
    .line 864
    new-instance v7, Lh0/d2;

    .line 865
    .line 866
    invoke-direct {v7}, Lh0/d2;-><init>()V

    .line 867
    .line 868
    .line 869
    sget-object v8, Lh0/e2;->l:Lh0/e2;

    .line 870
    .line 871
    invoke-static {v2, v8, v7, v6, v7}, Lu/w;->b(Lh0/g2;Lh0/e2;Lh0/d2;Ljava/util/ArrayList;Lh0/d2;)Lh0/d2;

    .line 872
    .line 873
    .line 874
    move-result-object v7

    .line 875
    invoke-static {v13, v8, v7, v6, v7}, Lu/w;->b(Lh0/g2;Lh0/e2;Lh0/d2;Ljava/util/ArrayList;Lh0/d2;)Lh0/d2;

    .line 876
    .line 877
    .line 878
    move-result-object v7

    .line 879
    invoke-static {v15, v8, v7, v6, v7}, Lu/w;->b(Lh0/g2;Lh0/e2;Lh0/d2;Ljava/util/ArrayList;Lh0/d2;)Lh0/d2;

    .line 880
    .line 881
    .line 882
    move-result-object v7

    .line 883
    sget-object v9, Lh0/e2;->h:Lh0/e2;

    .line 884
    .line 885
    invoke-static {v2, v9, v7, v15, v8}, Lu/w;->l(Lh0/g2;Lh0/e2;Lh0/d2;Lh0/g2;Lh0/e2;)V

    .line 886
    .line 887
    .line 888
    invoke-static {v6, v7}, Lu/w;->c(Ljava/util/ArrayList;Lh0/d2;)Lh0/d2;

    .line 889
    .line 890
    .line 891
    move-result-object v7

    .line 892
    invoke-static {v13, v9, v7, v15, v8}, Lu/w;->l(Lh0/g2;Lh0/e2;Lh0/d2;Lh0/g2;Lh0/e2;)V

    .line 893
    .line 894
    .line 895
    invoke-static {v6, v7}, Lu/w;->c(Ljava/util/ArrayList;Lh0/d2;)Lh0/d2;

    .line 896
    .line 897
    .line 898
    move-result-object v7

    .line 899
    invoke-static {v2, v9, v7, v2, v8}, Lu/w;->l(Lh0/g2;Lh0/e2;Lh0/d2;Lh0/g2;Lh0/e2;)V

    .line 900
    .line 901
    .line 902
    invoke-static {v6, v7}, Lu/w;->c(Ljava/util/ArrayList;Lh0/d2;)Lh0/d2;

    .line 903
    .line 904
    .line 905
    move-result-object v7

    .line 906
    invoke-static {v2, v9, v7, v13, v8}, Lu/w;->l(Lh0/g2;Lh0/e2;Lh0/d2;Lh0/g2;Lh0/e2;)V

    .line 907
    .line 908
    .line 909
    invoke-static {v6, v7}, Lu/w;->c(Ljava/util/ArrayList;Lh0/d2;)Lh0/d2;

    .line 910
    .line 911
    .line 912
    move-result-object v7

    .line 913
    invoke-static {v13, v9, v7, v2, v8}, Lu/w;->l(Lh0/g2;Lh0/e2;Lh0/d2;Lh0/g2;Lh0/e2;)V

    .line 914
    .line 915
    .line 916
    invoke-static {v6, v7}, Lu/w;->c(Ljava/util/ArrayList;Lh0/d2;)Lh0/d2;

    .line 917
    .line 918
    .line 919
    move-result-object v7

    .line 920
    invoke-static {v13, v9, v7, v13, v8}, Lu/w;->l(Lh0/g2;Lh0/e2;Lh0/d2;Lh0/g2;Lh0/e2;)V

    .line 921
    .line 922
    .line 923
    invoke-virtual {v6, v7}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 924
    .line 925
    .line 926
    invoke-virtual {v3, v6}, Ljava/util/ArrayList;->addAll(Ljava/util/Collection;)Z

    .line 927
    .line 928
    .line 929
    :cond_15
    iget-boolean v1, v1, Lcom/google/android/gms/internal/measurement/i4;->e:Z

    .line 930
    .line 931
    if-eqz v1, :cond_16

    .line 932
    .line 933
    iget-object v1, v0, Lu/c1;->h:Ljava/util/ArrayList;

    .line 934
    .line 935
    new-instance v3, Ljava/util/ArrayList;

    .line 936
    .line 937
    invoke-direct {v3}, Ljava/util/ArrayList;-><init>()V

    .line 938
    .line 939
    .line 940
    new-instance v6, Lh0/d2;

    .line 941
    .line 942
    invoke-direct {v6}, Lh0/d2;-><init>()V

    .line 943
    .line 944
    .line 945
    invoke-static {v13, v14, v6, v3, v6}, Lu/w;->b(Lh0/g2;Lh0/e2;Lh0/d2;Ljava/util/ArrayList;Lh0/d2;)Lh0/d2;

    .line 946
    .line 947
    .line 948
    move-result-object v6

    .line 949
    invoke-static {v2, v14, v6, v3, v6}, Lu/w;->b(Lh0/g2;Lh0/e2;Lh0/d2;Ljava/util/ArrayList;Lh0/d2;)Lh0/d2;

    .line 950
    .line 951
    .line 952
    move-result-object v6

    .line 953
    invoke-static {v13, v4, v6, v15, v14}, Lu/w;->l(Lh0/g2;Lh0/e2;Lh0/d2;Lh0/g2;Lh0/e2;)V

    .line 954
    .line 955
    .line 956
    invoke-static {v3, v6}, Lu/w;->c(Ljava/util/ArrayList;Lh0/d2;)Lh0/d2;

    .line 957
    .line 958
    .line 959
    move-result-object v6

    .line 960
    invoke-static {v13, v4, v6, v2, v14}, Lu/w;->l(Lh0/g2;Lh0/e2;Lh0/d2;Lh0/g2;Lh0/e2;)V

    .line 961
    .line 962
    .line 963
    invoke-static {v3, v6}, Lu/w;->c(Ljava/util/ArrayList;Lh0/d2;)Lh0/d2;

    .line 964
    .line 965
    .line 966
    move-result-object v6

    .line 967
    invoke-static {v2, v4, v6, v2, v14}, Lu/w;->l(Lh0/g2;Lh0/e2;Lh0/d2;Lh0/g2;Lh0/e2;)V

    .line 968
    .line 969
    .line 970
    invoke-static {v3, v6}, Lu/w;->c(Ljava/util/ArrayList;Lh0/d2;)Lh0/d2;

    .line 971
    .line 972
    .line 973
    move-result-object v6

    .line 974
    invoke-static {v13, v4}, Lh0/h2;->a(Lh0/g2;Lh0/e2;)Lh0/h2;

    .line 975
    .line 976
    .line 977
    move-result-object v7

    .line 978
    invoke-virtual {v6, v7}, Lh0/d2;->a(Lh0/h2;)V

    .line 979
    .line 980
    .line 981
    sget-object v7, Lh0/e2;->o:Lh0/e2;

    .line 982
    .line 983
    invoke-static {v13, v7, v6, v3, v6}, Lu/w;->b(Lh0/g2;Lh0/e2;Lh0/d2;Ljava/util/ArrayList;Lh0/d2;)Lh0/d2;

    .line 984
    .line 985
    .line 986
    move-result-object v6

    .line 987
    invoke-static {v13, v4, v6, v13, v7}, Lu/w;->l(Lh0/g2;Lh0/e2;Lh0/d2;Lh0/g2;Lh0/e2;)V

    .line 988
    .line 989
    .line 990
    invoke-static {v2, v7, v6, v3, v6}, Lu/w;->b(Lh0/g2;Lh0/e2;Lh0/d2;Ljava/util/ArrayList;Lh0/d2;)Lh0/d2;

    .line 991
    .line 992
    .line 993
    move-result-object v6

    .line 994
    invoke-static {v13, v4, v6, v13, v7}, Lu/w;->l(Lh0/g2;Lh0/e2;Lh0/d2;Lh0/g2;Lh0/e2;)V

    .line 995
    .line 996
    .line 997
    invoke-static {v15, v7}, Lh0/h2;->a(Lh0/g2;Lh0/e2;)Lh0/h2;

    .line 998
    .line 999
    .line 1000
    move-result-object v7

    .line 1001
    invoke-virtual {v6, v7}, Lh0/d2;->a(Lh0/h2;)V

    .line 1002
    .line 1003
    .line 1004
    invoke-virtual {v3, v6}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 1005
    .line 1006
    .line 1007
    invoke-virtual {v1, v3}, Ljava/util/ArrayList;->addAll(Ljava/util/Collection;)Z

    .line 1008
    .line 1009
    .line 1010
    :cond_16
    iget-object v1, v0, Lu/c1;->m:Lv/b;

    .line 1011
    .line 1012
    sget-object v3, Lu/b1;->a:Lh0/g;

    .line 1013
    .line 1014
    const-string v3, "characteristicsCompat"

    .line 1015
    .line 1016
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1017
    .line 1018
    .line 1019
    sget v3, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 1020
    .line 1021
    const/16 v6, 0x21

    .line 1022
    .line 1023
    if-ge v3, v6, :cond_18

    .line 1024
    .line 1025
    :cond_17
    :goto_7
    const/4 v1, 0x0

    .line 1026
    goto :goto_8

    .line 1027
    :cond_18
    invoke-static {}, Lu/a1;->a()Landroid/hardware/camera2/CameraCharacteristics$Key;

    .line 1028
    .line 1029
    .line 1030
    move-result-object v7

    .line 1031
    invoke-virtual {v1, v7}, Lv/b;->a(Landroid/hardware/camera2/CameraCharacteristics$Key;)Ljava/lang/Object;

    .line 1032
    .line 1033
    .line 1034
    move-result-object v1

    .line 1035
    check-cast v1, [J

    .line 1036
    .line 1037
    if-eqz v1, :cond_17

    .line 1038
    .line 1039
    array-length v1, v1

    .line 1040
    if-nez v1, :cond_19

    .line 1041
    .line 1042
    goto :goto_7

    .line 1043
    :cond_19
    move v1, v5

    .line 1044
    :goto_8
    iput-boolean v1, v0, Lu/c1;->s:Z

    .line 1045
    .line 1046
    if-eqz v1, :cond_1a

    .line 1047
    .line 1048
    if-lt v3, v6, :cond_1a

    .line 1049
    .line 1050
    iget-object v1, v0, Lu/c1;->j:Ljava/util/ArrayList;

    .line 1051
    .line 1052
    new-instance v7, Ljava/util/ArrayList;

    .line 1053
    .line 1054
    invoke-direct {v7}, Ljava/util/ArrayList;-><init>()V

    .line 1055
    .line 1056
    .line 1057
    new-instance v8, Lh0/d2;

    .line 1058
    .line 1059
    invoke-direct {v8}, Lh0/d2;-><init>()V

    .line 1060
    .line 1061
    .line 1062
    sget-object v9, Lh0/e2;->l:Lh0/e2;

    .line 1063
    .line 1064
    sget-object v10, Lh0/c2;->i:Lh0/c2;

    .line 1065
    .line 1066
    invoke-static {v13, v9, v10}, Lkp/aa;->c(Lh0/g2;Lh0/e2;Lh0/c2;)Lh0/h2;

    .line 1067
    .line 1068
    .line 1069
    move-result-object v11

    .line 1070
    invoke-virtual {v8, v11}, Lh0/d2;->a(Lh0/h2;)V

    .line 1071
    .line 1072
    .line 1073
    invoke-virtual {v7, v8}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 1074
    .line 1075
    .line 1076
    new-instance v8, Lh0/d2;

    .line 1077
    .line 1078
    invoke-direct {v8}, Lh0/d2;-><init>()V

    .line 1079
    .line 1080
    .line 1081
    invoke-static {v2, v9, v10}, Lkp/aa;->c(Lh0/g2;Lh0/e2;Lh0/c2;)Lh0/h2;

    .line 1082
    .line 1083
    .line 1084
    move-result-object v9

    .line 1085
    invoke-virtual {v8, v9}, Lh0/d2;->a(Lh0/h2;)V

    .line 1086
    .line 1087
    .line 1088
    invoke-virtual {v7, v8}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 1089
    .line 1090
    .line 1091
    new-instance v8, Lh0/d2;

    .line 1092
    .line 1093
    invoke-direct {v8}, Lh0/d2;-><init>()V

    .line 1094
    .line 1095
    .line 1096
    sget-object v9, Lh0/e2;->o:Lh0/e2;

    .line 1097
    .line 1098
    sget-object v10, Lh0/c2;->g:Lh0/c2;

    .line 1099
    .line 1100
    invoke-static {v13, v9, v10}, Lkp/aa;->c(Lh0/g2;Lh0/e2;Lh0/c2;)Lh0/h2;

    .line 1101
    .line 1102
    .line 1103
    move-result-object v11

    .line 1104
    invoke-virtual {v8, v11}, Lh0/d2;->a(Lh0/h2;)V

    .line 1105
    .line 1106
    .line 1107
    invoke-virtual {v7, v8}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 1108
    .line 1109
    .line 1110
    new-instance v8, Lh0/d2;

    .line 1111
    .line 1112
    invoke-direct {v8}, Lh0/d2;-><init>()V

    .line 1113
    .line 1114
    .line 1115
    invoke-static {v2, v9, v10}, Lkp/aa;->c(Lh0/g2;Lh0/e2;Lh0/c2;)Lh0/h2;

    .line 1116
    .line 1117
    .line 1118
    move-result-object v11

    .line 1119
    invoke-virtual {v8, v11}, Lh0/d2;->a(Lh0/h2;)V

    .line 1120
    .line 1121
    .line 1122
    invoke-virtual {v7, v8}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 1123
    .line 1124
    .line 1125
    new-instance v8, Lh0/d2;

    .line 1126
    .line 1127
    invoke-direct {v8}, Lh0/d2;-><init>()V

    .line 1128
    .line 1129
    .line 1130
    sget-object v11, Lh0/c2;->h:Lh0/c2;

    .line 1131
    .line 1132
    invoke-static {v15, v14, v11}, Lkp/aa;->c(Lh0/g2;Lh0/e2;Lh0/c2;)Lh0/h2;

    .line 1133
    .line 1134
    .line 1135
    move-result-object v12

    .line 1136
    invoke-virtual {v8, v12}, Lh0/d2;->a(Lh0/h2;)V

    .line 1137
    .line 1138
    .line 1139
    invoke-virtual {v7, v8}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 1140
    .line 1141
    .line 1142
    new-instance v8, Lh0/d2;

    .line 1143
    .line 1144
    invoke-direct {v8}, Lh0/d2;-><init>()V

    .line 1145
    .line 1146
    .line 1147
    invoke-static {v2, v14, v11}, Lkp/aa;->c(Lh0/g2;Lh0/e2;Lh0/c2;)Lh0/h2;

    .line 1148
    .line 1149
    .line 1150
    move-result-object v12

    .line 1151
    invoke-virtual {v8, v12}, Lh0/d2;->a(Lh0/h2;)V

    .line 1152
    .line 1153
    .line 1154
    invoke-virtual {v7, v8}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 1155
    .line 1156
    .line 1157
    new-instance v8, Lh0/d2;

    .line 1158
    .line 1159
    invoke-direct {v8}, Lh0/d2;-><init>()V

    .line 1160
    .line 1161
    .line 1162
    sget-object v12, Lh0/c2;->f:Lh0/c2;

    .line 1163
    .line 1164
    invoke-static {v13, v4, v12}, Lkp/aa;->c(Lh0/g2;Lh0/e2;Lh0/c2;)Lh0/h2;

    .line 1165
    .line 1166
    .line 1167
    move-result-object v5

    .line 1168
    invoke-virtual {v8, v5}, Lh0/d2;->a(Lh0/h2;)V

    .line 1169
    .line 1170
    .line 1171
    invoke-static {v15, v14, v11}, Lkp/aa;->c(Lh0/g2;Lh0/e2;Lh0/c2;)Lh0/h2;

    .line 1172
    .line 1173
    .line 1174
    move-result-object v5

    .line 1175
    invoke-virtual {v8, v5}, Lh0/d2;->a(Lh0/h2;)V

    .line 1176
    .line 1177
    .line 1178
    invoke-static {v7, v8}, Lu/w;->c(Ljava/util/ArrayList;Lh0/d2;)Lh0/d2;

    .line 1179
    .line 1180
    .line 1181
    move-result-object v5

    .line 1182
    invoke-static {v13, v4, v12}, Lkp/aa;->c(Lh0/g2;Lh0/e2;Lh0/c2;)Lh0/h2;

    .line 1183
    .line 1184
    .line 1185
    move-result-object v8

    .line 1186
    invoke-virtual {v5, v8}, Lh0/d2;->a(Lh0/h2;)V

    .line 1187
    .line 1188
    .line 1189
    invoke-static {v2, v14, v11}, Lkp/aa;->c(Lh0/g2;Lh0/e2;Lh0/c2;)Lh0/h2;

    .line 1190
    .line 1191
    .line 1192
    move-result-object v8

    .line 1193
    invoke-virtual {v5, v8}, Lh0/d2;->a(Lh0/h2;)V

    .line 1194
    .line 1195
    .line 1196
    invoke-static {v7, v5}, Lu/w;->c(Ljava/util/ArrayList;Lh0/d2;)Lh0/d2;

    .line 1197
    .line 1198
    .line 1199
    move-result-object v5

    .line 1200
    invoke-static {v13, v4, v12}, Lkp/aa;->c(Lh0/g2;Lh0/e2;Lh0/c2;)Lh0/h2;

    .line 1201
    .line 1202
    .line 1203
    move-result-object v8

    .line 1204
    invoke-virtual {v5, v8}, Lh0/d2;->a(Lh0/h2;)V

    .line 1205
    .line 1206
    .line 1207
    invoke-static {v13, v9, v10}, Lkp/aa;->c(Lh0/g2;Lh0/e2;Lh0/c2;)Lh0/h2;

    .line 1208
    .line 1209
    .line 1210
    move-result-object v8

    .line 1211
    invoke-virtual {v5, v8}, Lh0/d2;->a(Lh0/h2;)V

    .line 1212
    .line 1213
    .line 1214
    invoke-static {v7, v5}, Lu/w;->c(Ljava/util/ArrayList;Lh0/d2;)Lh0/d2;

    .line 1215
    .line 1216
    .line 1217
    move-result-object v5

    .line 1218
    invoke-static {v13, v4, v12}, Lkp/aa;->c(Lh0/g2;Lh0/e2;Lh0/c2;)Lh0/h2;

    .line 1219
    .line 1220
    .line 1221
    move-result-object v8

    .line 1222
    invoke-virtual {v5, v8}, Lh0/d2;->a(Lh0/h2;)V

    .line 1223
    .line 1224
    .line 1225
    invoke-static {v2, v9, v10}, Lkp/aa;->c(Lh0/g2;Lh0/e2;Lh0/c2;)Lh0/h2;

    .line 1226
    .line 1227
    .line 1228
    move-result-object v8

    .line 1229
    invoke-virtual {v5, v8}, Lh0/d2;->a(Lh0/h2;)V

    .line 1230
    .line 1231
    .line 1232
    invoke-static {v7, v5}, Lu/w;->c(Ljava/util/ArrayList;Lh0/d2;)Lh0/d2;

    .line 1233
    .line 1234
    .line 1235
    move-result-object v5

    .line 1236
    invoke-static {v13, v4, v12}, Lkp/aa;->c(Lh0/g2;Lh0/e2;Lh0/c2;)Lh0/h2;

    .line 1237
    .line 1238
    .line 1239
    move-result-object v8

    .line 1240
    invoke-virtual {v5, v8}, Lh0/d2;->a(Lh0/h2;)V

    .line 1241
    .line 1242
    .line 1243
    invoke-static {v2, v4, v12}, Lkp/aa;->c(Lh0/g2;Lh0/e2;Lh0/c2;)Lh0/h2;

    .line 1244
    .line 1245
    .line 1246
    move-result-object v8

    .line 1247
    invoke-virtual {v5, v8}, Lh0/d2;->a(Lh0/h2;)V

    .line 1248
    .line 1249
    .line 1250
    invoke-static {v7, v5}, Lu/w;->c(Ljava/util/ArrayList;Lh0/d2;)Lh0/d2;

    .line 1251
    .line 1252
    .line 1253
    move-result-object v5

    .line 1254
    invoke-static {v13, v4, v12}, Lkp/aa;->c(Lh0/g2;Lh0/e2;Lh0/c2;)Lh0/h2;

    .line 1255
    .line 1256
    .line 1257
    move-result-object v8

    .line 1258
    invoke-virtual {v5, v8}, Lh0/d2;->a(Lh0/h2;)V

    .line 1259
    .line 1260
    .line 1261
    invoke-static {v13, v9, v10}, Lkp/aa;->c(Lh0/g2;Lh0/e2;Lh0/c2;)Lh0/h2;

    .line 1262
    .line 1263
    .line 1264
    move-result-object v8

    .line 1265
    invoke-virtual {v5, v8}, Lh0/d2;->a(Lh0/h2;)V

    .line 1266
    .line 1267
    .line 1268
    invoke-static {v15, v9, v11}, Lkp/aa;->c(Lh0/g2;Lh0/e2;Lh0/c2;)Lh0/h2;

    .line 1269
    .line 1270
    .line 1271
    move-result-object v8

    .line 1272
    invoke-virtual {v5, v8}, Lh0/d2;->a(Lh0/h2;)V

    .line 1273
    .line 1274
    .line 1275
    invoke-virtual {v7, v5}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 1276
    .line 1277
    .line 1278
    new-instance v5, Lh0/d2;

    .line 1279
    .line 1280
    invoke-direct {v5}, Lh0/d2;-><init>()V

    .line 1281
    .line 1282
    .line 1283
    invoke-static {v13, v4, v12}, Lkp/aa;->c(Lh0/g2;Lh0/e2;Lh0/c2;)Lh0/h2;

    .line 1284
    .line 1285
    .line 1286
    move-result-object v8

    .line 1287
    invoke-virtual {v5, v8}, Lh0/d2;->a(Lh0/h2;)V

    .line 1288
    .line 1289
    .line 1290
    invoke-static {v2, v9, v10}, Lkp/aa;->c(Lh0/g2;Lh0/e2;Lh0/c2;)Lh0/h2;

    .line 1291
    .line 1292
    .line 1293
    move-result-object v8

    .line 1294
    invoke-virtual {v5, v8}, Lh0/d2;->a(Lh0/h2;)V

    .line 1295
    .line 1296
    .line 1297
    invoke-static {v15, v9, v11}, Lkp/aa;->c(Lh0/g2;Lh0/e2;Lh0/c2;)Lh0/h2;

    .line 1298
    .line 1299
    .line 1300
    move-result-object v8

    .line 1301
    invoke-virtual {v5, v8}, Lh0/d2;->a(Lh0/h2;)V

    .line 1302
    .line 1303
    .line 1304
    invoke-virtual {v7, v5}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 1305
    .line 1306
    .line 1307
    new-instance v5, Lh0/d2;

    .line 1308
    .line 1309
    invoke-direct {v5}, Lh0/d2;-><init>()V

    .line 1310
    .line 1311
    .line 1312
    invoke-static {v13, v4, v12}, Lkp/aa;->c(Lh0/g2;Lh0/e2;Lh0/c2;)Lh0/h2;

    .line 1313
    .line 1314
    .line 1315
    move-result-object v8

    .line 1316
    invoke-virtual {v5, v8}, Lh0/d2;->a(Lh0/h2;)V

    .line 1317
    .line 1318
    .line 1319
    invoke-static {v2, v4, v12}, Lkp/aa;->c(Lh0/g2;Lh0/e2;Lh0/c2;)Lh0/h2;

    .line 1320
    .line 1321
    .line 1322
    move-result-object v2

    .line 1323
    invoke-virtual {v5, v2}, Lh0/d2;->a(Lh0/h2;)V

    .line 1324
    .line 1325
    .line 1326
    invoke-static {v15, v14, v11}, Lkp/aa;->c(Lh0/g2;Lh0/e2;Lh0/c2;)Lh0/h2;

    .line 1327
    .line 1328
    .line 1329
    move-result-object v2

    .line 1330
    invoke-virtual {v5, v2}, Lh0/d2;->a(Lh0/h2;)V

    .line 1331
    .line 1332
    .line 1333
    invoke-virtual {v7, v5}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 1334
    .line 1335
    .line 1336
    invoke-virtual {v1, v7}, Ljava/util/ArrayList;->addAll(Ljava/util/Collection;)Z

    .line 1337
    .line 1338
    .line 1339
    :cond_1a
    iget-object v1, v0, Lu/c1;->m:Lv/b;

    .line 1340
    .line 1341
    if-ge v3, v6, :cond_1c

    .line 1342
    .line 1343
    :cond_1b
    :goto_9
    const/4 v2, 0x0

    .line 1344
    goto :goto_b

    .line 1345
    :cond_1c
    sget-object v2, Landroid/hardware/camera2/CameraCharacteristics;->CONTROL_AVAILABLE_VIDEO_STABILIZATION_MODES:Landroid/hardware/camera2/CameraCharacteristics$Key;

    .line 1346
    .line 1347
    invoke-virtual {v1, v2}, Lv/b;->a(Landroid/hardware/camera2/CameraCharacteristics$Key;)Ljava/lang/Object;

    .line 1348
    .line 1349
    .line 1350
    move-result-object v1

    .line 1351
    check-cast v1, [I

    .line 1352
    .line 1353
    if-eqz v1, :cond_1b

    .line 1354
    .line 1355
    array-length v2, v1

    .line 1356
    if-nez v2, :cond_1d

    .line 1357
    .line 1358
    goto :goto_9

    .line 1359
    :cond_1d
    array-length v2, v1

    .line 1360
    const/4 v3, 0x0

    .line 1361
    :goto_a
    if-ge v3, v2, :cond_1b

    .line 1362
    .line 1363
    aget v4, v1, v3

    .line 1364
    .line 1365
    const/4 v5, 0x2

    .line 1366
    if-ne v4, v5, :cond_1e

    .line 1367
    .line 1368
    const/4 v2, 0x1

    .line 1369
    goto :goto_b

    .line 1370
    :cond_1e
    add-int/lit8 v3, v3, 0x1

    .line 1371
    .line 1372
    goto :goto_a

    .line 1373
    :goto_b
    iput-boolean v2, v0, Lu/c1;->v:Z

    .line 1374
    .line 1375
    if-eqz v2, :cond_1f

    .line 1376
    .line 1377
    sget v1, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 1378
    .line 1379
    if-lt v1, v6, :cond_1f

    .line 1380
    .line 1381
    iget-object v1, v0, Lu/c1;->d:Ljava/util/ArrayList;

    .line 1382
    .line 1383
    new-instance v2, Ljava/util/ArrayList;

    .line 1384
    .line 1385
    invoke-direct {v2}, Ljava/util/ArrayList;-><init>()V

    .line 1386
    .line 1387
    .line 1388
    new-instance v3, Lh0/d2;

    .line 1389
    .line 1390
    invoke-direct {v3}, Lh0/d2;-><init>()V

    .line 1391
    .line 1392
    .line 1393
    sget-object v4, Lh0/g2;->d:Lh0/g2;

    .line 1394
    .line 1395
    sget-object v5, Lh0/e2;->l:Lh0/e2;

    .line 1396
    .line 1397
    invoke-static {v4, v5, v3, v2, v3}, Lu/w;->b(Lh0/g2;Lh0/e2;Lh0/d2;Ljava/util/ArrayList;Lh0/d2;)Lh0/d2;

    .line 1398
    .line 1399
    .line 1400
    move-result-object v3

    .line 1401
    sget-object v6, Lh0/g2;->e:Lh0/g2;

    .line 1402
    .line 1403
    invoke-static {v6, v5, v3, v2, v3}, Lu/w;->b(Lh0/g2;Lh0/e2;Lh0/d2;Ljava/util/ArrayList;Lh0/d2;)Lh0/d2;

    .line 1404
    .line 1405
    .line 1406
    move-result-object v3

    .line 1407
    invoke-static {v4, v5}, Lh0/h2;->a(Lh0/g2;Lh0/e2;)Lh0/h2;

    .line 1408
    .line 1409
    .line 1410
    move-result-object v7

    .line 1411
    invoke-virtual {v3, v7}, Lh0/d2;->a(Lh0/h2;)V

    .line 1412
    .line 1413
    .line 1414
    sget-object v7, Lh0/g2;->f:Lh0/g2;

    .line 1415
    .line 1416
    sget-object v8, Lh0/e2;->p:Lh0/e2;

    .line 1417
    .line 1418
    invoke-static {v7, v8, v3, v2, v3}, Lu/w;->b(Lh0/g2;Lh0/e2;Lh0/d2;Ljava/util/ArrayList;Lh0/d2;)Lh0/d2;

    .line 1419
    .line 1420
    .line 1421
    move-result-object v3

    .line 1422
    invoke-static {v6, v5, v3, v7, v8}, Lu/w;->l(Lh0/g2;Lh0/e2;Lh0/d2;Lh0/g2;Lh0/e2;)V

    .line 1423
    .line 1424
    .line 1425
    invoke-static {v2, v3}, Lu/w;->c(Ljava/util/ArrayList;Lh0/d2;)Lh0/d2;

    .line 1426
    .line 1427
    .line 1428
    move-result-object v3

    .line 1429
    invoke-static {v4, v5, v3, v6, v8}, Lu/w;->l(Lh0/g2;Lh0/e2;Lh0/d2;Lh0/g2;Lh0/e2;)V

    .line 1430
    .line 1431
    .line 1432
    invoke-static {v2, v3}, Lu/w;->c(Ljava/util/ArrayList;Lh0/d2;)Lh0/d2;

    .line 1433
    .line 1434
    .line 1435
    move-result-object v3

    .line 1436
    invoke-static {v6, v5, v3, v6, v8}, Lu/w;->l(Lh0/g2;Lh0/e2;Lh0/d2;Lh0/g2;Lh0/e2;)V

    .line 1437
    .line 1438
    .line 1439
    invoke-static {v2, v3}, Lu/w;->c(Ljava/util/ArrayList;Lh0/d2;)Lh0/d2;

    .line 1440
    .line 1441
    .line 1442
    move-result-object v3

    .line 1443
    sget-object v7, Lh0/e2;->i:Lh0/e2;

    .line 1444
    .line 1445
    invoke-static {v4, v7, v3, v4, v5}, Lu/w;->l(Lh0/g2;Lh0/e2;Lh0/d2;Lh0/g2;Lh0/e2;)V

    .line 1446
    .line 1447
    .line 1448
    invoke-static {v2, v3}, Lu/w;->c(Ljava/util/ArrayList;Lh0/d2;)Lh0/d2;

    .line 1449
    .line 1450
    .line 1451
    move-result-object v3

    .line 1452
    invoke-static {v6, v7, v3, v4, v5}, Lu/w;->l(Lh0/g2;Lh0/e2;Lh0/d2;Lh0/g2;Lh0/e2;)V

    .line 1453
    .line 1454
    .line 1455
    invoke-static {v2, v3}, Lu/w;->c(Ljava/util/ArrayList;Lh0/d2;)Lh0/d2;

    .line 1456
    .line 1457
    .line 1458
    move-result-object v3

    .line 1459
    invoke-static {v4, v7, v3, v6, v5}, Lu/w;->l(Lh0/g2;Lh0/e2;Lh0/d2;Lh0/g2;Lh0/e2;)V

    .line 1460
    .line 1461
    .line 1462
    invoke-static {v2, v3}, Lu/w;->c(Ljava/util/ArrayList;Lh0/d2;)Lh0/d2;

    .line 1463
    .line 1464
    .line 1465
    move-result-object v3

    .line 1466
    invoke-static {v6, v7, v3, v6, v5}, Lu/w;->l(Lh0/g2;Lh0/e2;Lh0/d2;Lh0/g2;Lh0/e2;)V

    .line 1467
    .line 1468
    .line 1469
    invoke-virtual {v2, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 1470
    .line 1471
    .line 1472
    invoke-virtual {v1, v2}, Ljava/util/ArrayList;->addAll(Ljava/util/Collection;)Z

    .line 1473
    .line 1474
    .line 1475
    :cond_1f
    invoke-virtual {v0}, Lu/c1;->c()V

    .line 1476
    .line 1477
    .line 1478
    move-object/from16 v1, p5

    .line 1479
    .line 1480
    iput-object v1, v0, Lu/c1;->D:Ld0/b;

    .line 1481
    .line 1482
    return-void

    .line 1483
    :catch_0
    move-exception v0

    .line 1484
    new-instance v1, Lb0/s;

    .line 1485
    .line 1486
    invoke-direct {v1, v0}, Ljava/lang/Exception;-><init>(Ljava/lang/Throwable;)V

    .line 1487
    .line 1488
    .line 1489
    throw v1
.end method

.method public static d(Landroid/util/Range;I[Landroid/util/Range;)Landroid/util/Range;
    .locals 13

    .line 1
    sget-object v0, Lh0/k;->h:Landroid/util/Range;

    .line 2
    .line 3
    invoke-virtual {v0, p0}, Landroid/util/Range;->equals(Ljava/lang/Object;)Z

    .line 4
    .line 5
    .line 6
    move-result v1

    .line 7
    if-eqz v1, :cond_0

    .line 8
    .line 9
    goto :goto_0

    .line 10
    :cond_0
    if-nez p2, :cond_1

    .line 11
    .line 12
    :goto_0
    return-object v0

    .line 13
    :cond_1
    new-instance v1, Landroid/util/Range;

    .line 14
    .line 15
    invoke-virtual {p0}, Landroid/util/Range;->getLower()Ljava/lang/Comparable;

    .line 16
    .line 17
    .line 18
    move-result-object v2

    .line 19
    check-cast v2, Ljava/lang/Integer;

    .line 20
    .line 21
    invoke-virtual {v2}, Ljava/lang/Integer;->intValue()I

    .line 22
    .line 23
    .line 24
    move-result v2

    .line 25
    invoke-static {v2, p1}, Ljava/lang/Math;->min(II)I

    .line 26
    .line 27
    .line 28
    move-result v2

    .line 29
    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 30
    .line 31
    .line 32
    move-result-object v2

    .line 33
    invoke-virtual {p0}, Landroid/util/Range;->getUpper()Ljava/lang/Comparable;

    .line 34
    .line 35
    .line 36
    move-result-object p0

    .line 37
    check-cast p0, Ljava/lang/Integer;

    .line 38
    .line 39
    invoke-virtual {p0}, Ljava/lang/Integer;->intValue()I

    .line 40
    .line 41
    .line 42
    move-result p0

    .line 43
    invoke-static {p0, p1}, Ljava/lang/Math;->min(II)I

    .line 44
    .line 45
    .line 46
    move-result p0

    .line 47
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 48
    .line 49
    .line 50
    move-result-object p0

    .line 51
    invoke-direct {v1, v2, p0}, Landroid/util/Range;-><init>(Ljava/lang/Comparable;Ljava/lang/Comparable;)V

    .line 52
    .line 53
    .line 54
    array-length p0, p2

    .line 55
    const/4 v2, 0x0

    .line 56
    move v3, v2

    .line 57
    :goto_1
    if-ge v2, p0, :cond_e

    .line 58
    .line 59
    aget-object v4, p2, v2

    .line 60
    .line 61
    invoke-static {v4}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    .line 62
    .line 63
    .line 64
    invoke-virtual {v4}, Landroid/util/Range;->getLower()Ljava/lang/Comparable;

    .line 65
    .line 66
    .line 67
    move-result-object v5

    .line 68
    check-cast v5, Ljava/lang/Integer;

    .line 69
    .line 70
    invoke-virtual {v5}, Ljava/lang/Integer;->intValue()I

    .line 71
    .line 72
    .line 73
    move-result v5

    .line 74
    if-lt p1, v5, :cond_d

    .line 75
    .line 76
    sget-object v5, Lh0/k;->h:Landroid/util/Range;

    .line 77
    .line 78
    invoke-virtual {v0, v5}, Landroid/util/Range;->equals(Ljava/lang/Object;)Z

    .line 79
    .line 80
    .line 81
    move-result v5

    .line 82
    if-eqz v5, :cond_2

    .line 83
    .line 84
    move-object v0, v4

    .line 85
    :cond_2
    invoke-virtual {v4, v1}, Landroid/util/Range;->equals(Ljava/lang/Object;)Z

    .line 86
    .line 87
    .line 88
    move-result v5

    .line 89
    if-eqz v5, :cond_3

    .line 90
    .line 91
    move-object v0, v4

    .line 92
    goto/16 :goto_6

    .line 93
    .line 94
    :cond_3
    :try_start_0
    invoke-virtual {v4, v1}, Landroid/util/Range;->intersect(Landroid/util/Range;)Landroid/util/Range;

    .line 95
    .line 96
    .line 97
    move-result-object v5

    .line 98
    invoke-static {v5}, Lu/c1;->i(Landroid/util/Range;)I

    .line 99
    .line 100
    .line 101
    move-result v5

    .line 102
    if-nez v3, :cond_4

    .line 103
    .line 104
    move v3, v5

    .line 105
    goto :goto_3

    .line 106
    :cond_4
    if-lt v5, v3, :cond_a

    .line 107
    .line 108
    invoke-virtual {v0, v1}, Landroid/util/Range;->intersect(Landroid/util/Range;)Landroid/util/Range;

    .line 109
    .line 110
    .line 111
    move-result-object v5

    .line 112
    invoke-static {v5}, Lu/c1;->i(Landroid/util/Range;)I

    .line 113
    .line 114
    .line 115
    move-result v5

    .line 116
    int-to-double v5, v5

    .line 117
    invoke-virtual {v4, v1}, Landroid/util/Range;->intersect(Landroid/util/Range;)Landroid/util/Range;

    .line 118
    .line 119
    .line 120
    move-result-object v7

    .line 121
    invoke-static {v7}, Lu/c1;->i(Landroid/util/Range;)I

    .line 122
    .line 123
    .line 124
    move-result v7

    .line 125
    int-to-double v7, v7

    .line 126
    invoke-static {v4}, Lu/c1;->i(Landroid/util/Range;)I

    .line 127
    .line 128
    .line 129
    move-result v9

    .line 130
    int-to-double v9, v9

    .line 131
    div-double v9, v7, v9

    .line 132
    .line 133
    invoke-static {v0}, Lu/c1;->i(Landroid/util/Range;)I

    .line 134
    .line 135
    .line 136
    move-result v11

    .line 137
    int-to-double v11, v11

    .line 138
    div-double v11, v5, v11

    .line 139
    .line 140
    cmpl-double v5, v7, v5

    .line 141
    .line 142
    const-wide/high16 v6, 0x3fe0000000000000L    # 0.5

    .line 143
    .line 144
    if-lez v5, :cond_5

    .line 145
    .line 146
    cmpl-double v5, v9, v6

    .line 147
    .line 148
    if-gez v5, :cond_8

    .line 149
    .line 150
    cmpl-double v5, v9, v11

    .line 151
    .line 152
    if-ltz v5, :cond_9

    .line 153
    .line 154
    goto :goto_2

    .line 155
    :cond_5
    if-nez v5, :cond_7

    .line 156
    .line 157
    cmpl-double v5, v9, v11

    .line 158
    .line 159
    if-lez v5, :cond_6

    .line 160
    .line 161
    goto :goto_2

    .line 162
    :cond_6
    if-nez v5, :cond_9

    .line 163
    .line 164
    invoke-virtual {v4}, Landroid/util/Range;->getLower()Ljava/lang/Comparable;

    .line 165
    .line 166
    .line 167
    move-result-object v5

    .line 168
    check-cast v5, Ljava/lang/Integer;

    .line 169
    .line 170
    invoke-virtual {v5}, Ljava/lang/Integer;->intValue()I

    .line 171
    .line 172
    .line 173
    move-result v5

    .line 174
    invoke-virtual {v0}, Landroid/util/Range;->getLower()Ljava/lang/Comparable;

    .line 175
    .line 176
    .line 177
    move-result-object v6

    .line 178
    check-cast v6, Ljava/lang/Integer;

    .line 179
    .line 180
    invoke-virtual {v6}, Ljava/lang/Integer;->intValue()I

    .line 181
    .line 182
    .line 183
    move-result v6

    .line 184
    if-le v5, v6, :cond_9

    .line 185
    .line 186
    goto :goto_2

    .line 187
    :cond_7
    cmpg-double v5, v11, v6

    .line 188
    .line 189
    if-gez v5, :cond_9

    .line 190
    .line 191
    cmpl-double v5, v9, v11

    .line 192
    .line 193
    if-lez v5, :cond_9

    .line 194
    .line 195
    :cond_8
    :goto_2
    move-object v0, v4

    .line 196
    :cond_9
    invoke-virtual {v1, v0}, Landroid/util/Range;->intersect(Landroid/util/Range;)Landroid/util/Range;

    .line 197
    .line 198
    .line 199
    move-result-object v5

    .line 200
    invoke-static {v5}, Lu/c1;->i(Landroid/util/Range;)I

    .line 201
    .line 202
    .line 203
    move-result v3
    :try_end_0
    .catch Ljava/lang/IllegalArgumentException; {:try_start_0 .. :try_end_0} :catch_0

    .line 204
    :cond_a
    move-object v4, v0

    .line 205
    :goto_3
    move-object v0, v4

    .line 206
    goto :goto_5

    .line 207
    :catch_0
    if-nez v3, :cond_d

    .line 208
    .line 209
    invoke-static {v4, v1}, Lu/c1;->h(Landroid/util/Range;Landroid/util/Range;)I

    .line 210
    .line 211
    .line 212
    move-result v5

    .line 213
    invoke-static {v0, v1}, Lu/c1;->h(Landroid/util/Range;Landroid/util/Range;)I

    .line 214
    .line 215
    .line 216
    move-result v6

    .line 217
    if-ge v5, v6, :cond_b

    .line 218
    .line 219
    goto :goto_4

    .line 220
    :cond_b
    invoke-static {v4, v1}, Lu/c1;->h(Landroid/util/Range;Landroid/util/Range;)I

    .line 221
    .line 222
    .line 223
    move-result v5

    .line 224
    invoke-static {v0, v1}, Lu/c1;->h(Landroid/util/Range;Landroid/util/Range;)I

    .line 225
    .line 226
    .line 227
    move-result v6

    .line 228
    if-ne v5, v6, :cond_d

    .line 229
    .line 230
    invoke-virtual {v4}, Landroid/util/Range;->getLower()Ljava/lang/Comparable;

    .line 231
    .line 232
    .line 233
    move-result-object v5

    .line 234
    check-cast v5, Ljava/lang/Integer;

    .line 235
    .line 236
    invoke-virtual {v5}, Ljava/lang/Integer;->intValue()I

    .line 237
    .line 238
    .line 239
    move-result v5

    .line 240
    invoke-virtual {v0}, Landroid/util/Range;->getUpper()Ljava/lang/Comparable;

    .line 241
    .line 242
    .line 243
    move-result-object v6

    .line 244
    check-cast v6, Ljava/lang/Integer;

    .line 245
    .line 246
    invoke-virtual {v6}, Ljava/lang/Integer;->intValue()I

    .line 247
    .line 248
    .line 249
    move-result v6

    .line 250
    if-le v5, v6, :cond_c

    .line 251
    .line 252
    goto :goto_4

    .line 253
    :cond_c
    invoke-static {v4}, Lu/c1;->i(Landroid/util/Range;)I

    .line 254
    .line 255
    .line 256
    move-result v5

    .line 257
    invoke-static {v0}, Lu/c1;->i(Landroid/util/Range;)I

    .line 258
    .line 259
    .line 260
    move-result v6

    .line 261
    if-ge v5, v6, :cond_d

    .line 262
    .line 263
    :goto_4
    goto :goto_3

    .line 264
    :cond_d
    :goto_5
    add-int/lit8 v2, v2, 0x1

    .line 265
    .line 266
    goto/16 :goto_1

    .line 267
    .line 268
    :cond_e
    :goto_6
    return-object v0
.end method

.method public static f(Landroid/hardware/camera2/params/StreamConfigurationMap;IZLandroid/util/Rational;)Landroid/util/Size;
    .locals 8

    .line 1
    const/16 v0, 0x22

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    if-ne p1, v0, :cond_0

    .line 5
    .line 6
    :try_start_0
    const-class v0, Landroid/graphics/SurfaceTexture;

    .line 7
    .line 8
    invoke-virtual {p0, v0}, Landroid/hardware/camera2/params/StreamConfigurationMap;->getOutputSizes(Ljava/lang/Class;)[Landroid/util/Size;

    .line 9
    .line 10
    .line 11
    move-result-object v0

    .line 12
    goto :goto_0

    .line 13
    :cond_0
    invoke-virtual {p0, p1}, Landroid/hardware/camera2/params/StreamConfigurationMap;->getOutputSizes(I)[Landroid/util/Size;

    .line 14
    .line 15
    .line 16
    move-result-object v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 17
    goto :goto_0

    .line 18
    :catchall_0
    move-object v0, v1

    .line 19
    :goto_0
    const/4 v2, 0x0

    .line 20
    if-eqz v0, :cond_4

    .line 21
    .line 22
    array-length v3, v0

    .line 23
    if-nez v3, :cond_1

    .line 24
    .line 25
    goto :goto_2

    .line 26
    :cond_1
    if-eqz p3, :cond_6

    .line 27
    .line 28
    new-instance v3, Ljava/util/ArrayList;

    .line 29
    .line 30
    invoke-direct {v3}, Ljava/util/ArrayList;-><init>()V

    .line 31
    .line 32
    .line 33
    array-length v4, v0

    .line 34
    move v5, v2

    .line 35
    :goto_1
    if-ge v5, v4, :cond_3

    .line 36
    .line 37
    aget-object v6, v0, v5

    .line 38
    .line 39
    invoke-static {p3, v6}, Li0/b;->a(Landroid/util/Rational;Landroid/util/Size;)Z

    .line 40
    .line 41
    .line 42
    move-result v7

    .line 43
    if-eqz v7, :cond_2

    .line 44
    .line 45
    invoke-virtual {v3, v6}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 46
    .line 47
    .line 48
    :cond_2
    add-int/lit8 v5, v5, 0x1

    .line 49
    .line 50
    goto :goto_1

    .line 51
    :cond_3
    invoke-virtual {v3}, Ljava/util/ArrayList;->isEmpty()Z

    .line 52
    .line 53
    .line 54
    move-result p3

    .line 55
    if-eqz p3, :cond_5

    .line 56
    .line 57
    :cond_4
    :goto_2
    move-object v0, v1

    .line 58
    goto :goto_3

    .line 59
    :cond_5
    new-array p3, v2, [Landroid/util/Size;

    .line 60
    .line 61
    invoke-virtual {v3, p3}, Ljava/util/ArrayList;->toArray([Ljava/lang/Object;)[Ljava/lang/Object;

    .line 62
    .line 63
    .line 64
    move-result-object p3

    .line 65
    move-object v0, p3

    .line 66
    check-cast v0, [Landroid/util/Size;

    .line 67
    .line 68
    :cond_6
    :goto_3
    if-eqz v0, :cond_9

    .line 69
    .line 70
    array-length p3, v0

    .line 71
    if-nez p3, :cond_7

    .line 72
    .line 73
    goto :goto_4

    .line 74
    :cond_7
    new-instance p3, Li0/c;

    .line 75
    .line 76
    invoke-direct {p3, v2}, Li0/c;-><init>(Z)V

    .line 77
    .line 78
    .line 79
    invoke-static {v0}, Ljava/util/Arrays;->asList([Ljava/lang/Object;)Ljava/util/List;

    .line 80
    .line 81
    .line 82
    move-result-object v0

    .line 83
    invoke-static {v0, p3}, Ljava/util/Collections;->max(Ljava/util/Collection;Ljava/util/Comparator;)Ljava/lang/Object;

    .line 84
    .line 85
    .line 86
    move-result-object v0

    .line 87
    check-cast v0, Landroid/util/Size;

    .line 88
    .line 89
    sget-object v1, Lo0/a;->a:Landroid/util/Size;

    .line 90
    .line 91
    if-eqz p2, :cond_8

    .line 92
    .line 93
    invoke-virtual {p0, p1}, Landroid/hardware/camera2/params/StreamConfigurationMap;->getHighResolutionOutputSizes(I)[Landroid/util/Size;

    .line 94
    .line 95
    .line 96
    move-result-object p0

    .line 97
    if-eqz p0, :cond_8

    .line 98
    .line 99
    array-length p1, p0

    .line 100
    if-lez p1, :cond_8

    .line 101
    .line 102
    invoke-static {p0}, Ljava/util/Arrays;->asList([Ljava/lang/Object;)Ljava/util/List;

    .line 103
    .line 104
    .line 105
    move-result-object p0

    .line 106
    invoke-static {p0, p3}, Ljava/util/Collections;->max(Ljava/util/Collection;Ljava/util/Comparator;)Ljava/lang/Object;

    .line 107
    .line 108
    .line 109
    move-result-object p0

    .line 110
    move-object v1, p0

    .line 111
    check-cast v1, Landroid/util/Size;

    .line 112
    .line 113
    :cond_8
    filled-new-array {v0, v1}, [Landroid/util/Size;

    .line 114
    .line 115
    .line 116
    move-result-object p0

    .line 117
    invoke-static {p0}, Ljava/util/Arrays;->asList([Ljava/lang/Object;)Ljava/util/List;

    .line 118
    .line 119
    .line 120
    move-result-object p0

    .line 121
    invoke-static {p0, p3}, Ljava/util/Collections;->max(Ljava/util/Collection;Ljava/util/Comparator;)Ljava/lang/Object;

    .line 122
    .line 123
    .line 124
    move-result-object p0

    .line 125
    check-cast p0, Landroid/util/Size;

    .line 126
    .line 127
    return-object p0

    .line 128
    :cond_9
    :goto_4
    return-object v1
.end method

.method public static h(Landroid/util/Range;Landroid/util/Range;)I
    .locals 2

    .line 1
    invoke-virtual {p1}, Landroid/util/Range;->getUpper()Ljava/lang/Comparable;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    check-cast v0, Ljava/lang/Integer;

    .line 6
    .line 7
    invoke-virtual {p0, v0}, Landroid/util/Range;->contains(Ljava/lang/Comparable;)Z

    .line 8
    .line 9
    .line 10
    move-result v0

    .line 11
    if-nez v0, :cond_0

    .line 12
    .line 13
    invoke-virtual {p1}, Landroid/util/Range;->getLower()Ljava/lang/Comparable;

    .line 14
    .line 15
    .line 16
    move-result-object v0

    .line 17
    check-cast v0, Ljava/lang/Integer;

    .line 18
    .line 19
    invoke-virtual {p0, v0}, Landroid/util/Range;->contains(Ljava/lang/Comparable;)Z

    .line 20
    .line 21
    .line 22
    move-result v0

    .line 23
    if-nez v0, :cond_0

    .line 24
    .line 25
    const/4 v0, 0x1

    .line 26
    goto :goto_0

    .line 27
    :cond_0
    const/4 v0, 0x0

    .line 28
    :goto_0
    const-string v1, "Ranges must not intersect"

    .line 29
    .line 30
    invoke-static {v1, v0}, Ljp/ed;->f(Ljava/lang/String;Z)V

    .line 31
    .line 32
    .line 33
    invoke-virtual {p0}, Landroid/util/Range;->getLower()Ljava/lang/Comparable;

    .line 34
    .line 35
    .line 36
    move-result-object v0

    .line 37
    check-cast v0, Ljava/lang/Integer;

    .line 38
    .line 39
    invoke-virtual {v0}, Ljava/lang/Integer;->intValue()I

    .line 40
    .line 41
    .line 42
    move-result v0

    .line 43
    invoke-virtual {p1}, Landroid/util/Range;->getUpper()Ljava/lang/Comparable;

    .line 44
    .line 45
    .line 46
    move-result-object v1

    .line 47
    check-cast v1, Ljava/lang/Integer;

    .line 48
    .line 49
    invoke-virtual {v1}, Ljava/lang/Integer;->intValue()I

    .line 50
    .line 51
    .line 52
    move-result v1

    .line 53
    if-le v0, v1, :cond_1

    .line 54
    .line 55
    invoke-virtual {p0}, Landroid/util/Range;->getLower()Ljava/lang/Comparable;

    .line 56
    .line 57
    .line 58
    move-result-object p0

    .line 59
    check-cast p0, Ljava/lang/Integer;

    .line 60
    .line 61
    invoke-virtual {p0}, Ljava/lang/Integer;->intValue()I

    .line 62
    .line 63
    .line 64
    move-result p0

    .line 65
    invoke-virtual {p1}, Landroid/util/Range;->getUpper()Ljava/lang/Comparable;

    .line 66
    .line 67
    .line 68
    move-result-object p1

    .line 69
    check-cast p1, Ljava/lang/Integer;

    .line 70
    .line 71
    invoke-virtual {p1}, Ljava/lang/Integer;->intValue()I

    .line 72
    .line 73
    .line 74
    move-result p1

    .line 75
    sub-int/2addr p0, p1

    .line 76
    return p0

    .line 77
    :cond_1
    invoke-virtual {p1}, Landroid/util/Range;->getLower()Ljava/lang/Comparable;

    .line 78
    .line 79
    .line 80
    move-result-object p1

    .line 81
    check-cast p1, Ljava/lang/Integer;

    .line 82
    .line 83
    invoke-virtual {p1}, Ljava/lang/Integer;->intValue()I

    .line 84
    .line 85
    .line 86
    move-result p1

    .line 87
    invoke-virtual {p0}, Landroid/util/Range;->getUpper()Ljava/lang/Comparable;

    .line 88
    .line 89
    .line 90
    move-result-object p0

    .line 91
    check-cast p0, Ljava/lang/Integer;

    .line 92
    .line 93
    invoke-virtual {p0}, Ljava/lang/Integer;->intValue()I

    .line 94
    .line 95
    .line 96
    move-result p0

    .line 97
    sub-int/2addr p1, p0

    .line 98
    return p1
.end method

.method public static i(Landroid/util/Range;)I
    .locals 1

    .line 1
    invoke-virtual {p0}, Landroid/util/Range;->getUpper()Ljava/lang/Comparable;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    check-cast v0, Ljava/lang/Integer;

    .line 6
    .line 7
    invoke-virtual {v0}, Ljava/lang/Integer;->intValue()I

    .line 8
    .line 9
    .line 10
    move-result v0

    .line 11
    invoke-virtual {p0}, Landroid/util/Range;->getLower()Ljava/lang/Comparable;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    check-cast p0, Ljava/lang/Integer;

    .line 16
    .line 17
    invoke-virtual {p0}, Ljava/lang/Integer;->intValue()I

    .line 18
    .line 19
    .line 20
    move-result p0

    .line 21
    sub-int/2addr v0, p0

    .line 22
    add-int/lit8 v0, v0, 0x1

    .line 23
    .line 24
    return v0
.end method

.method public static m(Landroid/util/Range;Landroid/util/Range;Z)Landroid/util/Range;
    .locals 2

    .line 1
    sget-object v0, Lh0/k;->h:Landroid/util/Range;

    .line 2
    .line 3
    invoke-virtual {v0, p1}, Landroid/util/Range;->equals(Ljava/lang/Object;)Z

    .line 4
    .line 5
    .line 6
    move-result v1

    .line 7
    if-eqz v1, :cond_0

    .line 8
    .line 9
    invoke-virtual {v0, p0}, Landroid/util/Range;->equals(Ljava/lang/Object;)Z

    .line 10
    .line 11
    .line 12
    move-result v1

    .line 13
    if-eqz v1, :cond_0

    .line 14
    .line 15
    return-object v0

    .line 16
    :cond_0
    invoke-virtual {v0, p1}, Landroid/util/Range;->equals(Ljava/lang/Object;)Z

    .line 17
    .line 18
    .line 19
    move-result v1

    .line 20
    if-eqz v1, :cond_1

    .line 21
    .line 22
    return-object p0

    .line 23
    :cond_1
    invoke-virtual {v0, p0}, Landroid/util/Range;->equals(Ljava/lang/Object;)Z

    .line 24
    .line 25
    .line 26
    move-result v0

    .line 27
    if-eqz v0, :cond_2

    .line 28
    .line 29
    return-object p1

    .line 30
    :cond_2
    if-eqz p2, :cond_4

    .line 31
    .line 32
    if-ne p0, p1, :cond_3

    .line 33
    .line 34
    const/4 p1, 0x1

    .line 35
    goto :goto_0

    .line 36
    :cond_3
    const/4 p1, 0x0

    .line 37
    :goto_0
    const-string p2, "All targetFrameRate should be the same if strict fps is required"

    .line 38
    .line 39
    invoke-static {p2, p1}, Ljp/ed;->f(Ljava/lang/String;Z)V

    .line 40
    .line 41
    .line 42
    return-object p0

    .line 43
    :cond_4
    :try_start_0
    invoke-virtual {p1, p0}, Landroid/util/Range;->intersect(Landroid/util/Range;)Landroid/util/Range;

    .line 44
    .line 45
    .line 46
    move-result-object p0
    :try_end_0
    .catch Ljava/lang/IllegalArgumentException; {:try_start_0 .. :try_end_0} :catch_0

    .line 47
    return-object p0

    .line 48
    :catch_0
    return-object p1
.end method


# virtual methods
.method public final a(Lu/d;Ljava/util/List;Ljava/util/Map;Ljava/util/List;Ljava/util/List;)Z
    .locals 18

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    move-object/from16 v2, p2

    .line 6
    .line 7
    move-object/from16 v3, p4

    .line 8
    .line 9
    iget-boolean v4, v1, Lu/d;->d:Z

    .line 10
    .line 11
    iget-boolean v5, v1, Lu/d;->h:Z

    .line 12
    .line 13
    iget-object v6, v0, Lu/c1;->g:Ljava/util/HashMap;

    .line 14
    .line 15
    invoke-virtual {v6, v1}, Ljava/util/HashMap;->containsKey(Ljava/lang/Object;)Z

    .line 16
    .line 17
    .line 18
    move-result v7

    .line 19
    if-eqz v7, :cond_0

    .line 20
    .line 21
    invoke-virtual {v6, v1}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 22
    .line 23
    .line 24
    move-result-object v6

    .line 25
    check-cast v6, Ljava/util/List;

    .line 26
    .line 27
    goto/16 :goto_2

    .line 28
    .line 29
    :cond_0
    new-instance v7, Ljava/util/ArrayList;

    .line 30
    .line 31
    invoke-direct {v7}, Ljava/util/ArrayList;-><init>()V

    .line 32
    .line 33
    .line 34
    iget v10, v1, Lu/d;->a:I

    .line 35
    .line 36
    if-eqz v5, :cond_2

    .line 37
    .line 38
    iget-object v10, v0, Lu/c1;->f:Ljava/util/ArrayList;

    .line 39
    .line 40
    invoke-virtual {v10}, Ljava/util/ArrayList;->isEmpty()Z

    .line 41
    .line 42
    .line 43
    move-result v11

    .line 44
    if-eqz v11, :cond_1

    .line 45
    .line 46
    new-instance v11, Ljava/util/ArrayList;

    .line 47
    .line 48
    invoke-direct {v11}, Ljava/util/ArrayList;-><init>()V

    .line 49
    .line 50
    .line 51
    new-instance v12, Lh0/d2;

    .line 52
    .line 53
    sget-object v13, Lh0/g2;->d:Lh0/g2;

    .line 54
    .line 55
    sget-object v14, Lh0/e2;->k:Lh0/e2;

    .line 56
    .line 57
    invoke-static {v13, v14}, Lh0/h2;->a(Lh0/g2;Lh0/e2;)Lh0/h2;

    .line 58
    .line 59
    .line 60
    move-result-object v15

    .line 61
    filled-new-array {v15}, [Lh0/h2;

    .line 62
    .line 63
    .line 64
    move-result-object v15

    .line 65
    invoke-direct {v12, v15}, Lh0/d2;-><init>([Lh0/h2;)V

    .line 66
    .line 67
    .line 68
    invoke-virtual {v11, v12}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 69
    .line 70
    .line 71
    new-instance v12, Lh0/d2;

    .line 72
    .line 73
    sget-object v15, Lh0/e2;->h:Lh0/e2;

    .line 74
    .line 75
    invoke-static {v13, v15}, Lh0/h2;->a(Lh0/g2;Lh0/e2;)Lh0/h2;

    .line 76
    .line 77
    .line 78
    move-result-object v13

    .line 79
    filled-new-array {v13}, [Lh0/h2;

    .line 80
    .line 81
    .line 82
    move-result-object v13

    .line 83
    invoke-direct {v12, v13}, Lh0/d2;-><init>([Lh0/h2;)V

    .line 84
    .line 85
    .line 86
    invoke-virtual {v11, v12}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 87
    .line 88
    .line 89
    sget-object v12, Lh0/e2;->r:Lh0/e2;

    .line 90
    .line 91
    invoke-static {v14, v12}, Llp/b1;->a(Lh0/e2;Lh0/e2;)Ljava/util/ArrayList;

    .line 92
    .line 93
    .line 94
    move-result-object v13

    .line 95
    invoke-virtual {v11, v13}, Ljava/util/ArrayList;->addAll(Ljava/util/Collection;)Z

    .line 96
    .line 97
    .line 98
    sget-object v13, Lh0/e2;->n:Lh0/e2;

    .line 99
    .line 100
    invoke-static {v14, v13}, Llp/b1;->a(Lh0/e2;Lh0/e2;)Ljava/util/ArrayList;

    .line 101
    .line 102
    .line 103
    move-result-object v8

    .line 104
    invoke-virtual {v11, v8}, Ljava/util/ArrayList;->addAll(Ljava/util/Collection;)Z

    .line 105
    .line 106
    .line 107
    sget-object v8, Lh0/e2;->m:Lh0/e2;

    .line 108
    .line 109
    invoke-static {v14, v8}, Llp/b1;->a(Lh0/e2;Lh0/e2;)Ljava/util/ArrayList;

    .line 110
    .line 111
    .line 112
    move-result-object v8

    .line 113
    invoke-virtual {v11, v8}, Ljava/util/ArrayList;->addAll(Ljava/util/Collection;)Z

    .line 114
    .line 115
    .line 116
    invoke-static {v14, v14}, Llp/b1;->a(Lh0/e2;Lh0/e2;)Ljava/util/ArrayList;

    .line 117
    .line 118
    .line 119
    move-result-object v8

    .line 120
    invoke-virtual {v11, v8}, Ljava/util/ArrayList;->addAll(Ljava/util/Collection;)Z

    .line 121
    .line 122
    .line 123
    invoke-static {v15, v12}, Llp/b1;->a(Lh0/e2;Lh0/e2;)Ljava/util/ArrayList;

    .line 124
    .line 125
    .line 126
    move-result-object v8

    .line 127
    invoke-virtual {v11, v8}, Ljava/util/ArrayList;->addAll(Ljava/util/Collection;)Z

    .line 128
    .line 129
    .line 130
    invoke-static {v15, v13}, Llp/b1;->a(Lh0/e2;Lh0/e2;)Ljava/util/ArrayList;

    .line 131
    .line 132
    .line 133
    move-result-object v8

    .line 134
    invoke-virtual {v11, v8}, Ljava/util/ArrayList;->addAll(Ljava/util/Collection;)Z

    .line 135
    .line 136
    .line 137
    invoke-static {v15, v14}, Llp/b1;->a(Lh0/e2;Lh0/e2;)Ljava/util/ArrayList;

    .line 138
    .line 139
    .line 140
    move-result-object v8

    .line 141
    invoke-virtual {v11, v8}, Ljava/util/ArrayList;->addAll(Ljava/util/Collection;)Z

    .line 142
    .line 143
    .line 144
    sget-object v8, Lh0/e2;->g:Lh0/e2;

    .line 145
    .line 146
    sget-object v12, Lh0/e2;->q:Lh0/e2;

    .line 147
    .line 148
    invoke-static {v8, v12}, Llp/b1;->a(Lh0/e2;Lh0/e2;)Ljava/util/ArrayList;

    .line 149
    .line 150
    .line 151
    move-result-object v8

    .line 152
    invoke-virtual {v11, v8}, Ljava/util/ArrayList;->addAll(Ljava/util/Collection;)Z

    .line 153
    .line 154
    .line 155
    sget-object v8, Lh0/e2;->j:Lh0/e2;

    .line 156
    .line 157
    invoke-static {v8, v12}, Llp/b1;->a(Lh0/e2;Lh0/e2;)Ljava/util/ArrayList;

    .line 158
    .line 159
    .line 160
    move-result-object v8

    .line 161
    invoke-virtual {v11, v8}, Ljava/util/ArrayList;->addAll(Ljava/util/Collection;)Z

    .line 162
    .line 163
    .line 164
    invoke-virtual {v10, v11}, Ljava/util/ArrayList;->addAll(Ljava/util/Collection;)Z

    .line 165
    .line 166
    .line 167
    :cond_1
    invoke-virtual {v7, v10}, Ljava/util/ArrayList;->addAll(Ljava/util/Collection;)Z

    .line 168
    .line 169
    .line 170
    goto/16 :goto_1

    .line 171
    .line 172
    :cond_2
    iget-boolean v8, v1, Lu/d;->e:Z

    .line 173
    .line 174
    if-eqz v8, :cond_4

    .line 175
    .line 176
    iget-object v8, v0, Lu/c1;->i:Ljava/util/ArrayList;

    .line 177
    .line 178
    invoke-virtual {v8}, Ljava/util/ArrayList;->isEmpty()Z

    .line 179
    .line 180
    .line 181
    move-result v11

    .line 182
    if-eqz v11, :cond_3

    .line 183
    .line 184
    new-instance v11, Ljava/util/ArrayList;

    .line 185
    .line 186
    invoke-direct {v11}, Ljava/util/ArrayList;-><init>()V

    .line 187
    .line 188
    .line 189
    new-instance v12, Lh0/d2;

    .line 190
    .line 191
    invoke-direct {v12}, Lh0/d2;-><init>()V

    .line 192
    .line 193
    .line 194
    sget-object v13, Lh0/g2;->g:Lh0/g2;

    .line 195
    .line 196
    sget-object v14, Lh0/e2;->p:Lh0/e2;

    .line 197
    .line 198
    invoke-static {v13, v14, v12, v11, v12}, Lu/w;->b(Lh0/g2;Lh0/e2;Lh0/d2;Ljava/util/ArrayList;Lh0/d2;)Lh0/d2;

    .line 199
    .line 200
    .line 201
    move-result-object v12

    .line 202
    sget-object v15, Lh0/g2;->d:Lh0/g2;

    .line 203
    .line 204
    sget-object v9, Lh0/e2;->i:Lh0/e2;

    .line 205
    .line 206
    invoke-static {v15, v9, v12, v13, v14}, Lu/w;->l(Lh0/g2;Lh0/e2;Lh0/d2;Lh0/g2;Lh0/e2;)V

    .line 207
    .line 208
    .line 209
    invoke-virtual {v11, v12}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 210
    .line 211
    .line 212
    invoke-virtual {v8, v11}, Ljava/util/ArrayList;->addAll(Ljava/util/Collection;)Z

    .line 213
    .line 214
    .line 215
    :cond_3
    if-nez v10, :cond_c

    .line 216
    .line 217
    invoke-virtual {v7, v8}, Ljava/util/ArrayList;->addAll(Ljava/util/Collection;)Z

    .line 218
    .line 219
    .line 220
    goto/16 :goto_1

    .line 221
    .line 222
    :cond_4
    iget-boolean v8, v1, Lu/d;->f:Z

    .line 223
    .line 224
    if-eqz v8, :cond_7

    .line 225
    .line 226
    iget-object v8, v0, Lu/c1;->e:Ljava/util/ArrayList;

    .line 227
    .line 228
    invoke-virtual {v8}, Ljava/util/ArrayList;->isEmpty()Z

    .line 229
    .line 230
    .line 231
    move-result v9

    .line 232
    if-eqz v9, :cond_6

    .line 233
    .line 234
    iget-object v9, v0, Lu/c1;->C:Lu/t0;

    .line 235
    .line 236
    iget-object v10, v9, Lu/t0;->b:Llx0/q;

    .line 237
    .line 238
    invoke-virtual {v10}, Llx0/q;->getValue()Ljava/lang/Object;

    .line 239
    .line 240
    .line 241
    move-result-object v10

    .line 242
    check-cast v10, Ljava/lang/Boolean;

    .line 243
    .line 244
    invoke-virtual {v10}, Ljava/lang/Boolean;->booleanValue()Z

    .line 245
    .line 246
    .line 247
    move-result v10

    .line 248
    if-nez v10, :cond_5

    .line 249
    .line 250
    goto :goto_0

    .line 251
    :cond_5
    invoke-virtual {v8}, Ljava/util/ArrayList;->clear()V

    .line 252
    .line 253
    .line 254
    iget-object v9, v9, Lu/t0;->c:Llx0/q;

    .line 255
    .line 256
    invoke-virtual {v9}, Llx0/q;->getValue()Ljava/lang/Object;

    .line 257
    .line 258
    .line 259
    move-result-object v9

    .line 260
    move-object v11, v9

    .line 261
    check-cast v11, Landroid/util/Size;

    .line 262
    .line 263
    if-eqz v11, :cond_6

    .line 264
    .line 265
    const/16 v9, 0x22

    .line 266
    .line 267
    invoke-virtual {v0, v9}, Lu/c1;->l(I)Lh0/l;

    .line 268
    .line 269
    .line 270
    move-result-object v12

    .line 271
    new-instance v9, Ljava/util/ArrayList;

    .line 272
    .line 273
    invoke-direct {v9}, Ljava/util/ArrayList;-><init>()V

    .line 274
    .line 275
    .line 276
    sget-object v10, Lh0/h2;->e:Lh0/c2;

    .line 277
    .line 278
    const-string v10, "surfaceSizeDefinition"

    .line 279
    .line 280
    invoke-static {v12, v10}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 281
    .line 282
    .line 283
    sget-object v14, Lh0/f2;->e:Lh0/f2;

    .line 284
    .line 285
    sget-object v15, Lh0/h2;->e:Lh0/c2;

    .line 286
    .line 287
    const/16 v10, 0x22

    .line 288
    .line 289
    const/4 v13, 0x0

    .line 290
    invoke-static/range {v10 .. v15}, Lkp/aa;->d(ILandroid/util/Size;Lh0/l;ILh0/f2;Lh0/c2;)Lh0/h2;

    .line 291
    .line 292
    .line 293
    move-result-object v10

    .line 294
    new-instance v11, Lh0/d2;

    .line 295
    .line 296
    invoke-direct {v11}, Lh0/d2;-><init>()V

    .line 297
    .line 298
    .line 299
    invoke-virtual {v11, v10}, Lh0/d2;->a(Lh0/h2;)V

    .line 300
    .line 301
    .line 302
    invoke-virtual {v9, v11}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 303
    .line 304
    .line 305
    new-instance v11, Lh0/d2;

    .line 306
    .line 307
    invoke-direct {v11}, Lh0/d2;-><init>()V

    .line 308
    .line 309
    .line 310
    invoke-virtual {v11, v10}, Lh0/d2;->a(Lh0/h2;)V

    .line 311
    .line 312
    .line 313
    invoke-virtual {v11, v10}, Lh0/d2;->a(Lh0/h2;)V

    .line 314
    .line 315
    .line 316
    invoke-virtual {v9, v11}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 317
    .line 318
    .line 319
    invoke-virtual {v8, v9}, Ljava/util/ArrayList;->addAll(Ljava/util/Collection;)Z

    .line 320
    .line 321
    .line 322
    :cond_6
    :goto_0
    invoke-virtual {v7, v8}, Ljava/util/ArrayList;->addAll(Ljava/util/Collection;)Z

    .line 323
    .line 324
    .line 325
    goto :goto_1

    .line 326
    :cond_7
    iget v8, v1, Lu/d;->c:I

    .line 327
    .line 328
    const/16 v9, 0x8

    .line 329
    .line 330
    if-ne v8, v9, :cond_b

    .line 331
    .line 332
    const/4 v9, 0x1

    .line 333
    if-eq v10, v9, :cond_a

    .line 334
    .line 335
    iget-object v8, v0, Lu/c1;->a:Ljava/util/ArrayList;

    .line 336
    .line 337
    const/4 v9, 0x2

    .line 338
    if-eq v10, v9, :cond_9

    .line 339
    .line 340
    if-eqz v4, :cond_8

    .line 341
    .line 342
    iget-object v8, v0, Lu/c1;->d:Ljava/util/ArrayList;

    .line 343
    .line 344
    :cond_8
    invoke-virtual {v7, v8}, Ljava/util/ArrayList;->addAll(Ljava/util/Collection;)Z

    .line 345
    .line 346
    .line 347
    goto :goto_1

    .line 348
    :cond_9
    iget-object v9, v0, Lu/c1;->b:Ljava/util/ArrayList;

    .line 349
    .line 350
    invoke-virtual {v7, v9}, Ljava/util/ArrayList;->addAll(Ljava/util/Collection;)Z

    .line 351
    .line 352
    .line 353
    invoke-virtual {v7, v8}, Ljava/util/ArrayList;->addAll(Ljava/util/Collection;)Z

    .line 354
    .line 355
    .line 356
    goto :goto_1

    .line 357
    :cond_a
    iget-object v7, v0, Lu/c1;->c:Ljava/util/ArrayList;

    .line 358
    .line 359
    goto :goto_1

    .line 360
    :cond_b
    const/16 v9, 0xa

    .line 361
    .line 362
    if-ne v8, v9, :cond_c

    .line 363
    .line 364
    if-nez v10, :cond_c

    .line 365
    .line 366
    iget-object v8, v0, Lu/c1;->h:Ljava/util/ArrayList;

    .line 367
    .line 368
    invoke-virtual {v7, v8}, Ljava/util/ArrayList;->addAll(Ljava/util/Collection;)Z

    .line 369
    .line 370
    .line 371
    :cond_c
    :goto_1
    invoke-virtual {v6, v1, v7}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 372
    .line 373
    .line 374
    move-object v6, v7

    .line 375
    :goto_2
    invoke-interface {v6}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 376
    .line 377
    .line 378
    move-result-object v6

    .line 379
    const/4 v9, 0x0

    .line 380
    move v7, v9

    .line 381
    :cond_d
    invoke-interface {v6}, Ljava/util/Iterator;->hasNext()Z

    .line 382
    .line 383
    .line 384
    move-result v8

    .line 385
    if-eqz v8, :cond_f

    .line 386
    .line 387
    invoke-interface {v6}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 388
    .line 389
    .line 390
    move-result-object v7

    .line 391
    check-cast v7, Lh0/d2;

    .line 392
    .line 393
    invoke-virtual {v7, v2}, Lh0/d2;->c(Ljava/util/List;)Ljava/util/List;

    .line 394
    .line 395
    .line 396
    move-result-object v7

    .line 397
    if-eqz v7, :cond_e

    .line 398
    .line 399
    const/4 v7, 0x1

    .line 400
    goto :goto_3

    .line 401
    :cond_e
    move v7, v9

    .line 402
    :goto_3
    if-eqz v7, :cond_d

    .line 403
    .line 404
    :cond_f
    if-eqz v7, :cond_1b

    .line 405
    .line 406
    if-eqz v5, :cond_1b

    .line 407
    .line 408
    iget-object v5, v1, Lu/d;->i:Landroid/util/Range;

    .line 409
    .line 410
    new-instance v6, Lh0/y1;

    .line 411
    .line 412
    invoke-direct {v6}, Lh0/y1;-><init>()V

    .line 413
    .line 414
    .line 415
    :goto_4
    invoke-interface {v2}, Ljava/util/List;->size()I

    .line 416
    .line 417
    .line 418
    move-result v7

    .line 419
    if-ge v9, v7, :cond_19

    .line 420
    .line 421
    invoke-interface {v2, v9}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 422
    .line 423
    .line 424
    move-result-object v7

    .line 425
    check-cast v7, Lh0/h2;

    .line 426
    .line 427
    iget v8, v7, Lh0/h2;->d:I

    .line 428
    .line 429
    invoke-virtual {v0, v8}, Lu/c1;->l(I)Lh0/l;

    .line 430
    .line 431
    .line 432
    move-result-object v8

    .line 433
    iget v10, v7, Lh0/h2;->d:I

    .line 434
    .line 435
    const-string v11, "definition"

    .line 436
    .line 437
    invoke-static {v8, v11}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 438
    .line 439
    .line 440
    iget-object v11, v8, Lh0/l;->f:Ljava/util/HashMap;

    .line 441
    .line 442
    iget-object v12, v7, Lh0/h2;->b:Lh0/e2;

    .line 443
    .line 444
    invoke-virtual {v12}, Ljava/lang/Enum;->ordinal()I

    .line 445
    .line 446
    .line 447
    move-result v13

    .line 448
    const/4 v14, 0x3

    .line 449
    if-eq v13, v14, :cond_10

    .line 450
    .line 451
    packed-switch v13, :pswitch_data_0

    .line 452
    .line 453
    .line 454
    iget-object v8, v12, Lh0/e2;->e:Landroid/util/Size;

    .line 455
    .line 456
    goto :goto_5

    .line 457
    :pswitch_0
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 458
    .line 459
    const-string v1, "Not supported config size"

    .line 460
    .line 461
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 462
    .line 463
    .line 464
    throw v0

    .line 465
    :pswitch_1
    iget-object v8, v8, Lh0/l;->i:Ljava/util/HashMap;

    .line 466
    .line 467
    invoke-static {v10}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 468
    .line 469
    .line 470
    move-result-object v10

    .line 471
    invoke-virtual {v8, v10}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 472
    .line 473
    .line 474
    move-result-object v8

    .line 475
    check-cast v8, Landroid/util/Size;

    .line 476
    .line 477
    goto :goto_5

    .line 478
    :pswitch_2
    invoke-static {v10}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 479
    .line 480
    .line 481
    move-result-object v8

    .line 482
    invoke-virtual {v11, v8}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 483
    .line 484
    .line 485
    move-result-object v8

    .line 486
    check-cast v8, Landroid/util/Size;

    .line 487
    .line 488
    goto :goto_5

    .line 489
    :pswitch_3
    invoke-static {v10}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 490
    .line 491
    .line 492
    move-result-object v8

    .line 493
    invoke-virtual {v11, v8}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 494
    .line 495
    .line 496
    move-result-object v8

    .line 497
    check-cast v8, Landroid/util/Size;

    .line 498
    .line 499
    goto :goto_5

    .line 500
    :pswitch_4
    invoke-static {v10}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 501
    .line 502
    .line 503
    move-result-object v8

    .line 504
    invoke-virtual {v11, v8}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 505
    .line 506
    .line 507
    move-result-object v8

    .line 508
    check-cast v8, Landroid/util/Size;

    .line 509
    .line 510
    goto :goto_5

    .line 511
    :pswitch_5
    iget-object v8, v8, Lh0/l;->e:Landroid/util/Size;

    .line 512
    .line 513
    goto :goto_5

    .line 514
    :cond_10
    iget-object v8, v8, Lh0/l;->c:Landroid/util/Size;

    .line 515
    .line 516
    :goto_5
    invoke-static {v8}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 517
    .line 518
    .line 519
    move-object/from16 v10, p5

    .line 520
    .line 521
    invoke-interface {v10, v9}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 522
    .line 523
    .line 524
    move-result-object v11

    .line 525
    check-cast v11, Ljava/lang/Integer;

    .line 526
    .line 527
    invoke-virtual {v11}, Ljava/lang/Integer;->intValue()I

    .line 528
    .line 529
    .line 530
    move-result v11

    .line 531
    invoke-interface {v3, v11}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 532
    .line 533
    .line 534
    move-result-object v11

    .line 535
    check-cast v11, Lh0/o2;

    .line 536
    .line 537
    move-object/from16 v12, p3

    .line 538
    .line 539
    invoke-interface {v12, v7}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 540
    .line 541
    .line 542
    move-result-object v13

    .line 543
    check-cast v13, Lb0/y;

    .line 544
    .line 545
    invoke-static {v13}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    .line 546
    .line 547
    .line 548
    const-string v15, "<this>"

    .line 549
    .line 550
    invoke-static {v11, v15}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 551
    .line 552
    .line 553
    invoke-interface {v11}, Lh0/z0;->l()I

    .line 554
    .line 555
    .line 556
    move-result v15

    .line 557
    new-instance v14, Ld0/a;

    .line 558
    .line 559
    invoke-direct {v14, v8, v15}, Lh0/t0;-><init>(Landroid/util/Size;I)V

    .line 560
    .line 561
    .line 562
    sget-object v15, Ld0/d;->e:Lip/v;

    .line 563
    .line 564
    invoke-virtual {v15}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 565
    .line 566
    .line 567
    invoke-interface {v11}, Lh0/o2;->J()Lh0/q2;

    .line 568
    .line 569
    .line 570
    move-result-object v15

    .line 571
    invoke-virtual {v15}, Ljava/lang/Enum;->ordinal()I

    .line 572
    .line 573
    .line 574
    move-result v15

    .line 575
    if-eqz v15, :cond_14

    .line 576
    .line 577
    move/from16 v17, v4

    .line 578
    .line 579
    const/4 v4, 0x1

    .line 580
    if-eq v15, v4, :cond_13

    .line 581
    .line 582
    const/4 v4, 0x3

    .line 583
    if-eq v15, v4, :cond_12

    .line 584
    .line 585
    const/4 v4, 0x4

    .line 586
    if-eq v15, v4, :cond_11

    .line 587
    .line 588
    sget-object v4, Ld0/d;->j:Ld0/d;

    .line 589
    .line 590
    goto :goto_6

    .line 591
    :cond_11
    sget-object v4, Ld0/d;->i:Ld0/d;

    .line 592
    .line 593
    goto :goto_6

    .line 594
    :cond_12
    sget-object v4, Ld0/d;->h:Ld0/d;

    .line 595
    .line 596
    goto :goto_6

    .line 597
    :cond_13
    sget-object v4, Ld0/d;->f:Ld0/d;

    .line 598
    .line 599
    goto :goto_6

    .line 600
    :cond_14
    move/from16 v17, v4

    .line 601
    .line 602
    sget-object v4, Ld0/d;->g:Ld0/d;

    .line 603
    .line 604
    :goto_6
    iget-object v4, v4, Ld0/d;->d:Ljava/lang/Class;

    .line 605
    .line 606
    if-eqz v4, :cond_15

    .line 607
    .line 608
    iput-object v4, v14, Lh0/t0;->j:Ljava/lang/Class;

    .line 609
    .line 610
    :cond_15
    invoke-static {v11, v8}, Lh0/v1;->d(Lh0/o2;Landroid/util/Size;)Lh0/v1;

    .line 611
    .line 612
    .line 613
    move-result-object v4

    .line 614
    iget-object v8, v4, Lh0/u1;->b:Lb0/n1;

    .line 615
    .line 616
    const/4 v15, -0x1

    .line 617
    invoke-virtual {v4, v14, v13, v15}, Lh0/v1;->b(Lh0/t0;Lb0/y;I)V

    .line 618
    .line 619
    .line 620
    sget-object v13, Lh0/k;->h:Landroid/util/Range;

    .line 621
    .line 622
    invoke-virtual {v13, v5}, Landroid/util/Range;->equals(Ljava/lang/Object;)Z

    .line 623
    .line 624
    .line 625
    move-result v13

    .line 626
    if-eqz v13, :cond_16

    .line 627
    .line 628
    sget-object v13, Le0/c;->d:Landroid/util/Range;

    .line 629
    .line 630
    goto :goto_7

    .line 631
    :cond_16
    move-object v13, v5

    .line 632
    :goto_7
    invoke-virtual {v8}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 633
    .line 634
    .line 635
    sget-object v14, Lh0/o0;->j:Lh0/g;

    .line 636
    .line 637
    iget-object v15, v8, Lb0/n1;->g:Ljava/lang/Object;

    .line 638
    .line 639
    check-cast v15, Lh0/j1;

    .line 640
    .line 641
    invoke-virtual {v15, v14, v13}, Lh0/j1;->n(Lh0/g;Ljava/lang/Object;)V

    .line 642
    .line 643
    .line 644
    if-eqz v17, :cond_17

    .line 645
    .line 646
    invoke-virtual {v8}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 647
    .line 648
    .line 649
    sget-object v13, Lh0/o2;->a1:Lh0/g;

    .line 650
    .line 651
    const/16 v16, 0x2

    .line 652
    .line 653
    invoke-static/range {v16 .. v16}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 654
    .line 655
    .line 656
    move-result-object v14

    .line 657
    iget-object v8, v8, Lb0/n1;->g:Ljava/lang/Object;

    .line 658
    .line 659
    check-cast v8, Lh0/j1;

    .line 660
    .line 661
    invoke-virtual {v8, v13, v14}, Lh0/j1;->n(Lh0/g;Ljava/lang/Object;)V

    .line 662
    .line 663
    .line 664
    goto :goto_8

    .line 665
    :cond_17
    const/16 v16, 0x2

    .line 666
    .line 667
    :goto_8
    invoke-virtual {v4}, Lh0/v1;->c()Lh0/z1;

    .line 668
    .line 669
    .line 670
    move-result-object v4

    .line 671
    invoke-virtual {v6, v4}, Lh0/y1;->a(Lh0/z1;)V

    .line 672
    .line 673
    .line 674
    invoke-virtual {v6}, Lh0/y1;->c()Z

    .line 675
    .line 676
    .line 677
    move-result v4

    .line 678
    new-instance v8, Ljava/lang/StringBuilder;

    .line 679
    .line 680
    const-string v13, "Cannot create a combined SessionConfig for feature combo after adding "

    .line 681
    .line 682
    invoke-direct {v8, v13}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 683
    .line 684
    .line 685
    invoke-virtual {v8, v11}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 686
    .line 687
    .line 688
    const-string v11, " with "

    .line 689
    .line 690
    invoke-virtual {v8, v11}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 691
    .line 692
    .line 693
    invoke-virtual {v8, v7}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 694
    .line 695
    .line 696
    const-string v7, " due to ["

    .line 697
    .line 698
    invoke-virtual {v8, v7}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 699
    .line 700
    .line 701
    iget-boolean v7, v6, Lh0/y1;->m:Z

    .line 702
    .line 703
    if-nez v7, :cond_18

    .line 704
    .line 705
    const-string v7, "Template is not set"

    .line 706
    .line 707
    goto :goto_9

    .line 708
    :cond_18
    iget-object v7, v6, Lh0/y1;->l:Ljava/lang/StringBuilder;

    .line 709
    .line 710
    invoke-virtual {v7}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 711
    .line 712
    .line 713
    move-result-object v7

    .line 714
    :goto_9
    const-string v11, "]; surfaceConfigList = "

    .line 715
    .line 716
    const-string v13, ", featureSettings = "

    .line 717
    .line 718
    invoke-static {v8, v7, v11, v2, v13}, Lu/w;->m(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;Ljava/util/List;Ljava/lang/String;)V

    .line 719
    .line 720
    .line 721
    invoke-virtual {v8, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 722
    .line 723
    .line 724
    const-string v7, ", newUseCaseConfigs = "

    .line 725
    .line 726
    invoke-virtual {v8, v7}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 727
    .line 728
    .line 729
    invoke-virtual {v8, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 730
    .line 731
    .line 732
    invoke-virtual {v8}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 733
    .line 734
    .line 735
    move-result-object v7

    .line 736
    invoke-static {v7, v4}, Ljp/ed;->f(Ljava/lang/String;Z)V

    .line 737
    .line 738
    .line 739
    add-int/lit8 v9, v9, 0x1

    .line 740
    .line 741
    move/from16 v4, v17

    .line 742
    .line 743
    goto/16 :goto_4

    .line 744
    .line 745
    :cond_19
    invoke-virtual {v6}, Lh0/y1;->b()Lh0/z1;

    .line 746
    .line 747
    .line 748
    move-result-object v1

    .line 749
    iget-object v0, v0, Lu/c1;->D:Ld0/b;

    .line 750
    .line 751
    invoke-interface {v0, v1}, Ld0/b;->a(Lh0/z1;)Z

    .line 752
    .line 753
    .line 754
    move-result v0

    .line 755
    invoke-virtual {v1}, Lh0/z1;->b()Ljava/util/List;

    .line 756
    .line 757
    .line 758
    move-result-object v1

    .line 759
    invoke-interface {v1}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 760
    .line 761
    .line 762
    move-result-object v1

    .line 763
    :goto_a
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 764
    .line 765
    .line 766
    move-result v2

    .line 767
    if-eqz v2, :cond_1a

    .line 768
    .line 769
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 770
    .line 771
    .line 772
    move-result-object v2

    .line 773
    check-cast v2, Lh0/t0;

    .line 774
    .line 775
    invoke-virtual {v2}, Lh0/t0;->a()V

    .line 776
    .line 777
    .line 778
    goto :goto_a

    .line 779
    :cond_1a
    return v0

    .line 780
    :cond_1b
    return v7

    .line 781
    :pswitch_data_0
    .packed-switch 0x9
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final b(IZLjava/util/HashMap;ZZZZZLandroid/util/Range;Z)Lu/d;
    .locals 12

    .line 1
    invoke-virtual {p3}, Ljava/util/HashMap;->values()Ljava/util/Collection;

    .line 2
    .line 3
    .line 4
    move-result-object v2

    .line 5
    invoke-interface {v2}, Ljava/util/Collection;->iterator()Ljava/util/Iterator;

    .line 6
    .line 7
    .line 8
    move-result-object v2

    .line 9
    :cond_0
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    .line 10
    .line 11
    .line 12
    move-result v3

    .line 13
    const/16 v4, 0xa

    .line 14
    .line 15
    if-eqz v3, :cond_1

    .line 16
    .line 17
    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 18
    .line 19
    .line 20
    move-result-object v3

    .line 21
    check-cast v3, Lb0/y;

    .line 22
    .line 23
    iget v3, v3, Lb0/y;->b:I

    .line 24
    .line 25
    if-ne v3, v4, :cond_0

    .line 26
    .line 27
    move v3, v4

    .line 28
    goto :goto_0

    .line 29
    :cond_1
    const/16 v2, 0x8

    .line 30
    .line 31
    move v3, v2

    .line 32
    :goto_0
    const-string v2, "CONCURRENT_CAMERA"

    .line 33
    .line 34
    const-string v5, "ULTRA_HIGH_RESOLUTION_CAMERA"

    .line 35
    .line 36
    const-string v6, "DEFAULT"

    .line 37
    .line 38
    const/4 v7, 0x2

    .line 39
    const/4 v8, 0x1

    .line 40
    const-string v9, " camera mode."

    .line 41
    .line 42
    const-string v10, "Camera device id is "

    .line 43
    .line 44
    iget-object v11, p0, Lu/c1;->k:Ljava/lang/String;

    .line 45
    .line 46
    if-eqz p1, :cond_5

    .line 47
    .line 48
    if-nez p5, :cond_2

    .line 49
    .line 50
    goto :goto_2

    .line 51
    :cond_2
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 52
    .line 53
    if-eq p1, v8, :cond_4

    .line 54
    .line 55
    if-eq p1, v7, :cond_3

    .line 56
    .line 57
    move-object v2, v6

    .line 58
    goto :goto_1

    .line 59
    :cond_3
    move-object v2, v5

    .line 60
    :cond_4
    :goto_1
    const-string v1, ". Ultra HDR is not currently supported in "

    .line 61
    .line 62
    invoke-static {v10, v11, v1, v2, v9}, Lu/w;->g(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 63
    .line 64
    .line 65
    move-result-object v1

    .line 66
    invoke-direct {v0, v1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 67
    .line 68
    .line 69
    throw v0

    .line 70
    :cond_5
    :goto_2
    if-eqz p1, :cond_9

    .line 71
    .line 72
    if-eq v3, v4, :cond_6

    .line 73
    .line 74
    goto :goto_4

    .line 75
    :cond_6
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 76
    .line 77
    if-eq p1, v8, :cond_8

    .line 78
    .line 79
    if-eq p1, v7, :cond_7

    .line 80
    .line 81
    move-object v2, v6

    .line 82
    goto :goto_3

    .line 83
    :cond_7
    move-object v2, v5

    .line 84
    :cond_8
    :goto_3
    const-string v1, ". 10 bit dynamic range is not currently supported in "

    .line 85
    .line 86
    invoke-static {v10, v11, v1, v2, v9}, Lu/w;->g(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 87
    .line 88
    .line 89
    move-result-object v1

    .line 90
    invoke-direct {v0, v1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 91
    .line 92
    .line 93
    throw v0

    .line 94
    :cond_9
    :goto_4
    if-eqz p1, :cond_d

    .line 95
    .line 96
    if-nez p7, :cond_a

    .line 97
    .line 98
    goto :goto_6

    .line 99
    :cond_a
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 100
    .line 101
    if-eq p1, v8, :cond_c

    .line 102
    .line 103
    if-eq p1, v7, :cond_b

    .line 104
    .line 105
    move-object v2, v6

    .line 106
    goto :goto_5

    .line 107
    :cond_b
    move-object v2, v5

    .line 108
    :cond_c
    :goto_5
    const-string v1, ". Feature combination query is not currently supported in "

    .line 109
    .line 110
    invoke-static {v10, v11, v1, v2, v9}, Lu/w;->g(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 111
    .line 112
    .line 113
    move-result-object v1

    .line 114
    invoke-direct {v0, v1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 115
    .line 116
    .line 117
    throw v0

    .line 118
    :cond_d
    :goto_6
    if-eqz p6, :cond_f

    .line 119
    .line 120
    if-nez p7, :cond_e

    .line 121
    .line 122
    goto :goto_7

    .line 123
    :cond_e
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 124
    .line 125
    const-string v1, "High-speed session is not supported with feature combination"

    .line 126
    .line 127
    invoke-direct {v0, v1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 128
    .line 129
    .line 130
    throw v0

    .line 131
    :cond_f
    :goto_7
    if-eqz p6, :cond_11

    .line 132
    .line 133
    iget-object v0, p0, Lu/c1;->C:Lu/t0;

    .line 134
    .line 135
    iget-object v0, v0, Lu/t0;->b:Llx0/q;

    .line 136
    .line 137
    invoke-virtual {v0}, Llx0/q;->getValue()Ljava/lang/Object;

    .line 138
    .line 139
    .line 140
    move-result-object v0

    .line 141
    check-cast v0, Ljava/lang/Boolean;

    .line 142
    .line 143
    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 144
    .line 145
    .line 146
    move-result v0

    .line 147
    if-eqz v0, :cond_10

    .line 148
    .line 149
    goto :goto_8

    .line 150
    :cond_10
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 151
    .line 152
    const-string v1, "High-speed session is not supported on this device."

    .line 153
    .line 154
    invoke-direct {v0, v1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 155
    .line 156
    .line 157
    throw v0

    .line 158
    :cond_11
    :goto_8
    if-eqz p7, :cond_12

    .line 159
    .line 160
    sget-object v0, Lh0/k;->h:Landroid/util/Range;

    .line 161
    .line 162
    move-object/from16 v2, p9

    .line 163
    .line 164
    if-ne v2, v0, :cond_13

    .line 165
    .line 166
    if-eqz p8, :cond_13

    .line 167
    .line 168
    sget-object v0, Le0/c;->d:Landroid/util/Range;

    .line 169
    .line 170
    move-object v9, v0

    .line 171
    goto :goto_9

    .line 172
    :cond_12
    move-object/from16 v2, p9

    .line 173
    .line 174
    :cond_13
    move-object v9, v2

    .line 175
    :goto_9
    new-instance v0, Lu/d;

    .line 176
    .line 177
    move v1, p1

    .line 178
    move v2, p2

    .line 179
    move/from16 v4, p4

    .line 180
    .line 181
    move/from16 v5, p5

    .line 182
    .line 183
    move/from16 v6, p6

    .line 184
    .line 185
    move/from16 v7, p7

    .line 186
    .line 187
    move/from16 v8, p8

    .line 188
    .line 189
    move/from16 v10, p10

    .line 190
    .line 191
    invoke-direct/range {v0 .. v10}, Lu/d;-><init>(IZIZZZZZLandroid/util/Range;Z)V

    .line 192
    .line 193
    .line 194
    return-object v0
.end method

.method public final c()V
    .locals 11

    .line 1
    iget-object v0, p0, Lu/c1;->y:Lu/q0;

    .line 2
    .line 3
    invoke-virtual {v0}, Lu/q0;->e()Landroid/util/Size;

    .line 4
    .line 5
    .line 6
    move-result-object v4

    .line 7
    const/4 v0, 0x0

    .line 8
    const/4 v1, 0x0

    .line 9
    :try_start_0
    iget-object v2, p0, Lu/c1;->k:Ljava/lang/String;

    .line 10
    .line 11
    invoke-static {v2}, Ljava/lang/Integer;->parseInt(Ljava/lang/String;)I

    .line 12
    .line 13
    .line 14
    move-result v2

    .line 15
    iget-object v3, p0, Lu/c1;->l:Lu/e;

    .line 16
    .line 17
    const/16 v5, 0x8

    .line 18
    .line 19
    new-array v6, v5, [I

    .line 20
    .line 21
    fill-array-data v6, :array_0

    .line 22
    .line 23
    .line 24
    move v7, v1

    .line 25
    :goto_0
    if-ge v7, v5, :cond_1

    .line 26
    .line 27
    aget v8, v6, v7

    .line 28
    .line 29
    invoke-interface {v3, v2, v8}, Lu/e;->f(II)Z

    .line 30
    .line 31
    .line 32
    move-result v9

    .line 33
    if-eqz v9, :cond_0

    .line 34
    .line 35
    invoke-interface {v3, v2, v8}, Lu/e;->b(II)Landroid/media/CamcorderProfile;

    .line 36
    .line 37
    .line 38
    move-result-object v8

    .line 39
    if-eqz v8, :cond_0

    .line 40
    .line 41
    new-instance v2, Landroid/util/Size;

    .line 42
    .line 43
    iget v3, v8, Landroid/media/CamcorderProfile;->videoFrameWidth:I

    .line 44
    .line 45
    iget v5, v8, Landroid/media/CamcorderProfile;->videoFrameHeight:I

    .line 46
    .line 47
    invoke-direct {v2, v3, v5}, Landroid/util/Size;-><init>(II)V
    :try_end_0
    .catch Ljava/lang/NumberFormatException; {:try_start_0 .. :try_end_0} :catch_0

    .line 48
    .line 49
    .line 50
    goto :goto_1

    .line 51
    :cond_0
    add-int/lit8 v7, v7, 0x1

    .line 52
    .line 53
    goto :goto_0

    .line 54
    :cond_1
    move-object v2, v0

    .line 55
    :goto_1
    if-eqz v2, :cond_2

    .line 56
    .line 57
    :goto_2
    move-object v6, v2

    .line 58
    goto :goto_6

    .line 59
    :catch_0
    :cond_2
    iget-object v2, p0, Lu/c1;->m:Lv/b;

    .line 60
    .line 61
    invoke-virtual {v2}, Lv/b;->c()Lrn/i;

    .line 62
    .line 63
    .line 64
    move-result-object v2

    .line 65
    :try_start_1
    iget-object v2, v2, Lrn/i;->e:Ljava/lang/Object;

    .line 66
    .line 67
    check-cast v2, Lro/f;

    .line 68
    .line 69
    iget-object v2, v2, Lro/f;->e:Ljava/lang/Object;

    .line 70
    .line 71
    check-cast v2, Landroid/hardware/camera2/params/StreamConfigurationMap;

    .line 72
    .line 73
    const-class v3, Landroid/media/MediaRecorder;

    .line 74
    .line 75
    invoke-virtual {v2, v3}, Landroid/hardware/camera2/params/StreamConfigurationMap;->getOutputSizes(Ljava/lang/Class;)[Landroid/util/Size;

    .line 76
    .line 77
    .line 78
    move-result-object v2
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 79
    goto :goto_3

    .line 80
    :catchall_0
    move-object v2, v0

    .line 81
    :goto_3
    if-nez v2, :cond_3

    .line 82
    .line 83
    goto :goto_5

    .line 84
    :cond_3
    new-instance v3, Li0/c;

    .line 85
    .line 86
    const/4 v5, 0x1

    .line 87
    invoke-direct {v3, v5}, Li0/c;-><init>(Z)V

    .line 88
    .line 89
    .line 90
    invoke-static {v2, v3}, Ljava/util/Arrays;->sort([Ljava/lang/Object;Ljava/util/Comparator;)V

    .line 91
    .line 92
    .line 93
    array-length v3, v2

    .line 94
    :goto_4
    if-ge v1, v3, :cond_5

    .line 95
    .line 96
    aget-object v5, v2, v1

    .line 97
    .line 98
    invoke-virtual {v5}, Landroid/util/Size;->getWidth()I

    .line 99
    .line 100
    .line 101
    move-result v6

    .line 102
    sget-object v7, Lo0/a;->e:Landroid/util/Size;

    .line 103
    .line 104
    invoke-virtual {v7}, Landroid/util/Size;->getWidth()I

    .line 105
    .line 106
    .line 107
    move-result v8

    .line 108
    if-gt v6, v8, :cond_4

    .line 109
    .line 110
    invoke-virtual {v5}, Landroid/util/Size;->getHeight()I

    .line 111
    .line 112
    .line 113
    move-result v6

    .line 114
    invoke-virtual {v7}, Landroid/util/Size;->getHeight()I

    .line 115
    .line 116
    .line 117
    move-result v7

    .line 118
    if-gt v6, v7, :cond_4

    .line 119
    .line 120
    move-object v0, v5

    .line 121
    goto :goto_5

    .line 122
    :cond_4
    add-int/lit8 v1, v1, 0x1

    .line 123
    .line 124
    goto :goto_4

    .line 125
    :cond_5
    :goto_5
    if-eqz v0, :cond_6

    .line 126
    .line 127
    move-object v6, v0

    .line 128
    goto :goto_6

    .line 129
    :cond_6
    sget-object v2, Lo0/a;->c:Landroid/util/Size;

    .line 130
    .line 131
    goto :goto_2

    .line 132
    :goto_6
    sget-object v2, Lo0/a;->b:Landroid/util/Size;

    .line 133
    .line 134
    new-instance v3, Ljava/util/HashMap;

    .line 135
    .line 136
    invoke-direct {v3}, Ljava/util/HashMap;-><init>()V

    .line 137
    .line 138
    .line 139
    new-instance v5, Ljava/util/HashMap;

    .line 140
    .line 141
    invoke-direct {v5}, Ljava/util/HashMap;-><init>()V

    .line 142
    .line 143
    .line 144
    new-instance v7, Ljava/util/HashMap;

    .line 145
    .line 146
    invoke-direct {v7}, Ljava/util/HashMap;-><init>()V

    .line 147
    .line 148
    .line 149
    new-instance v8, Ljava/util/HashMap;

    .line 150
    .line 151
    invoke-direct {v8}, Ljava/util/HashMap;-><init>()V

    .line 152
    .line 153
    .line 154
    new-instance v9, Ljava/util/HashMap;

    .line 155
    .line 156
    invoke-direct {v9}, Ljava/util/HashMap;-><init>()V

    .line 157
    .line 158
    .line 159
    new-instance v10, Ljava/util/HashMap;

    .line 160
    .line 161
    invoke-direct {v10}, Ljava/util/HashMap;-><init>()V

    .line 162
    .line 163
    .line 164
    new-instance v1, Lh0/l;

    .line 165
    .line 166
    invoke-direct/range {v1 .. v10}, Lh0/l;-><init>(Landroid/util/Size;Ljava/util/HashMap;Landroid/util/Size;Ljava/util/HashMap;Landroid/util/Size;Ljava/util/HashMap;Ljava/util/HashMap;Ljava/util/HashMap;Ljava/util/HashMap;)V

    .line 167
    .line 168
    .line 169
    iput-object v1, p0, Lu/c1;->w:Lh0/l;

    .line 170
    .line 171
    return-void

    .line 172
    nop

    .line 173
    :array_0
    .array-data 4
        0x1
        0xd
        0xa
        0x8
        0xc
        0x6
        0x5
        0x4
    .end array-data
.end method

.method public final e(ILandroid/util/Size;Z)I
    .locals 5

    .line 1
    const/4 v0, 0x0

    .line 2
    if-eqz p3, :cond_1

    .line 3
    .line 4
    const/16 v1, 0x22

    .line 5
    .line 6
    if-ne p1, v1, :cond_0

    .line 7
    .line 8
    goto :goto_0

    .line 9
    :cond_0
    move v1, v0

    .line 10
    goto :goto_1

    .line 11
    :cond_1
    :goto_0
    const/4 v1, 0x1

    .line 12
    :goto_1
    const/4 v2, 0x0

    .line 13
    invoke-static {v2, v1}, Ljp/ed;->f(Ljava/lang/String;Z)V

    .line 14
    .line 15
    .line 16
    if-eqz p3, :cond_7

    .line 17
    .line 18
    iget-object p0, p0, Lu/c1;->C:Lu/t0;

    .line 19
    .line 20
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 21
    .line 22
    .line 23
    const-string p1, "size"

    .line 24
    .line 25
    invoke-static {p2, p1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 26
    .line 27
    .line 28
    invoke-virtual {p0, p2}, Lu/t0;->c(Landroid/util/Size;)Ljava/util/List;

    .line 29
    .line 30
    .line 31
    move-result-object p0

    .line 32
    move-object p1, p0

    .line 33
    check-cast p1, Ljava/util/Collection;

    .line 34
    .line 35
    invoke-interface {p1}, Ljava/util/Collection;->isEmpty()Z

    .line 36
    .line 37
    .line 38
    move-result p1

    .line 39
    if-nez p1, :cond_2

    .line 40
    .line 41
    move-object v2, p0

    .line 42
    :cond_2
    if-nez v2, :cond_3

    .line 43
    .line 44
    new-instance p0, Ljava/lang/StringBuilder;

    .line 45
    .line 46
    const-string p1, "No supported high speed  fps for "

    .line 47
    .line 48
    invoke-direct {p0, p1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 49
    .line 50
    .line 51
    invoke-virtual {p0, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 52
    .line 53
    .line 54
    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 55
    .line 56
    .line 57
    move-result-object p0

    .line 58
    const-string p1, "HighSpeedResolver"

    .line 59
    .line 60
    invoke-static {p1, p0}, Ljp/v1;->k(Ljava/lang/String;Ljava/lang/String;)V

    .line 61
    .line 62
    .line 63
    return v0

    .line 64
    :cond_3
    check-cast v2, Ljava/lang/Iterable;

    .line 65
    .line 66
    invoke-interface {v2}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 67
    .line 68
    .line 69
    move-result-object p0

    .line 70
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 71
    .line 72
    .line 73
    move-result p1

    .line 74
    if-eqz p1, :cond_6

    .line 75
    .line 76
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 77
    .line 78
    .line 79
    move-result-object p1

    .line 80
    check-cast p1, Landroid/util/Range;

    .line 81
    .line 82
    invoke-virtual {p1}, Landroid/util/Range;->getUpper()Ljava/lang/Comparable;

    .line 83
    .line 84
    .line 85
    move-result-object p1

    .line 86
    check-cast p1, Ljava/lang/Integer;

    .line 87
    .line 88
    :cond_4
    :goto_2
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 89
    .line 90
    .line 91
    move-result p2

    .line 92
    if-eqz p2, :cond_5

    .line 93
    .line 94
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 95
    .line 96
    .line 97
    move-result-object p2

    .line 98
    check-cast p2, Landroid/util/Range;

    .line 99
    .line 100
    invoke-virtual {p2}, Landroid/util/Range;->getUpper()Ljava/lang/Comparable;

    .line 101
    .line 102
    .line 103
    move-result-object p2

    .line 104
    check-cast p2, Ljava/lang/Integer;

    .line 105
    .line 106
    invoke-virtual {p1, p2}, Ljava/lang/Integer;->compareTo(Ljava/lang/Object;)I

    .line 107
    .line 108
    .line 109
    move-result p3

    .line 110
    if-gez p3, :cond_4

    .line 111
    .line 112
    move-object p1, p2

    .line 113
    goto :goto_2

    .line 114
    :cond_5
    const-string p0, "maxOf(...)"

    .line 115
    .line 116
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 117
    .line 118
    .line 119
    invoke-virtual {p1}, Ljava/lang/Number;->intValue()I

    .line 120
    .line 121
    .line 122
    move-result p0

    .line 123
    return p0

    .line 124
    :cond_6
    new-instance p0, Ljava/util/NoSuchElementException;

    .line 125
    .line 126
    invoke-direct {p0}, Ljava/util/NoSuchElementException;-><init>()V

    .line 127
    .line 128
    .line 129
    throw p0

    .line 130
    :cond_7
    iget-object p3, p0, Lu/c1;->m:Lv/b;

    .line 131
    .line 132
    invoke-virtual {p3}, Lv/b;->c()Lrn/i;

    .line 133
    .line 134
    .line 135
    move-result-object p3

    .line 136
    invoke-static {p3}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    .line 137
    .line 138
    .line 139
    const-wide/16 v1, 0x0

    .line 140
    .line 141
    :try_start_0
    iget-object p3, p3, Lrn/i;->e:Ljava/lang/Object;

    .line 142
    .line 143
    check-cast p3, Lro/f;

    .line 144
    .line 145
    iget-object p3, p3, Lro/f;->e:Ljava/lang/Object;

    .line 146
    .line 147
    check-cast p3, Landroid/hardware/camera2/params/StreamConfigurationMap;

    .line 148
    .line 149
    invoke-virtual {p3, p1, p2}, Landroid/hardware/camera2/params/StreamConfigurationMap;->getOutputMinFrameDuration(ILandroid/util/Size;)J

    .line 150
    .line 151
    .line 152
    move-result-wide v3
    :try_end_0
    .catch Ljava/lang/RuntimeException; {:try_start_0 .. :try_end_0} :catch_0

    .line 153
    goto :goto_3

    .line 154
    :catch_0
    move-exception p3

    .line 155
    new-instance v3, Ljava/lang/StringBuilder;

    .line 156
    .line 157
    const-string v4, "Failed to get min frame duration for format = "

    .line 158
    .line 159
    invoke-direct {v3, v4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 160
    .line 161
    .line 162
    invoke-virtual {v3, p1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 163
    .line 164
    .line 165
    const-string v4, " and size = "

    .line 166
    .line 167
    invoke-virtual {v3, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 168
    .line 169
    .line 170
    invoke-virtual {v3, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 171
    .line 172
    .line 173
    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 174
    .line 175
    .line 176
    move-result-object v3

    .line 177
    const-string v4, "StreamConfigurationMapCompat"

    .line 178
    .line 179
    invoke-static {v4, v3, p3}, Ljp/v1;->l(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 180
    .line 181
    .line 182
    move-wide v3, v1

    .line 183
    :goto_3
    cmp-long p3, v3, v1

    .line 184
    .line 185
    if-gtz p3, :cond_9

    .line 186
    .line 187
    iget-boolean p0, p0, Lu/c1;->u:Z

    .line 188
    .line 189
    if-eqz p0, :cond_8

    .line 190
    .line 191
    new-instance p0, Ljava/lang/StringBuilder;

    .line 192
    .line 193
    const-string p3, "minFrameDuration: "

    .line 194
    .line 195
    invoke-direct {p0, p3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 196
    .line 197
    .line 198
    invoke-virtual {p0, v3, v4}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    .line 199
    .line 200
    .line 201
    const-string p3, " is invalid for imageFormat = "

    .line 202
    .line 203
    invoke-virtual {p0, p3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 204
    .line 205
    .line 206
    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 207
    .line 208
    .line 209
    const-string p1, ", size = "

    .line 210
    .line 211
    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 212
    .line 213
    .line 214
    invoke-virtual {p0, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 215
    .line 216
    .line 217
    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 218
    .line 219
    .line 220
    move-result-object p0

    .line 221
    const-string p1, "SupportedSurfaceCombination"

    .line 222
    .line 223
    invoke-static {p1, p0}, Ljp/v1;->k(Ljava/lang/String;Ljava/lang/String;)V

    .line 224
    .line 225
    .line 226
    goto :goto_4

    .line 227
    :cond_8
    const v0, 0x7fffffff

    .line 228
    .line 229
    .line 230
    goto :goto_4

    .line 231
    :cond_9
    const-wide p0, 0x41cdcd6500000000L    # 1.0E9

    .line 232
    .line 233
    .line 234
    .line 235
    .line 236
    long-to-double p2, v3

    .line 237
    div-double/2addr p0, p2

    .line 238
    double-to-int v0, p0

    .line 239
    :goto_4
    return v0
.end method

.method public final g(Lu/d;Ljava/util/List;Ljava/util/HashMap;Ljava/util/HashMap;)Ljava/util/List;
    .locals 10

    .line 1
    sget-object v0, Lu/b1;->a:Lh0/g;

    .line 2
    .line 3
    iget v0, p1, Lu/d;->a:I

    .line 4
    .line 5
    if-nez v0, :cond_7

    .line 6
    .line 7
    iget v0, p1, Lu/d;->c:I

    .line 8
    .line 9
    const/16 v1, 0x8

    .line 10
    .line 11
    if-ne v0, v1, :cond_7

    .line 12
    .line 13
    iget-boolean p1, p1, Lu/d;->f:Z

    .line 14
    .line 15
    if-nez p1, :cond_7

    .line 16
    .line 17
    iget-object p1, p0, Lu/c1;->j:Ljava/util/ArrayList;

    .line 18
    .line 19
    invoke-virtual {p1}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 20
    .line 21
    .line 22
    move-result-object p1

    .line 23
    :cond_0
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 24
    .line 25
    .line 26
    move-result v0

    .line 27
    if-eqz v0, :cond_7

    .line 28
    .line 29
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 30
    .line 31
    .line 32
    move-result-object v0

    .line 33
    check-cast v0, Lh0/d2;

    .line 34
    .line 35
    invoke-virtual {v0, p2}, Lh0/d2;->c(Ljava/util/List;)Ljava/util/List;

    .line 36
    .line 37
    .line 38
    move-result-object v0

    .line 39
    if-eqz v0, :cond_0

    .line 40
    .line 41
    sget-object v1, Lu/b1;->a:Lh0/g;

    .line 42
    .line 43
    move-object v1, v0

    .line 44
    check-cast v1, Ljava/util/Collection;

    .line 45
    .line 46
    invoke-interface {v1}, Ljava/util/Collection;->size()I

    .line 47
    .line 48
    .line 49
    move-result v1

    .line 50
    const/4 v2, 0x0

    .line 51
    move v3, v2

    .line 52
    :goto_0
    const/4 v4, 0x1

    .line 53
    if-ge v3, v1, :cond_6

    .line 54
    .line 55
    invoke-interface {v0, v3}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 56
    .line 57
    .line 58
    move-result-object v5

    .line 59
    check-cast v5, Lh0/h2;

    .line 60
    .line 61
    iget-object v5, v5, Lh0/h2;->c:Lh0/c2;

    .line 62
    .line 63
    iget-wide v5, v5, Lh0/c2;->d:J

    .line 64
    .line 65
    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 66
    .line 67
    .line 68
    move-result-object v7

    .line 69
    invoke-virtual {p3, v7}, Ljava/util/HashMap;->containsKey(Ljava/lang/Object;)Z

    .line 70
    .line 71
    .line 72
    move-result v7

    .line 73
    sget-object v8, Lh0/q2;->h:Lh0/q2;

    .line 74
    .line 75
    if-eqz v7, :cond_2

    .line 76
    .line 77
    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 78
    .line 79
    .line 80
    move-result-object v7

    .line 81
    invoke-virtual {p3, v7}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 82
    .line 83
    .line 84
    move-result-object v7

    .line 85
    check-cast v7, Lh0/e;

    .line 86
    .line 87
    invoke-static {v7}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 88
    .line 89
    .line 90
    iget-object v7, v7, Lh0/e;->e:Ljava/util/List;

    .line 91
    .line 92
    invoke-interface {v7}, Ljava/util/List;->size()I

    .line 93
    .line 94
    .line 95
    move-result v9

    .line 96
    if-ne v9, v4, :cond_1

    .line 97
    .line 98
    invoke-interface {v7, v2}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 99
    .line 100
    .line 101
    move-result-object v4

    .line 102
    move-object v8, v4

    .line 103
    check-cast v8, Lh0/q2;

    .line 104
    .line 105
    :cond_1
    invoke-static {v8}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 106
    .line 107
    .line 108
    invoke-static {v8, v5, v6, v7}, Lu/b1;->b(Lh0/q2;JLjava/util/List;)Z

    .line 109
    .line 110
    .line 111
    move-result v4

    .line 112
    if-nez v4, :cond_4

    .line 113
    .line 114
    goto :goto_2

    .line 115
    :cond_2
    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 116
    .line 117
    .line 118
    move-result-object v4

    .line 119
    invoke-virtual {p4, v4}, Ljava/util/HashMap;->containsKey(Ljava/lang/Object;)Z

    .line 120
    .line 121
    .line 122
    move-result v4

    .line 123
    if-eqz v4, :cond_5

    .line 124
    .line 125
    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 126
    .line 127
    .line 128
    move-result-object v4

    .line 129
    invoke-virtual {p4, v4}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 130
    .line 131
    .line 132
    move-result-object v4

    .line 133
    invoke-static {v4}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 134
    .line 135
    .line 136
    check-cast v4, Lh0/o2;

    .line 137
    .line 138
    invoke-interface {v4}, Lh0/o2;->J()Lh0/q2;

    .line 139
    .line 140
    .line 141
    move-result-object v7

    .line 142
    const-string v9, "getCaptureType(...)"

    .line 143
    .line 144
    invoke-static {v7, v9}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 145
    .line 146
    .line 147
    invoke-interface {v4}, Lh0/o2;->J()Lh0/q2;

    .line 148
    .line 149
    .line 150
    move-result-object v9

    .line 151
    if-ne v9, v8, :cond_3

    .line 152
    .line 153
    check-cast v4, Lt0/f;

    .line 154
    .line 155
    sget-object v8, Lt0/f;->e:Lh0/g;

    .line 156
    .line 157
    invoke-interface {v4, v8}, Lh0/t1;->f(Lh0/g;)Ljava/lang/Object;

    .line 158
    .line 159
    .line 160
    move-result-object v4

    .line 161
    check-cast v4, Ljava/util/List;

    .line 162
    .line 163
    const-string v8, "getCaptureTypes(...)"

    .line 164
    .line 165
    invoke-static {v4, v8}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 166
    .line 167
    .line 168
    goto :goto_1

    .line 169
    :cond_3
    sget-object v4, Lmx0/s;->d:Lmx0/s;

    .line 170
    .line 171
    :goto_1
    invoke-static {v7, v5, v6, v4}, Lu/b1;->b(Lh0/q2;JLjava/util/List;)Z

    .line 172
    .line 173
    .line 174
    move-result v4

    .line 175
    if-nez v4, :cond_4

    .line 176
    .line 177
    goto :goto_2

    .line 178
    :cond_4
    add-int/lit8 v3, v3, 0x1

    .line 179
    .line 180
    goto/16 :goto_0

    .line 181
    .line 182
    :cond_5
    new-instance p0, Ljava/lang/AssertionError;

    .line 183
    .line 184
    const-string p1, "SurfaceConfig does not map to any use case"

    .line 185
    .line 186
    invoke-direct {p0, p1}, Ljava/lang/AssertionError;-><init>(Ljava/lang/Object;)V

    .line 187
    .line 188
    .line 189
    throw p0

    .line 190
    :cond_6
    move v2, v4

    .line 191
    :goto_2
    new-instance v1, Lt61/g;

    .line 192
    .line 193
    const/16 v3, 0x13

    .line 194
    .line 195
    invoke-direct {v1, v3, p0, v0}, Lt61/g;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 196
    .line 197
    .line 198
    if-eqz v2, :cond_0

    .line 199
    .line 200
    invoke-virtual {v1}, Lt61/g;->invoke()Ljava/lang/Object;

    .line 201
    .line 202
    .line 203
    move-result-object v1

    .line 204
    check-cast v1, Ljava/lang/Boolean;

    .line 205
    .line 206
    invoke-virtual {v1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 207
    .line 208
    .line 209
    move-result v1

    .line 210
    if-eqz v1, :cond_0

    .line 211
    .line 212
    return-object v0

    .line 213
    :cond_7
    const/4 p0, 0x0

    .line 214
    return-object p0
.end method

.method public final j(ILjava/util/ArrayList;Ljava/util/HashMap;ZZZ)Lh0/i2;
    .locals 29

    .line 1
    move-object/from16 v1, p0

    .line 2
    .line 3
    sget-object v0, Lb0/y;->c:Lb0/y;

    .line 4
    .line 5
    sget-object v12, Lb0/y;->e:Lb0/y;

    .line 6
    .line 7
    const/4 v2, 0x0

    .line 8
    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 9
    .line 10
    .line 11
    move-result-object v3

    .line 12
    iget-object v4, v1, Lu/c1;->y:Lu/q0;

    .line 13
    .line 14
    invoke-virtual {v4}, Lu/q0;->a()Landroid/util/Size;

    .line 15
    .line 16
    .line 17
    move-result-object v5

    .line 18
    iput-object v5, v4, Lu/q0;->b:Landroid/util/Size;

    .line 19
    .line 20
    iget-object v4, v1, Lu/c1;->w:Lh0/l;

    .line 21
    .line 22
    if-nez v4, :cond_0

    .line 23
    .line 24
    invoke-virtual {v1}, Lu/c1;->c()V

    .line 25
    .line 26
    .line 27
    goto :goto_0

    .line 28
    :cond_0
    iget-object v4, v1, Lu/c1;->y:Lu/q0;

    .line 29
    .line 30
    invoke-virtual {v4}, Lu/q0;->e()Landroid/util/Size;

    .line 31
    .line 32
    .line 33
    move-result-object v16

    .line 34
    iget-object v4, v1, Lu/c1;->w:Lh0/l;

    .line 35
    .line 36
    iget-object v14, v4, Lh0/l;->a:Landroid/util/Size;

    .line 37
    .line 38
    iget-object v15, v4, Lh0/l;->b:Ljava/util/HashMap;

    .line 39
    .line 40
    iget-object v5, v4, Lh0/l;->d:Ljava/util/HashMap;

    .line 41
    .line 42
    iget-object v6, v4, Lh0/l;->e:Landroid/util/Size;

    .line 43
    .line 44
    iget-object v7, v4, Lh0/l;->f:Ljava/util/HashMap;

    .line 45
    .line 46
    iget-object v8, v4, Lh0/l;->g:Ljava/util/HashMap;

    .line 47
    .line 48
    iget-object v9, v4, Lh0/l;->h:Ljava/util/HashMap;

    .line 49
    .line 50
    iget-object v4, v4, Lh0/l;->i:Ljava/util/HashMap;

    .line 51
    .line 52
    new-instance v13, Lh0/l;

    .line 53
    .line 54
    move-object/from16 v22, v4

    .line 55
    .line 56
    move-object/from16 v17, v5

    .line 57
    .line 58
    move-object/from16 v18, v6

    .line 59
    .line 60
    move-object/from16 v19, v7

    .line 61
    .line 62
    move-object/from16 v20, v8

    .line 63
    .line 64
    move-object/from16 v21, v9

    .line 65
    .line 66
    invoke-direct/range {v13 .. v22}, Lh0/l;-><init>(Landroid/util/Size;Ljava/util/HashMap;Landroid/util/Size;Ljava/util/HashMap;Landroid/util/Size;Ljava/util/HashMap;Ljava/util/HashMap;Ljava/util/HashMap;Ljava/util/HashMap;)V

    .line 67
    .line 68
    .line 69
    iput-object v13, v1, Lu/c1;->w:Lh0/l;

    .line 70
    .line 71
    :goto_0
    invoke-interface/range {p3 .. p3}, Ljava/util/Map;->keySet()Ljava/util/Set;

    .line 72
    .line 73
    .line 74
    move-result-object v4

    .line 75
    sget-object v5, Lu/t0;->e:Landroid/util/Range;

    .line 76
    .line 77
    const-string v5, "newUseCaseConfigs"

    .line 78
    .line 79
    invoke-static {v4, v5}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 80
    .line 81
    .line 82
    new-instance v5, Ljava/util/ArrayList;

    .line 83
    .line 84
    const/16 v6, 0xa

    .line 85
    .line 86
    move-object/from16 v13, p2

    .line 87
    .line 88
    invoke-static {v13, v6}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 89
    .line 90
    .line 91
    move-result v7

    .line 92
    invoke-direct {v5, v7}, Ljava/util/ArrayList;-><init>(I)V

    .line 93
    .line 94
    .line 95
    invoke-interface {v13}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 96
    .line 97
    .line 98
    move-result-object v7

    .line 99
    :goto_1
    invoke-interface {v7}, Ljava/util/Iterator;->hasNext()Z

    .line 100
    .line 101
    .line 102
    move-result v8

    .line 103
    if-eqz v8, :cond_1

    .line 104
    .line 105
    invoke-interface {v7}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 106
    .line 107
    .line 108
    move-result-object v8

    .line 109
    check-cast v8, Lh0/e;

    .line 110
    .line 111
    iget v8, v8, Lh0/e;->g:I

    .line 112
    .line 113
    invoke-static {v8}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 114
    .line 115
    .line 116
    move-result-object v8

    .line 117
    invoke-virtual {v5, v8}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 118
    .line 119
    .line 120
    goto :goto_1

    .line 121
    :cond_1
    check-cast v4, Ljava/lang/Iterable;

    .line 122
    .line 123
    new-instance v7, Ljava/util/ArrayList;

    .line 124
    .line 125
    invoke-static {v4, v6}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 126
    .line 127
    .line 128
    move-result v8

    .line 129
    invoke-direct {v7, v8}, Ljava/util/ArrayList;-><init>(I)V

    .line 130
    .line 131
    .line 132
    invoke-interface {v4}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 133
    .line 134
    .line 135
    move-result-object v4

    .line 136
    :goto_2
    invoke-interface {v4}, Ljava/util/Iterator;->hasNext()Z

    .line 137
    .line 138
    .line 139
    move-result v8

    .line 140
    if-eqz v8, :cond_2

    .line 141
    .line 142
    invoke-interface {v4}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 143
    .line 144
    .line 145
    move-result-object v8

    .line 146
    check-cast v8, Lh0/o2;

    .line 147
    .line 148
    sget-object v9, Lh0/o2;->U0:Lh0/g;

    .line 149
    .line 150
    invoke-interface {v8, v9, v3}, Lh0/t1;->b(Lh0/g;Ljava/lang/Object;)Ljava/lang/Object;

    .line 151
    .line 152
    .line 153
    move-result-object v8

    .line 154
    check-cast v8, Ljava/lang/Integer;

    .line 155
    .line 156
    invoke-virtual {v8}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 157
    .line 158
    .line 159
    invoke-virtual {v7, v8}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 160
    .line 161
    .line 162
    goto :goto_2

    .line 163
    :cond_2
    invoke-static {v7, v5}, Lmx0/q;->a0(Ljava/lang/Iterable;Ljava/util/Collection;)Ljava/util/ArrayList;

    .line 164
    .line 165
    .line 166
    move-result-object v4

    .line 167
    invoke-virtual {v4}, Ljava/util/ArrayList;->isEmpty()Z

    .line 168
    .line 169
    .line 170
    move-result v5

    .line 171
    const/4 v14, 0x1

    .line 172
    if-eqz v5, :cond_4

    .line 173
    .line 174
    :cond_3
    move v7, v2

    .line 175
    goto :goto_3

    .line 176
    :cond_4
    invoke-virtual {v4}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 177
    .line 178
    .line 179
    move-result-object v5

    .line 180
    :cond_5
    invoke-interface {v5}, Ljava/util/Iterator;->hasNext()Z

    .line 181
    .line 182
    .line 183
    move-result v7

    .line 184
    if-eqz v7, :cond_3

    .line 185
    .line 186
    invoke-interface {v5}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 187
    .line 188
    .line 189
    move-result-object v7

    .line 190
    check-cast v7, Ljava/lang/Number;

    .line 191
    .line 192
    invoke-virtual {v7}, Ljava/lang/Number;->intValue()I

    .line 193
    .line 194
    .line 195
    move-result v7

    .line 196
    if-ne v7, v14, :cond_5

    .line 197
    .line 198
    move v7, v14

    .line 199
    :goto_3
    if-eqz v7, :cond_8

    .line 200
    .line 201
    invoke-virtual {v4}, Ljava/util/ArrayList;->isEmpty()Z

    .line 202
    .line 203
    .line 204
    move-result v5

    .line 205
    if-eqz v5, :cond_6

    .line 206
    .line 207
    goto :goto_5

    .line 208
    :cond_6
    invoke-virtual {v4}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 209
    .line 210
    .line 211
    move-result-object v4

    .line 212
    :goto_4
    invoke-interface {v4}, Ljava/util/Iterator;->hasNext()Z

    .line 213
    .line 214
    .line 215
    move-result v5

    .line 216
    if-eqz v5, :cond_8

    .line 217
    .line 218
    invoke-interface {v4}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 219
    .line 220
    .line 221
    move-result-object v5

    .line 222
    check-cast v5, Ljava/lang/Number;

    .line 223
    .line 224
    invoke-virtual {v5}, Ljava/lang/Number;->intValue()I

    .line 225
    .line 226
    .line 227
    move-result v5

    .line 228
    if-ne v5, v14, :cond_7

    .line 229
    .line 230
    goto :goto_4

    .line 231
    :cond_7
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 232
    .line 233
    const-string v1, "All sessionTypes should be high-speed when any of them is high-speed"

    .line 234
    .line 235
    invoke-direct {v0, v1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 236
    .line 237
    .line 238
    throw v0

    .line 239
    :cond_8
    :goto_5
    if-eqz v7, :cond_e

    .line 240
    .line 241
    iget-object v4, v1, Lu/c1;->C:Lu/t0;

    .line 242
    .line 243
    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 244
    .line 245
    .line 246
    invoke-interface/range {p3 .. p3}, Ljava/util/Map;->values()Ljava/util/Collection;

    .line 247
    .line 248
    .line 249
    move-result-object v5

    .line 250
    check-cast v5, Ljava/lang/Iterable;

    .line 251
    .line 252
    invoke-static {v5}, Lmx0/q;->x0(Ljava/lang/Iterable;)Ljava/util/List;

    .line 253
    .line 254
    .line 255
    move-result-object v5

    .line 256
    invoke-static {v5}, Lu/t0;->a(Ljava/util/List;)Ljava/util/List;

    .line 257
    .line 258
    .line 259
    move-result-object v5

    .line 260
    check-cast v5, Ljava/lang/Iterable;

    .line 261
    .line 262
    new-instance v8, Ljava/util/ArrayList;

    .line 263
    .line 264
    invoke-direct {v8}, Ljava/util/ArrayList;-><init>()V

    .line 265
    .line 266
    .line 267
    invoke-interface {v5}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 268
    .line 269
    .line 270
    move-result-object v5

    .line 271
    :cond_9
    :goto_6
    invoke-interface {v5}, Ljava/util/Iterator;->hasNext()Z

    .line 272
    .line 273
    .line 274
    move-result v9

    .line 275
    if-eqz v9, :cond_a

    .line 276
    .line 277
    invoke-interface {v5}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 278
    .line 279
    .line 280
    move-result-object v9

    .line 281
    move-object v10, v9

    .line 282
    check-cast v10, Landroid/util/Size;

    .line 283
    .line 284
    iget-object v11, v4, Lu/t0;->d:Llx0/q;

    .line 285
    .line 286
    invoke-virtual {v11}, Llx0/q;->getValue()Ljava/lang/Object;

    .line 287
    .line 288
    .line 289
    move-result-object v11

    .line 290
    check-cast v11, Ljava/util/List;

    .line 291
    .line 292
    invoke-interface {v11, v10}, Ljava/util/List;->contains(Ljava/lang/Object;)Z

    .line 293
    .line 294
    .line 295
    move-result v10

    .line 296
    if-eqz v10, :cond_9

    .line 297
    .line 298
    invoke-virtual {v8, v9}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 299
    .line 300
    .line 301
    goto :goto_6

    .line 302
    :cond_a
    new-instance v4, Ljava/util/LinkedHashMap;

    .line 303
    .line 304
    invoke-interface/range {p3 .. p3}, Ljava/util/Map;->size()I

    .line 305
    .line 306
    .line 307
    move-result v5

    .line 308
    invoke-static {v5}, Lmx0/x;->k(I)I

    .line 309
    .line 310
    .line 311
    move-result v5

    .line 312
    invoke-direct {v4, v5}, Ljava/util/LinkedHashMap;-><init>(I)V

    .line 313
    .line 314
    .line 315
    invoke-interface/range {p3 .. p3}, Ljava/util/Map;->entrySet()Ljava/util/Set;

    .line 316
    .line 317
    .line 318
    move-result-object v5

    .line 319
    check-cast v5, Ljava/lang/Iterable;

    .line 320
    .line 321
    invoke-interface {v5}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 322
    .line 323
    .line 324
    move-result-object v5

    .line 325
    :goto_7
    invoke-interface {v5}, Ljava/util/Iterator;->hasNext()Z

    .line 326
    .line 327
    .line 328
    move-result v9

    .line 329
    if-eqz v9, :cond_d

    .line 330
    .line 331
    invoke-interface {v5}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 332
    .line 333
    .line 334
    move-result-object v9

    .line 335
    check-cast v9, Ljava/util/Map$Entry;

    .line 336
    .line 337
    invoke-interface {v9}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 338
    .line 339
    .line 340
    move-result-object v10

    .line 341
    invoke-interface {v9}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 342
    .line 343
    .line 344
    move-result-object v9

    .line 345
    check-cast v9, Ljava/util/List;

    .line 346
    .line 347
    check-cast v9, Ljava/lang/Iterable;

    .line 348
    .line 349
    new-instance v11, Ljava/util/ArrayList;

    .line 350
    .line 351
    invoke-direct {v11}, Ljava/util/ArrayList;-><init>()V

    .line 352
    .line 353
    .line 354
    invoke-interface {v9}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 355
    .line 356
    .line 357
    move-result-object v9

    .line 358
    :goto_8
    invoke-interface {v9}, Ljava/util/Iterator;->hasNext()Z

    .line 359
    .line 360
    .line 361
    move-result v15

    .line 362
    if-eqz v15, :cond_c

    .line 363
    .line 364
    invoke-interface {v9}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 365
    .line 366
    .line 367
    move-result-object v15

    .line 368
    move-object v2, v15

    .line 369
    check-cast v2, Landroid/util/Size;

    .line 370
    .line 371
    invoke-virtual {v8, v2}, Ljava/util/ArrayList;->contains(Ljava/lang/Object;)Z

    .line 372
    .line 373
    .line 374
    move-result v2

    .line 375
    if-eqz v2, :cond_b

    .line 376
    .line 377
    invoke-virtual {v11, v15}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 378
    .line 379
    .line 380
    :cond_b
    const/4 v2, 0x0

    .line 381
    goto :goto_8

    .line 382
    :cond_c
    invoke-interface {v4, v10, v11}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 383
    .line 384
    .line 385
    const/4 v2, 0x0

    .line 386
    goto :goto_7

    .line 387
    :cond_d
    move-object v15, v4

    .line 388
    goto :goto_9

    .line 389
    :cond_e
    move-object/from16 v15, p3

    .line 390
    .line 391
    :goto_9
    new-instance v2, Ljava/util/ArrayList;

    .line 392
    .line 393
    invoke-interface {v15}, Ljava/util/Map;->keySet()Ljava/util/Set;

    .line 394
    .line 395
    .line 396
    move-result-object v4

    .line 397
    invoke-direct {v2, v4}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    .line 398
    .line 399
    .line 400
    new-instance v4, Ljava/util/ArrayList;

    .line 401
    .line 402
    invoke-direct {v4}, Ljava/util/ArrayList;-><init>()V

    .line 403
    .line 404
    .line 405
    new-instance v5, Ljava/util/ArrayList;

    .line 406
    .line 407
    invoke-direct {v5}, Ljava/util/ArrayList;-><init>()V

    .line 408
    .line 409
    .line 410
    invoke-virtual {v2}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 411
    .line 412
    .line 413
    move-result-object v8

    .line 414
    :cond_f
    :goto_a
    invoke-interface {v8}, Ljava/util/Iterator;->hasNext()Z

    .line 415
    .line 416
    .line 417
    move-result v9

    .line 418
    if-eqz v9, :cond_10

    .line 419
    .line 420
    invoke-interface {v8}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 421
    .line 422
    .line 423
    move-result-object v9

    .line 424
    check-cast v9, Lh0/o2;

    .line 425
    .line 426
    sget-object v10, Lh0/o2;->T0:Lh0/g;

    .line 427
    .line 428
    invoke-interface {v9, v10, v3}, Lh0/t1;->b(Lh0/g;Ljava/lang/Object;)Ljava/lang/Object;

    .line 429
    .line 430
    .line 431
    move-result-object v9

    .line 432
    check-cast v9, Ljava/lang/Integer;

    .line 433
    .line 434
    invoke-virtual {v9}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 435
    .line 436
    .line 437
    invoke-virtual {v5, v9}, Ljava/util/ArrayList;->contains(Ljava/lang/Object;)Z

    .line 438
    .line 439
    .line 440
    move-result v10

    .line 441
    if-nez v10, :cond_f

    .line 442
    .line 443
    invoke-virtual {v5, v9}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 444
    .line 445
    .line 446
    goto :goto_a

    .line 447
    :cond_10
    invoke-static {v5}, Ljava/util/Collections;->sort(Ljava/util/List;)V

    .line 448
    .line 449
    .line 450
    invoke-static {v5}, Ljava/util/Collections;->reverse(Ljava/util/List;)V

    .line 451
    .line 452
    .line 453
    invoke-virtual {v5}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 454
    .line 455
    .line 456
    move-result-object v5

    .line 457
    :cond_11
    invoke-interface {v5}, Ljava/util/Iterator;->hasNext()Z

    .line 458
    .line 459
    .line 460
    move-result v8

    .line 461
    if-eqz v8, :cond_13

    .line 462
    .line 463
    invoke-interface {v5}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 464
    .line 465
    .line 466
    move-result-object v8

    .line 467
    check-cast v8, Ljava/lang/Integer;

    .line 468
    .line 469
    invoke-virtual {v8}, Ljava/lang/Integer;->intValue()I

    .line 470
    .line 471
    .line 472
    move-result v8

    .line 473
    invoke-virtual {v2}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 474
    .line 475
    .line 476
    move-result-object v9

    .line 477
    :cond_12
    :goto_b
    invoke-interface {v9}, Ljava/util/Iterator;->hasNext()Z

    .line 478
    .line 479
    .line 480
    move-result v10

    .line 481
    if-eqz v10, :cond_11

    .line 482
    .line 483
    invoke-interface {v9}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 484
    .line 485
    .line 486
    move-result-object v10

    .line 487
    check-cast v10, Lh0/o2;

    .line 488
    .line 489
    sget-object v11, Lh0/o2;->T0:Lh0/g;

    .line 490
    .line 491
    invoke-interface {v10, v11, v3}, Lh0/t1;->b(Lh0/g;Ljava/lang/Object;)Ljava/lang/Object;

    .line 492
    .line 493
    .line 494
    move-result-object v11

    .line 495
    check-cast v11, Ljava/lang/Integer;

    .line 496
    .line 497
    invoke-virtual {v11}, Ljava/lang/Integer;->intValue()I

    .line 498
    .line 499
    .line 500
    move-result v11

    .line 501
    if-ne v8, v11, :cond_12

    .line 502
    .line 503
    invoke-virtual {v2, v10}, Ljava/util/ArrayList;->indexOf(Ljava/lang/Object;)I

    .line 504
    .line 505
    .line 506
    move-result v10

    .line 507
    invoke-static {v10}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 508
    .line 509
    .line 510
    move-result-object v10

    .line 511
    invoke-virtual {v4, v10}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 512
    .line 513
    .line 514
    goto :goto_b

    .line 515
    :cond_13
    iget-object v3, v1, Lu/c1;->B:Lcom/google/android/gms/internal/measurement/i4;

    .line 516
    .line 517
    iget-object v5, v3, Lcom/google/android/gms/internal/measurement/i4;->g:Ljava/lang/Object;

    .line 518
    .line 519
    check-cast v5, Lpv/g;

    .line 520
    .line 521
    new-instance v8, Ljava/util/LinkedHashSet;

    .line 522
    .line 523
    invoke-direct {v8}, Ljava/util/LinkedHashSet;-><init>()V

    .line 524
    .line 525
    .line 526
    invoke-virtual {v13}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 527
    .line 528
    .line 529
    move-result-object v9

    .line 530
    :goto_c
    invoke-interface {v9}, Ljava/util/Iterator;->hasNext()Z

    .line 531
    .line 532
    .line 533
    move-result v10

    .line 534
    if-eqz v10, :cond_14

    .line 535
    .line 536
    invoke-interface {v9}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 537
    .line 538
    .line 539
    move-result-object v10

    .line 540
    check-cast v10, Lh0/e;

    .line 541
    .line 542
    iget-object v10, v10, Lh0/e;->d:Lb0/y;

    .line 543
    .line 544
    invoke-interface {v8, v10}, Ljava/util/Set;->add(Ljava/lang/Object;)Z

    .line 545
    .line 546
    .line 547
    goto :goto_c

    .line 548
    :cond_14
    iget-object v9, v5, Lpv/g;->e:Ljava/lang/Object;

    .line 549
    .line 550
    check-cast v9, Lw/b;

    .line 551
    .line 552
    invoke-interface {v9}, Lw/b;->d()Ljava/util/Set;

    .line 553
    .line 554
    .line 555
    move-result-object v9

    .line 556
    new-instance v10, Ljava/util/HashSet;

    .line 557
    .line 558
    invoke-direct {v10, v9}, Ljava/util/HashSet;-><init>(Ljava/util/Collection;)V

    .line 559
    .line 560
    .line 561
    invoke-interface {v8}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 562
    .line 563
    .line 564
    move-result-object v11

    .line 565
    :goto_d
    invoke-interface {v11}, Ljava/util/Iterator;->hasNext()Z

    .line 566
    .line 567
    .line 568
    move-result v17

    .line 569
    if-eqz v17, :cond_15

    .line 570
    .line 571
    invoke-interface {v11}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 572
    .line 573
    .line 574
    move-result-object v17

    .line 575
    move-object/from16 v6, v17

    .line 576
    .line 577
    check-cast v6, Lb0/y;

    .line 578
    .line 579
    invoke-static {v10, v6, v5}, Lcom/google/android/gms/internal/measurement/i4;->w(Ljava/util/HashSet;Lb0/y;Lpv/g;)V

    .line 580
    .line 581
    .line 582
    const/16 v6, 0xa

    .line 583
    .line 584
    goto :goto_d

    .line 585
    :cond_15
    new-instance v6, Ljava/util/ArrayList;

    .line 586
    .line 587
    invoke-direct {v6}, Ljava/util/ArrayList;-><init>()V

    .line 588
    .line 589
    .line 590
    new-instance v11, Ljava/util/ArrayList;

    .line 591
    .line 592
    invoke-direct {v11}, Ljava/util/ArrayList;-><init>()V

    .line 593
    .line 594
    .line 595
    new-instance v14, Ljava/util/ArrayList;

    .line 596
    .line 597
    invoke-direct {v14}, Ljava/util/ArrayList;-><init>()V

    .line 598
    .line 599
    .line 600
    invoke-virtual {v4}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 601
    .line 602
    .line 603
    move-result-object v19

    .line 604
    :goto_e
    invoke-interface/range {v19 .. v19}, Ljava/util/Iterator;->hasNext()Z

    .line 605
    .line 606
    .line 607
    move-result v20

    .line 608
    if-eqz v20, :cond_1a

    .line 609
    .line 610
    invoke-interface/range {v19 .. v19}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 611
    .line 612
    .line 613
    move-result-object v20

    .line 614
    check-cast v20, Ljava/lang/Integer;

    .line 615
    .line 616
    invoke-virtual/range {v20 .. v20}, Ljava/lang/Integer;->intValue()I

    .line 617
    .line 618
    .line 619
    move-result v13

    .line 620
    invoke-virtual {v2, v13}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 621
    .line 622
    .line 623
    move-result-object v13

    .line 624
    check-cast v13, Lh0/o2;

    .line 625
    .line 626
    move-object/from16 v20, v4

    .line 627
    .line 628
    sget-object v4, Lh0/z0;->E0:Lh0/g;

    .line 629
    .line 630
    invoke-interface {v13, v4, v0}, Lh0/t1;->b(Lh0/g;Ljava/lang/Object;)Ljava/lang/Object;

    .line 631
    .line 632
    .line 633
    move-result-object v4

    .line 634
    check-cast v4, Lb0/y;

    .line 635
    .line 636
    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 637
    .line 638
    .line 639
    invoke-virtual {v4, v0}, Lb0/y;->equals(Ljava/lang/Object;)Z

    .line 640
    .line 641
    .line 642
    move-result v21

    .line 643
    if-eqz v21, :cond_16

    .line 644
    .line 645
    invoke-virtual {v14, v13}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 646
    .line 647
    .line 648
    move/from16 v21, v7

    .line 649
    .line 650
    goto :goto_10

    .line 651
    :cond_16
    move/from16 v21, v7

    .line 652
    .line 653
    iget v7, v4, Lb0/y;->a:I

    .line 654
    .line 655
    iget v4, v4, Lb0/y;->b:I

    .line 656
    .line 657
    move/from16 v22, v4

    .line 658
    .line 659
    const/4 v4, 0x2

    .line 660
    if-eq v7, v4, :cond_19

    .line 661
    .line 662
    if-eqz v7, :cond_17

    .line 663
    .line 664
    if-eqz v22, :cond_19

    .line 665
    .line 666
    :cond_17
    if-nez v7, :cond_18

    .line 667
    .line 668
    if-eqz v22, :cond_18

    .line 669
    .line 670
    goto :goto_f

    .line 671
    :cond_18
    invoke-virtual {v6, v13}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 672
    .line 673
    .line 674
    goto :goto_10

    .line 675
    :cond_19
    :goto_f
    invoke-virtual {v11, v13}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 676
    .line 677
    .line 678
    :goto_10
    move-object/from16 v13, p2

    .line 679
    .line 680
    move-object/from16 v4, v20

    .line 681
    .line 682
    move/from16 v7, v21

    .line 683
    .line 684
    goto :goto_e

    .line 685
    :cond_1a
    move-object/from16 v20, v4

    .line 686
    .line 687
    move/from16 v21, v7

    .line 688
    .line 689
    new-instance v7, Ljava/util/HashMap;

    .line 690
    .line 691
    invoke-direct {v7}, Ljava/util/HashMap;-><init>()V

    .line 692
    .line 693
    .line 694
    new-instance v4, Ljava/util/LinkedHashSet;

    .line 695
    .line 696
    invoke-direct {v4}, Ljava/util/LinkedHashSet;-><init>()V

    .line 697
    .line 698
    .line 699
    new-instance v13, Ljava/util/ArrayList;

    .line 700
    .line 701
    invoke-direct {v13}, Ljava/util/ArrayList;-><init>()V

    .line 702
    .line 703
    .line 704
    invoke-virtual {v13, v6}, Ljava/util/ArrayList;->addAll(Ljava/util/Collection;)Z

    .line 705
    .line 706
    .line 707
    invoke-virtual {v13, v11}, Ljava/util/ArrayList;->addAll(Ljava/util/Collection;)Z

    .line 708
    .line 709
    .line 710
    invoke-virtual {v13, v14}, Ljava/util/ArrayList;->addAll(Ljava/util/Collection;)Z

    .line 711
    .line 712
    .line 713
    invoke-virtual {v13}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 714
    .line 715
    .line 716
    move-result-object v6

    .line 717
    :goto_11
    invoke-interface {v6}, Ljava/util/Iterator;->hasNext()Z

    .line 718
    .line 719
    .line 720
    move-result v11

    .line 721
    if-eqz v11, :cond_2c

    .line 722
    .line 723
    invoke-interface {v6}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 724
    .line 725
    .line 726
    move-result-object v11

    .line 727
    check-cast v11, Lh0/o2;

    .line 728
    .line 729
    sget-object v14, Lh0/z0;->E0:Lh0/g;

    .line 730
    .line 731
    invoke-interface {v11, v14, v0}, Lh0/t1;->b(Lh0/g;Ljava/lang/Object;)Ljava/lang/Object;

    .line 732
    .line 733
    .line 734
    move-result-object v14

    .line 735
    check-cast v14, Lb0/y;

    .line 736
    .line 737
    invoke-virtual {v14}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 738
    .line 739
    .line 740
    sget-object v13, Ll0/k;->g1:Lh0/g;

    .line 741
    .line 742
    invoke-interface {v11, v13}, Lh0/t1;->f(Lh0/g;)Ljava/lang/Object;

    .line 743
    .line 744
    .line 745
    move-result-object v13

    .line 746
    check-cast v13, Ljava/lang/String;

    .line 747
    .line 748
    move-object/from16 v22, v0

    .line 749
    .line 750
    sget-object v0, Lb0/y;->d:Lb0/y;

    .line 751
    .line 752
    invoke-virtual {v14}, Lb0/y;->b()Z

    .line 753
    .line 754
    .line 755
    move-result v23

    .line 756
    if-eqz v23, :cond_1d

    .line 757
    .line 758
    invoke-virtual {v10, v14}, Ljava/util/HashSet;->contains(Ljava/lang/Object;)Z

    .line 759
    .line 760
    .line 761
    move-result v0

    .line 762
    if-eqz v0, :cond_1b

    .line 763
    .line 764
    move-object/from16 v25, v2

    .line 765
    .line 766
    move-object/from16 v23, v6

    .line 767
    .line 768
    move-object/from16 v27, v8

    .line 769
    .line 770
    move-object/from16 v26, v9

    .line 771
    .line 772
    move-object v13, v14

    .line 773
    move-object/from16 v24, v15

    .line 774
    .line 775
    goto/16 :goto_18

    .line 776
    .line 777
    :cond_1b
    move-object/from16 v25, v2

    .line 778
    .line 779
    move-object/from16 v23, v6

    .line 780
    .line 781
    move-object/from16 v27, v8

    .line 782
    .line 783
    move-object/from16 v26, v9

    .line 784
    .line 785
    move-object/from16 v24, v15

    .line 786
    .line 787
    :cond_1c
    :goto_12
    const/4 v13, 0x0

    .line 788
    goto/16 :goto_18

    .line 789
    .line 790
    :cond_1d
    move-object/from16 v23, v6

    .line 791
    .line 792
    iget v6, v14, Lb0/y;->a:I

    .line 793
    .line 794
    move-object/from16 v24, v15

    .line 795
    .line 796
    iget v15, v14, Lb0/y;->b:I

    .line 797
    .line 798
    const/4 v1, 0x1

    .line 799
    if-ne v6, v1, :cond_1f

    .line 800
    .line 801
    if-nez v15, :cond_1f

    .line 802
    .line 803
    invoke-virtual {v10, v0}, Ljava/util/HashSet;->contains(Ljava/lang/Object;)Z

    .line 804
    .line 805
    .line 806
    move-result v1

    .line 807
    if-eqz v1, :cond_1e

    .line 808
    .line 809
    move-object v13, v0

    .line 810
    move-object/from16 v25, v2

    .line 811
    .line 812
    move-object/from16 v27, v8

    .line 813
    .line 814
    move-object/from16 v26, v9

    .line 815
    .line 816
    goto/16 :goto_18

    .line 817
    .line 818
    :cond_1e
    move-object/from16 v25, v2

    .line 819
    .line 820
    move-object/from16 v27, v8

    .line 821
    .line 822
    move-object/from16 v26, v9

    .line 823
    .line 824
    goto :goto_12

    .line 825
    :cond_1f
    invoke-static {v14, v8, v10}, Lcom/google/android/gms/internal/measurement/i4;->p(Lb0/y;Ljava/util/LinkedHashSet;Ljava/util/HashSet;)Lb0/y;

    .line 826
    .line 827
    .line 828
    move-result-object v1

    .line 829
    move-object/from16 v25, v2

    .line 830
    .line 831
    const-string v2, "\n->\n"

    .line 832
    .line 833
    move-object/from16 v26, v9

    .line 834
    .line 835
    const-string v9, "Resolved dynamic range for use case "

    .line 836
    .line 837
    move-object/from16 v27, v8

    .line 838
    .line 839
    const-string v8, "DynamicRangeResolver"

    .line 840
    .line 841
    if-eqz v1, :cond_20

    .line 842
    .line 843
    new-instance v0, Ljava/lang/StringBuilder;

    .line 844
    .line 845
    invoke-direct {v0, v9}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 846
    .line 847
    .line 848
    invoke-virtual {v0, v13}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 849
    .line 850
    .line 851
    const-string v6, " from existing attached surface.\n"

    .line 852
    .line 853
    invoke-virtual {v0, v6}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 854
    .line 855
    .line 856
    invoke-virtual {v0, v14}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 857
    .line 858
    .line 859
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 860
    .line 861
    .line 862
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 863
    .line 864
    .line 865
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 866
    .line 867
    .line 868
    move-result-object v0

    .line 869
    invoke-static {v8, v0}, Ljp/v1;->c(Ljava/lang/String;Ljava/lang/String;)V

    .line 870
    .line 871
    .line 872
    :goto_13
    move-object v13, v1

    .line 873
    goto/16 :goto_18

    .line 874
    .line 875
    :cond_20
    invoke-static {v14, v4, v10}, Lcom/google/android/gms/internal/measurement/i4;->p(Lb0/y;Ljava/util/LinkedHashSet;Ljava/util/HashSet;)Lb0/y;

    .line 876
    .line 877
    .line 878
    move-result-object v1

    .line 879
    if-eqz v1, :cond_21

    .line 880
    .line 881
    new-instance v0, Ljava/lang/StringBuilder;

    .line 882
    .line 883
    invoke-direct {v0, v9}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 884
    .line 885
    .line 886
    invoke-virtual {v0, v13}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 887
    .line 888
    .line 889
    const-string v6, " from concurrently bound use case.\n"

    .line 890
    .line 891
    invoke-virtual {v0, v6}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 892
    .line 893
    .line 894
    invoke-virtual {v0, v14}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 895
    .line 896
    .line 897
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 898
    .line 899
    .line 900
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 901
    .line 902
    .line 903
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 904
    .line 905
    .line 906
    move-result-object v0

    .line 907
    invoke-static {v8, v0}, Ljp/v1;->c(Ljava/lang/String;Ljava/lang/String;)V

    .line 908
    .line 909
    .line 910
    goto :goto_13

    .line 911
    :cond_21
    invoke-static {v14, v0, v10}, Lcom/google/android/gms/internal/measurement/i4;->k(Lb0/y;Lb0/y;Ljava/util/HashSet;)Z

    .line 912
    .line 913
    .line 914
    move-result v1

    .line 915
    if-eqz v1, :cond_22

    .line 916
    .line 917
    new-instance v1, Ljava/lang/StringBuilder;

    .line 918
    .line 919
    invoke-direct {v1, v9}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 920
    .line 921
    .line 922
    invoke-virtual {v1, v13}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 923
    .line 924
    .line 925
    const-string v6, " to no compatible HDR dynamic ranges.\n"

    .line 926
    .line 927
    invoke-virtual {v1, v6}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 928
    .line 929
    .line 930
    invoke-virtual {v1, v14}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 931
    .line 932
    .line 933
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 934
    .line 935
    .line 936
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 937
    .line 938
    .line 939
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 940
    .line 941
    .line 942
    move-result-object v1

    .line 943
    invoke-static {v8, v1}, Ljp/v1;->c(Ljava/lang/String;Ljava/lang/String;)V

    .line 944
    .line 945
    .line 946
    move-object v13, v0

    .line 947
    goto/16 :goto_18

    .line 948
    .line 949
    :cond_22
    const/4 v1, 0x2

    .line 950
    if-ne v6, v1, :cond_27

    .line 951
    .line 952
    const/16 v1, 0xa

    .line 953
    .line 954
    if-eq v15, v1, :cond_23

    .line 955
    .line 956
    if-nez v15, :cond_27

    .line 957
    .line 958
    :cond_23
    new-instance v6, Ljava/util/LinkedHashSet;

    .line 959
    .line 960
    invoke-direct {v6}, Ljava/util/LinkedHashSet;-><init>()V

    .line 961
    .line 962
    .line 963
    sget v15, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 964
    .line 965
    const/16 v1, 0x21

    .line 966
    .line 967
    if-lt v15, v1, :cond_24

    .line 968
    .line 969
    iget-object v1, v3, Lcom/google/android/gms/internal/measurement/i4;->f:Ljava/lang/Object;

    .line 970
    .line 971
    check-cast v1, Lv/b;

    .line 972
    .line 973
    invoke-static {v1}, Lb/k;->d(Lv/b;)Lb0/y;

    .line 974
    .line 975
    .line 976
    move-result-object v1

    .line 977
    if-eqz v1, :cond_25

    .line 978
    .line 979
    invoke-interface {v6, v1}, Ljava/util/Set;->add(Ljava/lang/Object;)Z

    .line 980
    .line 981
    .line 982
    goto :goto_14

    .line 983
    :cond_24
    const/4 v1, 0x0

    .line 984
    :cond_25
    :goto_14
    invoke-interface {v6, v12}, Ljava/util/Set;->add(Ljava/lang/Object;)Z

    .line 985
    .line 986
    .line 987
    invoke-static {v14, v6, v10}, Lcom/google/android/gms/internal/measurement/i4;->p(Lb0/y;Ljava/util/LinkedHashSet;Ljava/util/HashSet;)Lb0/y;

    .line 988
    .line 989
    .line 990
    move-result-object v6

    .line 991
    if-eqz v6, :cond_27

    .line 992
    .line 993
    invoke-virtual {v6, v1}, Lb0/y;->equals(Ljava/lang/Object;)Z

    .line 994
    .line 995
    .line 996
    move-result v0

    .line 997
    if-eqz v0, :cond_26

    .line 998
    .line 999
    const-string v0, "recommended"

    .line 1000
    .line 1001
    goto :goto_15

    .line 1002
    :cond_26
    const-string v0, "required"

    .line 1003
    .line 1004
    :goto_15
    const-string v1, " from "

    .line 1005
    .line 1006
    const-string v15, " 10-bit supported dynamic range.\n"

    .line 1007
    .line 1008
    invoke-static {v9, v13, v1, v0, v15}, Lu/w;->k(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 1009
    .line 1010
    .line 1011
    move-result-object v0

    .line 1012
    invoke-virtual {v0, v14}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 1013
    .line 1014
    .line 1015
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 1016
    .line 1017
    .line 1018
    invoke-virtual {v0, v6}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 1019
    .line 1020
    .line 1021
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 1022
    .line 1023
    .line 1024
    move-result-object v0

    .line 1025
    invoke-static {v8, v0}, Ljp/v1;->c(Ljava/lang/String;Ljava/lang/String;)V

    .line 1026
    .line 1027
    .line 1028
    :goto_16
    move-object v13, v6

    .line 1029
    goto :goto_18

    .line 1030
    :cond_27
    invoke-virtual {v10}, Ljava/util/HashSet;->iterator()Ljava/util/Iterator;

    .line 1031
    .line 1032
    .line 1033
    move-result-object v1

    .line 1034
    :goto_17
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 1035
    .line 1036
    .line 1037
    move-result v6

    .line 1038
    if-eqz v6, :cond_1c

    .line 1039
    .line 1040
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 1041
    .line 1042
    .line 1043
    move-result-object v6

    .line 1044
    check-cast v6, Lb0/y;

    .line 1045
    .line 1046
    invoke-virtual {v6}, Lb0/y;->b()Z

    .line 1047
    .line 1048
    .line 1049
    move-result v15

    .line 1050
    move-object/from16 v28, v1

    .line 1051
    .line 1052
    const-string v1, "Candidate dynamic range must be fully specified."

    .line 1053
    .line 1054
    invoke-static {v1, v15}, Ljp/ed;->f(Ljava/lang/String;Z)V

    .line 1055
    .line 1056
    .line 1057
    invoke-virtual {v6, v0}, Lb0/y;->equals(Ljava/lang/Object;)Z

    .line 1058
    .line 1059
    .line 1060
    move-result v1

    .line 1061
    if-eqz v1, :cond_29

    .line 1062
    .line 1063
    :cond_28
    move-object/from16 v1, v28

    .line 1064
    .line 1065
    goto :goto_17

    .line 1066
    :cond_29
    invoke-static {v14, v6}, Lcom/google/android/gms/internal/measurement/i4;->j(Lb0/y;Lb0/y;)Z

    .line 1067
    .line 1068
    .line 1069
    move-result v1

    .line 1070
    if-eqz v1, :cond_28

    .line 1071
    .line 1072
    new-instance v0, Ljava/lang/StringBuilder;

    .line 1073
    .line 1074
    invoke-direct {v0, v9}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 1075
    .line 1076
    .line 1077
    invoke-virtual {v0, v13}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 1078
    .line 1079
    .line 1080
    const-string v1, " from validated dynamic range constraints or supported HDR dynamic ranges.\n"

    .line 1081
    .line 1082
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 1083
    .line 1084
    .line 1085
    invoke-virtual {v0, v14}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 1086
    .line 1087
    .line 1088
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 1089
    .line 1090
    .line 1091
    invoke-virtual {v0, v6}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 1092
    .line 1093
    .line 1094
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 1095
    .line 1096
    .line 1097
    move-result-object v0

    .line 1098
    invoke-static {v8, v0}, Ljp/v1;->c(Ljava/lang/String;Ljava/lang/String;)V

    .line 1099
    .line 1100
    .line 1101
    goto :goto_16

    .line 1102
    :goto_18
    if-eqz v13, :cond_2b

    .line 1103
    .line 1104
    invoke-static {v10, v13, v5}, Lcom/google/android/gms/internal/measurement/i4;->w(Ljava/util/HashSet;Lb0/y;Lpv/g;)V

    .line 1105
    .line 1106
    .line 1107
    invoke-virtual {v7, v11, v13}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 1108
    .line 1109
    .line 1110
    move-object/from16 v0, v27

    .line 1111
    .line 1112
    invoke-interface {v0, v13}, Ljava/util/Set;->contains(Ljava/lang/Object;)Z

    .line 1113
    .line 1114
    .line 1115
    move-result v1

    .line 1116
    if-nez v1, :cond_2a

    .line 1117
    .line 1118
    invoke-interface {v4, v13}, Ljava/util/Set;->add(Ljava/lang/Object;)Z

    .line 1119
    .line 1120
    .line 1121
    :cond_2a
    move-object/from16 v1, p0

    .line 1122
    .line 1123
    move-object v8, v0

    .line 1124
    move-object/from16 v0, v22

    .line 1125
    .line 1126
    move-object/from16 v6, v23

    .line 1127
    .line 1128
    move-object/from16 v15, v24

    .line 1129
    .line 1130
    move-object/from16 v2, v25

    .line 1131
    .line 1132
    move-object/from16 v9, v26

    .line 1133
    .line 1134
    goto/16 :goto_11

    .line 1135
    .line 1136
    :cond_2b
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 1137
    .line 1138
    sget-object v1, Ll0/k;->g1:Lh0/g;

    .line 1139
    .line 1140
    invoke-interface {v11, v1}, Lh0/t1;->f(Lh0/g;)Ljava/lang/Object;

    .line 1141
    .line 1142
    .line 1143
    move-result-object v1

    .line 1144
    check-cast v1, Ljava/lang/String;

    .line 1145
    .line 1146
    const-string v2, "\n  "

    .line 1147
    .line 1148
    move-object/from16 v3, v26

    .line 1149
    .line 1150
    invoke-static {v2, v3}, Landroid/text/TextUtils;->join(Ljava/lang/CharSequence;Ljava/lang/Iterable;)Ljava/lang/String;

    .line 1151
    .line 1152
    .line 1153
    move-result-object v3

    .line 1154
    invoke-static {v2, v10}, Landroid/text/TextUtils;->join(Ljava/lang/CharSequence;Ljava/lang/Iterable;)Ljava/lang/String;

    .line 1155
    .line 1156
    .line 1157
    move-result-object v2

    .line 1158
    new-instance v4, Ljava/lang/StringBuilder;

    .line 1159
    .line 1160
    const-string v5, "Unable to resolve supported dynamic range. The dynamic range may not be supported on the device or may not be allowed concurrently with other attached use cases.\nUse case:\n  "

    .line 1161
    .line 1162
    invoke-direct {v4, v5}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 1163
    .line 1164
    .line 1165
    invoke-virtual {v4, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 1166
    .line 1167
    .line 1168
    const-string v1, "\nRequested dynamic range:\n  "

    .line 1169
    .line 1170
    invoke-virtual {v4, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 1171
    .line 1172
    .line 1173
    invoke-virtual {v4, v14}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 1174
    .line 1175
    .line 1176
    const-string v1, "\nSupported dynamic ranges:\n  "

    .line 1177
    .line 1178
    invoke-virtual {v4, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 1179
    .line 1180
    .line 1181
    const-string v1, "\nConstrained set of concurrent dynamic ranges:\n  "

    .line 1182
    .line 1183
    invoke-static {v4, v3, v1, v2}, Lu/w;->h(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 1184
    .line 1185
    .line 1186
    move-result-object v1

    .line 1187
    invoke-direct {v0, v1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 1188
    .line 1189
    .line 1190
    throw v0

    .line 1191
    :cond_2c
    move-object/from16 v25, v2

    .line 1192
    .line 1193
    move-object/from16 v24, v15

    .line 1194
    .line 1195
    new-instance v0, Ljava/lang/StringBuilder;

    .line 1196
    .line 1197
    const-string v1, "resolvedDynamicRanges = "

    .line 1198
    .line 1199
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 1200
    .line 1201
    .line 1202
    invoke-virtual {v0, v7}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 1203
    .line 1204
    .line 1205
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 1206
    .line 1207
    .line 1208
    move-result-object v0

    .line 1209
    const-string v13, "SupportedSurfaceCombination"

    .line 1210
    .line 1211
    invoke-static {v13, v0}, Ljp/v1;->c(Ljava/lang/String;Ljava/lang/String;)V

    .line 1212
    .line 1213
    .line 1214
    invoke-virtual/range {p2 .. p2}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 1215
    .line 1216
    .line 1217
    move-result-object v0

    .line 1218
    :cond_2d
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 1219
    .line 1220
    .line 1221
    move-result v1

    .line 1222
    const/16 v2, 0x1005

    .line 1223
    .line 1224
    if-eqz v1, :cond_2e

    .line 1225
    .line 1226
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 1227
    .line 1228
    .line 1229
    move-result-object v1

    .line 1230
    check-cast v1, Lh0/e;

    .line 1231
    .line 1232
    iget v1, v1, Lh0/e;->b:I

    .line 1233
    .line 1234
    if-ne v1, v2, :cond_2d

    .line 1235
    .line 1236
    :goto_19
    const/4 v6, 0x1

    .line 1237
    goto :goto_1a

    .line 1238
    :cond_2e
    invoke-interface/range {v24 .. v24}, Ljava/util/Map;->keySet()Ljava/util/Set;

    .line 1239
    .line 1240
    .line 1241
    move-result-object v0

    .line 1242
    invoke-interface {v0}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 1243
    .line 1244
    .line 1245
    move-result-object v0

    .line 1246
    :cond_2f
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 1247
    .line 1248
    .line 1249
    move-result v1

    .line 1250
    if-eqz v1, :cond_30

    .line 1251
    .line 1252
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 1253
    .line 1254
    .line 1255
    move-result-object v1

    .line 1256
    check-cast v1, Lh0/o2;

    .line 1257
    .line 1258
    invoke-interface {v1}, Lh0/z0;->l()I

    .line 1259
    .line 1260
    .line 1261
    move-result v1

    .line 1262
    if-ne v1, v2, :cond_2f

    .line 1263
    .line 1264
    goto :goto_19

    .line 1265
    :cond_30
    const/4 v6, 0x0

    .line 1266
    :goto_1a
    invoke-virtual/range {p2 .. p2}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 1267
    .line 1268
    .line 1269
    move-result-object v0

    .line 1270
    const/16 v19, 0x0

    .line 1271
    .line 1272
    :goto_1b
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 1273
    .line 1274
    .line 1275
    move-result v1

    .line 1276
    const-string v2, "All isStrictFpsRequired should be the same"

    .line 1277
    .line 1278
    if-eqz v1, :cond_33

    .line 1279
    .line 1280
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 1281
    .line 1282
    .line 1283
    move-result-object v1

    .line 1284
    check-cast v1, Lh0/e;

    .line 1285
    .line 1286
    iget-boolean v1, v1, Lh0/e;->i:Z

    .line 1287
    .line 1288
    if-eqz v19, :cond_32

    .line 1289
    .line 1290
    invoke-virtual/range {v19 .. v19}, Ljava/lang/Boolean;->booleanValue()Z

    .line 1291
    .line 1292
    .line 1293
    move-result v3

    .line 1294
    if-ne v3, v1, :cond_31

    .line 1295
    .line 1296
    goto :goto_1c

    .line 1297
    :cond_31
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 1298
    .line 1299
    invoke-direct {v0, v2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 1300
    .line 1301
    .line 1302
    throw v0

    .line 1303
    :cond_32
    :goto_1c
    invoke-static {v1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 1304
    .line 1305
    .line 1306
    move-result-object v19

    .line 1307
    goto :goto_1b

    .line 1308
    :cond_33
    invoke-virtual/range {v25 .. v25}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 1309
    .line 1310
    .line 1311
    move-result-object v0

    .line 1312
    :goto_1d
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 1313
    .line 1314
    .line 1315
    move-result v1

    .line 1316
    if-eqz v1, :cond_36

    .line 1317
    .line 1318
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 1319
    .line 1320
    .line 1321
    move-result-object v1

    .line 1322
    check-cast v1, Lh0/o2;

    .line 1323
    .line 1324
    sget-object v3, Lh0/o2;->W0:Lh0/g;

    .line 1325
    .line 1326
    sget-object v4, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 1327
    .line 1328
    invoke-interface {v1, v3, v4}, Lh0/t1;->b(Lh0/g;Ljava/lang/Object;)Ljava/lang/Object;

    .line 1329
    .line 1330
    .line 1331
    move-result-object v1

    .line 1332
    check-cast v1, Ljava/lang/Boolean;

    .line 1333
    .line 1334
    invoke-static {v1}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    .line 1335
    .line 1336
    .line 1337
    invoke-virtual {v1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 1338
    .line 1339
    .line 1340
    move-result v3

    .line 1341
    if-eqz v19, :cond_35

    .line 1342
    .line 1343
    invoke-virtual/range {v19 .. v19}, Ljava/lang/Boolean;->booleanValue()Z

    .line 1344
    .line 1345
    .line 1346
    move-result v4

    .line 1347
    if-ne v4, v3, :cond_34

    .line 1348
    .line 1349
    goto :goto_1e

    .line 1350
    :cond_34
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 1351
    .line 1352
    invoke-direct {v0, v2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 1353
    .line 1354
    .line 1355
    throw v0

    .line 1356
    :cond_35
    :goto_1e
    move-object/from16 v19, v1

    .line 1357
    .line 1358
    goto :goto_1d

    .line 1359
    :cond_36
    if-eqz v19, :cond_37

    .line 1360
    .line 1361
    invoke-virtual/range {v19 .. v19}, Ljava/lang/Boolean;->booleanValue()Z

    .line 1362
    .line 1363
    .line 1364
    move-result v2

    .line 1365
    move v11, v2

    .line 1366
    goto :goto_1f

    .line 1367
    :cond_37
    const/4 v11, 0x0

    .line 1368
    :goto_1f
    sget-object v0, Lh0/k;->h:Landroid/util/Range;

    .line 1369
    .line 1370
    invoke-virtual/range {p2 .. p2}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 1371
    .line 1372
    .line 1373
    move-result-object v1

    .line 1374
    :goto_20
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 1375
    .line 1376
    .line 1377
    move-result v2

    .line 1378
    if-eqz v2, :cond_38

    .line 1379
    .line 1380
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 1381
    .line 1382
    .line 1383
    move-result-object v2

    .line 1384
    check-cast v2, Lh0/e;

    .line 1385
    .line 1386
    iget-object v2, v2, Lh0/e;->h:Landroid/util/Range;

    .line 1387
    .line 1388
    invoke-static {v2, v0, v11}, Lu/c1;->m(Landroid/util/Range;Landroid/util/Range;Z)Landroid/util/Range;

    .line 1389
    .line 1390
    .line 1391
    move-result-object v0

    .line 1392
    goto :goto_20

    .line 1393
    :cond_38
    invoke-virtual/range {v20 .. v20}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 1394
    .line 1395
    .line 1396
    move-result-object v1

    .line 1397
    move-object v10, v0

    .line 1398
    :goto_21
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 1399
    .line 1400
    .line 1401
    move-result v0

    .line 1402
    if-eqz v0, :cond_39

    .line 1403
    .line 1404
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 1405
    .line 1406
    .line 1407
    move-result-object v0

    .line 1408
    check-cast v0, Ljava/lang/Integer;

    .line 1409
    .line 1410
    invoke-virtual {v0}, Ljava/lang/Integer;->intValue()I

    .line 1411
    .line 1412
    .line 1413
    move-result v0

    .line 1414
    move-object/from16 v5, v25

    .line 1415
    .line 1416
    invoke-virtual {v5, v0}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 1417
    .line 1418
    .line 1419
    move-result-object v0

    .line 1420
    check-cast v0, Lh0/o2;

    .line 1421
    .line 1422
    sget-object v2, Lh0/k;->h:Landroid/util/Range;

    .line 1423
    .line 1424
    sget-object v3, Lh0/o2;->V0:Lh0/g;

    .line 1425
    .line 1426
    invoke-interface {v0, v3, v2}, Lh0/t1;->b(Lh0/g;Ljava/lang/Object;)Ljava/lang/Object;

    .line 1427
    .line 1428
    .line 1429
    move-result-object v0

    .line 1430
    check-cast v0, Landroid/util/Range;

    .line 1431
    .line 1432
    invoke-static {v0}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    .line 1433
    .line 1434
    .line 1435
    invoke-static {v0, v10, v11}, Lu/c1;->m(Landroid/util/Range;Landroid/util/Range;Z)Landroid/util/Range;

    .line 1436
    .line 1437
    .line 1438
    move-result-object v10

    .line 1439
    goto :goto_21

    .line 1440
    :cond_39
    move-object/from16 v5, v25

    .line 1441
    .line 1442
    move-object/from16 v1, p0

    .line 1443
    .line 1444
    if-eqz p4, :cond_3b

    .line 1445
    .line 1446
    iget-boolean v0, v1, Lu/c1;->v:Z

    .line 1447
    .line 1448
    if-nez v0, :cond_3b

    .line 1449
    .line 1450
    if-nez p6, :cond_3a

    .line 1451
    .line 1452
    goto :goto_22

    .line 1453
    :cond_3a
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 1454
    .line 1455
    const-string v1, "Preview stabilization is not supported by the camera."

    .line 1456
    .line 1457
    invoke-direct {v0, v1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 1458
    .line 1459
    .line 1460
    throw v0

    .line 1461
    :cond_3b
    :goto_22
    const/4 v9, 0x0

    .line 1462
    move/from16 v2, p1

    .line 1463
    .line 1464
    move/from16 v3, p5

    .line 1465
    .line 1466
    move/from16 v8, p6

    .line 1467
    .line 1468
    move-object/from16 v25, v5

    .line 1469
    .line 1470
    move-object v4, v7

    .line 1471
    move/from16 v7, v21

    .line 1472
    .line 1473
    move/from16 v5, p4

    .line 1474
    .line 1475
    invoke-virtual/range {v1 .. v11}, Lu/c1;->b(IZLjava/util/HashMap;ZZZZZLandroid/util/Range;Z)Lu/d;

    .line 1476
    .line 1477
    .line 1478
    move-result-object v2

    .line 1479
    move-object v7, v4

    .line 1480
    invoke-virtual {v7}, Ljava/util/HashMap;->values()Ljava/util/Collection;

    .line 1481
    .line 1482
    .line 1483
    move-result-object v0

    .line 1484
    const/4 v4, 0x3

    .line 1485
    if-nez p6, :cond_3c

    .line 1486
    .line 1487
    const/4 v0, 0x1

    .line 1488
    const/4 v1, 0x1

    .line 1489
    goto :goto_23

    .line 1490
    :cond_3c
    invoke-interface {v0, v12}, Ljava/util/Collection;->contains(Ljava/lang/Object;)Z

    .line 1491
    .line 1492
    .line 1493
    move-result v0

    .line 1494
    if-eqz v10, :cond_3d

    .line 1495
    .line 1496
    invoke-virtual {v10}, Landroid/util/Range;->getUpper()Ljava/lang/Comparable;

    .line 1497
    .line 1498
    .line 1499
    move-result-object v1

    .line 1500
    check-cast v1, Ljava/lang/Integer;

    .line 1501
    .line 1502
    invoke-virtual {v1}, Ljava/lang/Integer;->intValue()I

    .line 1503
    .line 1504
    .line 1505
    move-result v1

    .line 1506
    const/16 v3, 0x3c

    .line 1507
    .line 1508
    if-ne v1, v3, :cond_3d

    .line 1509
    .line 1510
    add-int/lit8 v0, v0, 0x1

    .line 1511
    .line 1512
    :cond_3d
    if-eqz p4, :cond_3e

    .line 1513
    .line 1514
    add-int/lit8 v0, v0, 0x1

    .line 1515
    .line 1516
    :cond_3e
    if-eqz v6, :cond_3f

    .line 1517
    .line 1518
    add-int/lit8 v0, v0, 0x1

    .line 1519
    .line 1520
    :cond_3f
    const/4 v1, 0x1

    .line 1521
    if-le v0, v1, :cond_40

    .line 1522
    .line 1523
    const/4 v0, 0x2

    .line 1524
    goto :goto_23

    .line 1525
    :cond_40
    if-ne v0, v1, :cond_41

    .line 1526
    .line 1527
    move v0, v4

    .line 1528
    goto :goto_23

    .line 1529
    :cond_41
    move v0, v1

    .line 1530
    :goto_23
    if-eq v0, v1, :cond_44

    .line 1531
    .line 1532
    const/4 v1, 0x2

    .line 1533
    if-eq v0, v1, :cond_43

    .line 1534
    .line 1535
    if-eq v0, v4, :cond_42

    .line 1536
    .line 1537
    const-string v1, "null"

    .line 1538
    .line 1539
    goto :goto_24

    .line 1540
    :cond_42
    const-string v1, "WITHOUT_FEATURE_COMBO_FIRST_AND_THEN_WITH_IT"

    .line 1541
    .line 1542
    goto :goto_24

    .line 1543
    :cond_43
    const-string v1, "WITH_FEATURE_COMBO"

    .line 1544
    .line 1545
    goto :goto_24

    .line 1546
    :cond_44
    const-string v1, "WITHOUT_FEATURE_COMBO"

    .line 1547
    .line 1548
    :goto_24
    const-string v3, "resolveSpecsByCheckingMethod: checkingMethod = "

    .line 1549
    .line 1550
    invoke-virtual {v3, v1}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 1551
    .line 1552
    .line 1553
    move-result-object v1

    .line 1554
    invoke-static {v13, v1}, Ljp/v1;->c(Ljava/lang/String;Ljava/lang/String;)V

    .line 1555
    .line 1556
    .line 1557
    invoke-static {v0}, Lu/w;->o(I)I

    .line 1558
    .line 1559
    .line 1560
    move-result v0

    .line 1561
    const/4 v1, 0x1

    .line 1562
    if-eq v0, v1, :cond_46

    .line 1563
    .line 1564
    const/4 v1, 0x2

    .line 1565
    if-eq v0, v1, :cond_45

    .line 1566
    .line 1567
    move-object/from16 v1, p0

    .line 1568
    .line 1569
    move-object/from16 v3, p2

    .line 1570
    .line 1571
    move-object/from16 v6, v20

    .line 1572
    .line 1573
    move-object/from16 v4, v24

    .line 1574
    .line 1575
    move-object/from16 v5, v25

    .line 1576
    .line 1577
    invoke-virtual/range {v1 .. v7}, Lu/c1;->n(Lu/d;Ljava/util/ArrayList;Ljava/util/Map;Ljava/util/ArrayList;Ljava/util/ArrayList;Ljava/util/HashMap;)Lh0/i2;

    .line 1578
    .line 1579
    .line 1580
    move-result-object v0

    .line 1581
    return-object v0

    .line 1582
    :cond_45
    move-object/from16 v1, p0

    .line 1583
    .line 1584
    move-object/from16 v3, p2

    .line 1585
    .line 1586
    move-object/from16 v6, v20

    .line 1587
    .line 1588
    move-object/from16 v4, v24

    .line 1589
    .line 1590
    move-object/from16 v5, v25

    .line 1591
    .line 1592
    :try_start_0
    invoke-virtual/range {v1 .. v7}, Lu/c1;->n(Lu/d;Ljava/util/ArrayList;Ljava/util/Map;Ljava/util/ArrayList;Ljava/util/ArrayList;Ljava/util/HashMap;)Lh0/i2;

    .line 1593
    .line 1594
    .line 1595
    move-result-object v0
    :try_end_0
    .catch Ljava/lang/IllegalArgumentException; {:try_start_0 .. :try_end_0} :catch_0

    .line 1596
    return-object v0

    .line 1597
    :catch_0
    move-exception v0

    .line 1598
    move-object/from16 v24, v4

    .line 1599
    .line 1600
    move-object/from16 v25, v5

    .line 1601
    .line 1602
    move-object/from16 v20, v6

    .line 1603
    .line 1604
    const-string v1, "Failed to find a supported combination without feature combo, trying again with feature combo"

    .line 1605
    .line 1606
    invoke-static {v13, v1, v0}, Ljp/v1;->d(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 1607
    .line 1608
    .line 1609
    iget v0, v2, Lu/d;->a:I

    .line 1610
    .line 1611
    iget-boolean v3, v2, Lu/d;->b:Z

    .line 1612
    .line 1613
    iget-boolean v5, v2, Lu/d;->d:Z

    .line 1614
    .line 1615
    iget-boolean v6, v2, Lu/d;->e:Z

    .line 1616
    .line 1617
    move-object v4, v7

    .line 1618
    iget-boolean v7, v2, Lu/d;->f:Z

    .line 1619
    .line 1620
    iget-boolean v8, v2, Lu/d;->g:Z

    .line 1621
    .line 1622
    iget-object v10, v2, Lu/d;->i:Landroid/util/Range;

    .line 1623
    .line 1624
    iget-boolean v11, v2, Lu/d;->j:Z

    .line 1625
    .line 1626
    const/4 v9, 0x1

    .line 1627
    move-object/from16 v1, p0

    .line 1628
    .line 1629
    move v2, v0

    .line 1630
    invoke-virtual/range {v1 .. v11}, Lu/c1;->b(IZLjava/util/HashMap;ZZZZZLandroid/util/Range;Z)Lu/d;

    .line 1631
    .line 1632
    .line 1633
    move-result-object v2

    .line 1634
    move-object/from16 v3, p2

    .line 1635
    .line 1636
    move-object v7, v4

    .line 1637
    move-object/from16 v6, v20

    .line 1638
    .line 1639
    move-object/from16 v4, v24

    .line 1640
    .line 1641
    move-object/from16 v5, v25

    .line 1642
    .line 1643
    invoke-virtual/range {v1 .. v7}, Lu/c1;->n(Lu/d;Ljava/util/ArrayList;Ljava/util/Map;Ljava/util/ArrayList;Ljava/util/ArrayList;Ljava/util/HashMap;)Lh0/i2;

    .line 1644
    .line 1645
    .line 1646
    move-result-object v0

    .line 1647
    return-object v0

    .line 1648
    :cond_46
    iget v0, v2, Lu/d;->a:I

    .line 1649
    .line 1650
    iget-boolean v3, v2, Lu/d;->b:Z

    .line 1651
    .line 1652
    iget-boolean v5, v2, Lu/d;->d:Z

    .line 1653
    .line 1654
    iget-boolean v6, v2, Lu/d;->e:Z

    .line 1655
    .line 1656
    move-object v4, v7

    .line 1657
    iget-boolean v7, v2, Lu/d;->f:Z

    .line 1658
    .line 1659
    iget-boolean v8, v2, Lu/d;->g:Z

    .line 1660
    .line 1661
    iget-object v10, v2, Lu/d;->i:Landroid/util/Range;

    .line 1662
    .line 1663
    iget-boolean v11, v2, Lu/d;->j:Z

    .line 1664
    .line 1665
    const/4 v9, 0x1

    .line 1666
    move-object/from16 v1, p0

    .line 1667
    .line 1668
    move v2, v0

    .line 1669
    invoke-virtual/range {v1 .. v11}, Lu/c1;->b(IZLjava/util/HashMap;ZZZZZLandroid/util/Range;Z)Lu/d;

    .line 1670
    .line 1671
    .line 1672
    move-result-object v2

    .line 1673
    move-object/from16 v3, p2

    .line 1674
    .line 1675
    move-object v7, v4

    .line 1676
    move-object/from16 v6, v20

    .line 1677
    .line 1678
    move-object/from16 v4, v24

    .line 1679
    .line 1680
    move-object/from16 v5, v25

    .line 1681
    .line 1682
    invoke-virtual/range {v1 .. v7}, Lu/c1;->n(Lu/d;Ljava/util/ArrayList;Ljava/util/Map;Ljava/util/ArrayList;Ljava/util/ArrayList;Ljava/util/HashMap;)Lh0/i2;

    .line 1683
    .line 1684
    .line 1685
    move-result-object v0

    .line 1686
    return-object v0
.end method

.method public final k(Lu/d;Ljava/util/ArrayList;Ljava/util/List;Ljava/util/ArrayList;Ljava/util/ArrayList;ILjava/util/HashMap;Ljava/util/HashMap;)Landroid/util/Pair;
    .locals 16

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    new-instance v2, Ljava/util/ArrayList;

    .line 6
    .line 7
    invoke-direct {v2}, Ljava/util/ArrayList;-><init>()V

    .line 8
    .line 9
    .line 10
    invoke-virtual/range {p2 .. p2}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 11
    .line 12
    .line 13
    move-result-object v3

    .line 14
    :goto_0
    invoke-interface {v3}, Ljava/util/Iterator;->hasNext()Z

    .line 15
    .line 16
    .line 17
    move-result v4

    .line 18
    if-eqz v4, :cond_0

    .line 19
    .line 20
    invoke-interface {v3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 21
    .line 22
    .line 23
    move-result-object v4

    .line 24
    check-cast v4, Lh0/e;

    .line 25
    .line 26
    iget-object v5, v4, Lh0/e;->a:Lh0/h2;

    .line 27
    .line 28
    invoke-virtual {v2, v5}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 29
    .line 30
    .line 31
    invoke-virtual {v2}, Ljava/util/ArrayList;->size()I

    .line 32
    .line 33
    .line 34
    move-result v5

    .line 35
    add-int/lit8 v5, v5, -0x1

    .line 36
    .line 37
    invoke-static {v5}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 38
    .line 39
    .line 40
    move-result-object v5

    .line 41
    move-object/from16 v6, p7

    .line 42
    .line 43
    invoke-virtual {v6, v5, v4}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 44
    .line 45
    .line 46
    goto :goto_0

    .line 47
    :cond_0
    const/4 v3, 0x0

    .line 48
    move v4, v3

    .line 49
    move/from16 v3, p6

    .line 50
    .line 51
    :goto_1
    invoke-interface/range {p3 .. p3}, Ljava/util/List;->size()I

    .line 52
    .line 53
    .line 54
    move-result v5

    .line 55
    if-ge v4, v5, :cond_2

    .line 56
    .line 57
    move-object/from16 v5, p3

    .line 58
    .line 59
    invoke-interface {v5, v4}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 60
    .line 61
    .line 62
    move-result-object v6

    .line 63
    move-object v8, v6

    .line 64
    check-cast v8, Landroid/util/Size;

    .line 65
    .line 66
    move-object/from16 v6, p5

    .line 67
    .line 68
    invoke-virtual {v6, v4}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 69
    .line 70
    .line 71
    move-result-object v7

    .line 72
    check-cast v7, Ljava/lang/Integer;

    .line 73
    .line 74
    invoke-virtual {v7}, Ljava/lang/Integer;->intValue()I

    .line 75
    .line 76
    .line 77
    move-result v7

    .line 78
    move-object/from16 v13, p4

    .line 79
    .line 80
    invoke-virtual {v13, v7}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 81
    .line 82
    .line 83
    move-result-object v7

    .line 84
    move-object v14, v7

    .line 85
    check-cast v14, Lh0/o2;

    .line 86
    .line 87
    invoke-interface {v14}, Lh0/z0;->l()I

    .line 88
    .line 89
    .line 90
    move-result v7

    .line 91
    invoke-interface {v14}, Lh0/o2;->H()Lh0/c2;

    .line 92
    .line 93
    .line 94
    move-result-object v12

    .line 95
    iget-boolean v9, v1, Lu/d;->h:Z

    .line 96
    .line 97
    if-eqz v9, :cond_1

    .line 98
    .line 99
    sget-object v9, Lh0/f2;->d:Lh0/f2;

    .line 100
    .line 101
    :goto_2
    move-object v11, v9

    .line 102
    goto :goto_3

    .line 103
    :cond_1
    sget-object v9, Lh0/f2;->e:Lh0/f2;

    .line 104
    .line 105
    goto :goto_2

    .line 106
    :goto_3
    invoke-virtual {v0, v7}, Lu/c1;->l(I)Lh0/l;

    .line 107
    .line 108
    .line 109
    move-result-object v9

    .line 110
    iget v10, v1, Lu/d;->a:I

    .line 111
    .line 112
    sget-object v15, Lh0/h2;->e:Lh0/c2;

    .line 113
    .line 114
    invoke-static/range {v7 .. v12}, Lkp/aa;->d(ILandroid/util/Size;Lh0/l;ILh0/f2;Lh0/c2;)Lh0/h2;

    .line 115
    .line 116
    .line 117
    move-result-object v7

    .line 118
    invoke-virtual {v2, v7}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 119
    .line 120
    .line 121
    invoke-virtual {v2}, Ljava/util/ArrayList;->size()I

    .line 122
    .line 123
    .line 124
    move-result v7

    .line 125
    add-int/lit8 v7, v7, -0x1

    .line 126
    .line 127
    invoke-static {v7}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 128
    .line 129
    .line 130
    move-result-object v7

    .line 131
    move-object/from16 v9, p8

    .line 132
    .line 133
    invoke-virtual {v9, v7, v14}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 134
    .line 135
    .line 136
    invoke-interface {v14}, Lh0/z0;->l()I

    .line 137
    .line 138
    .line 139
    move-result v7

    .line 140
    iget-boolean v10, v1, Lu/d;->f:Z

    .line 141
    .line 142
    invoke-virtual {v0, v7, v8, v10}, Lu/c1;->e(ILandroid/util/Size;Z)I

    .line 143
    .line 144
    .line 145
    move-result v7

    .line 146
    invoke-static {v3, v7}, Ljava/lang/Math;->min(II)I

    .line 147
    .line 148
    .line 149
    move-result v3

    .line 150
    add-int/lit8 v4, v4, 0x1

    .line 151
    .line 152
    goto :goto_1

    .line 153
    :cond_2
    new-instance v0, Landroid/util/Pair;

    .line 154
    .line 155
    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 156
    .line 157
    .line 158
    move-result-object v1

    .line 159
    invoke-direct {v0, v2, v1}, Landroid/util/Pair;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 160
    .line 161
    .line 162
    return-object v0
.end method

.method public final l(I)Lh0/l;
    .locals 6

    .line 1
    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    iget-object v1, p0, Lu/c1;->x:Ljava/util/ArrayList;

    .line 6
    .line 7
    invoke-virtual {v1, v0}, Ljava/util/ArrayList;->contains(Ljava/lang/Object;)Z

    .line 8
    .line 9
    .line 10
    move-result v0

    .line 11
    if-nez v0, :cond_3

    .line 12
    .line 13
    iget-object v0, p0, Lu/c1;->w:Lh0/l;

    .line 14
    .line 15
    iget-object v0, v0, Lh0/l;->b:Ljava/util/HashMap;

    .line 16
    .line 17
    sget-object v2, Lo0/a;->d:Landroid/util/Size;

    .line 18
    .line 19
    invoke-virtual {p0, v0, v2, p1}, Lu/c1;->p(Ljava/util/HashMap;Landroid/util/Size;I)V

    .line 20
    .line 21
    .line 22
    iget-object v0, p0, Lu/c1;->w:Lh0/l;

    .line 23
    .line 24
    iget-object v0, v0, Lh0/l;->d:Ljava/util/HashMap;

    .line 25
    .line 26
    sget-object v2, Lo0/a;->f:Landroid/util/Size;

    .line 27
    .line 28
    invoke-virtual {p0, v0, v2, p1}, Lu/c1;->p(Ljava/util/HashMap;Landroid/util/Size;I)V

    .line 29
    .line 30
    .line 31
    iget-object v0, p0, Lu/c1;->w:Lh0/l;

    .line 32
    .line 33
    iget-object v0, v0, Lh0/l;->f:Ljava/util/HashMap;

    .line 34
    .line 35
    const/4 v2, 0x0

    .line 36
    invoke-virtual {p0, v0, p1, v2}, Lu/c1;->o(Ljava/util/HashMap;ILandroid/util/Rational;)V

    .line 37
    .line 38
    .line 39
    iget-object v0, p0, Lu/c1;->w:Lh0/l;

    .line 40
    .line 41
    iget-object v0, v0, Lh0/l;->g:Ljava/util/HashMap;

    .line 42
    .line 43
    sget-object v3, Li0/b;->a:Landroid/util/Rational;

    .line 44
    .line 45
    invoke-virtual {p0, v0, p1, v3}, Lu/c1;->o(Ljava/util/HashMap;ILandroid/util/Rational;)V

    .line 46
    .line 47
    .line 48
    iget-object v0, p0, Lu/c1;->w:Lh0/l;

    .line 49
    .line 50
    iget-object v0, v0, Lh0/l;->h:Ljava/util/HashMap;

    .line 51
    .line 52
    sget-object v3, Li0/b;->c:Landroid/util/Rational;

    .line 53
    .line 54
    invoke-virtual {p0, v0, p1, v3}, Lu/c1;->o(Ljava/util/HashMap;ILandroid/util/Rational;)V

    .line 55
    .line 56
    .line 57
    iget-object v0, p0, Lu/c1;->w:Lh0/l;

    .line 58
    .line 59
    iget-object v0, v0, Lh0/l;->i:Ljava/util/HashMap;

    .line 60
    .line 61
    sget v3, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 62
    .line 63
    const/16 v4, 0x1f

    .line 64
    .line 65
    if-lt v3, v4, :cond_2

    .line 66
    .line 67
    iget-boolean v3, p0, Lu/c1;->t:Z

    .line 68
    .line 69
    if-nez v3, :cond_0

    .line 70
    .line 71
    goto :goto_0

    .line 72
    :cond_0
    iget-object v3, p0, Lu/c1;->m:Lv/b;

    .line 73
    .line 74
    invoke-static {}, Lu/m0;->a()Landroid/hardware/camera2/CameraCharacteristics$Key;

    .line 75
    .line 76
    .line 77
    move-result-object v4

    .line 78
    invoke-virtual {v3, v4}, Lv/b;->a(Landroid/hardware/camera2/CameraCharacteristics$Key;)Ljava/lang/Object;

    .line 79
    .line 80
    .line 81
    move-result-object v3

    .line 82
    check-cast v3, Landroid/hardware/camera2/params/StreamConfigurationMap;

    .line 83
    .line 84
    if-nez v3, :cond_1

    .line 85
    .line 86
    goto :goto_0

    .line 87
    :cond_1
    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 88
    .line 89
    .line 90
    move-result-object v4

    .line 91
    const/4 v5, 0x1

    .line 92
    invoke-static {v3, p1, v5, v2}, Lu/c1;->f(Landroid/hardware/camera2/params/StreamConfigurationMap;IZLandroid/util/Rational;)Landroid/util/Size;

    .line 93
    .line 94
    .line 95
    move-result-object v2

    .line 96
    invoke-virtual {v0, v4, v2}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 97
    .line 98
    .line 99
    :cond_2
    :goto_0
    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 100
    .line 101
    .line 102
    move-result-object p1

    .line 103
    invoke-virtual {v1, p1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 104
    .line 105
    .line 106
    :cond_3
    iget-object p0, p0, Lu/c1;->w:Lh0/l;

    .line 107
    .line 108
    return-object p0
.end method

.method public final n(Lu/d;Ljava/util/ArrayList;Ljava/util/Map;Ljava/util/ArrayList;Ljava/util/ArrayList;Ljava/util/HashMap;)Lh0/i2;
    .locals 41

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    move-object/from16 v6, p2

    .line 6
    .line 7
    move-object/from16 v7, p3

    .line 8
    .line 9
    move-object/from16 v8, p4

    .line 10
    .line 11
    move-object/from16 v9, p6

    .line 12
    .line 13
    new-instance v2, Ljava/lang/StringBuilder;

    .line 14
    .line 15
    const-string v3, "resolveSpecsBySettings: featureSettings = "

    .line 16
    .line 17
    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 18
    .line 19
    .line 20
    invoke-virtual {v2, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 21
    .line 22
    .line 23
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 24
    .line 25
    .line 26
    move-result-object v2

    .line 27
    const-string v10, "SupportedSurfaceCombination"

    .line 28
    .line 29
    invoke-static {v10, v2}, Ljp/v1;->c(Ljava/lang/String;Ljava/lang/String;)V

    .line 30
    .line 31
    .line 32
    iget-boolean v2, v1, Lu/d;->h:Z

    .line 33
    .line 34
    const-string v11, "No supported surface combination is found for camera device - Id : "

    .line 35
    .line 36
    const/4 v13, 0x0

    .line 37
    if-nez v2, :cond_4

    .line 38
    .line 39
    new-instance v2, Ljava/util/ArrayList;

    .line 40
    .line 41
    invoke-direct {v2}, Ljava/util/ArrayList;-><init>()V

    .line 42
    .line 43
    .line 44
    invoke-virtual {v6}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 45
    .line 46
    .line 47
    move-result-object v3

    .line 48
    :goto_0
    invoke-interface {v3}, Ljava/util/Iterator;->hasNext()Z

    .line 49
    .line 50
    .line 51
    move-result v4

    .line 52
    if-eqz v4, :cond_0

    .line 53
    .line 54
    invoke-interface {v3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 55
    .line 56
    .line 57
    move-result-object v4

    .line 58
    check-cast v4, Lh0/e;

    .line 59
    .line 60
    iget-object v4, v4, Lh0/e;->a:Lh0/h2;

    .line 61
    .line 62
    invoke-virtual {v2, v4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 63
    .line 64
    .line 65
    goto :goto_0

    .line 66
    :cond_0
    new-instance v3, Li0/c;

    .line 67
    .line 68
    invoke-direct {v3, v13}, Li0/c;-><init>(Z)V

    .line 69
    .line 70
    .line 71
    invoke-interface {v7}, Ljava/util/Map;->keySet()Ljava/util/Set;

    .line 72
    .line 73
    .line 74
    move-result-object v4

    .line 75
    invoke-interface {v4}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 76
    .line 77
    .line 78
    move-result-object v4

    .line 79
    :goto_1
    invoke-interface {v4}, Ljava/util/Iterator;->hasNext()Z

    .line 80
    .line 81
    .line 82
    move-result v5

    .line 83
    if-eqz v5, :cond_2

    .line 84
    .line 85
    invoke-interface {v4}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 86
    .line 87
    .line 88
    move-result-object v5

    .line 89
    check-cast v5, Lh0/o2;

    .line 90
    .line 91
    invoke-interface {v7, v5}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 92
    .line 93
    .line 94
    move-result-object v14

    .line 95
    check-cast v14, Ljava/util/List;

    .line 96
    .line 97
    if-eqz v14, :cond_1

    .line 98
    .line 99
    invoke-interface {v14}, Ljava/util/List;->isEmpty()Z

    .line 100
    .line 101
    .line 102
    move-result v15

    .line 103
    if-nez v15, :cond_1

    .line 104
    .line 105
    const/4 v15, 0x1

    .line 106
    :goto_2
    const/16 v16, 0x1

    .line 107
    .line 108
    goto :goto_3

    .line 109
    :cond_1
    move v15, v13

    .line 110
    goto :goto_2

    .line 111
    :goto_3
    new-instance v12, Ljava/lang/StringBuilder;

    .line 112
    .line 113
    const-string v13, "No available output size is found for "

    .line 114
    .line 115
    invoke-direct {v12, v13}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 116
    .line 117
    .line 118
    invoke-virtual {v12, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 119
    .line 120
    .line 121
    const-string v13, "."

    .line 122
    .line 123
    invoke-virtual {v12, v13}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 124
    .line 125
    .line 126
    invoke-virtual {v12}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 127
    .line 128
    .line 129
    move-result-object v12

    .line 130
    invoke-static {v15, v12}, Ljp/ed;->b(ZLjava/lang/String;)V

    .line 131
    .line 132
    .line 133
    invoke-static {v14, v3}, Ljava/util/Collections;->min(Ljava/util/Collection;Ljava/util/Comparator;)Ljava/lang/Object;

    .line 134
    .line 135
    .line 136
    move-result-object v12

    .line 137
    move-object/from16 v19, v12

    .line 138
    .line 139
    check-cast v19, Landroid/util/Size;

    .line 140
    .line 141
    invoke-interface {v5}, Lh0/z0;->l()I

    .line 142
    .line 143
    .line 144
    move-result v12

    .line 145
    invoke-virtual {v0, v12}, Lu/c1;->l(I)Lh0/l;

    .line 146
    .line 147
    .line 148
    move-result-object v20

    .line 149
    iget v13, v1, Lu/d;->a:I

    .line 150
    .line 151
    sget-object v22, Lh0/f2;->e:Lh0/f2;

    .line 152
    .line 153
    invoke-interface {v5}, Lh0/o2;->H()Lh0/c2;

    .line 154
    .line 155
    .line 156
    move-result-object v23

    .line 157
    sget-object v5, Lh0/h2;->e:Lh0/c2;

    .line 158
    .line 159
    move/from16 v18, v12

    .line 160
    .line 161
    move/from16 v21, v13

    .line 162
    .line 163
    invoke-static/range {v18 .. v23}, Lkp/aa;->d(ILandroid/util/Size;Lh0/l;ILh0/f2;Lh0/c2;)Lh0/h2;

    .line 164
    .line 165
    .line 166
    move-result-object v5

    .line 167
    invoke-virtual {v2, v5}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 168
    .line 169
    .line 170
    const/4 v13, 0x0

    .line 171
    goto :goto_1

    .line 172
    :cond_2
    const/16 v16, 0x1

    .line 173
    .line 174
    sget-object v3, Ljava/util/Collections;->EMPTY_MAP:Ljava/util/Map;

    .line 175
    .line 176
    sget-object v4, Ljava/util/Collections;->EMPTY_LIST:Ljava/util/List;

    .line 177
    .line 178
    move-object v5, v4

    .line 179
    invoke-virtual/range {v0 .. v5}, Lu/c1;->a(Lu/d;Ljava/util/List;Ljava/util/Map;Ljava/util/List;Ljava/util/List;)Z

    .line 180
    .line 181
    .line 182
    move-result v2

    .line 183
    if-eqz v2, :cond_3

    .line 184
    .line 185
    goto :goto_4

    .line 186
    :cond_3
    new-instance v2, Ljava/lang/IllegalArgumentException;

    .line 187
    .line 188
    new-instance v3, Ljava/lang/StringBuilder;

    .line 189
    .line 190
    invoke-direct {v3, v11}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 191
    .line 192
    .line 193
    iget-object v0, v0, Lu/c1;->k:Ljava/lang/String;

    .line 194
    .line 195
    invoke-virtual {v3, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 196
    .line 197
    .line 198
    const-string v0, ".  May be attempting to bind too many use cases. Existing surfaces: "

    .line 199
    .line 200
    invoke-virtual {v3, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 201
    .line 202
    .line 203
    invoke-virtual {v3, v6}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 204
    .line 205
    .line 206
    const-string v0, ". New configs: "

    .line 207
    .line 208
    invoke-virtual {v3, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 209
    .line 210
    .line 211
    invoke-virtual {v3, v8}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 212
    .line 213
    .line 214
    const-string v0, ". GroupableFeature settings: "

    .line 215
    .line 216
    invoke-virtual {v3, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 217
    .line 218
    .line 219
    invoke-virtual {v3, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 220
    .line 221
    .line 222
    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 223
    .line 224
    .line 225
    move-result-object v0

    .line 226
    invoke-direct {v2, v0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 227
    .line 228
    .line 229
    throw v2

    .line 230
    :cond_4
    const/16 v16, 0x1

    .line 231
    .line 232
    :goto_4
    new-instance v2, Ljava/util/HashMap;

    .line 233
    .line 234
    invoke-direct {v2}, Ljava/util/HashMap;-><init>()V

    .line 235
    .line 236
    .line 237
    invoke-interface {v7}, Ljava/util/Map;->keySet()Ljava/util/Set;

    .line 238
    .line 239
    .line 240
    move-result-object v3

    .line 241
    invoke-interface {v3}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 242
    .line 243
    .line 244
    move-result-object v3

    .line 245
    :goto_5
    invoke-interface {v3}, Ljava/util/Iterator;->hasNext()Z

    .line 246
    .line 247
    .line 248
    move-result v4

    .line 249
    if-eqz v4, :cond_b

    .line 250
    .line 251
    invoke-interface {v3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 252
    .line 253
    .line 254
    move-result-object v4

    .line 255
    check-cast v4, Lh0/o2;

    .line 256
    .line 257
    new-instance v5, Ljava/util/ArrayList;

    .line 258
    .line 259
    invoke-direct {v5}, Ljava/util/ArrayList;-><init>()V

    .line 260
    .line 261
    .line 262
    new-instance v13, Ljava/util/HashMap;

    .line 263
    .line 264
    invoke-direct {v13}, Ljava/util/HashMap;-><init>()V

    .line 265
    .line 266
    .line 267
    invoke-interface {v7, v4}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 268
    .line 269
    .line 270
    move-result-object v14

    .line 271
    check-cast v14, Ljava/util/List;

    .line 272
    .line 273
    invoke-static {v14}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    .line 274
    .line 275
    .line 276
    check-cast v14, Ljava/util/List;

    .line 277
    .line 278
    invoke-interface {v14}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 279
    .line 280
    .line 281
    move-result-object v14

    .line 282
    :goto_6
    invoke-interface {v14}, Ljava/util/Iterator;->hasNext()Z

    .line 283
    .line 284
    .line 285
    move-result v15

    .line 286
    if-eqz v15, :cond_a

    .line 287
    .line 288
    invoke-interface {v14}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 289
    .line 290
    .line 291
    move-result-object v15

    .line 292
    move-object/from16 v19, v15

    .line 293
    .line 294
    check-cast v19, Landroid/util/Size;

    .line 295
    .line 296
    invoke-interface {v4}, Lh0/z0;->l()I

    .line 297
    .line 298
    .line 299
    move-result v15

    .line 300
    invoke-interface {v4}, Lh0/o2;->H()Lh0/c2;

    .line 301
    .line 302
    .line 303
    move-result-object v23

    .line 304
    iget-object v12, v1, Lu/d;->i:Landroid/util/Range;

    .line 305
    .line 306
    invoke-virtual {v0, v15}, Lu/c1;->l(I)Lh0/l;

    .line 307
    .line 308
    .line 309
    move-result-object v20

    .line 310
    move-object/from16 v24, v3

    .line 311
    .line 312
    iget v3, v1, Lu/d;->a:I

    .line 313
    .line 314
    move/from16 v21, v3

    .line 315
    .line 316
    iget-boolean v3, v1, Lu/d;->h:Z

    .line 317
    .line 318
    if-eqz v3, :cond_5

    .line 319
    .line 320
    sget-object v3, Lh0/f2;->d:Lh0/f2;

    .line 321
    .line 322
    :goto_7
    move-object/from16 v22, v3

    .line 323
    .line 324
    goto :goto_8

    .line 325
    :cond_5
    sget-object v3, Lh0/f2;->e:Lh0/f2;

    .line 326
    .line 327
    goto :goto_7

    .line 328
    :goto_8
    sget-object v3, Lh0/h2;->e:Lh0/c2;

    .line 329
    .line 330
    move/from16 v18, v15

    .line 331
    .line 332
    invoke-static/range {v18 .. v23}, Lkp/aa;->d(ILandroid/util/Size;Lh0/l;ILh0/f2;Lh0/c2;)Lh0/h2;

    .line 333
    .line 334
    .line 335
    move-result-object v3

    .line 336
    move/from16 v6, v18

    .line 337
    .line 338
    move-object/from16 v15, v19

    .line 339
    .line 340
    iget-object v3, v3, Lh0/h2;->b:Lh0/e2;

    .line 341
    .line 342
    sget-object v7, Lh0/k;->h:Landroid/util/Range;

    .line 343
    .line 344
    invoke-virtual {v7, v12}, Landroid/util/Range;->equals(Ljava/lang/Object;)Z

    .line 345
    .line 346
    .line 347
    move-result v18

    .line 348
    if-eqz v18, :cond_6

    .line 349
    .line 350
    move-object/from16 v18, v14

    .line 351
    .line 352
    const v6, 0x7fffffff

    .line 353
    .line 354
    .line 355
    goto :goto_9

    .line 356
    :cond_6
    move-object/from16 v18, v14

    .line 357
    .line 358
    iget-boolean v14, v1, Lu/d;->f:Z

    .line 359
    .line 360
    invoke-virtual {v0, v6, v15, v14}, Lu/c1;->e(ILandroid/util/Size;Z)I

    .line 361
    .line 362
    .line 363
    move-result v6

    .line 364
    :goto_9
    iget-boolean v14, v1, Lu/d;->g:Z

    .line 365
    .line 366
    if-eqz v14, :cond_7

    .line 367
    .line 368
    sget-object v14, Lh0/e2;->t:Lh0/e2;

    .line 369
    .line 370
    if-eq v3, v14, :cond_9

    .line 371
    .line 372
    invoke-virtual {v7, v12}, Landroid/util/Range;->equals(Ljava/lang/Object;)Z

    .line 373
    .line 374
    .line 375
    move-result v7

    .line 376
    if-nez v7, :cond_7

    .line 377
    .line 378
    invoke-virtual {v12}, Landroid/util/Range;->getUpper()Ljava/lang/Comparable;

    .line 379
    .line 380
    .line 381
    move-result-object v7

    .line 382
    check-cast v7, Ljava/lang/Integer;

    .line 383
    .line 384
    invoke-virtual {v7}, Ljava/lang/Integer;->intValue()I

    .line 385
    .line 386
    .line 387
    move-result v7

    .line 388
    if-ge v6, v7, :cond_7

    .line 389
    .line 390
    goto :goto_a

    .line 391
    :cond_7
    invoke-virtual {v13, v3}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 392
    .line 393
    .line 394
    move-result-object v7

    .line 395
    check-cast v7, Ljava/util/Set;

    .line 396
    .line 397
    if-nez v7, :cond_8

    .line 398
    .line 399
    new-instance v7, Ljava/util/HashSet;

    .line 400
    .line 401
    invoke-direct {v7}, Ljava/util/HashSet;-><init>()V

    .line 402
    .line 403
    .line 404
    invoke-virtual {v13, v3, v7}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 405
    .line 406
    .line 407
    :cond_8
    invoke-static {v6}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 408
    .line 409
    .line 410
    move-result-object v3

    .line 411
    invoke-interface {v7, v3}, Ljava/util/Set;->contains(Ljava/lang/Object;)Z

    .line 412
    .line 413
    .line 414
    move-result v3

    .line 415
    if-nez v3, :cond_9

    .line 416
    .line 417
    invoke-virtual {v5, v15}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 418
    .line 419
    .line 420
    invoke-static {v6}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 421
    .line 422
    .line 423
    move-result-object v3

    .line 424
    invoke-interface {v7, v3}, Ljava/util/Set;->add(Ljava/lang/Object;)Z

    .line 425
    .line 426
    .line 427
    :cond_9
    :goto_a
    move-object/from16 v6, p2

    .line 428
    .line 429
    move-object/from16 v7, p3

    .line 430
    .line 431
    move-object/from16 v14, v18

    .line 432
    .line 433
    move-object/from16 v3, v24

    .line 434
    .line 435
    goto/16 :goto_6

    .line 436
    .line 437
    :cond_a
    move-object/from16 v24, v3

    .line 438
    .line 439
    invoke-virtual {v2, v4, v5}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 440
    .line 441
    .line 442
    move-object/from16 v6, p2

    .line 443
    .line 444
    move-object/from16 v7, p3

    .line 445
    .line 446
    goto/16 :goto_5

    .line 447
    .line 448
    :cond_b
    new-instance v3, Ljava/util/ArrayList;

    .line 449
    .line 450
    invoke-direct {v3}, Ljava/util/ArrayList;-><init>()V

    .line 451
    .line 452
    .line 453
    invoke-virtual/range {p5 .. p5}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 454
    .line 455
    .line 456
    move-result-object v4

    .line 457
    :goto_b
    invoke-interface {v4}, Ljava/util/Iterator;->hasNext()Z

    .line 458
    .line 459
    .line 460
    move-result v5

    .line 461
    if-eqz v5, :cond_1a

    .line 462
    .line 463
    invoke-interface {v4}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 464
    .line 465
    .line 466
    move-result-object v5

    .line 467
    check-cast v5, Ljava/lang/Integer;

    .line 468
    .line 469
    invoke-virtual {v5}, Ljava/lang/Integer;->intValue()I

    .line 470
    .line 471
    .line 472
    move-result v5

    .line 473
    invoke-virtual {v8, v5}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 474
    .line 475
    .line 476
    move-result-object v5

    .line 477
    check-cast v5, Lh0/o2;

    .line 478
    .line 479
    invoke-virtual {v2, v5}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 480
    .line 481
    .line 482
    move-result-object v6

    .line 483
    check-cast v6, Ljava/util/List;

    .line 484
    .line 485
    if-nez v6, :cond_c

    .line 486
    .line 487
    sget-object v6, Ljava/util/Collections;->EMPTY_LIST:Ljava/util/List;

    .line 488
    .line 489
    :cond_c
    invoke-interface {v5}, Lh0/z0;->l()I

    .line 490
    .line 491
    .line 492
    move-result v5

    .line 493
    iget-object v7, v0, Lu/c1;->z:Ldv/a;

    .line 494
    .line 495
    iget-object v13, v0, Lu/c1;->m:Lv/b;

    .line 496
    .line 497
    invoke-virtual {v7}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 498
    .line 499
    .line 500
    const-class v7, Landroidx/camera/camera2/internal/compat/quirk/Nexus4AndroidLTargetAspectRatioQuirk;

    .line 501
    .line 502
    sget-object v14, Lx/a;->a:Ld01/x;

    .line 503
    .line 504
    invoke-virtual {v14, v7}, Ld01/x;->l(Ljava/lang/Class;)Lh0/p1;

    .line 505
    .line 506
    .line 507
    move-result-object v7

    .line 508
    check-cast v7, Landroidx/camera/camera2/internal/compat/quirk/Nexus4AndroidLTargetAspectRatioQuirk;

    .line 509
    .line 510
    const/4 v14, 0x3

    .line 511
    const/4 v15, 0x2

    .line 512
    if-eqz v7, :cond_d

    .line 513
    .line 514
    :goto_c
    move v7, v15

    .line 515
    goto :goto_d

    .line 516
    :cond_d
    invoke-static {v13}, Llp/zd;->a(Lv/b;)Ld01/x;

    .line 517
    .line 518
    .line 519
    move-result-object v7

    .line 520
    const-class v13, Landroidx/camera/camera2/internal/compat/quirk/AspectRatioLegacyApi21Quirk;

    .line 521
    .line 522
    invoke-virtual {v7, v13}, Ld01/x;->l(Ljava/lang/Class;)Lh0/p1;

    .line 523
    .line 524
    .line 525
    move-result-object v7

    .line 526
    check-cast v7, Landroidx/camera/camera2/internal/compat/quirk/AspectRatioLegacyApi21Quirk;

    .line 527
    .line 528
    if-eqz v7, :cond_e

    .line 529
    .line 530
    goto :goto_c

    .line 531
    :cond_e
    move v7, v14

    .line 532
    :goto_d
    if-eq v7, v15, :cond_10

    .line 533
    .line 534
    if-ne v7, v14, :cond_f

    .line 535
    .line 536
    :goto_e
    const/4 v12, 0x0

    .line 537
    goto :goto_f

    .line 538
    :cond_f
    new-instance v0, Ljava/lang/AssertionError;

    .line 539
    .line 540
    const-string v1, "Undefined targetAspectRatio: "

    .line 541
    .line 542
    invoke-static {v7, v1}, Lkx/a;->h(ILjava/lang/String;)Ljava/lang/String;

    .line 543
    .line 544
    .line 545
    move-result-object v1

    .line 546
    invoke-direct {v0, v1}, Ljava/lang/AssertionError;-><init>(Ljava/lang/Object;)V

    .line 547
    .line 548
    .line 549
    throw v0

    .line 550
    :cond_10
    const/16 v7, 0x100

    .line 551
    .line 552
    invoke-virtual {v0, v7}, Lu/c1;->l(I)Lh0/l;

    .line 553
    .line 554
    .line 555
    move-result-object v13

    .line 556
    iget-object v13, v13, Lh0/l;->f:Ljava/util/HashMap;

    .line 557
    .line 558
    invoke-static {v7}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 559
    .line 560
    .line 561
    move-result-object v7

    .line 562
    invoke-virtual {v13, v7}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 563
    .line 564
    .line 565
    move-result-object v7

    .line 566
    check-cast v7, Landroid/util/Size;

    .line 567
    .line 568
    if-nez v7, :cond_11

    .line 569
    .line 570
    goto :goto_e

    .line 571
    :cond_11
    new-instance v12, Landroid/util/Rational;

    .line 572
    .line 573
    invoke-virtual {v7}, Landroid/util/Size;->getWidth()I

    .line 574
    .line 575
    .line 576
    move-result v13

    .line 577
    invoke-virtual {v7}, Landroid/util/Size;->getHeight()I

    .line 578
    .line 579
    .line 580
    move-result v7

    .line 581
    invoke-direct {v12, v13, v7}, Landroid/util/Rational;-><init>(II)V

    .line 582
    .line 583
    .line 584
    :goto_f
    if-nez v12, :cond_12

    .line 585
    .line 586
    goto :goto_11

    .line 587
    :cond_12
    new-instance v7, Ljava/util/ArrayList;

    .line 588
    .line 589
    invoke-direct {v7}, Ljava/util/ArrayList;-><init>()V

    .line 590
    .line 591
    .line 592
    new-instance v13, Ljava/util/ArrayList;

    .line 593
    .line 594
    invoke-direct {v13}, Ljava/util/ArrayList;-><init>()V

    .line 595
    .line 596
    .line 597
    invoke-interface {v6}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 598
    .line 599
    .line 600
    move-result-object v6

    .line 601
    :goto_10
    invoke-interface {v6}, Ljava/util/Iterator;->hasNext()Z

    .line 602
    .line 603
    .line 604
    move-result v14

    .line 605
    if-eqz v14, :cond_14

    .line 606
    .line 607
    invoke-interface {v6}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 608
    .line 609
    .line 610
    move-result-object v14

    .line 611
    check-cast v14, Landroid/util/Size;

    .line 612
    .line 613
    invoke-static {v12, v14}, Li0/b;->a(Landroid/util/Rational;Landroid/util/Size;)Z

    .line 614
    .line 615
    .line 616
    move-result v15

    .line 617
    if-eqz v15, :cond_13

    .line 618
    .line 619
    invoke-virtual {v7, v14}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 620
    .line 621
    .line 622
    goto :goto_10

    .line 623
    :cond_13
    invoke-virtual {v13, v14}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 624
    .line 625
    .line 626
    goto :goto_10

    .line 627
    :cond_14
    const/4 v14, 0x0

    .line 628
    invoke-virtual {v13, v14, v7}, Ljava/util/ArrayList;->addAll(ILjava/util/Collection;)Z

    .line 629
    .line 630
    .line 631
    move-object v6, v13

    .line 632
    :goto_11
    iget-object v7, v0, Lu/c1;->A:Lro/f;

    .line 633
    .line 634
    sget-object v12, Lh0/h2;->h:Ljava/util/LinkedHashMap;

    .line 635
    .line 636
    invoke-static {v5}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 637
    .line 638
    .line 639
    move-result-object v5

    .line 640
    invoke-virtual {v12, v5}, Ljava/util/LinkedHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 641
    .line 642
    .line 643
    move-result-object v5

    .line 644
    check-cast v5, Lh0/g2;

    .line 645
    .line 646
    if-nez v5, :cond_15

    .line 647
    .line 648
    sget-object v5, Lh0/g2;->d:Lh0/g2;

    .line 649
    .line 650
    :cond_15
    iget-object v7, v7, Lro/f;->e:Ljava/lang/Object;

    .line 651
    .line 652
    check-cast v7, Landroidx/camera/camera2/internal/compat/quirk/ExtraCroppingQuirk;

    .line 653
    .line 654
    if-nez v7, :cond_16

    .line 655
    .line 656
    goto :goto_13

    .line 657
    :cond_16
    invoke-static {v5}, Landroidx/camera/camera2/internal/compat/quirk/ExtraCroppingQuirk;->b(Lh0/g2;)Landroid/util/Size;

    .line 658
    .line 659
    .line 660
    move-result-object v5

    .line 661
    if-nez v5, :cond_17

    .line 662
    .line 663
    goto :goto_13

    .line 664
    :cond_17
    new-instance v7, Ljava/util/ArrayList;

    .line 665
    .line 666
    invoke-direct {v7}, Ljava/util/ArrayList;-><init>()V

    .line 667
    .line 668
    .line 669
    invoke-virtual {v7, v5}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 670
    .line 671
    .line 672
    invoke-interface {v6}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 673
    .line 674
    .line 675
    move-result-object v6

    .line 676
    :cond_18
    :goto_12
    invoke-interface {v6}, Ljava/util/Iterator;->hasNext()Z

    .line 677
    .line 678
    .line 679
    move-result v12

    .line 680
    if-eqz v12, :cond_19

    .line 681
    .line 682
    invoke-interface {v6}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 683
    .line 684
    .line 685
    move-result-object v12

    .line 686
    check-cast v12, Landroid/util/Size;

    .line 687
    .line 688
    invoke-virtual {v12, v5}, Landroid/util/Size;->equals(Ljava/lang/Object;)Z

    .line 689
    .line 690
    .line 691
    move-result v13

    .line 692
    if-nez v13, :cond_18

    .line 693
    .line 694
    invoke-virtual {v7, v12}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 695
    .line 696
    .line 697
    goto :goto_12

    .line 698
    :cond_19
    move-object v6, v7

    .line 699
    :goto_13
    invoke-virtual {v3, v6}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 700
    .line 701
    .line 702
    goto/16 :goto_b

    .line 703
    .line 704
    :cond_1a
    iget-boolean v2, v1, Lu/d;->f:Z

    .line 705
    .line 706
    if-eqz v2, :cond_1f

    .line 707
    .line 708
    iget-object v2, v0, Lu/c1;->C:Lu/t0;

    .line 709
    .line 710
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 711
    .line 712
    .line 713
    invoke-virtual {v3}, Ljava/util/ArrayList;->isEmpty()Z

    .line 714
    .line 715
    .line 716
    move-result v2

    .line 717
    if-eqz v2, :cond_1b

    .line 718
    .line 719
    sget-object v2, Lmx0/s;->d:Lmx0/s;

    .line 720
    .line 721
    goto :goto_16

    .line 722
    :cond_1b
    invoke-static {v3}, Lu/t0;->a(Ljava/util/List;)Ljava/util/List;

    .line 723
    .line 724
    .line 725
    move-result-object v2

    .line 726
    check-cast v2, Ljava/lang/Iterable;

    .line 727
    .line 728
    new-instance v4, Ljava/util/ArrayList;

    .line 729
    .line 730
    const/16 v5, 0xa

    .line 731
    .line 732
    invoke-static {v2, v5}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 733
    .line 734
    .line 735
    move-result v5

    .line 736
    invoke-direct {v4, v5}, Ljava/util/ArrayList;-><init>(I)V

    .line 737
    .line 738
    .line 739
    invoke-interface {v2}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 740
    .line 741
    .line 742
    move-result-object v2

    .line 743
    :goto_14
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    .line 744
    .line 745
    .line 746
    move-result v5

    .line 747
    if-eqz v5, :cond_1d

    .line 748
    .line 749
    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 750
    .line 751
    .line 752
    move-result-object v5

    .line 753
    check-cast v5, Landroid/util/Size;

    .line 754
    .line 755
    invoke-virtual {v3}, Ljava/util/ArrayList;->size()I

    .line 756
    .line 757
    .line 758
    move-result v6

    .line 759
    new-instance v7, Ljava/util/ArrayList;

    .line 760
    .line 761
    invoke-direct {v7, v6}, Ljava/util/ArrayList;-><init>(I)V

    .line 762
    .line 763
    .line 764
    const/4 v13, 0x0

    .line 765
    :goto_15
    if-ge v13, v6, :cond_1c

    .line 766
    .line 767
    invoke-virtual {v7, v5}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 768
    .line 769
    .line 770
    add-int/lit8 v13, v13, 0x1

    .line 771
    .line 772
    goto :goto_15

    .line 773
    :cond_1c
    invoke-virtual {v4, v7}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 774
    .line 775
    .line 776
    goto :goto_14

    .line 777
    :cond_1d
    move-object v2, v4

    .line 778
    :cond_1e
    :goto_16
    move-object v12, v2

    .line 779
    goto/16 :goto_1b

    .line 780
    .line 781
    :cond_1f
    invoke-virtual {v3}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 782
    .line 783
    .line 784
    move-result-object v2

    .line 785
    move/from16 v4, v16

    .line 786
    .line 787
    :goto_17
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    .line 788
    .line 789
    .line 790
    move-result v5

    .line 791
    if-eqz v5, :cond_20

    .line 792
    .line 793
    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 794
    .line 795
    .line 796
    move-result-object v5

    .line 797
    check-cast v5, Ljava/util/List;

    .line 798
    .line 799
    invoke-interface {v5}, Ljava/util/List;->size()I

    .line 800
    .line 801
    .line 802
    move-result v5

    .line 803
    mul-int/2addr v4, v5

    .line 804
    goto :goto_17

    .line 805
    :cond_20
    if-eqz v4, :cond_6a

    .line 806
    .line 807
    new-instance v2, Ljava/util/ArrayList;

    .line 808
    .line 809
    invoke-direct {v2}, Ljava/util/ArrayList;-><init>()V

    .line 810
    .line 811
    .line 812
    const/4 v5, 0x0

    .line 813
    :goto_18
    if-ge v5, v4, :cond_21

    .line 814
    .line 815
    new-instance v6, Ljava/util/ArrayList;

    .line 816
    .line 817
    invoke-direct {v6}, Ljava/util/ArrayList;-><init>()V

    .line 818
    .line 819
    .line 820
    invoke-virtual {v2, v6}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 821
    .line 822
    .line 823
    add-int/lit8 v5, v5, 0x1

    .line 824
    .line 825
    goto :goto_18

    .line 826
    :cond_21
    const/4 v14, 0x0

    .line 827
    invoke-virtual {v3, v14}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 828
    .line 829
    .line 830
    move-result-object v5

    .line 831
    check-cast v5, Ljava/util/List;

    .line 832
    .line 833
    invoke-interface {v5}, Ljava/util/List;->size()I

    .line 834
    .line 835
    .line 836
    move-result v5

    .line 837
    div-int v5, v4, v5

    .line 838
    .line 839
    move v7, v4

    .line 840
    const/4 v6, 0x0

    .line 841
    :goto_19
    invoke-virtual {v3}, Ljava/util/ArrayList;->size()I

    .line 842
    .line 843
    .line 844
    move-result v13

    .line 845
    if-ge v6, v13, :cond_1e

    .line 846
    .line 847
    invoke-virtual {v3, v6}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 848
    .line 849
    .line 850
    move-result-object v13

    .line 851
    check-cast v13, Ljava/util/List;

    .line 852
    .line 853
    const/4 v14, 0x0

    .line 854
    :goto_1a
    if-ge v14, v4, :cond_22

    .line 855
    .line 856
    invoke-virtual {v2, v14}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 857
    .line 858
    .line 859
    move-result-object v15

    .line 860
    check-cast v15, Ljava/util/List;

    .line 861
    .line 862
    rem-int v18, v14, v7

    .line 863
    .line 864
    div-int v12, v18, v5

    .line 865
    .line 866
    invoke-interface {v13, v12}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 867
    .line 868
    .line 869
    move-result-object v12

    .line 870
    check-cast v12, Landroid/util/Size;

    .line 871
    .line 872
    invoke-interface {v15, v12}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 873
    .line 874
    .line 875
    add-int/lit8 v14, v14, 0x1

    .line 876
    .line 877
    goto :goto_1a

    .line 878
    :cond_22
    invoke-virtual {v3}, Ljava/util/ArrayList;->size()I

    .line 879
    .line 880
    .line 881
    move-result v12

    .line 882
    add-int/lit8 v12, v12, -0x1

    .line 883
    .line 884
    if-ge v6, v12, :cond_23

    .line 885
    .line 886
    add-int/lit8 v7, v6, 0x1

    .line 887
    .line 888
    invoke-virtual {v3, v7}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 889
    .line 890
    .line 891
    move-result-object v7

    .line 892
    check-cast v7, Ljava/util/List;

    .line 893
    .line 894
    invoke-interface {v7}, Ljava/util/List;->size()I

    .line 895
    .line 896
    .line 897
    move-result v7

    .line 898
    div-int v7, v5, v7

    .line 899
    .line 900
    move/from16 v40, v7

    .line 901
    .line 902
    move v7, v5

    .line 903
    move/from16 v5, v40

    .line 904
    .line 905
    :cond_23
    add-int/lit8 v6, v6, 0x1

    .line 906
    .line 907
    goto :goto_19

    .line 908
    :goto_1b
    new-instance v13, Ljava/util/HashMap;

    .line 909
    .line 910
    invoke-direct {v13}, Ljava/util/HashMap;-><init>()V

    .line 911
    .line 912
    .line 913
    new-instance v14, Ljava/util/HashMap;

    .line 914
    .line 915
    invoke-direct {v14}, Ljava/util/HashMap;-><init>()V

    .line 916
    .line 917
    .line 918
    new-instance v7, Ljava/util/HashMap;

    .line 919
    .line 920
    invoke-direct {v7}, Ljava/util/HashMap;-><init>()V

    .line 921
    .line 922
    .line 923
    new-instance v8, Ljava/util/HashMap;

    .line 924
    .line 925
    invoke-direct {v8}, Ljava/util/HashMap;-><init>()V

    .line 926
    .line 927
    .line 928
    sget-object v2, Lu/b1;->a:Lh0/g;

    .line 929
    .line 930
    invoke-virtual/range {p2 .. p2}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 931
    .line 932
    .line 933
    move-result-object v2

    .line 934
    :cond_24
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    .line 935
    .line 936
    .line 937
    move-result v3

    .line 938
    if-eqz v3, :cond_25

    .line 939
    .line 940
    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 941
    .line 942
    .line 943
    move-result-object v3

    .line 944
    check-cast v3, Lh0/e;

    .line 945
    .line 946
    iget-object v4, v3, Lh0/e;->e:Ljava/util/List;

    .line 947
    .line 948
    const-string v5, "getCaptureTypes(...)"

    .line 949
    .line 950
    invoke-static {v4, v5}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 951
    .line 952
    .line 953
    const/4 v5, 0x0

    .line 954
    invoke-interface {v4, v5}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 955
    .line 956
    .line 957
    move-result-object v4

    .line 958
    check-cast v4, Lh0/q2;

    .line 959
    .line 960
    iget-object v3, v3, Lh0/e;->f:Lh0/q0;

    .line 961
    .line 962
    invoke-static {v3}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 963
    .line 964
    .line 965
    invoke-static {v4}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 966
    .line 967
    .line 968
    invoke-static {v3, v4}, Lu/b1;->c(Lh0/q0;Lh0/q2;)Z

    .line 969
    .line 970
    .line 971
    move-result v3

    .line 972
    if-eqz v3, :cond_24

    .line 973
    .line 974
    :goto_1c
    move/from16 v2, v16

    .line 975
    .line 976
    goto :goto_1d

    .line 977
    :cond_25
    invoke-virtual/range {p4 .. p4}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 978
    .line 979
    .line 980
    move-result-object v2

    .line 981
    :cond_26
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    .line 982
    .line 983
    .line 984
    move-result v3

    .line 985
    if-eqz v3, :cond_27

    .line 986
    .line 987
    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 988
    .line 989
    .line 990
    move-result-object v3

    .line 991
    check-cast v3, Lh0/o2;

    .line 992
    .line 993
    invoke-interface {v3}, Lh0/o2;->J()Lh0/q2;

    .line 994
    .line 995
    .line 996
    move-result-object v4

    .line 997
    const-string v5, "getCaptureType(...)"

    .line 998
    .line 999
    invoke-static {v4, v5}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1000
    .line 1001
    .line 1002
    invoke-static {v3, v4}, Lu/b1;->c(Lh0/q0;Lh0/q2;)Z

    .line 1003
    .line 1004
    .line 1005
    move-result v3

    .line 1006
    if-eqz v3, :cond_26

    .line 1007
    .line 1008
    goto :goto_1c

    .line 1009
    :cond_27
    const/4 v2, 0x0

    .line 1010
    :goto_1d
    iget-boolean v3, v1, Lu/d;->f:Z

    .line 1011
    .line 1012
    invoke-virtual/range {p2 .. p2}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 1013
    .line 1014
    .line 1015
    move-result-object v4

    .line 1016
    const v6, 0x7fffffff

    .line 1017
    .line 1018
    .line 1019
    :goto_1e
    invoke-interface {v4}, Ljava/util/Iterator;->hasNext()Z

    .line 1020
    .line 1021
    .line 1022
    move-result v5

    .line 1023
    if-eqz v5, :cond_28

    .line 1024
    .line 1025
    invoke-interface {v4}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 1026
    .line 1027
    .line 1028
    move-result-object v5

    .line 1029
    check-cast v5, Lh0/e;

    .line 1030
    .line 1031
    iget v15, v5, Lh0/e;->b:I

    .line 1032
    .line 1033
    iget-object v5, v5, Lh0/e;->c:Landroid/util/Size;

    .line 1034
    .line 1035
    invoke-virtual {v0, v15, v5, v3}, Lu/c1;->e(ILandroid/util/Size;Z)I

    .line 1036
    .line 1037
    .line 1038
    move-result v5

    .line 1039
    invoke-static {v6, v5}, Ljava/lang/Math;->min(II)I

    .line 1040
    .line 1041
    .line 1042
    move-result v6

    .line 1043
    goto :goto_1e

    .line 1044
    :cond_28
    iget-boolean v3, v0, Lu/c1;->s:Z

    .line 1045
    .line 1046
    if-eqz v3, :cond_2b

    .line 1047
    .line 1048
    if-nez v2, :cond_2b

    .line 1049
    .line 1050
    invoke-interface {v12}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 1051
    .line 1052
    .line 1053
    move-result-object v15

    .line 1054
    const/4 v2, 0x0

    .line 1055
    :goto_1f
    invoke-interface {v15}, Ljava/util/Iterator;->hasNext()Z

    .line 1056
    .line 1057
    .line 1058
    move-result v3

    .line 1059
    if-eqz v3, :cond_2a

    .line 1060
    .line 1061
    invoke-interface {v15}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 1062
    .line 1063
    .line 1064
    move-result-object v2

    .line 1065
    move-object v3, v2

    .line 1066
    check-cast v3, Ljava/util/List;

    .line 1067
    .line 1068
    move-object/from16 v2, p2

    .line 1069
    .line 1070
    move-object/from16 v4, p4

    .line 1071
    .line 1072
    move-object/from16 v5, p5

    .line 1073
    .line 1074
    invoke-virtual/range {v0 .. v8}, Lu/c1;->k(Lu/d;Ljava/util/ArrayList;Ljava/util/List;Ljava/util/ArrayList;Ljava/util/ArrayList;ILjava/util/HashMap;Ljava/util/HashMap;)Landroid/util/Pair;

    .line 1075
    .line 1076
    .line 1077
    move-result-object v3

    .line 1078
    move-object v4, v7

    .line 1079
    move-object v5, v8

    .line 1080
    iget-object v2, v3, Landroid/util/Pair;->first:Ljava/lang/Object;

    .line 1081
    .line 1082
    check-cast v2, Ljava/util/List;

    .line 1083
    .line 1084
    invoke-virtual {v0, v1, v2, v4, v5}, Lu/c1;->g(Lu/d;Ljava/util/List;Ljava/util/HashMap;Ljava/util/HashMap;)Ljava/util/List;

    .line 1085
    .line 1086
    .line 1087
    move-result-object v2

    .line 1088
    if-eqz v2, :cond_29

    .line 1089
    .line 1090
    goto :goto_20

    .line 1091
    :cond_29
    invoke-virtual {v4}, Ljava/util/HashMap;->clear()V

    .line 1092
    .line 1093
    .line 1094
    invoke-virtual {v5}, Ljava/util/HashMap;->clear()V

    .line 1095
    .line 1096
    .line 1097
    move-object v7, v4

    .line 1098
    move-object v8, v5

    .line 1099
    goto :goto_1f

    .line 1100
    :cond_2a
    move-object v4, v7

    .line 1101
    move-object v5, v8

    .line 1102
    :goto_20
    new-instance v3, Ljava/lang/StringBuilder;

    .line 1103
    .line 1104
    const-string v7, "orderedSurfaceConfigListForStreamUseCase = "

    .line 1105
    .line 1106
    invoke-direct {v3, v7}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 1107
    .line 1108
    .line 1109
    invoke-virtual {v3, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 1110
    .line 1111
    .line 1112
    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 1113
    .line 1114
    .line 1115
    move-result-object v3

    .line 1116
    invoke-static {v10, v3}, Ljp/v1;->c(Ljava/lang/String;Ljava/lang/String;)V

    .line 1117
    .line 1118
    .line 1119
    move-object v15, v2

    .line 1120
    goto :goto_21

    .line 1121
    :cond_2b
    move-object v4, v7

    .line 1122
    move-object v5, v8

    .line 1123
    const/4 v15, 0x0

    .line 1124
    :goto_21
    iget-object v2, v1, Lu/d;->i:Landroid/util/Range;

    .line 1125
    .line 1126
    invoke-interface {v12}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 1127
    .line 1128
    .line 1129
    move-result-object v12

    .line 1130
    const v3, 0x7fffffff

    .line 1131
    .line 1132
    .line 1133
    const v7, 0x7fffffff

    .line 1134
    .line 1135
    .line 1136
    const/16 v18, 0x0

    .line 1137
    .line 1138
    const/16 v19, 0x0

    .line 1139
    .line 1140
    const/16 v20, 0x0

    .line 1141
    .line 1142
    const/16 v21, 0x0

    .line 1143
    .line 1144
    :goto_22
    invoke-interface {v12}, Ljava/util/Iterator;->hasNext()Z

    .line 1145
    .line 1146
    .line 1147
    move-result v8

    .line 1148
    if-eqz v8, :cond_3b

    .line 1149
    .line 1150
    invoke-interface {v12}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 1151
    .line 1152
    .line 1153
    move-result-object v8

    .line 1154
    check-cast v8, Ljava/util/List;

    .line 1155
    .line 1156
    move/from16 v22, v7

    .line 1157
    .line 1158
    new-instance v7, Ljava/util/HashMap;

    .line 1159
    .line 1160
    invoke-direct {v7}, Ljava/util/HashMap;-><init>()V

    .line 1161
    .line 1162
    .line 1163
    move/from16 v23, v3

    .line 1164
    .line 1165
    move-object v3, v8

    .line 1166
    new-instance v8, Ljava/util/HashMap;

    .line 1167
    .line 1168
    invoke-direct {v8}, Ljava/util/HashMap;-><init>()V

    .line 1169
    .line 1170
    .line 1171
    move/from16 p3, v22

    .line 1172
    .line 1173
    move-object/from16 v22, v11

    .line 1174
    .line 1175
    move/from16 v11, p3

    .line 1176
    .line 1177
    move-object/from16 v25, v4

    .line 1178
    .line 1179
    move-object/from16 v26, v5

    .line 1180
    .line 1181
    move-object/from16 p3, v12

    .line 1182
    .line 1183
    move-object/from16 v24, v13

    .line 1184
    .line 1185
    move/from16 v12, v23

    .line 1186
    .line 1187
    move-object/from16 v4, p4

    .line 1188
    .line 1189
    move-object/from16 v5, p5

    .line 1190
    .line 1191
    move-object/from16 v23, v15

    .line 1192
    .line 1193
    move-object v15, v2

    .line 1194
    move-object/from16 v2, p2

    .line 1195
    .line 1196
    invoke-virtual/range {v0 .. v8}, Lu/c1;->k(Lu/d;Ljava/util/ArrayList;Ljava/util/List;Ljava/util/ArrayList;Ljava/util/ArrayList;ILjava/util/HashMap;Ljava/util/HashMap;)Landroid/util/Pair;

    .line 1197
    .line 1198
    .line 1199
    move-result-object v13

    .line 1200
    move-object v0, v7

    .line 1201
    move-object v1, v8

    .line 1202
    move-object v8, v3

    .line 1203
    move v7, v6

    .line 1204
    move-object v6, v2

    .line 1205
    iget-object v2, v13, Landroid/util/Pair;->first:Ljava/lang/Object;

    .line 1206
    .line 1207
    check-cast v2, Ljava/util/List;

    .line 1208
    .line 1209
    iget-object v3, v13, Landroid/util/Pair;->second:Ljava/lang/Object;

    .line 1210
    .line 1211
    check-cast v3, Ljava/lang/Integer;

    .line 1212
    .line 1213
    invoke-virtual {v3}, Ljava/lang/Integer;->intValue()I

    .line 1214
    .line 1215
    .line 1216
    move-result v13

    .line 1217
    sget-object v3, Lh0/k;->h:Landroid/util/Range;

    .line 1218
    .line 1219
    invoke-virtual {v3, v15}, Landroid/util/Range;->equals(Ljava/lang/Object;)Z

    .line 1220
    .line 1221
    .line 1222
    move-result v3

    .line 1223
    if-nez v3, :cond_2c

    .line 1224
    .line 1225
    if-ge v13, v7, :cond_2c

    .line 1226
    .line 1227
    invoke-virtual {v15}, Landroid/util/Range;->getUpper()Ljava/lang/Comparable;

    .line 1228
    .line 1229
    .line 1230
    move-result-object v3

    .line 1231
    check-cast v3, Ljava/lang/Integer;

    .line 1232
    .line 1233
    invoke-virtual {v3}, Ljava/lang/Integer;->intValue()I

    .line 1234
    .line 1235
    .line 1236
    move-result v3

    .line 1237
    if-ge v13, v3, :cond_2c

    .line 1238
    .line 1239
    const/16 v27, 0x0

    .line 1240
    .line 1241
    goto :goto_23

    .line 1242
    :cond_2c
    move/from16 v27, v16

    .line 1243
    .line 1244
    :goto_23
    new-instance v3, Ljava/util/HashMap;

    .line 1245
    .line 1246
    invoke-direct {v3}, Ljava/util/HashMap;-><init>()V

    .line 1247
    .line 1248
    .line 1249
    const/4 v4, 0x0

    .line 1250
    :goto_24
    invoke-interface {v2}, Ljava/util/List;->size()I

    .line 1251
    .line 1252
    .line 1253
    move-result v5

    .line 1254
    if-ge v4, v5, :cond_2f

    .line 1255
    .line 1256
    invoke-interface {v2, v4}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 1257
    .line 1258
    .line 1259
    move-result-object v5

    .line 1260
    check-cast v5, Lh0/h2;

    .line 1261
    .line 1262
    sget-object v28, Lb0/y;->c:Lb0/y;

    .line 1263
    .line 1264
    move-object/from16 v29, v2

    .line 1265
    .line 1266
    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 1267
    .line 1268
    .line 1269
    move-result-object v2

    .line 1270
    invoke-virtual {v0, v2}, Ljava/util/HashMap;->containsKey(Ljava/lang/Object;)Z

    .line 1271
    .line 1272
    .line 1273
    move-result v2

    .line 1274
    if-eqz v2, :cond_2d

    .line 1275
    .line 1276
    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 1277
    .line 1278
    .line 1279
    move-result-object v2

    .line 1280
    invoke-virtual {v0, v2}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 1281
    .line 1282
    .line 1283
    move-result-object v2

    .line 1284
    check-cast v2, Lh0/e;

    .line 1285
    .line 1286
    invoke-static {v2}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    .line 1287
    .line 1288
    .line 1289
    iget-object v2, v2, Lh0/e;->d:Lb0/y;

    .line 1290
    .line 1291
    goto :goto_25

    .line 1292
    :cond_2d
    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 1293
    .line 1294
    .line 1295
    move-result-object v2

    .line 1296
    invoke-virtual {v1, v2}, Ljava/util/HashMap;->containsKey(Ljava/lang/Object;)Z

    .line 1297
    .line 1298
    .line 1299
    move-result v2

    .line 1300
    if-eqz v2, :cond_2e

    .line 1301
    .line 1302
    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 1303
    .line 1304
    .line 1305
    move-result-object v2

    .line 1306
    invoke-virtual {v1, v2}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 1307
    .line 1308
    .line 1309
    move-result-object v2

    .line 1310
    check-cast v2, Lh0/o2;

    .line 1311
    .line 1312
    invoke-static {v2}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    .line 1313
    .line 1314
    .line 1315
    invoke-virtual {v9, v2}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 1316
    .line 1317
    .line 1318
    move-result-object v2

    .line 1319
    move-object/from16 v28, v2

    .line 1320
    .line 1321
    check-cast v28, Lb0/y;

    .line 1322
    .line 1323
    :cond_2e
    move-object/from16 v2, v28

    .line 1324
    .line 1325
    :goto_25
    invoke-virtual {v3, v5, v2}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 1326
    .line 1327
    .line 1328
    add-int/lit8 v4, v4, 0x1

    .line 1329
    .line 1330
    move-object/from16 v2, v29

    .line 1331
    .line 1332
    goto :goto_24

    .line 1333
    :cond_2f
    move-object/from16 v29, v2

    .line 1334
    .line 1335
    move-object/from16 v4, p4

    .line 1336
    .line 1337
    if-nez v20, :cond_33

    .line 1338
    .line 1339
    move-object/from16 v5, p5

    .line 1340
    .line 1341
    move/from16 v28, v7

    .line 1342
    .line 1343
    move-object/from16 v2, v29

    .line 1344
    .line 1345
    move-object v7, v0

    .line 1346
    move-object/from16 v29, v8

    .line 1347
    .line 1348
    move-object/from16 v0, p0

    .line 1349
    .line 1350
    move-object v8, v1

    .line 1351
    move-object/from16 v1, p1

    .line 1352
    .line 1353
    invoke-virtual/range {v0 .. v5}, Lu/c1;->a(Lu/d;Ljava/util/List;Ljava/util/Map;Ljava/util/List;Ljava/util/List;)Z

    .line 1354
    .line 1355
    .line 1356
    move-result v3

    .line 1357
    if-eqz v3, :cond_34

    .line 1358
    .line 1359
    const v3, 0x7fffffff

    .line 1360
    .line 1361
    .line 1362
    if-ne v12, v3, :cond_30

    .line 1363
    .line 1364
    goto :goto_26

    .line 1365
    :cond_30
    if-ge v12, v13, :cond_31

    .line 1366
    .line 1367
    :goto_26
    move v3, v13

    .line 1368
    move-object/from16 v18, v29

    .line 1369
    .line 1370
    goto :goto_27

    .line 1371
    :cond_31
    move v3, v12

    .line 1372
    :goto_27
    if-eqz v27, :cond_35

    .line 1373
    .line 1374
    if-eqz v21, :cond_32

    .line 1375
    .line 1376
    move/from16 v33, v11

    .line 1377
    .line 1378
    move v3, v13

    .line 1379
    move-object/from16 v31, v19

    .line 1380
    .line 1381
    move-object/from16 v30, v29

    .line 1382
    .line 1383
    goto/16 :goto_2c

    .line 1384
    .line 1385
    :cond_32
    move v3, v13

    .line 1386
    move/from16 v20, v16

    .line 1387
    .line 1388
    move-object/from16 v18, v29

    .line 1389
    .line 1390
    goto :goto_28

    .line 1391
    :cond_33
    move/from16 v28, v7

    .line 1392
    .line 1393
    move-object/from16 v2, v29

    .line 1394
    .line 1395
    move-object v7, v0

    .line 1396
    move-object/from16 v29, v8

    .line 1397
    .line 1398
    move-object/from16 v0, p0

    .line 1399
    .line 1400
    move-object v8, v1

    .line 1401
    move-object/from16 v1, p1

    .line 1402
    .line 1403
    :cond_34
    move v3, v12

    .line 1404
    :cond_35
    :goto_28
    if-eqz v23, :cond_39

    .line 1405
    .line 1406
    if-nez v21, :cond_39

    .line 1407
    .line 1408
    invoke-virtual {v0, v1, v2, v7, v8}, Lu/c1;->g(Lu/d;Ljava/util/List;Ljava/util/HashMap;Ljava/util/HashMap;)Ljava/util/List;

    .line 1409
    .line 1410
    .line 1411
    move-result-object v2

    .line 1412
    if-eqz v2, :cond_39

    .line 1413
    .line 1414
    const v2, 0x7fffffff

    .line 1415
    .line 1416
    .line 1417
    if-ne v11, v2, :cond_36

    .line 1418
    .line 1419
    goto :goto_29

    .line 1420
    :cond_36
    if-ge v11, v13, :cond_37

    .line 1421
    .line 1422
    :goto_29
    move v7, v13

    .line 1423
    move-object/from16 v19, v29

    .line 1424
    .line 1425
    goto :goto_2a

    .line 1426
    :cond_37
    move v7, v11

    .line 1427
    :goto_2a
    if-eqz v27, :cond_3a

    .line 1428
    .line 1429
    if-eqz v20, :cond_38

    .line 1430
    .line 1431
    move/from16 v33, v13

    .line 1432
    .line 1433
    move-object/from16 v30, v18

    .line 1434
    .line 1435
    move-object/from16 v31, v29

    .line 1436
    .line 1437
    goto :goto_2c

    .line 1438
    :cond_38
    move v7, v13

    .line 1439
    move/from16 v21, v16

    .line 1440
    .line 1441
    move-object/from16 v19, v29

    .line 1442
    .line 1443
    goto :goto_2b

    .line 1444
    :cond_39
    move v7, v11

    .line 1445
    :cond_3a
    :goto_2b
    move-object/from16 v12, p3

    .line 1446
    .line 1447
    move-object v2, v15

    .line 1448
    move-object/from16 v11, v22

    .line 1449
    .line 1450
    move-object/from16 v15, v23

    .line 1451
    .line 1452
    move-object/from16 v13, v24

    .line 1453
    .line 1454
    move-object/from16 v4, v25

    .line 1455
    .line 1456
    move-object/from16 v5, v26

    .line 1457
    .line 1458
    move/from16 v6, v28

    .line 1459
    .line 1460
    goto/16 :goto_22

    .line 1461
    .line 1462
    :cond_3b
    move-object/from16 v6, p2

    .line 1463
    .line 1464
    move v12, v3

    .line 1465
    move-object/from16 v25, v4

    .line 1466
    .line 1467
    move-object/from16 v26, v5

    .line 1468
    .line 1469
    move-object/from16 v22, v11

    .line 1470
    .line 1471
    move-object/from16 v24, v13

    .line 1472
    .line 1473
    move-object/from16 v23, v15

    .line 1474
    .line 1475
    move-object/from16 v4, p4

    .line 1476
    .line 1477
    move-object v15, v2

    .line 1478
    move v11, v7

    .line 1479
    move/from16 v33, v11

    .line 1480
    .line 1481
    move-object/from16 v30, v18

    .line 1482
    .line 1483
    move-object/from16 v31, v19

    .line 1484
    .line 1485
    :goto_2c
    iget-boolean v2, v1, Lu/d;->g:Z

    .line 1486
    .line 1487
    if-eqz v2, :cond_3d

    .line 1488
    .line 1489
    sget-object v2, Lh0/k;->h:Landroid/util/Range;

    .line 1490
    .line 1491
    invoke-virtual {v2, v15}, Landroid/util/Range;->equals(Ljava/lang/Object;)Z

    .line 1492
    .line 1493
    .line 1494
    move-result v2

    .line 1495
    if-nez v2, :cond_3d

    .line 1496
    .line 1497
    const v2, 0x7fffffff

    .line 1498
    .line 1499
    .line 1500
    if-eq v3, v2, :cond_3c

    .line 1501
    .line 1502
    invoke-virtual {v15}, Landroid/util/Range;->getUpper()Ljava/lang/Comparable;

    .line 1503
    .line 1504
    .line 1505
    move-result-object v2

    .line 1506
    check-cast v2, Ljava/lang/Integer;

    .line 1507
    .line 1508
    invoke-virtual {v2}, Ljava/lang/Integer;->intValue()I

    .line 1509
    .line 1510
    .line 1511
    move-result v2

    .line 1512
    if-ge v3, v2, :cond_3d

    .line 1513
    .line 1514
    :cond_3c
    new-instance v34, Lu/c;

    .line 1515
    .line 1516
    const/16 v35, 0x0

    .line 1517
    .line 1518
    const/16 v36, 0x0

    .line 1519
    .line 1520
    const v37, 0x7fffffff

    .line 1521
    .line 1522
    .line 1523
    const v38, 0x7fffffff

    .line 1524
    .line 1525
    .line 1526
    const v39, 0x7fffffff

    .line 1527
    .line 1528
    .line 1529
    invoke-direct/range {v34 .. v39}, Lu/c;-><init>(Ljava/util/List;Ljava/util/List;III)V

    .line 1530
    .line 1531
    .line 1532
    move-object/from16 v2, v34

    .line 1533
    .line 1534
    goto :goto_2d

    .line 1535
    :cond_3d
    new-instance v29, Lu/c;

    .line 1536
    .line 1537
    const v34, 0x7fffffff

    .line 1538
    .line 1539
    .line 1540
    move/from16 v32, v3

    .line 1541
    .line 1542
    invoke-direct/range {v29 .. v34}, Lu/c;-><init>(Ljava/util/List;Ljava/util/List;III)V

    .line 1543
    .line 1544
    .line 1545
    move-object/from16 v2, v29

    .line 1546
    .line 1547
    :goto_2d
    new-instance v3, Ljava/lang/StringBuilder;

    .line 1548
    .line 1549
    const-string v5, "resolveSpecsBySettings: bestSizesAndFps = "

    .line 1550
    .line 1551
    invoke-direct {v3, v5}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 1552
    .line 1553
    .line 1554
    invoke-virtual {v3, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 1555
    .line 1556
    .line 1557
    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 1558
    .line 1559
    .line 1560
    move-result-object v3

    .line 1561
    invoke-static {v10, v3}, Ljp/v1;->c(Ljava/lang/String;Ljava/lang/String;)V

    .line 1562
    .line 1563
    .line 1564
    iget-object v3, v2, Lu/c;->a:Ljava/util/List;

    .line 1565
    .line 1566
    iget v5, v2, Lu/c;->c:I

    .line 1567
    .line 1568
    iget-object v7, v2, Lu/c;->b:Ljava/util/List;

    .line 1569
    .line 1570
    iget v8, v2, Lu/c;->d:I

    .line 1571
    .line 1572
    iget v2, v2, Lu/c;->e:I

    .line 1573
    .line 1574
    if-eqz v3, :cond_69

    .line 1575
    .line 1576
    sget-object v10, Lh0/k;->h:Landroid/util/Range;

    .line 1577
    .line 1578
    iget-object v11, v1, Lu/d;->i:Landroid/util/Range;

    .line 1579
    .line 1580
    invoke-virtual {v10, v11}, Landroid/util/Range;->equals(Ljava/lang/Object;)Z

    .line 1581
    .line 1582
    .line 1583
    move-result v11

    .line 1584
    if-nez v11, :cond_41

    .line 1585
    .line 1586
    iget-boolean v10, v1, Lu/d;->f:Z

    .line 1587
    .line 1588
    if-eqz v10, :cond_3e

    .line 1589
    .line 1590
    iget-object v10, v0, Lu/c1;->C:Lu/t0;

    .line 1591
    .line 1592
    invoke-virtual {v10, v3}, Lu/t0;->b(Ljava/util/List;)[Landroid/util/Range;

    .line 1593
    .line 1594
    .line 1595
    move-result-object v10

    .line 1596
    goto :goto_2e

    .line 1597
    :cond_3e
    iget-object v10, v0, Lu/c1;->m:Lv/b;

    .line 1598
    .line 1599
    sget-object v11, Landroid/hardware/camera2/CameraCharacteristics;->CONTROL_AE_AVAILABLE_TARGET_FPS_RANGES:Landroid/hardware/camera2/CameraCharacteristics$Key;

    .line 1600
    .line 1601
    invoke-virtual {v10, v11}, Lv/b;->a(Landroid/hardware/camera2/CameraCharacteristics$Key;)Ljava/lang/Object;

    .line 1602
    .line 1603
    .line 1604
    move-result-object v10

    .line 1605
    check-cast v10, [Landroid/util/Range;

    .line 1606
    .line 1607
    :goto_2e
    iget-object v11, v1, Lu/d;->i:Landroid/util/Range;

    .line 1608
    .line 1609
    invoke-static {v11, v5, v10}, Lu/c1;->d(Landroid/util/Range;I[Landroid/util/Range;)Landroid/util/Range;

    .line 1610
    .line 1611
    .line 1612
    move-result-object v11

    .line 1613
    iget-boolean v12, v1, Lu/d;->g:Z

    .line 1614
    .line 1615
    if-nez v12, :cond_3f

    .line 1616
    .line 1617
    iget-boolean v12, v1, Lu/d;->j:Z

    .line 1618
    .line 1619
    if-eqz v12, :cond_40

    .line 1620
    .line 1621
    :cond_3f
    iget-object v12, v1, Lu/d;->i:Landroid/util/Range;

    .line 1622
    .line 1623
    invoke-virtual {v11, v12}, Landroid/util/Range;->equals(Ljava/lang/Object;)Z

    .line 1624
    .line 1625
    .line 1626
    move-result v12

    .line 1627
    new-instance v13, Ljava/lang/StringBuilder;

    .line 1628
    .line 1629
    const-string v15, "Target FPS range "

    .line 1630
    .line 1631
    invoke-direct {v13, v15}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 1632
    .line 1633
    .line 1634
    iget-object v15, v1, Lu/d;->i:Landroid/util/Range;

    .line 1635
    .line 1636
    invoke-virtual {v13, v15}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 1637
    .line 1638
    .line 1639
    const-string v15, " is not supported. Max FPS supported by the calculated best combination: "

    .line 1640
    .line 1641
    invoke-virtual {v13, v15}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 1642
    .line 1643
    .line 1644
    invoke-virtual {v13, v5}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 1645
    .line 1646
    .line 1647
    const-string v15, ". Calculated best FPS range for device: "

    .line 1648
    .line 1649
    invoke-virtual {v13, v15}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 1650
    .line 1651
    .line 1652
    invoke-virtual {v13, v11}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 1653
    .line 1654
    .line 1655
    const-string v15, ". Device supported FPS ranges: "

    .line 1656
    .line 1657
    invoke-virtual {v13, v15}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 1658
    .line 1659
    .line 1660
    invoke-static {v10}, Ljava/util/Arrays;->toString([Ljava/lang/Object;)Ljava/lang/String;

    .line 1661
    .line 1662
    .line 1663
    move-result-object v10

    .line 1664
    invoke-virtual {v13, v10}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 1665
    .line 1666
    .line 1667
    invoke-virtual {v13}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 1668
    .line 1669
    .line 1670
    move-result-object v10

    .line 1671
    invoke-static {v12, v10}, Ljp/ed;->b(ZLjava/lang/String;)V

    .line 1672
    .line 1673
    .line 1674
    :cond_40
    move-object v10, v11

    .line 1675
    goto :goto_2f

    .line 1676
    :cond_41
    iget-boolean v11, v1, Lu/d;->f:Z

    .line 1677
    .line 1678
    if-eqz v11, :cond_42

    .line 1679
    .line 1680
    iget-object v10, v0, Lu/c1;->C:Lu/t0;

    .line 1681
    .line 1682
    invoke-virtual {v10, v3}, Lu/t0;->b(Ljava/util/List;)[Landroid/util/Range;

    .line 1683
    .line 1684
    .line 1685
    move-result-object v10

    .line 1686
    sget-object v11, Lu/t0;->e:Landroid/util/Range;

    .line 1687
    .line 1688
    invoke-static {v11, v5, v10}, Lu/c1;->d(Landroid/util/Range;I[Landroid/util/Range;)Landroid/util/Range;

    .line 1689
    .line 1690
    .line 1691
    move-result-object v10

    .line 1692
    :cond_42
    :goto_2f
    invoke-virtual {v4}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 1693
    .line 1694
    .line 1695
    move-result-object v11

    .line 1696
    :goto_30
    invoke-interface {v11}, Ljava/util/Iterator;->hasNext()Z

    .line 1697
    .line 1698
    .line 1699
    move-result v12

    .line 1700
    if-eqz v12, :cond_48

    .line 1701
    .line 1702
    invoke-interface {v11}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 1703
    .line 1704
    .line 1705
    move-result-object v12

    .line 1706
    check-cast v12, Lh0/o2;

    .line 1707
    .line 1708
    invoke-virtual {v4, v12}, Ljava/util/ArrayList;->indexOf(Ljava/lang/Object;)I

    .line 1709
    .line 1710
    .line 1711
    move-result v13

    .line 1712
    invoke-static {v13}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 1713
    .line 1714
    .line 1715
    move-result-object v13

    .line 1716
    move-object/from16 v15, p5

    .line 1717
    .line 1718
    invoke-virtual {v15, v13}, Ljava/util/ArrayList;->indexOf(Ljava/lang/Object;)I

    .line 1719
    .line 1720
    .line 1721
    move-result v13

    .line 1722
    invoke-interface {v3, v13}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 1723
    .line 1724
    .line 1725
    move-result-object v13

    .line 1726
    check-cast v13, Landroid/util/Size;

    .line 1727
    .line 1728
    invoke-static {v13}, Lh0/k;->a(Landroid/util/Size;)Lss/b;

    .line 1729
    .line 1730
    .line 1731
    move-result-object v13

    .line 1732
    move-object/from16 p3, v11

    .line 1733
    .line 1734
    iget-boolean v11, v1, Lu/d;->f:Z

    .line 1735
    .line 1736
    invoke-static {v11}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 1737
    .line 1738
    .line 1739
    move-result-object v11

    .line 1740
    iput-object v11, v13, Lss/b;->h:Ljava/lang/Object;

    .line 1741
    .line 1742
    invoke-virtual {v9, v12}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 1743
    .line 1744
    .line 1745
    move-result-object v11

    .line 1746
    check-cast v11, Lb0/y;

    .line 1747
    .line 1748
    invoke-virtual {v11}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1749
    .line 1750
    .line 1751
    iput-object v11, v13, Lss/b;->g:Ljava/lang/Object;

    .line 1752
    .line 1753
    const-string v11, "useCaseConfig"

    .line 1754
    .line 1755
    invoke-static {v12, v11}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1756
    .line 1757
    .line 1758
    invoke-static {}, Lh0/j1;->c()Lh0/j1;

    .line 1759
    .line 1760
    .line 1761
    move-result-object v11

    .line 1762
    sget-object v9, Lt/a;->g:Lh0/g;

    .line 1763
    .line 1764
    invoke-interface {v12, v9}, Lh0/t1;->j(Lh0/g;)Z

    .line 1765
    .line 1766
    .line 1767
    move-result v18

    .line 1768
    if-eqz v18, :cond_43

    .line 1769
    .line 1770
    invoke-interface {v12, v9}, Lh0/t1;->f(Lh0/g;)Ljava/lang/Object;

    .line 1771
    .line 1772
    .line 1773
    move-result-object v15

    .line 1774
    invoke-virtual {v11, v9, v15}, Lh0/j1;->n(Lh0/g;Ljava/lang/Object;)V

    .line 1775
    .line 1776
    .line 1777
    :cond_43
    sget-object v9, Lh0/o2;->X0:Lh0/g;

    .line 1778
    .line 1779
    invoke-interface {v12, v9}, Lh0/t1;->j(Lh0/g;)Z

    .line 1780
    .line 1781
    .line 1782
    move-result v15

    .line 1783
    if-eqz v15, :cond_44

    .line 1784
    .line 1785
    invoke-interface {v12, v9}, Lh0/t1;->f(Lh0/g;)Ljava/lang/Object;

    .line 1786
    .line 1787
    .line 1788
    move-result-object v15

    .line 1789
    invoke-virtual {v11, v9, v15}, Lh0/j1;->n(Lh0/g;Ljava/lang/Object;)V

    .line 1790
    .line 1791
    .line 1792
    :cond_44
    sget-object v9, Lh0/y0;->e:Lh0/g;

    .line 1793
    .line 1794
    invoke-interface {v12, v9}, Lh0/t1;->j(Lh0/g;)Z

    .line 1795
    .line 1796
    .line 1797
    move-result v15

    .line 1798
    if-eqz v15, :cond_45

    .line 1799
    .line 1800
    invoke-interface {v12, v9}, Lh0/t1;->f(Lh0/g;)Ljava/lang/Object;

    .line 1801
    .line 1802
    .line 1803
    move-result-object v15

    .line 1804
    invoke-virtual {v11, v9, v15}, Lh0/j1;->n(Lh0/g;Ljava/lang/Object;)V

    .line 1805
    .line 1806
    .line 1807
    :cond_45
    sget-object v9, Lh0/z0;->C0:Lh0/g;

    .line 1808
    .line 1809
    invoke-interface {v12, v9}, Lh0/t1;->j(Lh0/g;)Z

    .line 1810
    .line 1811
    .line 1812
    move-result v15

    .line 1813
    if-eqz v15, :cond_46

    .line 1814
    .line 1815
    invoke-interface {v12, v9}, Lh0/t1;->f(Lh0/g;)Ljava/lang/Object;

    .line 1816
    .line 1817
    .line 1818
    move-result-object v15

    .line 1819
    invoke-virtual {v11, v9, v15}, Lh0/j1;->n(Lh0/g;Ljava/lang/Object;)V

    .line 1820
    .line 1821
    .line 1822
    :cond_46
    new-instance v9, Lt/a;

    .line 1823
    .line 1824
    const/4 v15, 0x0

    .line 1825
    invoke-direct {v9, v11, v15}, La0/j;-><init>(Ljava/lang/Object;I)V

    .line 1826
    .line 1827
    .line 1828
    iput-object v9, v13, Lss/b;->j:Ljava/lang/Object;

    .line 1829
    .line 1830
    iget-boolean v9, v1, Lu/d;->b:Z

    .line 1831
    .line 1832
    invoke-static {v9}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 1833
    .line 1834
    .line 1835
    move-result-object v9

    .line 1836
    iput-object v9, v13, Lss/b;->k:Ljava/lang/Object;

    .line 1837
    .line 1838
    sget-object v9, Lh0/k;->h:Landroid/util/Range;

    .line 1839
    .line 1840
    invoke-virtual {v9, v10}, Landroid/util/Range;->equals(Ljava/lang/Object;)Z

    .line 1841
    .line 1842
    .line 1843
    move-result v9

    .line 1844
    if-nez v9, :cond_47

    .line 1845
    .line 1846
    iput-object v10, v13, Lss/b;->i:Ljava/lang/Object;

    .line 1847
    .line 1848
    :cond_47
    invoke-virtual {v13}, Lss/b;->c()Lh0/k;

    .line 1849
    .line 1850
    .line 1851
    move-result-object v9

    .line 1852
    invoke-virtual {v14, v12, v9}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 1853
    .line 1854
    .line 1855
    move-object/from16 v11, p3

    .line 1856
    .line 1857
    move-object/from16 v9, p6

    .line 1858
    .line 1859
    goto/16 :goto_30

    .line 1860
    .line 1861
    :cond_48
    const/4 v15, 0x0

    .line 1862
    if-eqz v23, :cond_49

    .line 1863
    .line 1864
    if-ne v5, v8, :cond_49

    .line 1865
    .line 1866
    invoke-interface {v3}, Ljava/util/List;->size()I

    .line 1867
    .line 1868
    .line 1869
    move-result v1

    .line 1870
    invoke-interface {v7}, Ljava/util/List;->size()I

    .line 1871
    .line 1872
    .line 1873
    move-result v4

    .line 1874
    if-ne v1, v4, :cond_49

    .line 1875
    .line 1876
    move v1, v15

    .line 1877
    :goto_31
    invoke-interface {v3}, Ljava/util/List;->size()I

    .line 1878
    .line 1879
    .line 1880
    move-result v4

    .line 1881
    if-ge v1, v4, :cond_4b

    .line 1882
    .line 1883
    invoke-interface {v3, v1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 1884
    .line 1885
    .line 1886
    move-result-object v4

    .line 1887
    check-cast v4, Landroid/util/Size;

    .line 1888
    .line 1889
    invoke-interface {v7, v1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 1890
    .line 1891
    .line 1892
    move-result-object v5

    .line 1893
    invoke-virtual {v4, v5}, Landroid/util/Size;->equals(Ljava/lang/Object;)Z

    .line 1894
    .line 1895
    .line 1896
    move-result v4

    .line 1897
    if-nez v4, :cond_4a

    .line 1898
    .line 1899
    :cond_49
    move-object/from16 v7, v24

    .line 1900
    .line 1901
    goto/16 :goto_3f

    .line 1902
    .line 1903
    :cond_4a
    add-int/lit8 v1, v1, 0x1

    .line 1904
    .line 1905
    goto :goto_31

    .line 1906
    :cond_4b
    iget-object v0, v0, Lu/c1;->m:Lv/b;

    .line 1907
    .line 1908
    sget-object v1, Lu/b1;->a:Lh0/g;

    .line 1909
    .line 1910
    const-string v1, "characteristicsCompat"

    .line 1911
    .line 1912
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1913
    .line 1914
    .line 1915
    sget v1, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 1916
    .line 1917
    const/16 v3, 0x21

    .line 1918
    .line 1919
    const-string v4, "Null expectedFrameRateRange"

    .line 1920
    .line 1921
    const-string v5, "Null dynamicRange"

    .line 1922
    .line 1923
    if-ge v1, v3, :cond_4d

    .line 1924
    .line 1925
    :cond_4c
    :goto_32
    move-object/from16 v7, v24

    .line 1926
    .line 1927
    goto/16 :goto_3c

    .line 1928
    .line 1929
    :cond_4d
    new-instance v1, Ljava/util/ArrayList;

    .line 1930
    .line 1931
    invoke-virtual {v14}, Ljava/util/HashMap;->keySet()Ljava/util/Set;

    .line 1932
    .line 1933
    .line 1934
    move-result-object v3

    .line 1935
    check-cast v3, Ljava/util/Collection;

    .line 1936
    .line 1937
    invoke-direct {v1, v3}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    .line 1938
    .line 1939
    .line 1940
    invoke-virtual {v6}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 1941
    .line 1942
    .line 1943
    move-result-object v3

    .line 1944
    :goto_33
    invoke-interface {v3}, Ljava/util/Iterator;->hasNext()Z

    .line 1945
    .line 1946
    .line 1947
    move-result v7

    .line 1948
    if-eqz v7, :cond_4e

    .line 1949
    .line 1950
    invoke-interface {v3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 1951
    .line 1952
    .line 1953
    move-result-object v7

    .line 1954
    check-cast v7, Lh0/e;

    .line 1955
    .line 1956
    iget-object v7, v7, Lh0/e;->f:Lh0/q0;

    .line 1957
    .line 1958
    invoke-virtual {v7}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1959
    .line 1960
    .line 1961
    goto :goto_33

    .line 1962
    :cond_4e
    invoke-virtual {v1}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 1963
    .line 1964
    .line 1965
    move-result-object v3

    .line 1966
    :goto_34
    invoke-interface {v3}, Ljava/util/Iterator;->hasNext()Z

    .line 1967
    .line 1968
    .line 1969
    move-result v7

    .line 1970
    if-eqz v7, :cond_4f

    .line 1971
    .line 1972
    invoke-interface {v3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 1973
    .line 1974
    .line 1975
    move-result-object v7

    .line 1976
    check-cast v7, Lh0/o2;

    .line 1977
    .line 1978
    invoke-virtual {v14, v7}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 1979
    .line 1980
    .line 1981
    move-result-object v7

    .line 1982
    invoke-virtual {v7}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1983
    .line 1984
    .line 1985
    check-cast v7, Lh0/k;

    .line 1986
    .line 1987
    iget-object v7, v7, Lh0/k;->f:Lh0/q0;

    .line 1988
    .line 1989
    invoke-virtual {v7}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 1990
    .line 1991
    .line 1992
    goto :goto_34

    .line 1993
    :cond_4f
    invoke-static {}, Lu/a1;->a()Landroid/hardware/camera2/CameraCharacteristics$Key;

    .line 1994
    .line 1995
    .line 1996
    move-result-object v3

    .line 1997
    invoke-virtual {v0, v3}, Lv/b;->a(Landroid/hardware/camera2/CameraCharacteristics$Key;)Ljava/lang/Object;

    .line 1998
    .line 1999
    .line 2000
    move-result-object v0

    .line 2001
    check-cast v0, [J

    .line 2002
    .line 2003
    if-eqz v0, :cond_4c

    .line 2004
    .line 2005
    array-length v3, v0

    .line 2006
    if-nez v3, :cond_50

    .line 2007
    .line 2008
    goto :goto_32

    .line 2009
    :cond_50
    new-instance v3, Ljava/util/HashSet;

    .line 2010
    .line 2011
    invoke-direct {v3}, Ljava/util/HashSet;-><init>()V

    .line 2012
    .line 2013
    .line 2014
    array-length v7, v0

    .line 2015
    move v8, v15

    .line 2016
    :goto_35
    if-ge v8, v7, :cond_51

    .line 2017
    .line 2018
    aget-wide v9, v0, v8

    .line 2019
    .line 2020
    invoke-static {v9, v10}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 2021
    .line 2022
    .line 2023
    move-result-object v9

    .line 2024
    invoke-virtual {v3, v9}, Ljava/util/HashSet;->add(Ljava/lang/Object;)Z

    .line 2025
    .line 2026
    .line 2027
    add-int/lit8 v8, v8, 0x1

    .line 2028
    .line 2029
    goto :goto_35

    .line 2030
    :cond_51
    new-instance v0, Ljava/util/LinkedHashSet;

    .line 2031
    .line 2032
    invoke-direct {v0}, Ljava/util/LinkedHashSet;-><init>()V

    .line 2033
    .line 2034
    .line 2035
    invoke-virtual {v6}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 2036
    .line 2037
    .line 2038
    move-result-object v7

    .line 2039
    invoke-interface {v7}, Ljava/util/Iterator;->hasNext()Z

    .line 2040
    .line 2041
    .line 2042
    move-result v8

    .line 2043
    const-wide/16 v9, 0x0

    .line 2044
    .line 2045
    if-eqz v8, :cond_54

    .line 2046
    .line 2047
    invoke-interface {v7}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 2048
    .line 2049
    .line 2050
    move-result-object v7

    .line 2051
    check-cast v7, Lh0/e;

    .line 2052
    .line 2053
    iget-object v8, v7, Lh0/e;->f:Lh0/q0;

    .line 2054
    .line 2055
    invoke-static {v8}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 2056
    .line 2057
    .line 2058
    sget-object v11, Lt/a;->g:Lh0/g;

    .line 2059
    .line 2060
    invoke-interface {v8, v11}, Lh0/q0;->j(Lh0/g;)Z

    .line 2061
    .line 2062
    .line 2063
    move-result v8

    .line 2064
    if-nez v8, :cond_52

    .line 2065
    .line 2066
    :goto_36
    move v7, v15

    .line 2067
    move/from16 v8, v16

    .line 2068
    .line 2069
    goto :goto_37

    .line 2070
    :cond_52
    iget-object v7, v7, Lh0/e;->f:Lh0/q0;

    .line 2071
    .line 2072
    invoke-static {v7}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 2073
    .line 2074
    .line 2075
    invoke-interface {v7, v11}, Lh0/q0;->f(Lh0/g;)Ljava/lang/Object;

    .line 2076
    .line 2077
    .line 2078
    move-result-object v7

    .line 2079
    invoke-static {v7}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 2080
    .line 2081
    .line 2082
    check-cast v7, Ljava/lang/Number;

    .line 2083
    .line 2084
    invoke-virtual {v7}, Ljava/lang/Number;->longValue()J

    .line 2085
    .line 2086
    .line 2087
    move-result-wide v7

    .line 2088
    cmp-long v7, v7, v9

    .line 2089
    .line 2090
    if-nez v7, :cond_53

    .line 2091
    .line 2092
    goto :goto_36

    .line 2093
    :cond_53
    move v8, v15

    .line 2094
    move/from16 v7, v16

    .line 2095
    .line 2096
    goto :goto_37

    .line 2097
    :cond_54
    move v7, v15

    .line 2098
    move v8, v7

    .line 2099
    :goto_37
    invoke-virtual {v1}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 2100
    .line 2101
    .line 2102
    move-result-object v11

    .line 2103
    :goto_38
    invoke-interface {v11}, Ljava/util/Iterator;->hasNext()Z

    .line 2104
    .line 2105
    .line 2106
    move-result v12

    .line 2107
    if-eqz v12, :cond_5a

    .line 2108
    .line 2109
    invoke-interface {v11}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 2110
    .line 2111
    .line 2112
    move-result-object v12

    .line 2113
    check-cast v12, Lh0/o2;

    .line 2114
    .line 2115
    sget-object v13, Lt/a;->g:Lh0/g;

    .line 2116
    .line 2117
    invoke-interface {v12, v13}, Lh0/t1;->j(Lh0/g;)Z

    .line 2118
    .line 2119
    .line 2120
    move-result v17

    .line 2121
    move-wide/from16 p0, v9

    .line 2122
    .line 2123
    const-string v9, "Either all use cases must have non-default stream use case assigned or none should have it"

    .line 2124
    .line 2125
    if-nez v17, :cond_56

    .line 2126
    .line 2127
    if-nez v7, :cond_55

    .line 2128
    .line 2129
    :goto_39
    move-wide/from16 v9, p0

    .line 2130
    .line 2131
    move/from16 v8, v16

    .line 2132
    .line 2133
    goto :goto_38

    .line 2134
    :cond_55
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 2135
    .line 2136
    invoke-direct {v0, v9}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 2137
    .line 2138
    .line 2139
    throw v0

    .line 2140
    :cond_56
    invoke-interface {v12, v13}, Lh0/t1;->f(Lh0/g;)Ljava/lang/Object;

    .line 2141
    .line 2142
    .line 2143
    move-result-object v10

    .line 2144
    invoke-static {v10}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 2145
    .line 2146
    .line 2147
    check-cast v10, Ljava/lang/Number;

    .line 2148
    .line 2149
    invoke-virtual {v10}, Ljava/lang/Number;->longValue()J

    .line 2150
    .line 2151
    .line 2152
    move-result-wide v12

    .line 2153
    cmp-long v10, v12, p0

    .line 2154
    .line 2155
    if-nez v10, :cond_58

    .line 2156
    .line 2157
    if-nez v7, :cond_57

    .line 2158
    .line 2159
    goto :goto_39

    .line 2160
    :cond_57
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 2161
    .line 2162
    invoke-direct {v0, v9}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 2163
    .line 2164
    .line 2165
    throw v0

    .line 2166
    :cond_58
    if-nez v8, :cond_59

    .line 2167
    .line 2168
    invoke-static {v12, v13}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 2169
    .line 2170
    .line 2171
    move-result-object v7

    .line 2172
    invoke-interface {v0, v7}, Ljava/util/Set;->add(Ljava/lang/Object;)Z

    .line 2173
    .line 2174
    .line 2175
    move-wide/from16 v9, p0

    .line 2176
    .line 2177
    move/from16 v7, v16

    .line 2178
    .line 2179
    goto :goto_38

    .line 2180
    :cond_59
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 2181
    .line 2182
    invoke-direct {v0, v9}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 2183
    .line 2184
    .line 2185
    throw v0

    .line 2186
    :cond_5a
    if-nez v8, :cond_4c

    .line 2187
    .line 2188
    invoke-interface {v0}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 2189
    .line 2190
    .line 2191
    move-result-object v0

    .line 2192
    :cond_5b
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 2193
    .line 2194
    .line 2195
    move-result v7

    .line 2196
    if-eqz v7, :cond_5c

    .line 2197
    .line 2198
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 2199
    .line 2200
    .line 2201
    move-result-object v7

    .line 2202
    check-cast v7, Ljava/lang/Number;

    .line 2203
    .line 2204
    invoke-virtual {v7}, Ljava/lang/Number;->longValue()J

    .line 2205
    .line 2206
    .line 2207
    move-result-wide v7

    .line 2208
    invoke-static {v7, v8}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 2209
    .line 2210
    .line 2211
    move-result-object v7

    .line 2212
    invoke-virtual {v3, v7}, Ljava/util/HashSet;->contains(Ljava/lang/Object;)Z

    .line 2213
    .line 2214
    .line 2215
    move-result v7

    .line 2216
    if-nez v7, :cond_5b

    .line 2217
    .line 2218
    goto/16 :goto_32

    .line 2219
    .line 2220
    :cond_5c
    invoke-virtual {v6}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 2221
    .line 2222
    .line 2223
    move-result-object v0

    .line 2224
    :cond_5d
    :goto_3a
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 2225
    .line 2226
    .line 2227
    move-result v3

    .line 2228
    if-eqz v3, :cond_60

    .line 2229
    .line 2230
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 2231
    .line 2232
    .line 2233
    move-result-object v3

    .line 2234
    check-cast v3, Lh0/e;

    .line 2235
    .line 2236
    iget-object v6, v3, Lh0/e;->f:Lh0/q0;

    .line 2237
    .line 2238
    invoke-static {v6}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 2239
    .line 2240
    .line 2241
    sget-object v7, Lt/a;->g:Lh0/g;

    .line 2242
    .line 2243
    invoke-interface {v6, v7}, Lh0/q0;->f(Lh0/g;)Ljava/lang/Object;

    .line 2244
    .line 2245
    .line 2246
    move-result-object v7

    .line 2247
    check-cast v7, Ljava/lang/Long;

    .line 2248
    .line 2249
    invoke-static {v6, v7}, Lu/b1;->a(Lh0/q0;Ljava/lang/Long;)Lt/a;

    .line 2250
    .line 2251
    .line 2252
    move-result-object v6

    .line 2253
    if-eqz v6, :cond_5d

    .line 2254
    .line 2255
    iget-object v7, v3, Lh0/e;->c:Landroid/util/Size;

    .line 2256
    .line 2257
    invoke-static {v7}, Lh0/k;->a(Landroid/util/Size;)Lss/b;

    .line 2258
    .line 2259
    .line 2260
    move-result-object v7

    .line 2261
    iget v8, v3, Lh0/e;->g:I

    .line 2262
    .line 2263
    invoke-static {v8}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 2264
    .line 2265
    .line 2266
    move-result-object v8

    .line 2267
    iput-object v8, v7, Lss/b;->h:Ljava/lang/Object;

    .line 2268
    .line 2269
    iget-object v8, v3, Lh0/e;->h:Landroid/util/Range;

    .line 2270
    .line 2271
    if-eqz v8, :cond_5f

    .line 2272
    .line 2273
    iput-object v8, v7, Lss/b;->i:Ljava/lang/Object;

    .line 2274
    .line 2275
    iget-object v8, v3, Lh0/e;->d:Lb0/y;

    .line 2276
    .line 2277
    if-eqz v8, :cond_5e

    .line 2278
    .line 2279
    iput-object v8, v7, Lss/b;->g:Ljava/lang/Object;

    .line 2280
    .line 2281
    iput-object v6, v7, Lss/b;->j:Ljava/lang/Object;

    .line 2282
    .line 2283
    invoke-virtual {v7}, Lss/b;->c()Lh0/k;

    .line 2284
    .line 2285
    .line 2286
    move-result-object v6

    .line 2287
    move-object/from16 v7, v24

    .line 2288
    .line 2289
    invoke-virtual {v7, v3, v6}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 2290
    .line 2291
    .line 2292
    goto :goto_3a

    .line 2293
    :cond_5e
    new-instance v0, Ljava/lang/NullPointerException;

    .line 2294
    .line 2295
    invoke-direct {v0, v5}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    .line 2296
    .line 2297
    .line 2298
    throw v0

    .line 2299
    :cond_5f
    new-instance v0, Ljava/lang/NullPointerException;

    .line 2300
    .line 2301
    invoke-direct {v0, v4}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    .line 2302
    .line 2303
    .line 2304
    throw v0

    .line 2305
    :cond_60
    move-object/from16 v7, v24

    .line 2306
    .line 2307
    invoke-virtual {v1}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 2308
    .line 2309
    .line 2310
    move-result-object v0

    .line 2311
    :cond_61
    :goto_3b
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 2312
    .line 2313
    .line 2314
    move-result v1

    .line 2315
    if-eqz v1, :cond_68

    .line 2316
    .line 2317
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 2318
    .line 2319
    .line 2320
    move-result-object v1

    .line 2321
    check-cast v1, Lh0/o2;

    .line 2322
    .line 2323
    invoke-virtual {v14, v1}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 2324
    .line 2325
    .line 2326
    move-result-object v3

    .line 2327
    check-cast v3, Lh0/k;

    .line 2328
    .line 2329
    invoke-static {v3}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 2330
    .line 2331
    .line 2332
    iget-object v4, v3, Lh0/k;->f:Lh0/q0;

    .line 2333
    .line 2334
    invoke-static {v4}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 2335
    .line 2336
    .line 2337
    sget-object v5, Lt/a;->g:Lh0/g;

    .line 2338
    .line 2339
    invoke-interface {v4, v5}, Lh0/q0;->f(Lh0/g;)Ljava/lang/Object;

    .line 2340
    .line 2341
    .line 2342
    move-result-object v5

    .line 2343
    check-cast v5, Ljava/lang/Long;

    .line 2344
    .line 2345
    invoke-static {v4, v5}, Lu/b1;->a(Lh0/q0;Ljava/lang/Long;)Lt/a;

    .line 2346
    .line 2347
    .line 2348
    move-result-object v4

    .line 2349
    if-eqz v4, :cond_61

    .line 2350
    .line 2351
    invoke-virtual {v3}, Lh0/k;->b()Lss/b;

    .line 2352
    .line 2353
    .line 2354
    move-result-object v3

    .line 2355
    iput-object v4, v3, Lss/b;->j:Ljava/lang/Object;

    .line 2356
    .line 2357
    invoke-virtual {v3}, Lss/b;->c()Lh0/k;

    .line 2358
    .line 2359
    .line 2360
    move-result-object v3

    .line 2361
    invoke-virtual {v14, v1, v3}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 2362
    .line 2363
    .line 2364
    goto :goto_3b

    .line 2365
    :goto_3c
    sget-object v0, Lu/b1;->a:Lh0/g;

    .line 2366
    .line 2367
    move-object/from16 v0, v23

    .line 2368
    .line 2369
    check-cast v0, Ljava/util/Collection;

    .line 2370
    .line 2371
    invoke-interface {v0}, Ljava/util/Collection;->size()I

    .line 2372
    .line 2373
    .line 2374
    move-result v0

    .line 2375
    move v13, v15

    .line 2376
    :goto_3d
    if-ge v13, v0, :cond_68

    .line 2377
    .line 2378
    move-object/from16 v1, v23

    .line 2379
    .line 2380
    invoke-interface {v1, v13}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 2381
    .line 2382
    .line 2383
    move-result-object v3

    .line 2384
    check-cast v3, Lh0/h2;

    .line 2385
    .line 2386
    iget-object v3, v3, Lh0/h2;->c:Lh0/c2;

    .line 2387
    .line 2388
    iget-wide v8, v3, Lh0/c2;->d:J

    .line 2389
    .line 2390
    invoke-static {v13}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 2391
    .line 2392
    .line 2393
    move-result-object v3

    .line 2394
    move-object/from16 v6, v25

    .line 2395
    .line 2396
    invoke-virtual {v6, v3}, Ljava/util/HashMap;->containsKey(Ljava/lang/Object;)Z

    .line 2397
    .line 2398
    .line 2399
    move-result v3

    .line 2400
    if-eqz v3, :cond_65

    .line 2401
    .line 2402
    invoke-static {v13}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 2403
    .line 2404
    .line 2405
    move-result-object v3

    .line 2406
    invoke-virtual {v6, v3}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 2407
    .line 2408
    .line 2409
    move-result-object v3

    .line 2410
    check-cast v3, Lh0/e;

    .line 2411
    .line 2412
    invoke-static {v3}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 2413
    .line 2414
    .line 2415
    iget-object v10, v3, Lh0/e;->f:Lh0/q0;

    .line 2416
    .line 2417
    invoke-static {v10}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 2418
    .line 2419
    .line 2420
    invoke-static {v8, v9}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 2421
    .line 2422
    .line 2423
    move-result-object v8

    .line 2424
    invoke-static {v10, v8}, Lu/b1;->a(Lh0/q0;Ljava/lang/Long;)Lt/a;

    .line 2425
    .line 2426
    .line 2427
    move-result-object v8

    .line 2428
    if-eqz v8, :cond_62

    .line 2429
    .line 2430
    iget-object v9, v3, Lh0/e;->c:Landroid/util/Size;

    .line 2431
    .line 2432
    invoke-static {v9}, Lh0/k;->a(Landroid/util/Size;)Lss/b;

    .line 2433
    .line 2434
    .line 2435
    move-result-object v9

    .line 2436
    iget v10, v3, Lh0/e;->g:I

    .line 2437
    .line 2438
    invoke-static {v10}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 2439
    .line 2440
    .line 2441
    move-result-object v10

    .line 2442
    iput-object v10, v9, Lss/b;->h:Ljava/lang/Object;

    .line 2443
    .line 2444
    iget-object v10, v3, Lh0/e;->h:Landroid/util/Range;

    .line 2445
    .line 2446
    if-eqz v10, :cond_64

    .line 2447
    .line 2448
    iput-object v10, v9, Lss/b;->i:Ljava/lang/Object;

    .line 2449
    .line 2450
    iget-object v10, v3, Lh0/e;->d:Lb0/y;

    .line 2451
    .line 2452
    if-eqz v10, :cond_63

    .line 2453
    .line 2454
    iput-object v10, v9, Lss/b;->g:Ljava/lang/Object;

    .line 2455
    .line 2456
    iput-object v8, v9, Lss/b;->j:Ljava/lang/Object;

    .line 2457
    .line 2458
    invoke-virtual {v9}, Lss/b;->c()Lh0/k;

    .line 2459
    .line 2460
    .line 2461
    move-result-object v8

    .line 2462
    invoke-virtual {v7, v3, v8}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 2463
    .line 2464
    .line 2465
    :cond_62
    move-object/from16 v10, v26

    .line 2466
    .line 2467
    goto :goto_3e

    .line 2468
    :cond_63
    new-instance v0, Ljava/lang/NullPointerException;

    .line 2469
    .line 2470
    invoke-direct {v0, v5}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    .line 2471
    .line 2472
    .line 2473
    throw v0

    .line 2474
    :cond_64
    new-instance v0, Ljava/lang/NullPointerException;

    .line 2475
    .line 2476
    invoke-direct {v0, v4}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    .line 2477
    .line 2478
    .line 2479
    throw v0

    .line 2480
    :cond_65
    invoke-static {v13}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 2481
    .line 2482
    .line 2483
    move-result-object v3

    .line 2484
    move-object/from16 v10, v26

    .line 2485
    .line 2486
    invoke-virtual {v10, v3}, Ljava/util/HashMap;->containsKey(Ljava/lang/Object;)Z

    .line 2487
    .line 2488
    .line 2489
    move-result v3

    .line 2490
    if-eqz v3, :cond_67

    .line 2491
    .line 2492
    invoke-static {v13}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 2493
    .line 2494
    .line 2495
    move-result-object v3

    .line 2496
    invoke-virtual {v10, v3}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 2497
    .line 2498
    .line 2499
    move-result-object v3

    .line 2500
    invoke-static {v3}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 2501
    .line 2502
    .line 2503
    check-cast v3, Lh0/o2;

    .line 2504
    .line 2505
    invoke-virtual {v14, v3}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 2506
    .line 2507
    .line 2508
    move-result-object v11

    .line 2509
    check-cast v11, Lh0/k;

    .line 2510
    .line 2511
    invoke-static {v11}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 2512
    .line 2513
    .line 2514
    iget-object v12, v11, Lh0/k;->f:Lh0/q0;

    .line 2515
    .line 2516
    invoke-static {v12}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 2517
    .line 2518
    .line 2519
    invoke-static {v8, v9}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 2520
    .line 2521
    .line 2522
    move-result-object v8

    .line 2523
    invoke-static {v12, v8}, Lu/b1;->a(Lh0/q0;Ljava/lang/Long;)Lt/a;

    .line 2524
    .line 2525
    .line 2526
    move-result-object v8

    .line 2527
    if-eqz v8, :cond_66

    .line 2528
    .line 2529
    invoke-virtual {v11}, Lh0/k;->b()Lss/b;

    .line 2530
    .line 2531
    .line 2532
    move-result-object v9

    .line 2533
    iput-object v8, v9, Lss/b;->j:Ljava/lang/Object;

    .line 2534
    .line 2535
    invoke-virtual {v9}, Lss/b;->c()Lh0/k;

    .line 2536
    .line 2537
    .line 2538
    move-result-object v8

    .line 2539
    invoke-virtual {v14, v3, v8}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 2540
    .line 2541
    .line 2542
    :cond_66
    :goto_3e
    add-int/lit8 v13, v13, 0x1

    .line 2543
    .line 2544
    move-object/from16 v23, v1

    .line 2545
    .line 2546
    move-object/from16 v25, v6

    .line 2547
    .line 2548
    move-object/from16 v26, v10

    .line 2549
    .line 2550
    goto/16 :goto_3d

    .line 2551
    .line 2552
    :cond_67
    new-instance v0, Ljava/lang/AssertionError;

    .line 2553
    .line 2554
    const-string v1, "SurfaceConfig does not map to any use case"

    .line 2555
    .line 2556
    invoke-direct {v0, v1}, Ljava/lang/AssertionError;-><init>(Ljava/lang/Object;)V

    .line 2557
    .line 2558
    .line 2559
    throw v0

    .line 2560
    :cond_68
    :goto_3f
    new-instance v0, Lh0/i2;

    .line 2561
    .line 2562
    invoke-direct {v0, v14, v7, v2}, Lh0/i2;-><init>(Ljava/util/HashMap;Ljava/util/HashMap;I)V

    .line 2563
    .line 2564
    .line 2565
    return-object v0

    .line 2566
    :cond_69
    new-instance v1, Ljava/lang/IllegalArgumentException;

    .line 2567
    .line 2568
    new-instance v2, Ljava/lang/StringBuilder;

    .line 2569
    .line 2570
    move-object/from16 v3, v22

    .line 2571
    .line 2572
    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 2573
    .line 2574
    .line 2575
    iget-object v3, v0, Lu/c1;->k:Ljava/lang/String;

    .line 2576
    .line 2577
    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 2578
    .line 2579
    .line 2580
    const-string v3, " and Hardware level: "

    .line 2581
    .line 2582
    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 2583
    .line 2584
    .line 2585
    iget v0, v0, Lu/c1;->o:I

    .line 2586
    .line 2587
    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 2588
    .line 2589
    .line 2590
    const-string v0, ". May be the specified resolution is too large and not supported. Existing surfaces: "

    .line 2591
    .line 2592
    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 2593
    .line 2594
    .line 2595
    invoke-virtual {v2, v6}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 2596
    .line 2597
    .line 2598
    const-string v0, " New configs: "

    .line 2599
    .line 2600
    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 2601
    .line 2602
    .line 2603
    invoke-virtual {v2, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 2604
    .line 2605
    .line 2606
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 2607
    .line 2608
    .line 2609
    move-result-object v0

    .line 2610
    invoke-direct {v1, v0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 2611
    .line 2612
    .line 2613
    throw v1

    .line 2614
    :cond_6a
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 2615
    .line 2616
    const-string v1, "Failed to find supported resolutions."

    .line 2617
    .line 2618
    invoke-direct {v0, v1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 2619
    .line 2620
    .line 2621
    throw v0
.end method

.method public final o(Ljava/util/HashMap;ILandroid/util/Rational;)V
    .locals 1

    .line 1
    iget-object p0, p0, Lu/c1;->m:Lv/b;

    .line 2
    .line 3
    invoke-virtual {p0}, Lv/b;->c()Lrn/i;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    iget-object p0, p0, Lrn/i;->e:Ljava/lang/Object;

    .line 8
    .line 9
    check-cast p0, Lro/f;

    .line 10
    .line 11
    iget-object p0, p0, Lro/f;->e:Ljava/lang/Object;

    .line 12
    .line 13
    check-cast p0, Landroid/hardware/camera2/params/StreamConfigurationMap;

    .line 14
    .line 15
    const/4 v0, 0x1

    .line 16
    invoke-static {p0, p2, v0, p3}, Lu/c1;->f(Landroid/hardware/camera2/params/StreamConfigurationMap;IZLandroid/util/Rational;)Landroid/util/Size;

    .line 17
    .line 18
    .line 19
    move-result-object p0

    .line 20
    if-eqz p0, :cond_0

    .line 21
    .line 22
    invoke-static {p2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 23
    .line 24
    .line 25
    move-result-object p2

    .line 26
    invoke-virtual {p1, p2, p0}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 27
    .line 28
    .line 29
    :cond_0
    return-void
.end method

.method public final p(Ljava/util/HashMap;Landroid/util/Size;I)V
    .locals 2

    .line 1
    iget-boolean v0, p0, Lu/c1;->r:Z

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    return-void

    .line 6
    :cond_0
    iget-object p0, p0, Lu/c1;->m:Lv/b;

    .line 7
    .line 8
    invoke-virtual {p0}, Lv/b;->c()Lrn/i;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    iget-object p0, p0, Lrn/i;->e:Ljava/lang/Object;

    .line 13
    .line 14
    check-cast p0, Lro/f;

    .line 15
    .line 16
    iget-object p0, p0, Lro/f;->e:Ljava/lang/Object;

    .line 17
    .line 18
    check-cast p0, Landroid/hardware/camera2/params/StreamConfigurationMap;

    .line 19
    .line 20
    const/4 v0, 0x0

    .line 21
    const/4 v1, 0x0

    .line 22
    invoke-static {p0, p3, v1, v0}, Lu/c1;->f(Landroid/hardware/camera2/params/StreamConfigurationMap;IZLandroid/util/Rational;)Landroid/util/Size;

    .line 23
    .line 24
    .line 25
    move-result-object p0

    .line 26
    invoke-static {p3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 27
    .line 28
    .line 29
    move-result-object p3

    .line 30
    if-nez p0, :cond_1

    .line 31
    .line 32
    goto :goto_0

    .line 33
    :cond_1
    filled-new-array {p2, p0}, [Landroid/util/Size;

    .line 34
    .line 35
    .line 36
    move-result-object p0

    .line 37
    invoke-static {p0}, Ljava/util/Arrays;->asList([Ljava/lang/Object;)Ljava/util/List;

    .line 38
    .line 39
    .line 40
    move-result-object p0

    .line 41
    new-instance p2, Li0/c;

    .line 42
    .line 43
    invoke-direct {p2, v1}, Li0/c;-><init>(Z)V

    .line 44
    .line 45
    .line 46
    invoke-static {p0, p2}, Ljava/util/Collections;->min(Ljava/util/Collection;Ljava/util/Comparator;)Ljava/lang/Object;

    .line 47
    .line 48
    .line 49
    move-result-object p0

    .line 50
    move-object p2, p0

    .line 51
    check-cast p2, Landroid/util/Size;

    .line 52
    .line 53
    :goto_0
    invoke-virtual {p1, p3, p2}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 54
    .line 55
    .line 56
    return-void
.end method
