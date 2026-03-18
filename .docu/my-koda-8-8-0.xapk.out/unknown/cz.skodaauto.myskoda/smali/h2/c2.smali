.class public final Lh2/c2;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Lh2/c2;

.field public static final b:Lgy0/j;

.field public static final c:F


# direct methods
.method static constructor <clinit>()V
    .locals 4

    .line 1
    new-instance v0, Lh2/c2;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lh2/c2;->a:Lh2/c2;

    .line 7
    .line 8
    new-instance v0, Lgy0/j;

    .line 9
    .line 10
    const/16 v1, 0x834

    .line 11
    .line 12
    const/4 v2, 0x1

    .line 13
    const/16 v3, 0x76c

    .line 14
    .line 15
    invoke-direct {v0, v3, v1, v2}, Lgy0/h;-><init>(III)V

    .line 16
    .line 17
    .line 18
    sput-object v0, Lh2/c2;->b:Lgy0/j;

    .line 19
    .line 20
    sget v0, Lk2/p;->a:F

    .line 21
    .line 22
    sput v0, Lh2/c2;->c:F

    .line 23
    .line 24
    return-void
.end method

.method public static b(Ll2/o;I)Lh2/z1;
    .locals 2

    .line 1
    sget-object v0, Lh2/g1;->a:Ll2/u2;

    .line 2
    .line 3
    move-object v1, p0

    .line 4
    check-cast v1, Ll2/t;

    .line 5
    .line 6
    invoke-virtual {v1, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 7
    .line 8
    .line 9
    move-result-object v0

    .line 10
    check-cast v0, Lh2/f1;

    .line 11
    .line 12
    shl-int/lit8 p1, p1, 0x3

    .line 13
    .line 14
    and-int/lit8 p1, p1, 0x70

    .line 15
    .line 16
    invoke-static {v0, p0, p1}, Lh2/c2;->c(Lh2/f1;Ll2/o;I)Lh2/z1;

    .line 17
    .line 18
    .line 19
    move-result-object p0

    .line 20
    return-object p0
.end method

.method public static c(Lh2/f1;Ll2/o;I)Lh2/z1;
    .locals 196

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget-object v1, v0, Lh2/f1;->a0:Lh2/z1;

    .line 4
    .line 5
    if-nez v1, :cond_3

    .line 6
    .line 7
    move-object/from16 v1, p1

    .line 8
    .line 9
    check-cast v1, Ll2/t;

    .line 10
    .line 11
    const v3, 0x264a7f77

    .line 12
    .line 13
    .line 14
    invoke-virtual {v1, v3}, Ll2/t;->Y(I)V

    .line 15
    .line 16
    .line 17
    sget-object v3, Lk2/m;->a:Lk2/l;

    .line 18
    .line 19
    invoke-static {v0, v3}, Lh2/g1;->c(Lh2/f1;Lk2/l;)J

    .line 20
    .line 21
    .line 22
    move-result-wide v5

    .line 23
    sget-object v3, Lk2/m;->s:Lk2/l;

    .line 24
    .line 25
    invoke-static {v0, v3}, Lh2/g1;->c(Lh2/f1;Lk2/l;)J

    .line 26
    .line 27
    .line 28
    move-result-wide v7

    .line 29
    sget-object v3, Lk2/m;->q:Lk2/l;

    .line 30
    .line 31
    invoke-static {v0, v3}, Lh2/g1;->c(Lh2/f1;Lk2/l;)J

    .line 32
    .line 33
    .line 34
    move-result-wide v9

    .line 35
    sget-object v3, Lk2/m;->A:Lk2/l;

    .line 36
    .line 37
    invoke-static {v0, v3}, Lh2/g1;->c(Lh2/f1;Lk2/l;)J

    .line 38
    .line 39
    .line 40
    move-result-wide v11

    .line 41
    sget-object v3, Lk2/m;->y:Lk2/l;

    .line 42
    .line 43
    invoke-static {v0, v3}, Lh2/g1;->c(Lh2/f1;Lk2/l;)J

    .line 44
    .line 45
    .line 46
    move-result-wide v13

    .line 47
    iget-wide v3, v0, Lh2/f1;->s:J

    .line 48
    .line 49
    sget-object v15, Lk2/m;->I:Lk2/l;

    .line 50
    .line 51
    invoke-static {v0, v15}, Lh2/g1;->c(Lh2/f1;Lk2/l;)J

    .line 52
    .line 53
    .line 54
    move-result-wide v17

    .line 55
    move-wide/from16 v19, v3

    .line 56
    .line 57
    invoke-static {v0, v15}, Lh2/g1;->c(Lh2/f1;Lk2/l;)J

    .line 58
    .line 59
    .line 60
    move-result-wide v2

    .line 61
    const v4, 0x3ec28f5c    # 0.38f

    .line 62
    .line 63
    .line 64
    invoke-static {v2, v3, v4}, Le3/s;->b(JF)J

    .line 65
    .line 66
    .line 67
    move-result-wide v2

    .line 68
    sget-object v15, Lk2/m;->n:Lk2/l;

    .line 69
    .line 70
    invoke-static {v0, v15}, Lh2/g1;->c(Lh2/f1;Lk2/l;)J

    .line 71
    .line 72
    .line 73
    move-result-wide v21

    .line 74
    sget-object v4, Lk2/m;->G:Lk2/l;

    .line 75
    .line 76
    invoke-static {v0, v4}, Lh2/g1;->c(Lh2/f1;Lk2/l;)J

    .line 77
    .line 78
    .line 79
    move-result-wide v23

    .line 80
    move-wide/from16 v25, v2

    .line 81
    .line 82
    invoke-static {v0, v4}, Lh2/g1;->c(Lh2/f1;Lk2/l;)J

    .line 83
    .line 84
    .line 85
    move-result-wide v2

    .line 86
    const v4, 0x3ec28f5c    # 0.38f

    .line 87
    .line 88
    .line 89
    invoke-static {v2, v3, v4}, Le3/s;->b(JF)J

    .line 90
    .line 91
    .line 92
    move-result-wide v2

    .line 93
    sget-object v4, Lk2/m;->F:Lk2/l;

    .line 94
    .line 95
    invoke-static {v0, v4}, Lh2/g1;->c(Lh2/f1;Lk2/l;)J

    .line 96
    .line 97
    .line 98
    move-result-wide v27

    .line 99
    move-wide/from16 v29, v2

    .line 100
    .line 101
    invoke-static {v0, v4}, Lh2/g1;->c(Lh2/f1;Lk2/l;)J

    .line 102
    .line 103
    .line 104
    move-result-wide v2

    .line 105
    const v4, 0x3ec28f5c    # 0.38f

    .line 106
    .line 107
    .line 108
    invoke-static {v2, v3, v4}, Le3/s;->b(JF)J

    .line 109
    .line 110
    .line 111
    move-result-wide v2

    .line 112
    sget-object v4, Lk2/m;->o:Lk2/l;

    .line 113
    .line 114
    invoke-static {v0, v4}, Lh2/g1;->c(Lh2/f1;Lk2/l;)J

    .line 115
    .line 116
    .line 117
    move-result-wide v31

    .line 118
    move-wide/from16 v33, v2

    .line 119
    .line 120
    invoke-static {v0, v4}, Lh2/g1;->c(Lh2/f1;Lk2/l;)J

    .line 121
    .line 122
    .line 123
    move-result-wide v2

    .line 124
    const v4, 0x3ec28f5c    # 0.38f

    .line 125
    .line 126
    .line 127
    invoke-static {v2, v3, v4}, Le3/s;->b(JF)J

    .line 128
    .line 129
    .line 130
    move-result-wide v2

    .line 131
    sget-object v4, Lk2/m;->j:Lk2/l;

    .line 132
    .line 133
    invoke-static {v0, v4}, Lh2/g1;->c(Lh2/f1;Lk2/l;)J

    .line 134
    .line 135
    .line 136
    move-result-wide v35

    .line 137
    move-wide/from16 v37, v2

    .line 138
    .line 139
    invoke-static {v0, v4}, Lh2/g1;->c(Lh2/f1;Lk2/l;)J

    .line 140
    .line 141
    .line 142
    move-result-wide v2

    .line 143
    const v4, 0x3ec28f5c    # 0.38f

    .line 144
    .line 145
    .line 146
    invoke-static {v2, v3, v4}, Le3/s;->b(JF)J

    .line 147
    .line 148
    .line 149
    move-result-wide v2

    .line 150
    sget-object v4, Lk2/m;->i:Lk2/l;

    .line 151
    .line 152
    invoke-static {v0, v4}, Lh2/g1;->c(Lh2/f1;Lk2/l;)J

    .line 153
    .line 154
    .line 155
    move-result-wide v39

    .line 156
    move-wide/from16 v41, v2

    .line 157
    .line 158
    invoke-static {v0, v4}, Lh2/g1;->c(Lh2/f1;Lk2/l;)J

    .line 159
    .line 160
    .line 161
    move-result-wide v2

    .line 162
    const v4, 0x3ec28f5c    # 0.38f

    .line 163
    .line 164
    .line 165
    invoke-static {v2, v3, v4}, Le3/s;->b(JF)J

    .line 166
    .line 167
    .line 168
    move-result-wide v2

    .line 169
    invoke-static {v0, v15}, Lh2/g1;->c(Lh2/f1;Lk2/l;)J

    .line 170
    .line 171
    .line 172
    move-result-wide v43

    .line 173
    sget-object v4, Lk2/m;->l:Lk2/l;

    .line 174
    .line 175
    invoke-static {v0, v4}, Lh2/g1;->c(Lh2/f1;Lk2/l;)J

    .line 176
    .line 177
    .line 178
    move-result-wide v45

    .line 179
    sget-object v4, Lk2/m;->v:Lk2/l;

    .line 180
    .line 181
    invoke-static {v0, v4}, Lh2/g1;->c(Lh2/f1;Lk2/l;)J

    .line 182
    .line 183
    .line 184
    move-result-wide v49

    .line 185
    sget-object v4, Lk2/m;->u:Lk2/l;

    .line 186
    .line 187
    invoke-static {v0, v4}, Lh2/g1;->c(Lh2/f1;Lk2/l;)J

    .line 188
    .line 189
    .line 190
    move-result-wide v47

    .line 191
    sget-object v4, Lk2/o;->a:Lk2/l;

    .line 192
    .line 193
    invoke-static {v0, v4}, Lh2/g1;->c(Lh2/f1;Lk2/l;)J

    .line 194
    .line 195
    .line 196
    move-result-wide v51

    .line 197
    sget-object v4, Lh2/v6;->a:Lh2/v6;

    .line 198
    .line 199
    iget-object v4, v0, Lh2/f1;->f0:Lh2/eb;

    .line 200
    .line 201
    if-nez v4, :cond_0

    .line 202
    .line 203
    const v4, 0x1745d472

    .line 204
    .line 205
    .line 206
    invoke-virtual {v1, v4}, Ll2/t;->Y(I)V

    .line 207
    .line 208
    .line 209
    const/4 v4, 0x0

    .line 210
    invoke-virtual {v1, v4}, Ll2/t;->q(Z)V

    .line 211
    .line 212
    .line 213
    const/4 v4, 0x0

    .line 214
    move-wide/from16 v108, v2

    .line 215
    .line 216
    goto :goto_2

    .line 217
    :cond_0
    const v15, 0x1745d473

    .line 218
    .line 219
    .line 220
    invoke-virtual {v1, v15}, Ll2/t;->Y(I)V

    .line 221
    .line 222
    .line 223
    sget-object v15, Le2/e1;->a:Ll2/e0;

    .line 224
    .line 225
    invoke-virtual {v1, v15}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 226
    .line 227
    .line 228
    move-result-object v15

    .line 229
    check-cast v15, Le2/d1;

    .line 230
    .line 231
    move-wide/from16 v108, v2

    .line 232
    .line 233
    iget-object v2, v4, Lh2/eb;->k:Le2/d1;

    .line 234
    .line 235
    invoke-static {v2, v15}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 236
    .line 237
    .line 238
    move-result v2

    .line 239
    if-eqz v2, :cond_1

    .line 240
    .line 241
    :goto_0
    const/4 v2, 0x0

    .line 242
    goto :goto_1

    .line 243
    :cond_1
    const-wide/16 v105, 0x0

    .line 244
    .line 245
    const/16 v107, -0x401

    .line 246
    .line 247
    const-wide/16 v54, 0x0

    .line 248
    .line 249
    const-wide/16 v56, 0x0

    .line 250
    .line 251
    const-wide/16 v58, 0x0

    .line 252
    .line 253
    const-wide/16 v60, 0x0

    .line 254
    .line 255
    const-wide/16 v62, 0x0

    .line 256
    .line 257
    const-wide/16 v64, 0x0

    .line 258
    .line 259
    const-wide/16 v66, 0x0

    .line 260
    .line 261
    const-wide/16 v68, 0x0

    .line 262
    .line 263
    const-wide/16 v70, 0x0

    .line 264
    .line 265
    const-wide/16 v73, 0x0

    .line 266
    .line 267
    const-wide/16 v75, 0x0

    .line 268
    .line 269
    const-wide/16 v77, 0x0

    .line 270
    .line 271
    const-wide/16 v79, 0x0

    .line 272
    .line 273
    const-wide/16 v81, 0x0

    .line 274
    .line 275
    const-wide/16 v83, 0x0

    .line 276
    .line 277
    const-wide/16 v85, 0x0

    .line 278
    .line 279
    const-wide/16 v87, 0x0

    .line 280
    .line 281
    const-wide/16 v89, 0x0

    .line 282
    .line 283
    const-wide/16 v91, 0x0

    .line 284
    .line 285
    const-wide/16 v93, 0x0

    .line 286
    .line 287
    const-wide/16 v95, 0x0

    .line 288
    .line 289
    const-wide/16 v97, 0x0

    .line 290
    .line 291
    const-wide/16 v99, 0x0

    .line 292
    .line 293
    const-wide/16 v101, 0x0

    .line 294
    .line 295
    const-wide/16 v103, 0x0

    .line 296
    .line 297
    move-object/from16 v53, v4

    .line 298
    .line 299
    move-object/from16 v72, v15

    .line 300
    .line 301
    invoke-static/range {v53 .. v107}, Lh2/eb;->b(Lh2/eb;JJJJJJJJJLe2/d1;JJJJJJJJJJJJJJJJJI)Lh2/eb;

    .line 302
    .line 303
    .line 304
    move-result-object v4

    .line 305
    iput-object v4, v0, Lh2/f1;->f0:Lh2/eb;

    .line 306
    .line 307
    goto :goto_0

    .line 308
    :goto_1
    invoke-virtual {v1, v2}, Ll2/t;->q(Z)V

    .line 309
    .line 310
    .line 311
    :goto_2
    if-nez v4, :cond_2

    .line 312
    .line 313
    const v2, -0x6a979da7

    .line 314
    .line 315
    .line 316
    invoke-virtual {v1, v2}, Ll2/t;->Y(I)V

    .line 317
    .line 318
    .line 319
    new-instance v110, Lh2/eb;

    .line 320
    .line 321
    sget-object v2, Lk2/z;->p:Lk2/l;

    .line 322
    .line 323
    invoke-static {v0, v2}, Lh2/g1;->c(Lh2/f1;Lk2/l;)J

    .line 324
    .line 325
    .line 326
    move-result-wide v111

    .line 327
    sget-object v2, Lk2/z;->v:Lk2/l;

    .line 328
    .line 329
    invoke-static {v0, v2}, Lh2/g1;->c(Lh2/f1;Lk2/l;)J

    .line 330
    .line 331
    .line 332
    move-result-wide v113

    .line 333
    sget-object v2, Lk2/z;->c:Lk2/l;

    .line 334
    .line 335
    invoke-static {v0, v2}, Lh2/g1;->c(Lh2/f1;Lk2/l;)J

    .line 336
    .line 337
    .line 338
    move-result-wide v3

    .line 339
    const v15, 0x3ec28f5c    # 0.38f

    .line 340
    .line 341
    .line 342
    invoke-static {v3, v4, v15}, Le3/s;->b(JF)J

    .line 343
    .line 344
    .line 345
    move-result-wide v115

    .line 346
    sget-object v3, Lk2/z;->j:Lk2/l;

    .line 347
    .line 348
    invoke-static {v0, v3}, Lh2/g1;->c(Lh2/f1;Lk2/l;)J

    .line 349
    .line 350
    .line 351
    move-result-wide v117

    .line 352
    sget-wide v119, Le3/s;->h:J

    .line 353
    .line 354
    sget-object v3, Lk2/z;->a:Lk2/l;

    .line 355
    .line 356
    invoke-static {v0, v3}, Lh2/g1;->c(Lh2/f1;Lk2/l;)J

    .line 357
    .line 358
    .line 359
    move-result-wide v127

    .line 360
    sget-object v3, Lk2/z;->i:Lk2/l;

    .line 361
    .line 362
    invoke-static {v0, v3}, Lh2/g1;->c(Lh2/f1;Lk2/l;)J

    .line 363
    .line 364
    .line 365
    move-result-wide v129

    .line 366
    sget-object v3, Le2/e1;->a:Ll2/e0;

    .line 367
    .line 368
    invoke-virtual {v1, v3}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 369
    .line 370
    .line 371
    move-result-object v3

    .line 372
    move-object/from16 v131, v3

    .line 373
    .line 374
    check-cast v131, Le2/d1;

    .line 375
    .line 376
    sget-object v3, Lk2/z;->s:Lk2/l;

    .line 377
    .line 378
    invoke-static {v0, v3}, Lh2/g1;->c(Lh2/f1;Lk2/l;)J

    .line 379
    .line 380
    .line 381
    move-result-wide v132

    .line 382
    sget-object v3, Lk2/z;->B:Lk2/l;

    .line 383
    .line 384
    invoke-static {v0, v3}, Lh2/g1;->c(Lh2/f1;Lk2/l;)J

    .line 385
    .line 386
    .line 387
    move-result-wide v134

    .line 388
    sget-object v3, Lk2/z;->f:Lk2/l;

    .line 389
    .line 390
    invoke-static {v0, v3}, Lh2/g1;->c(Lh2/f1;Lk2/l;)J

    .line 391
    .line 392
    .line 393
    move-result-wide v3

    .line 394
    const v15, 0x3df5c28f    # 0.12f

    .line 395
    .line 396
    .line 397
    invoke-static {v3, v4, v15}, Le3/s;->b(JF)J

    .line 398
    .line 399
    .line 400
    move-result-wide v136

    .line 401
    sget-object v3, Lk2/z;->m:Lk2/l;

    .line 402
    .line 403
    invoke-static {v0, v3}, Lh2/g1;->c(Lh2/f1;Lk2/l;)J

    .line 404
    .line 405
    .line 406
    move-result-wide v138

    .line 407
    sget-object v3, Lk2/z;->r:Lk2/l;

    .line 408
    .line 409
    invoke-static {v0, v3}, Lh2/g1;->c(Lh2/f1;Lk2/l;)J

    .line 410
    .line 411
    .line 412
    move-result-wide v140

    .line 413
    sget-object v3, Lk2/z;->A:Lk2/l;

    .line 414
    .line 415
    invoke-static {v0, v3}, Lh2/g1;->c(Lh2/f1;Lk2/l;)J

    .line 416
    .line 417
    .line 418
    move-result-wide v142

    .line 419
    sget-object v3, Lk2/z;->e:Lk2/l;

    .line 420
    .line 421
    invoke-static {v0, v3}, Lh2/g1;->c(Lh2/f1;Lk2/l;)J

    .line 422
    .line 423
    .line 424
    move-result-wide v3

    .line 425
    const v15, 0x3ec28f5c    # 0.38f

    .line 426
    .line 427
    .line 428
    invoke-static {v3, v4, v15}, Le3/s;->b(JF)J

    .line 429
    .line 430
    .line 431
    move-result-wide v144

    .line 432
    sget-object v3, Lk2/z;->l:Lk2/l;

    .line 433
    .line 434
    invoke-static {v0, v3}, Lh2/g1;->c(Lh2/f1;Lk2/l;)J

    .line 435
    .line 436
    .line 437
    move-result-wide v146

    .line 438
    sget-object v3, Lk2/z;->u:Lk2/l;

    .line 439
    .line 440
    invoke-static {v0, v3}, Lh2/g1;->c(Lh2/f1;Lk2/l;)J

    .line 441
    .line 442
    .line 443
    move-result-wide v148

    .line 444
    sget-object v3, Lk2/z;->D:Lk2/l;

    .line 445
    .line 446
    invoke-static {v0, v3}, Lh2/g1;->c(Lh2/f1;Lk2/l;)J

    .line 447
    .line 448
    .line 449
    move-result-wide v150

    .line 450
    sget-object v3, Lk2/z;->h:Lk2/l;

    .line 451
    .line 452
    invoke-static {v0, v3}, Lh2/g1;->c(Lh2/f1;Lk2/l;)J

    .line 453
    .line 454
    .line 455
    move-result-wide v3

    .line 456
    invoke-static {v3, v4, v15}, Le3/s;->b(JF)J

    .line 457
    .line 458
    .line 459
    move-result-wide v152

    .line 460
    sget-object v3, Lk2/z;->o:Lk2/l;

    .line 461
    .line 462
    invoke-static {v0, v3}, Lh2/g1;->c(Lh2/f1;Lk2/l;)J

    .line 463
    .line 464
    .line 465
    move-result-wide v154

    .line 466
    sget-object v3, Lk2/z;->q:Lk2/l;

    .line 467
    .line 468
    invoke-static {v0, v3}, Lh2/g1;->c(Lh2/f1;Lk2/l;)J

    .line 469
    .line 470
    .line 471
    move-result-wide v156

    .line 472
    sget-object v3, Lk2/z;->z:Lk2/l;

    .line 473
    .line 474
    invoke-static {v0, v3}, Lh2/g1;->c(Lh2/f1;Lk2/l;)J

    .line 475
    .line 476
    .line 477
    move-result-wide v158

    .line 478
    sget-object v3, Lk2/z;->d:Lk2/l;

    .line 479
    .line 480
    invoke-static {v0, v3}, Lh2/g1;->c(Lh2/f1;Lk2/l;)J

    .line 481
    .line 482
    .line 483
    move-result-wide v3

    .line 484
    invoke-static {v3, v4, v15}, Le3/s;->b(JF)J

    .line 485
    .line 486
    .line 487
    move-result-wide v160

    .line 488
    sget-object v3, Lk2/z;->k:Lk2/l;

    .line 489
    .line 490
    invoke-static {v0, v3}, Lh2/g1;->c(Lh2/f1;Lk2/l;)J

    .line 491
    .line 492
    .line 493
    move-result-wide v162

    .line 494
    sget-object v3, Lk2/z;->w:Lk2/l;

    .line 495
    .line 496
    invoke-static {v0, v3}, Lh2/g1;->c(Lh2/f1;Lk2/l;)J

    .line 497
    .line 498
    .line 499
    move-result-wide v164

    .line 500
    invoke-static {v0, v3}, Lh2/g1;->c(Lh2/f1;Lk2/l;)J

    .line 501
    .line 502
    .line 503
    move-result-wide v166

    .line 504
    move-wide/from16 v53, v5

    .line 505
    .line 506
    invoke-static {v0, v2}, Lh2/g1;->c(Lh2/f1;Lk2/l;)J

    .line 507
    .line 508
    .line 509
    move-result-wide v4

    .line 510
    invoke-static {v4, v5, v15}, Le3/s;->b(JF)J

    .line 511
    .line 512
    .line 513
    move-result-wide v168

    .line 514
    invoke-static {v0, v3}, Lh2/g1;->c(Lh2/f1;Lk2/l;)J

    .line 515
    .line 516
    .line 517
    move-result-wide v170

    .line 518
    sget-object v2, Lk2/z;->t:Lk2/l;

    .line 519
    .line 520
    invoke-static {v0, v2}, Lh2/g1;->c(Lh2/f1;Lk2/l;)J

    .line 521
    .line 522
    .line 523
    move-result-wide v172

    .line 524
    sget-object v2, Lk2/z;->C:Lk2/l;

    .line 525
    .line 526
    invoke-static {v0, v2}, Lh2/g1;->c(Lh2/f1;Lk2/l;)J

    .line 527
    .line 528
    .line 529
    move-result-wide v174

    .line 530
    sget-object v2, Lk2/z;->g:Lk2/l;

    .line 531
    .line 532
    invoke-static {v0, v2}, Lh2/g1;->c(Lh2/f1;Lk2/l;)J

    .line 533
    .line 534
    .line 535
    move-result-wide v2

    .line 536
    invoke-static {v2, v3, v15}, Le3/s;->b(JF)J

    .line 537
    .line 538
    .line 539
    move-result-wide v176

    .line 540
    sget-object v2, Lk2/z;->n:Lk2/l;

    .line 541
    .line 542
    invoke-static {v0, v2}, Lh2/g1;->c(Lh2/f1;Lk2/l;)J

    .line 543
    .line 544
    .line 545
    move-result-wide v178

    .line 546
    sget-object v2, Lk2/z;->x:Lk2/l;

    .line 547
    .line 548
    invoke-static {v0, v2}, Lh2/g1;->c(Lh2/f1;Lk2/l;)J

    .line 549
    .line 550
    .line 551
    move-result-wide v180

    .line 552
    invoke-static {v0, v2}, Lh2/g1;->c(Lh2/f1;Lk2/l;)J

    .line 553
    .line 554
    .line 555
    move-result-wide v182

    .line 556
    invoke-static {v0, v2}, Lh2/g1;->c(Lh2/f1;Lk2/l;)J

    .line 557
    .line 558
    .line 559
    move-result-wide v3

    .line 560
    invoke-static {v3, v4, v15}, Le3/s;->b(JF)J

    .line 561
    .line 562
    .line 563
    move-result-wide v184

    .line 564
    invoke-static {v0, v2}, Lh2/g1;->c(Lh2/f1;Lk2/l;)J

    .line 565
    .line 566
    .line 567
    move-result-wide v186

    .line 568
    sget-object v2, Lk2/z;->y:Lk2/l;

    .line 569
    .line 570
    invoke-static {v0, v2}, Lh2/g1;->c(Lh2/f1;Lk2/l;)J

    .line 571
    .line 572
    .line 573
    move-result-wide v188

    .line 574
    invoke-static {v0, v2}, Lh2/g1;->c(Lh2/f1;Lk2/l;)J

    .line 575
    .line 576
    .line 577
    move-result-wide v190

    .line 578
    invoke-static {v0, v2}, Lh2/g1;->c(Lh2/f1;Lk2/l;)J

    .line 579
    .line 580
    .line 581
    move-result-wide v3

    .line 582
    invoke-static {v3, v4, v15}, Le3/s;->b(JF)J

    .line 583
    .line 584
    .line 585
    move-result-wide v192

    .line 586
    invoke-static {v0, v2}, Lh2/g1;->c(Lh2/f1;Lk2/l;)J

    .line 587
    .line 588
    .line 589
    move-result-wide v194

    .line 590
    move-wide/from16 v121, v119

    .line 591
    .line 592
    move-wide/from16 v123, v119

    .line 593
    .line 594
    move-wide/from16 v125, v119

    .line 595
    .line 596
    invoke-direct/range {v110 .. v195}, Lh2/eb;-><init>(JJJJJJJJJJLe2/d1;JJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJ)V

    .line 597
    .line 598
    .line 599
    move-object/from16 v4, v110

    .line 600
    .line 601
    iput-object v4, v0, Lh2/f1;->f0:Lh2/eb;

    .line 602
    .line 603
    const/4 v2, 0x0

    .line 604
    invoke-virtual {v1, v2}, Ll2/t;->q(Z)V

    .line 605
    .line 606
    .line 607
    goto :goto_3

    .line 608
    :cond_2
    move-wide/from16 v53, v5

    .line 609
    .line 610
    const/4 v2, 0x0

    .line 611
    const v3, -0x6a9a946d

    .line 612
    .line 613
    .line 614
    invoke-virtual {v1, v3}, Ll2/t;->Y(I)V

    .line 615
    .line 616
    .line 617
    invoke-virtual {v1, v2}, Ll2/t;->q(Z)V

    .line 618
    .line 619
    .line 620
    :goto_3
    new-instance v3, Lh2/z1;

    .line 621
    .line 622
    move-wide/from16 v15, v19

    .line 623
    .line 624
    move-wide/from16 v19, v25

    .line 625
    .line 626
    move-wide/from16 v25, v29

    .line 627
    .line 628
    move-wide/from16 v29, v33

    .line 629
    .line 630
    move-wide/from16 v33, v37

    .line 631
    .line 632
    move-wide/from16 v37, v41

    .line 633
    .line 634
    move-wide/from16 v5, v53

    .line 635
    .line 636
    move-wide/from16 v41, v108

    .line 637
    .line 638
    move-object/from16 v53, v4

    .line 639
    .line 640
    move-object v4, v3

    .line 641
    invoke-direct/range {v4 .. v53}, Lh2/z1;-><init>(JJJJJJJJJJJJJJJJJJJJJJJJLh2/eb;)V

    .line 642
    .line 643
    .line 644
    iput-object v4, v0, Lh2/f1;->a0:Lh2/z1;

    .line 645
    .line 646
    invoke-virtual {v1, v2}, Ll2/t;->q(Z)V

    .line 647
    .line 648
    .line 649
    return-object v4

    .line 650
    :cond_3
    const/4 v2, 0x0

    .line 651
    move-object/from16 v0, p1

    .line 652
    .line 653
    check-cast v0, Ll2/t;

    .line 654
    .line 655
    const v3, 0x26489319

    .line 656
    .line 657
    .line 658
    invoke-virtual {v0, v3}, Ll2/t;->Y(I)V

    .line 659
    .line 660
    .line 661
    invoke-virtual {v0, v2}, Ll2/t;->q(Z)V

    .line 662
    .line 663
    .line 664
    return-object v1
.end method


# virtual methods
.method public final a(Ljava/lang/Long;ILh2/g2;Lx2/s;JLl2/o;I)V
    .locals 28

    .line 1
    move-object/from16 v2, p1

    .line 2
    .line 3
    move/from16 v3, p2

    .line 4
    .line 5
    move-object/from16 v4, p3

    .line 6
    .line 7
    move-object/from16 v0, p7

    .line 8
    .line 9
    check-cast v0, Ll2/t;

    .line 10
    .line 11
    const v1, 0x72111f7c

    .line 12
    .line 13
    .line 14
    invoke-virtual {v0, v1}, Ll2/t;->a0(I)Ll2/t;

    .line 15
    .line 16
    .line 17
    invoke-virtual {v0, v2}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 18
    .line 19
    .line 20
    move-result v1

    .line 21
    if-eqz v1, :cond_0

    .line 22
    .line 23
    const/4 v1, 0x4

    .line 24
    goto :goto_0

    .line 25
    :cond_0
    const/4 v1, 0x2

    .line 26
    :goto_0
    or-int v1, p8, v1

    .line 27
    .line 28
    invoke-virtual {v0, v3}, Ll2/t;->e(I)Z

    .line 29
    .line 30
    .line 31
    move-result v5

    .line 32
    if-eqz v5, :cond_1

    .line 33
    .line 34
    const/16 v5, 0x20

    .line 35
    .line 36
    goto :goto_1

    .line 37
    :cond_1
    const/16 v5, 0x10

    .line 38
    .line 39
    :goto_1
    or-int/2addr v1, v5

    .line 40
    invoke-virtual {v0, v4}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 41
    .line 42
    .line 43
    move-result v5

    .line 44
    if-eqz v5, :cond_2

    .line 45
    .line 46
    const/16 v5, 0x100

    .line 47
    .line 48
    goto :goto_2

    .line 49
    :cond_2
    const/16 v5, 0x80

    .line 50
    .line 51
    :goto_2
    or-int/2addr v1, v5

    .line 52
    move-wide/from16 v7, p5

    .line 53
    .line 54
    invoke-virtual {v0, v7, v8}, Ll2/t;->f(J)Z

    .line 55
    .line 56
    .line 57
    move-result v5

    .line 58
    if-eqz v5, :cond_3

    .line 59
    .line 60
    const/16 v5, 0x4000

    .line 61
    .line 62
    goto :goto_3

    .line 63
    :cond_3
    const/16 v5, 0x2000

    .line 64
    .line 65
    :goto_3
    or-int/2addr v1, v5

    .line 66
    const v5, 0x12493

    .line 67
    .line 68
    .line 69
    and-int/2addr v5, v1

    .line 70
    const v6, 0x12492

    .line 71
    .line 72
    .line 73
    const/4 v9, 0x0

    .line 74
    const/4 v10, 0x1

    .line 75
    if-eq v5, v6, :cond_4

    .line 76
    .line 77
    move v5, v10

    .line 78
    goto :goto_4

    .line 79
    :cond_4
    move v5, v9

    .line 80
    :goto_4
    and-int/lit8 v6, v1, 0x1

    .line 81
    .line 82
    invoke-virtual {v0, v6, v5}, Ll2/t;->O(IZ)Z

    .line 83
    .line 84
    .line 85
    move-result v5

    .line 86
    if-eqz v5, :cond_11

    .line 87
    .line 88
    invoke-virtual {v0}, Ll2/t;->T()V

    .line 89
    .line 90
    .line 91
    and-int/lit8 v5, p8, 0x1

    .line 92
    .line 93
    if-eqz v5, :cond_6

    .line 94
    .line 95
    invoke-virtual {v0}, Ll2/t;->y()Z

    .line 96
    .line 97
    .line 98
    move-result v5

    .line 99
    if-eqz v5, :cond_5

    .line 100
    .line 101
    goto :goto_5

    .line 102
    :cond_5
    invoke-virtual {v0}, Ll2/t;->R()V

    .line 103
    .line 104
    .line 105
    :cond_6
    :goto_5
    invoke-virtual {v0}, Ll2/t;->r()V

    .line 106
    .line 107
    .line 108
    invoke-static {v0}, Lh2/r;->y(Ll2/o;)Ljava/util/Locale;

    .line 109
    .line 110
    .line 111
    move-result-object v5

    .line 112
    invoke-virtual {v4, v2, v5, v9}, Lh2/g2;->a(Ljava/lang/Long;Ljava/util/Locale;Z)Ljava/lang/String;

    .line 113
    .line 114
    .line 115
    move-result-object v6

    .line 116
    invoke-virtual {v4, v2, v5, v10}, Lh2/g2;->a(Ljava/lang/Long;Ljava/util/Locale;Z)Ljava/lang/String;

    .line 117
    .line 118
    .line 119
    move-result-object v5

    .line 120
    const-string v11, ""

    .line 121
    .line 122
    if-nez v5, :cond_9

    .line 123
    .line 124
    const v5, 0x16a92d4b

    .line 125
    .line 126
    .line 127
    invoke-virtual {v0, v5}, Ll2/t;->Y(I)V

    .line 128
    .line 129
    .line 130
    if-nez v3, :cond_7

    .line 131
    .line 132
    const v5, 0x32478caf

    .line 133
    .line 134
    .line 135
    invoke-virtual {v0, v5}, Ll2/t;->Y(I)V

    .line 136
    .line 137
    .line 138
    const v5, 0x7f12059e

    .line 139
    .line 140
    .line 141
    invoke-static {v0, v5}, Li2/a1;->k(Ll2/o;I)Ljava/lang/String;

    .line 142
    .line 143
    .line 144
    move-result-object v5

    .line 145
    invoke-virtual {v0, v9}, Ll2/t;->q(Z)V

    .line 146
    .line 147
    .line 148
    goto :goto_6

    .line 149
    :cond_7
    if-ne v3, v10, :cond_8

    .line 150
    .line 151
    const v5, 0x3247984a

    .line 152
    .line 153
    .line 154
    invoke-virtual {v0, v5}, Ll2/t;->Y(I)V

    .line 155
    .line 156
    .line 157
    const v5, 0x7f120599

    .line 158
    .line 159
    .line 160
    invoke-static {v0, v5}, Li2/a1;->k(Ll2/o;I)Ljava/lang/String;

    .line 161
    .line 162
    .line 163
    move-result-object v5

    .line 164
    invoke-virtual {v0, v9}, Ll2/t;->q(Z)V

    .line 165
    .line 166
    .line 167
    goto :goto_6

    .line 168
    :cond_8
    const v5, 0x16ac8e42

    .line 169
    .line 170
    .line 171
    invoke-virtual {v0, v5}, Ll2/t;->Y(I)V

    .line 172
    .line 173
    .line 174
    invoke-virtual {v0, v9}, Ll2/t;->q(Z)V

    .line 175
    .line 176
    .line 177
    move-object v5, v11

    .line 178
    :goto_6
    invoke-virtual {v0, v9}, Ll2/t;->q(Z)V

    .line 179
    .line 180
    .line 181
    goto :goto_7

    .line 182
    :cond_9
    const v12, 0x32476ef2

    .line 183
    .line 184
    .line 185
    invoke-virtual {v0, v12}, Ll2/t;->Y(I)V

    .line 186
    .line 187
    .line 188
    invoke-virtual {v0, v9}, Ll2/t;->q(Z)V

    .line 189
    .line 190
    .line 191
    :goto_7
    if-nez v6, :cond_c

    .line 192
    .line 193
    const v6, 0x16ae15c3

    .line 194
    .line 195
    .line 196
    invoke-virtual {v0, v6}, Ll2/t;->Y(I)V

    .line 197
    .line 198
    .line 199
    if-nez v3, :cond_a

    .line 200
    .line 201
    const v6, 0x3247b541

    .line 202
    .line 203
    .line 204
    invoke-virtual {v0, v6}, Ll2/t;->Y(I)V

    .line 205
    .line 206
    .line 207
    const v6, 0x7f12059b

    .line 208
    .line 209
    .line 210
    invoke-static {v0, v6}, Li2/a1;->k(Ll2/o;I)Ljava/lang/String;

    .line 211
    .line 212
    .line 213
    move-result-object v6

    .line 214
    invoke-virtual {v0, v9}, Ll2/t;->q(Z)V

    .line 215
    .line 216
    .line 217
    goto :goto_8

    .line 218
    :cond_a
    if-ne v3, v10, :cond_b

    .line 219
    .line 220
    const v6, 0x3247bf20

    .line 221
    .line 222
    .line 223
    invoke-virtual {v0, v6}, Ll2/t;->Y(I)V

    .line 224
    .line 225
    .line 226
    const v6, 0x7f120593

    .line 227
    .line 228
    .line 229
    invoke-static {v0, v6}, Li2/a1;->k(Ll2/o;I)Ljava/lang/String;

    .line 230
    .line 231
    .line 232
    move-result-object v6

    .line 233
    invoke-virtual {v0, v9}, Ll2/t;->q(Z)V

    .line 234
    .line 235
    .line 236
    goto :goto_8

    .line 237
    :cond_b
    const v6, 0x16b11ca2

    .line 238
    .line 239
    .line 240
    invoke-virtual {v0, v6}, Ll2/t;->Y(I)V

    .line 241
    .line 242
    .line 243
    invoke-virtual {v0, v9}, Ll2/t;->q(Z)V

    .line 244
    .line 245
    .line 246
    move-object v6, v11

    .line 247
    :goto_8
    invoke-virtual {v0, v9}, Ll2/t;->q(Z)V

    .line 248
    .line 249
    .line 250
    goto :goto_9

    .line 251
    :cond_c
    const v12, 0x3247aa20

    .line 252
    .line 253
    .line 254
    invoke-virtual {v0, v12}, Ll2/t;->Y(I)V

    .line 255
    .line 256
    .line 257
    invoke-virtual {v0, v9}, Ll2/t;->q(Z)V

    .line 258
    .line 259
    .line 260
    :goto_9
    if-nez v3, :cond_d

    .line 261
    .line 262
    const v11, 0x3247dd0c

    .line 263
    .line 264
    .line 265
    invoke-virtual {v0, v11}, Ll2/t;->Y(I)V

    .line 266
    .line 267
    .line 268
    const v11, 0x7f12059c

    .line 269
    .line 270
    .line 271
    invoke-static {v0, v11}, Li2/a1;->k(Ll2/o;I)Ljava/lang/String;

    .line 272
    .line 273
    .line 274
    move-result-object v11

    .line 275
    invoke-virtual {v0, v9}, Ll2/t;->q(Z)V

    .line 276
    .line 277
    .line 278
    goto :goto_a

    .line 279
    :cond_d
    if-ne v3, v10, :cond_e

    .line 280
    .line 281
    const v11, 0x3247e84b

    .line 282
    .line 283
    .line 284
    invoke-virtual {v0, v11}, Ll2/t;->Y(I)V

    .line 285
    .line 286
    .line 287
    const v11, 0x7f120594

    .line 288
    .line 289
    .line 290
    invoke-static {v0, v11}, Li2/a1;->k(Ll2/o;I)Ljava/lang/String;

    .line 291
    .line 292
    .line 293
    move-result-object v11

    .line 294
    invoke-virtual {v0, v9}, Ll2/t;->q(Z)V

    .line 295
    .line 296
    .line 297
    goto :goto_a

    .line 298
    :cond_e
    const v12, 0x16b64222

    .line 299
    .line 300
    .line 301
    invoke-virtual {v0, v12}, Ll2/t;->Y(I)V

    .line 302
    .line 303
    .line 304
    invoke-virtual {v0, v9}, Ll2/t;->q(Z)V

    .line 305
    .line 306
    .line 307
    :goto_a
    filled-new-array {v5}, [Ljava/lang/Object;

    .line 308
    .line 309
    .line 310
    move-result-object v5

    .line 311
    invoke-static {v5, v10}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    .line 312
    .line 313
    .line 314
    move-result-object v5

    .line 315
    invoke-static {v11, v5}, Ljava/lang/String;->format(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    .line 316
    .line 317
    .line 318
    move-result-object v5

    .line 319
    invoke-virtual {v0, v5}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 320
    .line 321
    .line 322
    move-result v10

    .line 323
    invoke-virtual {v0}, Ll2/t;->L()Ljava/lang/Object;

    .line 324
    .line 325
    .line 326
    move-result-object v11

    .line 327
    if-nez v10, :cond_f

    .line 328
    .line 329
    sget-object v10, Ll2/n;->a:Ll2/x0;

    .line 330
    .line 331
    if-ne v11, v10, :cond_10

    .line 332
    .line 333
    :cond_f
    new-instance v11, Lac0/r;

    .line 334
    .line 335
    const/16 v10, 0xd

    .line 336
    .line 337
    invoke-direct {v11, v5, v10}, Lac0/r;-><init>(Ljava/lang/String;I)V

    .line 338
    .line 339
    .line 340
    invoke-virtual {v0, v11}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 341
    .line 342
    .line 343
    :cond_10
    check-cast v11, Lay0/k;

    .line 344
    .line 345
    move-object/from16 v5, p4

    .line 346
    .line 347
    invoke-static {v5, v9, v11}, Ld4/n;->b(Lx2/s;ZLay0/k;)Lx2/s;

    .line 348
    .line 349
    .line 350
    move-result-object v9

    .line 351
    shr-int/lit8 v1, v1, 0x6

    .line 352
    .line 353
    and-int/lit16 v1, v1, 0x380

    .line 354
    .line 355
    const/16 v26, 0x6000

    .line 356
    .line 357
    const v27, 0x3bff8

    .line 358
    .line 359
    .line 360
    move-object v5, v6

    .line 361
    move-object v6, v9

    .line 362
    const-wide/16 v9, 0x0

    .line 363
    .line 364
    const/4 v11, 0x0

    .line 365
    const-wide/16 v12, 0x0

    .line 366
    .line 367
    const/4 v14, 0x0

    .line 368
    const/4 v15, 0x0

    .line 369
    const-wide/16 v16, 0x0

    .line 370
    .line 371
    const/16 v18, 0x0

    .line 372
    .line 373
    const/16 v19, 0x0

    .line 374
    .line 375
    const/16 v20, 0x1

    .line 376
    .line 377
    const/16 v21, 0x0

    .line 378
    .line 379
    const/16 v22, 0x0

    .line 380
    .line 381
    const/16 v23, 0x0

    .line 382
    .line 383
    move-object/from16 v24, v0

    .line 384
    .line 385
    move/from16 v25, v1

    .line 386
    .line 387
    invoke-static/range {v5 .. v27}, Lh2/rb;->b(Ljava/lang/String;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZIILay0/k;Lg4/p0;Ll2/o;III)V

    .line 388
    .line 389
    .line 390
    goto :goto_b

    .line 391
    :cond_11
    move-object/from16 v24, v0

    .line 392
    .line 393
    invoke-virtual/range {v24 .. v24}, Ll2/t;->R()V

    .line 394
    .line 395
    .line 396
    :goto_b
    invoke-virtual/range {v24 .. v24}, Ll2/t;->s()Ll2/u1;

    .line 397
    .line 398
    .line 399
    move-result-object v9

    .line 400
    if-eqz v9, :cond_12

    .line 401
    .line 402
    new-instance v0, Lh2/a2;

    .line 403
    .line 404
    move-object/from16 v1, p0

    .line 405
    .line 406
    move-object/from16 v5, p4

    .line 407
    .line 408
    move-wide/from16 v6, p5

    .line 409
    .line 410
    move/from16 v8, p8

    .line 411
    .line 412
    invoke-direct/range {v0 .. v8}, Lh2/a2;-><init>(Lh2/c2;Ljava/lang/Long;ILh2/g2;Lx2/s;JI)V

    .line 413
    .line 414
    .line 415
    iput-object v0, v9, Ll2/u1;->d:Lay0/n;

    .line 416
    .line 417
    :cond_12
    return-void
.end method
