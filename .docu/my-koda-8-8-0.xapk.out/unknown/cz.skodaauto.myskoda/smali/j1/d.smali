.class public abstract Lj1/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:[Ljava/lang/StackTraceElement;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    const/4 v0, 0x0

    .line 2
    new-array v0, v0, [Ljava/lang/StackTraceElement;

    .line 3
    .line 4
    sput-object v0, Lj1/d;->a:[Ljava/lang/StackTraceElement;

    .line 5
    .line 6
    return-void
.end method

.method public static final a(Lg4/g;)Lw3/b1;
    .locals 21

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    new-instance v1, Lw3/b1;

    .line 4
    .line 5
    iget-object v2, v0, Lg4/g;->f:Ljava/util/ArrayList;

    .line 6
    .line 7
    sget-object v3, Lmx0/s;->d:Lmx0/s;

    .line 8
    .line 9
    if-nez v2, :cond_0

    .line 10
    .line 11
    move-object v4, v3

    .line 12
    goto :goto_0

    .line 13
    :cond_0
    move-object v4, v2

    .line 14
    :goto_0
    iget-object v0, v0, Lg4/g;->e:Ljava/lang/String;

    .line 15
    .line 16
    invoke-interface {v4}, Ljava/util/List;->isEmpty()Z

    .line 17
    .line 18
    .line 19
    move-result v4

    .line 20
    if-eqz v4, :cond_1

    .line 21
    .line 22
    goto/16 :goto_5

    .line 23
    .line 24
    :cond_1
    new-instance v4, Landroid/text/SpannableString;

    .line 25
    .line 26
    invoke-direct {v4, v0}, Landroid/text/SpannableString;-><init>(Ljava/lang/CharSequence;)V

    .line 27
    .line 28
    .line 29
    new-instance v0, Lj1/a;

    .line 30
    .line 31
    const/4 v5, 0x0

    .line 32
    const/4 v6, 0x0

    .line 33
    invoke-direct {v0, v5, v6}, Lj1/a;-><init>(IZ)V

    .line 34
    .line 35
    .line 36
    invoke-static {}, Landroid/os/Parcel;->obtain()Landroid/os/Parcel;

    .line 37
    .line 38
    .line 39
    move-result-object v5

    .line 40
    iput-object v5, v0, Lj1/a;->e:Ljava/lang/Object;

    .line 41
    .line 42
    if-nez v2, :cond_2

    .line 43
    .line 44
    move-object v2, v3

    .line 45
    :cond_2
    move-object v3, v2

    .line 46
    check-cast v3, Ljava/util/Collection;

    .line 47
    .line 48
    invoke-interface {v3}, Ljava/util/Collection;->size()I

    .line 49
    .line 50
    .line 51
    move-result v3

    .line 52
    const/4 v6, 0x0

    .line 53
    :goto_1
    if-ge v6, v3, :cond_15

    .line 54
    .line 55
    invoke-interface {v2, v6}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 56
    .line 57
    .line 58
    move-result-object v7

    .line 59
    check-cast v7, Lg4/e;

    .line 60
    .line 61
    iget-object v8, v7, Lg4/e;->a:Ljava/lang/Object;

    .line 62
    .line 63
    check-cast v8, Lg4/g0;

    .line 64
    .line 65
    iget v9, v7, Lg4/e;->b:I

    .line 66
    .line 67
    iget v7, v7, Lg4/e;->c:I

    .line 68
    .line 69
    iget-object v10, v0, Lj1/a;->e:Ljava/lang/Object;

    .line 70
    .line 71
    check-cast v10, Landroid/os/Parcel;

    .line 72
    .line 73
    invoke-virtual {v10}, Landroid/os/Parcel;->recycle()V

    .line 74
    .line 75
    .line 76
    invoke-static {}, Landroid/os/Parcel;->obtain()Landroid/os/Parcel;

    .line 77
    .line 78
    .line 79
    move-result-object v10

    .line 80
    iput-object v10, v0, Lj1/a;->e:Ljava/lang/Object;

    .line 81
    .line 82
    iget-object v10, v8, Lg4/g0;->a:Lr4/o;

    .line 83
    .line 84
    iget-wide v11, v8, Lg4/g0;->l:J

    .line 85
    .line 86
    iget-wide v13, v8, Lg4/g0;->h:J

    .line 87
    .line 88
    move v15, v6

    .line 89
    iget-wide v5, v8, Lg4/g0;->b:J

    .line 90
    .line 91
    move-object/from16 v16, v2

    .line 92
    .line 93
    move/from16 v17, v3

    .line 94
    .line 95
    invoke-interface {v10}, Lr4/o;->a()J

    .line 96
    .line 97
    .line 98
    move-result-wide v2

    .line 99
    move/from16 v18, v9

    .line 100
    .line 101
    sget-wide v9, Le3/s;->i:J

    .line 102
    .line 103
    invoke-static {v2, v3, v9, v10}, Le3/s;->c(JJ)Z

    .line 104
    .line 105
    .line 106
    move-result v2

    .line 107
    const/4 v3, 0x1

    .line 108
    if-nez v2, :cond_3

    .line 109
    .line 110
    invoke-virtual {v0, v3}, Lj1/a;->e(B)V

    .line 111
    .line 112
    .line 113
    iget-object v2, v8, Lg4/g0;->a:Lr4/o;

    .line 114
    .line 115
    move-object/from16 v19, v4

    .line 116
    .line 117
    invoke-interface {v2}, Lr4/o;->a()J

    .line 118
    .line 119
    .line 120
    move-result-wide v3

    .line 121
    iget-object v2, v0, Lj1/a;->e:Ljava/lang/Object;

    .line 122
    .line 123
    check-cast v2, Landroid/os/Parcel;

    .line 124
    .line 125
    invoke-virtual {v2, v3, v4}, Landroid/os/Parcel;->writeLong(J)V

    .line 126
    .line 127
    .line 128
    goto :goto_2

    .line 129
    :cond_3
    move-object/from16 v19, v4

    .line 130
    .line 131
    :goto_2
    sget-wide v2, Lt4/o;->c:J

    .line 132
    .line 133
    invoke-static {v5, v6, v2, v3}, Lt4/o;->a(JJ)Z

    .line 134
    .line 135
    .line 136
    move-result v4

    .line 137
    move/from16 v20, v4

    .line 138
    .line 139
    const/4 v4, 0x2

    .line 140
    if-nez v20, :cond_4

    .line 141
    .line 142
    invoke-virtual {v0, v4}, Lj1/a;->e(B)V

    .line 143
    .line 144
    .line 145
    invoke-virtual {v0, v5, v6}, Lj1/a;->k(J)V

    .line 146
    .line 147
    .line 148
    :cond_4
    iget-object v5, v8, Lg4/g0;->c:Lk4/x;

    .line 149
    .line 150
    const/4 v6, 0x3

    .line 151
    if-eqz v5, :cond_5

    .line 152
    .line 153
    invoke-virtual {v0, v6}, Lj1/a;->e(B)V

    .line 154
    .line 155
    .line 156
    iget v5, v5, Lk4/x;->d:I

    .line 157
    .line 158
    iget-object v6, v0, Lj1/a;->e:Ljava/lang/Object;

    .line 159
    .line 160
    check-cast v6, Landroid/os/Parcel;

    .line 161
    .line 162
    invoke-virtual {v6, v5}, Landroid/os/Parcel;->writeInt(I)V

    .line 163
    .line 164
    .line 165
    :cond_5
    iget-object v5, v8, Lg4/g0;->d:Lk4/t;

    .line 166
    .line 167
    if-eqz v5, :cond_8

    .line 168
    .line 169
    iget v5, v5, Lk4/t;->a:I

    .line 170
    .line 171
    const/4 v6, 0x4

    .line 172
    invoke-virtual {v0, v6}, Lj1/a;->e(B)V

    .line 173
    .line 174
    .line 175
    if-nez v5, :cond_7

    .line 176
    .line 177
    :cond_6
    const/4 v6, 0x0

    .line 178
    goto :goto_3

    .line 179
    :cond_7
    const/4 v6, 0x1

    .line 180
    if-ne v5, v6, :cond_6

    .line 181
    .line 182
    const/4 v6, 0x1

    .line 183
    :goto_3
    invoke-virtual {v0, v6}, Lj1/a;->e(B)V

    .line 184
    .line 185
    .line 186
    :cond_8
    iget-object v5, v8, Lg4/g0;->e:Lk4/u;

    .line 187
    .line 188
    if-eqz v5, :cond_d

    .line 189
    .line 190
    iget v5, v5, Lk4/u;->a:I

    .line 191
    .line 192
    const/4 v6, 0x5

    .line 193
    invoke-virtual {v0, v6}, Lj1/a;->e(B)V

    .line 194
    .line 195
    .line 196
    if-nez v5, :cond_a

    .line 197
    .line 198
    :cond_9
    const/4 v4, 0x0

    .line 199
    goto :goto_4

    .line 200
    :cond_a
    const v6, 0xffff

    .line 201
    .line 202
    .line 203
    if-ne v5, v6, :cond_b

    .line 204
    .line 205
    const/4 v4, 0x1

    .line 206
    goto :goto_4

    .line 207
    :cond_b
    const/4 v6, 0x1

    .line 208
    if-ne v5, v6, :cond_c

    .line 209
    .line 210
    goto :goto_4

    .line 211
    :cond_c
    if-ne v5, v4, :cond_9

    .line 212
    .line 213
    const/4 v4, 0x3

    .line 214
    :goto_4
    invoke-virtual {v0, v4}, Lj1/a;->e(B)V

    .line 215
    .line 216
    .line 217
    :cond_d
    iget-object v4, v8, Lg4/g0;->g:Ljava/lang/String;

    .line 218
    .line 219
    if-eqz v4, :cond_e

    .line 220
    .line 221
    const/4 v5, 0x6

    .line 222
    invoke-virtual {v0, v5}, Lj1/a;->e(B)V

    .line 223
    .line 224
    .line 225
    iget-object v5, v0, Lj1/a;->e:Ljava/lang/Object;

    .line 226
    .line 227
    check-cast v5, Landroid/os/Parcel;

    .line 228
    .line 229
    invoke-virtual {v5, v4}, Landroid/os/Parcel;->writeString(Ljava/lang/String;)V

    .line 230
    .line 231
    .line 232
    :cond_e
    invoke-static {v13, v14, v2, v3}, Lt4/o;->a(JJ)Z

    .line 233
    .line 234
    .line 235
    move-result v2

    .line 236
    if-nez v2, :cond_f

    .line 237
    .line 238
    const/4 v2, 0x7

    .line 239
    invoke-virtual {v0, v2}, Lj1/a;->e(B)V

    .line 240
    .line 241
    .line 242
    invoke-virtual {v0, v13, v14}, Lj1/a;->k(J)V

    .line 243
    .line 244
    .line 245
    :cond_f
    iget-object v2, v8, Lg4/g0;->i:Lr4/a;

    .line 246
    .line 247
    if-eqz v2, :cond_10

    .line 248
    .line 249
    iget v2, v2, Lr4/a;->a:F

    .line 250
    .line 251
    const/16 v3, 0x8

    .line 252
    .line 253
    invoke-virtual {v0, v3}, Lj1/a;->e(B)V

    .line 254
    .line 255
    .line 256
    invoke-virtual {v0, v2}, Lj1/a;->j(F)V

    .line 257
    .line 258
    .line 259
    :cond_10
    iget-object v2, v8, Lg4/g0;->j:Lr4/p;

    .line 260
    .line 261
    if-eqz v2, :cond_11

    .line 262
    .line 263
    const/16 v3, 0x9

    .line 264
    .line 265
    invoke-virtual {v0, v3}, Lj1/a;->e(B)V

    .line 266
    .line 267
    .line 268
    iget v3, v2, Lr4/p;->a:F

    .line 269
    .line 270
    invoke-virtual {v0, v3}, Lj1/a;->j(F)V

    .line 271
    .line 272
    .line 273
    iget v2, v2, Lr4/p;->b:F

    .line 274
    .line 275
    invoke-virtual {v0, v2}, Lj1/a;->j(F)V

    .line 276
    .line 277
    .line 278
    :cond_11
    invoke-static {v11, v12, v9, v10}, Le3/s;->c(JJ)Z

    .line 279
    .line 280
    .line 281
    move-result v2

    .line 282
    if-nez v2, :cond_12

    .line 283
    .line 284
    const/16 v2, 0xa

    .line 285
    .line 286
    invoke-virtual {v0, v2}, Lj1/a;->e(B)V

    .line 287
    .line 288
    .line 289
    iget-object v2, v0, Lj1/a;->e:Ljava/lang/Object;

    .line 290
    .line 291
    check-cast v2, Landroid/os/Parcel;

    .line 292
    .line 293
    invoke-virtual {v2, v11, v12}, Landroid/os/Parcel;->writeLong(J)V

    .line 294
    .line 295
    .line 296
    :cond_12
    iget-object v2, v8, Lg4/g0;->m:Lr4/l;

    .line 297
    .line 298
    if-eqz v2, :cond_13

    .line 299
    .line 300
    const/16 v3, 0xb

    .line 301
    .line 302
    invoke-virtual {v0, v3}, Lj1/a;->e(B)V

    .line 303
    .line 304
    .line 305
    iget v2, v2, Lr4/l;->a:I

    .line 306
    .line 307
    iget-object v3, v0, Lj1/a;->e:Ljava/lang/Object;

    .line 308
    .line 309
    check-cast v3, Landroid/os/Parcel;

    .line 310
    .line 311
    invoke-virtual {v3, v2}, Landroid/os/Parcel;->writeInt(I)V

    .line 312
    .line 313
    .line 314
    :cond_13
    iget-object v2, v8, Lg4/g0;->n:Le3/m0;

    .line 315
    .line 316
    if-eqz v2, :cond_14

    .line 317
    .line 318
    const/16 v3, 0xc

    .line 319
    .line 320
    invoke-virtual {v0, v3}, Lj1/a;->e(B)V

    .line 321
    .line 322
    .line 323
    iget-wide v3, v2, Le3/m0;->a:J

    .line 324
    .line 325
    iget-object v5, v0, Lj1/a;->e:Ljava/lang/Object;

    .line 326
    .line 327
    check-cast v5, Landroid/os/Parcel;

    .line 328
    .line 329
    invoke-virtual {v5, v3, v4}, Landroid/os/Parcel;->writeLong(J)V

    .line 330
    .line 331
    .line 332
    iget-wide v3, v2, Le3/m0;->b:J

    .line 333
    .line 334
    const/16 v5, 0x20

    .line 335
    .line 336
    shr-long v5, v3, v5

    .line 337
    .line 338
    long-to-int v5, v5

    .line 339
    invoke-static {v5}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 340
    .line 341
    .line 342
    move-result v5

    .line 343
    invoke-virtual {v0, v5}, Lj1/a;->j(F)V

    .line 344
    .line 345
    .line 346
    const-wide v5, 0xffffffffL

    .line 347
    .line 348
    .line 349
    .line 350
    .line 351
    and-long/2addr v3, v5

    .line 352
    long-to-int v3, v3

    .line 353
    invoke-static {v3}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 354
    .line 355
    .line 356
    move-result v3

    .line 357
    invoke-virtual {v0, v3}, Lj1/a;->j(F)V

    .line 358
    .line 359
    .line 360
    iget v2, v2, Le3/m0;->c:F

    .line 361
    .line 362
    invoke-virtual {v0, v2}, Lj1/a;->j(F)V

    .line 363
    .line 364
    .line 365
    :cond_14
    new-instance v2, Landroid/text/Annotation;

    .line 366
    .line 367
    iget-object v3, v0, Lj1/a;->e:Ljava/lang/Object;

    .line 368
    .line 369
    check-cast v3, Landroid/os/Parcel;

    .line 370
    .line 371
    invoke-virtual {v3}, Landroid/os/Parcel;->marshall()[B

    .line 372
    .line 373
    .line 374
    move-result-object v3

    .line 375
    const/4 v4, 0x0

    .line 376
    invoke-static {v3, v4}, Landroid/util/Base64;->encodeToString([BI)Ljava/lang/String;

    .line 377
    .line 378
    .line 379
    move-result-object v3

    .line 380
    const-string v5, "androidx.compose.text.SpanStyle"

    .line 381
    .line 382
    invoke-direct {v2, v5, v3}, Landroid/text/Annotation;-><init>(Ljava/lang/String;Ljava/lang/String;)V

    .line 383
    .line 384
    .line 385
    const/16 v3, 0x21

    .line 386
    .line 387
    move/from16 v6, v18

    .line 388
    .line 389
    move-object/from16 v5, v19

    .line 390
    .line 391
    invoke-virtual {v5, v2, v6, v7, v3}, Landroid/text/SpannableString;->setSpan(Ljava/lang/Object;III)V

    .line 392
    .line 393
    .line 394
    add-int/lit8 v6, v15, 0x1

    .line 395
    .line 396
    move-object v4, v5

    .line 397
    move-object/from16 v2, v16

    .line 398
    .line 399
    move/from16 v3, v17

    .line 400
    .line 401
    goto/16 :goto_1

    .line 402
    .line 403
    :cond_15
    move-object v5, v4

    .line 404
    move-object v0, v5

    .line 405
    :goto_5
    const-string v2, "plain text"

    .line 406
    .line 407
    invoke-static {v2, v0}, Landroid/content/ClipData;->newPlainText(Ljava/lang/CharSequence;Ljava/lang/CharSequence;)Landroid/content/ClipData;

    .line 408
    .line 409
    .line 410
    move-result-object v0

    .line 411
    invoke-direct {v1, v0}, Lw3/b1;-><init>(Landroid/content/ClipData;)V

    .line 412
    .line 413
    .line 414
    return-object v1
.end method
