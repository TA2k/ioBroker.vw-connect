.class public final Lw3/i;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lw3/d1;


# instance fields
.field public final a:Landroid/content/ClipboardManager;


# direct methods
.method public constructor <init>(Landroid/content/Context;)V
    .locals 1

    .line 1
    const-string v0, "clipboard"

    .line 2
    .line 3
    invoke-virtual {p1, v0}, Landroid/content/Context;->getSystemService(Ljava/lang/String;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p1

    .line 7
    const-string v0, "null cannot be cast to non-null type android.content.ClipboardManager"

    .line 8
    .line 9
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    check-cast p1, Landroid/content/ClipboardManager;

    .line 13
    .line 14
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 15
    .line 16
    .line 17
    iput-object p1, p0, Lw3/i;->a:Landroid/content/ClipboardManager;

    .line 18
    .line 19
    return-void
.end method


# virtual methods
.method public final a(Lg4/g;)V
    .locals 20

    .line 1
    move-object/from16 v0, p1

    .line 2
    .line 3
    iget-object v1, v0, Lg4/g;->f:Ljava/util/ArrayList;

    .line 4
    .line 5
    sget-object v2, Lmx0/s;->d:Lmx0/s;

    .line 6
    .line 7
    if-nez v1, :cond_0

    .line 8
    .line 9
    move-object v3, v2

    .line 10
    goto :goto_0

    .line 11
    :cond_0
    move-object v3, v1

    .line 12
    :goto_0
    iget-object v0, v0, Lg4/g;->e:Ljava/lang/String;

    .line 13
    .line 14
    invoke-interface {v3}, Ljava/util/List;->isEmpty()Z

    .line 15
    .line 16
    .line 17
    move-result v3

    .line 18
    if-eqz v3, :cond_1

    .line 19
    .line 20
    goto/16 :goto_5

    .line 21
    .line 22
    :cond_1
    new-instance v3, Landroid/text/SpannableString;

    .line 23
    .line 24
    invoke-direct {v3, v0}, Landroid/text/SpannableString;-><init>(Ljava/lang/CharSequence;)V

    .line 25
    .line 26
    .line 27
    new-instance v0, Lro/f;

    .line 28
    .line 29
    const/16 v4, 0xc

    .line 30
    .line 31
    const/4 v5, 0x0

    .line 32
    invoke-direct {v0, v4, v5}, Lro/f;-><init>(IZ)V

    .line 33
    .line 34
    .line 35
    invoke-static {}, Landroid/os/Parcel;->obtain()Landroid/os/Parcel;

    .line 36
    .line 37
    .line 38
    move-result-object v4

    .line 39
    iput-object v4, v0, Lro/f;->e:Ljava/lang/Object;

    .line 40
    .line 41
    if-nez v1, :cond_2

    .line 42
    .line 43
    move-object v1, v2

    .line 44
    :cond_2
    move-object v2, v1

    .line 45
    check-cast v2, Ljava/util/Collection;

    .line 46
    .line 47
    invoke-interface {v2}, Ljava/util/Collection;->size()I

    .line 48
    .line 49
    .line 50
    move-result v2

    .line 51
    const/4 v5, 0x0

    .line 52
    :goto_1
    if-ge v5, v2, :cond_15

    .line 53
    .line 54
    invoke-interface {v1, v5}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 55
    .line 56
    .line 57
    move-result-object v6

    .line 58
    check-cast v6, Lg4/e;

    .line 59
    .line 60
    iget-object v7, v6, Lg4/e;->a:Ljava/lang/Object;

    .line 61
    .line 62
    check-cast v7, Lg4/g0;

    .line 63
    .line 64
    iget v8, v6, Lg4/e;->b:I

    .line 65
    .line 66
    iget v6, v6, Lg4/e;->c:I

    .line 67
    .line 68
    iget-object v9, v0, Lro/f;->e:Ljava/lang/Object;

    .line 69
    .line 70
    check-cast v9, Landroid/os/Parcel;

    .line 71
    .line 72
    invoke-virtual {v9}, Landroid/os/Parcel;->recycle()V

    .line 73
    .line 74
    .line 75
    invoke-static {}, Landroid/os/Parcel;->obtain()Landroid/os/Parcel;

    .line 76
    .line 77
    .line 78
    move-result-object v9

    .line 79
    iput-object v9, v0, Lro/f;->e:Ljava/lang/Object;

    .line 80
    .line 81
    iget-object v9, v7, Lg4/g0;->a:Lr4/o;

    .line 82
    .line 83
    iget-wide v10, v7, Lg4/g0;->l:J

    .line 84
    .line 85
    iget-wide v12, v7, Lg4/g0;->h:J

    .line 86
    .line 87
    iget-wide v14, v7, Lg4/g0;->b:J

    .line 88
    .line 89
    move/from16 v16, v5

    .line 90
    .line 91
    invoke-interface {v9}, Lr4/o;->a()J

    .line 92
    .line 93
    .line 94
    move-result-wide v4

    .line 95
    move-object v9, v1

    .line 96
    move/from16 v17, v2

    .line 97
    .line 98
    sget-wide v1, Le3/s;->i:J

    .line 99
    .line 100
    invoke-static {v4, v5, v1, v2}, Le3/s;->c(JJ)Z

    .line 101
    .line 102
    .line 103
    move-result v4

    .line 104
    const/4 v5, 0x1

    .line 105
    if-nez v4, :cond_3

    .line 106
    .line 107
    invoke-virtual {v0, v5}, Lro/f;->g(B)V

    .line 108
    .line 109
    .line 110
    iget-object v4, v7, Lg4/g0;->a:Lr4/o;

    .line 111
    .line 112
    move/from16 v18, v6

    .line 113
    .line 114
    invoke-interface {v4}, Lr4/o;->a()J

    .line 115
    .line 116
    .line 117
    move-result-wide v5

    .line 118
    invoke-virtual {v0, v5, v6}, Lro/f;->j(J)V

    .line 119
    .line 120
    .line 121
    goto :goto_2

    .line 122
    :cond_3
    move/from16 v18, v6

    .line 123
    .line 124
    :goto_2
    sget-wide v4, Lt4/o;->c:J

    .line 125
    .line 126
    invoke-static {v14, v15, v4, v5}, Lt4/o;->a(JJ)Z

    .line 127
    .line 128
    .line 129
    move-result v6

    .line 130
    move/from16 v19, v6

    .line 131
    .line 132
    const/4 v6, 0x2

    .line 133
    if-nez v19, :cond_4

    .line 134
    .line 135
    invoke-virtual {v0, v6}, Lro/f;->g(B)V

    .line 136
    .line 137
    .line 138
    invoke-virtual {v0, v14, v15}, Lro/f;->i(J)V

    .line 139
    .line 140
    .line 141
    :cond_4
    iget-object v14, v7, Lg4/g0;->c:Lk4/x;

    .line 142
    .line 143
    const/4 v15, 0x3

    .line 144
    if-eqz v14, :cond_5

    .line 145
    .line 146
    invoke-virtual {v0, v15}, Lro/f;->g(B)V

    .line 147
    .line 148
    .line 149
    iget v14, v14, Lk4/x;->d:I

    .line 150
    .line 151
    iget-object v15, v0, Lro/f;->e:Ljava/lang/Object;

    .line 152
    .line 153
    check-cast v15, Landroid/os/Parcel;

    .line 154
    .line 155
    invoke-virtual {v15, v14}, Landroid/os/Parcel;->writeInt(I)V

    .line 156
    .line 157
    .line 158
    :cond_5
    iget-object v14, v7, Lg4/g0;->d:Lk4/t;

    .line 159
    .line 160
    if-eqz v14, :cond_8

    .line 161
    .line 162
    iget v14, v14, Lk4/t;->a:I

    .line 163
    .line 164
    const/4 v15, 0x4

    .line 165
    invoke-virtual {v0, v15}, Lro/f;->g(B)V

    .line 166
    .line 167
    .line 168
    if-nez v14, :cond_7

    .line 169
    .line 170
    :cond_6
    const/4 v15, 0x0

    .line 171
    goto :goto_3

    .line 172
    :cond_7
    const/4 v15, 0x1

    .line 173
    if-ne v14, v15, :cond_6

    .line 174
    .line 175
    const/4 v15, 0x1

    .line 176
    :goto_3
    invoke-virtual {v0, v15}, Lro/f;->g(B)V

    .line 177
    .line 178
    .line 179
    :cond_8
    iget-object v14, v7, Lg4/g0;->e:Lk4/u;

    .line 180
    .line 181
    if-eqz v14, :cond_d

    .line 182
    .line 183
    iget v14, v14, Lk4/u;->a:I

    .line 184
    .line 185
    const/4 v15, 0x5

    .line 186
    invoke-virtual {v0, v15}, Lro/f;->g(B)V

    .line 187
    .line 188
    .line 189
    if-nez v14, :cond_a

    .line 190
    .line 191
    :cond_9
    const/4 v6, 0x0

    .line 192
    goto :goto_4

    .line 193
    :cond_a
    const v15, 0xffff

    .line 194
    .line 195
    .line 196
    if-ne v14, v15, :cond_b

    .line 197
    .line 198
    const/4 v6, 0x1

    .line 199
    goto :goto_4

    .line 200
    :cond_b
    const/4 v15, 0x1

    .line 201
    if-ne v14, v15, :cond_c

    .line 202
    .line 203
    goto :goto_4

    .line 204
    :cond_c
    if-ne v14, v6, :cond_9

    .line 205
    .line 206
    const/4 v6, 0x3

    .line 207
    :goto_4
    invoke-virtual {v0, v6}, Lro/f;->g(B)V

    .line 208
    .line 209
    .line 210
    :cond_d
    iget-object v6, v7, Lg4/g0;->g:Ljava/lang/String;

    .line 211
    .line 212
    if-eqz v6, :cond_e

    .line 213
    .line 214
    const/4 v14, 0x6

    .line 215
    invoke-virtual {v0, v14}, Lro/f;->g(B)V

    .line 216
    .line 217
    .line 218
    iget-object v14, v0, Lro/f;->e:Ljava/lang/Object;

    .line 219
    .line 220
    check-cast v14, Landroid/os/Parcel;

    .line 221
    .line 222
    invoke-virtual {v14, v6}, Landroid/os/Parcel;->writeString(Ljava/lang/String;)V

    .line 223
    .line 224
    .line 225
    :cond_e
    invoke-static {v12, v13, v4, v5}, Lt4/o;->a(JJ)Z

    .line 226
    .line 227
    .line 228
    move-result v4

    .line 229
    if-nez v4, :cond_f

    .line 230
    .line 231
    const/4 v4, 0x7

    .line 232
    invoke-virtual {v0, v4}, Lro/f;->g(B)V

    .line 233
    .line 234
    .line 235
    invoke-virtual {v0, v12, v13}, Lro/f;->i(J)V

    .line 236
    .line 237
    .line 238
    :cond_f
    iget-object v4, v7, Lg4/g0;->i:Lr4/a;

    .line 239
    .line 240
    if-eqz v4, :cond_10

    .line 241
    .line 242
    iget v4, v4, Lr4/a;->a:F

    .line 243
    .line 244
    const/16 v5, 0x8

    .line 245
    .line 246
    invoke-virtual {v0, v5}, Lro/f;->g(B)V

    .line 247
    .line 248
    .line 249
    invoke-virtual {v0, v4}, Lro/f;->h(F)V

    .line 250
    .line 251
    .line 252
    :cond_10
    iget-object v4, v7, Lg4/g0;->j:Lr4/p;

    .line 253
    .line 254
    if-eqz v4, :cond_11

    .line 255
    .line 256
    const/16 v5, 0x9

    .line 257
    .line 258
    invoke-virtual {v0, v5}, Lro/f;->g(B)V

    .line 259
    .line 260
    .line 261
    iget v5, v4, Lr4/p;->a:F

    .line 262
    .line 263
    invoke-virtual {v0, v5}, Lro/f;->h(F)V

    .line 264
    .line 265
    .line 266
    iget v4, v4, Lr4/p;->b:F

    .line 267
    .line 268
    invoke-virtual {v0, v4}, Lro/f;->h(F)V

    .line 269
    .line 270
    .line 271
    :cond_11
    invoke-static {v10, v11, v1, v2}, Le3/s;->c(JJ)Z

    .line 272
    .line 273
    .line 274
    move-result v1

    .line 275
    if-nez v1, :cond_12

    .line 276
    .line 277
    const/16 v1, 0xa

    .line 278
    .line 279
    invoke-virtual {v0, v1}, Lro/f;->g(B)V

    .line 280
    .line 281
    .line 282
    invoke-virtual {v0, v10, v11}, Lro/f;->j(J)V

    .line 283
    .line 284
    .line 285
    :cond_12
    iget-object v1, v7, Lg4/g0;->m:Lr4/l;

    .line 286
    .line 287
    if-eqz v1, :cond_13

    .line 288
    .line 289
    const/16 v2, 0xb

    .line 290
    .line 291
    invoke-virtual {v0, v2}, Lro/f;->g(B)V

    .line 292
    .line 293
    .line 294
    iget v1, v1, Lr4/l;->a:I

    .line 295
    .line 296
    iget-object v2, v0, Lro/f;->e:Ljava/lang/Object;

    .line 297
    .line 298
    check-cast v2, Landroid/os/Parcel;

    .line 299
    .line 300
    invoke-virtual {v2, v1}, Landroid/os/Parcel;->writeInt(I)V

    .line 301
    .line 302
    .line 303
    :cond_13
    iget-object v1, v7, Lg4/g0;->n:Le3/m0;

    .line 304
    .line 305
    if-eqz v1, :cond_14

    .line 306
    .line 307
    const/16 v2, 0xc

    .line 308
    .line 309
    invoke-virtual {v0, v2}, Lro/f;->g(B)V

    .line 310
    .line 311
    .line 312
    iget-wide v4, v1, Le3/m0;->a:J

    .line 313
    .line 314
    invoke-virtual {v0, v4, v5}, Lro/f;->j(J)V

    .line 315
    .line 316
    .line 317
    iget-wide v4, v1, Le3/m0;->b:J

    .line 318
    .line 319
    const/16 v2, 0x20

    .line 320
    .line 321
    shr-long v6, v4, v2

    .line 322
    .line 323
    long-to-int v2, v6

    .line 324
    invoke-static {v2}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 325
    .line 326
    .line 327
    move-result v2

    .line 328
    invoke-virtual {v0, v2}, Lro/f;->h(F)V

    .line 329
    .line 330
    .line 331
    const-wide v6, 0xffffffffL

    .line 332
    .line 333
    .line 334
    .line 335
    .line 336
    and-long/2addr v4, v6

    .line 337
    long-to-int v2, v4

    .line 338
    invoke-static {v2}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 339
    .line 340
    .line 341
    move-result v2

    .line 342
    invoke-virtual {v0, v2}, Lro/f;->h(F)V

    .line 343
    .line 344
    .line 345
    iget v1, v1, Le3/m0;->c:F

    .line 346
    .line 347
    invoke-virtual {v0, v1}, Lro/f;->h(F)V

    .line 348
    .line 349
    .line 350
    :cond_14
    new-instance v1, Landroid/text/Annotation;

    .line 351
    .line 352
    iget-object v2, v0, Lro/f;->e:Ljava/lang/Object;

    .line 353
    .line 354
    check-cast v2, Landroid/os/Parcel;

    .line 355
    .line 356
    invoke-virtual {v2}, Landroid/os/Parcel;->marshall()[B

    .line 357
    .line 358
    .line 359
    move-result-object v2

    .line 360
    const/4 v4, 0x0

    .line 361
    invoke-static {v2, v4}, Landroid/util/Base64;->encodeToString([BI)Ljava/lang/String;

    .line 362
    .line 363
    .line 364
    move-result-object v2

    .line 365
    const-string v5, "androidx.compose.text.SpanStyle"

    .line 366
    .line 367
    invoke-direct {v1, v5, v2}, Landroid/text/Annotation;-><init>(Ljava/lang/String;Ljava/lang/String;)V

    .line 368
    .line 369
    .line 370
    const/16 v2, 0x21

    .line 371
    .line 372
    move/from16 v5, v18

    .line 373
    .line 374
    invoke-virtual {v3, v1, v8, v5, v2}, Landroid/text/SpannableString;->setSpan(Ljava/lang/Object;III)V

    .line 375
    .line 376
    .line 377
    add-int/lit8 v5, v16, 0x1

    .line 378
    .line 379
    move-object v1, v9

    .line 380
    move/from16 v2, v17

    .line 381
    .line 382
    goto/16 :goto_1

    .line 383
    .line 384
    :cond_15
    move-object v0, v3

    .line 385
    :goto_5
    const-string v1, "plain text"

    .line 386
    .line 387
    invoke-static {v1, v0}, Landroid/content/ClipData;->newPlainText(Ljava/lang/CharSequence;Ljava/lang/CharSequence;)Landroid/content/ClipData;

    .line 388
    .line 389
    .line 390
    move-result-object v0

    .line 391
    move-object/from16 v1, p0

    .line 392
    .line 393
    iget-object v1, v1, Lw3/i;->a:Landroid/content/ClipboardManager;

    .line 394
    .line 395
    invoke-virtual {v1, v0}, Landroid/content/ClipboardManager;->setPrimaryClip(Landroid/content/ClipData;)V

    .line 396
    .line 397
    .line 398
    return-void
.end method
