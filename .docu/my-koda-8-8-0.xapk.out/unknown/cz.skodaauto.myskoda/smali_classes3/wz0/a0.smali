.class public final Lwz0/a0;
.super Llp/u0;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lvz0/l;


# instance fields
.field public final a:Lvz0/d;

.field public final b:Lwz0/f0;

.field public final c:Lo8/j;

.field public final d:Lwq/f;

.field public e:I

.field public f:Lgr/f;

.field public final g:Lvz0/k;

.field public final h:Lwz0/m;


# direct methods
.method public constructor <init>(Lvz0/d;Lwz0/f0;Lo8/j;Lsz0/g;Lgr/f;)V
    .locals 1

    .line 1
    const-string v0, "descriptor"

    .line 2
    .line 3
    invoke-static {p4, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object p1, p0, Lwz0/a0;->a:Lvz0/d;

    .line 10
    .line 11
    iput-object p2, p0, Lwz0/a0;->b:Lwz0/f0;

    .line 12
    .line 13
    iput-object p3, p0, Lwz0/a0;->c:Lo8/j;

    .line 14
    .line 15
    iget-object p2, p1, Lvz0/d;->b:Lwq/f;

    .line 16
    .line 17
    iput-object p2, p0, Lwz0/a0;->d:Lwq/f;

    .line 18
    .line 19
    const/4 p2, -0x1

    .line 20
    iput p2, p0, Lwz0/a0;->e:I

    .line 21
    .line 22
    iput-object p5, p0, Lwz0/a0;->f:Lgr/f;

    .line 23
    .line 24
    iget-object p1, p1, Lvz0/d;->a:Lvz0/k;

    .line 25
    .line 26
    iput-object p1, p0, Lwz0/a0;->g:Lvz0/k;

    .line 27
    .line 28
    iget-boolean p1, p1, Lvz0/k;->e:Z

    .line 29
    .line 30
    if-eqz p1, :cond_0

    .line 31
    .line 32
    const/4 p1, 0x0

    .line 33
    goto :goto_0

    .line 34
    :cond_0
    new-instance p1, Lwz0/m;

    .line 35
    .line 36
    invoke-direct {p1, p4}, Lwz0/m;-><init>(Lsz0/g;)V

    .line 37
    .line 38
    .line 39
    :goto_0
    iput-object p1, p0, Lwz0/a0;->h:Lwz0/m;

    .line 40
    .line 41
    return-void
.end method


# virtual methods
.method public final C(Lsz0/g;)Ltz0/c;
    .locals 1

    .line 1
    const-string v0, "descriptor"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-static {p1}, Lwz0/c0;->a(Lsz0/g;)Z

    .line 7
    .line 8
    .line 9
    move-result p1

    .line 10
    if-eqz p1, :cond_0

    .line 11
    .line 12
    new-instance p1, Lwz0/k;

    .line 13
    .line 14
    iget-object v0, p0, Lwz0/a0;->c:Lo8/j;

    .line 15
    .line 16
    iget-object p0, p0, Lwz0/a0;->a:Lvz0/d;

    .line 17
    .line 18
    invoke-direct {p1, v0, p0}, Lwz0/k;-><init>(Lo8/j;Lvz0/d;)V

    .line 19
    .line 20
    .line 21
    return-object p1

    .line 22
    :cond_0
    return-object p0
.end method

.method public final D()B
    .locals 5

    .line 1
    iget-object p0, p0, Lwz0/a0;->c:Lo8/j;

    .line 2
    .line 3
    invoke-virtual {p0}, Lo8/j;->i()J

    .line 4
    .line 5
    .line 6
    move-result-wide v0

    .line 7
    long-to-int v2, v0

    .line 8
    int-to-byte v2, v2

    .line 9
    int-to-long v3, v2

    .line 10
    cmp-long v3, v0, v3

    .line 11
    .line 12
    if-nez v3, :cond_0

    .line 13
    .line 14
    return v2

    .line 15
    :cond_0
    new-instance v2, Ljava/lang/StringBuilder;

    .line 16
    .line 17
    const-string v3, "Failed to parse byte for input \'"

    .line 18
    .line 19
    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 20
    .line 21
    .line 22
    invoke-virtual {v2, v0, v1}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    .line 23
    .line 24
    .line 25
    const/16 v0, 0x27

    .line 26
    .line 27
    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 28
    .line 29
    .line 30
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 31
    .line 32
    .line 33
    move-result-object v0

    .line 34
    const/4 v1, 0x0

    .line 35
    const/4 v2, 0x6

    .line 36
    const/4 v3, 0x0

    .line 37
    invoke-static {p0, v0, v1, v3, v2}, Lo8/j;->r(Lo8/j;Ljava/lang/String;ILjava/lang/String;I)V

    .line 38
    .line 39
    .line 40
    throw v3
.end method

.method public final E(Lsz0/g;)I
    .locals 20

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    iget-object v2, v0, Lwz0/a0;->c:Lo8/j;

    .line 6
    .line 7
    iget-object v3, v2, Lo8/j;->c:Ljava/lang/Object;

    .line 8
    .line 9
    check-cast v3, Lbb/g0;

    .line 10
    .line 11
    const-string v4, "descriptor"

    .line 12
    .line 13
    invoke-static {v1, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    iget-object v4, v0, Lwz0/a0;->b:Lwz0/f0;

    .line 17
    .line 18
    invoke-virtual {v4}, Ljava/lang/Enum;->ordinal()I

    .line 19
    .line 20
    .line 21
    move-result v5

    .line 22
    const-string v6, "object"

    .line 23
    .line 24
    const/4 v7, 0x6

    .line 25
    const/16 v8, 0x3a

    .line 26
    .line 27
    const/4 v9, 0x0

    .line 28
    const/4 v10, 0x1

    .line 29
    const/4 v11, -0x1

    .line 30
    const/4 v12, 0x0

    .line 31
    if-eqz v5, :cond_e

    .line 32
    .line 33
    const/4 v1, 0x2

    .line 34
    if-eq v5, v1, :cond_4

    .line 35
    .line 36
    invoke-virtual {v2}, Lo8/j;->E()Z

    .line 37
    .line 38
    .line 39
    move-result v1

    .line 40
    invoke-virtual {v2}, Lo8/j;->c()Z

    .line 41
    .line 42
    .line 43
    move-result v5

    .line 44
    if-eqz v5, :cond_2

    .line 45
    .line 46
    iget v5, v0, Lwz0/a0;->e:I

    .line 47
    .line 48
    if-eq v5, v11, :cond_1

    .line 49
    .line 50
    if-eqz v1, :cond_0

    .line 51
    .line 52
    goto :goto_0

    .line 53
    :cond_0
    const-string v0, "Expected end of the array or comma"

    .line 54
    .line 55
    invoke-static {v2, v0, v9, v12, v7}, Lo8/j;->r(Lo8/j;Ljava/lang/String;ILjava/lang/String;I)V

    .line 56
    .line 57
    .line 58
    throw v12

    .line 59
    :cond_1
    :goto_0
    add-int/lit8 v11, v5, 0x1

    .line 60
    .line 61
    iput v11, v0, Lwz0/a0;->e:I

    .line 62
    .line 63
    goto/16 :goto_10

    .line 64
    .line 65
    :cond_2
    if-nez v1, :cond_3

    .line 66
    .line 67
    goto/16 :goto_10

    .line 68
    .line 69
    :cond_3
    const-string v0, "array"

    .line 70
    .line 71
    invoke-static {v2, v0}, Lwz0/p;->m(Lo8/j;Ljava/lang/String;)V

    .line 72
    .line 73
    .line 74
    throw v12

    .line 75
    :cond_4
    iget v1, v0, Lwz0/a0;->e:I

    .line 76
    .line 77
    rem-int/lit8 v5, v1, 0x2

    .line 78
    .line 79
    if-eqz v5, :cond_5

    .line 80
    .line 81
    move v5, v10

    .line 82
    goto :goto_1

    .line 83
    :cond_5
    move v5, v9

    .line 84
    :goto_1
    if-eqz v5, :cond_6

    .line 85
    .line 86
    if-eq v1, v11, :cond_7

    .line 87
    .line 88
    invoke-virtual {v2}, Lo8/j;->E()Z

    .line 89
    .line 90
    .line 91
    move-result v9

    .line 92
    goto :goto_2

    .line 93
    :cond_6
    invoke-virtual {v2, v8}, Lo8/j;->h(C)V

    .line 94
    .line 95
    .line 96
    :cond_7
    :goto_2
    invoke-virtual {v2}, Lo8/j;->c()Z

    .line 97
    .line 98
    .line 99
    move-result v1

    .line 100
    if-eqz v1, :cond_c

    .line 101
    .line 102
    if-eqz v5, :cond_b

    .line 103
    .line 104
    iget v1, v0, Lwz0/a0;->e:I

    .line 105
    .line 106
    const/4 v5, 0x4

    .line 107
    if-ne v1, v11, :cond_9

    .line 108
    .line 109
    iget v1, v2, Lo8/j;->b:I

    .line 110
    .line 111
    if-nez v9, :cond_8

    .line 112
    .line 113
    goto :goto_3

    .line 114
    :cond_8
    const-string v0, "Unexpected leading comma"

    .line 115
    .line 116
    invoke-static {v2, v0, v1, v12, v5}, Lo8/j;->r(Lo8/j;Ljava/lang/String;ILjava/lang/String;I)V

    .line 117
    .line 118
    .line 119
    throw v12

    .line 120
    :cond_9
    iget v1, v2, Lo8/j;->b:I

    .line 121
    .line 122
    if-eqz v9, :cond_a

    .line 123
    .line 124
    goto :goto_3

    .line 125
    :cond_a
    const-string v0, "Expected comma after the key-value pair"

    .line 126
    .line 127
    invoke-static {v2, v0, v1, v12, v5}, Lo8/j;->r(Lo8/j;Ljava/lang/String;ILjava/lang/String;I)V

    .line 128
    .line 129
    .line 130
    throw v12

    .line 131
    :cond_b
    :goto_3
    iget v1, v0, Lwz0/a0;->e:I

    .line 132
    .line 133
    add-int/lit8 v11, v1, 0x1

    .line 134
    .line 135
    iput v11, v0, Lwz0/a0;->e:I

    .line 136
    .line 137
    goto/16 :goto_10

    .line 138
    .line 139
    :cond_c
    if-nez v9, :cond_d

    .line 140
    .line 141
    goto/16 :goto_10

    .line 142
    .line 143
    :cond_d
    invoke-static {v2, v6}, Lwz0/p;->m(Lo8/j;Ljava/lang/String;)V

    .line 144
    .line 145
    .line 146
    throw v12

    .line 147
    :cond_e
    invoke-virtual {v2}, Lo8/j;->E()Z

    .line 148
    .line 149
    .line 150
    move-result v5

    .line 151
    :goto_4
    invoke-virtual {v2}, Lo8/j;->c()Z

    .line 152
    .line 153
    .line 154
    move-result v13

    .line 155
    const/16 v14, 0x40

    .line 156
    .line 157
    const-wide/16 v16, 0x1

    .line 158
    .line 159
    iget-object v15, v0, Lwz0/a0;->h:Lwz0/m;

    .line 160
    .line 161
    if-eqz v13, :cond_22

    .line 162
    .line 163
    iget-object v5, v0, Lwz0/a0;->g:Lvz0/k;

    .line 164
    .line 165
    iget-boolean v13, v5, Lvz0/k;->c:Z

    .line 166
    .line 167
    if-eqz v13, :cond_f

    .line 168
    .line 169
    invoke-virtual {v2}, Lo8/j;->m()Ljava/lang/String;

    .line 170
    .line 171
    .line 172
    move-result-object v5

    .line 173
    goto :goto_5

    .line 174
    :cond_f
    invoke-virtual {v2}, Lo8/j;->e()Ljava/lang/String;

    .line 175
    .line 176
    .line 177
    move-result-object v5

    .line 178
    :goto_5
    invoke-virtual {v2, v8}, Lo8/j;->h(C)V

    .line 179
    .line 180
    .line 181
    iget-object v8, v0, Lwz0/a0;->a:Lvz0/d;

    .line 182
    .line 183
    move/from16 v18, v10

    .line 184
    .line 185
    invoke-static {v1, v8, v5}, Lwz0/p;->j(Lsz0/g;Lvz0/d;Ljava/lang/String;)I

    .line 186
    .line 187
    .line 188
    move-result v10

    .line 189
    const/4 v7, -0x3

    .line 190
    if-eq v10, v7, :cond_12

    .line 191
    .line 192
    if-eqz v15, :cond_10

    .line 193
    .line 194
    iget-object v0, v15, Lwz0/m;->a:Luz0/w;

    .line 195
    .line 196
    if-ge v10, v14, :cond_11

    .line 197
    .line 198
    iget-wide v1, v0, Luz0/w;->c:J

    .line 199
    .line 200
    shl-long v5, v16, v10

    .line 201
    .line 202
    or-long/2addr v1, v5

    .line 203
    iput-wide v1, v0, Luz0/w;->c:J

    .line 204
    .line 205
    :cond_10
    :goto_6
    move v11, v10

    .line 206
    goto/16 :goto_10

    .line 207
    .line 208
    :cond_11
    ushr-int/lit8 v1, v10, 0x6

    .line 209
    .line 210
    add-int/lit8 v1, v1, -0x1

    .line 211
    .line 212
    and-int/lit8 v2, v10, 0x3f

    .line 213
    .line 214
    iget-object v0, v0, Luz0/w;->d:[J

    .line 215
    .line 216
    aget-wide v5, v0, v1

    .line 217
    .line 218
    shl-long v7, v16, v2

    .line 219
    .line 220
    or-long/2addr v5, v7

    .line 221
    aput-wide v5, v0, v1

    .line 222
    .line 223
    goto :goto_6

    .line 224
    :cond_12
    invoke-static {v1, v8}, Lwz0/p;->l(Lsz0/g;Lvz0/d;)Z

    .line 225
    .line 226
    .line 227
    move-result v7

    .line 228
    if-nez v7, :cond_16

    .line 229
    .line 230
    iget-object v7, v0, Lwz0/a0;->f:Lgr/f;

    .line 231
    .line 232
    if-eqz v7, :cond_13

    .line 233
    .line 234
    iget-object v8, v7, Lgr/f;->a:Ljava/lang/String;

    .line 235
    .line 236
    invoke-static {v8, v5}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 237
    .line 238
    .line 239
    move-result v8

    .line 240
    if-eqz v8, :cond_13

    .line 241
    .line 242
    iput-object v12, v7, Lgr/f;->a:Ljava/lang/String;

    .line 243
    .line 244
    goto :goto_7

    .line 245
    :cond_13
    iget v0, v3, Lbb/g0;->e:I

    .line 246
    .line 247
    iget-object v1, v3, Lbb/g0;->g:Ljava/lang/Object;

    .line 248
    .line 249
    check-cast v1, [I

    .line 250
    .line 251
    aget v4, v1, v0

    .line 252
    .line 253
    const/4 v6, -0x2

    .line 254
    if-ne v4, v6, :cond_14

    .line 255
    .line 256
    aput v11, v1, v0

    .line 257
    .line 258
    add-int/2addr v0, v11

    .line 259
    iput v0, v3, Lbb/g0;->e:I

    .line 260
    .line 261
    :cond_14
    iget v0, v3, Lbb/g0;->e:I

    .line 262
    .line 263
    if-eq v0, v11, :cond_15

    .line 264
    .line 265
    add-int/2addr v0, v11

    .line 266
    iput v0, v3, Lbb/g0;->e:I

    .line 267
    .line 268
    :cond_15
    iget v0, v2, Lo8/j;->b:I

    .line 269
    .line 270
    invoke-virtual {v2, v9, v0}, Lo8/j;->D(II)Ljava/lang/String;

    .line 271
    .line 272
    .line 273
    move-result-object v0

    .line 274
    const/4 v1, 0x6

    .line 275
    invoke-static {v0, v5, v9, v1}, Lly0/p;->P(Ljava/lang/String;Ljava/lang/String;II)I

    .line 276
    .line 277
    .line 278
    move-result v0

    .line 279
    new-instance v1, Lwz0/l;

    .line 280
    .line 281
    const-string v4, "\' at offset "

    .line 282
    .line 283
    const-string v6, " at path: "

    .line 284
    .line 285
    const-string v7, "Encountered an unknown key \'"

    .line 286
    .line 287
    invoke-static {v7, v0, v5, v4, v6}, La7/g0;->m(Ljava/lang/String;ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 288
    .line 289
    .line 290
    move-result-object v4

    .line 291
    invoke-virtual {v3}, Lbb/g0;->l()Ljava/lang/String;

    .line 292
    .line 293
    .line 294
    move-result-object v3

    .line 295
    invoke-virtual {v4, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 296
    .line 297
    .line 298
    const-string v3, "\nUse \'ignoreUnknownKeys = true\' in \'Json {}\' builder or \'@JsonIgnoreUnknownKeys\' annotation to ignore unknown keys.\nJSON input: "

    .line 299
    .line 300
    invoke-virtual {v4, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 301
    .line 302
    .line 303
    invoke-virtual {v2}, Lo8/j;->t()Ljava/lang/CharSequence;

    .line 304
    .line 305
    .line 306
    move-result-object v2

    .line 307
    invoke-static {v0, v2}, Lwz0/p;->n(ILjava/lang/CharSequence;)Ljava/lang/CharSequence;

    .line 308
    .line 309
    .line 310
    move-result-object v0

    .line 311
    invoke-virtual {v4, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 312
    .line 313
    .line 314
    invoke-virtual {v4}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 315
    .line 316
    .line 317
    move-result-object v0

    .line 318
    const/4 v2, 0x0

    .line 319
    invoke-direct {v1, v0, v2}, Lwz0/l;-><init>(Ljava/lang/String;I)V

    .line 320
    .line 321
    .line 322
    throw v1

    .line 323
    :cond_16
    :goto_7
    new-instance v7, Ljava/util/ArrayList;

    .line 324
    .line 325
    invoke-direct {v7}, Ljava/util/ArrayList;-><init>()V

    .line 326
    .line 327
    .line 328
    invoke-virtual {v2}, Lo8/j;->x()B

    .line 329
    .line 330
    .line 331
    move-result v5

    .line 332
    const/16 v8, 0x8

    .line 333
    .line 334
    if-eq v5, v8, :cond_17

    .line 335
    .line 336
    const/4 v10, 0x6

    .line 337
    if-eq v5, v10, :cond_17

    .line 338
    .line 339
    invoke-virtual {v2}, Lo8/j;->l()Ljava/lang/String;

    .line 340
    .line 341
    .line 342
    move/from16 v10, v18

    .line 343
    .line 344
    const/4 v14, 0x6

    .line 345
    goto/16 :goto_d

    .line 346
    .line 347
    :cond_17
    :goto_8
    invoke-virtual {v2}, Lo8/j;->x()B

    .line 348
    .line 349
    .line 350
    move-result v5

    .line 351
    move/from16 v10, v18

    .line 352
    .line 353
    if-ne v5, v10, :cond_1a

    .line 354
    .line 355
    if-eqz v13, :cond_18

    .line 356
    .line 357
    invoke-virtual {v2}, Lo8/j;->l()Ljava/lang/String;

    .line 358
    .line 359
    .line 360
    goto :goto_9

    .line 361
    :cond_18
    invoke-virtual {v2}, Lo8/j;->e()Ljava/lang/String;

    .line 362
    .line 363
    .line 364
    :cond_19
    :goto_9
    move/from16 v18, v10

    .line 365
    .line 366
    goto :goto_8

    .line 367
    :cond_1a
    const/4 v14, 0x6

    .line 368
    if-eq v5, v8, :cond_21

    .line 369
    .line 370
    if-ne v5, v14, :cond_1b

    .line 371
    .line 372
    goto :goto_b

    .line 373
    :cond_1b
    const/16 v14, 0x9

    .line 374
    .line 375
    if-ne v5, v14, :cond_1d

    .line 376
    .line 377
    invoke-static {v7}, Lmx0/q;->T(Ljava/util/List;)Ljava/lang/Object;

    .line 378
    .line 379
    .line 380
    move-result-object v5

    .line 381
    check-cast v5, Ljava/lang/Number;

    .line 382
    .line 383
    invoke-virtual {v5}, Ljava/lang/Number;->byteValue()B

    .line 384
    .line 385
    .line 386
    move-result v5

    .line 387
    if-ne v5, v8, :cond_1c

    .line 388
    .line 389
    invoke-static {v7}, Lmx0/q;->e0(Ljava/util/List;)Ljava/lang/Object;

    .line 390
    .line 391
    .line 392
    :goto_a
    const/4 v14, 0x6

    .line 393
    goto :goto_c

    .line 394
    :cond_1c
    iget v0, v2, Lo8/j;->b:I

    .line 395
    .line 396
    new-instance v1, Ljava/lang/StringBuilder;

    .line 397
    .line 398
    const-string v4, "found ] instead of } at path: "

    .line 399
    .line 400
    invoke-direct {v1, v4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 401
    .line 402
    .line 403
    invoke-virtual {v1, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 404
    .line 405
    .line 406
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 407
    .line 408
    .line 409
    move-result-object v1

    .line 410
    invoke-virtual {v2}, Lo8/j;->t()Ljava/lang/CharSequence;

    .line 411
    .line 412
    .line 413
    move-result-object v2

    .line 414
    invoke-static {v0, v2, v1}, Lwz0/p;->c(ILjava/lang/CharSequence;Ljava/lang/String;)Lwz0/l;

    .line 415
    .line 416
    .line 417
    move-result-object v0

    .line 418
    throw v0

    .line 419
    :cond_1d
    const/4 v14, 0x7

    .line 420
    if-ne v5, v14, :cond_1f

    .line 421
    .line 422
    invoke-static {v7}, Lmx0/q;->T(Ljava/util/List;)Ljava/lang/Object;

    .line 423
    .line 424
    .line 425
    move-result-object v5

    .line 426
    check-cast v5, Ljava/lang/Number;

    .line 427
    .line 428
    invoke-virtual {v5}, Ljava/lang/Number;->byteValue()B

    .line 429
    .line 430
    .line 431
    move-result v5

    .line 432
    const/4 v14, 0x6

    .line 433
    if-ne v5, v14, :cond_1e

    .line 434
    .line 435
    invoke-static {v7}, Lmx0/q;->e0(Ljava/util/List;)Ljava/lang/Object;

    .line 436
    .line 437
    .line 438
    goto :goto_a

    .line 439
    :cond_1e
    iget v0, v2, Lo8/j;->b:I

    .line 440
    .line 441
    new-instance v1, Ljava/lang/StringBuilder;

    .line 442
    .line 443
    const-string v4, "found } instead of ] at path: "

    .line 444
    .line 445
    invoke-direct {v1, v4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 446
    .line 447
    .line 448
    invoke-virtual {v1, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 449
    .line 450
    .line 451
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 452
    .line 453
    .line 454
    move-result-object v1

    .line 455
    invoke-virtual {v2}, Lo8/j;->t()Ljava/lang/CharSequence;

    .line 456
    .line 457
    .line 458
    move-result-object v2

    .line 459
    invoke-static {v0, v2, v1}, Lwz0/p;->c(ILjava/lang/CharSequence;Ljava/lang/String;)Lwz0/l;

    .line 460
    .line 461
    .line 462
    move-result-object v0

    .line 463
    throw v0

    .line 464
    :cond_1f
    const/16 v14, 0xa

    .line 465
    .line 466
    if-eq v5, v14, :cond_20

    .line 467
    .line 468
    goto :goto_a

    .line 469
    :cond_20
    const-string v0, "Unexpected end of input due to malformed JSON during ignoring unknown keys"

    .line 470
    .line 471
    const/4 v14, 0x6

    .line 472
    invoke-static {v2, v0, v9, v12, v14}, Lo8/j;->r(Lo8/j;Ljava/lang/String;ILjava/lang/String;I)V

    .line 473
    .line 474
    .line 475
    throw v12

    .line 476
    :cond_21
    :goto_b
    invoke-static {v5}, Ljava/lang/Byte;->valueOf(B)Ljava/lang/Byte;

    .line 477
    .line 478
    .line 479
    move-result-object v5

    .line 480
    invoke-virtual {v7, v5}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 481
    .line 482
    .line 483
    :goto_c
    invoke-virtual {v2}, Lo8/j;->f()B

    .line 484
    .line 485
    .line 486
    invoke-virtual {v7}, Ljava/util/ArrayList;->size()I

    .line 487
    .line 488
    .line 489
    move-result v5

    .line 490
    if-nez v5, :cond_19

    .line 491
    .line 492
    :goto_d
    invoke-virtual {v2}, Lo8/j;->E()Z

    .line 493
    .line 494
    .line 495
    move-result v5

    .line 496
    move v7, v14

    .line 497
    const/16 v8, 0x3a

    .line 498
    .line 499
    goto/16 :goto_4

    .line 500
    .line 501
    :cond_22
    if-nez v5, :cond_29

    .line 502
    .line 503
    if-eqz v15, :cond_27

    .line 504
    .line 505
    iget-object v0, v15, Lwz0/m;->a:Luz0/w;

    .line 506
    .line 507
    iget-object v1, v0, Luz0/w;->b:Lth/b;

    .line 508
    .line 509
    iget-object v2, v0, Luz0/w;->a:Lsz0/g;

    .line 510
    .line 511
    invoke-interface {v2}, Lsz0/g;->d()I

    .line 512
    .line 513
    .line 514
    move-result v5

    .line 515
    :cond_23
    iget-wide v6, v0, Luz0/w;->c:J

    .line 516
    .line 517
    const-wide/16 v12, -0x1

    .line 518
    .line 519
    cmp-long v8, v6, v12

    .line 520
    .line 521
    if-eqz v8, :cond_24

    .line 522
    .line 523
    not-long v6, v6

    .line 524
    invoke-static {v6, v7}, Ljava/lang/Long;->numberOfTrailingZeros(J)I

    .line 525
    .line 526
    .line 527
    move-result v6

    .line 528
    iget-wide v7, v0, Luz0/w;->c:J

    .line 529
    .line 530
    shl-long v12, v16, v6

    .line 531
    .line 532
    or-long/2addr v7, v12

    .line 533
    iput-wide v7, v0, Luz0/w;->c:J

    .line 534
    .line 535
    invoke-static {v6}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 536
    .line 537
    .line 538
    move-result-object v7

    .line 539
    invoke-virtual {v1, v2, v7}, Lth/b;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 540
    .line 541
    .line 542
    move-result-object v7

    .line 543
    check-cast v7, Ljava/lang/Boolean;

    .line 544
    .line 545
    invoke-virtual {v7}, Ljava/lang/Boolean;->booleanValue()Z

    .line 546
    .line 547
    .line 548
    move-result v7

    .line 549
    if-eqz v7, :cond_23

    .line 550
    .line 551
    move v11, v6

    .line 552
    goto :goto_10

    .line 553
    :cond_24
    if-le v5, v14, :cond_27

    .line 554
    .line 555
    iget-object v0, v0, Luz0/w;->d:[J

    .line 556
    .line 557
    array-length v5, v0

    .line 558
    :goto_e
    if-ge v9, v5, :cond_27

    .line 559
    .line 560
    add-int/lit8 v6, v9, 0x1

    .line 561
    .line 562
    mul-int/lit8 v7, v6, 0x40

    .line 563
    .line 564
    aget-wide v14, v0, v9

    .line 565
    .line 566
    :goto_f
    cmp-long v8, v14, v12

    .line 567
    .line 568
    if-eqz v8, :cond_26

    .line 569
    .line 570
    not-long v11, v14

    .line 571
    invoke-static {v11, v12}, Ljava/lang/Long;->numberOfTrailingZeros(J)I

    .line 572
    .line 573
    .line 574
    move-result v10

    .line 575
    shl-long v11, v16, v10

    .line 576
    .line 577
    or-long/2addr v14, v11

    .line 578
    add-int/2addr v10, v7

    .line 579
    invoke-static {v10}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 580
    .line 581
    .line 582
    move-result-object v11

    .line 583
    invoke-virtual {v1, v2, v11}, Lth/b;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 584
    .line 585
    .line 586
    move-result-object v11

    .line 587
    check-cast v11, Ljava/lang/Boolean;

    .line 588
    .line 589
    invoke-virtual {v11}, Ljava/lang/Boolean;->booleanValue()Z

    .line 590
    .line 591
    .line 592
    move-result v11

    .line 593
    if-eqz v11, :cond_25

    .line 594
    .line 595
    aput-wide v14, v0, v9

    .line 596
    .line 597
    goto/16 :goto_6

    .line 598
    .line 599
    :cond_25
    const/4 v11, -0x1

    .line 600
    const-wide/16 v12, -0x1

    .line 601
    .line 602
    goto :goto_f

    .line 603
    :cond_26
    aput-wide v14, v0, v9

    .line 604
    .line 605
    move v9, v6

    .line 606
    const/4 v11, -0x1

    .line 607
    const-wide/16 v12, -0x1

    .line 608
    .line 609
    goto :goto_e

    .line 610
    :cond_27
    const/4 v11, -0x1

    .line 611
    :goto_10
    sget-object v0, Lwz0/f0;->h:Lwz0/f0;

    .line 612
    .line 613
    if-eq v4, v0, :cond_28

    .line 614
    .line 615
    iget-object v0, v3, Lbb/g0;->g:Ljava/lang/Object;

    .line 616
    .line 617
    check-cast v0, [I

    .line 618
    .line 619
    iget v1, v3, Lbb/g0;->e:I

    .line 620
    .line 621
    aput v11, v0, v1

    .line 622
    .line 623
    :cond_28
    return v11

    .line 624
    :cond_29
    invoke-static {v2, v6}, Lwz0/p;->m(Lo8/j;Ljava/lang/String;)V

    .line 625
    .line 626
    .line 627
    throw v12
.end method

.method public final a(Lsz0/g;)Ltz0/a;
    .locals 7

    .line 1
    const-string v0, "descriptor"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object v2, p0, Lwz0/a0;->a:Lvz0/d;

    .line 7
    .line 8
    invoke-static {p1, v2}, Lwz0/p;->q(Lsz0/g;Lvz0/d;)Lwz0/f0;

    .line 9
    .line 10
    .line 11
    move-result-object v3

    .line 12
    iget-object v4, p0, Lwz0/a0;->c:Lo8/j;

    .line 13
    .line 14
    iget-object v0, v4, Lo8/j;->c:Ljava/lang/Object;

    .line 15
    .line 16
    check-cast v0, Lbb/g0;

    .line 17
    .line 18
    iget v1, v0, Lbb/g0;->e:I

    .line 19
    .line 20
    const/4 v5, 0x1

    .line 21
    add-int/2addr v1, v5

    .line 22
    iput v1, v0, Lbb/g0;->e:I

    .line 23
    .line 24
    iget-object v6, v0, Lbb/g0;->f:Ljava/lang/Object;

    .line 25
    .line 26
    check-cast v6, [Ljava/lang/Object;

    .line 27
    .line 28
    array-length v6, v6

    .line 29
    if-ne v1, v6, :cond_0

    .line 30
    .line 31
    invoke-virtual {v0}, Lbb/g0;->s()V

    .line 32
    .line 33
    .line 34
    :cond_0
    iget-object v0, v0, Lbb/g0;->f:Ljava/lang/Object;

    .line 35
    .line 36
    check-cast v0, [Ljava/lang/Object;

    .line 37
    .line 38
    aput-object p1, v0, v1

    .line 39
    .line 40
    iget-char v0, v3, Lwz0/f0;->d:C

    .line 41
    .line 42
    invoke-virtual {v4, v0}, Lo8/j;->h(C)V

    .line 43
    .line 44
    .line 45
    invoke-virtual {v4}, Lo8/j;->x()B

    .line 46
    .line 47
    .line 48
    move-result v0

    .line 49
    const/4 v1, 0x4

    .line 50
    if-eq v0, v1, :cond_3

    .line 51
    .line 52
    invoke-virtual {v3}, Ljava/lang/Enum;->ordinal()I

    .line 53
    .line 54
    .line 55
    move-result v0

    .line 56
    if-eq v0, v5, :cond_2

    .line 57
    .line 58
    const/4 v1, 0x2

    .line 59
    if-eq v0, v1, :cond_2

    .line 60
    .line 61
    const/4 v1, 0x3

    .line 62
    if-eq v0, v1, :cond_2

    .line 63
    .line 64
    iget-object v0, p0, Lwz0/a0;->b:Lwz0/f0;

    .line 65
    .line 66
    if-ne v0, v3, :cond_1

    .line 67
    .line 68
    iget-object v0, v2, Lvz0/d;->a:Lvz0/k;

    .line 69
    .line 70
    iget-boolean v0, v0, Lvz0/k;->e:Z

    .line 71
    .line 72
    if-eqz v0, :cond_1

    .line 73
    .line 74
    return-object p0

    .line 75
    :cond_1
    new-instance v1, Lwz0/a0;

    .line 76
    .line 77
    iget-object v6, p0, Lwz0/a0;->f:Lgr/f;

    .line 78
    .line 79
    move-object v5, p1

    .line 80
    invoke-direct/range {v1 .. v6}, Lwz0/a0;-><init>(Lvz0/d;Lwz0/f0;Lo8/j;Lsz0/g;Lgr/f;)V

    .line 81
    .line 82
    .line 83
    return-object v1

    .line 84
    :cond_2
    move-object v5, p1

    .line 85
    new-instance v1, Lwz0/a0;

    .line 86
    .line 87
    iget-object v6, p0, Lwz0/a0;->f:Lgr/f;

    .line 88
    .line 89
    invoke-direct/range {v1 .. v6}, Lwz0/a0;-><init>(Lvz0/d;Lwz0/f0;Lo8/j;Lsz0/g;Lgr/f;)V

    .line 90
    .line 91
    .line 92
    return-object v1

    .line 93
    :cond_3
    const/4 p0, 0x0

    .line 94
    const/4 p1, 0x6

    .line 95
    const-string v0, "Unexpected leading comma"

    .line 96
    .line 97
    const/4 v1, 0x0

    .line 98
    invoke-static {v4, v0, p0, v1, p1}, Lo8/j;->r(Lo8/j;Ljava/lang/String;ILjava/lang/String;I)V

    .line 99
    .line 100
    .line 101
    throw v1
.end method

.method public final b(Lsz0/g;)V
    .locals 4

    .line 1
    const-string v0, "descriptor"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-interface {p1}, Lsz0/g;->d()I

    .line 7
    .line 8
    .line 9
    move-result v0

    .line 10
    const/4 v1, -0x1

    .line 11
    if-nez v0, :cond_1

    .line 12
    .line 13
    iget-object v0, p0, Lwz0/a0;->a:Lvz0/d;

    .line 14
    .line 15
    invoke-static {p1, v0}, Lwz0/p;->l(Lsz0/g;Lvz0/d;)Z

    .line 16
    .line 17
    .line 18
    move-result v0

    .line 19
    if-eqz v0, :cond_1

    .line 20
    .line 21
    :cond_0
    invoke-virtual {p0, p1}, Lwz0/a0;->E(Lsz0/g;)I

    .line 22
    .line 23
    .line 24
    move-result v0

    .line 25
    if-ne v0, v1, :cond_0

    .line 26
    .line 27
    :cond_1
    iget-object p1, p0, Lwz0/a0;->c:Lo8/j;

    .line 28
    .line 29
    invoke-virtual {p1}, Lo8/j;->E()Z

    .line 30
    .line 31
    .line 32
    move-result v0

    .line 33
    if-nez v0, :cond_4

    .line 34
    .line 35
    iget-object p0, p0, Lwz0/a0;->b:Lwz0/f0;

    .line 36
    .line 37
    iget-char p0, p0, Lwz0/f0;->e:C

    .line 38
    .line 39
    invoke-virtual {p1, p0}, Lo8/j;->h(C)V

    .line 40
    .line 41
    .line 42
    iget-object p0, p1, Lo8/j;->c:Ljava/lang/Object;

    .line 43
    .line 44
    check-cast p0, Lbb/g0;

    .line 45
    .line 46
    iget p1, p0, Lbb/g0;->e:I

    .line 47
    .line 48
    iget-object v0, p0, Lbb/g0;->g:Ljava/lang/Object;

    .line 49
    .line 50
    check-cast v0, [I

    .line 51
    .line 52
    aget v2, v0, p1

    .line 53
    .line 54
    const/4 v3, -0x2

    .line 55
    if-ne v2, v3, :cond_2

    .line 56
    .line 57
    aput v1, v0, p1

    .line 58
    .line 59
    add-int/2addr p1, v1

    .line 60
    iput p1, p0, Lbb/g0;->e:I

    .line 61
    .line 62
    :cond_2
    iget p1, p0, Lbb/g0;->e:I

    .line 63
    .line 64
    if-eq p1, v1, :cond_3

    .line 65
    .line 66
    add-int/2addr p1, v1

    .line 67
    iput p1, p0, Lbb/g0;->e:I

    .line 68
    .line 69
    :cond_3
    return-void

    .line 70
    :cond_4
    const-string p0, ""

    .line 71
    .line 72
    invoke-static {p1, p0}, Lwz0/p;->m(Lo8/j;Ljava/lang/String;)V

    .line 73
    .line 74
    .line 75
    const/4 p0, 0x0

    .line 76
    throw p0
.end method

.method public final c()Lwq/f;
    .locals 0

    .line 1
    iget-object p0, p0, Lwz0/a0;->d:Lwq/f;

    .line 2
    .line 3
    return-object p0
.end method

.method public final d(Lqz0/a;)Ljava/lang/Object;
    .locals 10

    .line 1
    iget-object v0, p0, Lwz0/a0;->a:Lvz0/d;

    .line 2
    .line 3
    iget-object v1, p0, Lwz0/a0;->c:Lo8/j;

    .line 4
    .line 5
    iget-object v2, v1, Lo8/j;->c:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast v2, Lbb/g0;

    .line 8
    .line 9
    const-string v3, "Expected "

    .line 10
    .line 11
    const-string v4, "deserializer"

    .line 12
    .line 13
    invoke-static {p1, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    const/4 v4, 0x0

    .line 17
    :try_start_0
    instance-of v5, p1, Luz0/b;

    .line 18
    .line 19
    if-eqz v5, :cond_5

    .line 20
    .line 21
    move-object v5, p1

    .line 22
    check-cast v5, Luz0/b;

    .line 23
    .line 24
    invoke-interface {v5}, Lqz0/a;->getDescriptor()Lsz0/g;

    .line 25
    .line 26
    .line 27
    move-result-object v5

    .line 28
    invoke-static {v5, v0}, Lwz0/p;->i(Lsz0/g;Lvz0/d;)Ljava/lang/String;

    .line 29
    .line 30
    .line 31
    move-result-object v5

    .line 32
    iget-object v6, p0, Lwz0/a0;->g:Lvz0/k;

    .line 33
    .line 34
    iget-boolean v6, v6, Lvz0/k;->c:Z

    .line 35
    .line 36
    invoke-virtual {v1, v5, v6}, Lo8/j;->w(Ljava/lang/String;Z)Ljava/lang/String;

    .line 37
    .line 38
    .line 39
    move-result-object v6

    .line 40
    const/4 v7, 0x0

    .line 41
    if-nez v6, :cond_4

    .line 42
    .line 43
    instance-of v1, p1, Luz0/b;

    .line 44
    .line 45
    if-eqz v1, :cond_3

    .line 46
    .line 47
    move-object v1, p1

    .line 48
    check-cast v1, Luz0/b;

    .line 49
    .line 50
    invoke-interface {v1}, Lqz0/a;->getDescriptor()Lsz0/g;

    .line 51
    .line 52
    .line 53
    move-result-object v1

    .line 54
    invoke-static {v1, v0}, Lwz0/p;->i(Lsz0/g;Lvz0/d;)Ljava/lang/String;

    .line 55
    .line 56
    .line 57
    move-result-object v1

    .line 58
    invoke-virtual {p0}, Lwz0/a0;->h()Lvz0/n;

    .line 59
    .line 60
    .line 61
    move-result-object v5

    .line 62
    move-object v6, p1

    .line 63
    check-cast v6, Luz0/b;

    .line 64
    .line 65
    invoke-interface {v6}, Lqz0/a;->getDescriptor()Lsz0/g;

    .line 66
    .line 67
    .line 68
    move-result-object v6

    .line 69
    invoke-interface {v6}, Lsz0/g;->h()Ljava/lang/String;

    .line 70
    .line 71
    .line 72
    move-result-object v6

    .line 73
    instance-of v8, v5, Lvz0/a0;

    .line 74
    .line 75
    const/4 v9, -0x1

    .line 76
    if-eqz v8, :cond_2

    .line 77
    .line 78
    check-cast v5, Lvz0/a0;

    .line 79
    .line 80
    invoke-virtual {v5, v1}, Lvz0/a0;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 81
    .line 82
    .line 83
    move-result-object v3

    .line 84
    check-cast v3, Lvz0/n;

    .line 85
    .line 86
    if-eqz v3, :cond_1

    .line 87
    .line 88
    invoke-static {v3}, Lvz0/o;->e(Lvz0/n;)Lvz0/e0;

    .line 89
    .line 90
    .line 91
    move-result-object v3

    .line 92
    instance-of v6, v3, Lvz0/x;

    .line 93
    .line 94
    if-eqz v6, :cond_0

    .line 95
    .line 96
    goto :goto_0

    .line 97
    :cond_0
    invoke-virtual {v3}, Lvz0/e0;->c()Ljava/lang/String;

    .line 98
    .line 99
    .line 100
    move-result-object v7
    :try_end_0
    .catch Lqz0/b; {:try_start_0 .. :try_end_0} :catch_0

    .line 101
    goto :goto_0

    .line 102
    :catch_0
    move-exception p0

    .line 103
    goto/16 :goto_1

    .line 104
    .line 105
    :cond_1
    :goto_0
    :try_start_1
    check-cast p1, Luz0/b;

    .line 106
    .line 107
    invoke-static {p1, p0, v7}, Ljp/lg;->b(Luz0/b;Ltz0/a;Ljava/lang/String;)Lqz0/a;

    .line 108
    .line 109
    .line 110
    move-result-object p0
    :try_end_1
    .catch Lqz0/h; {:try_start_1 .. :try_end_1} :catch_1

    .line 111
    :try_start_2
    invoke-static {v0, v1, v5, p0}, Lwz0/p;->p(Lvz0/d;Ljava/lang/String;Lvz0/a0;Lqz0/a;)Ljava/lang/Object;

    .line 112
    .line 113
    .line 114
    move-result-object p0

    .line 115
    return-object p0

    .line 116
    :catch_1
    move-exception p0

    .line 117
    invoke-virtual {p0}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    .line 118
    .line 119
    .line 120
    move-result-object p0

    .line 121
    invoke-static {p0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 122
    .line 123
    .line 124
    invoke-virtual {v5}, Lvz0/a0;->toString()Ljava/lang/String;

    .line 125
    .line 126
    .line 127
    move-result-object p1

    .line 128
    invoke-static {v9, p1, p0}, Lwz0/p;->c(ILjava/lang/CharSequence;Ljava/lang/String;)Lwz0/l;

    .line 129
    .line 130
    .line 131
    move-result-object p0

    .line 132
    throw p0

    .line 133
    :cond_2
    new-instance p0, Ljava/lang/StringBuilder;

    .line 134
    .line 135
    invoke-direct {p0, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 136
    .line 137
    .line 138
    const-class p1, Lvz0/a0;

    .line 139
    .line 140
    sget-object v0, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 141
    .line 142
    invoke-virtual {v0, p1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 143
    .line 144
    .line 145
    move-result-object p1

    .line 146
    invoke-interface {p1}, Lhy0/d;->getSimpleName()Ljava/lang/String;

    .line 147
    .line 148
    .line 149
    move-result-object p1

    .line 150
    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 151
    .line 152
    .line 153
    const-string p1, ", but had "

    .line 154
    .line 155
    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 156
    .line 157
    .line 158
    invoke-virtual {v5}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 159
    .line 160
    .line 161
    move-result-object p1

    .line 162
    invoke-virtual {v0, p1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 163
    .line 164
    .line 165
    move-result-object p1

    .line 166
    invoke-interface {p1}, Lhy0/d;->getSimpleName()Ljava/lang/String;

    .line 167
    .line 168
    .line 169
    move-result-object p1

    .line 170
    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 171
    .line 172
    .line 173
    const-string p1, " as the serialized body of "

    .line 174
    .line 175
    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 176
    .line 177
    .line 178
    invoke-virtual {p0, v6}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 179
    .line 180
    .line 181
    const-string p1, " at element: "

    .line 182
    .line 183
    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 184
    .line 185
    .line 186
    invoke-virtual {v2}, Lbb/g0;->l()Ljava/lang/String;

    .line 187
    .line 188
    .line 189
    move-result-object p1

    .line 190
    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 191
    .line 192
    .line 193
    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 194
    .line 195
    .line 196
    move-result-object p0

    .line 197
    invoke-virtual {v5}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 198
    .line 199
    .line 200
    move-result-object p1

    .line 201
    invoke-static {v9, p1, p0}, Lwz0/p;->c(ILjava/lang/CharSequence;Ljava/lang/String;)Lwz0/l;

    .line 202
    .line 203
    .line 204
    move-result-object p0

    .line 205
    throw p0

    .line 206
    :cond_3
    invoke-interface {p1, p0}, Lqz0/a;->deserialize(Ltz0/c;)Ljava/lang/Object;

    .line 207
    .line 208
    .line 209
    move-result-object p0
    :try_end_2
    .catch Lqz0/b; {:try_start_2 .. :try_end_2} :catch_0

    .line 210
    return-object p0

    .line 211
    :cond_4
    :try_start_3
    check-cast p1, Luz0/b;

    .line 212
    .line 213
    invoke-static {p1, p0, v6}, Ljp/lg;->b(Luz0/b;Ltz0/a;Ljava/lang/String;)Lqz0/a;

    .line 214
    .line 215
    .line 216
    move-result-object p1
    :try_end_3
    .catch Lqz0/h; {:try_start_3 .. :try_end_3} :catch_2

    .line 217
    :try_start_4
    new-instance v0, Lgr/f;

    .line 218
    .line 219
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 220
    .line 221
    .line 222
    iput-object v5, v0, Lgr/f;->a:Ljava/lang/String;

    .line 223
    .line 224
    iput-object v0, p0, Lwz0/a0;->f:Lgr/f;

    .line 225
    .line 226
    invoke-interface {p1, p0}, Lqz0/a;->deserialize(Ltz0/c;)Ljava/lang/Object;

    .line 227
    .line 228
    .line 229
    move-result-object p0

    .line 230
    return-object p0

    .line 231
    :catch_2
    move-exception p0

    .line 232
    invoke-virtual {p0}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    .line 233
    .line 234
    .line 235
    move-result-object p1

    .line 236
    invoke-static {p1}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 237
    .line 238
    .line 239
    const/16 v0, 0xa

    .line 240
    .line 241
    invoke-static {p1, v0}, Lly0/p;->f0(Ljava/lang/String;C)Ljava/lang/String;

    .line 242
    .line 243
    .line 244
    move-result-object p1

    .line 245
    const-string v3, "."

    .line 246
    .line 247
    invoke-static {p1, v3}, Lly0/p;->T(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 248
    .line 249
    .line 250
    move-result-object p1

    .line 251
    invoke-virtual {p0}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    .line 252
    .line 253
    .line 254
    move-result-object p0

    .line 255
    invoke-static {p0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 256
    .line 257
    .line 258
    const-string v3, ""

    .line 259
    .line 260
    invoke-static {v0, p0, v3}, Lly0/p;->c0(CLjava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 261
    .line 262
    .line 263
    move-result-object p0

    .line 264
    const/4 v0, 0x2

    .line 265
    invoke-static {v1, p1, v4, p0, v0}, Lo8/j;->r(Lo8/j;Ljava/lang/String;ILjava/lang/String;I)V

    .line 266
    .line 267
    .line 268
    throw v7

    .line 269
    :cond_5
    invoke-interface {p1, p0}, Lqz0/a;->deserialize(Ltz0/c;)Ljava/lang/Object;

    .line 270
    .line 271
    .line 272
    move-result-object p0
    :try_end_4
    .catch Lqz0/b; {:try_start_4 .. :try_end_4} :catch_0

    .line 273
    return-object p0

    .line 274
    :goto_1
    invoke-virtual {p0}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    .line 275
    .line 276
    .line 277
    move-result-object p1

    .line 278
    invoke-static {p1}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 279
    .line 280
    .line 281
    const-string v0, "at path"

    .line 282
    .line 283
    invoke-static {p1, v0, v4}, Lly0/p;->A(Ljava/lang/CharSequence;Ljava/lang/CharSequence;Z)Z

    .line 284
    .line 285
    .line 286
    move-result p1

    .line 287
    if-eqz p1, :cond_6

    .line 288
    .line 289
    throw p0

    .line 290
    :cond_6
    new-instance p1, Lqz0/b;

    .line 291
    .line 292
    new-instance v0, Ljava/lang/StringBuilder;

    .line 293
    .line 294
    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    .line 295
    .line 296
    .line 297
    invoke-virtual {p0}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    .line 298
    .line 299
    .line 300
    move-result-object v1

    .line 301
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 302
    .line 303
    .line 304
    const-string v1, " at path: "

    .line 305
    .line 306
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 307
    .line 308
    .line 309
    invoke-virtual {v2}, Lbb/g0;->l()Ljava/lang/String;

    .line 310
    .line 311
    .line 312
    move-result-object v1

    .line 313
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 314
    .line 315
    .line 316
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 317
    .line 318
    .line 319
    move-result-object v0

    .line 320
    iget-object v1, p0, Lqz0/b;->d:Ljava/util/List;

    .line 321
    .line 322
    invoke-direct {p1, v1, v0, p0}, Lqz0/b;-><init>(Ljava/util/List;Ljava/lang/String;Lqz0/b;)V

    .line 323
    .line 324
    .line 325
    throw p1
.end method

.method public final h()Lvz0/n;
    .locals 2

    .line 1
    new-instance v0, Lin/o;

    .line 2
    .line 3
    iget-object v1, p0, Lwz0/a0;->a:Lvz0/d;

    .line 4
    .line 5
    iget-object v1, v1, Lvz0/d;->a:Lvz0/k;

    .line 6
    .line 7
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 8
    .line 9
    .line 10
    iget-object p0, p0, Lwz0/a0;->c:Lo8/j;

    .line 11
    .line 12
    iput-object p0, v0, Lin/o;->c:Ljava/lang/Object;

    .line 13
    .line 14
    iget-boolean p0, v1, Lvz0/k;->c:Z

    .line 15
    .line 16
    iput-boolean p0, v0, Lin/o;->b:Z

    .line 17
    .line 18
    invoke-virtual {v0}, Lin/o;->j()Lvz0/n;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0
.end method

.method public final i()I
    .locals 5

    .line 1
    iget-object p0, p0, Lwz0/a0;->c:Lo8/j;

    .line 2
    .line 3
    invoke-virtual {p0}, Lo8/j;->i()J

    .line 4
    .line 5
    .line 6
    move-result-wide v0

    .line 7
    long-to-int v2, v0

    .line 8
    int-to-long v3, v2

    .line 9
    cmp-long v3, v0, v3

    .line 10
    .line 11
    if-nez v3, :cond_0

    .line 12
    .line 13
    return v2

    .line 14
    :cond_0
    new-instance v2, Ljava/lang/StringBuilder;

    .line 15
    .line 16
    const-string v3, "Failed to parse int for input \'"

    .line 17
    .line 18
    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    invoke-virtual {v2, v0, v1}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    .line 22
    .line 23
    .line 24
    const/16 v0, 0x27

    .line 25
    .line 26
    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 27
    .line 28
    .line 29
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 30
    .line 31
    .line 32
    move-result-object v0

    .line 33
    const/4 v1, 0x0

    .line 34
    const/4 v2, 0x6

    .line 35
    const/4 v3, 0x0

    .line 36
    invoke-static {p0, v0, v1, v3, v2}, Lo8/j;->r(Lo8/j;Ljava/lang/String;ILjava/lang/String;I)V

    .line 37
    .line 38
    .line 39
    throw v3
.end method

.method public final m()J
    .locals 2

    .line 1
    iget-object p0, p0, Lwz0/a0;->c:Lo8/j;

    .line 2
    .line 3
    invoke-virtual {p0}, Lo8/j;->i()J

    .line 4
    .line 5
    .line 6
    move-result-wide v0

    .line 7
    return-wide v0
.end method

.method public final n(Lsz0/g;)I
    .locals 3

    .line 1
    const-string v0, "enumDescriptor"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0}, Lwz0/a0;->x()Ljava/lang/String;

    .line 7
    .line 8
    .line 9
    move-result-object v0

    .line 10
    new-instance v1, Ljava/lang/StringBuilder;

    .line 11
    .line 12
    const-string v2, " at path "

    .line 13
    .line 14
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    iget-object v2, p0, Lwz0/a0;->c:Lo8/j;

    .line 18
    .line 19
    iget-object v2, v2, Lo8/j;->c:Ljava/lang/Object;

    .line 20
    .line 21
    check-cast v2, Lbb/g0;

    .line 22
    .line 23
    invoke-virtual {v2}, Lbb/g0;->l()Ljava/lang/String;

    .line 24
    .line 25
    .line 26
    move-result-object v2

    .line 27
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 28
    .line 29
    .line 30
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 31
    .line 32
    .line 33
    move-result-object v1

    .line 34
    iget-object p0, p0, Lwz0/a0;->a:Lvz0/d;

    .line 35
    .line 36
    invoke-static {p1, p0, v0, v1}, Lwz0/p;->k(Lsz0/g;Lvz0/d;Ljava/lang/String;Ljava/lang/String;)I

    .line 37
    .line 38
    .line 39
    move-result p0

    .line 40
    return p0
.end method

.method public final o()S
    .locals 5

    .line 1
    iget-object p0, p0, Lwz0/a0;->c:Lo8/j;

    .line 2
    .line 3
    invoke-virtual {p0}, Lo8/j;->i()J

    .line 4
    .line 5
    .line 6
    move-result-wide v0

    .line 7
    long-to-int v2, v0

    .line 8
    int-to-short v2, v2

    .line 9
    int-to-long v3, v2

    .line 10
    cmp-long v3, v0, v3

    .line 11
    .line 12
    if-nez v3, :cond_0

    .line 13
    .line 14
    return v2

    .line 15
    :cond_0
    new-instance v2, Ljava/lang/StringBuilder;

    .line 16
    .line 17
    const-string v3, "Failed to parse short for input \'"

    .line 18
    .line 19
    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 20
    .line 21
    .line 22
    invoke-virtual {v2, v0, v1}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    .line 23
    .line 24
    .line 25
    const/16 v0, 0x27

    .line 26
    .line 27
    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 28
    .line 29
    .line 30
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 31
    .line 32
    .line 33
    move-result-object v0

    .line 34
    const/4 v1, 0x0

    .line 35
    const/4 v2, 0x6

    .line 36
    const/4 v3, 0x0

    .line 37
    invoke-static {p0, v0, v1, v3, v2}, Lo8/j;->r(Lo8/j;Ljava/lang/String;ILjava/lang/String;I)V

    .line 38
    .line 39
    .line 40
    throw v3
.end method

.method public final p()F
    .locals 4

    .line 1
    iget-object v0, p0, Lwz0/a0;->c:Lo8/j;

    .line 2
    .line 3
    invoke-virtual {v0}, Lo8/j;->l()Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object v1

    .line 7
    const/4 v2, 0x0

    .line 8
    :try_start_0
    invoke-static {v1}, Ljava/lang/Float;->parseFloat(Ljava/lang/String;)F

    .line 9
    .line 10
    .line 11
    move-result v1
    :try_end_0
    .catch Ljava/lang/IllegalArgumentException; {:try_start_0 .. :try_end_0} :catch_0

    .line 12
    iget-object p0, p0, Lwz0/a0;->a:Lvz0/d;

    .line 13
    .line 14
    iget-object p0, p0, Lvz0/d;->a:Lvz0/k;

    .line 15
    .line 16
    iget-boolean p0, p0, Lvz0/k;->h:Z

    .line 17
    .line 18
    if-nez p0, :cond_1

    .line 19
    .line 20
    invoke-static {v1}, Ljava/lang/Math;->abs(F)F

    .line 21
    .line 22
    .line 23
    move-result p0

    .line 24
    const v3, 0x7f7fffff    # Float.MAX_VALUE

    .line 25
    .line 26
    .line 27
    cmpg-float p0, p0, v3

    .line 28
    .line 29
    if-gtz p0, :cond_0

    .line 30
    .line 31
    goto :goto_0

    .line 32
    :cond_0
    invoke-static {v1}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 33
    .line 34
    .line 35
    move-result-object p0

    .line 36
    invoke-static {v0, p0}, Lwz0/p;->r(Lo8/j;Ljava/lang/Number;)V

    .line 37
    .line 38
    .line 39
    throw v2

    .line 40
    :cond_1
    :goto_0
    return v1

    .line 41
    :catch_0
    const-string p0, "Failed to parse type \'float\' for input \'"

    .line 42
    .line 43
    const/16 v3, 0x27

    .line 44
    .line 45
    invoke-static {v3, p0, v1}, Lvj/b;->f(CLjava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 46
    .line 47
    .line 48
    move-result-object p0

    .line 49
    const/4 v1, 0x0

    .line 50
    const/4 v3, 0x6

    .line 51
    invoke-static {v0, p0, v1, v2, v3}, Lo8/j;->r(Lo8/j;Ljava/lang/String;ILjava/lang/String;I)V

    .line 52
    .line 53
    .line 54
    throw v2
.end method

.method public final q()D
    .locals 9

    .line 1
    iget-object v0, p0, Lwz0/a0;->c:Lo8/j;

    .line 2
    .line 3
    invoke-virtual {v0}, Lo8/j;->l()Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object v1

    .line 7
    const/4 v2, 0x0

    .line 8
    :try_start_0
    invoke-static {v1}, Ljava/lang/Double;->parseDouble(Ljava/lang/String;)D

    .line 9
    .line 10
    .line 11
    move-result-wide v3
    :try_end_0
    .catch Ljava/lang/IllegalArgumentException; {:try_start_0 .. :try_end_0} :catch_0

    .line 12
    iget-object p0, p0, Lwz0/a0;->a:Lvz0/d;

    .line 13
    .line 14
    iget-object p0, p0, Lvz0/d;->a:Lvz0/k;

    .line 15
    .line 16
    iget-boolean p0, p0, Lvz0/k;->h:Z

    .line 17
    .line 18
    if-nez p0, :cond_1

    .line 19
    .line 20
    invoke-static {v3, v4}, Ljava/lang/Math;->abs(D)D

    .line 21
    .line 22
    .line 23
    move-result-wide v5

    .line 24
    const-wide v7, 0x7fefffffffffffffL    # Double.MAX_VALUE

    .line 25
    .line 26
    .line 27
    .line 28
    .line 29
    cmpg-double p0, v5, v7

    .line 30
    .line 31
    if-gtz p0, :cond_0

    .line 32
    .line 33
    goto :goto_0

    .line 34
    :cond_0
    invoke-static {v3, v4}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 35
    .line 36
    .line 37
    move-result-object p0

    .line 38
    invoke-static {v0, p0}, Lwz0/p;->r(Lo8/j;Ljava/lang/Number;)V

    .line 39
    .line 40
    .line 41
    throw v2

    .line 42
    :cond_1
    :goto_0
    return-wide v3

    .line 43
    :catch_0
    const-string p0, "Failed to parse type \'double\' for input \'"

    .line 44
    .line 45
    const/16 v3, 0x27

    .line 46
    .line 47
    invoke-static {v3, p0, v1}, Lvj/b;->f(CLjava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 48
    .line 49
    .line 50
    move-result-object p0

    .line 51
    const/4 v1, 0x0

    .line 52
    const/4 v3, 0x6

    .line 53
    invoke-static {v0, p0, v1, v2, v3}, Lo8/j;->r(Lo8/j;Ljava/lang/String;ILjava/lang/String;I)V

    .line 54
    .line 55
    .line 56
    throw v2
.end method

.method public final r(Lsz0/g;ILqz0/a;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 7

    .line 1
    iget-object v0, p0, Lwz0/a0;->c:Lo8/j;

    .line 2
    .line 3
    iget-object v0, v0, Lo8/j;->c:Ljava/lang/Object;

    .line 4
    .line 5
    check-cast v0, Lbb/g0;

    .line 6
    .line 7
    const-string v1, "descriptor"

    .line 8
    .line 9
    invoke-static {p1, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    const-string v1, "deserializer"

    .line 13
    .line 14
    invoke-static {p3, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    iget-object v1, p0, Lwz0/a0;->b:Lwz0/f0;

    .line 18
    .line 19
    sget-object v2, Lwz0/f0;->h:Lwz0/f0;

    .line 20
    .line 21
    const/4 v3, 0x1

    .line 22
    if-ne v1, v2, :cond_0

    .line 23
    .line 24
    and-int/lit8 v1, p2, 0x1

    .line 25
    .line 26
    if-nez v1, :cond_0

    .line 27
    .line 28
    move v1, v3

    .line 29
    goto :goto_0

    .line 30
    :cond_0
    const/4 v1, 0x0

    .line 31
    :goto_0
    const/4 v2, -0x2

    .line 32
    if-eqz v1, :cond_1

    .line 33
    .line 34
    iget-object v4, v0, Lbb/g0;->g:Ljava/lang/Object;

    .line 35
    .line 36
    check-cast v4, [I

    .line 37
    .line 38
    iget v5, v0, Lbb/g0;->e:I

    .line 39
    .line 40
    aget v4, v4, v5

    .line 41
    .line 42
    if-ne v4, v2, :cond_1

    .line 43
    .line 44
    iget-object v4, v0, Lbb/g0;->f:Ljava/lang/Object;

    .line 45
    .line 46
    check-cast v4, [Ljava/lang/Object;

    .line 47
    .line 48
    sget-object v6, Lwz0/q;->a:Lwz0/q;

    .line 49
    .line 50
    aput-object v6, v4, v5

    .line 51
    .line 52
    :cond_1
    invoke-super {p0, p1, p2, p3, p4}, Llp/u0;->r(Lsz0/g;ILqz0/a;Ljava/lang/Object;)Ljava/lang/Object;

    .line 53
    .line 54
    .line 55
    move-result-object p0

    .line 56
    if-eqz v1, :cond_3

    .line 57
    .line 58
    iget-object p1, v0, Lbb/g0;->g:Ljava/lang/Object;

    .line 59
    .line 60
    check-cast p1, [I

    .line 61
    .line 62
    iget p2, v0, Lbb/g0;->e:I

    .line 63
    .line 64
    aget p1, p1, p2

    .line 65
    .line 66
    if-eq p1, v2, :cond_2

    .line 67
    .line 68
    add-int/2addr p2, v3

    .line 69
    iput p2, v0, Lbb/g0;->e:I

    .line 70
    .line 71
    iget-object p1, v0, Lbb/g0;->f:Ljava/lang/Object;

    .line 72
    .line 73
    check-cast p1, [Ljava/lang/Object;

    .line 74
    .line 75
    array-length p1, p1

    .line 76
    if-ne p2, p1, :cond_2

    .line 77
    .line 78
    invoke-virtual {v0}, Lbb/g0;->s()V

    .line 79
    .line 80
    .line 81
    :cond_2
    iget-object p1, v0, Lbb/g0;->f:Ljava/lang/Object;

    .line 82
    .line 83
    check-cast p1, [Ljava/lang/Object;

    .line 84
    .line 85
    iget p2, v0, Lbb/g0;->e:I

    .line 86
    .line 87
    aput-object p0, p1, p2

    .line 88
    .line 89
    iget-object p1, v0, Lbb/g0;->g:Ljava/lang/Object;

    .line 90
    .line 91
    check-cast p1, [I

    .line 92
    .line 93
    aput v2, p1, p2

    .line 94
    .line 95
    :cond_3
    return-object p0
.end method

.method public final s()Z
    .locals 10

    .line 1
    iget-object p0, p0, Lwz0/a0;->c:Lo8/j;

    .line 2
    .line 3
    invoke-virtual {p0}, Lo8/j;->C()I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    invoke-virtual {p0}, Lo8/j;->t()Ljava/lang/CharSequence;

    .line 8
    .line 9
    .line 10
    move-result-object v1

    .line 11
    invoke-interface {v1}, Ljava/lang/CharSequence;->length()I

    .line 12
    .line 13
    .line 14
    move-result v1

    .line 15
    const-string v2, "EOF"

    .line 16
    .line 17
    const/4 v3, 0x6

    .line 18
    const/4 v4, 0x0

    .line 19
    const/4 v5, 0x0

    .line 20
    if-eq v0, v1, :cond_7

    .line 21
    .line 22
    invoke-virtual {p0}, Lo8/j;->t()Ljava/lang/CharSequence;

    .line 23
    .line 24
    .line 25
    move-result-object v1

    .line 26
    invoke-interface {v1, v0}, Ljava/lang/CharSequence;->charAt(I)C

    .line 27
    .line 28
    .line 29
    move-result v1

    .line 30
    const/16 v6, 0x22

    .line 31
    .line 32
    const/4 v7, 0x1

    .line 33
    if-ne v1, v6, :cond_0

    .line 34
    .line 35
    add-int/lit8 v0, v0, 0x1

    .line 36
    .line 37
    move v1, v7

    .line 38
    goto :goto_0

    .line 39
    :cond_0
    move v1, v5

    .line 40
    :goto_0
    invoke-virtual {p0, v0}, Lo8/j;->z(I)I

    .line 41
    .line 42
    .line 43
    move-result v0

    .line 44
    invoke-virtual {p0}, Lo8/j;->t()Ljava/lang/CharSequence;

    .line 45
    .line 46
    .line 47
    move-result-object v8

    .line 48
    invoke-interface {v8}, Ljava/lang/CharSequence;->length()I

    .line 49
    .line 50
    .line 51
    move-result v8

    .line 52
    if-ge v0, v8, :cond_6

    .line 53
    .line 54
    const/4 v8, -0x1

    .line 55
    if-eq v0, v8, :cond_6

    .line 56
    .line 57
    invoke-virtual {p0}, Lo8/j;->t()Ljava/lang/CharSequence;

    .line 58
    .line 59
    .line 60
    move-result-object v8

    .line 61
    add-int/lit8 v9, v0, 0x1

    .line 62
    .line 63
    invoke-interface {v8, v0}, Ljava/lang/CharSequence;->charAt(I)C

    .line 64
    .line 65
    .line 66
    move-result v0

    .line 67
    or-int/lit8 v0, v0, 0x20

    .line 68
    .line 69
    const/16 v8, 0x66

    .line 70
    .line 71
    if-eq v0, v8, :cond_2

    .line 72
    .line 73
    const/16 v8, 0x74

    .line 74
    .line 75
    if-ne v0, v8, :cond_1

    .line 76
    .line 77
    const-string v0, "rue"

    .line 78
    .line 79
    invoke-virtual {p0, v9, v0}, Lo8/j;->d(ILjava/lang/String;)V

    .line 80
    .line 81
    .line 82
    move v0, v7

    .line 83
    goto :goto_1

    .line 84
    :cond_1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 85
    .line 86
    const-string v1, "Expected valid boolean literal prefix, but had \'"

    .line 87
    .line 88
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 89
    .line 90
    .line 91
    invoke-virtual {p0}, Lo8/j;->l()Ljava/lang/String;

    .line 92
    .line 93
    .line 94
    move-result-object v1

    .line 95
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 96
    .line 97
    .line 98
    const/16 v1, 0x27

    .line 99
    .line 100
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 101
    .line 102
    .line 103
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 104
    .line 105
    .line 106
    move-result-object v0

    .line 107
    invoke-static {p0, v0, v5, v4, v3}, Lo8/j;->r(Lo8/j;Ljava/lang/String;ILjava/lang/String;I)V

    .line 108
    .line 109
    .line 110
    throw v4

    .line 111
    :cond_2
    const-string v0, "alse"

    .line 112
    .line 113
    invoke-virtual {p0, v9, v0}, Lo8/j;->d(ILjava/lang/String;)V

    .line 114
    .line 115
    .line 116
    move v0, v5

    .line 117
    :goto_1
    if-eqz v1, :cond_5

    .line 118
    .line 119
    iget v1, p0, Lo8/j;->b:I

    .line 120
    .line 121
    invoke-virtual {p0}, Lo8/j;->t()Ljava/lang/CharSequence;

    .line 122
    .line 123
    .line 124
    move-result-object v8

    .line 125
    invoke-interface {v8}, Ljava/lang/CharSequence;->length()I

    .line 126
    .line 127
    .line 128
    move-result v8

    .line 129
    if-eq v1, v8, :cond_4

    .line 130
    .line 131
    invoke-virtual {p0}, Lo8/j;->t()Ljava/lang/CharSequence;

    .line 132
    .line 133
    .line 134
    move-result-object v1

    .line 135
    iget v2, p0, Lo8/j;->b:I

    .line 136
    .line 137
    invoke-interface {v1, v2}, Ljava/lang/CharSequence;->charAt(I)C

    .line 138
    .line 139
    .line 140
    move-result v1

    .line 141
    if-ne v1, v6, :cond_3

    .line 142
    .line 143
    iget v1, p0, Lo8/j;->b:I

    .line 144
    .line 145
    add-int/2addr v1, v7

    .line 146
    iput v1, p0, Lo8/j;->b:I

    .line 147
    .line 148
    return v0

    .line 149
    :cond_3
    const-string v0, "Expected closing quotation mark"

    .line 150
    .line 151
    invoke-static {p0, v0, v5, v4, v3}, Lo8/j;->r(Lo8/j;Ljava/lang/String;ILjava/lang/String;I)V

    .line 152
    .line 153
    .line 154
    throw v4

    .line 155
    :cond_4
    invoke-static {p0, v2, v5, v4, v3}, Lo8/j;->r(Lo8/j;Ljava/lang/String;ILjava/lang/String;I)V

    .line 156
    .line 157
    .line 158
    throw v4

    .line 159
    :cond_5
    return v0

    .line 160
    :cond_6
    invoke-static {p0, v2, v5, v4, v3}, Lo8/j;->r(Lo8/j;Ljava/lang/String;ILjava/lang/String;I)V

    .line 161
    .line 162
    .line 163
    throw v4

    .line 164
    :cond_7
    invoke-static {p0, v2, v5, v4, v3}, Lo8/j;->r(Lo8/j;Ljava/lang/String;ILjava/lang/String;I)V

    .line 165
    .line 166
    .line 167
    throw v4
.end method

.method public final u()C
    .locals 4

    .line 1
    iget-object p0, p0, Lwz0/a0;->c:Lo8/j;

    .line 2
    .line 3
    invoke-virtual {p0}, Lo8/j;->l()Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    invoke-virtual {v0}, Ljava/lang/String;->length()I

    .line 8
    .line 9
    .line 10
    move-result v1

    .line 11
    const/4 v2, 0x1

    .line 12
    const/4 v3, 0x0

    .line 13
    if-ne v1, v2, :cond_0

    .line 14
    .line 15
    invoke-virtual {v0, v3}, Ljava/lang/String;->charAt(I)C

    .line 16
    .line 17
    .line 18
    move-result p0

    .line 19
    return p0

    .line 20
    :cond_0
    const-string v1, "Expected single char, but got \'"

    .line 21
    .line 22
    const/16 v2, 0x27

    .line 23
    .line 24
    invoke-static {v2, v1, v0}, Lvj/b;->f(CLjava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 25
    .line 26
    .line 27
    move-result-object v0

    .line 28
    const/4 v1, 0x6

    .line 29
    const/4 v2, 0x0

    .line 30
    invoke-static {p0, v0, v3, v2, v1}, Lo8/j;->r(Lo8/j;Ljava/lang/String;ILjava/lang/String;I)V

    .line 31
    .line 32
    .line 33
    throw v2
.end method

.method public final x()Ljava/lang/String;
    .locals 1

    .line 1
    iget-object v0, p0, Lwz0/a0;->g:Lvz0/k;

    .line 2
    .line 3
    iget-boolean v0, v0, Lvz0/k;->c:Z

    .line 4
    .line 5
    iget-object p0, p0, Lwz0/a0;->c:Lo8/j;

    .line 6
    .line 7
    if-eqz v0, :cond_0

    .line 8
    .line 9
    invoke-virtual {p0}, Lo8/j;->m()Ljava/lang/String;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    return-object p0

    .line 14
    :cond_0
    invoke-virtual {p0}, Lo8/j;->j()Ljava/lang/String;

    .line 15
    .line 16
    .line 17
    move-result-object p0

    .line 18
    return-object p0
.end method

.method public final y()Z
    .locals 10

    .line 1
    const/4 v0, 0x0

    .line 2
    iget-object v1, p0, Lwz0/a0;->h:Lwz0/m;

    .line 3
    .line 4
    if-eqz v1, :cond_0

    .line 5
    .line 6
    iget-boolean v1, v1, Lwz0/m;->b:Z

    .line 7
    .line 8
    goto :goto_0

    .line 9
    :cond_0
    move v1, v0

    .line 10
    :goto_0
    if-nez v1, :cond_6

    .line 11
    .line 12
    iget-object p0, p0, Lwz0/a0;->c:Lo8/j;

    .line 13
    .line 14
    invoke-virtual {p0}, Lo8/j;->C()I

    .line 15
    .line 16
    .line 17
    move-result v1

    .line 18
    invoke-virtual {p0, v1}, Lo8/j;->z(I)I

    .line 19
    .line 20
    .line 21
    move-result v1

    .line 22
    invoke-virtual {p0}, Lo8/j;->t()Ljava/lang/CharSequence;

    .line 23
    .line 24
    .line 25
    move-result-object v2

    .line 26
    invoke-interface {v2}, Ljava/lang/CharSequence;->length()I

    .line 27
    .line 28
    .line 29
    move-result v2

    .line 30
    sub-int/2addr v2, v1

    .line 31
    const/4 v3, 0x1

    .line 32
    const/4 v4, 0x0

    .line 33
    const/4 v5, 0x4

    .line 34
    if-lt v2, v5, :cond_5

    .line 35
    .line 36
    const/4 v6, -0x1

    .line 37
    if-ne v1, v6, :cond_1

    .line 38
    .line 39
    goto :goto_2

    .line 40
    :cond_1
    move v6, v4

    .line 41
    :goto_1
    if-ge v6, v5, :cond_3

    .line 42
    .line 43
    const-string v7, "null"

    .line 44
    .line 45
    invoke-virtual {v7, v6}, Ljava/lang/String;->charAt(I)C

    .line 46
    .line 47
    .line 48
    move-result v7

    .line 49
    invoke-virtual {p0}, Lo8/j;->t()Ljava/lang/CharSequence;

    .line 50
    .line 51
    .line 52
    move-result-object v8

    .line 53
    add-int v9, v1, v6

    .line 54
    .line 55
    invoke-interface {v8, v9}, Ljava/lang/CharSequence;->charAt(I)C

    .line 56
    .line 57
    .line 58
    move-result v8

    .line 59
    if-eq v7, v8, :cond_2

    .line 60
    .line 61
    goto :goto_2

    .line 62
    :cond_2
    add-int/lit8 v6, v6, 0x1

    .line 63
    .line 64
    goto :goto_1

    .line 65
    :cond_3
    if-le v2, v5, :cond_4

    .line 66
    .line 67
    invoke-virtual {p0}, Lo8/j;->t()Ljava/lang/CharSequence;

    .line 68
    .line 69
    .line 70
    move-result-object v2

    .line 71
    add-int/lit8 v6, v1, 0x4

    .line 72
    .line 73
    invoke-interface {v2, v6}, Ljava/lang/CharSequence;->charAt(I)C

    .line 74
    .line 75
    .line 76
    move-result v2

    .line 77
    invoke-static {v2}, Lwz0/p;->g(C)B

    .line 78
    .line 79
    .line 80
    move-result v2

    .line 81
    if-nez v2, :cond_4

    .line 82
    .line 83
    goto :goto_2

    .line 84
    :cond_4
    const/4 v4, 0x1

    .line 85
    add-int/2addr v1, v5

    .line 86
    iput v1, p0, Lo8/j;->b:I

    .line 87
    .line 88
    :cond_5
    :goto_2
    if-nez v4, :cond_6

    .line 89
    .line 90
    return v3

    .line 91
    :cond_6
    return v0
.end method

.method public final z()Lvz0/d;
    .locals 0

    .line 1
    iget-object p0, p0, Lwz0/a0;->a:Lvz0/d;

    .line 2
    .line 3
    return-object p0
.end method
