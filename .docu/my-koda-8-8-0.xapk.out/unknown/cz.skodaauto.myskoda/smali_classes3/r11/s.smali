.class public final Lr11/s;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Ljp/u1;

.field public final b:Ljava/util/Locale;

.field public final c:I

.field public d:Ln11/f;

.field public e:Ljava/lang/Integer;

.field public f:[Lr11/q;

.field public g:I

.field public h:Z

.field public i:Lr11/r;


# direct methods
.method public constructor <init>(Ljp/u1;)V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    sget-object v0, Ln11/c;->a:Ljava/util/concurrent/atomic/AtomicReference;

    .line 5
    .line 6
    if-nez p1, :cond_0

    .line 7
    .line 8
    invoke-static {}, Lp11/n;->P()Lp11/n;

    .line 9
    .line 10
    .line 11
    move-result-object p1

    .line 12
    :cond_0
    invoke-virtual {p1}, Ljp/u1;->m()Ln11/f;

    .line 13
    .line 14
    .line 15
    move-result-object v0

    .line 16
    invoke-virtual {p1}, Ljp/u1;->I()Ljp/u1;

    .line 17
    .line 18
    .line 19
    move-result-object p1

    .line 20
    iput-object p1, p0, Lr11/s;->a:Ljp/u1;

    .line 21
    .line 22
    invoke-static {}, Ljava/util/Locale;->getDefault()Ljava/util/Locale;

    .line 23
    .line 24
    .line 25
    move-result-object p1

    .line 26
    iput-object p1, p0, Lr11/s;->b:Ljava/util/Locale;

    .line 27
    .line 28
    const/16 p1, 0x7d0

    .line 29
    .line 30
    iput p1, p0, Lr11/s;->c:I

    .line 31
    .line 32
    iput-object v0, p0, Lr11/s;->d:Ln11/f;

    .line 33
    .line 34
    const/16 p1, 0x8

    .line 35
    .line 36
    new-array p1, p1, [Lr11/q;

    .line 37
    .line 38
    iput-object p1, p0, Lr11/s;->f:[Lr11/q;

    .line 39
    .line 40
    return-void
.end method

.method public static a(Ln11/g;Ln11/g;)I
    .locals 1

    .line 1
    if-eqz p0, :cond_3

    .line 2
    .line 3
    invoke-virtual {p0}, Ln11/g;->f()Z

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    if-nez v0, :cond_0

    .line 8
    .line 9
    goto :goto_1

    .line 10
    :cond_0
    if-eqz p1, :cond_2

    .line 11
    .line 12
    invoke-virtual {p1}, Ln11/g;->f()Z

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    if-nez v0, :cond_1

    .line 17
    .line 18
    goto :goto_0

    .line 19
    :cond_1
    invoke-interface {p0, p1}, Ljava/lang/Comparable;->compareTo(Ljava/lang/Object;)I

    .line 20
    .line 21
    .line 22
    move-result p0

    .line 23
    neg-int p0, p0

    .line 24
    return p0

    .line 25
    :cond_2
    :goto_0
    const/4 p0, 0x1

    .line 26
    return p0

    .line 27
    :cond_3
    :goto_1
    if-eqz p1, :cond_5

    .line 28
    .line 29
    invoke-virtual {p1}, Ln11/g;->f()Z

    .line 30
    .line 31
    .line 32
    move-result p0

    .line 33
    if-nez p0, :cond_4

    .line 34
    .line 35
    goto :goto_2

    .line 36
    :cond_4
    const/4 p0, -0x1

    .line 37
    return p0

    .line 38
    :cond_5
    :goto_2
    const/4 p0, 0x0

    .line 39
    return p0
.end method


# virtual methods
.method public final b(Ljava/lang/CharSequence;)J
    .locals 12

    .line 1
    iget-object v0, p0, Lr11/s;->f:[Lr11/q;

    .line 2
    .line 3
    iget v1, p0, Lr11/s;->g:I

    .line 4
    .line 5
    iget-boolean v2, p0, Lr11/s;->h:Z

    .line 6
    .line 7
    const/4 v3, 0x0

    .line 8
    if-eqz v2, :cond_0

    .line 9
    .line 10
    invoke-virtual {v0}, [Lr11/q;->clone()Ljava/lang/Object;

    .line 11
    .line 12
    .line 13
    move-result-object v0

    .line 14
    check-cast v0, [Lr11/q;

    .line 15
    .line 16
    iput-object v0, p0, Lr11/s;->f:[Lr11/q;

    .line 17
    .line 18
    iput-boolean v3, p0, Lr11/s;->h:Z

    .line 19
    .line 20
    :cond_0
    const/16 v2, 0xa

    .line 21
    .line 22
    if-le v1, v2, :cond_1

    .line 23
    .line 24
    invoke-static {v0, v3, v1}, Ljava/util/Arrays;->sort([Ljava/lang/Object;II)V

    .line 25
    .line 26
    .line 27
    goto :goto_3

    .line 28
    :cond_1
    move v2, v3

    .line 29
    :goto_0
    if-ge v2, v1, :cond_4

    .line 30
    .line 31
    move v4, v2

    .line 32
    :goto_1
    if-lez v4, :cond_3

    .line 33
    .line 34
    add-int/lit8 v5, v4, -0x1

    .line 35
    .line 36
    aget-object v6, v0, v5

    .line 37
    .line 38
    aget-object v7, v0, v4

    .line 39
    .line 40
    invoke-virtual {v6}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 41
    .line 42
    .line 43
    iget-object v7, v7, Lr11/q;->d:Ln11/a;

    .line 44
    .line 45
    iget-object v8, v6, Lr11/q;->d:Ln11/a;

    .line 46
    .line 47
    invoke-virtual {v8}, Ln11/a;->p()Ln11/g;

    .line 48
    .line 49
    .line 50
    move-result-object v8

    .line 51
    invoke-virtual {v7}, Ln11/a;->p()Ln11/g;

    .line 52
    .line 53
    .line 54
    move-result-object v9

    .line 55
    invoke-static {v8, v9}, Lr11/s;->a(Ln11/g;Ln11/g;)I

    .line 56
    .line 57
    .line 58
    move-result v8

    .line 59
    if-eqz v8, :cond_2

    .line 60
    .line 61
    goto :goto_2

    .line 62
    :cond_2
    iget-object v6, v6, Lr11/q;->d:Ln11/a;

    .line 63
    .line 64
    invoke-virtual {v6}, Ln11/a;->i()Ln11/g;

    .line 65
    .line 66
    .line 67
    move-result-object v6

    .line 68
    invoke-virtual {v7}, Ln11/a;->i()Ln11/g;

    .line 69
    .line 70
    .line 71
    move-result-object v7

    .line 72
    invoke-static {v6, v7}, Lr11/s;->a(Ln11/g;Ln11/g;)I

    .line 73
    .line 74
    .line 75
    move-result v8

    .line 76
    :goto_2
    if-lez v8, :cond_3

    .line 77
    .line 78
    aget-object v6, v0, v4

    .line 79
    .line 80
    aget-object v7, v0, v5

    .line 81
    .line 82
    aput-object v7, v0, v4

    .line 83
    .line 84
    aput-object v6, v0, v5

    .line 85
    .line 86
    add-int/lit8 v4, v4, -0x1

    .line 87
    .line 88
    goto :goto_1

    .line 89
    :cond_3
    add-int/lit8 v2, v2, 0x1

    .line 90
    .line 91
    goto :goto_0

    .line 92
    :cond_4
    :goto_3
    if-lez v1, :cond_7

    .line 93
    .line 94
    sget-object v2, Ln11/c;->a:Ljava/util/concurrent/atomic/AtomicReference;

    .line 95
    .line 96
    iget-object v2, p0, Lr11/s;->a:Ljp/u1;

    .line 97
    .line 98
    if-nez v2, :cond_5

    .line 99
    .line 100
    invoke-static {}, Lp11/n;->P()Lp11/n;

    .line 101
    .line 102
    .line 103
    move-result-object v4

    .line 104
    goto :goto_4

    .line 105
    :cond_5
    move-object v4, v2

    .line 106
    :goto_4
    invoke-virtual {v4}, Ljp/u1;->z()Ln11/g;

    .line 107
    .line 108
    .line 109
    move-result-object v4

    .line 110
    if-nez v2, :cond_6

    .line 111
    .line 112
    invoke-static {}, Lp11/n;->P()Lp11/n;

    .line 113
    .line 114
    .line 115
    move-result-object v5

    .line 116
    goto :goto_5

    .line 117
    :cond_6
    move-object v5, v2

    .line 118
    :goto_5
    invoke-virtual {v5}, Ljp/u1;->i()Ln11/g;

    .line 119
    .line 120
    .line 121
    move-result-object v5

    .line 122
    aget-object v6, v0, v3

    .line 123
    .line 124
    iget-object v6, v6, Lr11/q;->d:Ln11/a;

    .line 125
    .line 126
    invoke-virtual {v6}, Ln11/a;->i()Ln11/g;

    .line 127
    .line 128
    .line 129
    move-result-object v6

    .line 130
    invoke-static {v6, v4}, Lr11/s;->a(Ln11/g;Ln11/g;)I

    .line 131
    .line 132
    .line 133
    move-result v4

    .line 134
    if-ltz v4, :cond_7

    .line 135
    .line 136
    invoke-static {v6, v5}, Lr11/s;->a(Ln11/g;Ln11/g;)I

    .line 137
    .line 138
    .line 139
    move-result v4

    .line 140
    if-gtz v4, :cond_7

    .line 141
    .line 142
    sget-object v0, Ln11/b;->l:Ln11/b;

    .line 143
    .line 144
    invoke-virtual {p0}, Lr11/s;->c()Lr11/q;

    .line 145
    .line 146
    .line 147
    move-result-object v1

    .line 148
    invoke-virtual {v0, v2}, Ln11/b;->a(Ljp/u1;)Ln11/a;

    .line 149
    .line 150
    .line 151
    move-result-object v0

    .line 152
    iput-object v0, v1, Lr11/q;->d:Ln11/a;

    .line 153
    .line 154
    iget v0, p0, Lr11/s;->c:I

    .line 155
    .line 156
    iput v0, v1, Lr11/q;->e:I

    .line 157
    .line 158
    const/4 v0, 0x0

    .line 159
    iput-object v0, v1, Lr11/q;->f:Ljava/lang/String;

    .line 160
    .line 161
    iput-object v0, v1, Lr11/q;->g:Ljava/util/Locale;

    .line 162
    .line 163
    invoke-virtual {p0, p1}, Lr11/s;->b(Ljava/lang/CharSequence;)J

    .line 164
    .line 165
    .line 166
    move-result-wide p0

    .line 167
    return-wide p0

    .line 168
    :cond_7
    const-wide/16 v4, 0x0

    .line 169
    .line 170
    move v2, v3

    .line 171
    :goto_6
    const-string v6, "Cannot parse \""

    .line 172
    .line 173
    if-ge v2, v1, :cond_9

    .line 174
    .line 175
    :try_start_0
    aget-object v7, v0, v2

    .line 176
    .line 177
    iget-object v8, v7, Lr11/q;->f:Ljava/lang/String;

    .line 178
    .line 179
    if-nez v8, :cond_8

    .line 180
    .line 181
    iget-object v8, v7, Lr11/q;->d:Ln11/a;

    .line 182
    .line 183
    iget v9, v7, Lr11/q;->e:I

    .line 184
    .line 185
    invoke-virtual {v8, v4, v5, v9}, Ln11/a;->x(JI)J

    .line 186
    .line 187
    .line 188
    move-result-wide v4

    .line 189
    goto :goto_7

    .line 190
    :cond_8
    iget-object v9, v7, Lr11/q;->d:Ln11/a;

    .line 191
    .line 192
    iget-object v10, v7, Lr11/q;->g:Ljava/util/Locale;

    .line 193
    .line 194
    invoke-virtual {v9, v4, v5, v8, v10}, Ln11/a;->w(JLjava/lang/String;Ljava/util/Locale;)J

    .line 195
    .line 196
    .line 197
    move-result-wide v4

    .line 198
    :goto_7
    iget-object v7, v7, Lr11/q;->d:Ln11/a;

    .line 199
    .line 200
    invoke-virtual {v7, v4, v5}, Ln11/a;->u(J)J

    .line 201
    .line 202
    .line 203
    move-result-wide v4

    .line 204
    add-int/lit8 v2, v2, 0x1

    .line 205
    .line 206
    goto :goto_6

    .line 207
    :catch_0
    move-exception p0

    .line 208
    goto :goto_b

    .line 209
    :cond_9
    move v2, v3

    .line 210
    :goto_8
    if-ge v2, v1, :cond_f

    .line 211
    .line 212
    aget-object v7, v0, v2

    .line 213
    .line 214
    add-int/lit8 v8, v1, -0x1

    .line 215
    .line 216
    if-ne v2, v8, :cond_a

    .line 217
    .line 218
    const/4 v8, 0x1

    .line 219
    goto :goto_9

    .line 220
    :cond_a
    move v8, v3

    .line 221
    :goto_9
    iget-object v9, v7, Lr11/q;->f:Ljava/lang/String;

    .line 222
    .line 223
    if-nez v9, :cond_b

    .line 224
    .line 225
    iget-object v9, v7, Lr11/q;->d:Ln11/a;

    .line 226
    .line 227
    iget v10, v7, Lr11/q;->e:I

    .line 228
    .line 229
    invoke-virtual {v9, v4, v5, v10}, Ln11/a;->x(JI)J

    .line 230
    .line 231
    .line 232
    move-result-wide v4

    .line 233
    goto :goto_a

    .line 234
    :cond_b
    iget-object v10, v7, Lr11/q;->d:Ln11/a;

    .line 235
    .line 236
    iget-object v11, v7, Lr11/q;->g:Ljava/util/Locale;

    .line 237
    .line 238
    invoke-virtual {v10, v4, v5, v9, v11}, Ln11/a;->w(JLjava/lang/String;Ljava/util/Locale;)J

    .line 239
    .line 240
    .line 241
    move-result-wide v4

    .line 242
    :goto_a
    if-eqz v8, :cond_c

    .line 243
    .line 244
    iget-object v7, v7, Lr11/q;->d:Ln11/a;

    .line 245
    .line 246
    invoke-virtual {v7, v4, v5}, Ln11/a;->u(J)J

    .line 247
    .line 248
    .line 249
    move-result-wide v4
    :try_end_0
    .catch Ln11/i; {:try_start_0 .. :try_end_0} :catch_0

    .line 250
    :cond_c
    add-int/lit8 v2, v2, 0x1

    .line 251
    .line 252
    goto :goto_8

    .line 253
    :goto_b
    if-eqz p1, :cond_e

    .line 254
    .line 255
    new-instance v0, Ljava/lang/StringBuilder;

    .line 256
    .line 257
    invoke-direct {v0, v6}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 258
    .line 259
    .line 260
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 261
    .line 262
    .line 263
    const/16 p1, 0x22

    .line 264
    .line 265
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 266
    .line 267
    .line 268
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 269
    .line 270
    .line 271
    move-result-object p1

    .line 272
    iget-object v0, p0, Ln11/i;->d:Ljava/lang/String;

    .line 273
    .line 274
    if-eqz v0, :cond_d

    .line 275
    .line 276
    if-eqz p1, :cond_e

    .line 277
    .line 278
    const-string v0, ": "

    .line 279
    .line 280
    invoke-static {p1, v0}, Lp3/m;->q(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 281
    .line 282
    .line 283
    move-result-object p1

    .line 284
    iget-object v0, p0, Ln11/i;->d:Ljava/lang/String;

    .line 285
    .line 286
    invoke-virtual {p1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 287
    .line 288
    .line 289
    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 290
    .line 291
    .line 292
    move-result-object p1

    .line 293
    iput-object p1, p0, Ln11/i;->d:Ljava/lang/String;

    .line 294
    .line 295
    goto :goto_c

    .line 296
    :cond_d
    iput-object p1, p0, Ln11/i;->d:Ljava/lang/String;

    .line 297
    .line 298
    :cond_e
    :goto_c
    throw p0

    .line 299
    :cond_f
    iget-object v0, p0, Lr11/s;->e:Ljava/lang/Integer;

    .line 300
    .line 301
    if-eqz v0, :cond_10

    .line 302
    .line 303
    invoke-virtual {v0}, Ljava/lang/Integer;->intValue()I

    .line 304
    .line 305
    .line 306
    move-result p0

    .line 307
    int-to-long p0, p0

    .line 308
    sub-long/2addr v4, p0

    .line 309
    return-wide v4

    .line 310
    :cond_10
    iget-object v0, p0, Lr11/s;->d:Ln11/f;

    .line 311
    .line 312
    if-eqz v0, :cond_12

    .line 313
    .line 314
    invoke-virtual {v0, v4, v5}, Ln11/f;->j(J)I

    .line 315
    .line 316
    .line 317
    move-result v0

    .line 318
    int-to-long v1, v0

    .line 319
    sub-long/2addr v4, v1

    .line 320
    iget-object v1, p0, Lr11/s;->d:Ln11/f;

    .line 321
    .line 322
    invoke-virtual {v1, v4, v5}, Ln11/f;->i(J)I

    .line 323
    .line 324
    .line 325
    move-result v1

    .line 326
    if-eq v0, v1, :cond_12

    .line 327
    .line 328
    new-instance v0, Ljava/lang/StringBuilder;

    .line 329
    .line 330
    const-string v1, "Illegal instant due to time zone offset transition ("

    .line 331
    .line 332
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 333
    .line 334
    .line 335
    iget-object p0, p0, Lr11/s;->d:Ln11/f;

    .line 336
    .line 337
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 338
    .line 339
    .line 340
    const/16 p0, 0x29

    .line 341
    .line 342
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 343
    .line 344
    .line 345
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 346
    .line 347
    .line 348
    move-result-object p0

    .line 349
    if-eqz p1, :cond_11

    .line 350
    .line 351
    new-instance v0, Ljava/lang/StringBuilder;

    .line 352
    .line 353
    invoke-direct {v0, v6}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 354
    .line 355
    .line 356
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 357
    .line 358
    .line 359
    const-string p1, "\": "

    .line 360
    .line 361
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 362
    .line 363
    .line 364
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 365
    .line 366
    .line 367
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 368
    .line 369
    .line 370
    move-result-object p0

    .line 371
    :cond_11
    new-instance p1, Lgz0/a;

    .line 372
    .line 373
    invoke-direct {p1, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 374
    .line 375
    .line 376
    throw p1

    .line 377
    :cond_12
    return-wide v4
.end method

.method public final c()Lr11/q;
    .locals 4

    .line 1
    iget-object v0, p0, Lr11/s;->f:[Lr11/q;

    .line 2
    .line 3
    iget v1, p0, Lr11/s;->g:I

    .line 4
    .line 5
    array-length v2, v0

    .line 6
    if-eq v1, v2, :cond_0

    .line 7
    .line 8
    iget-boolean v2, p0, Lr11/s;->h:Z

    .line 9
    .line 10
    if-eqz v2, :cond_2

    .line 11
    .line 12
    :cond_0
    array-length v2, v0

    .line 13
    if-ne v1, v2, :cond_1

    .line 14
    .line 15
    mul-int/lit8 v2, v1, 0x2

    .line 16
    .line 17
    goto :goto_0

    .line 18
    :cond_1
    array-length v2, v0

    .line 19
    :goto_0
    new-array v2, v2, [Lr11/q;

    .line 20
    .line 21
    const/4 v3, 0x0

    .line 22
    invoke-static {v0, v3, v2, v3, v1}, Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V

    .line 23
    .line 24
    .line 25
    iput-object v2, p0, Lr11/s;->f:[Lr11/q;

    .line 26
    .line 27
    iput-boolean v3, p0, Lr11/s;->h:Z

    .line 28
    .line 29
    move-object v0, v2

    .line 30
    :cond_2
    const/4 v2, 0x0

    .line 31
    iput-object v2, p0, Lr11/s;->i:Lr11/r;

    .line 32
    .line 33
    aget-object v2, v0, v1

    .line 34
    .line 35
    if-nez v2, :cond_3

    .line 36
    .line 37
    new-instance v2, Lr11/q;

    .line 38
    .line 39
    invoke-direct {v2}, Ljava/lang/Object;-><init>()V

    .line 40
    .line 41
    .line 42
    aput-object v2, v0, v1

    .line 43
    .line 44
    :cond_3
    add-int/lit8 v1, v1, 0x1

    .line 45
    .line 46
    iput v1, p0, Lr11/s;->g:I

    .line 47
    .line 48
    return-object v2
.end method

.method public final d(Ljava/lang/Object;)V
    .locals 2

    .line 1
    instance-of v0, p1, Lr11/r;

    .line 2
    .line 3
    if-eqz v0, :cond_2

    .line 4
    .line 5
    check-cast p1, Lr11/r;

    .line 6
    .line 7
    iget-object v0, p1, Lr11/r;->e:Lr11/s;

    .line 8
    .line 9
    if-eq p0, v0, :cond_0

    .line 10
    .line 11
    goto :goto_0

    .line 12
    :cond_0
    iget-object v0, p1, Lr11/r;->a:Ln11/f;

    .line 13
    .line 14
    iput-object v0, p0, Lr11/s;->d:Ln11/f;

    .line 15
    .line 16
    iget-object v0, p1, Lr11/r;->b:Ljava/lang/Integer;

    .line 17
    .line 18
    iput-object v0, p0, Lr11/s;->e:Ljava/lang/Integer;

    .line 19
    .line 20
    iget-object v0, p1, Lr11/r;->c:[Lr11/q;

    .line 21
    .line 22
    iput-object v0, p0, Lr11/s;->f:[Lr11/q;

    .line 23
    .line 24
    iget v0, p1, Lr11/r;->d:I

    .line 25
    .line 26
    iget v1, p0, Lr11/s;->g:I

    .line 27
    .line 28
    if-ge v0, v1, :cond_1

    .line 29
    .line 30
    const/4 v1, 0x1

    .line 31
    iput-boolean v1, p0, Lr11/s;->h:Z

    .line 32
    .line 33
    :cond_1
    iput v0, p0, Lr11/s;->g:I

    .line 34
    .line 35
    iput-object p1, p0, Lr11/s;->i:Lr11/r;

    .line 36
    .line 37
    :cond_2
    :goto_0
    return-void
.end method
