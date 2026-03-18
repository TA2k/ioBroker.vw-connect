.class public final Lj01/c;
.super Lj01/a;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public h:J

.field public i:Z

.field public final synthetic j:Lj01/f;


# direct methods
.method public constructor <init>(Lj01/f;Ld01/a0;)V
    .locals 1

    .line 1
    const-string v0, "url"

    .line 2
    .line 3
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iput-object p1, p0, Lj01/c;->j:Lj01/f;

    .line 7
    .line 8
    invoke-direct {p0, p1, p2}, Lj01/a;-><init>(Lj01/f;Ld01/a0;)V

    .line 9
    .line 10
    .line 11
    const-wide/16 p1, -0x1

    .line 12
    .line 13
    iput-wide p1, p0, Lj01/c;->h:J

    .line 14
    .line 15
    const/4 p1, 0x1

    .line 16
    iput-boolean p1, p0, Lj01/c;->i:Z

    .line 17
    .line 18
    return-void
.end method


# virtual methods
.method public final A(Lu01/f;J)J
    .locals 17

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    move-wide/from16 v2, p2

    .line 6
    .line 7
    iget-object v4, v0, Lj01/c;->j:Lj01/f;

    .line 8
    .line 9
    iget-object v5, v4, Lj01/f;->c:Lgw0/c;

    .line 10
    .line 11
    const-string v6, "sink"

    .line 12
    .line 13
    invoke-static {v1, v6}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    const-wide/16 v6, 0x0

    .line 17
    .line 18
    cmp-long v8, v2, v6

    .line 19
    .line 20
    if-ltz v8, :cond_10

    .line 21
    .line 22
    iget-boolean v8, v0, Lj01/a;->f:Z

    .line 23
    .line 24
    if-nez v8, :cond_f

    .line 25
    .line 26
    iget-boolean v8, v0, Lj01/c;->i:Z

    .line 27
    .line 28
    const-wide/16 v9, -0x1

    .line 29
    .line 30
    if-nez v8, :cond_0

    .line 31
    .line 32
    goto/16 :goto_5

    .line 33
    .line 34
    :cond_0
    iget-wide v11, v0, Lj01/c;->h:J

    .line 35
    .line 36
    cmp-long v8, v11, v6

    .line 37
    .line 38
    if-eqz v8, :cond_1

    .line 39
    .line 40
    cmp-long v8, v11, v9

    .line 41
    .line 42
    if-nez v8, :cond_c

    .line 43
    .line 44
    :cond_1
    cmp-long v8, v11, v9

    .line 45
    .line 46
    if-eqz v8, :cond_2

    .line 47
    .line 48
    iget-object v8, v5, Lgw0/c;->f:Ljava/lang/Object;

    .line 49
    .line 50
    check-cast v8, Lu01/b0;

    .line 51
    .line 52
    const-wide v11, 0x7fffffffffffffffL

    .line 53
    .line 54
    .line 55
    .line 56
    .line 57
    invoke-virtual {v8, v11, v12}, Lu01/b0;->x(J)Ljava/lang/String;

    .line 58
    .line 59
    .line 60
    :cond_2
    :try_start_0
    iget-object v8, v5, Lgw0/c;->f:Ljava/lang/Object;

    .line 61
    .line 62
    check-cast v8, Lu01/b0;

    .line 63
    .line 64
    iget-object v11, v8, Lu01/b0;->e:Lu01/f;

    .line 65
    .line 66
    const-wide/16 v12, 0x1

    .line 67
    .line 68
    invoke-virtual {v8, v12, v13}, Lu01/b0;->e(J)V

    .line 69
    .line 70
    .line 71
    const/4 v12, 0x0

    .line 72
    move v13, v12

    .line 73
    :goto_0
    add-int/lit8 v14, v13, 0x1

    .line 74
    .line 75
    move-wide v15, v6

    .line 76
    int-to-long v6, v14

    .line 77
    invoke-virtual {v8, v6, v7}, Lu01/b0;->c(J)Z

    .line 78
    .line 79
    .line 80
    move-result v6

    .line 81
    if-eqz v6, :cond_8

    .line 82
    .line 83
    int-to-long v6, v13

    .line 84
    invoke-virtual {v11, v6, v7}, Lu01/f;->h(J)B

    .line 85
    .line 86
    .line 87
    move-result v6

    .line 88
    const/16 v7, 0x30

    .line 89
    .line 90
    if-lt v6, v7, :cond_3

    .line 91
    .line 92
    const/16 v7, 0x39

    .line 93
    .line 94
    if-le v6, v7, :cond_5

    .line 95
    .line 96
    :cond_3
    const/16 v7, 0x61

    .line 97
    .line 98
    if-lt v6, v7, :cond_4

    .line 99
    .line 100
    const/16 v7, 0x66

    .line 101
    .line 102
    if-le v6, v7, :cond_5

    .line 103
    .line 104
    :cond_4
    const/16 v7, 0x41

    .line 105
    .line 106
    if-lt v6, v7, :cond_6

    .line 107
    .line 108
    const/16 v7, 0x46

    .line 109
    .line 110
    if-le v6, v7, :cond_5

    .line 111
    .line 112
    goto :goto_1

    .line 113
    :cond_5
    move v13, v14

    .line 114
    move-wide v6, v15

    .line 115
    goto :goto_0

    .line 116
    :cond_6
    :goto_1
    if-eqz v13, :cond_7

    .line 117
    .line 118
    goto :goto_2

    .line 119
    :cond_7
    new-instance v0, Ljava/lang/NumberFormatException;

    .line 120
    .line 121
    const/16 v1, 0x10

    .line 122
    .line 123
    invoke-static {v1}, Lry/a;->a(I)V

    .line 124
    .line 125
    .line 126
    invoke-static {v6, v1}, Ljava/lang/Integer;->toString(II)Ljava/lang/String;

    .line 127
    .line 128
    .line 129
    move-result-object v1

    .line 130
    const-string v2, "toString(...)"

    .line 131
    .line 132
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 133
    .line 134
    .line 135
    const-string v2, "Expected leading [0-9a-fA-F] character but was 0x"

    .line 136
    .line 137
    invoke-virtual {v2, v1}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 138
    .line 139
    .line 140
    move-result-object v1

    .line 141
    invoke-direct {v0, v1}, Ljava/lang/NumberFormatException;-><init>(Ljava/lang/String;)V

    .line 142
    .line 143
    .line 144
    throw v0

    .line 145
    :cond_8
    :goto_2
    invoke-virtual {v11}, Lu01/f;->E()J

    .line 146
    .line 147
    .line 148
    move-result-wide v6

    .line 149
    iput-wide v6, v0, Lj01/c;->h:J

    .line 150
    .line 151
    iget-object v5, v5, Lgw0/c;->f:Ljava/lang/Object;

    .line 152
    .line 153
    check-cast v5, Lu01/b0;

    .line 154
    .line 155
    const-wide v6, 0x7fffffffffffffffL

    .line 156
    .line 157
    .line 158
    .line 159
    .line 160
    invoke-virtual {v5, v6, v7}, Lu01/b0;->x(J)Ljava/lang/String;

    .line 161
    .line 162
    .line 163
    move-result-object v5

    .line 164
    invoke-static {v5}, Lly0/p;->l0(Ljava/lang/CharSequence;)Ljava/lang/CharSequence;

    .line 165
    .line 166
    .line 167
    move-result-object v5

    .line 168
    invoke-virtual {v5}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 169
    .line 170
    .line 171
    move-result-object v5

    .line 172
    iget-wide v6, v0, Lj01/c;->h:J

    .line 173
    .line 174
    cmp-long v6, v6, v15

    .line 175
    .line 176
    if-ltz v6, :cond_e

    .line 177
    .line 178
    invoke-virtual {v5}, Ljava/lang/String;->length()I

    .line 179
    .line 180
    .line 181
    move-result v6

    .line 182
    if-lez v6, :cond_9

    .line 183
    .line 184
    const-string v6, ";"

    .line 185
    .line 186
    invoke-static {v5, v6, v12}, Lly0/w;->x(Ljava/lang/String;Ljava/lang/String;Z)Z

    .line 187
    .line 188
    .line 189
    move-result v6
    :try_end_0
    .catch Ljava/lang/NumberFormatException; {:try_start_0 .. :try_end_0} :catch_0

    .line 190
    if-eqz v6, :cond_e

    .line 191
    .line 192
    :cond_9
    iget-wide v5, v0, Lj01/c;->h:J

    .line 193
    .line 194
    cmp-long v5, v5, v15

    .line 195
    .line 196
    if-nez v5, :cond_b

    .line 197
    .line 198
    iput-boolean v12, v0, Lj01/c;->i:Z

    .line 199
    .line 200
    iget-object v5, v4, Lj01/f;->e:Lg1/i3;

    .line 201
    .line 202
    invoke-virtual {v5}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 203
    .line 204
    .line 205
    new-instance v6, Ld01/x;

    .line 206
    .line 207
    const/4 v7, 0x0

    .line 208
    const/4 v8, 0x0

    .line 209
    invoke-direct {v6, v8, v7}, Ld01/x;-><init>(BI)V

    .line 210
    .line 211
    .line 212
    :goto_3
    iget-object v7, v5, Lg1/i3;->f:Ljava/lang/Object;

    .line 213
    .line 214
    check-cast v7, Lu01/h;

    .line 215
    .line 216
    iget-wide v11, v5, Lg1/i3;->e:J

    .line 217
    .line 218
    invoke-interface {v7, v11, v12}, Lu01/h;->x(J)Ljava/lang/String;

    .line 219
    .line 220
    .line 221
    move-result-object v7

    .line 222
    iget-wide v11, v5, Lg1/i3;->e:J

    .line 223
    .line 224
    invoke-virtual {v7}, Ljava/lang/String;->length()I

    .line 225
    .line 226
    .line 227
    move-result v8

    .line 228
    int-to-long v13, v8

    .line 229
    sub-long/2addr v11, v13

    .line 230
    iput-wide v11, v5, Lg1/i3;->e:J

    .line 231
    .line 232
    invoke-virtual {v7}, Ljava/lang/String;->length()I

    .line 233
    .line 234
    .line 235
    move-result v8

    .line 236
    if-nez v8, :cond_a

    .line 237
    .line 238
    invoke-virtual {v6}, Ld01/x;->j()Ld01/y;

    .line 239
    .line 240
    .line 241
    move-result-object v5

    .line 242
    invoke-virtual {v0, v5}, Lj01/a;->a(Ld01/y;)V

    .line 243
    .line 244
    .line 245
    goto :goto_4

    .line 246
    :cond_a
    invoke-virtual {v6, v7}, Ld01/x;->e(Ljava/lang/String;)V

    .line 247
    .line 248
    .line 249
    goto :goto_3

    .line 250
    :cond_b
    :goto_4
    iget-boolean v5, v0, Lj01/c;->i:Z

    .line 251
    .line 252
    if-nez v5, :cond_c

    .line 253
    .line 254
    :goto_5
    return-wide v9

    .line 255
    :cond_c
    iget-wide v5, v0, Lj01/c;->h:J

    .line 256
    .line 257
    invoke-static {v2, v3, v5, v6}, Ljava/lang/Math;->min(JJ)J

    .line 258
    .line 259
    .line 260
    move-result-wide v2

    .line 261
    invoke-super {v0, v1, v2, v3}, Lj01/a;->A(Lu01/f;J)J

    .line 262
    .line 263
    .line 264
    move-result-wide v1

    .line 265
    cmp-long v3, v1, v9

    .line 266
    .line 267
    if-eqz v3, :cond_d

    .line 268
    .line 269
    iget-wide v3, v0, Lj01/c;->h:J

    .line 270
    .line 271
    sub-long/2addr v3, v1

    .line 272
    iput-wide v3, v0, Lj01/c;->h:J

    .line 273
    .line 274
    return-wide v1

    .line 275
    :cond_d
    iget-object v1, v4, Lj01/f;->b:Li01/c;

    .line 276
    .line 277
    invoke-interface {v1}, Li01/c;->c()V

    .line 278
    .line 279
    .line 280
    new-instance v1, Ljava/net/ProtocolException;

    .line 281
    .line 282
    const-string v2, "unexpected end of stream"

    .line 283
    .line 284
    invoke-direct {v1, v2}, Ljava/net/ProtocolException;-><init>(Ljava/lang/String;)V

    .line 285
    .line 286
    .line 287
    sget-object v2, Lj01/f;->g:Ld01/y;

    .line 288
    .line 289
    invoke-virtual {v0, v2}, Lj01/a;->a(Ld01/y;)V

    .line 290
    .line 291
    .line 292
    throw v1

    .line 293
    :cond_e
    :try_start_1
    new-instance v1, Ljava/net/ProtocolException;

    .line 294
    .line 295
    new-instance v2, Ljava/lang/StringBuilder;

    .line 296
    .line 297
    invoke-direct {v2}, Ljava/lang/StringBuilder;-><init>()V

    .line 298
    .line 299
    .line 300
    const-string v3, "expected chunk size and optional extensions but was \""

    .line 301
    .line 302
    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 303
    .line 304
    .line 305
    iget-wide v3, v0, Lj01/c;->h:J

    .line 306
    .line 307
    invoke-virtual {v2, v3, v4}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    .line 308
    .line 309
    .line 310
    invoke-virtual {v2, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 311
    .line 312
    .line 313
    const/16 v0, 0x22

    .line 314
    .line 315
    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 316
    .line 317
    .line 318
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 319
    .line 320
    .line 321
    move-result-object v0

    .line 322
    invoke-direct {v1, v0}, Ljava/net/ProtocolException;-><init>(Ljava/lang/String;)V

    .line 323
    .line 324
    .line 325
    throw v1
    :try_end_1
    .catch Ljava/lang/NumberFormatException; {:try_start_1 .. :try_end_1} :catch_0

    .line 326
    :catch_0
    move-exception v0

    .line 327
    new-instance v1, Ljava/net/ProtocolException;

    .line 328
    .line 329
    invoke-virtual {v0}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    .line 330
    .line 331
    .line 332
    move-result-object v0

    .line 333
    invoke-direct {v1, v0}, Ljava/net/ProtocolException;-><init>(Ljava/lang/String;)V

    .line 334
    .line 335
    .line 336
    throw v1

    .line 337
    :cond_f
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 338
    .line 339
    const-string v1, "closed"

    .line 340
    .line 341
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 342
    .line 343
    .line 344
    throw v0

    .line 345
    :cond_10
    const-string v0, "byteCount < 0: "

    .line 346
    .line 347
    invoke-static {v2, v3, v0}, Lp3/m;->f(JLjava/lang/String;)Ljava/lang/String;

    .line 348
    .line 349
    .line 350
    move-result-object v0

    .line 351
    new-instance v1, Ljava/lang/IllegalArgumentException;

    .line 352
    .line 353
    invoke-virtual {v0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 354
    .line 355
    .line 356
    move-result-object v0

    .line 357
    invoke-direct {v1, v0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 358
    .line 359
    .line 360
    throw v1
.end method

.method public final close()V
    .locals 2

    .line 1
    iget-boolean v0, p0, Lj01/a;->f:Z

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    return-void

    .line 6
    :cond_0
    iget-boolean v0, p0, Lj01/c;->i:Z

    .line 7
    .line 8
    if-eqz v0, :cond_1

    .line 9
    .line 10
    sget-object v0, Ljava/util/concurrent/TimeUnit;->MILLISECONDS:Ljava/util/concurrent/TimeUnit;

    .line 11
    .line 12
    sget-object v1, Le01/g;->a:Ljava/util/TimeZone;

    .line 13
    .line 14
    const-string v1, "timeUnit"

    .line 15
    .line 16
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 17
    .line 18
    .line 19
    const/16 v0, 0x64

    .line 20
    .line 21
    :try_start_0
    invoke-static {p0, v0}, Le01/g;->g(Lu01/h0;I)Z

    .line 22
    .line 23
    .line 24
    move-result v0
    :try_end_0
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_0

    .line 25
    goto :goto_0

    .line 26
    :catch_0
    const/4 v0, 0x0

    .line 27
    :goto_0
    if-nez v0, :cond_1

    .line 28
    .line 29
    iget-object v0, p0, Lj01/c;->j:Lj01/f;

    .line 30
    .line 31
    iget-object v0, v0, Lj01/f;->b:Li01/c;

    .line 32
    .line 33
    invoke-interface {v0}, Li01/c;->c()V

    .line 34
    .line 35
    .line 36
    sget-object v0, Lj01/f;->g:Ld01/y;

    .line 37
    .line 38
    invoke-virtual {p0, v0}, Lj01/a;->a(Ld01/y;)V

    .line 39
    .line 40
    .line 41
    :cond_1
    const/4 v0, 0x1

    .line 42
    iput-boolean v0, p0, Lj01/a;->f:Z

    .line 43
    .line 44
    return-void
.end method
