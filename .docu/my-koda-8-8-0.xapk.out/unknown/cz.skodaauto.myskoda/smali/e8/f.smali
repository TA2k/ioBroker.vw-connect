.class public final Le8/f;
.super La8/f;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public A:Le8/e;

.field public B:J

.field public C:J

.field public D:I

.field public E:I

.field public F:Lt7/o;

.field public G:Le8/b;

.field public H:Lz7/e;

.field public I:Landroidx/media3/exoplayer/image/ImageOutput;

.field public J:Landroid/graphics/Bitmap;

.field public K:Z

.field public L:Lcom/google/crypto/tink/shaded/protobuf/d;

.field public M:Lcom/google/crypto/tink/shaded/protobuf/d;

.field public N:I

.field public O:Z

.field public final v:Lcq/r1;

.field public final w:Lz7/e;

.field public final x:Ljava/util/ArrayDeque;

.field public y:Z

.field public z:Z


# direct methods
.method public constructor <init>(Lcq/r1;)V
    .locals 3

    .line 1
    const/4 v0, 0x4

    .line 2
    invoke-direct {p0, v0}, La8/f;-><init>(I)V

    .line 3
    .line 4
    .line 5
    iput-object p1, p0, Le8/f;->v:Lcq/r1;

    .line 6
    .line 7
    sget-object p1, Landroidx/media3/exoplayer/image/ImageOutput;->a:Le8/d;

    .line 8
    .line 9
    iput-object p1, p0, Le8/f;->I:Landroidx/media3/exoplayer/image/ImageOutput;

    .line 10
    .line 11
    new-instance p1, Lz7/e;

    .line 12
    .line 13
    const/4 v0, 0x0

    .line 14
    invoke-direct {p1, v0}, Lz7/e;-><init>(I)V

    .line 15
    .line 16
    .line 17
    iput-object p1, p0, Le8/f;->w:Lz7/e;

    .line 18
    .line 19
    sget-object p1, Le8/e;->c:Le8/e;

    .line 20
    .line 21
    iput-object p1, p0, Le8/f;->A:Le8/e;

    .line 22
    .line 23
    new-instance p1, Ljava/util/ArrayDeque;

    .line 24
    .line 25
    invoke-direct {p1}, Ljava/util/ArrayDeque;-><init>()V

    .line 26
    .line 27
    .line 28
    iput-object p1, p0, Le8/f;->x:Ljava/util/ArrayDeque;

    .line 29
    .line 30
    const-wide v1, -0x7fffffffffffffffL    # -4.9E-324

    .line 31
    .line 32
    .line 33
    .line 34
    .line 35
    iput-wide v1, p0, Le8/f;->C:J

    .line 36
    .line 37
    iput-wide v1, p0, Le8/f;->B:J

    .line 38
    .line 39
    iput v0, p0, Le8/f;->D:I

    .line 40
    .line 41
    const/4 p1, 0x1

    .line 42
    iput p1, p0, Le8/f;->E:I

    .line 43
    .line 44
    return-void
.end method


# virtual methods
.method public final B(Lt7/o;)I
    .locals 0

    .line 1
    iget-object p0, p0, Le8/f;->v:Lcq/r1;

    .line 2
    .line 3
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 4
    .line 5
    .line 6
    invoke-static {p1}, Lcq/r1;->f(Lt7/o;)I

    .line 7
    .line 8
    .line 9
    move-result p0

    .line 10
    return p0
.end method

.method public final D(J)Z
    .locals 12

    .line 1
    iget-object v0, p0, Le8/f;->J:Landroid/graphics/Bitmap;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    if-eqz v0, :cond_0

    .line 5
    .line 6
    iget-object v2, p0, Le8/f;->L:Lcom/google/crypto/tink/shaded/protobuf/d;

    .line 7
    .line 8
    if-nez v2, :cond_0

    .line 9
    .line 10
    goto/16 :goto_8

    .line 11
    .line 12
    :cond_0
    iget v2, p0, Le8/f;->E:I

    .line 13
    .line 14
    const/4 v3, 0x2

    .line 15
    if-nez v2, :cond_1

    .line 16
    .line 17
    iget v2, p0, La8/f;->k:I

    .line 18
    .line 19
    if-eq v2, v3, :cond_1

    .line 20
    .line 21
    goto/16 :goto_8

    .line 22
    .line 23
    :cond_1
    iget-object v2, p0, Le8/f;->x:Ljava/util/ArrayDeque;

    .line 24
    .line 25
    const/4 v4, 0x3

    .line 26
    const/4 v5, 0x1

    .line 27
    if-nez v0, :cond_5

    .line 28
    .line 29
    iget-object v0, p0, Le8/f;->G:Le8/b;

    .line 30
    .line 31
    invoke-static {v0}, Lw7/a;->k(Ljava/lang/Object;)V

    .line 32
    .line 33
    .line 34
    iget-object v0, p0, Le8/f;->G:Le8/b;

    .line 35
    .line 36
    invoke-virtual {v0}, Lz7/g;->l()Lz7/f;

    .line 37
    .line 38
    .line 39
    move-result-object v0

    .line 40
    check-cast v0, Le8/a;

    .line 41
    .line 42
    if-nez v0, :cond_2

    .line 43
    .line 44
    goto/16 :goto_8

    .line 45
    .line 46
    :cond_2
    const/4 v6, 0x4

    .line 47
    invoke-virtual {v0, v6}, Lkq/d;->c(I)Z

    .line 48
    .line 49
    .line 50
    move-result v6

    .line 51
    if-eqz v6, :cond_4

    .line 52
    .line 53
    iget p1, p0, Le8/f;->D:I

    .line 54
    .line 55
    if-ne p1, v4, :cond_3

    .line 56
    .line 57
    invoke-virtual {p0}, Le8/f;->G()V

    .line 58
    .line 59
    .line 60
    iget-object p1, p0, Le8/f;->F:Lt7/o;

    .line 61
    .line 62
    invoke-static {p1}, Lw7/a;->k(Ljava/lang/Object;)V

    .line 63
    .line 64
    .line 65
    invoke-virtual {p0}, Le8/f;->F()V

    .line 66
    .line 67
    .line 68
    return v1

    .line 69
    :cond_3
    invoke-virtual {v0}, Le8/a;->n()V

    .line 70
    .line 71
    .line 72
    invoke-virtual {v2}, Ljava/util/ArrayDeque;->isEmpty()Z

    .line 73
    .line 74
    .line 75
    move-result p1

    .line 76
    if-eqz p1, :cond_14

    .line 77
    .line 78
    iput-boolean v5, p0, Le8/f;->z:Z

    .line 79
    .line 80
    return v1

    .line 81
    :cond_4
    iget-object v6, v0, Le8/a;->h:Landroid/graphics/Bitmap;

    .line 82
    .line 83
    const-string v7, "Non-EOS buffer came back from the decoder without bitmap."

    .line 84
    .line 85
    invoke-static {v6, v7}, Lw7/a;->l(Ljava/lang/Object;Ljava/lang/String;)V

    .line 86
    .line 87
    .line 88
    iget-object v6, v0, Le8/a;->h:Landroid/graphics/Bitmap;

    .line 89
    .line 90
    iput-object v6, p0, Le8/f;->J:Landroid/graphics/Bitmap;

    .line 91
    .line 92
    invoke-virtual {v0}, Le8/a;->n()V

    .line 93
    .line 94
    .line 95
    :cond_5
    iget-boolean v0, p0, Le8/f;->K:Z

    .line 96
    .line 97
    if-eqz v0, :cond_14

    .line 98
    .line 99
    iget-object v0, p0, Le8/f;->J:Landroid/graphics/Bitmap;

    .line 100
    .line 101
    if-eqz v0, :cond_14

    .line 102
    .line 103
    iget-object v0, p0, Le8/f;->L:Lcom/google/crypto/tink/shaded/protobuf/d;

    .line 104
    .line 105
    if-eqz v0, :cond_14

    .line 106
    .line 107
    iget-object v0, p0, Le8/f;->F:Lt7/o;

    .line 108
    .line 109
    invoke-static {v0}, Lw7/a;->k(Ljava/lang/Object;)V

    .line 110
    .line 111
    .line 112
    iget-object v0, p0, Le8/f;->F:Lt7/o;

    .line 113
    .line 114
    iget v6, v0, Lt7/o;->M:I

    .line 115
    .line 116
    iget v0, v0, Lt7/o;->N:I

    .line 117
    .line 118
    if-ne v6, v5, :cond_6

    .line 119
    .line 120
    if-eq v0, v5, :cond_7

    .line 121
    .line 122
    :cond_6
    const/4 v7, -0x1

    .line 123
    if-eq v6, v7, :cond_7

    .line 124
    .line 125
    if-eq v0, v7, :cond_7

    .line 126
    .line 127
    move v0, v5

    .line 128
    goto :goto_0

    .line 129
    :cond_7
    move v0, v1

    .line 130
    :goto_0
    iget-object v6, p0, Le8/f;->L:Lcom/google/crypto/tink/shaded/protobuf/d;

    .line 131
    .line 132
    iget-object v7, v6, Lcom/google/crypto/tink/shaded/protobuf/d;->c:Ljava/lang/Object;

    .line 133
    .line 134
    check-cast v7, Landroid/graphics/Bitmap;

    .line 135
    .line 136
    if-eqz v7, :cond_8

    .line 137
    .line 138
    goto :goto_2

    .line 139
    :cond_8
    if-eqz v0, :cond_9

    .line 140
    .line 141
    iget v7, v6, Lcom/google/crypto/tink/shaded/protobuf/d;->a:I

    .line 142
    .line 143
    iget-object v8, p0, Le8/f;->J:Landroid/graphics/Bitmap;

    .line 144
    .line 145
    invoke-static {v8}, Lw7/a;->k(Ljava/lang/Object;)V

    .line 146
    .line 147
    .line 148
    iget-object v8, p0, Le8/f;->J:Landroid/graphics/Bitmap;

    .line 149
    .line 150
    invoke-virtual {v8}, Landroid/graphics/Bitmap;->getWidth()I

    .line 151
    .line 152
    .line 153
    move-result v8

    .line 154
    iget-object v9, p0, Le8/f;->F:Lt7/o;

    .line 155
    .line 156
    invoke-static {v9}, Lw7/a;->k(Ljava/lang/Object;)V

    .line 157
    .line 158
    .line 159
    iget v9, v9, Lt7/o;->M:I

    .line 160
    .line 161
    div-int/2addr v8, v9

    .line 162
    iget-object v9, p0, Le8/f;->J:Landroid/graphics/Bitmap;

    .line 163
    .line 164
    invoke-virtual {v9}, Landroid/graphics/Bitmap;->getHeight()I

    .line 165
    .line 166
    .line 167
    move-result v9

    .line 168
    iget-object v10, p0, Le8/f;->F:Lt7/o;

    .line 169
    .line 170
    invoke-static {v10}, Lw7/a;->k(Ljava/lang/Object;)V

    .line 171
    .line 172
    .line 173
    iget v10, v10, Lt7/o;->N:I

    .line 174
    .line 175
    div-int/2addr v9, v10

    .line 176
    iget-object v10, p0, Le8/f;->F:Lt7/o;

    .line 177
    .line 178
    iget v10, v10, Lt7/o;->M:I

    .line 179
    .line 180
    rem-int v11, v7, v10

    .line 181
    .line 182
    mul-int/2addr v11, v8

    .line 183
    div-int/2addr v7, v10

    .line 184
    mul-int/2addr v7, v9

    .line 185
    iget-object v10, p0, Le8/f;->J:Landroid/graphics/Bitmap;

    .line 186
    .line 187
    invoke-static {v10, v11, v7, v8, v9}, Landroid/graphics/Bitmap;->createBitmap(Landroid/graphics/Bitmap;IIII)Landroid/graphics/Bitmap;

    .line 188
    .line 189
    .line 190
    move-result-object v7

    .line 191
    goto :goto_1

    .line 192
    :cond_9
    iget-object v7, p0, Le8/f;->J:Landroid/graphics/Bitmap;

    .line 193
    .line 194
    invoke-static {v7}, Lw7/a;->k(Ljava/lang/Object;)V

    .line 195
    .line 196
    .line 197
    :goto_1
    iput-object v7, v6, Lcom/google/crypto/tink/shaded/protobuf/d;->c:Ljava/lang/Object;

    .line 198
    .line 199
    :goto_2
    iget-object v6, p0, Le8/f;->L:Lcom/google/crypto/tink/shaded/protobuf/d;

    .line 200
    .line 201
    iget-object v6, v6, Lcom/google/crypto/tink/shaded/protobuf/d;->c:Ljava/lang/Object;

    .line 202
    .line 203
    check-cast v6, Landroid/graphics/Bitmap;

    .line 204
    .line 205
    invoke-static {v6}, Lw7/a;->k(Ljava/lang/Object;)V

    .line 206
    .line 207
    .line 208
    iget-object v7, p0, Le8/f;->L:Lcom/google/crypto/tink/shaded/protobuf/d;

    .line 209
    .line 210
    iget-wide v7, v7, Lcom/google/crypto/tink/shaded/protobuf/d;->b:J

    .line 211
    .line 212
    sub-long p1, v7, p1

    .line 213
    .line 214
    iget v9, p0, La8/f;->k:I

    .line 215
    .line 216
    if-ne v9, v3, :cond_a

    .line 217
    .line 218
    move v3, v5

    .line 219
    goto :goto_3

    .line 220
    :cond_a
    move v3, v1

    .line 221
    :goto_3
    iget v9, p0, Le8/f;->E:I

    .line 222
    .line 223
    if-eqz v9, :cond_d

    .line 224
    .line 225
    if-eq v9, v5, :cond_c

    .line 226
    .line 227
    if-ne v9, v4, :cond_b

    .line 228
    .line 229
    move v3, v1

    .line 230
    goto :goto_4

    .line 231
    :cond_b
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 232
    .line 233
    invoke-direct {p0}, Ljava/lang/IllegalStateException;-><init>()V

    .line 234
    .line 235
    .line 236
    throw p0

    .line 237
    :cond_c
    move v3, v5

    .line 238
    :cond_d
    :goto_4
    if-nez v3, :cond_f

    .line 239
    .line 240
    const-wide/16 v9, 0x7530

    .line 241
    .line 242
    cmp-long p1, p1, v9

    .line 243
    .line 244
    if-gez p1, :cond_e

    .line 245
    .line 246
    goto :goto_5

    .line 247
    :cond_e
    move p1, v1

    .line 248
    goto :goto_6

    .line 249
    :cond_f
    :goto_5
    iget-object p1, p0, Le8/f;->I:Landroidx/media3/exoplayer/image/ImageOutput;

    .line 250
    .line 251
    iget-object p2, p0, Le8/f;->A:Le8/e;

    .line 252
    .line 253
    iget-wide v9, p2, Le8/e;->b:J

    .line 254
    .line 255
    sub-long/2addr v7, v9

    .line 256
    invoke-interface {p1, v7, v8, v6}, Landroidx/media3/exoplayer/image/ImageOutput;->onImageAvailable(JLandroid/graphics/Bitmap;)V

    .line 257
    .line 258
    .line 259
    move p1, v5

    .line 260
    :goto_6
    if-nez p1, :cond_10

    .line 261
    .line 262
    goto :goto_8

    .line 263
    :cond_10
    iget-object p1, p0, Le8/f;->L:Lcom/google/crypto/tink/shaded/protobuf/d;

    .line 264
    .line 265
    invoke-static {p1}, Lw7/a;->k(Ljava/lang/Object;)V

    .line 266
    .line 267
    .line 268
    iget-wide p1, p1, Lcom/google/crypto/tink/shaded/protobuf/d;->b:J

    .line 269
    .line 270
    iput-wide p1, p0, Le8/f;->B:J

    .line 271
    .line 272
    :goto_7
    invoke-virtual {v2}, Ljava/util/ArrayDeque;->isEmpty()Z

    .line 273
    .line 274
    .line 275
    move-result v1

    .line 276
    if-nez v1, :cond_11

    .line 277
    .line 278
    invoke-virtual {v2}, Ljava/util/ArrayDeque;->peek()Ljava/lang/Object;

    .line 279
    .line 280
    .line 281
    move-result-object v1

    .line 282
    check-cast v1, Le8/e;

    .line 283
    .line 284
    iget-wide v6, v1, Le8/e;->a:J

    .line 285
    .line 286
    cmp-long v1, p1, v6

    .line 287
    .line 288
    if-ltz v1, :cond_11

    .line 289
    .line 290
    invoke-virtual {v2}, Ljava/util/ArrayDeque;->removeFirst()Ljava/lang/Object;

    .line 291
    .line 292
    .line 293
    move-result-object v1

    .line 294
    check-cast v1, Le8/e;

    .line 295
    .line 296
    iput-object v1, p0, Le8/f;->A:Le8/e;

    .line 297
    .line 298
    goto :goto_7

    .line 299
    :cond_11
    iput v4, p0, Le8/f;->E:I

    .line 300
    .line 301
    const/4 p1, 0x0

    .line 302
    if-eqz v0, :cond_12

    .line 303
    .line 304
    iget-object p2, p0, Le8/f;->L:Lcom/google/crypto/tink/shaded/protobuf/d;

    .line 305
    .line 306
    invoke-static {p2}, Lw7/a;->k(Ljava/lang/Object;)V

    .line 307
    .line 308
    .line 309
    iget p2, p2, Lcom/google/crypto/tink/shaded/protobuf/d;->a:I

    .line 310
    .line 311
    iget-object v0, p0, Le8/f;->F:Lt7/o;

    .line 312
    .line 313
    invoke-static {v0}, Lw7/a;->k(Ljava/lang/Object;)V

    .line 314
    .line 315
    .line 316
    iget v0, v0, Lt7/o;->N:I

    .line 317
    .line 318
    iget-object v1, p0, Le8/f;->F:Lt7/o;

    .line 319
    .line 320
    invoke-static {v1}, Lw7/a;->k(Ljava/lang/Object;)V

    .line 321
    .line 322
    .line 323
    iget v1, v1, Lt7/o;->M:I

    .line 324
    .line 325
    mul-int/2addr v0, v1

    .line 326
    sub-int/2addr v0, v5

    .line 327
    if-ne p2, v0, :cond_13

    .line 328
    .line 329
    :cond_12
    iput-object p1, p0, Le8/f;->J:Landroid/graphics/Bitmap;

    .line 330
    .line 331
    :cond_13
    iget-object p2, p0, Le8/f;->M:Lcom/google/crypto/tink/shaded/protobuf/d;

    .line 332
    .line 333
    iput-object p2, p0, Le8/f;->L:Lcom/google/crypto/tink/shaded/protobuf/d;

    .line 334
    .line 335
    iput-object p1, p0, Le8/f;->M:Lcom/google/crypto/tink/shaded/protobuf/d;

    .line 336
    .line 337
    return v5

    .line 338
    :cond_14
    :goto_8
    return v1
.end method

.method public final E(J)Z
    .locals 12

    .line 1
    iget-boolean v0, p0, Le8/f;->K:Z

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    if-eqz v0, :cond_0

    .line 5
    .line 6
    iget-object v0, p0, Le8/f;->L:Lcom/google/crypto/tink/shaded/protobuf/d;

    .line 7
    .line 8
    if-eqz v0, :cond_0

    .line 9
    .line 10
    goto/16 :goto_9

    .line 11
    .line 12
    :cond_0
    iget-object v0, p0, La8/f;->f:Lb81/d;

    .line 13
    .line 14
    invoke-virtual {v0}, Lb81/d;->i()V

    .line 15
    .line 16
    .line 17
    iget-object v2, p0, Le8/f;->G:Le8/b;

    .line 18
    .line 19
    if-eqz v2, :cond_15

    .line 20
    .line 21
    iget v3, p0, Le8/f;->D:I

    .line 22
    .line 23
    const/4 v4, 0x3

    .line 24
    if-eq v3, v4, :cond_15

    .line 25
    .line 26
    iget-boolean v3, p0, Le8/f;->y:Z

    .line 27
    .line 28
    if-eqz v3, :cond_1

    .line 29
    .line 30
    goto/16 :goto_9

    .line 31
    .line 32
    :cond_1
    iget-object v3, p0, Le8/f;->H:Lz7/e;

    .line 33
    .line 34
    if-nez v3, :cond_2

    .line 35
    .line 36
    invoke-virtual {v2}, Lz7/g;->f()Ljava/lang/Object;

    .line 37
    .line 38
    .line 39
    move-result-object v2

    .line 40
    check-cast v2, Lz7/e;

    .line 41
    .line 42
    iput-object v2, p0, Le8/f;->H:Lz7/e;

    .line 43
    .line 44
    if-nez v2, :cond_2

    .line 45
    .line 46
    goto/16 :goto_9

    .line 47
    .line 48
    :cond_2
    iget v2, p0, Le8/f;->D:I

    .line 49
    .line 50
    const/4 v3, 0x2

    .line 51
    const/4 v5, 0x0

    .line 52
    const/4 v6, 0x4

    .line 53
    if-ne v2, v3, :cond_3

    .line 54
    .line 55
    iget-object p1, p0, Le8/f;->H:Lz7/e;

    .line 56
    .line 57
    invoke-static {p1}, Lw7/a;->k(Ljava/lang/Object;)V

    .line 58
    .line 59
    .line 60
    iget-object p1, p0, Le8/f;->H:Lz7/e;

    .line 61
    .line 62
    iput v6, p1, Lkq/d;->e:I

    .line 63
    .line 64
    iget-object p1, p0, Le8/f;->G:Le8/b;

    .line 65
    .line 66
    invoke-static {p1}, Lw7/a;->k(Ljava/lang/Object;)V

    .line 67
    .line 68
    .line 69
    iget-object p2, p0, Le8/f;->H:Lz7/e;

    .line 70
    .line 71
    invoke-virtual {p1, p2}, Lz7/g;->m(Lz7/e;)V

    .line 72
    .line 73
    .line 74
    iput-object v5, p0, Le8/f;->H:Lz7/e;

    .line 75
    .line 76
    iput v4, p0, Le8/f;->D:I

    .line 77
    .line 78
    return v1

    .line 79
    :cond_3
    iget-object v2, p0, Le8/f;->H:Lz7/e;

    .line 80
    .line 81
    invoke-virtual {p0, v0, v2, v1}, La8/f;->x(Lb81/d;Lz7/e;I)I

    .line 82
    .line 83
    .line 84
    move-result v2

    .line 85
    const/4 v4, -0x5

    .line 86
    const/4 v7, 0x1

    .line 87
    if-eq v2, v4, :cond_14

    .line 88
    .line 89
    const/4 v0, -0x4

    .line 90
    if-eq v2, v0, :cond_5

    .line 91
    .line 92
    const/4 p0, -0x3

    .line 93
    if-ne v2, p0, :cond_4

    .line 94
    .line 95
    goto/16 :goto_9

    .line 96
    .line 97
    :cond_4
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 98
    .line 99
    invoke-direct {p0}, Ljava/lang/IllegalStateException;-><init>()V

    .line 100
    .line 101
    .line 102
    throw p0

    .line 103
    :cond_5
    iget-object v0, p0, Le8/f;->H:Lz7/e;

    .line 104
    .line 105
    invoke-virtual {v0}, Lz7/e;->p()V

    .line 106
    .line 107
    .line 108
    iget-object v0, p0, Le8/f;->H:Lz7/e;

    .line 109
    .line 110
    iget-object v0, v0, Lz7/e;->h:Ljava/nio/ByteBuffer;

    .line 111
    .line 112
    if-eqz v0, :cond_6

    .line 113
    .line 114
    invoke-virtual {v0}, Ljava/nio/Buffer;->remaining()I

    .line 115
    .line 116
    .line 117
    move-result v0

    .line 118
    if-gtz v0, :cond_7

    .line 119
    .line 120
    :cond_6
    iget-object v0, p0, Le8/f;->H:Lz7/e;

    .line 121
    .line 122
    invoke-static {v0}, Lw7/a;->k(Ljava/lang/Object;)V

    .line 123
    .line 124
    .line 125
    invoke-virtual {v0, v6}, Lkq/d;->c(I)Z

    .line 126
    .line 127
    .line 128
    move-result v0

    .line 129
    if-eqz v0, :cond_8

    .line 130
    .line 131
    :cond_7
    move v0, v7

    .line 132
    goto :goto_0

    .line 133
    :cond_8
    move v0, v1

    .line 134
    :goto_0
    if-eqz v0, :cond_9

    .line 135
    .line 136
    iget-object v2, p0, Le8/f;->H:Lz7/e;

    .line 137
    .line 138
    invoke-static {v2}, Lw7/a;->k(Ljava/lang/Object;)V

    .line 139
    .line 140
    .line 141
    iget-object v3, p0, Le8/f;->F:Lt7/o;

    .line 142
    .line 143
    iput-object v3, v2, Lz7/e;->f:Lt7/o;

    .line 144
    .line 145
    iget-object v2, p0, Le8/f;->G:Le8/b;

    .line 146
    .line 147
    invoke-static {v2}, Lw7/a;->k(Ljava/lang/Object;)V

    .line 148
    .line 149
    .line 150
    iget-object v3, p0, Le8/f;->H:Lz7/e;

    .line 151
    .line 152
    invoke-static {v3}, Lw7/a;->k(Ljava/lang/Object;)V

    .line 153
    .line 154
    .line 155
    invoke-virtual {v2, v3}, Lz7/g;->m(Lz7/e;)V

    .line 156
    .line 157
    .line 158
    iput v1, p0, Le8/f;->N:I

    .line 159
    .line 160
    :cond_9
    iget-object v2, p0, Le8/f;->H:Lz7/e;

    .line 161
    .line 162
    invoke-static {v2}, Lw7/a;->k(Ljava/lang/Object;)V

    .line 163
    .line 164
    .line 165
    invoke-virtual {v2, v6}, Lkq/d;->c(I)Z

    .line 166
    .line 167
    .line 168
    move-result v3

    .line 169
    if-eqz v3, :cond_a

    .line 170
    .line 171
    iput-boolean v7, p0, Le8/f;->K:Z

    .line 172
    .line 173
    goto/16 :goto_7

    .line 174
    .line 175
    :cond_a
    new-instance v3, Lcom/google/crypto/tink/shaded/protobuf/d;

    .line 176
    .line 177
    iget v4, p0, Le8/f;->N:I

    .line 178
    .line 179
    iget-wide v8, v2, Lz7/e;->j:J

    .line 180
    .line 181
    invoke-direct {v3}, Ljava/lang/Object;-><init>()V

    .line 182
    .line 183
    .line 184
    iput v4, v3, Lcom/google/crypto/tink/shaded/protobuf/d;->a:I

    .line 185
    .line 186
    iput-wide v8, v3, Lcom/google/crypto/tink/shaded/protobuf/d;->b:J

    .line 187
    .line 188
    iput-object v3, p0, Le8/f;->M:Lcom/google/crypto/tink/shaded/protobuf/d;

    .line 189
    .line 190
    add-int/lit8 v2, v4, 0x1

    .line 191
    .line 192
    iput v2, p0, Le8/f;->N:I

    .line 193
    .line 194
    iget-boolean v2, p0, Le8/f;->K:Z

    .line 195
    .line 196
    if-nez v2, :cond_11

    .line 197
    .line 198
    const-wide/16 v2, 0x7530

    .line 199
    .line 200
    sub-long v10, v8, v2

    .line 201
    .line 202
    cmp-long v10, v10, p1

    .line 203
    .line 204
    if-gtz v10, :cond_b

    .line 205
    .line 206
    add-long/2addr v2, v8

    .line 207
    cmp-long v2, p1, v2

    .line 208
    .line 209
    if-gtz v2, :cond_b

    .line 210
    .line 211
    move v2, v7

    .line 212
    goto :goto_1

    .line 213
    :cond_b
    move v2, v1

    .line 214
    :goto_1
    iget-object v3, p0, Le8/f;->L:Lcom/google/crypto/tink/shaded/protobuf/d;

    .line 215
    .line 216
    if-eqz v3, :cond_c

    .line 217
    .line 218
    iget-wide v10, v3, Lcom/google/crypto/tink/shaded/protobuf/d;->b:J

    .line 219
    .line 220
    cmp-long v3, v10, p1

    .line 221
    .line 222
    if-gtz v3, :cond_c

    .line 223
    .line 224
    cmp-long p1, p1, v8

    .line 225
    .line 226
    if-gez p1, :cond_c

    .line 227
    .line 228
    move p1, v7

    .line 229
    goto :goto_2

    .line 230
    :cond_c
    move p1, v1

    .line 231
    :goto_2
    iget-object p2, p0, Le8/f;->F:Lt7/o;

    .line 232
    .line 233
    invoke-static {p2}, Lw7/a;->k(Ljava/lang/Object;)V

    .line 234
    .line 235
    .line 236
    iget p2, p2, Lt7/o;->M:I

    .line 237
    .line 238
    const/4 v3, -0x1

    .line 239
    if-eq p2, v3, :cond_e

    .line 240
    .line 241
    iget-object p2, p0, Le8/f;->F:Lt7/o;

    .line 242
    .line 243
    iget v8, p2, Lt7/o;->N:I

    .line 244
    .line 245
    if-eq v8, v3, :cond_e

    .line 246
    .line 247
    iget p2, p2, Lt7/o;->M:I

    .line 248
    .line 249
    mul-int/2addr v8, p2

    .line 250
    sub-int/2addr v8, v7

    .line 251
    if-ne v4, v8, :cond_d

    .line 252
    .line 253
    goto :goto_3

    .line 254
    :cond_d
    move p2, v1

    .line 255
    goto :goto_4

    .line 256
    :cond_e
    :goto_3
    move p2, v7

    .line 257
    :goto_4
    if-nez v2, :cond_10

    .line 258
    .line 259
    if-nez p1, :cond_10

    .line 260
    .line 261
    if-eqz p2, :cond_f

    .line 262
    .line 263
    goto :goto_5

    .line 264
    :cond_f
    move p2, v1

    .line 265
    goto :goto_6

    .line 266
    :cond_10
    :goto_5
    move p2, v7

    .line 267
    :goto_6
    iput-boolean p2, p0, Le8/f;->K:Z

    .line 268
    .line 269
    if-eqz p1, :cond_11

    .line 270
    .line 271
    if-nez v2, :cond_11

    .line 272
    .line 273
    goto :goto_7

    .line 274
    :cond_11
    iget-object p1, p0, Le8/f;->M:Lcom/google/crypto/tink/shaded/protobuf/d;

    .line 275
    .line 276
    iput-object p1, p0, Le8/f;->L:Lcom/google/crypto/tink/shaded/protobuf/d;

    .line 277
    .line 278
    iput-object v5, p0, Le8/f;->M:Lcom/google/crypto/tink/shaded/protobuf/d;

    .line 279
    .line 280
    :goto_7
    iget-object p1, p0, Le8/f;->H:Lz7/e;

    .line 281
    .line 282
    invoke-static {p1}, Lw7/a;->k(Ljava/lang/Object;)V

    .line 283
    .line 284
    .line 285
    invoke-virtual {p1, v6}, Lkq/d;->c(I)Z

    .line 286
    .line 287
    .line 288
    move-result p1

    .line 289
    if-eqz p1, :cond_12

    .line 290
    .line 291
    iput-boolean v7, p0, Le8/f;->y:Z

    .line 292
    .line 293
    iput-object v5, p0, Le8/f;->H:Lz7/e;

    .line 294
    .line 295
    return v1

    .line 296
    :cond_12
    iget-wide p1, p0, Le8/f;->C:J

    .line 297
    .line 298
    iget-object v1, p0, Le8/f;->H:Lz7/e;

    .line 299
    .line 300
    invoke-static {v1}, Lw7/a;->k(Ljava/lang/Object;)V

    .line 301
    .line 302
    .line 303
    iget-wide v1, v1, Lz7/e;->j:J

    .line 304
    .line 305
    invoke-static {p1, p2, v1, v2}, Ljava/lang/Math;->max(JJ)J

    .line 306
    .line 307
    .line 308
    move-result-wide p1

    .line 309
    iput-wide p1, p0, Le8/f;->C:J

    .line 310
    .line 311
    if-eqz v0, :cond_13

    .line 312
    .line 313
    iput-object v5, p0, Le8/f;->H:Lz7/e;

    .line 314
    .line 315
    goto :goto_8

    .line 316
    :cond_13
    iget-object p1, p0, Le8/f;->H:Lz7/e;

    .line 317
    .line 318
    invoke-static {p1}, Lw7/a;->k(Ljava/lang/Object;)V

    .line 319
    .line 320
    .line 321
    invoke-virtual {p1}, Lz7/e;->m()V

    .line 322
    .line 323
    .line 324
    :goto_8
    iget-boolean p0, p0, Le8/f;->K:Z

    .line 325
    .line 326
    xor-int/2addr p0, v7

    .line 327
    return p0

    .line 328
    :cond_14
    iget-object p1, v0, Lb81/d;->f:Ljava/lang/Object;

    .line 329
    .line 330
    check-cast p1, Lt7/o;

    .line 331
    .line 332
    invoke-static {p1}, Lw7/a;->k(Ljava/lang/Object;)V

    .line 333
    .line 334
    .line 335
    iput-object p1, p0, Le8/f;->F:Lt7/o;

    .line 336
    .line 337
    iput-boolean v7, p0, Le8/f;->O:Z

    .line 338
    .line 339
    iput v3, p0, Le8/f;->D:I

    .line 340
    .line 341
    return v7

    .line 342
    :cond_15
    :goto_9
    return v1
.end method

.method public final F()V
    .locals 4

    .line 1
    iget-boolean v0, p0, Le8/f;->O:Z

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    return-void

    .line 6
    :cond_0
    iget-object v0, p0, Le8/f;->F:Lt7/o;

    .line 7
    .line 8
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 9
    .line 10
    .line 11
    iget-object v1, p0, Le8/f;->v:Lcq/r1;

    .line 12
    .line 13
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 14
    .line 15
    .line 16
    invoke-static {v0}, Lcq/r1;->f(Lt7/o;)I

    .line 17
    .line 18
    .line 19
    move-result v0

    .line 20
    const/4 v2, 0x4

    .line 21
    const/4 v3, 0x0

    .line 22
    invoke-static {v2, v3, v3, v3}, La8/f;->f(IIII)I

    .line 23
    .line 24
    .line 25
    move-result v2

    .line 26
    if-eq v0, v2, :cond_2

    .line 27
    .line 28
    const/4 v2, 0x3

    .line 29
    invoke-static {v2, v3, v3, v3}, La8/f;->f(IIII)I

    .line 30
    .line 31
    .line 32
    move-result v2

    .line 33
    if-ne v0, v2, :cond_1

    .line 34
    .line 35
    goto :goto_0

    .line 36
    :cond_1
    new-instance v0, Le8/c;

    .line 37
    .line 38
    const-string v1, "Provided decoder factory can\'t create decoder for format."

    .line 39
    .line 40
    invoke-direct {v0, v1}, Ljava/lang/Exception;-><init>(Ljava/lang/String;)V

    .line 41
    .line 42
    .line 43
    iget-object v1, p0, Le8/f;->F:Lt7/o;

    .line 44
    .line 45
    const/16 v2, 0xfa5

    .line 46
    .line 47
    invoke-virtual {p0, v0, v1, v3, v2}, La8/f;->g(Ljava/lang/Exception;Lt7/o;ZI)La8/o;

    .line 48
    .line 49
    .line 50
    move-result-object p0

    .line 51
    throw p0

    .line 52
    :cond_2
    :goto_0
    iget-object v0, p0, Le8/f;->G:Le8/b;

    .line 53
    .line 54
    if-eqz v0, :cond_3

    .line 55
    .line 56
    invoke-virtual {v0}, Lz7/g;->b()V

    .line 57
    .line 58
    .line 59
    :cond_3
    new-instance v0, Le8/b;

    .line 60
    .line 61
    iget-object v1, v1, Lcq/r1;->d:Landroid/content/Context;

    .line 62
    .line 63
    invoke-direct {v0, v1}, Le8/b;-><init>(Landroid/content/Context;)V

    .line 64
    .line 65
    .line 66
    iput-object v0, p0, Le8/f;->G:Le8/b;

    .line 67
    .line 68
    iput-boolean v3, p0, Le8/f;->O:Z

    .line 69
    .line 70
    return-void
.end method

.method public final G()V
    .locals 3

    .line 1
    const/4 v0, 0x0

    .line 2
    iput-object v0, p0, Le8/f;->H:Lz7/e;

    .line 3
    .line 4
    const/4 v1, 0x0

    .line 5
    iput v1, p0, Le8/f;->D:I

    .line 6
    .line 7
    const-wide v1, -0x7fffffffffffffffL    # -4.9E-324

    .line 8
    .line 9
    .line 10
    .line 11
    .line 12
    iput-wide v1, p0, Le8/f;->C:J

    .line 13
    .line 14
    iget-object v1, p0, Le8/f;->G:Le8/b;

    .line 15
    .line 16
    if-eqz v1, :cond_0

    .line 17
    .line 18
    invoke-virtual {v1}, Lz7/g;->b()V

    .line 19
    .line 20
    .line 21
    iput-object v0, p0, Le8/f;->G:Le8/b;

    .line 22
    .line 23
    :cond_0
    return-void
.end method

.method public final a(ILjava/lang/Object;)V
    .locals 1

    .line 1
    const/16 v0, 0xf

    .line 2
    .line 3
    if-eq p1, v0, :cond_0

    .line 4
    .line 5
    return-void

    .line 6
    :cond_0
    instance-of p1, p2, Landroidx/media3/exoplayer/image/ImageOutput;

    .line 7
    .line 8
    if-eqz p1, :cond_1

    .line 9
    .line 10
    check-cast p2, Landroidx/media3/exoplayer/image/ImageOutput;

    .line 11
    .line 12
    goto :goto_0

    .line 13
    :cond_1
    const/4 p2, 0x0

    .line 14
    :goto_0
    if-nez p2, :cond_2

    .line 15
    .line 16
    sget-object p2, Landroidx/media3/exoplayer/image/ImageOutput;->a:Le8/d;

    .line 17
    .line 18
    :cond_2
    iput-object p2, p0, Le8/f;->I:Landroidx/media3/exoplayer/image/ImageOutput;

    .line 19
    .line 20
    return-void
.end method

.method public final k()Ljava/lang/String;
    .locals 0

    .line 1
    const-string p0, "ImageRenderer"

    .line 2
    .line 3
    return-object p0
.end method

.method public final m()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Le8/f;->z:Z

    .line 2
    .line 3
    return p0
.end method

.method public final o()Z
    .locals 2

    .line 1
    iget v0, p0, Le8/f;->E:I

    .line 2
    .line 3
    const/4 v1, 0x3

    .line 4
    if-eq v0, v1, :cond_1

    .line 5
    .line 6
    if-nez v0, :cond_0

    .line 7
    .line 8
    iget-boolean p0, p0, Le8/f;->K:Z

    .line 9
    .line 10
    if-eqz p0, :cond_0

    .line 11
    .line 12
    goto :goto_0

    .line 13
    :cond_0
    const/4 p0, 0x0

    .line 14
    return p0

    .line 15
    :cond_1
    :goto_0
    const/4 p0, 0x1

    .line 16
    return p0
.end method

.method public final p()V
    .locals 1

    .line 1
    const/4 v0, 0x0

    .line 2
    iput-object v0, p0, Le8/f;->F:Lt7/o;

    .line 3
    .line 4
    sget-object v0, Le8/e;->c:Le8/e;

    .line 5
    .line 6
    iput-object v0, p0, Le8/f;->A:Le8/e;

    .line 7
    .line 8
    iget-object v0, p0, Le8/f;->x:Ljava/util/ArrayDeque;

    .line 9
    .line 10
    invoke-virtual {v0}, Ljava/util/ArrayDeque;->clear()V

    .line 11
    .line 12
    .line 13
    invoke-virtual {p0}, Le8/f;->G()V

    .line 14
    .line 15
    .line 16
    iget-object p0, p0, Le8/f;->I:Landroidx/media3/exoplayer/image/ImageOutput;

    .line 17
    .line 18
    invoke-interface {p0}, Landroidx/media3/exoplayer/image/ImageOutput;->a()V

    .line 19
    .line 20
    .line 21
    return-void
.end method

.method public final q(ZZ)V
    .locals 0

    .line 1
    iput p2, p0, Le8/f;->E:I

    .line 2
    .line 3
    return-void
.end method

.method public final r(JZ)V
    .locals 0

    .line 1
    const/4 p1, 0x1

    .line 2
    iget p2, p0, Le8/f;->E:I

    .line 3
    .line 4
    invoke-static {p2, p1}, Ljava/lang/Math;->min(II)I

    .line 5
    .line 6
    .line 7
    move-result p1

    .line 8
    iput p1, p0, Le8/f;->E:I

    .line 9
    .line 10
    const/4 p1, 0x0

    .line 11
    iput-boolean p1, p0, Le8/f;->z:Z

    .line 12
    .line 13
    iput-boolean p1, p0, Le8/f;->y:Z

    .line 14
    .line 15
    const/4 p2, 0x0

    .line 16
    iput-object p2, p0, Le8/f;->J:Landroid/graphics/Bitmap;

    .line 17
    .line 18
    iput-object p2, p0, Le8/f;->L:Lcom/google/crypto/tink/shaded/protobuf/d;

    .line 19
    .line 20
    iput-object p2, p0, Le8/f;->M:Lcom/google/crypto/tink/shaded/protobuf/d;

    .line 21
    .line 22
    iput-boolean p1, p0, Le8/f;->K:Z

    .line 23
    .line 24
    iput-object p2, p0, Le8/f;->H:Lz7/e;

    .line 25
    .line 26
    iget-object p1, p0, Le8/f;->G:Le8/b;

    .line 27
    .line 28
    if-eqz p1, :cond_0

    .line 29
    .line 30
    invoke-virtual {p1}, Lz7/g;->flush()V

    .line 31
    .line 32
    .line 33
    :cond_0
    iget-object p0, p0, Le8/f;->x:Ljava/util/ArrayDeque;

    .line 34
    .line 35
    invoke-virtual {p0}, Ljava/util/ArrayDeque;->clear()V

    .line 36
    .line 37
    .line 38
    return-void
.end method

.method public final s()V
    .locals 0

    .line 1
    invoke-virtual {p0}, Le8/f;->G()V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public final t()V
    .locals 2

    .line 1
    invoke-virtual {p0}, Le8/f;->G()V

    .line 2
    .line 3
    .line 4
    const/4 v0, 0x1

    .line 5
    iget v1, p0, Le8/f;->E:I

    .line 6
    .line 7
    invoke-static {v1, v0}, Ljava/lang/Math;->min(II)I

    .line 8
    .line 9
    .line 10
    move-result v0

    .line 11
    iput v0, p0, Le8/f;->E:I

    .line 12
    .line 13
    return-void
.end method

.method public final w([Lt7/o;JJLh8/b0;)V
    .locals 4

    .line 1
    iget-object p1, p0, Le8/f;->A:Le8/e;

    .line 2
    .line 3
    iget-wide p1, p1, Le8/e;->b:J

    .line 4
    .line 5
    const-wide v0, -0x7fffffffffffffffL    # -4.9E-324

    .line 6
    .line 7
    .line 8
    .line 9
    .line 10
    cmp-long p1, p1, v0

    .line 11
    .line 12
    if-eqz p1, :cond_1

    .line 13
    .line 14
    iget-object p1, p0, Le8/f;->x:Ljava/util/ArrayDeque;

    .line 15
    .line 16
    invoke-virtual {p1}, Ljava/util/ArrayDeque;->isEmpty()Z

    .line 17
    .line 18
    .line 19
    move-result p2

    .line 20
    if-eqz p2, :cond_0

    .line 21
    .line 22
    iget-wide p2, p0, Le8/f;->C:J

    .line 23
    .line 24
    cmp-long p6, p2, v0

    .line 25
    .line 26
    if-eqz p6, :cond_1

    .line 27
    .line 28
    iget-wide v2, p0, Le8/f;->B:J

    .line 29
    .line 30
    cmp-long p6, v2, v0

    .line 31
    .line 32
    if-eqz p6, :cond_0

    .line 33
    .line 34
    cmp-long p2, v2, p2

    .line 35
    .line 36
    if-ltz p2, :cond_0

    .line 37
    .line 38
    goto :goto_0

    .line 39
    :cond_0
    new-instance p2, Le8/e;

    .line 40
    .line 41
    iget-wide v0, p0, Le8/f;->C:J

    .line 42
    .line 43
    invoke-direct {p2, v0, v1, p4, p5}, Le8/e;-><init>(JJ)V

    .line 44
    .line 45
    .line 46
    invoke-virtual {p1, p2}, Ljava/util/ArrayDeque;->add(Ljava/lang/Object;)Z

    .line 47
    .line 48
    .line 49
    return-void

    .line 50
    :cond_1
    :goto_0
    new-instance p1, Le8/e;

    .line 51
    .line 52
    invoke-direct {p1, v0, v1, p4, p5}, Le8/e;-><init>(JJ)V

    .line 53
    .line 54
    .line 55
    iput-object p1, p0, Le8/f;->A:Le8/e;

    .line 56
    .line 57
    return-void
.end method

.method public final y(JJ)V
    .locals 3

    .line 1
    iget-boolean p3, p0, Le8/f;->z:Z

    .line 2
    .line 3
    if-eqz p3, :cond_0

    .line 4
    .line 5
    goto :goto_0

    .line 6
    :cond_0
    iget-object p3, p0, Le8/f;->F:Lt7/o;

    .line 7
    .line 8
    if-nez p3, :cond_3

    .line 9
    .line 10
    iget-object p3, p0, La8/f;->f:Lb81/d;

    .line 11
    .line 12
    invoke-virtual {p3}, Lb81/d;->i()V

    .line 13
    .line 14
    .line 15
    iget-object p4, p0, Le8/f;->w:Lz7/e;

    .line 16
    .line 17
    invoke-virtual {p4}, Lz7/e;->m()V

    .line 18
    .line 19
    .line 20
    const/4 v0, 0x2

    .line 21
    invoke-virtual {p0, p3, p4, v0}, La8/f;->x(Lb81/d;Lz7/e;I)I

    .line 22
    .line 23
    .line 24
    move-result v0

    .line 25
    const/4 v1, -0x5

    .line 26
    const/4 v2, 0x1

    .line 27
    if-ne v0, v1, :cond_1

    .line 28
    .line 29
    iget-object p3, p3, Lb81/d;->f:Ljava/lang/Object;

    .line 30
    .line 31
    check-cast p3, Lt7/o;

    .line 32
    .line 33
    invoke-static {p3}, Lw7/a;->k(Ljava/lang/Object;)V

    .line 34
    .line 35
    .line 36
    iput-object p3, p0, Le8/f;->F:Lt7/o;

    .line 37
    .line 38
    iput-boolean v2, p0, Le8/f;->O:Z

    .line 39
    .line 40
    goto :goto_1

    .line 41
    :cond_1
    const/4 p1, -0x4

    .line 42
    if-ne v0, p1, :cond_2

    .line 43
    .line 44
    const/4 p1, 0x4

    .line 45
    invoke-virtual {p4, p1}, Lkq/d;->c(I)Z

    .line 46
    .line 47
    .line 48
    move-result p1

    .line 49
    invoke-static {p1}, Lw7/a;->j(Z)V

    .line 50
    .line 51
    .line 52
    iput-boolean v2, p0, Le8/f;->y:Z

    .line 53
    .line 54
    iput-boolean v2, p0, Le8/f;->z:Z

    .line 55
    .line 56
    :cond_2
    :goto_0
    return-void

    .line 57
    :cond_3
    :goto_1
    iget-object p3, p0, Le8/f;->G:Le8/b;

    .line 58
    .line 59
    if-nez p3, :cond_4

    .line 60
    .line 61
    invoke-virtual {p0}, Le8/f;->F()V

    .line 62
    .line 63
    .line 64
    :cond_4
    :try_start_0
    const-string p3, "drainAndFeedDecoder"

    .line 65
    .line 66
    invoke-static {p3}, Landroid/os/Trace;->beginSection(Ljava/lang/String;)V

    .line 67
    .line 68
    .line 69
    :goto_2
    invoke-virtual {p0, p1, p2}, Le8/f;->D(J)Z

    .line 70
    .line 71
    .line 72
    move-result p3

    .line 73
    if-eqz p3, :cond_5

    .line 74
    .line 75
    goto :goto_2

    .line 76
    :cond_5
    :goto_3
    invoke-virtual {p0, p1, p2}, Le8/f;->E(J)Z

    .line 77
    .line 78
    .line 79
    move-result p3

    .line 80
    if-eqz p3, :cond_6

    .line 81
    .line 82
    goto :goto_3

    .line 83
    :cond_6
    invoke-static {}, Landroid/os/Trace;->endSection()V
    :try_end_0
    .catch Le8/c; {:try_start_0 .. :try_end_0} :catch_0

    .line 84
    .line 85
    .line 86
    return-void

    .line 87
    :catch_0
    move-exception p1

    .line 88
    const/16 p2, 0xfa3

    .line 89
    .line 90
    const/4 p3, 0x0

    .line 91
    const/4 p4, 0x0

    .line 92
    invoke-virtual {p0, p1, p4, p3, p2}, La8/f;->g(Ljava/lang/Exception;Lt7/o;ZI)La8/o;

    .line 93
    .line 94
    .line 95
    move-result-object p0

    .line 96
    throw p0
.end method
