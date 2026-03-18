.class public final Lq8/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lo8/o;


# instance fields
.field public final a:Lw7/p;

.field public final b:Lm8/j;

.field public final c:Z

.field public final d:Ll9/h;

.field public e:I

.field public f:Lo8/q;

.field public g:Lq8/c;

.field public h:J

.field public i:[Lq8/e;

.field public j:J

.field public k:Lq8/e;

.field public l:I

.field public m:J

.field public n:J

.field public o:I

.field public p:Z


# direct methods
.method public constructor <init>(ILwe0/b;)V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p2, p0, Lq8/b;->d:Ll9/h;

    .line 5
    .line 6
    const/4 p2, 0x1

    .line 7
    and-int/2addr p1, p2

    .line 8
    const/4 v0, 0x0

    .line 9
    if-nez p1, :cond_0

    .line 10
    .line 11
    goto :goto_0

    .line 12
    :cond_0
    move p2, v0

    .line 13
    :goto_0
    iput-boolean p2, p0, Lq8/b;->c:Z

    .line 14
    .line 15
    new-instance p1, Lw7/p;

    .line 16
    .line 17
    const/16 p2, 0xc

    .line 18
    .line 19
    invoke-direct {p1, p2}, Lw7/p;-><init>(I)V

    .line 20
    .line 21
    .line 22
    iput-object p1, p0, Lq8/b;->a:Lw7/p;

    .line 23
    .line 24
    new-instance p1, Lm8/j;

    .line 25
    .line 26
    invoke-direct {p1}, Ljava/lang/Object;-><init>()V

    .line 27
    .line 28
    .line 29
    iput-object p1, p0, Lq8/b;->b:Lm8/j;

    .line 30
    .line 31
    new-instance p1, Lst/b;

    .line 32
    .line 33
    const/16 p2, 0xa

    .line 34
    .line 35
    invoke-direct {p1, p2}, Lst/b;-><init>(I)V

    .line 36
    .line 37
    .line 38
    iput-object p1, p0, Lq8/b;->f:Lo8/q;

    .line 39
    .line 40
    new-array p1, v0, [Lq8/e;

    .line 41
    .line 42
    iput-object p1, p0, Lq8/b;->i:[Lq8/e;

    .line 43
    .line 44
    const-wide/16 p1, -0x1

    .line 45
    .line 46
    iput-wide p1, p0, Lq8/b;->m:J

    .line 47
    .line 48
    iput-wide p1, p0, Lq8/b;->n:J

    .line 49
    .line 50
    const/4 p1, -0x1

    .line 51
    iput p1, p0, Lq8/b;->l:I

    .line 52
    .line 53
    const-wide p1, -0x7fffffffffffffffL    # -4.9E-324

    .line 54
    .line 55
    .line 56
    .line 57
    .line 58
    iput-wide p1, p0, Lq8/b;->h:J

    .line 59
    .line 60
    return-void
.end method


# virtual methods
.method public final a(Lo8/p;)Z
    .locals 3

    .line 1
    iget-object p0, p0, Lq8/b;->a:Lw7/p;

    .line 2
    .line 3
    iget-object v0, p0, Lw7/p;->a:[B

    .line 4
    .line 5
    const/16 v1, 0xc

    .line 6
    .line 7
    const/4 v2, 0x0

    .line 8
    invoke-interface {p1, v0, v2, v1}, Lo8/p;->o([BII)V

    .line 9
    .line 10
    .line 11
    invoke-virtual {p0, v2}, Lw7/p;->I(I)V

    .line 12
    .line 13
    .line 14
    invoke-virtual {p0}, Lw7/p;->l()I

    .line 15
    .line 16
    .line 17
    move-result p1

    .line 18
    const v0, 0x46464952

    .line 19
    .line 20
    .line 21
    if-eq p1, v0, :cond_0

    .line 22
    .line 23
    goto :goto_0

    .line 24
    :cond_0
    const/4 p1, 0x4

    .line 25
    invoke-virtual {p0, p1}, Lw7/p;->J(I)V

    .line 26
    .line 27
    .line 28
    invoke-virtual {p0}, Lw7/p;->l()I

    .line 29
    .line 30
    .line 31
    move-result p0

    .line 32
    const p1, 0x20495641

    .line 33
    .line 34
    .line 35
    if-ne p0, p1, :cond_1

    .line 36
    .line 37
    const/4 p0, 0x1

    .line 38
    return p0

    .line 39
    :cond_1
    :goto_0
    return v2
.end method

.method public final b()V
    .locals 0

    .line 1
    return-void
.end method

.method public final c(Lo8/q;)V
    .locals 2

    .line 1
    const/4 v0, 0x0

    .line 2
    iput v0, p0, Lq8/b;->e:I

    .line 3
    .line 4
    iget-boolean v0, p0, Lq8/b;->c:Z

    .line 5
    .line 6
    if-eqz v0, :cond_0

    .line 7
    .line 8
    new-instance v0, La8/b;

    .line 9
    .line 10
    iget-object v1, p0, Lq8/b;->d:Ll9/h;

    .line 11
    .line 12
    invoke-direct {v0, p1, v1}, La8/b;-><init>(Lo8/q;Ll9/h;)V

    .line 13
    .line 14
    .line 15
    move-object p1, v0

    .line 16
    :cond_0
    iput-object p1, p0, Lq8/b;->f:Lo8/q;

    .line 17
    .line 18
    const-wide/16 v0, -0x1

    .line 19
    .line 20
    iput-wide v0, p0, Lq8/b;->j:J

    .line 21
    .line 22
    return-void
.end method

.method public final d(JJ)V
    .locals 5

    .line 1
    const-wide/16 p3, -0x1

    .line 2
    .line 3
    iput-wide p3, p0, Lq8/b;->j:J

    .line 4
    .line 5
    const/4 p3, 0x0

    .line 6
    iput-object p3, p0, Lq8/b;->k:Lq8/e;

    .line 7
    .line 8
    iget-object p3, p0, Lq8/b;->i:[Lq8/e;

    .line 9
    .line 10
    array-length p4, p3

    .line 11
    const/4 v0, 0x0

    .line 12
    move v1, v0

    .line 13
    :goto_0
    if-ge v1, p4, :cond_1

    .line 14
    .line 15
    aget-object v2, p3, v1

    .line 16
    .line 17
    iget v3, v2, Lq8/e;->k:I

    .line 18
    .line 19
    if-nez v3, :cond_0

    .line 20
    .line 21
    iput v0, v2, Lq8/e;->i:I

    .line 22
    .line 23
    goto :goto_1

    .line 24
    :cond_0
    iget-object v3, v2, Lq8/e;->m:[J

    .line 25
    .line 26
    const/4 v4, 0x1

    .line 27
    invoke-static {v3, p1, p2, v4}, Lw7/w;->d([JJZ)I

    .line 28
    .line 29
    .line 30
    move-result v3

    .line 31
    iget-object v4, v2, Lq8/e;->n:[I

    .line 32
    .line 33
    aget v3, v4, v3

    .line 34
    .line 35
    iput v3, v2, Lq8/e;->i:I

    .line 36
    .line 37
    :goto_1
    add-int/lit8 v1, v1, 0x1

    .line 38
    .line 39
    goto :goto_0

    .line 40
    :cond_1
    const-wide/16 p3, 0x0

    .line 41
    .line 42
    cmp-long p1, p1, p3

    .line 43
    .line 44
    if-nez p1, :cond_3

    .line 45
    .line 46
    iget-object p1, p0, Lq8/b;->i:[Lq8/e;

    .line 47
    .line 48
    array-length p1, p1

    .line 49
    if-nez p1, :cond_2

    .line 50
    .line 51
    iput v0, p0, Lq8/b;->e:I

    .line 52
    .line 53
    return-void

    .line 54
    :cond_2
    const/4 p1, 0x3

    .line 55
    iput p1, p0, Lq8/b;->e:I

    .line 56
    .line 57
    return-void

    .line 58
    :cond_3
    const/4 p1, 0x6

    .line 59
    iput p1, p0, Lq8/b;->e:I

    .line 60
    .line 61
    return-void
.end method

.method public final h(Lo8/p;Lo8/s;)I
    .locals 23

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    iget-wide v2, v0, Lq8/b;->j:J

    .line 6
    .line 7
    const-wide/16 v4, -0x1

    .line 8
    .line 9
    cmp-long v2, v2, v4

    .line 10
    .line 11
    const/4 v3, 0x1

    .line 12
    const/4 v6, 0x0

    .line 13
    if-eqz v2, :cond_2

    .line 14
    .line 15
    invoke-interface {v1}, Lo8/p;->getPosition()J

    .line 16
    .line 17
    .line 18
    move-result-wide v7

    .line 19
    iget-wide v9, v0, Lq8/b;->j:J

    .line 20
    .line 21
    cmp-long v2, v9, v7

    .line 22
    .line 23
    if-ltz v2, :cond_0

    .line 24
    .line 25
    const-wide/32 v11, 0x40000

    .line 26
    .line 27
    .line 28
    add-long/2addr v11, v7

    .line 29
    cmp-long v2, v9, v11

    .line 30
    .line 31
    if-lez v2, :cond_1

    .line 32
    .line 33
    :cond_0
    move-object/from16 v2, p2

    .line 34
    .line 35
    goto :goto_0

    .line 36
    :cond_1
    sub-long/2addr v9, v7

    .line 37
    long-to-int v2, v9

    .line 38
    invoke-interface {v1, v2}, Lo8/p;->n(I)V

    .line 39
    .line 40
    .line 41
    goto :goto_1

    .line 42
    :goto_0
    iput-wide v9, v2, Lo8/s;->a:J

    .line 43
    .line 44
    move v2, v3

    .line 45
    goto :goto_2

    .line 46
    :cond_2
    :goto_1
    move v2, v6

    .line 47
    :goto_2
    iput-wide v4, v0, Lq8/b;->j:J

    .line 48
    .line 49
    if-eqz v2, :cond_3

    .line 50
    .line 51
    return v3

    .line 52
    :cond_3
    iget v2, v0, Lq8/b;->e:I

    .line 53
    .line 54
    const/4 v8, 0x6

    .line 55
    const/16 v10, 0x10

    .line 56
    .line 57
    const v11, 0x69766f6d

    .line 58
    .line 59
    .line 60
    const/4 v12, 0x2

    .line 61
    const/4 v13, 0x4

    .line 62
    const v14, 0x5453494c

    .line 63
    .line 64
    .line 65
    const/16 v15, 0x8

    .line 66
    .line 67
    const-wide/16 v16, 0x8

    .line 68
    .line 69
    move-wide/from16 v18, v4

    .line 70
    .line 71
    const/4 v4, 0x0

    .line 72
    const/16 v5, 0xc

    .line 73
    .line 74
    const/16 p2, 0x3

    .line 75
    .line 76
    iget-object v9, v0, Lq8/b;->b:Lm8/j;

    .line 77
    .line 78
    iget-object v7, v0, Lq8/b;->a:Lw7/p;

    .line 79
    .line 80
    packed-switch v2, :pswitch_data_0

    .line 81
    .line 82
    .line 83
    new-instance v0, Ljava/lang/AssertionError;

    .line 84
    .line 85
    invoke-direct {v0}, Ljava/lang/AssertionError;-><init>()V

    .line 86
    .line 87
    .line 88
    throw v0

    .line 89
    :pswitch_0
    invoke-interface {v1}, Lo8/p;->getPosition()J

    .line 90
    .line 91
    .line 92
    move-result-wide v8

    .line 93
    iget-wide v12, v0, Lq8/b;->n:J

    .line 94
    .line 95
    cmp-long v2, v8, v12

    .line 96
    .line 97
    if-ltz v2, :cond_4

    .line 98
    .line 99
    const/4 v0, -0x1

    .line 100
    return v0

    .line 101
    :cond_4
    iget-object v2, v0, Lq8/b;->k:Lq8/e;

    .line 102
    .line 103
    if-eqz v2, :cond_a

    .line 104
    .line 105
    iget v5, v2, Lq8/e;->h:I

    .line 106
    .line 107
    iget-object v7, v2, Lq8/e;->b:Lo8/i0;

    .line 108
    .line 109
    invoke-interface {v7, v1, v5, v6}, Lo8/i0;->d(Lt7/g;IZ)I

    .line 110
    .line 111
    .line 112
    move-result v1

    .line 113
    sub-int/2addr v5, v1

    .line 114
    iput v5, v2, Lq8/e;->h:I

    .line 115
    .line 116
    if-nez v5, :cond_5

    .line 117
    .line 118
    move v1, v3

    .line 119
    goto :goto_3

    .line 120
    :cond_5
    move v1, v6

    .line 121
    :goto_3
    if-eqz v1, :cond_8

    .line 122
    .line 123
    iget v5, v2, Lq8/e;->g:I

    .line 124
    .line 125
    if-lez v5, :cond_7

    .line 126
    .line 127
    iget-object v7, v2, Lq8/e;->b:Lo8/i0;

    .line 128
    .line 129
    iget v5, v2, Lq8/e;->i:I

    .line 130
    .line 131
    iget-wide v8, v2, Lq8/e;->e:J

    .line 132
    .line 133
    int-to-long v10, v5

    .line 134
    mul-long/2addr v8, v10

    .line 135
    iget v10, v2, Lq8/e;->f:I

    .line 136
    .line 137
    int-to-long v10, v10

    .line 138
    div-long/2addr v8, v10

    .line 139
    iget-object v10, v2, Lq8/e;->n:[I

    .line 140
    .line 141
    invoke-static {v10, v5}, Ljava/util/Arrays;->binarySearch([II)I

    .line 142
    .line 143
    .line 144
    move-result v5

    .line 145
    if-ltz v5, :cond_6

    .line 146
    .line 147
    move v10, v3

    .line 148
    goto :goto_4

    .line 149
    :cond_6
    move v10, v6

    .line 150
    :goto_4
    iget v11, v2, Lq8/e;->g:I

    .line 151
    .line 152
    const/4 v12, 0x0

    .line 153
    const/4 v13, 0x0

    .line 154
    invoke-interface/range {v7 .. v13}, Lo8/i0;->b(JIIILo8/h0;)V

    .line 155
    .line 156
    .line 157
    :cond_7
    iget v5, v2, Lq8/e;->i:I

    .line 158
    .line 159
    add-int/2addr v5, v3

    .line 160
    iput v5, v2, Lq8/e;->i:I

    .line 161
    .line 162
    :cond_8
    if-eqz v1, :cond_9

    .line 163
    .line 164
    iput-object v4, v0, Lq8/b;->k:Lq8/e;

    .line 165
    .line 166
    :cond_9
    return v6

    .line 167
    :cond_a
    invoke-interface {v1}, Lo8/p;->getPosition()J

    .line 168
    .line 169
    .line 170
    move-result-wide v8

    .line 171
    const-wide/16 v12, 0x1

    .line 172
    .line 173
    and-long/2addr v8, v12

    .line 174
    cmp-long v2, v8, v12

    .line 175
    .line 176
    if-nez v2, :cond_b

    .line 177
    .line 178
    invoke-interface {v1, v3}, Lo8/p;->n(I)V

    .line 179
    .line 180
    .line 181
    :cond_b
    iget-object v2, v7, Lw7/p;->a:[B

    .line 182
    .line 183
    invoke-interface {v1, v2, v6, v5}, Lo8/p;->o([BII)V

    .line 184
    .line 185
    .line 186
    invoke-virtual {v7, v6}, Lw7/p;->I(I)V

    .line 187
    .line 188
    .line 189
    invoke-virtual {v7}, Lw7/p;->l()I

    .line 190
    .line 191
    .line 192
    move-result v2

    .line 193
    if-ne v2, v14, :cond_d

    .line 194
    .line 195
    invoke-virtual {v7, v15}, Lw7/p;->I(I)V

    .line 196
    .line 197
    .line 198
    invoke-virtual {v7}, Lw7/p;->l()I

    .line 199
    .line 200
    .line 201
    move-result v0

    .line 202
    if-ne v0, v11, :cond_c

    .line 203
    .line 204
    move v15, v5

    .line 205
    :cond_c
    invoke-interface {v1, v15}, Lo8/p;->n(I)V

    .line 206
    .line 207
    .line 208
    invoke-interface {v1}, Lo8/p;->e()V

    .line 209
    .line 210
    .line 211
    return v6

    .line 212
    :cond_d
    invoke-virtual {v7}, Lw7/p;->l()I

    .line 213
    .line 214
    .line 215
    move-result v3

    .line 216
    const v5, 0x4b4e554a    # 1.352225E7f

    .line 217
    .line 218
    .line 219
    if-ne v2, v5, :cond_e

    .line 220
    .line 221
    invoke-interface {v1}, Lo8/p;->getPosition()J

    .line 222
    .line 223
    .line 224
    move-result-wide v1

    .line 225
    int-to-long v3, v3

    .line 226
    add-long/2addr v1, v3

    .line 227
    add-long v1, v1, v16

    .line 228
    .line 229
    iput-wide v1, v0, Lq8/b;->j:J

    .line 230
    .line 231
    return v6

    .line 232
    :cond_e
    invoke-interface {v1, v15}, Lo8/p;->n(I)V

    .line 233
    .line 234
    .line 235
    invoke-interface {v1}, Lo8/p;->e()V

    .line 236
    .line 237
    .line 238
    iget-object v5, v0, Lq8/b;->i:[Lq8/e;

    .line 239
    .line 240
    array-length v7, v5

    .line 241
    move v8, v6

    .line 242
    :goto_5
    if-ge v8, v7, :cond_11

    .line 243
    .line 244
    aget-object v9, v5, v8

    .line 245
    .line 246
    iget v10, v9, Lq8/e;->c:I

    .line 247
    .line 248
    if-eq v10, v2, :cond_10

    .line 249
    .line 250
    iget v10, v9, Lq8/e;->d:I

    .line 251
    .line 252
    if-ne v10, v2, :cond_f

    .line 253
    .line 254
    goto :goto_6

    .line 255
    :cond_f
    add-int/lit8 v8, v8, 0x1

    .line 256
    .line 257
    goto :goto_5

    .line 258
    :cond_10
    :goto_6
    move-object v4, v9

    .line 259
    :cond_11
    if-nez v4, :cond_12

    .line 260
    .line 261
    invoke-interface {v1}, Lo8/p;->getPosition()J

    .line 262
    .line 263
    .line 264
    move-result-wide v1

    .line 265
    int-to-long v3, v3

    .line 266
    add-long/2addr v1, v3

    .line 267
    iput-wide v1, v0, Lq8/b;->j:J

    .line 268
    .line 269
    return v6

    .line 270
    :cond_12
    iput v3, v4, Lq8/e;->g:I

    .line 271
    .line 272
    iput v3, v4, Lq8/e;->h:I

    .line 273
    .line 274
    iput-object v4, v0, Lq8/b;->k:Lq8/e;

    .line 275
    .line 276
    return v6

    .line 277
    :pswitch_1
    new-instance v2, Lw7/p;

    .line 278
    .line 279
    iget v5, v0, Lq8/b;->o:I

    .line 280
    .line 281
    invoke-direct {v2, v5}, Lw7/p;-><init>(I)V

    .line 282
    .line 283
    .line 284
    iget-object v5, v2, Lw7/p;->a:[B

    .line 285
    .line 286
    iget v7, v0, Lq8/b;->o:I

    .line 287
    .line 288
    invoke-interface {v1, v5, v6, v7}, Lo8/p;->readFully([BII)V

    .line 289
    .line 290
    .line 291
    invoke-virtual {v2}, Lw7/p;->a()I

    .line 292
    .line 293
    .line 294
    move-result v1

    .line 295
    const-wide/16 v20, 0x0

    .line 296
    .line 297
    if-ge v1, v10, :cond_13

    .line 298
    .line 299
    goto :goto_8

    .line 300
    :cond_13
    iget v1, v2, Lw7/p;->b:I

    .line 301
    .line 302
    invoke-virtual {v2, v15}, Lw7/p;->J(I)V

    .line 303
    .line 304
    .line 305
    invoke-virtual {v2}, Lw7/p;->l()I

    .line 306
    .line 307
    .line 308
    move-result v5

    .line 309
    int-to-long v14, v5

    .line 310
    iget-wide v4, v0, Lq8/b;->m:J

    .line 311
    .line 312
    cmp-long v7, v14, v4

    .line 313
    .line 314
    if-lez v7, :cond_14

    .line 315
    .line 316
    goto :goto_7

    .line 317
    :cond_14
    add-long v20, v4, v16

    .line 318
    .line 319
    :goto_7
    invoke-virtual {v2, v1}, Lw7/p;->I(I)V

    .line 320
    .line 321
    .line 322
    :goto_8
    invoke-virtual {v2}, Lw7/p;->a()I

    .line 323
    .line 324
    .line 325
    move-result v1

    .line 326
    if-lt v1, v10, :cond_1d

    .line 327
    .line 328
    invoke-virtual {v2}, Lw7/p;->l()I

    .line 329
    .line 330
    .line 331
    move-result v1

    .line 332
    invoke-virtual {v2}, Lw7/p;->l()I

    .line 333
    .line 334
    .line 335
    move-result v4

    .line 336
    invoke-virtual {v2}, Lw7/p;->l()I

    .line 337
    .line 338
    .line 339
    move-result v5

    .line 340
    int-to-long v14, v5

    .line 341
    add-long v14, v14, v20

    .line 342
    .line 343
    invoke-virtual {v2, v13}, Lw7/p;->J(I)V

    .line 344
    .line 345
    .line 346
    iget-object v5, v0, Lq8/b;->i:[Lq8/e;

    .line 347
    .line 348
    array-length v7, v5

    .line 349
    move v9, v6

    .line 350
    :goto_9
    if-ge v9, v7, :cond_16

    .line 351
    .line 352
    aget-object v11, v5, v9

    .line 353
    .line 354
    iget v13, v11, Lq8/e;->c:I

    .line 355
    .line 356
    if-eq v13, v1, :cond_17

    .line 357
    .line 358
    iget v13, v11, Lq8/e;->d:I

    .line 359
    .line 360
    if-ne v13, v1, :cond_15

    .line 361
    .line 362
    goto :goto_a

    .line 363
    :cond_15
    add-int/lit8 v9, v9, 0x1

    .line 364
    .line 365
    const/4 v13, 0x4

    .line 366
    goto :goto_9

    .line 367
    :cond_16
    const/4 v11, 0x0

    .line 368
    :cond_17
    :goto_a
    if-nez v11, :cond_18

    .line 369
    .line 370
    :goto_b
    const/4 v13, 0x4

    .line 371
    goto :goto_8

    .line 372
    :cond_18
    and-int/lit8 v1, v4, 0x10

    .line 373
    .line 374
    if-ne v1, v10, :cond_19

    .line 375
    .line 376
    move v1, v3

    .line 377
    goto :goto_c

    .line 378
    :cond_19
    move v1, v6

    .line 379
    :goto_c
    iget-wide v4, v11, Lq8/e;->l:J

    .line 380
    .line 381
    cmp-long v4, v4, v18

    .line 382
    .line 383
    if-nez v4, :cond_1a

    .line 384
    .line 385
    iput-wide v14, v11, Lq8/e;->l:J

    .line 386
    .line 387
    :cond_1a
    if-eqz v1, :cond_1c

    .line 388
    .line 389
    iget v1, v11, Lq8/e;->k:I

    .line 390
    .line 391
    iget-object v4, v11, Lq8/e;->n:[I

    .line 392
    .line 393
    array-length v4, v4

    .line 394
    if-ne v1, v4, :cond_1b

    .line 395
    .line 396
    iget-object v1, v11, Lq8/e;->m:[J

    .line 397
    .line 398
    array-length v4, v1

    .line 399
    mul-int/lit8 v4, v4, 0x3

    .line 400
    .line 401
    div-int/2addr v4, v12

    .line 402
    invoke-static {v1, v4}, Ljava/util/Arrays;->copyOf([JI)[J

    .line 403
    .line 404
    .line 405
    move-result-object v1

    .line 406
    iput-object v1, v11, Lq8/e;->m:[J

    .line 407
    .line 408
    iget-object v1, v11, Lq8/e;->n:[I

    .line 409
    .line 410
    array-length v4, v1

    .line 411
    mul-int/lit8 v4, v4, 0x3

    .line 412
    .line 413
    div-int/2addr v4, v12

    .line 414
    invoke-static {v1, v4}, Ljava/util/Arrays;->copyOf([II)[I

    .line 415
    .line 416
    .line 417
    move-result-object v1

    .line 418
    iput-object v1, v11, Lq8/e;->n:[I

    .line 419
    .line 420
    :cond_1b
    iget-object v1, v11, Lq8/e;->m:[J

    .line 421
    .line 422
    iget v4, v11, Lq8/e;->k:I

    .line 423
    .line 424
    aput-wide v14, v1, v4

    .line 425
    .line 426
    iget-object v1, v11, Lq8/e;->n:[I

    .line 427
    .line 428
    iget v5, v11, Lq8/e;->j:I

    .line 429
    .line 430
    aput v5, v1, v4

    .line 431
    .line 432
    add-int/2addr v4, v3

    .line 433
    iput v4, v11, Lq8/e;->k:I

    .line 434
    .line 435
    :cond_1c
    iget v1, v11, Lq8/e;->j:I

    .line 436
    .line 437
    add-int/2addr v1, v3

    .line 438
    iput v1, v11, Lq8/e;->j:I

    .line 439
    .line 440
    goto :goto_b

    .line 441
    :cond_1d
    iget-object v1, v0, Lq8/b;->i:[Lq8/e;

    .line 442
    .line 443
    array-length v2, v1

    .line 444
    move v4, v6

    .line 445
    :goto_d
    if-ge v4, v2, :cond_1f

    .line 446
    .line 447
    aget-object v5, v1, v4

    .line 448
    .line 449
    iget-object v7, v5, Lq8/e;->m:[J

    .line 450
    .line 451
    iget v9, v5, Lq8/e;->k:I

    .line 452
    .line 453
    invoke-static {v7, v9}, Ljava/util/Arrays;->copyOf([JI)[J

    .line 454
    .line 455
    .line 456
    move-result-object v7

    .line 457
    iput-object v7, v5, Lq8/e;->m:[J

    .line 458
    .line 459
    iget-object v7, v5, Lq8/e;->n:[I

    .line 460
    .line 461
    iget v9, v5, Lq8/e;->k:I

    .line 462
    .line 463
    invoke-static {v7, v9}, Ljava/util/Arrays;->copyOf([II)[I

    .line 464
    .line 465
    .line 466
    move-result-object v7

    .line 467
    iput-object v7, v5, Lq8/e;->n:[I

    .line 468
    .line 469
    iget v7, v5, Lq8/e;->c:I

    .line 470
    .line 471
    const/high16 v9, 0x62770000

    .line 472
    .line 473
    and-int/2addr v7, v9

    .line 474
    if-ne v7, v9, :cond_1e

    .line 475
    .line 476
    iget-object v7, v5, Lq8/e;->a:Lq8/d;

    .line 477
    .line 478
    iget v7, v7, Lq8/d;->f:I

    .line 479
    .line 480
    if-eqz v7, :cond_1e

    .line 481
    .line 482
    iget v7, v5, Lq8/e;->k:I

    .line 483
    .line 484
    if-lez v7, :cond_1e

    .line 485
    .line 486
    iput v7, v5, Lq8/e;->f:I

    .line 487
    .line 488
    :cond_1e
    add-int/lit8 v4, v4, 0x1

    .line 489
    .line 490
    goto :goto_d

    .line 491
    :cond_1f
    iput-boolean v3, v0, Lq8/b;->p:Z

    .line 492
    .line 493
    iget-object v1, v0, Lq8/b;->i:[Lq8/e;

    .line 494
    .line 495
    array-length v1, v1

    .line 496
    if-nez v1, :cond_20

    .line 497
    .line 498
    iget-object v1, v0, Lq8/b;->f:Lo8/q;

    .line 499
    .line 500
    new-instance v2, Lo8/t;

    .line 501
    .line 502
    iget-wide v3, v0, Lq8/b;->h:J

    .line 503
    .line 504
    invoke-direct {v2, v3, v4}, Lo8/t;-><init>(J)V

    .line 505
    .line 506
    .line 507
    invoke-interface {v1, v2}, Lo8/q;->c(Lo8/c0;)V

    .line 508
    .line 509
    .line 510
    goto :goto_e

    .line 511
    :cond_20
    iget-object v1, v0, Lq8/b;->f:Lo8/q;

    .line 512
    .line 513
    new-instance v2, Lo8/t;

    .line 514
    .line 515
    iget-wide v3, v0, Lq8/b;->h:J

    .line 516
    .line 517
    invoke-direct {v2, v0, v3, v4, v12}, Lo8/t;-><init>(Ljava/lang/Object;JI)V

    .line 518
    .line 519
    .line 520
    invoke-interface {v1, v2}, Lo8/q;->c(Lo8/c0;)V

    .line 521
    .line 522
    .line 523
    :goto_e
    iput v8, v0, Lq8/b;->e:I

    .line 524
    .line 525
    iget-wide v1, v0, Lq8/b;->m:J

    .line 526
    .line 527
    iput-wide v1, v0, Lq8/b;->j:J

    .line 528
    .line 529
    return v6

    .line 530
    :pswitch_2
    iget-object v2, v7, Lw7/p;->a:[B

    .line 531
    .line 532
    invoke-interface {v1, v2, v6, v15}, Lo8/p;->readFully([BII)V

    .line 533
    .line 534
    .line 535
    invoke-virtual {v7, v6}, Lw7/p;->I(I)V

    .line 536
    .line 537
    .line 538
    invoke-virtual {v7}, Lw7/p;->l()I

    .line 539
    .line 540
    .line 541
    move-result v2

    .line 542
    invoke-virtual {v7}, Lw7/p;->l()I

    .line 543
    .line 544
    .line 545
    move-result v3

    .line 546
    const v4, 0x31786469

    .line 547
    .line 548
    .line 549
    if-ne v2, v4, :cond_21

    .line 550
    .line 551
    const/4 v1, 0x5

    .line 552
    iput v1, v0, Lq8/b;->e:I

    .line 553
    .line 554
    iput v3, v0, Lq8/b;->o:I

    .line 555
    .line 556
    return v6

    .line 557
    :cond_21
    invoke-interface {v1}, Lo8/p;->getPosition()J

    .line 558
    .line 559
    .line 560
    move-result-wide v1

    .line 561
    int-to-long v3, v3

    .line 562
    add-long/2addr v1, v3

    .line 563
    iput-wide v1, v0, Lq8/b;->j:J

    .line 564
    .line 565
    return v6

    .line 566
    :pswitch_3
    iget-wide v12, v0, Lq8/b;->m:J

    .line 567
    .line 568
    cmp-long v2, v12, v18

    .line 569
    .line 570
    if-eqz v2, :cond_22

    .line 571
    .line 572
    invoke-interface {v1}, Lo8/p;->getPosition()J

    .line 573
    .line 574
    .line 575
    move-result-wide v12

    .line 576
    iget-wide v3, v0, Lq8/b;->m:J

    .line 577
    .line 578
    cmp-long v12, v12, v3

    .line 579
    .line 580
    if-eqz v12, :cond_22

    .line 581
    .line 582
    iput-wide v3, v0, Lq8/b;->j:J

    .line 583
    .line 584
    return v6

    .line 585
    :cond_22
    iget-object v3, v7, Lw7/p;->a:[B

    .line 586
    .line 587
    invoke-interface {v1, v3, v6, v5}, Lo8/p;->o([BII)V

    .line 588
    .line 589
    .line 590
    invoke-interface {v1}, Lo8/p;->e()V

    .line 591
    .line 592
    .line 593
    invoke-virtual {v7, v6}, Lw7/p;->I(I)V

    .line 594
    .line 595
    .line 596
    invoke-virtual {v9}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 597
    .line 598
    .line 599
    invoke-virtual {v7}, Lw7/p;->l()I

    .line 600
    .line 601
    .line 602
    move-result v3

    .line 603
    iput v3, v9, Lm8/j;->a:I

    .line 604
    .line 605
    invoke-virtual {v7}, Lw7/p;->l()I

    .line 606
    .line 607
    .line 608
    move-result v3

    .line 609
    iput v3, v9, Lm8/j;->b:I

    .line 610
    .line 611
    iput v6, v9, Lm8/j;->c:I

    .line 612
    .line 613
    invoke-virtual {v7}, Lw7/p;->l()I

    .line 614
    .line 615
    .line 616
    move-result v3

    .line 617
    iget v4, v9, Lm8/j;->a:I

    .line 618
    .line 619
    const v7, 0x46464952

    .line 620
    .line 621
    .line 622
    if-ne v4, v7, :cond_23

    .line 623
    .line 624
    invoke-interface {v1, v5}, Lo8/p;->n(I)V

    .line 625
    .line 626
    .line 627
    return v6

    .line 628
    :cond_23
    if-ne v4, v14, :cond_27

    .line 629
    .line 630
    if-eq v3, v11, :cond_24

    .line 631
    .line 632
    goto :goto_f

    .line 633
    :cond_24
    invoke-interface {v1}, Lo8/p;->getPosition()J

    .line 634
    .line 635
    .line 636
    move-result-wide v3

    .line 637
    iput-wide v3, v0, Lq8/b;->m:J

    .line 638
    .line 639
    iget v5, v9, Lm8/j;->b:I

    .line 640
    .line 641
    int-to-long v11, v5

    .line 642
    add-long/2addr v3, v11

    .line 643
    add-long v3, v3, v16

    .line 644
    .line 645
    iput-wide v3, v0, Lq8/b;->n:J

    .line 646
    .line 647
    iget-boolean v3, v0, Lq8/b;->p:Z

    .line 648
    .line 649
    if-nez v3, :cond_26

    .line 650
    .line 651
    iget-object v3, v0, Lq8/b;->g:Lq8/c;

    .line 652
    .line 653
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 654
    .line 655
    .line 656
    iget v3, v3, Lq8/c;->b:I

    .line 657
    .line 658
    and-int/2addr v3, v10

    .line 659
    if-ne v3, v10, :cond_25

    .line 660
    .line 661
    const/4 v3, 0x4

    .line 662
    iput v3, v0, Lq8/b;->e:I

    .line 663
    .line 664
    iget-wide v1, v0, Lq8/b;->n:J

    .line 665
    .line 666
    iput-wide v1, v0, Lq8/b;->j:J

    .line 667
    .line 668
    return v6

    .line 669
    :cond_25
    iget-object v3, v0, Lq8/b;->f:Lo8/q;

    .line 670
    .line 671
    new-instance v4, Lo8/t;

    .line 672
    .line 673
    iget-wide v9, v0, Lq8/b;->h:J

    .line 674
    .line 675
    invoke-direct {v4, v9, v10}, Lo8/t;-><init>(J)V

    .line 676
    .line 677
    .line 678
    invoke-interface {v3, v4}, Lo8/q;->c(Lo8/c0;)V

    .line 679
    .line 680
    .line 681
    const/4 v2, 0x1

    .line 682
    iput-boolean v2, v0, Lq8/b;->p:Z

    .line 683
    .line 684
    :cond_26
    invoke-interface {v1}, Lo8/p;->getPosition()J

    .line 685
    .line 686
    .line 687
    move-result-wide v1

    .line 688
    const-wide/16 v3, 0xc

    .line 689
    .line 690
    add-long/2addr v1, v3

    .line 691
    iput-wide v1, v0, Lq8/b;->j:J

    .line 692
    .line 693
    iput v8, v0, Lq8/b;->e:I

    .line 694
    .line 695
    return v6

    .line 696
    :cond_27
    :goto_f
    invoke-interface {v1}, Lo8/p;->getPosition()J

    .line 697
    .line 698
    .line 699
    move-result-wide v1

    .line 700
    iget v3, v9, Lm8/j;->b:I

    .line 701
    .line 702
    int-to-long v3, v3

    .line 703
    add-long/2addr v1, v3

    .line 704
    add-long v1, v1, v16

    .line 705
    .line 706
    iput-wide v1, v0, Lq8/b;->j:J

    .line 707
    .line 708
    return v6

    .line 709
    :pswitch_4
    iget v3, v0, Lq8/b;->l:I

    .line 710
    .line 711
    const/16 v22, 0x4

    .line 712
    .line 713
    add-int/lit8 v3, v3, -0x4

    .line 714
    .line 715
    new-instance v4, Lw7/p;

    .line 716
    .line 717
    invoke-direct {v4, v3}, Lw7/p;-><init>(I)V

    .line 718
    .line 719
    .line 720
    iget-object v5, v4, Lw7/p;->a:[B

    .line 721
    .line 722
    invoke-interface {v1, v5, v6, v3}, Lo8/p;->readFully([BII)V

    .line 723
    .line 724
    .line 725
    const v1, 0x6c726468

    .line 726
    .line 727
    .line 728
    invoke-static {v1, v4}, Lq8/f;->b(ILw7/p;)Lq8/f;

    .line 729
    .line 730
    .line 731
    move-result-object v3

    .line 732
    iget v4, v3, Lq8/f;->b:I

    .line 733
    .line 734
    if-ne v4, v1, :cond_32

    .line 735
    .line 736
    const-class v1, Lq8/c;

    .line 737
    .line 738
    invoke-virtual {v3, v1}, Lq8/f;->a(Ljava/lang/Class;)Lq8/a;

    .line 739
    .line 740
    .line 741
    move-result-object v1

    .line 742
    check-cast v1, Lq8/c;

    .line 743
    .line 744
    if-eqz v1, :cond_31

    .line 745
    .line 746
    iput-object v1, v0, Lq8/b;->g:Lq8/c;

    .line 747
    .line 748
    iget v4, v1, Lq8/c;->c:I

    .line 749
    .line 750
    int-to-long v4, v4

    .line 751
    iget v1, v1, Lq8/c;->a:I

    .line 752
    .line 753
    int-to-long v7, v1

    .line 754
    mul-long/2addr v4, v7

    .line 755
    iput-wide v4, v0, Lq8/b;->h:J

    .line 756
    .line 757
    new-instance v1, Ljava/util/ArrayList;

    .line 758
    .line 759
    invoke-direct {v1}, Ljava/util/ArrayList;-><init>()V

    .line 760
    .line 761
    .line 762
    iget-object v3, v3, Lq8/f;->a:Lhr/h0;

    .line 763
    .line 764
    invoke-virtual {v3, v6}, Lhr/h0;->s(I)Lhr/f0;

    .line 765
    .line 766
    .line 767
    move-result-object v3

    .line 768
    move v4, v6

    .line 769
    :cond_28
    :goto_10
    invoke-virtual {v3}, Lhr/f0;->hasNext()Z

    .line 770
    .line 771
    .line 772
    move-result v5

    .line 773
    if-eqz v5, :cond_30

    .line 774
    .line 775
    invoke-virtual {v3}, Lhr/f0;->next()Ljava/lang/Object;

    .line 776
    .line 777
    .line 778
    move-result-object v5

    .line 779
    check-cast v5, Lq8/a;

    .line 780
    .line 781
    invoke-interface {v5}, Lq8/a;->getType()I

    .line 782
    .line 783
    .line 784
    move-result v7

    .line 785
    const v8, 0x6c727473

    .line 786
    .line 787
    .line 788
    if-ne v7, v8, :cond_28

    .line 789
    .line 790
    check-cast v5, Lq8/f;

    .line 791
    .line 792
    add-int/lit8 v7, v4, 0x1

    .line 793
    .line 794
    const-class v8, Lq8/d;

    .line 795
    .line 796
    invoke-virtual {v5, v8}, Lq8/f;->a(Ljava/lang/Class;)Lq8/a;

    .line 797
    .line 798
    .line 799
    move-result-object v8

    .line 800
    check-cast v8, Lq8/d;

    .line 801
    .line 802
    const-class v9, Lq8/g;

    .line 803
    .line 804
    invoke-virtual {v5, v9}, Lq8/f;->a(Ljava/lang/Class;)Lq8/a;

    .line 805
    .line 806
    .line 807
    move-result-object v9

    .line 808
    check-cast v9, Lq8/g;

    .line 809
    .line 810
    const-string v10, "AviExtractor"

    .line 811
    .line 812
    if-nez v8, :cond_2a

    .line 813
    .line 814
    const-string v4, "Missing Stream Header"

    .line 815
    .line 816
    invoke-static {v10, v4}, Lw7/a;->y(Ljava/lang/String;Ljava/lang/String;)V

    .line 817
    .line 818
    .line 819
    :cond_29
    :goto_11
    const/4 v9, 0x0

    .line 820
    goto :goto_12

    .line 821
    :cond_2a
    if-nez v9, :cond_2b

    .line 822
    .line 823
    const-string v4, "Missing Stream Format"

    .line 824
    .line 825
    invoke-static {v10, v4}, Lw7/a;->y(Ljava/lang/String;Ljava/lang/String;)V

    .line 826
    .line 827
    .line 828
    goto :goto_11

    .line 829
    :cond_2b
    iget v10, v8, Lq8/d;->d:I

    .line 830
    .line 831
    int-to-long v13, v10

    .line 832
    iget v10, v8, Lq8/d;->b:I

    .line 833
    .line 834
    int-to-long v10, v10

    .line 835
    const-wide/32 v15, 0xf4240

    .line 836
    .line 837
    .line 838
    mul-long/2addr v15, v10

    .line 839
    iget v10, v8, Lq8/d;->c:I

    .line 840
    .line 841
    int-to-long v10, v10

    .line 842
    sget-object v17, Lw7/w;->a:Ljava/lang/String;

    .line 843
    .line 844
    sget-object v19, Ljava/math/RoundingMode;->DOWN:Ljava/math/RoundingMode;

    .line 845
    .line 846
    move-wide/from16 v17, v10

    .line 847
    .line 848
    invoke-static/range {v13 .. v19}, Lw7/w;->J(JJJLjava/math/RoundingMode;)J

    .line 849
    .line 850
    .line 851
    move-result-wide v10

    .line 852
    iget-object v9, v9, Lq8/g;->a:Lt7/o;

    .line 853
    .line 854
    invoke-virtual {v9}, Lt7/o;->a()Lt7/n;

    .line 855
    .line 856
    .line 857
    move-result-object v13

    .line 858
    invoke-static {v4}, Ljava/lang/Integer;->toString(I)Ljava/lang/String;

    .line 859
    .line 860
    .line 861
    move-result-object v14

    .line 862
    iput-object v14, v13, Lt7/n;->a:Ljava/lang/String;

    .line 863
    .line 864
    iget v14, v8, Lq8/d;->e:I

    .line 865
    .line 866
    if-eqz v14, :cond_2c

    .line 867
    .line 868
    iput v14, v13, Lt7/n;->n:I

    .line 869
    .line 870
    :cond_2c
    const-class v14, Lq8/h;

    .line 871
    .line 872
    invoke-virtual {v5, v14}, Lq8/f;->a(Ljava/lang/Class;)Lq8/a;

    .line 873
    .line 874
    .line 875
    move-result-object v5

    .line 876
    check-cast v5, Lq8/h;

    .line 877
    .line 878
    if-eqz v5, :cond_2d

    .line 879
    .line 880
    iget-object v5, v5, Lq8/h;->a:Ljava/lang/String;

    .line 881
    .line 882
    iput-object v5, v13, Lt7/n;->b:Ljava/lang/String;

    .line 883
    .line 884
    :cond_2d
    iget-object v5, v9, Lt7/o;->n:Ljava/lang/String;

    .line 885
    .line 886
    invoke-static {v5}, Lt7/d0;->h(Ljava/lang/String;)I

    .line 887
    .line 888
    .line 889
    move-result v5

    .line 890
    const/4 v2, 0x1

    .line 891
    if-eq v5, v2, :cond_2e

    .line 892
    .line 893
    if-ne v5, v12, :cond_29

    .line 894
    .line 895
    :cond_2e
    iget-object v9, v0, Lq8/b;->f:Lo8/q;

    .line 896
    .line 897
    invoke-interface {v9, v4, v5}, Lo8/q;->q(II)Lo8/i0;

    .line 898
    .line 899
    .line 900
    move-result-object v5

    .line 901
    invoke-static {v13, v5}, Lf2/m0;->x(Lt7/n;Lo8/i0;)V

    .line 902
    .line 903
    .line 904
    iget-wide v13, v0, Lq8/b;->h:J

    .line 905
    .line 906
    invoke-static {v13, v14, v10, v11}, Ljava/lang/Math;->max(JJ)J

    .line 907
    .line 908
    .line 909
    move-result-wide v9

    .line 910
    iput-wide v9, v0, Lq8/b;->h:J

    .line 911
    .line 912
    new-instance v9, Lq8/e;

    .line 913
    .line 914
    invoke-direct {v9, v4, v8, v5}, Lq8/e;-><init>(ILq8/d;Lo8/i0;)V

    .line 915
    .line 916
    .line 917
    :goto_12
    if-eqz v9, :cond_2f

    .line 918
    .line 919
    invoke-virtual {v1, v9}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 920
    .line 921
    .line 922
    :cond_2f
    move v4, v7

    .line 923
    goto/16 :goto_10

    .line 924
    .line 925
    :cond_30
    new-array v2, v6, [Lq8/e;

    .line 926
    .line 927
    invoke-virtual {v1, v2}, Ljava/util/ArrayList;->toArray([Ljava/lang/Object;)[Ljava/lang/Object;

    .line 928
    .line 929
    .line 930
    move-result-object v1

    .line 931
    check-cast v1, [Lq8/e;

    .line 932
    .line 933
    iput-object v1, v0, Lq8/b;->i:[Lq8/e;

    .line 934
    .line 935
    iget-object v1, v0, Lq8/b;->f:Lo8/q;

    .line 936
    .line 937
    invoke-interface {v1}, Lo8/q;->m()V

    .line 938
    .line 939
    .line 940
    move/from16 v1, p2

    .line 941
    .line 942
    iput v1, v0, Lq8/b;->e:I

    .line 943
    .line 944
    return v6

    .line 945
    :cond_31
    const-string v0, "AviHeader not found"

    .line 946
    .line 947
    const/4 v1, 0x0

    .line 948
    invoke-static {v1, v0}, Lt7/e0;->a(Ljava/lang/RuntimeException;Ljava/lang/String;)Lt7/e0;

    .line 949
    .line 950
    .line 951
    move-result-object v0

    .line 952
    throw v0

    .line 953
    :cond_32
    const/4 v1, 0x0

    .line 954
    new-instance v0, Ljava/lang/StringBuilder;

    .line 955
    .line 956
    const-string v2, "Unexpected header list type "

    .line 957
    .line 958
    invoke-direct {v0, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 959
    .line 960
    .line 961
    invoke-virtual {v0, v4}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 962
    .line 963
    .line 964
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 965
    .line 966
    .line 967
    move-result-object v0

    .line 968
    invoke-static {v1, v0}, Lt7/e0;->a(Ljava/lang/RuntimeException;Ljava/lang/String;)Lt7/e0;

    .line 969
    .line 970
    .line 971
    move-result-object v0

    .line 972
    throw v0

    .line 973
    :pswitch_5
    iget-object v2, v7, Lw7/p;->a:[B

    .line 974
    .line 975
    invoke-interface {v1, v2, v6, v5}, Lo8/p;->readFully([BII)V

    .line 976
    .line 977
    .line 978
    invoke-virtual {v7, v6}, Lw7/p;->I(I)V

    .line 979
    .line 980
    .line 981
    invoke-virtual {v9}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 982
    .line 983
    .line 984
    invoke-virtual {v7}, Lw7/p;->l()I

    .line 985
    .line 986
    .line 987
    move-result v1

    .line 988
    iput v1, v9, Lm8/j;->a:I

    .line 989
    .line 990
    invoke-virtual {v7}, Lw7/p;->l()I

    .line 991
    .line 992
    .line 993
    move-result v1

    .line 994
    iput v1, v9, Lm8/j;->b:I

    .line 995
    .line 996
    iput v6, v9, Lm8/j;->c:I

    .line 997
    .line 998
    iget v1, v9, Lm8/j;->a:I

    .line 999
    .line 1000
    if-ne v1, v14, :cond_34

    .line 1001
    .line 1002
    invoke-virtual {v7}, Lw7/p;->l()I

    .line 1003
    .line 1004
    .line 1005
    move-result v1

    .line 1006
    iput v1, v9, Lm8/j;->c:I

    .line 1007
    .line 1008
    const v2, 0x6c726468

    .line 1009
    .line 1010
    .line 1011
    if-ne v1, v2, :cond_33

    .line 1012
    .line 1013
    iget v1, v9, Lm8/j;->b:I

    .line 1014
    .line 1015
    iput v1, v0, Lq8/b;->l:I

    .line 1016
    .line 1017
    iput v12, v0, Lq8/b;->e:I

    .line 1018
    .line 1019
    return v6

    .line 1020
    :cond_33
    new-instance v0, Ljava/lang/StringBuilder;

    .line 1021
    .line 1022
    const-string v1, "hdrl expected, found: "

    .line 1023
    .line 1024
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 1025
    .line 1026
    .line 1027
    iget v1, v9, Lm8/j;->c:I

    .line 1028
    .line 1029
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 1030
    .line 1031
    .line 1032
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 1033
    .line 1034
    .line 1035
    move-result-object v0

    .line 1036
    const/4 v3, 0x0

    .line 1037
    invoke-static {v3, v0}, Lt7/e0;->a(Ljava/lang/RuntimeException;Ljava/lang/String;)Lt7/e0;

    .line 1038
    .line 1039
    .line 1040
    move-result-object v0

    .line 1041
    throw v0

    .line 1042
    :cond_34
    const/4 v3, 0x0

    .line 1043
    new-instance v0, Ljava/lang/StringBuilder;

    .line 1044
    .line 1045
    const-string v1, "LIST expected, found: "

    .line 1046
    .line 1047
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 1048
    .line 1049
    .line 1050
    iget v1, v9, Lm8/j;->a:I

    .line 1051
    .line 1052
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 1053
    .line 1054
    .line 1055
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 1056
    .line 1057
    .line 1058
    move-result-object v0

    .line 1059
    invoke-static {v3, v0}, Lt7/e0;->a(Ljava/lang/RuntimeException;Ljava/lang/String;)Lt7/e0;

    .line 1060
    .line 1061
    .line 1062
    move-result-object v0

    .line 1063
    throw v0

    .line 1064
    :pswitch_6
    move-object v3, v4

    .line 1065
    invoke-virtual/range {p0 .. p1}, Lq8/b;->a(Lo8/p;)Z

    .line 1066
    .line 1067
    .line 1068
    move-result v4

    .line 1069
    if-eqz v4, :cond_35

    .line 1070
    .line 1071
    invoke-interface {v1, v5}, Lo8/p;->n(I)V

    .line 1072
    .line 1073
    .line 1074
    const/4 v2, 0x1

    .line 1075
    iput v2, v0, Lq8/b;->e:I

    .line 1076
    .line 1077
    return v6

    .line 1078
    :cond_35
    const-string v0, "AVI Header List not found"

    .line 1079
    .line 1080
    invoke-static {v3, v0}, Lt7/e0;->a(Ljava/lang/RuntimeException;Ljava/lang/String;)Lt7/e0;

    .line 1081
    .line 1082
    .line 1083
    move-result-object v0

    .line 1084
    throw v0

    .line 1085
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
