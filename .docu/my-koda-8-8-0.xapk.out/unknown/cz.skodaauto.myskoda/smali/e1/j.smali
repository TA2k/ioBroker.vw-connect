.class public final Le1/j;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Lt4/c;

.field public b:J

.field public final c:Le1/f0;

.field public final d:Ll2/j1;

.field public final e:Z

.field public f:Z

.field public g:J

.field public h:J

.field public final i:Lv3/n;


# direct methods
.method public constructor <init>(Landroid/content/Context;Lt4/c;JLk1/z0;)V
    .locals 2

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p2, p0, Le1/j;->a:Lt4/c;

    .line 5
    .line 6
    const-wide v0, 0x7fc000007fc00000L    # 2.247117487993712E307

    .line 7
    .line 8
    .line 9
    .line 10
    .line 11
    iput-wide v0, p0, Le1/j;->b:J

    .line 12
    .line 13
    new-instance p2, Le1/f0;

    .line 14
    .line 15
    invoke-static {p3, p4}, Le3/j0;->z(J)I

    .line 16
    .line 17
    .line 18
    move-result p3

    .line 19
    invoke-direct {p2, p1, p3}, Le1/f0;-><init>(Landroid/content/Context;I)V

    .line 20
    .line 21
    .line 22
    iput-object p2, p0, Le1/j;->c:Le1/f0;

    .line 23
    .line 24
    sget-object p1, Ll2/x0;->f:Ll2/x0;

    .line 25
    .line 26
    new-instance p3, Ll2/j1;

    .line 27
    .line 28
    sget-object p4, Llx0/b0;->a:Llx0/b0;

    .line 29
    .line 30
    invoke-direct {p3, p4, p1}, Ll2/j1;-><init>(Ljava/lang/Object;Ll2/n2;)V

    .line 31
    .line 32
    .line 33
    iput-object p3, p0, Le1/j;->d:Ll2/j1;

    .line 34
    .line 35
    const/4 p1, 0x1

    .line 36
    iput-boolean p1, p0, Le1/j;->e:Z

    .line 37
    .line 38
    const-wide/16 p3, 0x0

    .line 39
    .line 40
    iput-wide p3, p0, Le1/j;->g:J

    .line 41
    .line 42
    const-wide/16 p3, -0x1

    .line 43
    .line 44
    iput-wide p3, p0, Le1/j;->h:J

    .line 45
    .line 46
    new-instance p1, Lb2/b;

    .line 47
    .line 48
    const/4 p3, 0x1

    .line 49
    invoke-direct {p1, p0, p3}, Lb2/b;-><init>(Ljava/lang/Object;I)V

    .line 50
    .line 51
    .line 52
    invoke-static {p1}, Lp3/f0;->a(Landroidx/compose/ui/input/pointer/PointerInputEventHandler;)Lp3/j0;

    .line 53
    .line 54
    .line 55
    move-result-object p1

    .line 56
    sget p3, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 57
    .line 58
    const/16 p4, 0x1f

    .line 59
    .line 60
    if-lt p3, p4, :cond_0

    .line 61
    .line 62
    new-instance p3, Le1/j0;

    .line 63
    .line 64
    invoke-direct {p3, p1, p0, p2}, Le1/j0;-><init>(Lp3/j0;Le1/j;Le1/f0;)V

    .line 65
    .line 66
    .line 67
    goto :goto_0

    .line 68
    :cond_0
    new-instance p3, Le1/j0;

    .line 69
    .line 70
    invoke-direct {p3, p1, p0, p2, p5}, Le1/j0;-><init>(Lp3/j0;Le1/j;Le1/f0;Lk1/z0;)V

    .line 71
    .line 72
    .line 73
    :goto_0
    iput-object p3, p0, Le1/j;->i:Lv3/n;

    .line 74
    .line 75
    return-void
.end method


# virtual methods
.method public final a()V
    .locals 5

    .line 1
    iget-object v0, p0, Le1/j;->c:Le1/f0;

    .line 2
    .line 3
    iget-object v1, v0, Le1/f0;->d:Landroid/widget/EdgeEffect;

    .line 4
    .line 5
    const/4 v2, 0x1

    .line 6
    const/4 v3, 0x0

    .line 7
    if-eqz v1, :cond_0

    .line 8
    .line 9
    invoke-virtual {v1}, Landroid/widget/EdgeEffect;->onRelease()V

    .line 10
    .line 11
    .line 12
    invoke-virtual {v1}, Landroid/widget/EdgeEffect;->isFinished()Z

    .line 13
    .line 14
    .line 15
    move-result v1

    .line 16
    xor-int/2addr v1, v2

    .line 17
    goto :goto_0

    .line 18
    :cond_0
    move v1, v3

    .line 19
    :goto_0
    iget-object v4, v0, Le1/f0;->e:Landroid/widget/EdgeEffect;

    .line 20
    .line 21
    if-eqz v4, :cond_3

    .line 22
    .line 23
    invoke-virtual {v4}, Landroid/widget/EdgeEffect;->onRelease()V

    .line 24
    .line 25
    .line 26
    invoke-virtual {v4}, Landroid/widget/EdgeEffect;->isFinished()Z

    .line 27
    .line 28
    .line 29
    move-result v4

    .line 30
    if-eqz v4, :cond_2

    .line 31
    .line 32
    if-eqz v1, :cond_1

    .line 33
    .line 34
    goto :goto_1

    .line 35
    :cond_1
    move v1, v3

    .line 36
    goto :goto_2

    .line 37
    :cond_2
    :goto_1
    move v1, v2

    .line 38
    :cond_3
    :goto_2
    iget-object v4, v0, Le1/f0;->f:Landroid/widget/EdgeEffect;

    .line 39
    .line 40
    if-eqz v4, :cond_6

    .line 41
    .line 42
    invoke-virtual {v4}, Landroid/widget/EdgeEffect;->onRelease()V

    .line 43
    .line 44
    .line 45
    invoke-virtual {v4}, Landroid/widget/EdgeEffect;->isFinished()Z

    .line 46
    .line 47
    .line 48
    move-result v4

    .line 49
    if-eqz v4, :cond_5

    .line 50
    .line 51
    if-eqz v1, :cond_4

    .line 52
    .line 53
    goto :goto_3

    .line 54
    :cond_4
    move v1, v3

    .line 55
    goto :goto_4

    .line 56
    :cond_5
    :goto_3
    move v1, v2

    .line 57
    :cond_6
    :goto_4
    iget-object v0, v0, Le1/f0;->g:Landroid/widget/EdgeEffect;

    .line 58
    .line 59
    if-eqz v0, :cond_9

    .line 60
    .line 61
    invoke-virtual {v0}, Landroid/widget/EdgeEffect;->onRelease()V

    .line 62
    .line 63
    .line 64
    invoke-virtual {v0}, Landroid/widget/EdgeEffect;->isFinished()Z

    .line 65
    .line 66
    .line 67
    move-result v0

    .line 68
    if-eqz v0, :cond_8

    .line 69
    .line 70
    if-eqz v1, :cond_7

    .line 71
    .line 72
    goto :goto_5

    .line 73
    :cond_7
    move v2, v3

    .line 74
    :cond_8
    :goto_5
    move v1, v2

    .line 75
    :cond_9
    if-eqz v1, :cond_a

    .line 76
    .line 77
    invoke-virtual {p0}, Le1/j;->d()V

    .line 78
    .line 79
    .line 80
    :cond_a
    return-void
.end method

.method public final b(JLay0/n;Lrx0/c;)Ljava/lang/Object;
    .locals 18

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-wide/from16 v1, p1

    .line 4
    .line 5
    move-object/from16 v3, p3

    .line 6
    .line 7
    move-object/from16 v4, p4

    .line 8
    .line 9
    instance-of v5, v4, Le1/i;

    .line 10
    .line 11
    if-eqz v5, :cond_0

    .line 12
    .line 13
    move-object v5, v4

    .line 14
    check-cast v5, Le1/i;

    .line 15
    .line 16
    iget v6, v5, Le1/i;->g:I

    .line 17
    .line 18
    const/high16 v7, -0x80000000

    .line 19
    .line 20
    and-int v8, v6, v7

    .line 21
    .line 22
    if-eqz v8, :cond_0

    .line 23
    .line 24
    sub-int/2addr v6, v7

    .line 25
    iput v6, v5, Le1/i;->g:I

    .line 26
    .line 27
    goto :goto_0

    .line 28
    :cond_0
    new-instance v5, Le1/i;

    .line 29
    .line 30
    invoke-direct {v5, v0, v4}, Le1/i;-><init>(Le1/j;Lrx0/c;)V

    .line 31
    .line 32
    .line 33
    :goto_0
    iget-object v4, v5, Le1/i;->e:Ljava/lang/Object;

    .line 34
    .line 35
    sget-object v6, Lqx0/a;->d:Lqx0/a;

    .line 36
    .line 37
    iget v7, v5, Le1/i;->g:I

    .line 38
    .line 39
    sget-object v8, Llx0/b0;->a:Llx0/b0;

    .line 40
    .line 41
    const/4 v9, 0x2

    .line 42
    const/4 v10, 0x1

    .line 43
    const/4 v11, 0x0

    .line 44
    iget-object v12, v0, Le1/j;->c:Le1/f0;

    .line 45
    .line 46
    if-eqz v7, :cond_3

    .line 47
    .line 48
    if-eq v7, v10, :cond_2

    .line 49
    .line 50
    if-ne v7, v9, :cond_1

    .line 51
    .line 52
    iget-wide v1, v5, Le1/i;->d:J

    .line 53
    .line 54
    invoke-static {v4}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 55
    .line 56
    .line 57
    goto/16 :goto_5

    .line 58
    .line 59
    :cond_1
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 60
    .line 61
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 62
    .line 63
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 64
    .line 65
    .line 66
    throw v0

    .line 67
    :cond_2
    invoke-static {v4}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 68
    .line 69
    .line 70
    return-object v8

    .line 71
    :cond_3
    invoke-static {v4}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 72
    .line 73
    .line 74
    iget-wide v13, v0, Le1/j;->g:J

    .line 75
    .line 76
    invoke-static {v13, v14}, Ld3/e;->e(J)Z

    .line 77
    .line 78
    .line 79
    move-result v4

    .line 80
    if-eqz v4, :cond_5

    .line 81
    .line 82
    new-instance v0, Lt4/q;

    .line 83
    .line 84
    invoke-direct {v0, v1, v2}, Lt4/q;-><init>(J)V

    .line 85
    .line 86
    .line 87
    iput v10, v5, Le1/i;->g:I

    .line 88
    .line 89
    invoke-interface {v3, v0, v5}, Lay0/n;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 90
    .line 91
    .line 92
    move-result-object v0

    .line 93
    if-ne v0, v6, :cond_4

    .line 94
    .line 95
    goto/16 :goto_4

    .line 96
    .line 97
    :cond_4
    return-object v8

    .line 98
    :cond_5
    iget-object v4, v12, Le1/f0;->f:Landroid/widget/EdgeEffect;

    .line 99
    .line 100
    invoke-static {v4}, Le1/f0;->g(Landroid/widget/EdgeEffect;)Z

    .line 101
    .line 102
    .line 103
    move-result v4

    .line 104
    const/16 v7, 0x20

    .line 105
    .line 106
    iget-object v10, v0, Le1/j;->a:Lt4/c;

    .line 107
    .line 108
    if-eqz v4, :cond_6

    .line 109
    .line 110
    invoke-static {v1, v2}, Lt4/q;->b(J)F

    .line 111
    .line 112
    .line 113
    move-result v4

    .line 114
    cmpg-float v4, v4, v11

    .line 115
    .line 116
    if-gez v4, :cond_6

    .line 117
    .line 118
    invoke-virtual {v12}, Le1/f0;->c()Landroid/widget/EdgeEffect;

    .line 119
    .line 120
    .line 121
    move-result-object v4

    .line 122
    invoke-static {v1, v2}, Lt4/q;->b(J)F

    .line 123
    .line 124
    .line 125
    move-result v13

    .line 126
    iget-wide v14, v0, Le1/j;->g:J

    .line 127
    .line 128
    shr-long/2addr v14, v7

    .line 129
    long-to-int v7, v14

    .line 130
    invoke-static {v7}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 131
    .line 132
    .line 133
    move-result v7

    .line 134
    invoke-static {v4, v13, v7, v10}, Lkp/l;->a(Landroid/widget/EdgeEffect;FFLt4/c;)F

    .line 135
    .line 136
    .line 137
    move-result v4

    .line 138
    goto :goto_1

    .line 139
    :cond_6
    iget-object v4, v12, Le1/f0;->g:Landroid/widget/EdgeEffect;

    .line 140
    .line 141
    invoke-static {v4}, Le1/f0;->g(Landroid/widget/EdgeEffect;)Z

    .line 142
    .line 143
    .line 144
    move-result v4

    .line 145
    if-eqz v4, :cond_7

    .line 146
    .line 147
    invoke-static {v1, v2}, Lt4/q;->b(J)F

    .line 148
    .line 149
    .line 150
    move-result v4

    .line 151
    cmpl-float v4, v4, v11

    .line 152
    .line 153
    if-lez v4, :cond_7

    .line 154
    .line 155
    invoke-virtual {v12}, Le1/f0;->d()Landroid/widget/EdgeEffect;

    .line 156
    .line 157
    .line 158
    move-result-object v4

    .line 159
    invoke-static {v1, v2}, Lt4/q;->b(J)F

    .line 160
    .line 161
    .line 162
    move-result v13

    .line 163
    neg-float v13, v13

    .line 164
    iget-wide v14, v0, Le1/j;->g:J

    .line 165
    .line 166
    shr-long/2addr v14, v7

    .line 167
    long-to-int v7, v14

    .line 168
    invoke-static {v7}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 169
    .line 170
    .line 171
    move-result v7

    .line 172
    invoke-static {v4, v13, v7, v10}, Lkp/l;->a(Landroid/widget/EdgeEffect;FFLt4/c;)F

    .line 173
    .line 174
    .line 175
    move-result v4

    .line 176
    neg-float v4, v4

    .line 177
    goto :goto_1

    .line 178
    :cond_7
    move v4, v11

    .line 179
    :goto_1
    iget-object v7, v12, Le1/f0;->d:Landroid/widget/EdgeEffect;

    .line 180
    .line 181
    invoke-static {v7}, Le1/f0;->g(Landroid/widget/EdgeEffect;)Z

    .line 182
    .line 183
    .line 184
    move-result v7

    .line 185
    if-eqz v7, :cond_8

    .line 186
    .line 187
    invoke-static {v1, v2}, Lt4/q;->c(J)F

    .line 188
    .line 189
    .line 190
    move-result v7

    .line 191
    cmpg-float v7, v7, v11

    .line 192
    .line 193
    if-gez v7, :cond_8

    .line 194
    .line 195
    invoke-virtual {v12}, Le1/f0;->e()Landroid/widget/EdgeEffect;

    .line 196
    .line 197
    .line 198
    move-result-object v7

    .line 199
    invoke-static {v1, v2}, Lt4/q;->c(J)F

    .line 200
    .line 201
    .line 202
    move-result v15

    .line 203
    const-wide v16, 0xffffffffL

    .line 204
    .line 205
    .line 206
    .line 207
    .line 208
    iget-wide v13, v0, Le1/j;->g:J

    .line 209
    .line 210
    and-long v13, v13, v16

    .line 211
    .line 212
    long-to-int v13, v13

    .line 213
    invoke-static {v13}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 214
    .line 215
    .line 216
    move-result v13

    .line 217
    invoke-static {v7, v15, v13, v10}, Lkp/l;->a(Landroid/widget/EdgeEffect;FFLt4/c;)F

    .line 218
    .line 219
    .line 220
    move-result v7

    .line 221
    goto :goto_2

    .line 222
    :cond_8
    const-wide v16, 0xffffffffL

    .line 223
    .line 224
    .line 225
    .line 226
    .line 227
    iget-object v7, v12, Le1/f0;->e:Landroid/widget/EdgeEffect;

    .line 228
    .line 229
    invoke-static {v7}, Le1/f0;->g(Landroid/widget/EdgeEffect;)Z

    .line 230
    .line 231
    .line 232
    move-result v7

    .line 233
    if-eqz v7, :cond_9

    .line 234
    .line 235
    invoke-static {v1, v2}, Lt4/q;->c(J)F

    .line 236
    .line 237
    .line 238
    move-result v7

    .line 239
    cmpl-float v7, v7, v11

    .line 240
    .line 241
    if-lez v7, :cond_9

    .line 242
    .line 243
    invoke-virtual {v12}, Le1/f0;->b()Landroid/widget/EdgeEffect;

    .line 244
    .line 245
    .line 246
    move-result-object v7

    .line 247
    invoke-static {v1, v2}, Lt4/q;->c(J)F

    .line 248
    .line 249
    .line 250
    move-result v13

    .line 251
    neg-float v13, v13

    .line 252
    iget-wide v14, v0, Le1/j;->g:J

    .line 253
    .line 254
    and-long v14, v14, v16

    .line 255
    .line 256
    long-to-int v14, v14

    .line 257
    invoke-static {v14}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 258
    .line 259
    .line 260
    move-result v14

    .line 261
    invoke-static {v7, v13, v14, v10}, Lkp/l;->a(Landroid/widget/EdgeEffect;FFLt4/c;)F

    .line 262
    .line 263
    .line 264
    move-result v7

    .line 265
    neg-float v7, v7

    .line 266
    goto :goto_2

    .line 267
    :cond_9
    move v7, v11

    .line 268
    :goto_2
    invoke-static {v4, v7}, Lkp/g9;->a(FF)J

    .line 269
    .line 270
    .line 271
    move-result-wide v13

    .line 272
    const-wide/16 v15, 0x0

    .line 273
    .line 274
    cmp-long v4, v13, v15

    .line 275
    .line 276
    if-nez v4, :cond_a

    .line 277
    .line 278
    goto :goto_3

    .line 279
    :cond_a
    invoke-virtual {v0}, Le1/j;->d()V

    .line 280
    .line 281
    .line 282
    :goto_3
    invoke-static {v1, v2, v13, v14}, Lt4/q;->d(JJ)J

    .line 283
    .line 284
    .line 285
    move-result-wide v1

    .line 286
    new-instance v4, Lt4/q;

    .line 287
    .line 288
    invoke-direct {v4, v1, v2}, Lt4/q;-><init>(J)V

    .line 289
    .line 290
    .line 291
    iput-wide v1, v5, Le1/i;->d:J

    .line 292
    .line 293
    iput v9, v5, Le1/i;->g:I

    .line 294
    .line 295
    invoke-interface {v3, v4, v5}, Lay0/n;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 296
    .line 297
    .line 298
    move-result-object v4

    .line 299
    if-ne v4, v6, :cond_b

    .line 300
    .line 301
    :goto_4
    return-object v6

    .line 302
    :cond_b
    :goto_5
    check-cast v4, Lt4/q;

    .line 303
    .line 304
    iget-wide v3, v4, Lt4/q;->a:J

    .line 305
    .line 306
    invoke-static {v1, v2, v3, v4}, Lt4/q;->d(JJ)J

    .line 307
    .line 308
    .line 309
    move-result-wide v1

    .line 310
    const/4 v3, 0x0

    .line 311
    iput-boolean v3, v0, Le1/j;->f:Z

    .line 312
    .line 313
    invoke-static {v1, v2}, Lt4/q;->b(J)F

    .line 314
    .line 315
    .line 316
    move-result v3

    .line 317
    cmpl-float v3, v3, v11

    .line 318
    .line 319
    const/16 v4, 0x1f

    .line 320
    .line 321
    if-lez v3, :cond_d

    .line 322
    .line 323
    invoke-virtual {v12}, Le1/f0;->c()Landroid/widget/EdgeEffect;

    .line 324
    .line 325
    .line 326
    move-result-object v3

    .line 327
    invoke-static {v1, v2}, Lt4/q;->b(J)F

    .line 328
    .line 329
    .line 330
    move-result v5

    .line 331
    invoke-static {v5}, Lcy0/a;->i(F)I

    .line 332
    .line 333
    .line 334
    move-result v5

    .line 335
    sget v6, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 336
    .line 337
    if-lt v6, v4, :cond_c

    .line 338
    .line 339
    invoke-virtual {v3, v5}, Landroid/widget/EdgeEffect;->onAbsorb(I)V

    .line 340
    .line 341
    .line 342
    goto :goto_6

    .line 343
    :cond_c
    invoke-virtual {v3}, Landroid/widget/EdgeEffect;->isFinished()Z

    .line 344
    .line 345
    .line 346
    move-result v6

    .line 347
    if-eqz v6, :cond_f

    .line 348
    .line 349
    invoke-virtual {v3, v5}, Landroid/widget/EdgeEffect;->onAbsorb(I)V

    .line 350
    .line 351
    .line 352
    goto :goto_6

    .line 353
    :cond_d
    invoke-static {v1, v2}, Lt4/q;->b(J)F

    .line 354
    .line 355
    .line 356
    move-result v3

    .line 357
    cmpg-float v3, v3, v11

    .line 358
    .line 359
    if-gez v3, :cond_f

    .line 360
    .line 361
    invoke-virtual {v12}, Le1/f0;->d()Landroid/widget/EdgeEffect;

    .line 362
    .line 363
    .line 364
    move-result-object v3

    .line 365
    invoke-static {v1, v2}, Lt4/q;->b(J)F

    .line 366
    .line 367
    .line 368
    move-result v5

    .line 369
    invoke-static {v5}, Lcy0/a;->i(F)I

    .line 370
    .line 371
    .line 372
    move-result v5

    .line 373
    neg-int v5, v5

    .line 374
    sget v6, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 375
    .line 376
    if-lt v6, v4, :cond_e

    .line 377
    .line 378
    invoke-virtual {v3, v5}, Landroid/widget/EdgeEffect;->onAbsorb(I)V

    .line 379
    .line 380
    .line 381
    goto :goto_6

    .line 382
    :cond_e
    invoke-virtual {v3}, Landroid/widget/EdgeEffect;->isFinished()Z

    .line 383
    .line 384
    .line 385
    move-result v6

    .line 386
    if-eqz v6, :cond_f

    .line 387
    .line 388
    invoke-virtual {v3, v5}, Landroid/widget/EdgeEffect;->onAbsorb(I)V

    .line 389
    .line 390
    .line 391
    :cond_f
    :goto_6
    invoke-static {v1, v2}, Lt4/q;->c(J)F

    .line 392
    .line 393
    .line 394
    move-result v3

    .line 395
    cmpl-float v3, v3, v11

    .line 396
    .line 397
    if-lez v3, :cond_11

    .line 398
    .line 399
    invoke-virtual {v12}, Le1/f0;->e()Landroid/widget/EdgeEffect;

    .line 400
    .line 401
    .line 402
    move-result-object v3

    .line 403
    invoke-static {v1, v2}, Lt4/q;->c(J)F

    .line 404
    .line 405
    .line 406
    move-result v1

    .line 407
    invoke-static {v1}, Lcy0/a;->i(F)I

    .line 408
    .line 409
    .line 410
    move-result v1

    .line 411
    sget v2, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 412
    .line 413
    if-lt v2, v4, :cond_10

    .line 414
    .line 415
    invoke-virtual {v3, v1}, Landroid/widget/EdgeEffect;->onAbsorb(I)V

    .line 416
    .line 417
    .line 418
    goto :goto_7

    .line 419
    :cond_10
    invoke-virtual {v3}, Landroid/widget/EdgeEffect;->isFinished()Z

    .line 420
    .line 421
    .line 422
    move-result v2

    .line 423
    if-eqz v2, :cond_13

    .line 424
    .line 425
    invoke-virtual {v3, v1}, Landroid/widget/EdgeEffect;->onAbsorb(I)V

    .line 426
    .line 427
    .line 428
    goto :goto_7

    .line 429
    :cond_11
    invoke-static {v1, v2}, Lt4/q;->c(J)F

    .line 430
    .line 431
    .line 432
    move-result v3

    .line 433
    cmpg-float v3, v3, v11

    .line 434
    .line 435
    if-gez v3, :cond_13

    .line 436
    .line 437
    invoke-virtual {v12}, Le1/f0;->b()Landroid/widget/EdgeEffect;

    .line 438
    .line 439
    .line 440
    move-result-object v3

    .line 441
    invoke-static {v1, v2}, Lt4/q;->c(J)F

    .line 442
    .line 443
    .line 444
    move-result v1

    .line 445
    invoke-static {v1}, Lcy0/a;->i(F)I

    .line 446
    .line 447
    .line 448
    move-result v1

    .line 449
    neg-int v1, v1

    .line 450
    sget v2, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 451
    .line 452
    if-lt v2, v4, :cond_12

    .line 453
    .line 454
    invoke-virtual {v3, v1}, Landroid/widget/EdgeEffect;->onAbsorb(I)V

    .line 455
    .line 456
    .line 457
    goto :goto_7

    .line 458
    :cond_12
    invoke-virtual {v3}, Landroid/widget/EdgeEffect;->isFinished()Z

    .line 459
    .line 460
    .line 461
    move-result v2

    .line 462
    if-eqz v2, :cond_13

    .line 463
    .line 464
    invoke-virtual {v3, v1}, Landroid/widget/EdgeEffect;->onAbsorb(I)V

    .line 465
    .line 466
    .line 467
    :cond_13
    :goto_7
    invoke-virtual {v0}, Le1/j;->a()V

    .line 468
    .line 469
    .line 470
    return-object v8
.end method

.method public final c()J
    .locals 8

    .line 1
    iget-wide v0, p0, Le1/j;->b:J

    .line 2
    .line 3
    const-wide v2, 0x7fffffff7fffffffL

    .line 4
    .line 5
    .line 6
    .line 7
    .line 8
    and-long/2addr v2, v0

    .line 9
    const-wide v4, 0x7fc000007fc00000L    # 2.247117487993712E307

    .line 10
    .line 11
    .line 12
    .line 13
    .line 14
    cmp-long v2, v2, v4

    .line 15
    .line 16
    if-eqz v2, :cond_0

    .line 17
    .line 18
    goto :goto_0

    .line 19
    :cond_0
    iget-wide v0, p0, Le1/j;->g:J

    .line 20
    .line 21
    invoke-static {v0, v1}, Ljp/ef;->d(J)J

    .line 22
    .line 23
    .line 24
    move-result-wide v0

    .line 25
    :goto_0
    const/16 v2, 0x20

    .line 26
    .line 27
    shr-long v3, v0, v2

    .line 28
    .line 29
    long-to-int v3, v3

    .line 30
    invoke-static {v3}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 31
    .line 32
    .line 33
    move-result v3

    .line 34
    iget-wide v4, p0, Le1/j;->g:J

    .line 35
    .line 36
    shr-long/2addr v4, v2

    .line 37
    long-to-int v4, v4

    .line 38
    invoke-static {v4}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 39
    .line 40
    .line 41
    move-result v4

    .line 42
    div-float/2addr v3, v4

    .line 43
    const-wide v4, 0xffffffffL

    .line 44
    .line 45
    .line 46
    .line 47
    .line 48
    and-long/2addr v0, v4

    .line 49
    long-to-int v0, v0

    .line 50
    invoke-static {v0}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 51
    .line 52
    .line 53
    move-result v0

    .line 54
    iget-wide v6, p0, Le1/j;->g:J

    .line 55
    .line 56
    and-long/2addr v6, v4

    .line 57
    long-to-int p0, v6

    .line 58
    invoke-static {p0}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 59
    .line 60
    .line 61
    move-result p0

    .line 62
    div-float/2addr v0, p0

    .line 63
    invoke-static {v3}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 64
    .line 65
    .line 66
    move-result p0

    .line 67
    int-to-long v6, p0

    .line 68
    invoke-static {v0}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 69
    .line 70
    .line 71
    move-result p0

    .line 72
    int-to-long v0, p0

    .line 73
    shl-long v2, v6, v2

    .line 74
    .line 75
    and-long/2addr v0, v4

    .line 76
    or-long/2addr v0, v2

    .line 77
    return-wide v0
.end method

.method public final d()V
    .locals 1

    .line 1
    iget-boolean v0, p0, Le1/j;->e:Z

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    iget-object p0, p0, Le1/j;->d:Ll2/j1;

    .line 6
    .line 7
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 8
    .line 9
    invoke-virtual {p0, v0}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 10
    .line 11
    .line 12
    :cond_0
    return-void
.end method

.method public final e(J)F
    .locals 8

    .line 1
    invoke-virtual {p0}, Le1/j;->c()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    const/16 v2, 0x20

    .line 6
    .line 7
    shr-long/2addr v0, v2

    .line 8
    long-to-int v0, v0

    .line 9
    invoke-static {v0}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 10
    .line 11
    .line 12
    move-result v0

    .line 13
    const-wide v1, 0xffffffffL

    .line 14
    .line 15
    .line 16
    .line 17
    .line 18
    and-long/2addr p1, v1

    .line 19
    long-to-int p1, p1

    .line 20
    invoke-static {p1}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 21
    .line 22
    .line 23
    move-result p2

    .line 24
    iget-wide v3, p0, Le1/j;->g:J

    .line 25
    .line 26
    and-long/2addr v3, v1

    .line 27
    long-to-int v3, v3

    .line 28
    invoke-static {v3}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 29
    .line 30
    .line 31
    move-result v3

    .line 32
    div-float/2addr p2, v3

    .line 33
    iget-object v3, p0, Le1/j;->c:Le1/f0;

    .line 34
    .line 35
    invoke-virtual {v3}, Le1/f0;->b()Landroid/widget/EdgeEffect;

    .line 36
    .line 37
    .line 38
    move-result-object v3

    .line 39
    neg-float p2, p2

    .line 40
    const/4 v4, 0x1

    .line 41
    int-to-float v4, v4

    .line 42
    sub-float/2addr v4, v0

    .line 43
    sget v0, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 44
    .line 45
    const/16 v5, 0x1f

    .line 46
    .line 47
    if-lt v0, v5, :cond_0

    .line 48
    .line 49
    invoke-static {v3, p2, v4}, Le1/m;->e(Landroid/widget/EdgeEffect;FF)F

    .line 50
    .line 51
    .line 52
    move-result p2

    .line 53
    goto :goto_0

    .line 54
    :cond_0
    invoke-virtual {v3, p2, v4}, Landroid/widget/EdgeEffect;->onPull(FF)V

    .line 55
    .line 56
    .line 57
    :goto_0
    neg-float p2, p2

    .line 58
    iget-wide v6, p0, Le1/j;->g:J

    .line 59
    .line 60
    and-long/2addr v1, v6

    .line 61
    long-to-int p0, v1

    .line 62
    invoke-static {p0}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 63
    .line 64
    .line 65
    move-result p0

    .line 66
    mul-float/2addr p0, p2

    .line 67
    const/4 p2, 0x0

    .line 68
    if-lt v0, v5, :cond_1

    .line 69
    .line 70
    invoke-static {v3}, Le1/m;->b(Landroid/widget/EdgeEffect;)F

    .line 71
    .line 72
    .line 73
    move-result v0

    .line 74
    goto :goto_1

    .line 75
    :cond_1
    move v0, p2

    .line 76
    :goto_1
    cmpg-float p2, v0, p2

    .line 77
    .line 78
    if-nez p2, :cond_2

    .line 79
    .line 80
    return p0

    .line 81
    :cond_2
    invoke-static {p1}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 82
    .line 83
    .line 84
    move-result p0

    .line 85
    return p0
.end method

.method public final f(J)F
    .locals 7

    .line 1
    invoke-virtual {p0}, Le1/j;->c()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    const-wide v2, 0xffffffffL

    .line 6
    .line 7
    .line 8
    .line 9
    .line 10
    and-long/2addr v0, v2

    .line 11
    long-to-int v0, v0

    .line 12
    invoke-static {v0}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    const/16 v1, 0x20

    .line 17
    .line 18
    shr-long/2addr p1, v1

    .line 19
    long-to-int p1, p1

    .line 20
    invoke-static {p1}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 21
    .line 22
    .line 23
    move-result p2

    .line 24
    iget-wide v2, p0, Le1/j;->g:J

    .line 25
    .line 26
    shr-long/2addr v2, v1

    .line 27
    long-to-int v2, v2

    .line 28
    invoke-static {v2}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 29
    .line 30
    .line 31
    move-result v2

    .line 32
    div-float/2addr p2, v2

    .line 33
    iget-object v2, p0, Le1/j;->c:Le1/f0;

    .line 34
    .line 35
    invoke-virtual {v2}, Le1/f0;->c()Landroid/widget/EdgeEffect;

    .line 36
    .line 37
    .line 38
    move-result-object v2

    .line 39
    const/4 v3, 0x1

    .line 40
    int-to-float v3, v3

    .line 41
    sub-float/2addr v3, v0

    .line 42
    sget v0, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 43
    .line 44
    const/16 v4, 0x1f

    .line 45
    .line 46
    if-lt v0, v4, :cond_0

    .line 47
    .line 48
    invoke-static {v2, p2, v3}, Le1/m;->e(Landroid/widget/EdgeEffect;FF)F

    .line 49
    .line 50
    .line 51
    move-result p2

    .line 52
    goto :goto_0

    .line 53
    :cond_0
    invoke-virtual {v2, p2, v3}, Landroid/widget/EdgeEffect;->onPull(FF)V

    .line 54
    .line 55
    .line 56
    :goto_0
    iget-wide v5, p0, Le1/j;->g:J

    .line 57
    .line 58
    shr-long/2addr v5, v1

    .line 59
    long-to-int p0, v5

    .line 60
    invoke-static {p0}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 61
    .line 62
    .line 63
    move-result p0

    .line 64
    mul-float/2addr p0, p2

    .line 65
    const/4 p2, 0x0

    .line 66
    if-lt v0, v4, :cond_1

    .line 67
    .line 68
    invoke-static {v2}, Le1/m;->b(Landroid/widget/EdgeEffect;)F

    .line 69
    .line 70
    .line 71
    move-result v0

    .line 72
    goto :goto_1

    .line 73
    :cond_1
    move v0, p2

    .line 74
    :goto_1
    cmpg-float p2, v0, p2

    .line 75
    .line 76
    if-nez p2, :cond_2

    .line 77
    .line 78
    return p0

    .line 79
    :cond_2
    invoke-static {p1}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 80
    .line 81
    .line 82
    move-result p0

    .line 83
    return p0
.end method

.method public final g(J)F
    .locals 7

    .line 1
    invoke-virtual {p0}, Le1/j;->c()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    const-wide v2, 0xffffffffL

    .line 6
    .line 7
    .line 8
    .line 9
    .line 10
    and-long/2addr v0, v2

    .line 11
    long-to-int v0, v0

    .line 12
    invoke-static {v0}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    const/16 v1, 0x20

    .line 17
    .line 18
    shr-long/2addr p1, v1

    .line 19
    long-to-int p1, p1

    .line 20
    invoke-static {p1}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 21
    .line 22
    .line 23
    move-result p2

    .line 24
    iget-wide v2, p0, Le1/j;->g:J

    .line 25
    .line 26
    shr-long/2addr v2, v1

    .line 27
    long-to-int v2, v2

    .line 28
    invoke-static {v2}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 29
    .line 30
    .line 31
    move-result v2

    .line 32
    div-float/2addr p2, v2

    .line 33
    iget-object v2, p0, Le1/j;->c:Le1/f0;

    .line 34
    .line 35
    invoke-virtual {v2}, Le1/f0;->d()Landroid/widget/EdgeEffect;

    .line 36
    .line 37
    .line 38
    move-result-object v2

    .line 39
    neg-float p2, p2

    .line 40
    sget v3, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 41
    .line 42
    const/16 v4, 0x1f

    .line 43
    .line 44
    if-lt v3, v4, :cond_0

    .line 45
    .line 46
    invoke-static {v2, p2, v0}, Le1/m;->e(Landroid/widget/EdgeEffect;FF)F

    .line 47
    .line 48
    .line 49
    move-result p2

    .line 50
    goto :goto_0

    .line 51
    :cond_0
    invoke-virtual {v2, p2, v0}, Landroid/widget/EdgeEffect;->onPull(FF)V

    .line 52
    .line 53
    .line 54
    :goto_0
    neg-float p2, p2

    .line 55
    iget-wide v5, p0, Le1/j;->g:J

    .line 56
    .line 57
    shr-long v0, v5, v1

    .line 58
    .line 59
    long-to-int p0, v0

    .line 60
    invoke-static {p0}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 61
    .line 62
    .line 63
    move-result p0

    .line 64
    mul-float/2addr p0, p2

    .line 65
    const/4 p2, 0x0

    .line 66
    if-lt v3, v4, :cond_1

    .line 67
    .line 68
    invoke-static {v2}, Le1/m;->b(Landroid/widget/EdgeEffect;)F

    .line 69
    .line 70
    .line 71
    move-result v0

    .line 72
    goto :goto_1

    .line 73
    :cond_1
    move v0, p2

    .line 74
    :goto_1
    cmpg-float p2, v0, p2

    .line 75
    .line 76
    if-nez p2, :cond_2

    .line 77
    .line 78
    return p0

    .line 79
    :cond_2
    invoke-static {p1}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 80
    .line 81
    .line 82
    move-result p0

    .line 83
    return p0
.end method

.method public final h(J)F
    .locals 8

    .line 1
    invoke-virtual {p0}, Le1/j;->c()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    const/16 v2, 0x20

    .line 6
    .line 7
    shr-long/2addr v0, v2

    .line 8
    long-to-int v0, v0

    .line 9
    invoke-static {v0}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 10
    .line 11
    .line 12
    move-result v0

    .line 13
    const-wide v1, 0xffffffffL

    .line 14
    .line 15
    .line 16
    .line 17
    .line 18
    and-long/2addr p1, v1

    .line 19
    long-to-int p1, p1

    .line 20
    invoke-static {p1}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 21
    .line 22
    .line 23
    move-result p2

    .line 24
    iget-wide v3, p0, Le1/j;->g:J

    .line 25
    .line 26
    and-long/2addr v3, v1

    .line 27
    long-to-int v3, v3

    .line 28
    invoke-static {v3}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 29
    .line 30
    .line 31
    move-result v3

    .line 32
    div-float/2addr p2, v3

    .line 33
    iget-object v3, p0, Le1/j;->c:Le1/f0;

    .line 34
    .line 35
    invoke-virtual {v3}, Le1/f0;->e()Landroid/widget/EdgeEffect;

    .line 36
    .line 37
    .line 38
    move-result-object v3

    .line 39
    sget v4, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 40
    .line 41
    const/16 v5, 0x1f

    .line 42
    .line 43
    if-lt v4, v5, :cond_0

    .line 44
    .line 45
    invoke-static {v3, p2, v0}, Le1/m;->e(Landroid/widget/EdgeEffect;FF)F

    .line 46
    .line 47
    .line 48
    move-result p2

    .line 49
    goto :goto_0

    .line 50
    :cond_0
    invoke-virtual {v3, p2, v0}, Landroid/widget/EdgeEffect;->onPull(FF)V

    .line 51
    .line 52
    .line 53
    :goto_0
    iget-wide v6, p0, Le1/j;->g:J

    .line 54
    .line 55
    and-long v0, v6, v1

    .line 56
    .line 57
    long-to-int p0, v0

    .line 58
    invoke-static {p0}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 59
    .line 60
    .line 61
    move-result p0

    .line 62
    mul-float/2addr p0, p2

    .line 63
    const/4 p2, 0x0

    .line 64
    if-lt v4, v5, :cond_1

    .line 65
    .line 66
    invoke-static {v3}, Le1/m;->b(Landroid/widget/EdgeEffect;)F

    .line 67
    .line 68
    .line 69
    move-result v0

    .line 70
    goto :goto_1

    .line 71
    :cond_1
    move v0, p2

    .line 72
    :goto_1
    cmpg-float p2, v0, p2

    .line 73
    .line 74
    if-nez p2, :cond_2

    .line 75
    .line 76
    return p0

    .line 77
    :cond_2
    invoke-static {p1}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 78
    .line 79
    .line 80
    move-result p0

    .line 81
    return p0
.end method

.method public final i(J)V
    .locals 10

    .line 1
    iget-wide v0, p0, Le1/j;->g:J

    .line 2
    .line 3
    const-wide/16 v2, 0x0

    .line 4
    .line 5
    invoke-static {v0, v1, v2, v3}, Ld3/e;->a(JJ)Z

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    iget-wide v1, p0, Le1/j;->g:J

    .line 10
    .line 11
    invoke-static {p1, p2, v1, v2}, Ld3/e;->a(JJ)Z

    .line 12
    .line 13
    .line 14
    move-result v1

    .line 15
    iput-wide p1, p0, Le1/j;->g:J

    .line 16
    .line 17
    if-nez v1, :cond_7

    .line 18
    .line 19
    const/16 v2, 0x20

    .line 20
    .line 21
    shr-long v3, p1, v2

    .line 22
    .line 23
    long-to-int v3, v3

    .line 24
    invoke-static {v3}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 25
    .line 26
    .line 27
    move-result v3

    .line 28
    invoke-static {v3}, Lcy0/a;->i(F)I

    .line 29
    .line 30
    .line 31
    move-result v3

    .line 32
    const-wide v4, 0xffffffffL

    .line 33
    .line 34
    .line 35
    .line 36
    .line 37
    and-long/2addr p1, v4

    .line 38
    long-to-int p1, p1

    .line 39
    invoke-static {p1}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 40
    .line 41
    .line 42
    move-result p1

    .line 43
    invoke-static {p1}, Lcy0/a;->i(F)I

    .line 44
    .line 45
    .line 46
    move-result p1

    .line 47
    int-to-long v6, v3

    .line 48
    shl-long/2addr v6, v2

    .line 49
    int-to-long p1, p1

    .line 50
    and-long/2addr p1, v4

    .line 51
    or-long/2addr p1, v6

    .line 52
    iget-object v3, p0, Le1/j;->c:Le1/f0;

    .line 53
    .line 54
    iput-wide p1, v3, Le1/f0;->c:J

    .line 55
    .line 56
    iget-object v6, v3, Le1/f0;->d:Landroid/widget/EdgeEffect;

    .line 57
    .line 58
    if-eqz v6, :cond_0

    .line 59
    .line 60
    shr-long v7, p1, v2

    .line 61
    .line 62
    long-to-int v7, v7

    .line 63
    and-long v8, p1, v4

    .line 64
    .line 65
    long-to-int v8, v8

    .line 66
    invoke-virtual {v6, v7, v8}, Landroid/widget/EdgeEffect;->setSize(II)V

    .line 67
    .line 68
    .line 69
    :cond_0
    iget-object v6, v3, Le1/f0;->e:Landroid/widget/EdgeEffect;

    .line 70
    .line 71
    if-eqz v6, :cond_1

    .line 72
    .line 73
    shr-long v7, p1, v2

    .line 74
    .line 75
    long-to-int v7, v7

    .line 76
    and-long v8, p1, v4

    .line 77
    .line 78
    long-to-int v8, v8

    .line 79
    invoke-virtual {v6, v7, v8}, Landroid/widget/EdgeEffect;->setSize(II)V

    .line 80
    .line 81
    .line 82
    :cond_1
    iget-object v6, v3, Le1/f0;->f:Landroid/widget/EdgeEffect;

    .line 83
    .line 84
    if-eqz v6, :cond_2

    .line 85
    .line 86
    and-long v7, p1, v4

    .line 87
    .line 88
    long-to-int v7, v7

    .line 89
    shr-long v8, p1, v2

    .line 90
    .line 91
    long-to-int v8, v8

    .line 92
    invoke-virtual {v6, v7, v8}, Landroid/widget/EdgeEffect;->setSize(II)V

    .line 93
    .line 94
    .line 95
    :cond_2
    iget-object v6, v3, Le1/f0;->g:Landroid/widget/EdgeEffect;

    .line 96
    .line 97
    if-eqz v6, :cond_3

    .line 98
    .line 99
    and-long v7, p1, v4

    .line 100
    .line 101
    long-to-int v7, v7

    .line 102
    shr-long v8, p1, v2

    .line 103
    .line 104
    long-to-int v8, v8

    .line 105
    invoke-virtual {v6, v7, v8}, Landroid/widget/EdgeEffect;->setSize(II)V

    .line 106
    .line 107
    .line 108
    :cond_3
    iget-object v6, v3, Le1/f0;->h:Landroid/widget/EdgeEffect;

    .line 109
    .line 110
    if-eqz v6, :cond_4

    .line 111
    .line 112
    shr-long v7, p1, v2

    .line 113
    .line 114
    long-to-int v7, v7

    .line 115
    and-long v8, p1, v4

    .line 116
    .line 117
    long-to-int v8, v8

    .line 118
    invoke-virtual {v6, v7, v8}, Landroid/widget/EdgeEffect;->setSize(II)V

    .line 119
    .line 120
    .line 121
    :cond_4
    iget-object v6, v3, Le1/f0;->i:Landroid/widget/EdgeEffect;

    .line 122
    .line 123
    if-eqz v6, :cond_5

    .line 124
    .line 125
    shr-long v7, p1, v2

    .line 126
    .line 127
    long-to-int v7, v7

    .line 128
    and-long v8, p1, v4

    .line 129
    .line 130
    long-to-int v8, v8

    .line 131
    invoke-virtual {v6, v7, v8}, Landroid/widget/EdgeEffect;->setSize(II)V

    .line 132
    .line 133
    .line 134
    :cond_5
    iget-object v6, v3, Le1/f0;->j:Landroid/widget/EdgeEffect;

    .line 135
    .line 136
    if-eqz v6, :cond_6

    .line 137
    .line 138
    and-long v7, p1, v4

    .line 139
    .line 140
    long-to-int v7, v7

    .line 141
    shr-long v8, p1, v2

    .line 142
    .line 143
    long-to-int v8, v8

    .line 144
    invoke-virtual {v6, v7, v8}, Landroid/widget/EdgeEffect;->setSize(II)V

    .line 145
    .line 146
    .line 147
    :cond_6
    iget-object v3, v3, Le1/f0;->k:Landroid/widget/EdgeEffect;

    .line 148
    .line 149
    if-eqz v3, :cond_7

    .line 150
    .line 151
    and-long/2addr v4, p1

    .line 152
    long-to-int v4, v4

    .line 153
    shr-long/2addr p1, v2

    .line 154
    long-to-int p1, p1

    .line 155
    invoke-virtual {v3, v4, p1}, Landroid/widget/EdgeEffect;->setSize(II)V

    .line 156
    .line 157
    .line 158
    :cond_7
    if-nez v0, :cond_8

    .line 159
    .line 160
    if-nez v1, :cond_8

    .line 161
    .line 162
    invoke-virtual {p0}, Le1/j;->a()V

    .line 163
    .line 164
    .line 165
    :cond_8
    return-void
.end method
