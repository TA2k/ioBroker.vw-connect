.class public final Lx21/g0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Lm1/t;

.field public final b:Lvy0/b0;

.field public final c:La4/b;

.field public d:Lvy0/x1;

.field public final e:Lxy0/j;


# direct methods
.method public constructor <init>(Lm1/t;Lvy0/b0;La4/b;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lx21/g0;->a:Lm1/t;

    .line 5
    .line 6
    iput-object p2, p0, Lx21/g0;->b:Lvy0/b0;

    .line 7
    .line 8
    iput-object p3, p0, Lx21/g0;->c:La4/b;

    .line 9
    .line 10
    const/4 p1, 0x0

    .line 11
    const/4 p2, 0x6

    .line 12
    const/4 p3, -0x1

    .line 13
    invoke-static {p3, p2, p1}, Llp/jf;->a(IILxy0/a;)Lxy0/j;

    .line 14
    .line 15
    .line 16
    move-result-object p1

    .line 17
    iput-object p1, p0, Lx21/g0;->e:Lxy0/j;

    .line 18
    .line 19
    return-void
.end method

.method public static final a(Lx21/g0;Lrx0/c;)Ljava/lang/Object;
    .locals 18

    .line 1
    move-object/from16 v0, p1

    .line 2
    .line 3
    invoke-virtual/range {p0 .. p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 4
    .line 5
    .line 6
    instance-of v1, v0, Lx21/d0;

    .line 7
    .line 8
    if-eqz v1, :cond_0

    .line 9
    .line 10
    move-object v1, v0

    .line 11
    check-cast v1, Lx21/d0;

    .line 12
    .line 13
    iget v2, v1, Lx21/d0;->k:I

    .line 14
    .line 15
    const/high16 v3, -0x80000000

    .line 16
    .line 17
    and-int v4, v2, v3

    .line 18
    .line 19
    if-eqz v4, :cond_0

    .line 20
    .line 21
    sub-int/2addr v2, v3

    .line 22
    iput v2, v1, Lx21/d0;->k:I

    .line 23
    .line 24
    move-object/from16 v2, p0

    .line 25
    .line 26
    goto :goto_0

    .line 27
    :cond_0
    new-instance v1, Lx21/d0;

    .line 28
    .line 29
    move-object/from16 v2, p0

    .line 30
    .line 31
    invoke-direct {v1, v2, v0}, Lx21/d0;-><init>(Lx21/g0;Lrx0/c;)V

    .line 32
    .line 33
    .line 34
    :goto_0
    iget-object v0, v1, Lx21/d0;->i:Ljava/lang/Object;

    .line 35
    .line 36
    sget-object v3, Lqx0/a;->d:Lqx0/a;

    .line 37
    .line 38
    iget v4, v1, Lx21/d0;->k:I

    .line 39
    .line 40
    const/4 v5, 0x3

    .line 41
    const/4 v6, 0x2

    .line 42
    const/4 v7, 0x1

    .line 43
    const/4 v8, 0x0

    .line 44
    if-eqz v4, :cond_4

    .line 45
    .line 46
    if-eq v4, v7, :cond_3

    .line 47
    .line 48
    if-eq v4, v6, :cond_2

    .line 49
    .line 50
    if-ne v4, v5, :cond_1

    .line 51
    .line 52
    goto :goto_1

    .line 53
    :cond_1
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 54
    .line 55
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 56
    .line 57
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 58
    .line 59
    .line 60
    throw v0

    .line 61
    :cond_2
    :goto_1
    iget-object v2, v1, Lx21/d0;->e:Lx21/c0;

    .line 62
    .line 63
    iget-object v4, v1, Lx21/d0;->d:Lx21/g0;

    .line 64
    .line 65
    invoke-static {v0}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 66
    .line 67
    .line 68
    move-object v0, v2

    .line 69
    move-object v2, v4

    .line 70
    goto :goto_2

    .line 71
    :cond_3
    iget v2, v1, Lx21/d0;->h:F

    .line 72
    .line 73
    iget-object v4, v1, Lx21/d0;->g:Lkotlin/jvm/internal/n;

    .line 74
    .line 75
    check-cast v4, Lay0/a;

    .line 76
    .line 77
    iget-object v9, v1, Lx21/d0;->f:Lx21/b0;

    .line 78
    .line 79
    iget-object v10, v1, Lx21/d0;->e:Lx21/c0;

    .line 80
    .line 81
    iget-object v11, v1, Lx21/d0;->d:Lx21/g0;

    .line 82
    .line 83
    invoke-static {v0}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 84
    .line 85
    .line 86
    move-object v0, v10

    .line 87
    goto :goto_4

    .line 88
    :cond_4
    invoke-static {v0}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 89
    .line 90
    .line 91
    move-object v0, v8

    .line 92
    :goto_2
    iget-object v4, v2, Lx21/g0;->e:Lxy0/j;

    .line 93
    .line 94
    invoke-virtual {v4}, Lxy0/j;->n()Ljava/lang/Object;

    .line 95
    .line 96
    .line 97
    move-result-object v4

    .line 98
    invoke-static {v4}, Lxy0/q;->b(Ljava/lang/Object;)Ljava/lang/Object;

    .line 99
    .line 100
    .line 101
    move-result-object v4

    .line 102
    check-cast v4, Lx21/c0;

    .line 103
    .line 104
    if-nez v4, :cond_5

    .line 105
    .line 106
    goto :goto_3

    .line 107
    :cond_5
    move-object v0, v4

    .line 108
    :goto_3
    if-eqz v0, :cond_e

    .line 109
    .line 110
    sget-object v4, Lx21/c0;->e:Lx21/c0;

    .line 111
    .line 112
    invoke-virtual {v0, v4}, Lx21/c0;->equals(Ljava/lang/Object;)Z

    .line 113
    .line 114
    .line 115
    move-result v4

    .line 116
    if-eqz v4, :cond_6

    .line 117
    .line 118
    goto/16 :goto_8

    .line 119
    .line 120
    :cond_6
    iget-object v9, v0, Lx21/c0;->a:Lx21/b0;

    .line 121
    .line 122
    iget v4, v0, Lx21/c0;->b:F

    .line 123
    .line 124
    iget-object v10, v0, Lx21/c0;->c:Lkotlin/jvm/internal/n;

    .line 125
    .line 126
    iget-object v11, v0, Lx21/c0;->d:Lrx0/i;

    .line 127
    .line 128
    iget-object v12, v2, Lx21/g0;->c:La4/b;

    .line 129
    .line 130
    invoke-virtual {v12}, La4/b;->invoke()Ljava/lang/Object;

    .line 131
    .line 132
    .line 133
    move-result-object v12

    .line 134
    check-cast v12, Ljava/lang/Number;

    .line 135
    .line 136
    invoke-virtual {v12}, Ljava/lang/Number;->floatValue()F

    .line 137
    .line 138
    .line 139
    move-result v12

    .line 140
    mul-float/2addr v12, v4

    .line 141
    const/high16 v4, 0x447a0000    # 1000.0f

    .line 142
    .line 143
    div-float v4, v12, v4

    .line 144
    .line 145
    iput-object v2, v1, Lx21/d0;->d:Lx21/g0;

    .line 146
    .line 147
    iput-object v0, v1, Lx21/d0;->e:Lx21/c0;

    .line 148
    .line 149
    iput-object v9, v1, Lx21/d0;->f:Lx21/b0;

    .line 150
    .line 151
    iput-object v10, v1, Lx21/d0;->g:Lkotlin/jvm/internal/n;

    .line 152
    .line 153
    iput v4, v1, Lx21/d0;->h:F

    .line 154
    .line 155
    iput v7, v1, Lx21/d0;->k:I

    .line 156
    .line 157
    invoke-interface {v11, v1}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 158
    .line 159
    .line 160
    move-result-object v11

    .line 161
    if-ne v11, v3, :cond_7

    .line 162
    .line 163
    goto/16 :goto_7

    .line 164
    .line 165
    :cond_7
    move-object v11, v2

    .line 166
    move v2, v4

    .line 167
    move-object v4, v10

    .line 168
    :goto_4
    iget-object v10, v11, Lx21/g0;->a:Lm1/t;

    .line 169
    .line 170
    invoke-virtual {v9}, Ljava/lang/Enum;->ordinal()I

    .line 171
    .line 172
    .line 173
    move-result v12

    .line 174
    if-eqz v12, :cond_9

    .line 175
    .line 176
    if-ne v12, v7, :cond_8

    .line 177
    .line 178
    invoke-virtual {v10}, Lm1/t;->d()Z

    .line 179
    .line 180
    .line 181
    move-result v10

    .line 182
    goto :goto_5

    .line 183
    :cond_8
    new-instance v0, La8/r0;

    .line 184
    .line 185
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 186
    .line 187
    .line 188
    throw v0

    .line 189
    :cond_9
    invoke-virtual {v10}, Lm1/t;->b()Z

    .line 190
    .line 191
    .line 192
    move-result v10

    .line 193
    :goto_5
    if-eqz v10, :cond_e

    .line 194
    .line 195
    invoke-interface {v4}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 196
    .line 197
    .line 198
    move-result-object v4

    .line 199
    check-cast v4, Ljava/lang/Number;

    .line 200
    .line 201
    invoke-virtual {v4}, Ljava/lang/Number;->floatValue()F

    .line 202
    .line 203
    .line 204
    move-result v4

    .line 205
    const/4 v10, 0x0

    .line 206
    cmpg-float v10, v4, v10

    .line 207
    .line 208
    if-gtz v10, :cond_b

    .line 209
    .line 210
    iput-object v11, v1, Lx21/d0;->d:Lx21/g0;

    .line 211
    .line 212
    iput-object v0, v1, Lx21/d0;->e:Lx21/c0;

    .line 213
    .line 214
    iput-object v8, v1, Lx21/d0;->f:Lx21/b0;

    .line 215
    .line 216
    iput-object v8, v1, Lx21/d0;->g:Lkotlin/jvm/internal/n;

    .line 217
    .line 218
    iput v6, v1, Lx21/d0;->k:I

    .line 219
    .line 220
    const-wide/16 v9, 0x64

    .line 221
    .line 222
    invoke-static {v9, v10, v1}, Lvy0/e0;->p(JLkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 223
    .line 224
    .line 225
    move-result-object v2

    .line 226
    if-ne v2, v3, :cond_a

    .line 227
    .line 228
    goto :goto_7

    .line 229
    :cond_a
    move-object v2, v11

    .line 230
    goto/16 :goto_2

    .line 231
    .line 232
    :cond_b
    div-float v2, v4, v2

    .line 233
    .line 234
    float-to-long v12, v2

    .line 235
    const-wide/16 v14, 0x1

    .line 236
    .line 237
    const-wide/16 v16, 0x64

    .line 238
    .line 239
    invoke-static/range {v12 .. v17}, Lkp/r9;->g(JJJ)J

    .line 240
    .line 241
    .line 242
    move-result-wide v12

    .line 243
    long-to-float v10, v12

    .line 244
    div-float/2addr v10, v2

    .line 245
    mul-float/2addr v10, v4

    .line 246
    invoke-virtual {v9}, Ljava/lang/Enum;->ordinal()I

    .line 247
    .line 248
    .line 249
    move-result v2

    .line 250
    if-eqz v2, :cond_d

    .line 251
    .line 252
    if-ne v2, v7, :cond_c

    .line 253
    .line 254
    goto :goto_6

    .line 255
    :cond_c
    new-instance v0, La8/r0;

    .line 256
    .line 257
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 258
    .line 259
    .line 260
    throw v0

    .line 261
    :cond_d
    neg-float v10, v10

    .line 262
    :goto_6
    iget-object v2, v11, Lx21/g0;->a:Lm1/t;

    .line 263
    .line 264
    long-to-int v4, v12

    .line 265
    const/4 v9, 0x0

    .line 266
    sget-object v12, Lc1/z;->d:Lc1/y;

    .line 267
    .line 268
    invoke-static {v4, v9, v12, v6}, Lc1/d;->u(IILc1/w;I)Lc1/a2;

    .line 269
    .line 270
    .line 271
    move-result-object v4

    .line 272
    iput-object v11, v1, Lx21/d0;->d:Lx21/g0;

    .line 273
    .line 274
    iput-object v0, v1, Lx21/d0;->e:Lx21/c0;

    .line 275
    .line 276
    iput-object v8, v1, Lx21/d0;->f:Lx21/b0;

    .line 277
    .line 278
    iput-object v8, v1, Lx21/d0;->g:Lkotlin/jvm/internal/n;

    .line 279
    .line 280
    iput v5, v1, Lx21/d0;->k:I

    .line 281
    .line 282
    invoke-static {v2, v10, v4, v1}, Lg1/h3;->a(Lg1/q2;FLc1/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 283
    .line 284
    .line 285
    move-result-object v2

    .line 286
    if-ne v2, v3, :cond_a

    .line 287
    .line 288
    :goto_7
    return-object v3

    .line 289
    :cond_e
    :goto_8
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 290
    .line 291
    return-object v0
.end method


# virtual methods
.method public final b(Lx21/b0;FLay0/a;Lay0/k;)Z
    .locals 5

    .line 1
    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    const/4 v1, 0x1

    .line 6
    iget-object v2, p0, Lx21/g0;->a:Lm1/t;

    .line 7
    .line 8
    if-eqz v0, :cond_1

    .line 9
    .line 10
    if-ne v0, v1, :cond_0

    .line 11
    .line 12
    invoke-virtual {v2}, Lm1/t;->d()Z

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    goto :goto_0

    .line 17
    :cond_0
    new-instance p0, La8/r0;

    .line 18
    .line 19
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 20
    .line 21
    .line 22
    throw p0

    .line 23
    :cond_1
    invoke-virtual {v2}, Lm1/t;->b()Z

    .line 24
    .line 25
    .line 26
    move-result v0

    .line 27
    :goto_0
    if-nez v0, :cond_2

    .line 28
    .line 29
    const/4 p0, 0x0

    .line 30
    return p0

    .line 31
    :cond_2
    iget-object v0, p0, Lx21/g0;->d:Lvy0/x1;

    .line 32
    .line 33
    if-nez v0, :cond_3

    .line 34
    .line 35
    new-instance v0, Lx21/e0;

    .line 36
    .line 37
    const/4 v2, 0x0

    .line 38
    const/4 v3, 0x0

    .line 39
    invoke-direct {v0, p0, v3, v2}, Lx21/e0;-><init>(Lx21/g0;Lkotlin/coroutines/Continuation;I)V

    .line 40
    .line 41
    .line 42
    const/4 v2, 0x3

    .line 43
    iget-object v4, p0, Lx21/g0;->b:Lvy0/b0;

    .line 44
    .line 45
    invoke-static {v4, v3, v3, v0, v2}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 46
    .line 47
    .line 48
    move-result-object v0

    .line 49
    iput-object v0, p0, Lx21/g0;->d:Lvy0/x1;

    .line 50
    .line 51
    :cond_3
    new-instance v0, Lx21/c0;

    .line 52
    .line 53
    invoke-direct {v0, p1, p2, p3, p4}, Lx21/c0;-><init>(Lx21/b0;FLay0/a;Lay0/k;)V

    .line 54
    .line 55
    .line 56
    iget-object p0, p0, Lx21/g0;->e:Lxy0/j;

    .line 57
    .line 58
    invoke-interface {p0, v0}, Lxy0/a0;->e(Ljava/lang/Object;)Ljava/lang/Object;

    .line 59
    .line 60
    .line 61
    return v1
.end method

.method public final c(Lrx0/c;)Ljava/lang/Object;
    .locals 5

    .line 1
    instance-of v0, p1, Lx21/f0;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, Lx21/f0;

    .line 7
    .line 8
    iget v1, v0, Lx21/f0;->g:I

    .line 9
    .line 10
    const/high16 v2, -0x80000000

    .line 11
    .line 12
    and-int v3, v1, v2

    .line 13
    .line 14
    if-eqz v3, :cond_0

    .line 15
    .line 16
    sub-int/2addr v1, v2

    .line 17
    iput v1, v0, Lx21/f0;->g:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lx21/f0;

    .line 21
    .line 22
    invoke-direct {v0, p0, p1}, Lx21/f0;-><init>(Lx21/g0;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p1, v0, Lx21/f0;->e:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lx21/f0;->g:I

    .line 30
    .line 31
    const/4 v3, 0x2

    .line 32
    const/4 v4, 0x1

    .line 33
    if-eqz v2, :cond_3

    .line 34
    .line 35
    if-eq v2, v4, :cond_2

    .line 36
    .line 37
    if-ne v2, v3, :cond_1

    .line 38
    .line 39
    iget-object p0, v0, Lx21/f0;->d:Lx21/g0;

    .line 40
    .line 41
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 42
    .line 43
    .line 44
    goto :goto_3

    .line 45
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 46
    .line 47
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 48
    .line 49
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 50
    .line 51
    .line 52
    throw p0

    .line 53
    :cond_2
    iget-object p0, v0, Lx21/f0;->d:Lx21/g0;

    .line 54
    .line 55
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 56
    .line 57
    .line 58
    goto :goto_1

    .line 59
    :cond_3
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 60
    .line 61
    .line 62
    sget-object p1, Lx21/c0;->e:Lx21/c0;

    .line 63
    .line 64
    iput-object p0, v0, Lx21/f0;->d:Lx21/g0;

    .line 65
    .line 66
    iput v4, v0, Lx21/f0;->g:I

    .line 67
    .line 68
    iget-object v2, p0, Lx21/g0;->e:Lxy0/j;

    .line 69
    .line 70
    invoke-interface {v2, p1, v0}, Lxy0/a0;->u(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 71
    .line 72
    .line 73
    move-result-object p1

    .line 74
    if-ne p1, v1, :cond_4

    .line 75
    .line 76
    goto :goto_2

    .line 77
    :cond_4
    :goto_1
    iget-object p1, p0, Lx21/g0;->d:Lvy0/x1;

    .line 78
    .line 79
    if-eqz p1, :cond_5

    .line 80
    .line 81
    iput-object p0, v0, Lx21/f0;->d:Lx21/g0;

    .line 82
    .line 83
    iput v3, v0, Lx21/f0;->g:I

    .line 84
    .line 85
    invoke-static {p1, v0}, Lvy0/e0;->m(Lvy0/i1;Lrx0/c;)Ljava/lang/Object;

    .line 86
    .line 87
    .line 88
    move-result-object p1

    .line 89
    if-ne p1, v1, :cond_5

    .line 90
    .line 91
    :goto_2
    return-object v1

    .line 92
    :cond_5
    :goto_3
    const/4 p1, 0x0

    .line 93
    iput-object p1, p0, Lx21/g0;->d:Lvy0/x1;

    .line 94
    .line 95
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 96
    .line 97
    return-object p0
.end method
