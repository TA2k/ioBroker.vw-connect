.class public final Lh2/x0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:F

.field public final b:F

.field public final c:F

.field public final d:F

.field public final e:F

.field public final f:F


# direct methods
.method public constructor <init>(FFFFFF)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput p1, p0, Lh2/x0;->a:F

    .line 5
    .line 6
    iput p2, p0, Lh2/x0;->b:F

    .line 7
    .line 8
    iput p3, p0, Lh2/x0;->c:F

    .line 9
    .line 10
    iput p4, p0, Lh2/x0;->d:F

    .line 11
    .line 12
    iput p5, p0, Lh2/x0;->e:F

    .line 13
    .line 14
    iput p6, p0, Lh2/x0;->f:F

    .line 15
    .line 16
    return-void
.end method


# virtual methods
.method public final a(ZLi1/l;Ll2/o;I)Ll2/t2;
    .locals 14

    .line 1
    move-object/from16 v0, p2

    .line 2
    .line 3
    move/from16 v1, p4

    .line 4
    .line 5
    move-object/from16 v8, p3

    .line 6
    .line 7
    check-cast v8, Ll2/t;

    .line 8
    .line 9
    const v2, -0x691c96f5

    .line 10
    .line 11
    .line 12
    invoke-virtual {v8, v2}, Ll2/t;->Y(I)V

    .line 13
    .line 14
    .line 15
    iget v2, p0, Lh2/x0;->a:F

    .line 16
    .line 17
    sget-object v5, Ll2/n;->a:Ll2/x0;

    .line 18
    .line 19
    const/4 v9, 0x0

    .line 20
    if-nez v0, :cond_1

    .line 21
    .line 22
    const v0, 0x9ffae2b

    .line 23
    .line 24
    .line 25
    invoke-virtual {v8, v0}, Ll2/t;->Y(I)V

    .line 26
    .line 27
    .line 28
    invoke-virtual {v8}, Ll2/t;->L()Ljava/lang/Object;

    .line 29
    .line 30
    .line 31
    move-result-object v0

    .line 32
    if-ne v0, v5, :cond_0

    .line 33
    .line 34
    new-instance v0, Lt4/f;

    .line 35
    .line 36
    invoke-direct {v0, v2}, Lt4/f;-><init>(F)V

    .line 37
    .line 38
    .line 39
    invoke-static {v0}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 40
    .line 41
    .line 42
    move-result-object v0

    .line 43
    invoke-virtual {v8, v0}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 44
    .line 45
    .line 46
    :cond_0
    check-cast v0, Ll2/b1;

    .line 47
    .line 48
    invoke-virtual {v8, v9}, Ll2/t;->q(Z)V

    .line 49
    .line 50
    .line 51
    invoke-virtual {v8, v9}, Ll2/t;->q(Z)V

    .line 52
    .line 53
    .line 54
    return-object v0

    .line 55
    :cond_1
    const v6, 0xa00cb77

    .line 56
    .line 57
    .line 58
    invoke-virtual {v8, v6}, Ll2/t;->Y(I)V

    .line 59
    .line 60
    .line 61
    invoke-virtual {v8, v9}, Ll2/t;->q(Z)V

    .line 62
    .line 63
    .line 64
    invoke-virtual {v8}, Ll2/t;->L()Ljava/lang/Object;

    .line 65
    .line 66
    .line 67
    move-result-object v6

    .line 68
    if-ne v6, v5, :cond_2

    .line 69
    .line 70
    new-instance v6, Lv2/o;

    .line 71
    .line 72
    invoke-direct {v6}, Lv2/o;-><init>()V

    .line 73
    .line 74
    .line 75
    invoke-virtual {v8, v6}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 76
    .line 77
    .line 78
    :cond_2
    check-cast v6, Lv2/o;

    .line 79
    .line 80
    and-int/lit8 v7, v1, 0x70

    .line 81
    .line 82
    xor-int/lit8 v7, v7, 0x30

    .line 83
    .line 84
    const/16 v10, 0x20

    .line 85
    .line 86
    const/4 v11, 0x1

    .line 87
    if-le v7, v10, :cond_3

    .line 88
    .line 89
    invoke-virtual {v8, v0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 90
    .line 91
    .line 92
    move-result v7

    .line 93
    if-nez v7, :cond_4

    .line 94
    .line 95
    :cond_3
    and-int/lit8 v7, v1, 0x30

    .line 96
    .line 97
    if-ne v7, v10, :cond_5

    .line 98
    .line 99
    :cond_4
    move v7, v11

    .line 100
    goto :goto_0

    .line 101
    :cond_5
    move v7, v9

    .line 102
    :goto_0
    invoke-virtual {v8}, Ll2/t;->L()Ljava/lang/Object;

    .line 103
    .line 104
    .line 105
    move-result-object v10

    .line 106
    const/4 v12, 0x0

    .line 107
    if-nez v7, :cond_6

    .line 108
    .line 109
    if-ne v10, v5, :cond_7

    .line 110
    .line 111
    :cond_6
    new-instance v10, Lf2/n;

    .line 112
    .line 113
    const/4 v7, 0x2

    .line 114
    invoke-direct {v10, v0, v6, v12, v7}, Lf2/n;-><init>(Li1/l;Lv2/o;Lkotlin/coroutines/Continuation;I)V

    .line 115
    .line 116
    .line 117
    invoke-virtual {v8, v10}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 118
    .line 119
    .line 120
    :cond_7
    check-cast v10, Lay0/n;

    .line 121
    .line 122
    invoke-static {v10, v0, v8}, Ll2/l0;->d(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 123
    .line 124
    .line 125
    invoke-static {v6}, Lmx0/q;->U(Ljava/util/List;)Ljava/lang/Object;

    .line 126
    .line 127
    .line 128
    move-result-object v0

    .line 129
    check-cast v0, Li1/k;

    .line 130
    .line 131
    if-nez p1, :cond_8

    .line 132
    .line 133
    iget v2, p0, Lh2/x0;->f:F

    .line 134
    .line 135
    goto :goto_1

    .line 136
    :cond_8
    instance-of v6, v0, Li1/n;

    .line 137
    .line 138
    if-eqz v6, :cond_9

    .line 139
    .line 140
    iget v2, p0, Lh2/x0;->b:F

    .line 141
    .line 142
    goto :goto_1

    .line 143
    :cond_9
    instance-of v6, v0, Li1/i;

    .line 144
    .line 145
    if-eqz v6, :cond_a

    .line 146
    .line 147
    iget v2, p0, Lh2/x0;->d:F

    .line 148
    .line 149
    goto :goto_1

    .line 150
    :cond_a
    instance-of v6, v0, Li1/e;

    .line 151
    .line 152
    if-eqz v6, :cond_b

    .line 153
    .line 154
    iget v2, p0, Lh2/x0;->c:F

    .line 155
    .line 156
    goto :goto_1

    .line 157
    :cond_b
    instance-of v6, v0, Li1/b;

    .line 158
    .line 159
    if-eqz v6, :cond_c

    .line 160
    .line 161
    iget v2, p0, Lh2/x0;->e:F

    .line 162
    .line 163
    :cond_c
    :goto_1
    invoke-virtual {v8}, Ll2/t;->L()Ljava/lang/Object;

    .line 164
    .line 165
    .line 166
    move-result-object v6

    .line 167
    if-ne v6, v5, :cond_d

    .line 168
    .line 169
    new-instance v6, Lc1/c;

    .line 170
    .line 171
    new-instance v7, Lt4/f;

    .line 172
    .line 173
    invoke-direct {v7, v2}, Lt4/f;-><init>(F)V

    .line 174
    .line 175
    .line 176
    sget-object v10, Lc1/d;->l:Lc1/b2;

    .line 177
    .line 178
    const/16 v13, 0xc

    .line 179
    .line 180
    invoke-direct {v6, v7, v10, v12, v13}, Lc1/c;-><init>(Ljava/lang/Object;Lc1/b2;Ljava/lang/Object;I)V

    .line 181
    .line 182
    .line 183
    invoke-virtual {v8, v6}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 184
    .line 185
    .line 186
    :cond_d
    check-cast v6, Lc1/c;

    .line 187
    .line 188
    new-instance v10, Lt4/f;

    .line 189
    .line 190
    invoke-direct {v10, v2}, Lt4/f;-><init>(F)V

    .line 191
    .line 192
    .line 193
    invoke-virtual {v8, v6}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 194
    .line 195
    .line 196
    move-result v7

    .line 197
    invoke-virtual {v8, v2}, Ll2/t;->d(F)Z

    .line 198
    .line 199
    .line 200
    move-result v12

    .line 201
    or-int/2addr v7, v12

    .line 202
    and-int/lit8 v12, v1, 0xe

    .line 203
    .line 204
    xor-int/lit8 v12, v12, 0x6

    .line 205
    .line 206
    const/4 v13, 0x4

    .line 207
    if-le v12, v13, :cond_e

    .line 208
    .line 209
    invoke-virtual {v8, p1}, Ll2/t;->h(Z)Z

    .line 210
    .line 211
    .line 212
    move-result v12

    .line 213
    if-nez v12, :cond_f

    .line 214
    .line 215
    :cond_e
    and-int/lit8 v12, v1, 0x6

    .line 216
    .line 217
    if-ne v12, v13, :cond_10

    .line 218
    .line 219
    :cond_f
    move v12, v11

    .line 220
    goto :goto_2

    .line 221
    :cond_10
    move v12, v9

    .line 222
    :goto_2
    or-int/2addr v7, v12

    .line 223
    and-int/lit16 v12, v1, 0x380

    .line 224
    .line 225
    xor-int/lit16 v12, v12, 0x180

    .line 226
    .line 227
    const/16 v13, 0x100

    .line 228
    .line 229
    if-le v12, v13, :cond_11

    .line 230
    .line 231
    invoke-virtual {v8, p0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 232
    .line 233
    .line 234
    move-result v12

    .line 235
    if-nez v12, :cond_13

    .line 236
    .line 237
    :cond_11
    and-int/lit16 v1, v1, 0x180

    .line 238
    .line 239
    if-ne v1, v13, :cond_12

    .line 240
    .line 241
    goto :goto_3

    .line 242
    :cond_12
    move v11, v9

    .line 243
    :cond_13
    :goto_3
    or-int v1, v7, v11

    .line 244
    .line 245
    invoke-virtual {v8, v0}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 246
    .line 247
    .line 248
    move-result v7

    .line 249
    or-int/2addr v1, v7

    .line 250
    invoke-virtual {v8}, Ll2/t;->L()Ljava/lang/Object;

    .line 251
    .line 252
    .line 253
    move-result-object v7

    .line 254
    if-nez v1, :cond_14

    .line 255
    .line 256
    if-ne v7, v5, :cond_15

    .line 257
    .line 258
    :cond_14
    move-object v5, v0

    .line 259
    goto :goto_4

    .line 260
    :cond_15
    move-object v1, v6

    .line 261
    goto :goto_5

    .line 262
    :goto_4
    new-instance v0, Lh2/p0;

    .line 263
    .line 264
    move-object v1, v6

    .line 265
    const/4 v6, 0x0

    .line 266
    const/4 v7, 0x1

    .line 267
    move-object v4, p0

    .line 268
    move v3, p1

    .line 269
    invoke-direct/range {v0 .. v7}, Lh2/p0;-><init>(Lc1/c;FZLjava/lang/Object;Li1/k;Lkotlin/coroutines/Continuation;I)V

    .line 270
    .line 271
    .line 272
    invoke-virtual {v8, v0}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 273
    .line 274
    .line 275
    move-object v7, v0

    .line 276
    :goto_5
    check-cast v7, Lay0/n;

    .line 277
    .line 278
    invoke-static {v7, v10, v8}, Ll2/l0;->d(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 279
    .line 280
    .line 281
    iget-object v0, v1, Lc1/c;->c:Lc1/k;

    .line 282
    .line 283
    invoke-virtual {v8, v9}, Ll2/t;->q(Z)V

    .line 284
    .line 285
    .line 286
    return-object v0
.end method

.method public final equals(Ljava/lang/Object;)Z
    .locals 2

    .line 1
    if-ne p0, p1, :cond_0

    .line 2
    .line 3
    goto :goto_0

    .line 4
    :cond_0
    if-eqz p1, :cond_7

    .line 5
    .line 6
    instance-of v0, p1, Lh2/x0;

    .line 7
    .line 8
    if-nez v0, :cond_1

    .line 9
    .line 10
    goto :goto_1

    .line 11
    :cond_1
    check-cast p1, Lh2/x0;

    .line 12
    .line 13
    iget v0, p1, Lh2/x0;->a:F

    .line 14
    .line 15
    iget v1, p0, Lh2/x0;->a:F

    .line 16
    .line 17
    invoke-static {v1, v0}, Lt4/f;->a(FF)Z

    .line 18
    .line 19
    .line 20
    move-result v0

    .line 21
    if-nez v0, :cond_2

    .line 22
    .line 23
    goto :goto_1

    .line 24
    :cond_2
    iget v0, p0, Lh2/x0;->b:F

    .line 25
    .line 26
    iget v1, p1, Lh2/x0;->b:F

    .line 27
    .line 28
    invoke-static {v0, v1}, Lt4/f;->a(FF)Z

    .line 29
    .line 30
    .line 31
    move-result v0

    .line 32
    if-nez v0, :cond_3

    .line 33
    .line 34
    goto :goto_1

    .line 35
    :cond_3
    iget v0, p0, Lh2/x0;->c:F

    .line 36
    .line 37
    iget v1, p1, Lh2/x0;->c:F

    .line 38
    .line 39
    invoke-static {v0, v1}, Lt4/f;->a(FF)Z

    .line 40
    .line 41
    .line 42
    move-result v0

    .line 43
    if-nez v0, :cond_4

    .line 44
    .line 45
    goto :goto_1

    .line 46
    :cond_4
    iget v0, p0, Lh2/x0;->d:F

    .line 47
    .line 48
    iget v1, p1, Lh2/x0;->d:F

    .line 49
    .line 50
    invoke-static {v0, v1}, Lt4/f;->a(FF)Z

    .line 51
    .line 52
    .line 53
    move-result v0

    .line 54
    if-nez v0, :cond_5

    .line 55
    .line 56
    goto :goto_1

    .line 57
    :cond_5
    iget p0, p0, Lh2/x0;->f:F

    .line 58
    .line 59
    iget p1, p1, Lh2/x0;->f:F

    .line 60
    .line 61
    invoke-static {p0, p1}, Lt4/f;->a(FF)Z

    .line 62
    .line 63
    .line 64
    move-result p0

    .line 65
    if-nez p0, :cond_6

    .line 66
    .line 67
    goto :goto_1

    .line 68
    :cond_6
    :goto_0
    const/4 p0, 0x1

    .line 69
    return p0

    .line 70
    :cond_7
    :goto_1
    const/4 p0, 0x0

    .line 71
    return p0
.end method

.method public final hashCode()I
    .locals 3

    .line 1
    iget v0, p0, Lh2/x0;->a:F

    .line 2
    .line 3
    invoke-static {v0}, Ljava/lang/Float;->hashCode(F)I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    const/16 v1, 0x1f

    .line 8
    .line 9
    mul-int/2addr v0, v1

    .line 10
    iget v2, p0, Lh2/x0;->b:F

    .line 11
    .line 12
    invoke-static {v2, v0, v1}, La7/g0;->c(FII)I

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    iget v2, p0, Lh2/x0;->c:F

    .line 17
    .line 18
    invoke-static {v2, v0, v1}, La7/g0;->c(FII)I

    .line 19
    .line 20
    .line 21
    move-result v0

    .line 22
    iget v2, p0, Lh2/x0;->d:F

    .line 23
    .line 24
    invoke-static {v2, v0, v1}, La7/g0;->c(FII)I

    .line 25
    .line 26
    .line 27
    move-result v0

    .line 28
    iget p0, p0, Lh2/x0;->f:F

    .line 29
    .line 30
    invoke-static {p0}, Ljava/lang/Float;->hashCode(F)I

    .line 31
    .line 32
    .line 33
    move-result p0

    .line 34
    add-int/2addr p0, v0

    .line 35
    return p0
.end method
