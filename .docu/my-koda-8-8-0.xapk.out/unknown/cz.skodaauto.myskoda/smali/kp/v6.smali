.class public abstract Lkp/v6;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Ll2/o;I)V
    .locals 10

    .line 1
    check-cast p0, Ll2/t;

    .line 2
    .line 3
    const v0, 0x5f0c27ab

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 7
    .line 8
    .line 9
    const/4 v0, 0x1

    .line 10
    const/4 v1, 0x0

    .line 11
    if-eqz p1, :cond_0

    .line 12
    .line 13
    move v2, v0

    .line 14
    goto :goto_0

    .line 15
    :cond_0
    move v2, v1

    .line 16
    :goto_0
    and-int/lit8 v3, p1, 0x1

    .line 17
    .line 18
    invoke-virtual {p0, v3, v2}, Ll2/t;->O(IZ)Z

    .line 19
    .line 20
    .line 21
    move-result v2

    .line 22
    if-eqz v2, :cond_d

    .line 23
    .line 24
    const v2, -0x6040e0aa

    .line 25
    .line 26
    .line 27
    invoke-virtual {p0, v2}, Ll2/t;->Y(I)V

    .line 28
    .line 29
    .line 30
    invoke-static {p0}, Lq7/a;->a(Ll2/o;)Landroidx/lifecycle/i1;

    .line 31
    .line 32
    .line 33
    move-result-object v2

    .line 34
    if-eqz v2, :cond_c

    .line 35
    .line 36
    invoke-static {v2}, Ljp/ib;->a(Landroidx/lifecycle/i1;)Lp7/c;

    .line 37
    .line 38
    .line 39
    move-result-object v6

    .line 40
    invoke-static {p0}, Lw11/c;->b(Ll2/o;)Lk21/a;

    .line 41
    .line 42
    .line 43
    move-result-object v8

    .line 44
    const-class v3, Ldv0/e;

    .line 45
    .line 46
    sget-object v4, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 47
    .line 48
    invoke-virtual {v4, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 49
    .line 50
    .line 51
    move-result-object v3

    .line 52
    invoke-interface {v2}, Landroidx/lifecycle/i1;->getViewModelStore()Landroidx/lifecycle/h1;

    .line 53
    .line 54
    .line 55
    move-result-object v4

    .line 56
    const/4 v5, 0x0

    .line 57
    const/4 v7, 0x0

    .line 58
    const/4 v9, 0x0

    .line 59
    invoke-static/range {v3 .. v9}, Ljp/lb;->a(Lhy0/d;Landroidx/lifecycle/h1;Ljava/lang/String;Lp7/c;Lh21/b;Lk21/a;Lay0/a;)Landroidx/lifecycle/b1;

    .line 60
    .line 61
    .line 62
    move-result-object v2

    .line 63
    invoke-virtual {p0, v1}, Ll2/t;->q(Z)V

    .line 64
    .line 65
    .line 66
    check-cast v2, Lql0/j;

    .line 67
    .line 68
    invoke-static {v2, p0, v1, v0}, Lkp/x5;->b(Lql0/j;Ll2/o;II)V

    .line 69
    .line 70
    .line 71
    check-cast v2, Ldv0/e;

    .line 72
    .line 73
    iget-object v3, v2, Lql0/j;->g:Lyy0/l1;

    .line 74
    .line 75
    const/4 v4, 0x0

    .line 76
    invoke-static {v3, v4, p0, v0}, Ll2/b;->f(Lyy0/a2;Lwy0/c;Ll2/o;I)Ll2/b1;

    .line 77
    .line 78
    .line 79
    move-result-object v3

    .line 80
    invoke-virtual {p0}, Ll2/t;->L()Ljava/lang/Object;

    .line 81
    .line 82
    .line 83
    move-result-object v4

    .line 84
    sget-object v5, Ll2/n;->a:Ll2/x0;

    .line 85
    .line 86
    if-ne v4, v5, :cond_1

    .line 87
    .line 88
    invoke-static {p0}, Ll2/l0;->h(Ll2/o;)Lvy0/b0;

    .line 89
    .line 90
    .line 91
    move-result-object v4

    .line 92
    invoke-virtual {p0, v4}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 93
    .line 94
    .line 95
    :cond_1
    check-cast v4, Lvy0/b0;

    .line 96
    .line 97
    invoke-static {v1, v0, p0}, Lkp/n;->b(IILl2/o;)Le1/n1;

    .line 98
    .line 99
    .line 100
    move-result-object v6

    .line 101
    invoke-interface {v3}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 102
    .line 103
    .line 104
    move-result-object v7

    .line 105
    check-cast v7, Ldv0/d;

    .line 106
    .line 107
    iget-boolean v7, v7, Ldv0/d;->a:Z

    .line 108
    .line 109
    const v8, -0x38910a29

    .line 110
    .line 111
    .line 112
    if-eqz v7, :cond_4

    .line 113
    .line 114
    const v7, -0x387fb850    # -65679.375f

    .line 115
    .line 116
    .line 117
    invoke-virtual {p0, v7}, Ll2/t;->Y(I)V

    .line 118
    .line 119
    .line 120
    invoke-virtual {p0, v4}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 121
    .line 122
    .line 123
    move-result v7

    .line 124
    invoke-virtual {p0, v6}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 125
    .line 126
    .line 127
    move-result v9

    .line 128
    or-int/2addr v7, v9

    .line 129
    invoke-virtual {p0, v2}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 130
    .line 131
    .line 132
    move-result v9

    .line 133
    or-int/2addr v7, v9

    .line 134
    invoke-virtual {p0}, Ll2/t;->L()Ljava/lang/Object;

    .line 135
    .line 136
    .line 137
    move-result-object v9

    .line 138
    if-nez v7, :cond_2

    .line 139
    .line 140
    if-ne v9, v5, :cond_3

    .line 141
    .line 142
    :cond_2
    new-instance v9, Lc41/b;

    .line 143
    .line 144
    const/4 v7, 0x2

    .line 145
    invoke-direct {v9, v4, v6, v2, v7}, Lc41/b;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 146
    .line 147
    .line 148
    invoke-virtual {p0, v9}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 149
    .line 150
    .line 151
    :cond_3
    check-cast v9, Lay0/a;

    .line 152
    .line 153
    invoke-static {v9, p0}, Ll2/l0;->g(Lay0/a;Ll2/o;)V

    .line 154
    .line 155
    .line 156
    :goto_1
    invoke-virtual {p0, v1}, Ll2/t;->q(Z)V

    .line 157
    .line 158
    .line 159
    goto :goto_2

    .line 160
    :cond_4
    invoke-virtual {p0, v8}, Ll2/t;->Y(I)V

    .line 161
    .line 162
    .line 163
    goto :goto_1

    .line 164
    :goto_2
    invoke-interface {v3}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 165
    .line 166
    .line 167
    move-result-object v4

    .line 168
    check-cast v4, Ldv0/d;

    .line 169
    .line 170
    iget-boolean v4, v4, Ldv0/d;->c:Z

    .line 171
    .line 172
    if-eqz v4, :cond_7

    .line 173
    .line 174
    const v4, -0x387ca43c

    .line 175
    .line 176
    .line 177
    invoke-virtual {p0, v4}, Ll2/t;->Y(I)V

    .line 178
    .line 179
    .line 180
    invoke-virtual {p0, v2}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 181
    .line 182
    .line 183
    move-result v4

    .line 184
    invoke-virtual {p0}, Ll2/t;->L()Ljava/lang/Object;

    .line 185
    .line 186
    .line 187
    move-result-object v7

    .line 188
    if-nez v4, :cond_5

    .line 189
    .line 190
    if-ne v7, v5, :cond_6

    .line 191
    .line 192
    :cond_5
    new-instance v7, Ld2/g;

    .line 193
    .line 194
    const/16 v4, 0xa

    .line 195
    .line 196
    invoke-direct {v7, v2, v4}, Ld2/g;-><init>(Ljava/lang/Object;I)V

    .line 197
    .line 198
    .line 199
    invoke-virtual {p0, v7}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 200
    .line 201
    .line 202
    :cond_6
    check-cast v7, Lay0/a;

    .line 203
    .line 204
    invoke-static {v7, p0, v1}, Lvb0/a;->a(Lay0/a;Ll2/o;I)V

    .line 205
    .line 206
    .line 207
    :goto_3
    invoke-virtual {p0, v1}, Ll2/t;->q(Z)V

    .line 208
    .line 209
    .line 210
    goto :goto_4

    .line 211
    :cond_7
    invoke-virtual {p0, v8}, Ll2/t;->Y(I)V

    .line 212
    .line 213
    .line 214
    goto :goto_3

    .line 215
    :goto_4
    invoke-interface {v3}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 216
    .line 217
    .line 218
    move-result-object v2

    .line 219
    check-cast v2, Ldv0/d;

    .line 220
    .line 221
    iget-object v2, v2, Ldv0/d;->b:Lhb0/a;

    .line 222
    .line 223
    const/4 v3, -0x1

    .line 224
    if-nez v2, :cond_8

    .line 225
    .line 226
    move v2, v3

    .line 227
    goto :goto_5

    .line 228
    :cond_8
    sget-object v4, Lev0/a;->a:[I

    .line 229
    .line 230
    invoke-virtual {v2}, Ljava/lang/Enum;->ordinal()I

    .line 231
    .line 232
    .line 233
    move-result v2

    .line 234
    aget v2, v4, v2

    .line 235
    .line 236
    :goto_5
    if-eq v2, v3, :cond_b

    .line 237
    .line 238
    if-eq v2, v0, :cond_a

    .line 239
    .line 240
    const/4 v0, 0x2

    .line 241
    if-ne v2, v0, :cond_9

    .line 242
    .line 243
    const v0, -0x335ebd54    # -8.4546912E7f

    .line 244
    .line 245
    .line 246
    invoke-virtual {p0, v0}, Ll2/t;->Y(I)V

    .line 247
    .line 248
    .line 249
    invoke-static {v6, p0, v1}, Ljp/oe;->b(Le1/n1;Ll2/o;I)V

    .line 250
    .line 251
    .line 252
    invoke-virtual {p0, v1}, Ll2/t;->q(Z)V

    .line 253
    .line 254
    .line 255
    goto :goto_6

    .line 256
    :cond_9
    const p1, -0x335ecc9a    # -8.4515632E7f

    .line 257
    .line 258
    .line 259
    invoke-static {p1, p0, v1}, Lf2/m0;->b(ILl2/t;Z)La8/r0;

    .line 260
    .line 261
    .line 262
    move-result-object p0

    .line 263
    throw p0

    .line 264
    :cond_a
    const v0, -0x335ec5b2

    .line 265
    .line 266
    .line 267
    invoke-virtual {p0, v0}, Ll2/t;->Y(I)V

    .line 268
    .line 269
    .line 270
    invoke-static {v6, p0, v1}, Lvu0/g;->a(Le1/n1;Ll2/o;I)V

    .line 271
    .line 272
    .line 273
    invoke-virtual {p0, v1}, Ll2/t;->q(Z)V

    .line 274
    .line 275
    .line 276
    goto :goto_6

    .line 277
    :cond_b
    const v0, -0x335eb731    # -8.455948E7f

    .line 278
    .line 279
    .line 280
    invoke-virtual {p0, v0}, Ll2/t;->Y(I)V

    .line 281
    .line 282
    .line 283
    invoke-virtual {p0, v1}, Ll2/t;->q(Z)V

    .line 284
    .line 285
    .line 286
    goto :goto_6

    .line 287
    :cond_c
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 288
    .line 289
    const-string p1, "No ViewModelStoreOwner was provided via LocalViewModelStoreOwner"

    .line 290
    .line 291
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 292
    .line 293
    .line 294
    throw p0

    .line 295
    :cond_d
    invoke-virtual {p0}, Ll2/t;->R()V

    .line 296
    .line 297
    .line 298
    :goto_6
    invoke-virtual {p0}, Ll2/t;->s()Ll2/u1;

    .line 299
    .line 300
    .line 301
    move-result-object p0

    .line 302
    if-eqz p0, :cond_e

    .line 303
    .line 304
    new-instance v0, Ldl0/k;

    .line 305
    .line 306
    const/16 v1, 0x1d

    .line 307
    .line 308
    invoke-direct {v0, p1, v1}, Ldl0/k;-><init>(II)V

    .line 309
    .line 310
    .line 311
    iput-object v0, p0, Ll2/u1;->d:Lay0/n;

    .line 312
    .line 313
    :cond_e
    return-void
.end method

.method public static b(Ljava/io/DataInput;Ljava/lang/String;)Ln11/f;
    .locals 5

    .line 1
    invoke-interface {p0}, Ljava/io/DataInput;->readUnsignedByte()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    const/16 v1, 0x43

    .line 6
    .line 7
    if-eq v0, v1, :cond_3

    .line 8
    .line 9
    const/16 v1, 0x46

    .line 10
    .line 11
    if-eq v0, v1, :cond_1

    .line 12
    .line 13
    const/16 v1, 0x50

    .line 14
    .line 15
    if-ne v0, v1, :cond_0

    .line 16
    .line 17
    invoke-static {p0, p1}, Ls11/d;->s(Ljava/io/DataInput;Ljava/lang/String;)Ls11/d;

    .line 18
    .line 19
    .line 20
    move-result-object p0

    .line 21
    return-object p0

    .line 22
    :cond_0
    new-instance p0, Ljava/io/IOException;

    .line 23
    .line 24
    const-string p1, "Invalid encoding"

    .line 25
    .line 26
    invoke-direct {p0, p1}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    .line 27
    .line 28
    .line 29
    throw p0

    .line 30
    :cond_1
    new-instance v0, Ls11/g;

    .line 31
    .line 32
    invoke-interface {p0}, Ljava/io/DataInput;->readUTF()Ljava/lang/String;

    .line 33
    .line 34
    .line 35
    move-result-object v1

    .line 36
    invoke-static {p0}, Lkp/v6;->c(Ljava/io/DataInput;)J

    .line 37
    .line 38
    .line 39
    move-result-wide v2

    .line 40
    long-to-int v2, v2

    .line 41
    invoke-static {p0}, Lkp/v6;->c(Ljava/io/DataInput;)J

    .line 42
    .line 43
    .line 44
    move-result-wide v3

    .line 45
    long-to-int p0, v3

    .line 46
    invoke-direct {v0, p1, v1, v2, p0}, Ls11/g;-><init>(Ljava/lang/String;Ljava/lang/String;II)V

    .line 47
    .line 48
    .line 49
    sget-object p0, Ln11/f;->e:Ln11/n;

    .line 50
    .line 51
    invoke-virtual {v0, p0}, Ls11/g;->equals(Ljava/lang/Object;)Z

    .line 52
    .line 53
    .line 54
    move-result p1

    .line 55
    if-eqz p1, :cond_2

    .line 56
    .line 57
    return-object p0

    .line 58
    :cond_2
    return-object v0

    .line 59
    :cond_3
    invoke-static {p0, p1}, Ls11/d;->s(Ljava/io/DataInput;Ljava/lang/String;)Ls11/d;

    .line 60
    .line 61
    .line 62
    move-result-object p0

    .line 63
    new-instance p1, Ls11/a;

    .line 64
    .line 65
    invoke-direct {p1, p0}, Ls11/a;-><init>(Ls11/d;)V

    .line 66
    .line 67
    .line 68
    return-object p1
.end method

.method public static c(Ljava/io/DataInput;)J
    .locals 5

    .line 1
    invoke-interface {p0}, Ljava/io/DataInput;->readUnsignedByte()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    shr-int/lit8 v1, v0, 0x6

    .line 6
    .line 7
    const/4 v2, 0x1

    .line 8
    const/4 v3, 0x2

    .line 9
    const/16 v4, 0x1a

    .line 10
    .line 11
    if-eq v1, v2, :cond_2

    .line 12
    .line 13
    if-eq v1, v3, :cond_1

    .line 14
    .line 15
    const/4 v2, 0x3

    .line 16
    if-eq v1, v2, :cond_0

    .line 17
    .line 18
    shl-int/lit8 p0, v0, 0x1a

    .line 19
    .line 20
    shr-int/2addr p0, v4

    .line 21
    int-to-long v0, p0

    .line 22
    const-wide/32 v2, 0x1b7740

    .line 23
    .line 24
    .line 25
    :goto_0
    mul-long/2addr v0, v2

    .line 26
    return-wide v0

    .line 27
    :cond_0
    invoke-interface {p0}, Ljava/io/DataInput;->readLong()J

    .line 28
    .line 29
    .line 30
    move-result-wide v0

    .line 31
    return-wide v0

    .line 32
    :cond_1
    int-to-long v0, v0

    .line 33
    const/16 v2, 0x3a

    .line 34
    .line 35
    shl-long/2addr v0, v2

    .line 36
    shr-long/2addr v0, v4

    .line 37
    invoke-interface {p0}, Ljava/io/DataInput;->readUnsignedByte()I

    .line 38
    .line 39
    .line 40
    move-result v2

    .line 41
    shl-int/lit8 v2, v2, 0x18

    .line 42
    .line 43
    int-to-long v2, v2

    .line 44
    or-long/2addr v0, v2

    .line 45
    invoke-interface {p0}, Ljava/io/DataInput;->readUnsignedByte()I

    .line 46
    .line 47
    .line 48
    move-result v2

    .line 49
    shl-int/lit8 v2, v2, 0x10

    .line 50
    .line 51
    int-to-long v2, v2

    .line 52
    or-long/2addr v0, v2

    .line 53
    invoke-interface {p0}, Ljava/io/DataInput;->readUnsignedByte()I

    .line 54
    .line 55
    .line 56
    move-result v2

    .line 57
    shl-int/lit8 v2, v2, 0x8

    .line 58
    .line 59
    int-to-long v2, v2

    .line 60
    or-long/2addr v0, v2

    .line 61
    invoke-interface {p0}, Ljava/io/DataInput;->readUnsignedByte()I

    .line 62
    .line 63
    .line 64
    move-result p0

    .line 65
    int-to-long v2, p0

    .line 66
    or-long/2addr v0, v2

    .line 67
    const-wide/16 v2, 0x3e8

    .line 68
    .line 69
    goto :goto_0

    .line 70
    :cond_2
    shl-int/2addr v0, v4

    .line 71
    shr-int/2addr v0, v3

    .line 72
    invoke-interface {p0}, Ljava/io/DataInput;->readUnsignedByte()I

    .line 73
    .line 74
    .line 75
    move-result v1

    .line 76
    shl-int/lit8 v1, v1, 0x10

    .line 77
    .line 78
    or-int/2addr v0, v1

    .line 79
    invoke-interface {p0}, Ljava/io/DataInput;->readUnsignedByte()I

    .line 80
    .line 81
    .line 82
    move-result v1

    .line 83
    shl-int/lit8 v1, v1, 0x8

    .line 84
    .line 85
    or-int/2addr v0, v1

    .line 86
    invoke-interface {p0}, Ljava/io/DataInput;->readUnsignedByte()I

    .line 87
    .line 88
    .line 89
    move-result p0

    .line 90
    or-int/2addr p0, v0

    .line 91
    int-to-long v0, p0

    .line 92
    const-wide/32 v2, 0xea60

    .line 93
    .line 94
    .line 95
    goto :goto_0
.end method
