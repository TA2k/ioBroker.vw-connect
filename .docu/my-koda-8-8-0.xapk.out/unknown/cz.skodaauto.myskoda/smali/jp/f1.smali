.class public abstract Ljp/f1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Ljava/lang/String;Lt2/b;Ll2/o;I)V
    .locals 22

    .line 1
    move-object/from16 v1, p0

    .line 2
    .line 3
    move/from16 v8, p3

    .line 4
    .line 5
    const-string v0, "vin"

    .line 6
    .line 7
    invoke-static {v1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    move-object/from16 v9, p2

    .line 11
    .line 12
    check-cast v9, Ll2/t;

    .line 13
    .line 14
    const v0, 0x4b8ceed0    # 1.8472352E7f

    .line 15
    .line 16
    .line 17
    invoke-virtual {v9, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 18
    .line 19
    .line 20
    invoke-virtual {v9, v1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 21
    .line 22
    .line 23
    move-result v0

    .line 24
    const/4 v2, 0x4

    .line 25
    if-eqz v0, :cond_0

    .line 26
    .line 27
    move v0, v2

    .line 28
    goto :goto_0

    .line 29
    :cond_0
    const/4 v0, 0x2

    .line 30
    :goto_0
    or-int/2addr v0, v8

    .line 31
    and-int/lit8 v3, v0, 0x13

    .line 32
    .line 33
    const/16 v4, 0x12

    .line 34
    .line 35
    const/4 v5, 0x1

    .line 36
    const/4 v6, 0x0

    .line 37
    if-eq v3, v4, :cond_1

    .line 38
    .line 39
    move v3, v5

    .line 40
    goto :goto_1

    .line 41
    :cond_1
    move v3, v6

    .line 42
    :goto_1
    and-int/lit8 v4, v0, 0x1

    .line 43
    .line 44
    invoke-virtual {v9, v4, v3}, Ll2/t;->O(IZ)Z

    .line 45
    .line 46
    .line 47
    move-result v3

    .line 48
    if-eqz v3, :cond_c

    .line 49
    .line 50
    new-array v3, v6, [Lz9/j0;

    .line 51
    .line 52
    invoke-static {v3, v9}, Ljp/s0;->b([Lz9/j0;Ll2/o;)Lz9/y;

    .line 53
    .line 54
    .line 55
    move-result-object v10

    .line 56
    invoke-virtual {v9, v10}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 57
    .line 58
    .line 59
    move-result v3

    .line 60
    invoke-virtual {v9}, Ll2/t;->L()Ljava/lang/Object;

    .line 61
    .line 62
    .line 63
    move-result-object v4

    .line 64
    sget-object v7, Ll2/n;->a:Ll2/x0;

    .line 65
    .line 66
    if-nez v3, :cond_2

    .line 67
    .line 68
    if-ne v4, v7, :cond_3

    .line 69
    .line 70
    :cond_2
    new-instance v4, Lle/a;

    .line 71
    .line 72
    const/16 v3, 0x12

    .line 73
    .line 74
    invoke-direct {v4, v10, v3}, Lle/a;-><init>(Lz9/y;I)V

    .line 75
    .line 76
    .line 77
    invoke-virtual {v9, v4}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 78
    .line 79
    .line 80
    :cond_3
    check-cast v4, Lay0/a;

    .line 81
    .line 82
    invoke-virtual {v9, v10}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 83
    .line 84
    .line 85
    move-result v3

    .line 86
    invoke-virtual {v9}, Ll2/t;->L()Ljava/lang/Object;

    .line 87
    .line 88
    .line 89
    move-result-object v11

    .line 90
    if-nez v3, :cond_4

    .line 91
    .line 92
    if-ne v11, v7, :cond_5

    .line 93
    .line 94
    :cond_4
    new-instance v11, Lle/a;

    .line 95
    .line 96
    const/16 v3, 0x13

    .line 97
    .line 98
    invoke-direct {v11, v10, v3}, Lle/a;-><init>(Lz9/y;I)V

    .line 99
    .line 100
    .line 101
    invoke-virtual {v9, v11}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 102
    .line 103
    .line 104
    :cond_5
    move-object v3, v11

    .line 105
    check-cast v3, Lay0/a;

    .line 106
    .line 107
    new-array v11, v6, [Ljava/lang/Object;

    .line 108
    .line 109
    invoke-virtual {v9}, Ll2/t;->L()Ljava/lang/Object;

    .line 110
    .line 111
    .line 112
    move-result-object v12

    .line 113
    if-ne v12, v7, :cond_6

    .line 114
    .line 115
    new-instance v12, Lz81/g;

    .line 116
    .line 117
    const/16 v13, 0xb

    .line 118
    .line 119
    invoke-direct {v12, v13}, Lz81/g;-><init>(I)V

    .line 120
    .line 121
    .line 122
    invoke-virtual {v9, v12}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 123
    .line 124
    .line 125
    :cond_6
    check-cast v12, Lay0/a;

    .line 126
    .line 127
    const/16 v13, 0x30

    .line 128
    .line 129
    invoke-static {v11, v12, v9, v13}, Lu2/m;->c([Ljava/lang/Object;Lay0/a;Ll2/o;I)Ljava/lang/Object;

    .line 130
    .line 131
    .line 132
    move-result-object v11

    .line 133
    check-cast v11, Ll2/b1;

    .line 134
    .line 135
    invoke-virtual {v9, v11}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 136
    .line 137
    .line 138
    move-result v12

    .line 139
    invoke-virtual {v9, v10}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 140
    .line 141
    .line 142
    move-result v13

    .line 143
    or-int/2addr v12, v13

    .line 144
    invoke-virtual {v9}, Ll2/t;->L()Ljava/lang/Object;

    .line 145
    .line 146
    .line 147
    move-result-object v13

    .line 148
    if-nez v12, :cond_7

    .line 149
    .line 150
    if-ne v13, v7, :cond_8

    .line 151
    .line 152
    :cond_7
    new-instance v13, Lxh/e;

    .line 153
    .line 154
    const/16 v12, 0x9

    .line 155
    .line 156
    invoke-direct {v13, v12, v10, v11}, Lxh/e;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 157
    .line 158
    .line 159
    invoke-virtual {v9, v13}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 160
    .line 161
    .line 162
    :cond_8
    check-cast v13, Lay0/k;

    .line 163
    .line 164
    and-int/lit8 v0, v0, 0xe

    .line 165
    .line 166
    if-ne v0, v2, :cond_9

    .line 167
    .line 168
    goto :goto_2

    .line 169
    :cond_9
    move v5, v6

    .line 170
    :goto_2
    invoke-virtual {v9, v13}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 171
    .line 172
    .line 173
    move-result v0

    .line 174
    or-int/2addr v0, v5

    .line 175
    invoke-virtual {v9, v3}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 176
    .line 177
    .line 178
    move-result v2

    .line 179
    or-int/2addr v0, v2

    .line 180
    invoke-virtual {v9, v11}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 181
    .line 182
    .line 183
    move-result v2

    .line 184
    or-int/2addr v0, v2

    .line 185
    invoke-virtual {v9, v4}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 186
    .line 187
    .line 188
    move-result v2

    .line 189
    or-int/2addr v0, v2

    .line 190
    invoke-virtual {v9}, Ll2/t;->L()Ljava/lang/Object;

    .line 191
    .line 192
    .line 193
    move-result-object v2

    .line 194
    if-nez v0, :cond_a

    .line 195
    .line 196
    if-ne v2, v7, :cond_b

    .line 197
    .line 198
    :cond_a
    new-instance v0, Lbi/a;

    .line 199
    .line 200
    const/16 v7, 0x8

    .line 201
    .line 202
    move-object/from16 v5, p1

    .line 203
    .line 204
    move-object v6, v4

    .line 205
    move-object v4, v11

    .line 206
    move-object v2, v13

    .line 207
    invoke-direct/range {v0 .. v7}, Lbi/a;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 208
    .line 209
    .line 210
    invoke-virtual {v9, v0}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 211
    .line 212
    .line 213
    move-object v2, v0

    .line 214
    :cond_b
    move-object/from16 v17, v2

    .line 215
    .line 216
    check-cast v17, Lay0/k;

    .line 217
    .line 218
    const/16 v20, 0x0

    .line 219
    .line 220
    const/16 v21, 0x3fc

    .line 221
    .line 222
    move-object/from16 v18, v9

    .line 223
    .line 224
    move-object v9, v10

    .line 225
    const-string v10, "/overview"

    .line 226
    .line 227
    const/4 v11, 0x0

    .line 228
    const/4 v12, 0x0

    .line 229
    const/4 v13, 0x0

    .line 230
    const/4 v14, 0x0

    .line 231
    const/4 v15, 0x0

    .line 232
    const/16 v16, 0x0

    .line 233
    .line 234
    const/16 v19, 0x30

    .line 235
    .line 236
    invoke-static/range {v9 .. v21}, Ljp/w0;->b(Lz9/y;Ljava/lang/String;Lx2/s;Lx2/e;Lay0/k;Lay0/k;Lay0/k;Lay0/k;Lay0/k;Ll2/o;III)V

    .line 237
    .line 238
    .line 239
    goto :goto_3

    .line 240
    :cond_c
    move-object/from16 v18, v9

    .line 241
    .line 242
    invoke-virtual/range {v18 .. v18}, Ll2/t;->R()V

    .line 243
    .line 244
    .line 245
    :goto_3
    invoke-virtual/range {v18 .. v18}, Ll2/t;->s()Ll2/u1;

    .line 246
    .line 247
    .line 248
    move-result-object v0

    .line 249
    if-eqz v0, :cond_d

    .line 250
    .line 251
    new-instance v2, Ld90/t;

    .line 252
    .line 253
    const/4 v3, 0x3

    .line 254
    move-object/from16 v5, p1

    .line 255
    .line 256
    invoke-direct {v2, v1, v5, v8, v3}, Ld90/t;-><init>(Ljava/lang/String;Lt2/b;II)V

    .line 257
    .line 258
    .line 259
    iput-object v2, v0, Ll2/u1;->d:Lay0/n;

    .line 260
    .line 261
    :cond_d
    return-void
.end method

.method public static b(B)Z
    .locals 1

    .line 1
    const/16 v0, -0x41

    .line 2
    .line 3
    if-le p0, v0, :cond_0

    .line 4
    .line 5
    const/4 p0, 0x1

    .line 6
    return p0

    .line 7
    :cond_0
    const/4 p0, 0x0

    .line 8
    return p0
.end method

.method public static final c(Llg0/b;)Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0}, Ljava/lang/Enum;->ordinal()I

    .line 7
    .line 8
    .line 9
    move-result p0

    .line 10
    if-eqz p0, :cond_2

    .line 11
    .line 12
    const/4 v0, 0x1

    .line 13
    if-eq p0, v0, :cond_1

    .line 14
    .line 15
    const/4 v0, 0x2

    .line 16
    if-ne p0, v0, :cond_0

    .line 17
    .line 18
    const-string p0, "image/png"

    .line 19
    .line 20
    return-object p0

    .line 21
    :cond_0
    new-instance p0, La8/r0;

    .line 22
    .line 23
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 24
    .line 25
    .line 26
    throw p0

    .line 27
    :cond_1
    const-string p0, "application/pdf"

    .line 28
    .line 29
    return-object p0

    .line 30
    :cond_2
    const-string p0, "text/csv"

    .line 31
    .line 32
    return-object p0
.end method
