.class public abstract Ln70/m;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:F

.field public static final b:F

.field public static final c:F

.field public static final d:F

.field public static final e:F


# direct methods
.method static constructor <clinit>()V
    .locals 21

    .line 1
    new-instance v9, Lm70/q;

    .line 2
    .line 3
    const/16 v0, 0x28

    .line 4
    .line 5
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    const-string v1, "40%"

    .line 10
    .line 11
    const-string v2, "100%"

    .line 12
    .line 13
    const/4 v10, 0x1

    .line 14
    invoke-direct {v9, v0, v1, v2, v10}, Lm70/q;-><init>(Ljava/lang/Integer;Ljava/lang/String;Ljava/lang/String;Z)V

    .line 15
    .line 16
    .line 17
    new-instance v0, Lm70/r;

    .line 18
    .line 19
    const/4 v7, 0x0

    .line 20
    const-string v8, "293 km \u2014 3 h 14 min"

    .line 21
    .line 22
    const/16 v1, 0x41

    .line 23
    .line 24
    const-string v2, "Belluno"

    .line 25
    .line 26
    const/4 v3, 0x0

    .line 27
    const-string v4, "Belluno, Italy"

    .line 28
    .line 29
    const/4 v5, 0x0

    .line 30
    const-string v6, "08:00"

    .line 31
    .line 32
    invoke-direct/range {v0 .. v9}, Lm70/r;-><init>(CLjava/lang/String;Lxj0/f;Ljava/lang/String;ZLjava/lang/String;Ljava/lang/String;Ljava/lang/String;Lm70/q;)V

    .line 33
    .line 34
    .line 35
    new-instance v11, Lm70/r;

    .line 36
    .line 37
    new-instance v1, Lm70/q;

    .line 38
    .line 39
    const/16 v2, 0x32

    .line 40
    .line 41
    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 42
    .line 43
    .line 44
    move-result-object v2

    .line 45
    const-string v3, "50%"

    .line 46
    .line 47
    const/4 v4, 0x0

    .line 48
    invoke-direct {v1, v2, v3, v4, v10}, Lm70/q;-><init>(Ljava/lang/Integer;Ljava/lang/String;Ljava/lang/String;Z)V

    .line 49
    .line 50
    .line 51
    const/16 v12, 0x42

    .line 52
    .line 53
    const-string v13, "Charging Station Supercharger Verona Sud"

    .line 54
    .line 55
    const/4 v14, 0x0

    .line 56
    const-string v15, "Via dell\'Industria, 1, 37066 Sommacampagna VR, Italy"

    .line 57
    .line 58
    const/16 v16, 0x1

    .line 59
    .line 60
    const-string v17, "10:15"

    .line 61
    .line 62
    const-string v18, "09:45"

    .line 63
    .line 64
    const/16 v19, 0x0

    .line 65
    .line 66
    move-object/from16 v20, v1

    .line 67
    .line 68
    invoke-direct/range {v11 .. v20}, Lm70/r;-><init>(CLjava/lang/String;Lxj0/f;Ljava/lang/String;ZLjava/lang/String;Ljava/lang/String;Ljava/lang/String;Lm70/q;)V

    .line 69
    .line 70
    .line 71
    filled-new-array {v0, v11}, [Lm70/r;

    .line 72
    .line 73
    .line 74
    move-result-object v0

    .line 75
    invoke-static {v0}, Ljp/k1;->j([Ljava/lang/Object;)Ljava/util/List;

    .line 76
    .line 77
    .line 78
    const/16 v0, 0x1e

    .line 79
    .line 80
    const/16 v1, 0x8

    .line 81
    .line 82
    and-int/2addr v0, v1

    .line 83
    if-eqz v0, :cond_0

    .line 84
    .line 85
    sget-object v4, Lxj0/j;->d:Lxj0/j;

    .line 86
    .line 87
    :cond_0
    const-string v0, "mapTileType"

    .line 88
    .line 89
    invoke-static {v4, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 90
    .line 91
    .line 92
    const/16 v0, 0x66

    .line 93
    .line 94
    int-to-float v0, v0

    .line 95
    sput v0, Ln70/m;->a:F

    .line 96
    .line 97
    int-to-float v0, v1

    .line 98
    sput v0, Ln70/m;->b:F

    .line 99
    .line 100
    const/16 v0, 0x68

    .line 101
    .line 102
    int-to-float v0, v0

    .line 103
    sput v0, Ln70/m;->c:F

    .line 104
    .line 105
    const/16 v0, 0x20

    .line 106
    .line 107
    int-to-float v0, v0

    .line 108
    sput v0, Ln70/m;->d:F

    .line 109
    .line 110
    const/16 v0, 0xc4

    .line 111
    .line 112
    int-to-float v0, v0

    .line 113
    sput v0, Ln70/m;->e:F

    .line 114
    .line 115
    return-void
.end method

.method public static final a(Li91/r2;Ll2/b1;Luu/g;Ll2/o;I)V
    .locals 16

    .line 1
    move-object/from16 v1, p0

    .line 2
    .line 3
    move-object/from16 v10, p1

    .line 4
    .line 5
    move-object/from16 v5, p2

    .line 6
    .line 7
    move/from16 v11, p4

    .line 8
    .line 9
    const-string v0, "drawerState"

    .line 10
    .line 11
    invoke-static {v1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 12
    .line 13
    .line 14
    const-string v0, "currentDrawerHeight"

    .line 15
    .line 16
    invoke-static {v10, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 17
    .line 18
    .line 19
    move-object/from16 v12, p3

    .line 20
    .line 21
    check-cast v12, Ll2/t;

    .line 22
    .line 23
    const v0, -0x1e96c953

    .line 24
    .line 25
    .line 26
    invoke-virtual {v12, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 27
    .line 28
    .line 29
    and-int/lit8 v0, v11, 0x6

    .line 30
    .line 31
    const/4 v2, 0x4

    .line 32
    if-nez v0, :cond_2

    .line 33
    .line 34
    and-int/lit8 v0, v11, 0x8

    .line 35
    .line 36
    if-nez v0, :cond_0

    .line 37
    .line 38
    invoke-virtual {v12, v1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 39
    .line 40
    .line 41
    move-result v0

    .line 42
    goto :goto_0

    .line 43
    :cond_0
    invoke-virtual {v12, v1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 44
    .line 45
    .line 46
    move-result v0

    .line 47
    :goto_0
    if-eqz v0, :cond_1

    .line 48
    .line 49
    move v0, v2

    .line 50
    goto :goto_1

    .line 51
    :cond_1
    const/4 v0, 0x2

    .line 52
    :goto_1
    or-int/2addr v0, v11

    .line 53
    goto :goto_2

    .line 54
    :cond_2
    move v0, v11

    .line 55
    :goto_2
    and-int/lit8 v3, v11, 0x30

    .line 56
    .line 57
    if-nez v3, :cond_4

    .line 58
    .line 59
    invoke-virtual {v12, v10}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 60
    .line 61
    .line 62
    move-result v3

    .line 63
    if-eqz v3, :cond_3

    .line 64
    .line 65
    const/16 v3, 0x20

    .line 66
    .line 67
    goto :goto_3

    .line 68
    :cond_3
    const/16 v3, 0x10

    .line 69
    .line 70
    :goto_3
    or-int/2addr v0, v3

    .line 71
    :cond_4
    and-int/lit16 v3, v11, 0x180

    .line 72
    .line 73
    const/16 v4, 0x100

    .line 74
    .line 75
    if-nez v3, :cond_7

    .line 76
    .line 77
    and-int/lit16 v3, v11, 0x200

    .line 78
    .line 79
    if-nez v3, :cond_5

    .line 80
    .line 81
    invoke-virtual {v12, v5}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 82
    .line 83
    .line 84
    move-result v3

    .line 85
    goto :goto_4

    .line 86
    :cond_5
    invoke-virtual {v12, v5}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 87
    .line 88
    .line 89
    move-result v3

    .line 90
    :goto_4
    if-eqz v3, :cond_6

    .line 91
    .line 92
    move v3, v4

    .line 93
    goto :goto_5

    .line 94
    :cond_6
    const/16 v3, 0x80

    .line 95
    .line 96
    :goto_5
    or-int/2addr v0, v3

    .line 97
    :cond_7
    and-int/lit16 v3, v0, 0x93

    .line 98
    .line 99
    const/16 v6, 0x92

    .line 100
    .line 101
    if-eq v3, v6, :cond_8

    .line 102
    .line 103
    const/4 v3, 0x1

    .line 104
    goto :goto_6

    .line 105
    :cond_8
    const/4 v3, 0x0

    .line 106
    :goto_6
    and-int/lit8 v6, v0, 0x1

    .line 107
    .line 108
    invoke-virtual {v12, v6, v3}, Ll2/t;->O(IZ)Z

    .line 109
    .line 110
    .line 111
    move-result v3

    .line 112
    if-eqz v3, :cond_13

    .line 113
    .line 114
    sget-object v3, Lw3/h1;->t:Ll2/u2;

    .line 115
    .line 116
    invoke-virtual {v12, v3}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 117
    .line 118
    .line 119
    move-result-object v3

    .line 120
    check-cast v3, Lw3/j2;

    .line 121
    .line 122
    invoke-virtual {v12}, Ll2/t;->L()Ljava/lang/Object;

    .line 123
    .line 124
    .line 125
    move-result-object v6

    .line 126
    sget-object v9, Ll2/n;->a:Ll2/x0;

    .line 127
    .line 128
    if-ne v6, v9, :cond_9

    .line 129
    .line 130
    new-instance v6, Llk/j;

    .line 131
    .line 132
    const/16 v13, 0xc

    .line 133
    .line 134
    invoke-direct {v6, v13, v10, v3}, Llk/j;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 135
    .line 136
    .line 137
    invoke-static {v6}, Ll2/b;->h(Lay0/a;)Ll2/h0;

    .line 138
    .line 139
    .line 140
    move-result-object v6

    .line 141
    invoke-virtual {v12, v6}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 142
    .line 143
    .line 144
    :cond_9
    check-cast v6, Ll2/t2;

    .line 145
    .line 146
    invoke-virtual {v12}, Ll2/t;->L()Ljava/lang/Object;

    .line 147
    .line 148
    .line 149
    move-result-object v13

    .line 150
    const/4 v14, 0x0

    .line 151
    if-ne v13, v9, :cond_a

    .line 152
    .line 153
    invoke-static {v14}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 154
    .line 155
    .line 156
    move-result-object v13

    .line 157
    invoke-virtual {v12, v13}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 158
    .line 159
    .line 160
    :cond_a
    check-cast v13, Ll2/b1;

    .line 161
    .line 162
    invoke-virtual {v12}, Ll2/t;->L()Ljava/lang/Object;

    .line 163
    .line 164
    .line 165
    move-result-object v15

    .line 166
    if-ne v15, v9, :cond_b

    .line 167
    .line 168
    invoke-static {v14}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 169
    .line 170
    .line 171
    move-result-object v15

    .line 172
    invoke-virtual {v12, v15}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 173
    .line 174
    .line 175
    :cond_b
    check-cast v15, Ll2/b1;

    .line 176
    .line 177
    invoke-virtual {v12}, Ll2/t;->L()Ljava/lang/Object;

    .line 178
    .line 179
    .line 180
    move-result-object v14

    .line 181
    if-ne v14, v9, :cond_c

    .line 182
    .line 183
    sget-object v14, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 184
    .line 185
    invoke-static {v14}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 186
    .line 187
    .line 188
    move-result-object v14

    .line 189
    invoke-virtual {v12, v14}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 190
    .line 191
    .line 192
    :cond_c
    check-cast v14, Ll2/b1;

    .line 193
    .line 194
    invoke-virtual {v1}, Li91/r2;->c()Li91/s2;

    .line 195
    .line 196
    .line 197
    move-result-object v8

    .line 198
    and-int/lit8 v7, v0, 0xe

    .line 199
    .line 200
    if-eq v7, v2, :cond_e

    .line 201
    .line 202
    and-int/lit8 v2, v0, 0x8

    .line 203
    .line 204
    if-eqz v2, :cond_d

    .line 205
    .line 206
    invoke-virtual {v12, v1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 207
    .line 208
    .line 209
    move-result v2

    .line 210
    if-eqz v2, :cond_d

    .line 211
    .line 212
    goto :goto_7

    .line 213
    :cond_d
    const/4 v2, 0x0

    .line 214
    goto :goto_8

    .line 215
    :cond_e
    :goto_7
    const/4 v2, 0x1

    .line 216
    :goto_8
    invoke-virtual {v12, v3}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 217
    .line 218
    .line 219
    move-result v7

    .line 220
    or-int/2addr v2, v7

    .line 221
    and-int/lit16 v7, v0, 0x380

    .line 222
    .line 223
    if-eq v7, v4, :cond_10

    .line 224
    .line 225
    and-int/lit16 v0, v0, 0x200

    .line 226
    .line 227
    if-eqz v0, :cond_f

    .line 228
    .line 229
    invoke-virtual {v12, v5}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 230
    .line 231
    .line 232
    move-result v0

    .line 233
    if-eqz v0, :cond_f

    .line 234
    .line 235
    goto :goto_9

    .line 236
    :cond_f
    const/4 v7, 0x0

    .line 237
    goto :goto_a

    .line 238
    :cond_10
    :goto_9
    const/4 v7, 0x1

    .line 239
    :goto_a
    or-int v0, v2, v7

    .line 240
    .line 241
    invoke-virtual {v12}, Ll2/t;->L()Ljava/lang/Object;

    .line 242
    .line 243
    .line 244
    move-result-object v2

    .line 245
    if-nez v0, :cond_12

    .line 246
    .line 247
    if-ne v2, v9, :cond_11

    .line 248
    .line 249
    goto :goto_b

    .line 250
    :cond_11
    move-object v13, v8

    .line 251
    goto :goto_c

    .line 252
    :cond_12
    :goto_b
    new-instance v0, Lg1/y0;

    .line 253
    .line 254
    move-object v2, v8

    .line 255
    const/4 v8, 0x0

    .line 256
    const/4 v9, 0x3

    .line 257
    move-object v4, v3

    .line 258
    move-object v3, v6

    .line 259
    move-object v6, v13

    .line 260
    move-object v7, v15

    .line 261
    move-object v13, v2

    .line 262
    move-object v2, v14

    .line 263
    invoke-direct/range {v0 .. v9}, Lg1/y0;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 264
    .line 265
    .line 266
    invoke-virtual {v12, v0}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 267
    .line 268
    .line 269
    move-object v2, v0

    .line 270
    :goto_c
    check-cast v2, Lay0/n;

    .line 271
    .line 272
    invoke-static {v2, v13, v12}, Ll2/l0;->d(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 273
    .line 274
    .line 275
    goto :goto_d

    .line 276
    :cond_13
    invoke-virtual {v12}, Ll2/t;->R()V

    .line 277
    .line 278
    .line 279
    :goto_d
    invoke-virtual {v12}, Ll2/t;->s()Ll2/u1;

    .line 280
    .line 281
    .line 282
    move-result-object v6

    .line 283
    if-eqz v6, :cond_14

    .line 284
    .line 285
    new-instance v0, Li50/j0;

    .line 286
    .line 287
    const/16 v2, 0x12

    .line 288
    .line 289
    move-object/from16 v3, p0

    .line 290
    .line 291
    move-object/from16 v5, p2

    .line 292
    .line 293
    move-object v4, v10

    .line 294
    move v1, v11

    .line 295
    invoke-direct/range {v0 .. v5}, Li50/j0;-><init>(IILjava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)V

    .line 296
    .line 297
    .line 298
    iput-object v0, v6, Ll2/u1;->d:Lay0/n;

    .line 299
    .line 300
    :cond_14
    return-void
.end method

.method public static final b(Llx0/l;Ll2/o;I)V
    .locals 18

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v12, p1

    .line 4
    .line 5
    check-cast v12, Ll2/t;

    .line 6
    .line 7
    const v2, -0x45f1d658

    .line 8
    .line 9
    .line 10
    invoke-virtual {v12, v2}, Ll2/t;->a0(I)Ll2/t;

    .line 11
    .line 12
    .line 13
    invoke-virtual {v12, v0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 14
    .line 15
    .line 16
    move-result v2

    .line 17
    const/16 v3, 0x10

    .line 18
    .line 19
    if-eqz v2, :cond_0

    .line 20
    .line 21
    const/16 v2, 0x20

    .line 22
    .line 23
    goto :goto_0

    .line 24
    :cond_0
    move v2, v3

    .line 25
    :goto_0
    or-int v2, p2, v2

    .line 26
    .line 27
    and-int/lit8 v4, v2, 0x11

    .line 28
    .line 29
    const/4 v10, 0x1

    .line 30
    const/4 v11, 0x0

    .line 31
    if-eq v4, v3, :cond_1

    .line 32
    .line 33
    move v3, v10

    .line 34
    goto :goto_1

    .line 35
    :cond_1
    move v3, v11

    .line 36
    :goto_1
    and-int/2addr v2, v10

    .line 37
    invoke-virtual {v12, v2, v3}, Ll2/t;->O(IZ)Z

    .line 38
    .line 39
    .line 40
    move-result v2

    .line 41
    if-eqz v2, :cond_2

    .line 42
    .line 43
    const v2, 0x7f12144d

    .line 44
    .line 45
    .line 46
    invoke-static {v12, v2}, Ljp/ga;->d(Ll2/o;I)Ljava/lang/String;

    .line 47
    .line 48
    .line 49
    move-result-object v2

    .line 50
    sget-object v3, Lj91/j;->a:Ll2/u2;

    .line 51
    .line 52
    invoke-virtual {v12, v3}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 53
    .line 54
    .line 55
    move-result-object v3

    .line 56
    check-cast v3, Lj91/f;

    .line 57
    .line 58
    invoke-virtual {v3}, Lj91/f;->k()Lg4/p0;

    .line 59
    .line 60
    .line 61
    move-result-object v3

    .line 62
    const/16 v8, 0xc00

    .line 63
    .line 64
    const/16 v9, 0x14

    .line 65
    .line 66
    const/4 v4, 0x0

    .line 67
    const-string v5, "trip_detail_battery_header"

    .line 68
    .line 69
    const/4 v6, 0x0

    .line 70
    move-object v7, v12

    .line 71
    invoke-static/range {v2 .. v9}, Li91/j0;->H(Ljava/lang/String;Lg4/p0;Lx2/s;Ljava/lang/String;Ljava/lang/String;Ll2/o;II)V

    .line 72
    .line 73
    .line 74
    const v2, 0x7f121457

    .line 75
    .line 76
    .line 77
    invoke-static {v12, v2}, Ljp/ga;->d(Ll2/o;I)Ljava/lang/String;

    .line 78
    .line 79
    .line 80
    move-result-object v2

    .line 81
    new-instance v6, Li91/a2;

    .line 82
    .line 83
    iget-object v3, v0, Llx0/l;->d:Ljava/lang/Object;

    .line 84
    .line 85
    check-cast v3, Ljava/lang/String;

    .line 86
    .line 87
    invoke-static {v3}, Lxf0/y1;->I(Ljava/lang/String;)Lg4/g;

    .line 88
    .line 89
    .line 90
    move-result-object v3

    .line 91
    invoke-direct {v6, v3, v11}, Li91/a2;-><init>(Lg4/g;I)V

    .line 92
    .line 93
    .line 94
    const/16 v14, 0x30

    .line 95
    .line 96
    const/16 v15, 0x7ee

    .line 97
    .line 98
    const/4 v3, 0x0

    .line 99
    const/4 v5, 0x0

    .line 100
    const/4 v7, 0x0

    .line 101
    const/4 v8, 0x0

    .line 102
    const/4 v9, 0x0

    .line 103
    move v13, v10

    .line 104
    const/4 v10, 0x0

    .line 105
    move/from16 v16, v11

    .line 106
    .line 107
    const-string v11, "trip_detail_battery_start"

    .line 108
    .line 109
    move/from16 v17, v13

    .line 110
    .line 111
    const/4 v13, 0x0

    .line 112
    move/from16 v0, v16

    .line 113
    .line 114
    move/from16 v1, v17

    .line 115
    .line 116
    invoke-static/range {v2 .. v15}, Li91/j0;->L(Ljava/lang/String;Lx2/s;Ljava/lang/String;Li91/x1;Li91/v1;ZLi91/t1;Lay0/a;FLjava/lang/String;Ll2/o;III)V

    .line 117
    .line 118
    .line 119
    const/4 v2, 0x0

    .line 120
    invoke-static {v0, v1, v12, v2}, Li91/j0;->D(IILl2/o;Lx2/s;)V

    .line 121
    .line 122
    .line 123
    const v1, 0x7f121456

    .line 124
    .line 125
    .line 126
    invoke-static {v12, v1}, Ljp/ga;->d(Ll2/o;I)Ljava/lang/String;

    .line 127
    .line 128
    .line 129
    move-result-object v2

    .line 130
    new-instance v6, Li91/a2;

    .line 131
    .line 132
    move-object/from16 v1, p0

    .line 133
    .line 134
    iget-object v3, v1, Llx0/l;->e:Ljava/lang/Object;

    .line 135
    .line 136
    check-cast v3, Ljava/lang/String;

    .line 137
    .line 138
    invoke-static {v3}, Lxf0/y1;->I(Ljava/lang/String;)Lg4/g;

    .line 139
    .line 140
    .line 141
    move-result-object v3

    .line 142
    invoke-direct {v6, v3, v0}, Li91/a2;-><init>(Lg4/g;I)V

    .line 143
    .line 144
    .line 145
    const/4 v3, 0x0

    .line 146
    const-string v11, "trip_detail_battery_start"

    .line 147
    .line 148
    invoke-static/range {v2 .. v15}, Li91/j0;->L(Ljava/lang/String;Lx2/s;Ljava/lang/String;Li91/x1;Li91/v1;ZLi91/t1;Lay0/a;FLjava/lang/String;Ll2/o;III)V

    .line 149
    .line 150
    .line 151
    sget-object v0, Lj91/a;->a:Ll2/u2;

    .line 152
    .line 153
    invoke-virtual {v12, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 154
    .line 155
    .line 156
    move-result-object v0

    .line 157
    check-cast v0, Lj91/c;

    .line 158
    .line 159
    iget v0, v0, Lj91/c;->f:F

    .line 160
    .line 161
    sget-object v2, Lx2/p;->b:Lx2/p;

    .line 162
    .line 163
    invoke-static {v2, v0}, Landroidx/compose/foundation/layout/d;->e(Lx2/s;F)Lx2/s;

    .line 164
    .line 165
    .line 166
    move-result-object v0

    .line 167
    invoke-static {v12, v0}, Lk1/d;->d(Ll2/o;Lx2/s;)V

    .line 168
    .line 169
    .line 170
    goto :goto_2

    .line 171
    :cond_2
    move-object v1, v0

    .line 172
    invoke-virtual {v12}, Ll2/t;->R()V

    .line 173
    .line 174
    .line 175
    :goto_2
    invoke-virtual {v12}, Ll2/t;->s()Ll2/u1;

    .line 176
    .line 177
    .line 178
    move-result-object v0

    .line 179
    if-eqz v0, :cond_3

    .line 180
    .line 181
    new-instance v2, Ln70/k;

    .line 182
    .line 183
    const/4 v3, 0x1

    .line 184
    move/from16 v4, p2

    .line 185
    .line 186
    invoke-direct {v2, v1, v4, v3}, Ln70/k;-><init>(Llx0/l;II)V

    .line 187
    .line 188
    .line 189
    iput-object v2, v0, Ll2/u1;->d:Lay0/n;

    .line 190
    .line 191
    :cond_3
    return-void
.end method

.method public static final c(Ljava/lang/String;Ljava/lang/String;Ll2/o;I)V
    .locals 26

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    move-object/from16 v5, p2

    .line 6
    .line 7
    check-cast v5, Ll2/t;

    .line 8
    .line 9
    const v2, -0x18b5c352

    .line 10
    .line 11
    .line 12
    invoke-virtual {v5, v2}, Ll2/t;->a0(I)Ll2/t;

    .line 13
    .line 14
    .line 15
    invoke-virtual {v5, v0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 16
    .line 17
    .line 18
    move-result v2

    .line 19
    if-eqz v2, :cond_0

    .line 20
    .line 21
    const/16 v2, 0x20

    .line 22
    .line 23
    goto :goto_0

    .line 24
    :cond_0
    const/16 v2, 0x10

    .line 25
    .line 26
    :goto_0
    or-int v2, p3, v2

    .line 27
    .line 28
    invoke-virtual {v5, v1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 29
    .line 30
    .line 31
    move-result v3

    .line 32
    if-eqz v3, :cond_1

    .line 33
    .line 34
    const/16 v3, 0x100

    .line 35
    .line 36
    goto :goto_1

    .line 37
    :cond_1
    const/16 v3, 0x80

    .line 38
    .line 39
    :goto_1
    or-int/2addr v2, v3

    .line 40
    and-int/lit16 v3, v2, 0x91

    .line 41
    .line 42
    const/16 v4, 0x90

    .line 43
    .line 44
    const/4 v6, 0x0

    .line 45
    const/4 v7, 0x1

    .line 46
    if-eq v3, v4, :cond_2

    .line 47
    .line 48
    move v3, v7

    .line 49
    goto :goto_2

    .line 50
    :cond_2
    move v3, v6

    .line 51
    :goto_2
    and-int/lit8 v4, v2, 0x1

    .line 52
    .line 53
    invoke-virtual {v5, v4, v3}, Ll2/t;->O(IZ)Z

    .line 54
    .line 55
    .line 56
    move-result v3

    .line 57
    if-eqz v3, :cond_6

    .line 58
    .line 59
    invoke-static {v5}, Llp/nb;->c(Ll2/o;)Lj91/f;

    .line 60
    .line 61
    .line 62
    move-result-object v3

    .line 63
    invoke-virtual {v3}, Lj91/f;->k()Lg4/p0;

    .line 64
    .line 65
    .line 66
    move-result-object v3

    .line 67
    invoke-static {v5}, Llp/nb;->a(Ll2/o;)Lj91/e;

    .line 68
    .line 69
    .line 70
    move-result-object v4

    .line 71
    invoke-virtual {v4}, Lj91/e;->q()J

    .line 72
    .line 73
    .line 74
    move-result-wide v8

    .line 75
    const-string v4, "trip_detail_name"

    .line 76
    .line 77
    sget-object v10, Lx2/p;->b:Lx2/p;

    .line 78
    .line 79
    invoke-static {v10, v4}, Landroidx/compose/ui/platform/a;->a(Lx2/s;Ljava/lang/String;)Lx2/s;

    .line 80
    .line 81
    .line 82
    move-result-object v4

    .line 83
    shr-int/lit8 v11, v2, 0x3

    .line 84
    .line 85
    and-int/lit8 v11, v11, 0xe

    .line 86
    .line 87
    or-int/lit16 v11, v11, 0x180

    .line 88
    .line 89
    const/16 v20, 0x0

    .line 90
    .line 91
    const v21, 0xfff0

    .line 92
    .line 93
    .line 94
    move-object/from16 v18, v5

    .line 95
    .line 96
    move v12, v6

    .line 97
    const-wide/16 v5, 0x0

    .line 98
    .line 99
    move v13, v7

    .line 100
    const/4 v7, 0x0

    .line 101
    move v14, v2

    .line 102
    move-object v1, v3

    .line 103
    move-object v2, v4

    .line 104
    move-wide v3, v8

    .line 105
    const-wide/16 v8, 0x0

    .line 106
    .line 107
    move-object v15, v10

    .line 108
    const/4 v10, 0x0

    .line 109
    move/from16 v19, v11

    .line 110
    .line 111
    const/4 v11, 0x0

    .line 112
    move/from16 v16, v12

    .line 113
    .line 114
    move/from16 v17, v13

    .line 115
    .line 116
    const-wide/16 v12, 0x0

    .line 117
    .line 118
    move/from16 v22, v14

    .line 119
    .line 120
    const/4 v14, 0x0

    .line 121
    move-object/from16 v23, v15

    .line 122
    .line 123
    const/4 v15, 0x0

    .line 124
    move/from16 v24, v16

    .line 125
    .line 126
    const/16 v16, 0x0

    .line 127
    .line 128
    move/from16 v25, v17

    .line 129
    .line 130
    const/16 v17, 0x0

    .line 131
    .line 132
    invoke-static/range {v0 .. v21}, Li91/z3;->d(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZILay0/k;Ll2/o;III)V

    .line 133
    .line 134
    .line 135
    move-object/from16 v5, v18

    .line 136
    .line 137
    sget-object v0, Lx2/c;->n:Lx2/i;

    .line 138
    .line 139
    invoke-static {v5}, Llp/nb;->b(Ll2/o;)Lj91/c;

    .line 140
    .line 141
    .line 142
    move-result-object v1

    .line 143
    iget v12, v1, Lj91/c;->c:F

    .line 144
    .line 145
    invoke-static {v5}, Llp/nb;->b(Ll2/o;)Lj91/c;

    .line 146
    .line 147
    .line 148
    move-result-object v1

    .line 149
    iget v14, v1, Lj91/c;->c:F

    .line 150
    .line 151
    const/4 v15, 0x5

    .line 152
    const/4 v11, 0x0

    .line 153
    const/4 v13, 0x0

    .line 154
    move-object/from16 v10, v23

    .line 155
    .line 156
    invoke-static/range {v10 .. v15}, Landroidx/compose/foundation/layout/a;->q(Lx2/s;FFFFI)Lx2/s;

    .line 157
    .line 158
    .line 159
    move-result-object v1

    .line 160
    const-string v2, "trip_detail_time_and_distance"

    .line 161
    .line 162
    invoke-static {v1, v2}, Landroidx/compose/ui/platform/a;->a(Lx2/s;Ljava/lang/String;)Lx2/s;

    .line 163
    .line 164
    .line 165
    move-result-object v1

    .line 166
    sget-object v2, Lk1/j;->a:Lk1/c;

    .line 167
    .line 168
    const/16 v3, 0x30

    .line 169
    .line 170
    invoke-static {v2, v0, v5, v3}, Lk1/e1;->a(Lk1/g;Lx2/i;Ll2/o;I)Lk1/g1;

    .line 171
    .line 172
    .line 173
    move-result-object v0

    .line 174
    iget-wide v2, v5, Ll2/t;->T:J

    .line 175
    .line 176
    invoke-static {v2, v3}, Ljava/lang/Long;->hashCode(J)I

    .line 177
    .line 178
    .line 179
    move-result v2

    .line 180
    invoke-virtual {v5}, Ll2/t;->m()Ll2/p1;

    .line 181
    .line 182
    .line 183
    move-result-object v3

    .line 184
    invoke-static {v5, v1}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 185
    .line 186
    .line 187
    move-result-object v1

    .line 188
    sget-object v4, Lv3/k;->m1:Lv3/j;

    .line 189
    .line 190
    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 191
    .line 192
    .line 193
    sget-object v4, Lv3/j;->b:Lv3/i;

    .line 194
    .line 195
    invoke-virtual {v5}, Ll2/t;->c0()V

    .line 196
    .line 197
    .line 198
    iget-boolean v6, v5, Ll2/t;->S:Z

    .line 199
    .line 200
    if-eqz v6, :cond_3

    .line 201
    .line 202
    invoke-virtual {v5, v4}, Ll2/t;->l(Lay0/a;)V

    .line 203
    .line 204
    .line 205
    goto :goto_3

    .line 206
    :cond_3
    invoke-virtual {v5}, Ll2/t;->m0()V

    .line 207
    .line 208
    .line 209
    :goto_3
    sget-object v4, Lv3/j;->g:Lv3/h;

    .line 210
    .line 211
    invoke-static {v4, v0, v5}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 212
    .line 213
    .line 214
    sget-object v0, Lv3/j;->f:Lv3/h;

    .line 215
    .line 216
    invoke-static {v0, v3, v5}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 217
    .line 218
    .line 219
    sget-object v0, Lv3/j;->j:Lv3/h;

    .line 220
    .line 221
    iget-boolean v3, v5, Ll2/t;->S:Z

    .line 222
    .line 223
    if-nez v3, :cond_4

    .line 224
    .line 225
    invoke-virtual {v5}, Ll2/t;->L()Ljava/lang/Object;

    .line 226
    .line 227
    .line 228
    move-result-object v3

    .line 229
    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 230
    .line 231
    .line 232
    move-result-object v4

    .line 233
    invoke-static {v3, v4}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 234
    .line 235
    .line 236
    move-result v3

    .line 237
    if-nez v3, :cond_5

    .line 238
    .line 239
    :cond_4
    invoke-static {v2, v5, v2, v0}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 240
    .line 241
    .line 242
    :cond_5
    sget-object v0, Lv3/j;->d:Lv3/h;

    .line 243
    .line 244
    invoke-static {v0, v1, v5}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 245
    .line 246
    .line 247
    const v0, 0x7f0802fd

    .line 248
    .line 249
    .line 250
    const/4 v12, 0x0

    .line 251
    invoke-static {v0, v12, v5}, Ljp/fa;->b(IILl2/o;)Li3/c;

    .line 252
    .line 253
    .line 254
    move-result-object v0

    .line 255
    invoke-static {v5}, Llp/nb;->a(Ll2/o;)Lj91/e;

    .line 256
    .line 257
    .line 258
    move-result-object v1

    .line 259
    invoke-virtual {v1}, Lj91/e;->s()J

    .line 260
    .line 261
    .line 262
    move-result-wide v3

    .line 263
    const/16 v1, 0x14

    .line 264
    .line 265
    int-to-float v1, v1

    .line 266
    invoke-static {v10, v1}, Landroidx/compose/foundation/layout/d;->n(Lx2/s;F)Lx2/s;

    .line 267
    .line 268
    .line 269
    move-result-object v2

    .line 270
    const/16 v6, 0x1b0

    .line 271
    .line 272
    const/4 v7, 0x0

    .line 273
    const/4 v1, 0x0

    .line 274
    invoke-static/range {v0 .. v7}, Lh2/f5;->a(Li3/c;Ljava/lang/String;Lx2/s;JLl2/o;II)V

    .line 275
    .line 276
    .line 277
    move-object/from16 v18, v5

    .line 278
    .line 279
    invoke-static/range {v18 .. v18}, Llp/nb;->c(Ll2/o;)Lj91/f;

    .line 280
    .line 281
    .line 282
    move-result-object v0

    .line 283
    invoke-virtual {v0}, Lj91/f;->a()Lg4/p0;

    .line 284
    .line 285
    .line 286
    move-result-object v1

    .line 287
    invoke-static/range {v18 .. v18}, Llp/nb;->a(Ll2/o;)Lj91/e;

    .line 288
    .line 289
    .line 290
    move-result-object v0

    .line 291
    invoke-virtual {v0}, Lj91/e;->s()J

    .line 292
    .line 293
    .line 294
    move-result-wide v3

    .line 295
    invoke-static/range {v18 .. v18}, Llp/nb;->b(Ll2/o;)Lj91/c;

    .line 296
    .line 297
    .line 298
    move-result-object v0

    .line 299
    iget v11, v0, Lj91/c;->b:F

    .line 300
    .line 301
    const/4 v14, 0x0

    .line 302
    const/16 v15, 0xe

    .line 303
    .line 304
    const/4 v12, 0x0

    .line 305
    const/4 v13, 0x0

    .line 306
    invoke-static/range {v10 .. v15}, Landroidx/compose/foundation/layout/a;->q(Lx2/s;FFFFI)Lx2/s;

    .line 307
    .line 308
    .line 309
    move-result-object v2

    .line 310
    shr-int/lit8 v0, v22, 0x6

    .line 311
    .line 312
    and-int/lit8 v19, v0, 0xe

    .line 313
    .line 314
    const/16 v20, 0x0

    .line 315
    .line 316
    const v21, 0xfff0

    .line 317
    .line 318
    .line 319
    const-wide/16 v5, 0x0

    .line 320
    .line 321
    const/4 v7, 0x0

    .line 322
    const-wide/16 v8, 0x0

    .line 323
    .line 324
    const/4 v10, 0x0

    .line 325
    const/4 v11, 0x0

    .line 326
    const-wide/16 v12, 0x0

    .line 327
    .line 328
    const/4 v14, 0x0

    .line 329
    const/4 v15, 0x0

    .line 330
    const/16 v16, 0x0

    .line 331
    .line 332
    const/16 v17, 0x0

    .line 333
    .line 334
    move-object/from16 v0, p1

    .line 335
    .line 336
    invoke-static/range {v0 .. v21}, Li91/z3;->d(Ljava/lang/String;Lg4/p0;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZILay0/k;Ll2/o;III)V

    .line 337
    .line 338
    .line 339
    move-object/from16 v5, v18

    .line 340
    .line 341
    const/4 v13, 0x1

    .line 342
    invoke-virtual {v5, v13}, Ll2/t;->q(Z)V

    .line 343
    .line 344
    .line 345
    goto :goto_4

    .line 346
    :cond_6
    move-object v0, v1

    .line 347
    invoke-virtual {v5}, Ll2/t;->R()V

    .line 348
    .line 349
    .line 350
    :goto_4
    invoke-virtual {v5}, Ll2/t;->s()Ll2/u1;

    .line 351
    .line 352
    .line 353
    move-result-object v1

    .line 354
    if-eqz v1, :cond_7

    .line 355
    .line 356
    new-instance v2, Lbk/c;

    .line 357
    .line 358
    const/4 v3, 0x4

    .line 359
    move-object/from16 v4, p0

    .line 360
    .line 361
    move/from16 v5, p3

    .line 362
    .line 363
    invoke-direct {v2, v4, v0, v5, v3}, Lbk/c;-><init>(Ljava/lang/String;Ljava/lang/String;II)V

    .line 364
    .line 365
    .line 366
    iput-object v2, v1, Ll2/u1;->d:Lay0/n;

    .line 367
    .line 368
    :cond_7
    return-void
.end method

.method public static final d(Lm70/p;Lxj0/j;Li91/r2;FLl2/b1;Lk1/z0;Lm70/r;Lay0/a;Lay0/k;Ll2/o;I)V
    .locals 28

    .line 1
    move-object/from16 v1, p0

    .line 2
    .line 3
    move-object/from16 v3, p2

    .line 4
    .line 5
    move-object/from16 v5, p4

    .line 6
    .line 7
    move-object/from16 v6, p5

    .line 8
    .line 9
    move-object/from16 v8, p7

    .line 10
    .line 11
    const-string v0, "trip"

    .line 12
    .line 13
    invoke-static {v1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    const-string v0, "mapTileType"

    .line 17
    .line 18
    move-object/from16 v12, p1

    .line 19
    .line 20
    invoke-static {v12, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 21
    .line 22
    .line 23
    const-string v0, "drawerState"

    .line 24
    .line 25
    invoke-static {v3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 26
    .line 27
    .line 28
    const-string v0, "currentDrawerHeight"

    .line 29
    .line 30
    invoke-static {v5, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 31
    .line 32
    .line 33
    const-string v0, "paddingValues"

    .line 34
    .line 35
    invoke-static {v6, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 36
    .line 37
    .line 38
    const-string v0, "onSelectMapType"

    .line 39
    .line 40
    invoke-static {v8, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 41
    .line 42
    .line 43
    move-object/from16 v11, p9

    .line 44
    .line 45
    check-cast v11, Ll2/t;

    .line 46
    .line 47
    const v0, -0x44017d5b

    .line 48
    .line 49
    .line 50
    invoke-virtual {v11, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 51
    .line 52
    .line 53
    invoke-virtual {v11, v1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 54
    .line 55
    .line 56
    move-result v0

    .line 57
    if-eqz v0, :cond_0

    .line 58
    .line 59
    const/4 v0, 0x4

    .line 60
    goto :goto_0

    .line 61
    :cond_0
    const/4 v0, 0x2

    .line 62
    :goto_0
    or-int v0, p10, v0

    .line 63
    .line 64
    invoke-virtual {v12}, Ljava/lang/Enum;->ordinal()I

    .line 65
    .line 66
    .line 67
    move-result v2

    .line 68
    invoke-virtual {v11, v2}, Ll2/t;->e(I)Z

    .line 69
    .line 70
    .line 71
    move-result v2

    .line 72
    if-eqz v2, :cond_1

    .line 73
    .line 74
    const/16 v2, 0x20

    .line 75
    .line 76
    goto :goto_1

    .line 77
    :cond_1
    const/16 v2, 0x10

    .line 78
    .line 79
    :goto_1
    or-int/2addr v0, v2

    .line 80
    invoke-virtual {v11, v3}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 81
    .line 82
    .line 83
    move-result v2

    .line 84
    if-eqz v2, :cond_2

    .line 85
    .line 86
    const/16 v2, 0x100

    .line 87
    .line 88
    goto :goto_2

    .line 89
    :cond_2
    const/16 v2, 0x80

    .line 90
    .line 91
    :goto_2
    or-int/2addr v0, v2

    .line 92
    invoke-virtual {v11, v6}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 93
    .line 94
    .line 95
    move-result v2

    .line 96
    if-eqz v2, :cond_3

    .line 97
    .line 98
    const/high16 v2, 0x20000

    .line 99
    .line 100
    goto :goto_3

    .line 101
    :cond_3
    const/high16 v2, 0x10000

    .line 102
    .line 103
    :goto_3
    or-int/2addr v0, v2

    .line 104
    move-object/from16 v7, p6

    .line 105
    .line 106
    invoke-virtual {v11, v7}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 107
    .line 108
    .line 109
    move-result v2

    .line 110
    if-eqz v2, :cond_4

    .line 111
    .line 112
    const/high16 v2, 0x100000

    .line 113
    .line 114
    goto :goto_4

    .line 115
    :cond_4
    const/high16 v2, 0x80000

    .line 116
    .line 117
    :goto_4
    or-int/2addr v0, v2

    .line 118
    invoke-virtual {v11, v8}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 119
    .line 120
    .line 121
    move-result v2

    .line 122
    if-eqz v2, :cond_5

    .line 123
    .line 124
    const/high16 v2, 0x800000

    .line 125
    .line 126
    goto :goto_5

    .line 127
    :cond_5
    const/high16 v2, 0x400000

    .line 128
    .line 129
    :goto_5
    or-int/2addr v0, v2

    .line 130
    move-object/from16 v9, p8

    .line 131
    .line 132
    invoke-virtual {v11, v9}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 133
    .line 134
    .line 135
    move-result v2

    .line 136
    if-eqz v2, :cond_6

    .line 137
    .line 138
    const/high16 v2, 0x4000000

    .line 139
    .line 140
    goto :goto_6

    .line 141
    :cond_6
    const/high16 v2, 0x2000000

    .line 142
    .line 143
    :goto_6
    or-int/2addr v0, v2

    .line 144
    const v2, 0x2492493

    .line 145
    .line 146
    .line 147
    and-int/2addr v2, v0

    .line 148
    const v4, 0x2492492

    .line 149
    .line 150
    .line 151
    const/4 v13, 0x0

    .line 152
    if-eq v2, v4, :cond_7

    .line 153
    .line 154
    const/4 v2, 0x1

    .line 155
    goto :goto_7

    .line 156
    :cond_7
    move v2, v13

    .line 157
    :goto_7
    and-int/lit8 v4, v0, 0x1

    .line 158
    .line 159
    invoke-virtual {v11, v4, v2}, Ll2/t;->O(IZ)Z

    .line 160
    .line 161
    .line 162
    move-result v2

    .line 163
    if-eqz v2, :cond_e

    .line 164
    .line 165
    sget-object v2, Lj91/h;->a:Ll2/u2;

    .line 166
    .line 167
    invoke-virtual {v11, v2}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 168
    .line 169
    .line 170
    move-result-object v2

    .line 171
    check-cast v2, Lj91/e;

    .line 172
    .line 173
    invoke-virtual {v2}, Lj91/e;->c()J

    .line 174
    .line 175
    .line 176
    move-result-wide v14

    .line 177
    const v2, 0x3f4ccccd    # 0.8f

    .line 178
    .line 179
    .line 180
    invoke-static {v14, v15, v2}, Le3/s;->b(JF)J

    .line 181
    .line 182
    .line 183
    move-result-wide v17

    .line 184
    sget-wide v19, Le3/s;->h:J

    .line 185
    .line 186
    sget v21, Ln70/m;->a:F

    .line 187
    .line 188
    sget-object v22, Lx2/p;->b:Lx2/p;

    .line 189
    .line 190
    move-object/from16 v16, v22

    .line 191
    .line 192
    invoke-static/range {v16 .. v21}, Lxf0/y1;->B(Lx2/s;JJF)Lx2/s;

    .line 193
    .line 194
    .line 195
    move-result-object v2

    .line 196
    sget-object v4, Lx2/c;->d:Lx2/j;

    .line 197
    .line 198
    invoke-static {v4, v13}, Lk1/n;->d(Lx2/e;Z)Lt3/q0;

    .line 199
    .line 200
    .line 201
    move-result-object v4

    .line 202
    iget-wide v14, v11, Ll2/t;->T:J

    .line 203
    .line 204
    invoke-static {v14, v15}, Ljava/lang/Long;->hashCode(J)I

    .line 205
    .line 206
    .line 207
    move-result v14

    .line 208
    invoke-virtual {v11}, Ll2/t;->m()Ll2/p1;

    .line 209
    .line 210
    .line 211
    move-result-object v15

    .line 212
    invoke-static {v11, v2}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 213
    .line 214
    .line 215
    move-result-object v2

    .line 216
    sget-object v16, Lv3/k;->m1:Lv3/j;

    .line 217
    .line 218
    invoke-virtual/range {v16 .. v16}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 219
    .line 220
    .line 221
    sget-object v10, Lv3/j;->b:Lv3/i;

    .line 222
    .line 223
    invoke-virtual {v11}, Ll2/t;->c0()V

    .line 224
    .line 225
    .line 226
    iget-boolean v13, v11, Ll2/t;->S:Z

    .line 227
    .line 228
    if-eqz v13, :cond_8

    .line 229
    .line 230
    invoke-virtual {v11, v10}, Ll2/t;->l(Lay0/a;)V

    .line 231
    .line 232
    .line 233
    goto :goto_8

    .line 234
    :cond_8
    invoke-virtual {v11}, Ll2/t;->m0()V

    .line 235
    .line 236
    .line 237
    :goto_8
    sget-object v10, Lv3/j;->g:Lv3/h;

    .line 238
    .line 239
    invoke-static {v10, v4, v11}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 240
    .line 241
    .line 242
    sget-object v4, Lv3/j;->f:Lv3/h;

    .line 243
    .line 244
    invoke-static {v4, v15, v11}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 245
    .line 246
    .line 247
    sget-object v4, Lv3/j;->j:Lv3/h;

    .line 248
    .line 249
    iget-boolean v10, v11, Ll2/t;->S:Z

    .line 250
    .line 251
    if-nez v10, :cond_9

    .line 252
    .line 253
    invoke-virtual {v11}, Ll2/t;->L()Ljava/lang/Object;

    .line 254
    .line 255
    .line 256
    move-result-object v10

    .line 257
    invoke-static {v14}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 258
    .line 259
    .line 260
    move-result-object v13

    .line 261
    invoke-static {v10, v13}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 262
    .line 263
    .line 264
    move-result v10

    .line 265
    if-nez v10, :cond_a

    .line 266
    .line 267
    :cond_9
    invoke-static {v14, v11, v14, v4}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 268
    .line 269
    .line 270
    :cond_a
    sget-object v4, Lv3/j;->d:Lv3/h;

    .line 271
    .line 272
    invoke-static {v4, v2, v11}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 273
    .line 274
    .line 275
    const/4 v2, 0x0

    .line 276
    new-array v4, v2, [Ljava/lang/Object;

    .line 277
    .line 278
    new-instance v10, Lbp0/h;

    .line 279
    .line 280
    invoke-direct {v10}, Lbp0/h;-><init>()V

    .line 281
    .line 282
    .line 283
    sget-object v13, Luu/g;->h:Lu2/l;

    .line 284
    .line 285
    invoke-static {v4, v13, v10, v11, v2}, Lu2/m;->d([Ljava/lang/Object;Lu2/k;Lay0/a;Ll2/o;I)Ljava/lang/Object;

    .line 286
    .line 287
    .line 288
    move-result-object v4

    .line 289
    check-cast v4, Luu/g;

    .line 290
    .line 291
    invoke-virtual {v11}, Ll2/t;->L()Ljava/lang/Object;

    .line 292
    .line 293
    .line 294
    move-result-object v10

    .line 295
    sget-object v13, Ll2/n;->a:Ll2/x0;

    .line 296
    .line 297
    if-ne v10, v13, :cond_b

    .line 298
    .line 299
    new-instance v10, Lh2/j8;

    .line 300
    .line 301
    move/from16 v13, p3

    .line 302
    .line 303
    invoke-direct {v10, v13, v3}, Lh2/j8;-><init>(FLi91/r2;)V

    .line 304
    .line 305
    .line 306
    invoke-static {v10}, Ll2/b;->h(Lay0/a;)Ll2/h0;

    .line 307
    .line 308
    .line 309
    move-result-object v10

    .line 310
    invoke-virtual {v11, v10}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 311
    .line 312
    .line 313
    goto :goto_9

    .line 314
    :cond_b
    move/from16 v13, p3

    .line 315
    .line 316
    :goto_9
    check-cast v10, Ll2/t2;

    .line 317
    .line 318
    iget-object v9, v1, Lm70/p;->k:Ljava/lang/Object;

    .line 319
    .line 320
    invoke-interface {v6}, Lk1/z0;->d()F

    .line 321
    .line 322
    .line 323
    move-result v14

    .line 324
    invoke-interface {v10}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 325
    .line 326
    .line 327
    move-result-object v10

    .line 328
    check-cast v10, Lt4/f;

    .line 329
    .line 330
    iget v10, v10, Lt4/f;->d:F

    .line 331
    .line 332
    sget-object v15, Lj91/a;->a:Ll2/u2;

    .line 333
    .line 334
    invoke-virtual {v11, v15}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 335
    .line 336
    .line 337
    move-result-object v16

    .line 338
    move-object/from16 v2, v16

    .line 339
    .line 340
    check-cast v2, Lj91/c;

    .line 341
    .line 342
    iget v2, v2, Lj91/c;->c:F

    .line 343
    .line 344
    invoke-virtual {v11, v15}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 345
    .line 346
    .line 347
    move-result-object v16

    .line 348
    move/from16 v18, v0

    .line 349
    .line 350
    move-object/from16 v0, v16

    .line 351
    .line 352
    check-cast v0, Lj91/c;

    .line 353
    .line 354
    iget v0, v0, Lj91/c;->c:F

    .line 355
    .line 356
    new-instance v1, Lk1/a1;

    .line 357
    .line 358
    invoke-direct {v1, v2, v14, v0, v10}, Lk1/a1;-><init>(FFFF)V

    .line 359
    .line 360
    .line 361
    sget-object v13, Landroidx/compose/foundation/layout/d;->c:Landroidx/compose/foundation/layout/FillElement;

    .line 362
    .line 363
    const v0, 0xe000

    .line 364
    .line 365
    .line 366
    shl-int/lit8 v2, v18, 0x9

    .line 367
    .line 368
    and-int/2addr v0, v2

    .line 369
    const v2, 0x30180

    .line 370
    .line 371
    .line 372
    or-int/2addr v0, v2

    .line 373
    shr-int/lit8 v2, v18, 0x6

    .line 374
    .line 375
    const/high16 v10, 0x380000

    .line 376
    .line 377
    and-int/2addr v10, v2

    .line 378
    or-int/2addr v0, v10

    .line 379
    shl-int/lit8 v10, v18, 0x3

    .line 380
    .line 381
    const/high16 v14, 0x1c00000

    .line 382
    .line 383
    and-int/2addr v10, v14

    .line 384
    or-int/2addr v0, v10

    .line 385
    move-object/from16 v14, p8

    .line 386
    .line 387
    move/from16 v17, v0

    .line 388
    .line 389
    move-object v10, v1

    .line 390
    move-object/from16 v16, v11

    .line 391
    .line 392
    move-object v0, v15

    .line 393
    const/4 v1, 0x1

    .line 394
    move-object v11, v4

    .line 395
    move-object v15, v7

    .line 396
    const/4 v4, 0x0

    .line 397
    invoke-static/range {v9 .. v17}, Ln70/o;->a(Ljava/util/List;Lk1/a1;Luu/g;Lxj0/j;Lx2/s;Lay0/k;Lm70/r;Ll2/o;I)V

    .line 398
    .line 399
    .line 400
    move-object v7, v11

    .line 401
    move-object/from16 v11, v16

    .line 402
    .line 403
    and-int/lit8 v2, v2, 0xe

    .line 404
    .line 405
    or-int/lit8 v2, v2, 0x38

    .line 406
    .line 407
    invoke-static {v3, v5, v7, v11, v2}, Ln70/m;->a(Li91/r2;Ll2/b1;Luu/g;Ll2/o;I)V

    .line 408
    .line 409
    .line 410
    invoke-virtual {v3}, Li91/r2;->c()Li91/s2;

    .line 411
    .line 412
    .line 413
    move-result-object v2

    .line 414
    sget-object v7, Li91/s2;->f:Li91/s2;

    .line 415
    .line 416
    if-eq v2, v7, :cond_d

    .line 417
    .line 418
    const v2, -0x43a7f631

    .line 419
    .line 420
    .line 421
    invoke-virtual {v11, v2}, Ll2/t;->Y(I)V

    .line 422
    .line 423
    .line 424
    invoke-interface {v5}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 425
    .line 426
    .line 427
    move-result-object v2

    .line 428
    check-cast v2, Lt4/f;

    .line 429
    .line 430
    if-eqz v2, :cond_c

    .line 431
    .line 432
    iget v2, v2, Lt4/f;->d:F

    .line 433
    .line 434
    :goto_a
    move/from16 v26, v2

    .line 435
    .line 436
    goto :goto_b

    .line 437
    :cond_c
    int-to-float v2, v4

    .line 438
    goto :goto_a

    .line 439
    :goto_b
    const/16 v27, 0x7

    .line 440
    .line 441
    const/16 v23, 0x0

    .line 442
    .line 443
    const/16 v24, 0x0

    .line 444
    .line 445
    const/16 v25, 0x0

    .line 446
    .line 447
    invoke-static/range {v22 .. v27}, Landroidx/compose/foundation/layout/a;->q(Lx2/s;FFFFI)Lx2/s;

    .line 448
    .line 449
    .line 450
    move-result-object v2

    .line 451
    invoke-virtual {v11, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 452
    .line 453
    .line 454
    move-result-object v0

    .line 455
    check-cast v0, Lj91/c;

    .line 456
    .line 457
    iget v0, v0, Lj91/c;->d:F

    .line 458
    .line 459
    invoke-static {v2, v0}, Landroidx/compose/foundation/layout/a;->m(Lx2/s;F)Lx2/s;

    .line 460
    .line 461
    .line 462
    move-result-object v0

    .line 463
    sget-object v2, Lx2/c;->l:Lx2/j;

    .line 464
    .line 465
    sget-object v7, Landroidx/compose/foundation/layout/b;->a:Landroidx/compose/foundation/layout/b;

    .line 466
    .line 467
    invoke-virtual {v7, v0, v2}, Landroidx/compose/foundation/layout/b;->a(Lx2/s;Lx2/e;)Lx2/s;

    .line 468
    .line 469
    .line 470
    move-result-object v0

    .line 471
    const-string v2, "trip_detail_map_type_button"

    .line 472
    .line 473
    invoke-static {v0, v2}, Lxf0/i0;->I(Lx2/s;Ljava/lang/String;)Lx2/s;

    .line 474
    .line 475
    .line 476
    move-result-object v12

    .line 477
    shr-int/lit8 v0, v18, 0x15

    .line 478
    .line 479
    and-int/lit8 v0, v0, 0xe

    .line 480
    .line 481
    const/16 v9, 0x8

    .line 482
    .line 483
    const v7, 0x7f08041b

    .line 484
    .line 485
    .line 486
    const/4 v13, 0x0

    .line 487
    move-object v10, v8

    .line 488
    move v8, v0

    .line 489
    invoke-static/range {v7 .. v13}, Li91/j0;->i0(IIILay0/a;Ll2/o;Lx2/s;Z)V

    .line 490
    .line 491
    .line 492
    :goto_c
    invoke-virtual {v11, v4}, Ll2/t;->q(Z)V

    .line 493
    .line 494
    .line 495
    goto :goto_d

    .line 496
    :cond_d
    const v0, -0x4454743d

    .line 497
    .line 498
    .line 499
    invoke-virtual {v11, v0}, Ll2/t;->Y(I)V

    .line 500
    .line 501
    .line 502
    goto :goto_c

    .line 503
    :goto_d
    invoke-virtual {v11, v1}, Ll2/t;->q(Z)V

    .line 504
    .line 505
    .line 506
    goto :goto_e

    .line 507
    :cond_e
    invoke-virtual {v11}, Ll2/t;->R()V

    .line 508
    .line 509
    .line 510
    :goto_e
    invoke-virtual {v11}, Ll2/t;->s()Ll2/u1;

    .line 511
    .line 512
    .line 513
    move-result-object v11

    .line 514
    if-eqz v11, :cond_f

    .line 515
    .line 516
    new-instance v0, Ln70/j;

    .line 517
    .line 518
    move-object/from16 v1, p0

    .line 519
    .line 520
    move-object/from16 v2, p1

    .line 521
    .line 522
    move/from16 v4, p3

    .line 523
    .line 524
    move-object/from16 v7, p6

    .line 525
    .line 526
    move-object/from16 v8, p7

    .line 527
    .line 528
    move-object/from16 v9, p8

    .line 529
    .line 530
    move/from16 v10, p10

    .line 531
    .line 532
    invoke-direct/range {v0 .. v10}, Ln70/j;-><init>(Lm70/p;Lxj0/j;Li91/r2;FLl2/b1;Lk1/z0;Lm70/r;Lay0/a;Lay0/k;I)V

    .line 533
    .line 534
    .line 535
    iput-object v0, v11, Ll2/u1;->d:Lay0/n;

    .line 536
    .line 537
    :cond_f
    return-void
.end method

.method public static final e(Ll2/o;I)V
    .locals 18

    .line 1
    move/from16 v0, p1

    .line 2
    .line 3
    move-object/from16 v9, p0

    .line 4
    .line 5
    check-cast v9, Ll2/t;

    .line 6
    .line 7
    const v1, -0x482e86d7

    .line 8
    .line 9
    .line 10
    invoke-virtual {v9, v1}, Ll2/t;->a0(I)Ll2/t;

    .line 11
    .line 12
    .line 13
    const/4 v1, 0x1

    .line 14
    const/4 v2, 0x0

    .line 15
    if-eqz v0, :cond_0

    .line 16
    .line 17
    move v3, v1

    .line 18
    goto :goto_0

    .line 19
    :cond_0
    move v3, v2

    .line 20
    :goto_0
    and-int/lit8 v4, v0, 0x1

    .line 21
    .line 22
    invoke-virtual {v9, v4, v3}, Ll2/t;->O(IZ)Z

    .line 23
    .line 24
    .line 25
    move-result v3

    .line 26
    if-eqz v3, :cond_12

    .line 27
    .line 28
    const v3, -0x6040e0aa

    .line 29
    .line 30
    .line 31
    invoke-virtual {v9, v3}, Ll2/t;->Y(I)V

    .line 32
    .line 33
    .line 34
    invoke-static {v9}, Lq7/a;->a(Ll2/o;)Landroidx/lifecycle/i1;

    .line 35
    .line 36
    .line 37
    move-result-object v3

    .line 38
    if-eqz v3, :cond_11

    .line 39
    .line 40
    invoke-static {v3}, Ljp/ib;->a(Landroidx/lifecycle/i1;)Lp7/c;

    .line 41
    .line 42
    .line 43
    move-result-object v13

    .line 44
    invoke-static {v9}, Lw11/c;->b(Ll2/o;)Lk21/a;

    .line 45
    .line 46
    .line 47
    move-result-object v15

    .line 48
    const-class v4, Lm70/u;

    .line 49
    .line 50
    sget-object v5, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 51
    .line 52
    invoke-virtual {v5, v4}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 53
    .line 54
    .line 55
    move-result-object v10

    .line 56
    invoke-interface {v3}, Landroidx/lifecycle/i1;->getViewModelStore()Landroidx/lifecycle/h1;

    .line 57
    .line 58
    .line 59
    move-result-object v11

    .line 60
    const/4 v12, 0x0

    .line 61
    const/4 v14, 0x0

    .line 62
    const/16 v16, 0x0

    .line 63
    .line 64
    invoke-static/range {v10 .. v16}, Ljp/lb;->a(Lhy0/d;Landroidx/lifecycle/h1;Ljava/lang/String;Lp7/c;Lh21/b;Lk21/a;Lay0/a;)Landroidx/lifecycle/b1;

    .line 65
    .line 66
    .line 67
    move-result-object v3

    .line 68
    invoke-virtual {v9, v2}, Ll2/t;->q(Z)V

    .line 69
    .line 70
    .line 71
    check-cast v3, Lql0/j;

    .line 72
    .line 73
    invoke-static {v3, v9, v2, v1}, Lkp/x5;->b(Lql0/j;Ll2/o;II)V

    .line 74
    .line 75
    .line 76
    move-object v12, v3

    .line 77
    check-cast v12, Lm70/u;

    .line 78
    .line 79
    iget-object v3, v12, Lql0/j;->g:Lyy0/l1;

    .line 80
    .line 81
    const/4 v4, 0x0

    .line 82
    invoke-static {v3, v4, v9, v1}, Ll2/b;->f(Lyy0/a2;Lwy0/c;Ll2/o;I)Ll2/b1;

    .line 83
    .line 84
    .line 85
    move-result-object v3

    .line 86
    invoke-virtual {v9, v12}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 87
    .line 88
    .line 89
    move-result v4

    .line 90
    invoke-virtual {v9}, Ll2/t;->L()Ljava/lang/Object;

    .line 91
    .line 92
    .line 93
    move-result-object v5

    .line 94
    sget-object v6, Ll2/n;->a:Ll2/x0;

    .line 95
    .line 96
    if-nez v4, :cond_1

    .line 97
    .line 98
    if-ne v5, v6, :cond_2

    .line 99
    .line 100
    :cond_1
    new-instance v10, Ln10/b;

    .line 101
    .line 102
    const/16 v16, 0x0

    .line 103
    .line 104
    const/16 v17, 0x9

    .line 105
    .line 106
    const/4 v11, 0x0

    .line 107
    const-class v13, Lm70/u;

    .line 108
    .line 109
    const-string v14, "onBack"

    .line 110
    .line 111
    const-string v15, "onBack()V"

    .line 112
    .line 113
    invoke-direct/range {v10 .. v17}, Ln10/b;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 114
    .line 115
    .line 116
    invoke-virtual {v9, v10}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 117
    .line 118
    .line 119
    move-object v5, v10

    .line 120
    :cond_2
    check-cast v5, Lhy0/g;

    .line 121
    .line 122
    check-cast v5, Lay0/a;

    .line 123
    .line 124
    invoke-static {v2, v5, v9, v2, v1}, Ljp/tb;->a(ZLay0/a;Ll2/o;II)V

    .line 125
    .line 126
    .line 127
    invoke-interface {v3}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 128
    .line 129
    .line 130
    move-result-object v1

    .line 131
    check-cast v1, Lm70/s;

    .line 132
    .line 133
    invoke-virtual {v9, v12}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 134
    .line 135
    .line 136
    move-result v2

    .line 137
    invoke-virtual {v9}, Ll2/t;->L()Ljava/lang/Object;

    .line 138
    .line 139
    .line 140
    move-result-object v3

    .line 141
    if-nez v2, :cond_3

    .line 142
    .line 143
    if-ne v3, v6, :cond_4

    .line 144
    .line 145
    :cond_3
    new-instance v10, Ln10/b;

    .line 146
    .line 147
    const/16 v16, 0x0

    .line 148
    .line 149
    const/16 v17, 0xa

    .line 150
    .line 151
    const/4 v11, 0x0

    .line 152
    const-class v13, Lm70/u;

    .line 153
    .line 154
    const-string v14, "onBack"

    .line 155
    .line 156
    const-string v15, "onBack()V"

    .line 157
    .line 158
    invoke-direct/range {v10 .. v17}, Ln10/b;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 159
    .line 160
    .line 161
    invoke-virtual {v9, v10}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 162
    .line 163
    .line 164
    move-object v3, v10

    .line 165
    :cond_4
    check-cast v3, Lhy0/g;

    .line 166
    .line 167
    move-object v2, v3

    .line 168
    check-cast v2, Lay0/a;

    .line 169
    .line 170
    invoke-virtual {v9, v12}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 171
    .line 172
    .line 173
    move-result v3

    .line 174
    invoke-virtual {v9}, Ll2/t;->L()Ljava/lang/Object;

    .line 175
    .line 176
    .line 177
    move-result-object v4

    .line 178
    if-nez v3, :cond_5

    .line 179
    .line 180
    if-ne v4, v6, :cond_6

    .line 181
    .line 182
    :cond_5
    new-instance v10, Ln10/b;

    .line 183
    .line 184
    const/16 v16, 0x0

    .line 185
    .line 186
    const/16 v17, 0xb

    .line 187
    .line 188
    const/4 v11, 0x0

    .line 189
    const-class v13, Lm70/u;

    .line 190
    .line 191
    const-string v14, "onToggleWaypointsOverview"

    .line 192
    .line 193
    const-string v15, "onToggleWaypointsOverview()V"

    .line 194
    .line 195
    invoke-direct/range {v10 .. v17}, Ln10/b;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 196
    .line 197
    .line 198
    invoke-virtual {v9, v10}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 199
    .line 200
    .line 201
    move-object v4, v10

    .line 202
    :cond_6
    check-cast v4, Lhy0/g;

    .line 203
    .line 204
    move-object v3, v4

    .line 205
    check-cast v3, Lay0/a;

    .line 206
    .line 207
    invoke-virtual {v9, v12}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 208
    .line 209
    .line 210
    move-result v4

    .line 211
    invoke-virtual {v9}, Ll2/t;->L()Ljava/lang/Object;

    .line 212
    .line 213
    .line 214
    move-result-object v5

    .line 215
    if-nez v4, :cond_7

    .line 216
    .line 217
    if-ne v5, v6, :cond_8

    .line 218
    .line 219
    :cond_7
    new-instance v10, Ln10/b;

    .line 220
    .line 221
    const/16 v16, 0x0

    .line 222
    .line 223
    const/16 v17, 0xc

    .line 224
    .line 225
    const/4 v11, 0x0

    .line 226
    const-class v13, Lm70/u;

    .line 227
    .line 228
    const-string v14, "onSelectMapType"

    .line 229
    .line 230
    const-string v15, "onSelectMapType()V"

    .line 231
    .line 232
    invoke-direct/range {v10 .. v17}, Ln10/b;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 233
    .line 234
    .line 235
    invoke-virtual {v9, v10}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 236
    .line 237
    .line 238
    move-object v5, v10

    .line 239
    :cond_8
    check-cast v5, Lhy0/g;

    .line 240
    .line 241
    move-object v4, v5

    .line 242
    check-cast v4, Lay0/a;

    .line 243
    .line 244
    invoke-virtual {v9, v12}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 245
    .line 246
    .line 247
    move-result v5

    .line 248
    invoke-virtual {v9}, Ll2/t;->L()Ljava/lang/Object;

    .line 249
    .line 250
    .line 251
    move-result-object v7

    .line 252
    if-nez v5, :cond_9

    .line 253
    .line 254
    if-ne v7, v6, :cond_a

    .line 255
    .line 256
    :cond_9
    new-instance v10, Ll20/g;

    .line 257
    .line 258
    const/16 v16, 0x0

    .line 259
    .line 260
    const/16 v17, 0x1b

    .line 261
    .line 262
    const/4 v11, 0x1

    .line 263
    const-class v13, Lm70/u;

    .line 264
    .line 265
    const-string v14, "onMapTypeChanged"

    .line 266
    .line 267
    const-string v15, "onMapTypeChanged(Lcz/skodaauto/myskoda/library/map/model/MapTileType;)V"

    .line 268
    .line 269
    invoke-direct/range {v10 .. v17}, Ll20/g;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 270
    .line 271
    .line 272
    invoke-virtual {v9, v10}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 273
    .line 274
    .line 275
    move-object v7, v10

    .line 276
    :cond_a
    check-cast v7, Lhy0/g;

    .line 277
    .line 278
    move-object v5, v7

    .line 279
    check-cast v5, Lay0/k;

    .line 280
    .line 281
    invoke-virtual {v9, v12}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 282
    .line 283
    .line 284
    move-result v7

    .line 285
    invoke-virtual {v9}, Ll2/t;->L()Ljava/lang/Object;

    .line 286
    .line 287
    .line 288
    move-result-object v8

    .line 289
    if-nez v7, :cond_b

    .line 290
    .line 291
    if-ne v8, v6, :cond_c

    .line 292
    .line 293
    :cond_b
    new-instance v10, Ln10/b;

    .line 294
    .line 295
    const/16 v16, 0x0

    .line 296
    .line 297
    const/16 v17, 0xd

    .line 298
    .line 299
    const/4 v11, 0x0

    .line 300
    const-class v13, Lm70/u;

    .line 301
    .line 302
    const-string v14, "onMapTypePickerDismissed"

    .line 303
    .line 304
    const-string v15, "onMapTypePickerDismissed()V"

    .line 305
    .line 306
    invoke-direct/range {v10 .. v17}, Ln10/b;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 307
    .line 308
    .line 309
    invoke-virtual {v9, v10}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 310
    .line 311
    .line 312
    move-object v8, v10

    .line 313
    :cond_c
    check-cast v8, Lhy0/g;

    .line 314
    .line 315
    check-cast v8, Lay0/a;

    .line 316
    .line 317
    invoke-virtual {v9, v12}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 318
    .line 319
    .line 320
    move-result v7

    .line 321
    invoke-virtual {v9}, Ll2/t;->L()Ljava/lang/Object;

    .line 322
    .line 323
    .line 324
    move-result-object v10

    .line 325
    if-nez v7, :cond_d

    .line 326
    .line 327
    if-ne v10, v6, :cond_e

    .line 328
    .line 329
    :cond_d
    new-instance v10, Ll20/g;

    .line 330
    .line 331
    const/16 v16, 0x0

    .line 332
    .line 333
    const/16 v17, 0x1c

    .line 334
    .line 335
    const/4 v11, 0x1

    .line 336
    const-class v13, Lm70/u;

    .line 337
    .line 338
    const-string v14, "onSelectWaypoint"

    .line 339
    .line 340
    const-string v15, "onSelectWaypoint(Lcz/skodaauto/myskoda/feature/remotetripstatistics/presentation/MebTripDetailViewModel$State$Waypoint;)V"

    .line 341
    .line 342
    invoke-direct/range {v10 .. v17}, Ll20/g;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 343
    .line 344
    .line 345
    invoke-virtual {v9, v10}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 346
    .line 347
    .line 348
    :cond_e
    check-cast v10, Lhy0/g;

    .line 349
    .line 350
    move-object v7, v10

    .line 351
    check-cast v7, Lay0/k;

    .line 352
    .line 353
    invoke-virtual {v9, v12}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 354
    .line 355
    .line 356
    move-result v10

    .line 357
    invoke-virtual {v9}, Ll2/t;->L()Ljava/lang/Object;

    .line 358
    .line 359
    .line 360
    move-result-object v11

    .line 361
    if-nez v10, :cond_f

    .line 362
    .line 363
    if-ne v11, v6, :cond_10

    .line 364
    .line 365
    :cond_f
    new-instance v10, Ln10/b;

    .line 366
    .line 367
    const/16 v16, 0x0

    .line 368
    .line 369
    const/16 v17, 0xe

    .line 370
    .line 371
    const/4 v11, 0x0

    .line 372
    const-class v13, Lm70/u;

    .line 373
    .line 374
    const-string v14, "onOpenMaps"

    .line 375
    .line 376
    const-string v15, "onOpenMaps()V"

    .line 377
    .line 378
    invoke-direct/range {v10 .. v17}, Ln10/b;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 379
    .line 380
    .line 381
    invoke-virtual {v9, v10}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 382
    .line 383
    .line 384
    move-object v11, v10

    .line 385
    :cond_10
    check-cast v11, Lhy0/g;

    .line 386
    .line 387
    check-cast v11, Lay0/a;

    .line 388
    .line 389
    const/4 v10, 0x0

    .line 390
    move-object v6, v8

    .line 391
    move-object v8, v11

    .line 392
    invoke-static/range {v1 .. v10}, Ln70/m;->f(Lm70/s;Lay0/a;Lay0/a;Lay0/a;Lay0/k;Lay0/a;Lay0/k;Lay0/a;Ll2/o;I)V

    .line 393
    .line 394
    .line 395
    goto :goto_1

    .line 396
    :cond_11
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 397
    .line 398
    const-string v1, "No ViewModelStoreOwner was provided via LocalViewModelStoreOwner"

    .line 399
    .line 400
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 401
    .line 402
    .line 403
    throw v0

    .line 404
    :cond_12
    invoke-virtual {v9}, Ll2/t;->R()V

    .line 405
    .line 406
    .line 407
    :goto_1
    invoke-virtual {v9}, Ll2/t;->s()Ll2/u1;

    .line 408
    .line 409
    .line 410
    move-result-object v1

    .line 411
    if-eqz v1, :cond_13

    .line 412
    .line 413
    new-instance v2, Lmo0/a;

    .line 414
    .line 415
    const/16 v3, 0x1a

    .line 416
    .line 417
    invoke-direct {v2, v0, v3}, Lmo0/a;-><init>(II)V

    .line 418
    .line 419
    .line 420
    iput-object v2, v1, Ll2/u1;->d:Lay0/n;

    .line 421
    .line 422
    :cond_13
    return-void
.end method

.method public static final f(Lm70/s;Lay0/a;Lay0/a;Lay0/a;Lay0/k;Lay0/a;Lay0/k;Lay0/a;Ll2/o;I)V
    .locals 25

    .line 1
    move-object/from16 v1, p0

    .line 2
    .line 3
    move-object/from16 v9, p1

    .line 4
    .line 5
    const-string v0, "state"

    .line 6
    .line 7
    invoke-static {v1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    move-object/from16 v10, p8

    .line 11
    .line 12
    check-cast v10, Ll2/t;

    .line 13
    .line 14
    const v0, -0x7a9702a4

    .line 15
    .line 16
    .line 17
    invoke-virtual {v10, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 18
    .line 19
    .line 20
    invoke-virtual {v10, v1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 21
    .line 22
    .line 23
    move-result v0

    .line 24
    if-eqz v0, :cond_0

    .line 25
    .line 26
    const/4 v0, 0x4

    .line 27
    goto :goto_0

    .line 28
    :cond_0
    const/4 v0, 0x2

    .line 29
    :goto_0
    or-int v0, p9, v0

    .line 30
    .line 31
    invoke-virtual {v10, v9}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 32
    .line 33
    .line 34
    move-result v2

    .line 35
    if-eqz v2, :cond_1

    .line 36
    .line 37
    const/16 v2, 0x20

    .line 38
    .line 39
    goto :goto_1

    .line 40
    :cond_1
    const/16 v2, 0x10

    .line 41
    .line 42
    :goto_1
    or-int/2addr v0, v2

    .line 43
    move-object/from16 v2, p2

    .line 44
    .line 45
    invoke-virtual {v10, v2}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 46
    .line 47
    .line 48
    move-result v3

    .line 49
    if-eqz v3, :cond_2

    .line 50
    .line 51
    const/16 v3, 0x100

    .line 52
    .line 53
    goto :goto_2

    .line 54
    :cond_2
    const/16 v3, 0x80

    .line 55
    .line 56
    :goto_2
    or-int/2addr v0, v3

    .line 57
    move-object/from16 v3, p3

    .line 58
    .line 59
    invoke-virtual {v10, v3}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 60
    .line 61
    .line 62
    move-result v4

    .line 63
    if-eqz v4, :cond_3

    .line 64
    .line 65
    const/16 v4, 0x800

    .line 66
    .line 67
    goto :goto_3

    .line 68
    :cond_3
    const/16 v4, 0x400

    .line 69
    .line 70
    :goto_3
    or-int/2addr v0, v4

    .line 71
    move-object/from16 v4, p4

    .line 72
    .line 73
    invoke-virtual {v10, v4}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 74
    .line 75
    .line 76
    move-result v5

    .line 77
    if-eqz v5, :cond_4

    .line 78
    .line 79
    const/16 v5, 0x4000

    .line 80
    .line 81
    goto :goto_4

    .line 82
    :cond_4
    const/16 v5, 0x2000

    .line 83
    .line 84
    :goto_4
    or-int/2addr v0, v5

    .line 85
    move-object/from16 v6, p5

    .line 86
    .line 87
    invoke-virtual {v10, v6}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 88
    .line 89
    .line 90
    move-result v5

    .line 91
    if-eqz v5, :cond_5

    .line 92
    .line 93
    const/high16 v5, 0x20000

    .line 94
    .line 95
    goto :goto_5

    .line 96
    :cond_5
    const/high16 v5, 0x10000

    .line 97
    .line 98
    :goto_5
    or-int/2addr v0, v5

    .line 99
    move-object/from16 v7, p6

    .line 100
    .line 101
    invoke-virtual {v10, v7}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 102
    .line 103
    .line 104
    move-result v5

    .line 105
    if-eqz v5, :cond_6

    .line 106
    .line 107
    const/high16 v5, 0x100000

    .line 108
    .line 109
    goto :goto_6

    .line 110
    :cond_6
    const/high16 v5, 0x80000

    .line 111
    .line 112
    :goto_6
    or-int/2addr v0, v5

    .line 113
    move-object/from16 v8, p7

    .line 114
    .line 115
    invoke-virtual {v10, v8}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 116
    .line 117
    .line 118
    move-result v5

    .line 119
    if-eqz v5, :cond_7

    .line 120
    .line 121
    const/high16 v5, 0x800000

    .line 122
    .line 123
    goto :goto_7

    .line 124
    :cond_7
    const/high16 v5, 0x400000

    .line 125
    .line 126
    :goto_7
    or-int/2addr v0, v5

    .line 127
    const v5, 0x492493

    .line 128
    .line 129
    .line 130
    and-int/2addr v5, v0

    .line 131
    const v11, 0x492492

    .line 132
    .line 133
    .line 134
    const/4 v12, 0x0

    .line 135
    const/4 v13, 0x1

    .line 136
    if-eq v5, v11, :cond_8

    .line 137
    .line 138
    move v5, v13

    .line 139
    goto :goto_8

    .line 140
    :cond_8
    move v5, v12

    .line 141
    :goto_8
    and-int/2addr v0, v13

    .line 142
    invoke-virtual {v10, v0, v5}, Ll2/t;->O(IZ)Z

    .line 143
    .line 144
    .line 145
    move-result v0

    .line 146
    if-eqz v0, :cond_a

    .line 147
    .line 148
    invoke-virtual {v10}, Ll2/t;->L()Ljava/lang/Object;

    .line 149
    .line 150
    .line 151
    move-result-object v0

    .line 152
    sget-object v5, Ll2/n;->a:Ll2/x0;

    .line 153
    .line 154
    if-ne v0, v5, :cond_9

    .line 155
    .line 156
    int-to-float v0, v12

    .line 157
    new-instance v5, Lt4/f;

    .line 158
    .line 159
    invoke-direct {v5, v0}, Lt4/f;-><init>(F)V

    .line 160
    .line 161
    .line 162
    invoke-static {v5}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 163
    .line 164
    .line 165
    move-result-object v0

    .line 166
    invoke-virtual {v10, v0}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 167
    .line 168
    .line 169
    :cond_9
    check-cast v0, Ll2/b1;

    .line 170
    .line 171
    new-instance v5, Ln70/i;

    .line 172
    .line 173
    const/4 v11, 0x0

    .line 174
    invoke-direct {v5, v1, v9, v0, v11}, Ln70/i;-><init>(Lm70/s;Lay0/a;Ll2/b1;I)V

    .line 175
    .line 176
    .line 177
    const v11, 0x151b3020

    .line 178
    .line 179
    .line 180
    invoke-static {v11, v10, v5}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 181
    .line 182
    .line 183
    move-result-object v11

    .line 184
    move-object v6, v0

    .line 185
    new-instance v0, Lcv0/c;

    .line 186
    .line 187
    move-object/from16 v5, p5

    .line 188
    .line 189
    invoke-direct/range {v0 .. v8}, Lcv0/c;-><init>(Lm70/s;Lay0/a;Lay0/a;Lay0/k;Lay0/a;Ll2/b1;Lay0/k;Lay0/a;)V

    .line 190
    .line 191
    .line 192
    const v1, -0x753c2695

    .line 193
    .line 194
    .line 195
    invoke-static {v1, v10, v0}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 196
    .line 197
    .line 198
    move-result-object v21

    .line 199
    const v23, 0x30000030

    .line 200
    .line 201
    .line 202
    const/16 v24, 0x1fd

    .line 203
    .line 204
    move-object/from16 v22, v10

    .line 205
    .line 206
    const/4 v10, 0x0

    .line 207
    const/4 v12, 0x0

    .line 208
    const/4 v13, 0x0

    .line 209
    const/4 v14, 0x0

    .line 210
    const/4 v15, 0x0

    .line 211
    const-wide/16 v16, 0x0

    .line 212
    .line 213
    const-wide/16 v18, 0x0

    .line 214
    .line 215
    const/16 v20, 0x0

    .line 216
    .line 217
    invoke-static/range {v10 .. v24}, Lh2/c8;->a(Lx2/s;Lay0/n;Lay0/n;Lay0/n;Lay0/n;IJJLk1/q1;Lay0/o;Ll2/o;II)V

    .line 218
    .line 219
    .line 220
    goto :goto_9

    .line 221
    :cond_a
    move-object/from16 v22, v10

    .line 222
    .line 223
    invoke-virtual/range {v22 .. v22}, Ll2/t;->R()V

    .line 224
    .line 225
    .line 226
    :goto_9
    invoke-virtual/range {v22 .. v22}, Ll2/t;->s()Ll2/u1;

    .line 227
    .line 228
    .line 229
    move-result-object v10

    .line 230
    if-eqz v10, :cond_b

    .line 231
    .line 232
    new-instance v0, Lcz/o;

    .line 233
    .line 234
    move-object/from16 v1, p0

    .line 235
    .line 236
    move-object/from16 v3, p2

    .line 237
    .line 238
    move-object/from16 v4, p3

    .line 239
    .line 240
    move-object/from16 v5, p4

    .line 241
    .line 242
    move-object/from16 v6, p5

    .line 243
    .line 244
    move-object/from16 v7, p6

    .line 245
    .line 246
    move-object/from16 v8, p7

    .line 247
    .line 248
    move-object v2, v9

    .line 249
    move/from16 v9, p9

    .line 250
    .line 251
    invoke-direct/range {v0 .. v9}, Lcz/o;-><init>(Lm70/s;Lay0/a;Lay0/a;Lay0/a;Lay0/k;Lay0/a;Lay0/k;Lay0/a;I)V

    .line 252
    .line 253
    .line 254
    iput-object v0, v10, Ll2/u1;->d:Lay0/n;

    .line 255
    .line 256
    :cond_b
    return-void
.end method

.method public static final g(Llx0/l;Ll2/o;I)V
    .locals 18

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v12, p1

    .line 4
    .line 5
    check-cast v12, Ll2/t;

    .line 6
    .line 7
    const v2, -0x7cf58bb5

    .line 8
    .line 9
    .line 10
    invoke-virtual {v12, v2}, Ll2/t;->a0(I)Ll2/t;

    .line 11
    .line 12
    .line 13
    invoke-virtual {v12, v0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 14
    .line 15
    .line 16
    move-result v2

    .line 17
    const/16 v3, 0x10

    .line 18
    .line 19
    if-eqz v2, :cond_0

    .line 20
    .line 21
    const/16 v2, 0x20

    .line 22
    .line 23
    goto :goto_0

    .line 24
    :cond_0
    move v2, v3

    .line 25
    :goto_0
    or-int v2, p2, v2

    .line 26
    .line 27
    and-int/lit8 v4, v2, 0x11

    .line 28
    .line 29
    const/4 v10, 0x1

    .line 30
    const/4 v11, 0x0

    .line 31
    if-eq v4, v3, :cond_1

    .line 32
    .line 33
    move v3, v10

    .line 34
    goto :goto_1

    .line 35
    :cond_1
    move v3, v11

    .line 36
    :goto_1
    and-int/2addr v2, v10

    .line 37
    invoke-virtual {v12, v2, v3}, Ll2/t;->O(IZ)Z

    .line 38
    .line 39
    .line 40
    move-result v2

    .line 41
    if-eqz v2, :cond_2

    .line 42
    .line 43
    const v2, 0x7f12144e

    .line 44
    .line 45
    .line 46
    invoke-static {v12, v2}, Ljp/ga;->d(Ll2/o;I)Ljava/lang/String;

    .line 47
    .line 48
    .line 49
    move-result-object v2

    .line 50
    sget-object v3, Lj91/j;->a:Ll2/u2;

    .line 51
    .line 52
    invoke-virtual {v12, v3}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 53
    .line 54
    .line 55
    move-result-object v3

    .line 56
    check-cast v3, Lj91/f;

    .line 57
    .line 58
    invoke-virtual {v3}, Lj91/f;->k()Lg4/p0;

    .line 59
    .line 60
    .line 61
    move-result-object v3

    .line 62
    const/16 v8, 0xc00

    .line 63
    .line 64
    const/16 v9, 0x14

    .line 65
    .line 66
    const/4 v4, 0x0

    .line 67
    const-string v5, "trip_detail_odometer_header"

    .line 68
    .line 69
    const/4 v6, 0x0

    .line 70
    move-object v7, v12

    .line 71
    invoke-static/range {v2 .. v9}, Li91/j0;->H(Ljava/lang/String;Lg4/p0;Lx2/s;Ljava/lang/String;Ljava/lang/String;Ll2/o;II)V

    .line 72
    .line 73
    .line 74
    const v2, 0x7f121459

    .line 75
    .line 76
    .line 77
    invoke-static {v12, v2}, Ljp/ga;->d(Ll2/o;I)Ljava/lang/String;

    .line 78
    .line 79
    .line 80
    move-result-object v2

    .line 81
    new-instance v6, Li91/a2;

    .line 82
    .line 83
    iget-object v3, v0, Llx0/l;->d:Ljava/lang/Object;

    .line 84
    .line 85
    check-cast v3, Ljava/lang/String;

    .line 86
    .line 87
    invoke-static {v3}, Lxf0/y1;->I(Ljava/lang/String;)Lg4/g;

    .line 88
    .line 89
    .line 90
    move-result-object v3

    .line 91
    invoke-direct {v6, v3, v11}, Li91/a2;-><init>(Lg4/g;I)V

    .line 92
    .line 93
    .line 94
    const/16 v14, 0x30

    .line 95
    .line 96
    const/16 v15, 0x7ee

    .line 97
    .line 98
    const/4 v3, 0x0

    .line 99
    const/4 v5, 0x0

    .line 100
    const/4 v7, 0x0

    .line 101
    const/4 v8, 0x0

    .line 102
    const/4 v9, 0x0

    .line 103
    move v13, v10

    .line 104
    const/4 v10, 0x0

    .line 105
    move/from16 v16, v11

    .line 106
    .line 107
    const-string v11, "trip_detail_odometer_start"

    .line 108
    .line 109
    move/from16 v17, v13

    .line 110
    .line 111
    const/4 v13, 0x0

    .line 112
    move/from16 v0, v16

    .line 113
    .line 114
    move/from16 v1, v17

    .line 115
    .line 116
    invoke-static/range {v2 .. v15}, Li91/j0;->L(Ljava/lang/String;Lx2/s;Ljava/lang/String;Li91/x1;Li91/v1;ZLi91/t1;Lay0/a;FLjava/lang/String;Ll2/o;III)V

    .line 117
    .line 118
    .line 119
    const/4 v2, 0x0

    .line 120
    invoke-static {v0, v1, v12, v2}, Li91/j0;->D(IILl2/o;Lx2/s;)V

    .line 121
    .line 122
    .line 123
    const v1, 0x7f121458

    .line 124
    .line 125
    .line 126
    invoke-static {v12, v1}, Ljp/ga;->d(Ll2/o;I)Ljava/lang/String;

    .line 127
    .line 128
    .line 129
    move-result-object v2

    .line 130
    new-instance v6, Li91/a2;

    .line 131
    .line 132
    move-object/from16 v1, p0

    .line 133
    .line 134
    iget-object v3, v1, Llx0/l;->e:Ljava/lang/Object;

    .line 135
    .line 136
    check-cast v3, Ljava/lang/String;

    .line 137
    .line 138
    invoke-static {v3}, Lxf0/y1;->I(Ljava/lang/String;)Lg4/g;

    .line 139
    .line 140
    .line 141
    move-result-object v3

    .line 142
    invoke-direct {v6, v3, v0}, Li91/a2;-><init>(Lg4/g;I)V

    .line 143
    .line 144
    .line 145
    const/4 v3, 0x0

    .line 146
    const-string v11, "trip_detail_odometer_end"

    .line 147
    .line 148
    invoke-static/range {v2 .. v15}, Li91/j0;->L(Ljava/lang/String;Lx2/s;Ljava/lang/String;Li91/x1;Li91/v1;ZLi91/t1;Lay0/a;FLjava/lang/String;Ll2/o;III)V

    .line 149
    .line 150
    .line 151
    sget-object v0, Lj91/a;->a:Ll2/u2;

    .line 152
    .line 153
    invoke-virtual {v12, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 154
    .line 155
    .line 156
    move-result-object v0

    .line 157
    check-cast v0, Lj91/c;

    .line 158
    .line 159
    iget v0, v0, Lj91/c;->f:F

    .line 160
    .line 161
    sget-object v2, Lx2/p;->b:Lx2/p;

    .line 162
    .line 163
    invoke-static {v2, v0}, Landroidx/compose/foundation/layout/d;->e(Lx2/s;F)Lx2/s;

    .line 164
    .line 165
    .line 166
    move-result-object v0

    .line 167
    invoke-static {v12, v0}, Lk1/d;->d(Ll2/o;Lx2/s;)V

    .line 168
    .line 169
    .line 170
    goto :goto_2

    .line 171
    :cond_2
    move-object v1, v0

    .line 172
    invoke-virtual {v12}, Ll2/t;->R()V

    .line 173
    .line 174
    .line 175
    :goto_2
    invoke-virtual {v12}, Ll2/t;->s()Ll2/u1;

    .line 176
    .line 177
    .line 178
    move-result-object v0

    .line 179
    if-eqz v0, :cond_3

    .line 180
    .line 181
    new-instance v2, Ln70/k;

    .line 182
    .line 183
    const/4 v3, 0x0

    .line 184
    move/from16 v4, p2

    .line 185
    .line 186
    invoke-direct {v2, v1, v4, v3}, Ln70/k;-><init>(Llx0/l;II)V

    .line 187
    .line 188
    .line 189
    iput-object v2, v0, Ll2/u1;->d:Lay0/n;

    .line 190
    .line 191
    :cond_3
    return-void
.end method

.method public static final h(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ll2/o;I)V
    .locals 21

    .line 1
    move-object/from16 v1, p0

    .line 2
    .line 3
    move-object/from16 v2, p1

    .line 4
    .line 5
    move-object/from16 v3, p2

    .line 6
    .line 7
    const-string v0, "totalConsumption"

    .line 8
    .line 9
    invoke-static {v1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    const-string v0, "avgConsumption"

    .line 13
    .line 14
    invoke-static {v2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    const-string v0, "avgSpeed"

    .line 18
    .line 19
    invoke-static {v3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 20
    .line 21
    .line 22
    move-object/from16 v14, p5

    .line 23
    .line 24
    check-cast v14, Ll2/t;

    .line 25
    .line 26
    const v0, -0x4fbd91bf

    .line 27
    .line 28
    .line 29
    invoke-virtual {v14, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 30
    .line 31
    .line 32
    invoke-virtual {v14, v1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 33
    .line 34
    .line 35
    move-result v0

    .line 36
    if-eqz v0, :cond_0

    .line 37
    .line 38
    const/16 v0, 0x20

    .line 39
    .line 40
    goto :goto_0

    .line 41
    :cond_0
    const/16 v0, 0x10

    .line 42
    .line 43
    :goto_0
    or-int v0, p6, v0

    .line 44
    .line 45
    invoke-virtual {v14, v2}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 46
    .line 47
    .line 48
    move-result v4

    .line 49
    if-eqz v4, :cond_1

    .line 50
    .line 51
    const/16 v4, 0x100

    .line 52
    .line 53
    goto :goto_1

    .line 54
    :cond_1
    const/16 v4, 0x80

    .line 55
    .line 56
    :goto_1
    or-int/2addr v0, v4

    .line 57
    invoke-virtual {v14, v3}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 58
    .line 59
    .line 60
    move-result v4

    .line 61
    if-eqz v4, :cond_2

    .line 62
    .line 63
    const/16 v4, 0x800

    .line 64
    .line 65
    goto :goto_2

    .line 66
    :cond_2
    const/16 v4, 0x400

    .line 67
    .line 68
    :goto_2
    or-int/2addr v0, v4

    .line 69
    move-object/from16 v12, p3

    .line 70
    .line 71
    invoke-virtual {v14, v12}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 72
    .line 73
    .line 74
    move-result v4

    .line 75
    if-eqz v4, :cond_3

    .line 76
    .line 77
    const/16 v4, 0x4000

    .line 78
    .line 79
    goto :goto_3

    .line 80
    :cond_3
    const/16 v4, 0x2000

    .line 81
    .line 82
    :goto_3
    or-int/2addr v0, v4

    .line 83
    move-object/from16 v13, p4

    .line 84
    .line 85
    invoke-virtual {v14, v13}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 86
    .line 87
    .line 88
    move-result v4

    .line 89
    if-eqz v4, :cond_4

    .line 90
    .line 91
    const/high16 v4, 0x20000

    .line 92
    .line 93
    goto :goto_4

    .line 94
    :cond_4
    const/high16 v4, 0x10000

    .line 95
    .line 96
    :goto_4
    or-int/2addr v0, v4

    .line 97
    const v4, 0x12491

    .line 98
    .line 99
    .line 100
    and-int/2addr v4, v0

    .line 101
    const v5, 0x12490

    .line 102
    .line 103
    .line 104
    const/4 v15, 0x1

    .line 105
    const/4 v6, 0x0

    .line 106
    if-eq v4, v5, :cond_5

    .line 107
    .line 108
    move v4, v15

    .line 109
    goto :goto_5

    .line 110
    :cond_5
    move v4, v6

    .line 111
    :goto_5
    and-int/lit8 v5, v0, 0x1

    .line 112
    .line 113
    invoke-virtual {v14, v5, v4}, Ll2/t;->O(IZ)Z

    .line 114
    .line 115
    .line 116
    move-result v4

    .line 117
    if-eqz v4, :cond_6

    .line 118
    .line 119
    const v4, 0x7f12144f

    .line 120
    .line 121
    .line 122
    invoke-static {v14, v4}, Ljp/ga;->d(Ll2/o;I)Ljava/lang/String;

    .line 123
    .line 124
    .line 125
    move-result-object v4

    .line 126
    sget-object v5, Lj91/j;->a:Ll2/u2;

    .line 127
    .line 128
    invoke-virtual {v14, v5}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 129
    .line 130
    .line 131
    move-result-object v5

    .line 132
    check-cast v5, Lj91/f;

    .line 133
    .line 134
    invoke-virtual {v5}, Lj91/f;->k()Lg4/p0;

    .line 135
    .line 136
    .line 137
    move-result-object v5

    .line 138
    const/16 v10, 0xc00

    .line 139
    .line 140
    const/16 v11, 0x14

    .line 141
    .line 142
    move v7, v6

    .line 143
    const/4 v6, 0x0

    .line 144
    move v8, v7

    .line 145
    const-string v7, "trip_detail_overview_header"

    .line 146
    .line 147
    move v9, v8

    .line 148
    const/4 v8, 0x0

    .line 149
    move-object/from16 v20, v14

    .line 150
    .line 151
    move v14, v9

    .line 152
    move-object/from16 v9, v20

    .line 153
    .line 154
    invoke-static/range {v4 .. v11}, Li91/j0;->H(Ljava/lang/String;Lg4/p0;Lx2/s;Ljava/lang/String;Ljava/lang/String;Ll2/o;II)V

    .line 155
    .line 156
    .line 157
    const v4, 0x7f12145a

    .line 158
    .line 159
    .line 160
    invoke-static {v9, v4}, Ljp/ga;->d(Ll2/o;I)Ljava/lang/String;

    .line 161
    .line 162
    .line 163
    move-result-object v4

    .line 164
    new-instance v8, Li91/a2;

    .line 165
    .line 166
    invoke-static {v1}, Lxf0/y1;->I(Ljava/lang/String;)Lg4/g;

    .line 167
    .line 168
    .line 169
    move-result-object v5

    .line 170
    invoke-direct {v8, v5, v14}, Li91/a2;-><init>(Lg4/g;I)V

    .line 171
    .line 172
    .line 173
    const/16 v16, 0x30

    .line 174
    .line 175
    const/16 v17, 0x7ee

    .line 176
    .line 177
    const/4 v5, 0x0

    .line 178
    const/4 v7, 0x0

    .line 179
    move v10, v14

    .line 180
    move-object v14, v9

    .line 181
    const/4 v9, 0x0

    .line 182
    move v11, v10

    .line 183
    const/4 v10, 0x0

    .line 184
    move/from16 v18, v11

    .line 185
    .line 186
    const/4 v11, 0x0

    .line 187
    const/4 v12, 0x0

    .line 188
    const-string v13, "trip_detail_total_battery"

    .line 189
    .line 190
    move/from16 v19, v15

    .line 191
    .line 192
    const/4 v15, 0x0

    .line 193
    move/from16 p5, v0

    .line 194
    .line 195
    move/from16 v1, v18

    .line 196
    .line 197
    move/from16 v0, v19

    .line 198
    .line 199
    invoke-static/range {v4 .. v17}, Li91/j0;->L(Ljava/lang/String;Lx2/s;Ljava/lang/String;Li91/x1;Li91/v1;ZLi91/t1;Lay0/a;FLjava/lang/String;Ll2/o;III)V

    .line 200
    .line 201
    .line 202
    const/4 v4, 0x0

    .line 203
    invoke-static {v1, v0, v14, v4}, Li91/j0;->D(IILl2/o;Lx2/s;)V

    .line 204
    .line 205
    .line 206
    const v5, 0x7f121454

    .line 207
    .line 208
    .line 209
    invoke-static {v14, v5}, Ljp/ga;->d(Ll2/o;I)Ljava/lang/String;

    .line 210
    .line 211
    .line 212
    move-result-object v5

    .line 213
    new-instance v8, Li91/a2;

    .line 214
    .line 215
    invoke-static {v2}, Lxf0/y1;->I(Ljava/lang/String;)Lg4/g;

    .line 216
    .line 217
    .line 218
    move-result-object v6

    .line 219
    invoke-direct {v8, v6, v1}, Li91/a2;-><init>(Lg4/g;I)V

    .line 220
    .line 221
    .line 222
    move-object v6, v4

    .line 223
    move-object v4, v5

    .line 224
    const/4 v5, 0x0

    .line 225
    move-object v7, v6

    .line 226
    const/4 v6, 0x0

    .line 227
    move-object v9, v7

    .line 228
    const/4 v7, 0x0

    .line 229
    move-object v10, v9

    .line 230
    const/4 v9, 0x0

    .line 231
    move-object v11, v10

    .line 232
    const/4 v10, 0x0

    .line 233
    move-object v12, v11

    .line 234
    const/4 v11, 0x0

    .line 235
    move-object v13, v12

    .line 236
    const/4 v12, 0x0

    .line 237
    move-object/from16 v18, v13

    .line 238
    .line 239
    const-string v13, "trip_detail_averagevalues_battery"

    .line 240
    .line 241
    move-object/from16 v2, v18

    .line 242
    .line 243
    invoke-static/range {v4 .. v17}, Li91/j0;->L(Ljava/lang/String;Lx2/s;Ljava/lang/String;Li91/x1;Li91/v1;ZLi91/t1;Lay0/a;FLjava/lang/String;Ll2/o;III)V

    .line 244
    .line 245
    .line 246
    invoke-static {v1, v0, v14, v2}, Li91/j0;->D(IILl2/o;Lx2/s;)V

    .line 247
    .line 248
    .line 249
    const v0, 0x7f121455

    .line 250
    .line 251
    .line 252
    invoke-static {v14, v0}, Ljp/ga;->d(Ll2/o;I)Ljava/lang/String;

    .line 253
    .line 254
    .line 255
    move-result-object v4

    .line 256
    new-instance v8, Li91/a2;

    .line 257
    .line 258
    invoke-static {v3}, Lxf0/y1;->I(Ljava/lang/String;)Lg4/g;

    .line 259
    .line 260
    .line 261
    move-result-object v0

    .line 262
    invoke-direct {v8, v0, v1}, Li91/a2;-><init>(Lg4/g;I)V

    .line 263
    .line 264
    .line 265
    const-string v13, "trip_detail_averagevalues_speed"

    .line 266
    .line 267
    invoke-static/range {v4 .. v17}, Li91/j0;->L(Ljava/lang/String;Lx2/s;Ljava/lang/String;Li91/x1;Li91/v1;ZLi91/t1;Lay0/a;FLjava/lang/String;Ll2/o;III)V

    .line 268
    .line 269
    .line 270
    sget-object v0, Lj91/a;->a:Ll2/u2;

    .line 271
    .line 272
    invoke-virtual {v14, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 273
    .line 274
    .line 275
    move-result-object v1

    .line 276
    check-cast v1, Lj91/c;

    .line 277
    .line 278
    iget v1, v1, Lj91/c;->c:F

    .line 279
    .line 280
    sget-object v2, Lx2/p;->b:Lx2/p;

    .line 281
    .line 282
    invoke-static {v2, v1}, Landroidx/compose/foundation/layout/d;->e(Lx2/s;F)Lx2/s;

    .line 283
    .line 284
    .line 285
    move-result-object v1

    .line 286
    invoke-static {v14, v1}, Lk1/d;->d(Ll2/o;Lx2/s;)V

    .line 287
    .line 288
    .line 289
    sget-object v8, Li91/r0;->f:Li91/r0;

    .line 290
    .line 291
    shr-int/lit8 v1, p5, 0x9

    .line 292
    .line 293
    and-int/lit8 v4, v1, 0x70

    .line 294
    .line 295
    const v5, 0x36000

    .line 296
    .line 297
    .line 298
    or-int/2addr v4, v5

    .line 299
    and-int/lit16 v1, v1, 0x380

    .line 300
    .line 301
    or-int/2addr v1, v4

    .line 302
    const/16 v15, 0xc00

    .line 303
    .line 304
    const/16 v16, 0x1fc9

    .line 305
    .line 306
    const/4 v4, 0x0

    .line 307
    const/4 v9, 0x1

    .line 308
    const-string v12, "trip_detail_disclaimer"

    .line 309
    .line 310
    move-object/from16 v5, p3

    .line 311
    .line 312
    move-object/from16 v6, p4

    .line 313
    .line 314
    move-object v13, v14

    .line 315
    move v14, v1

    .line 316
    invoke-static/range {v4 .. v16}, Li91/d0;->b(Lx2/s;Ljava/lang/String;Ljava/lang/String;Li91/q0;Li91/r0;ZLay0/a;Li91/p0;Ljava/lang/String;Ll2/o;III)V

    .line 317
    .line 318
    .line 319
    move-object v14, v13

    .line 320
    invoke-virtual {v14, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 321
    .line 322
    .line 323
    move-result-object v0

    .line 324
    check-cast v0, Lj91/c;

    .line 325
    .line 326
    iget v0, v0, Lj91/c;->f:F

    .line 327
    .line 328
    invoke-static {v2, v0}, Landroidx/compose/foundation/layout/d;->e(Lx2/s;F)Lx2/s;

    .line 329
    .line 330
    .line 331
    move-result-object v0

    .line 332
    invoke-static {v14, v0}, Lk1/d;->d(Ll2/o;Lx2/s;)V

    .line 333
    .line 334
    .line 335
    goto :goto_6

    .line 336
    :cond_6
    invoke-virtual {v14}, Ll2/t;->R()V

    .line 337
    .line 338
    .line 339
    :goto_6
    invoke-virtual {v14}, Ll2/t;->s()Ll2/u1;

    .line 340
    .line 341
    .line 342
    move-result-object v8

    .line 343
    if-eqz v8, :cond_7

    .line 344
    .line 345
    new-instance v0, Lb10/c;

    .line 346
    .line 347
    const/16 v7, 0x19

    .line 348
    .line 349
    move-object/from16 v1, p0

    .line 350
    .line 351
    move-object/from16 v2, p1

    .line 352
    .line 353
    move-object/from16 v4, p3

    .line 354
    .line 355
    move-object/from16 v5, p4

    .line 356
    .line 357
    move/from16 v6, p6

    .line 358
    .line 359
    invoke-direct/range {v0 .. v7}, Lb10/c;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;II)V

    .line 360
    .line 361
    .line 362
    iput-object v0, v8, Ll2/u1;->d:Lay0/n;

    .line 363
    .line 364
    :cond_7
    return-void
.end method

.method public static final i(Ljava/util/List;ZLay0/a;Lay0/k;Ll2/o;I)V
    .locals 10

    .line 1
    const-string v0, "onToggle"

    .line 2
    .line 3
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    move-object v6, p4

    .line 7
    check-cast v6, Ll2/t;

    .line 8
    .line 9
    const p4, -0x3a055dca

    .line 10
    .line 11
    .line 12
    invoke-virtual {v6, p4}, Ll2/t;->a0(I)Ll2/t;

    .line 13
    .line 14
    .line 15
    and-int/lit8 p4, p5, 0x6

    .line 16
    .line 17
    if-nez p4, :cond_1

    .line 18
    .line 19
    sget-object p4, Lk1/t;->a:Lk1/t;

    .line 20
    .line 21
    invoke-virtual {v6, p4}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 22
    .line 23
    .line 24
    move-result p4

    .line 25
    if-eqz p4, :cond_0

    .line 26
    .line 27
    const/4 p4, 0x4

    .line 28
    goto :goto_0

    .line 29
    :cond_0
    const/4 p4, 0x2

    .line 30
    :goto_0
    or-int/2addr p4, p5

    .line 31
    goto :goto_1

    .line 32
    :cond_1
    move p4, p5

    .line 33
    :goto_1
    and-int/lit8 v0, p5, 0x30

    .line 34
    .line 35
    if-nez v0, :cond_3

    .line 36
    .line 37
    invoke-virtual {v6, p0}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 38
    .line 39
    .line 40
    move-result v0

    .line 41
    if-eqz v0, :cond_2

    .line 42
    .line 43
    const/16 v0, 0x20

    .line 44
    .line 45
    goto :goto_2

    .line 46
    :cond_2
    const/16 v0, 0x10

    .line 47
    .line 48
    :goto_2
    or-int/2addr p4, v0

    .line 49
    :cond_3
    and-int/lit16 v0, p5, 0x180

    .line 50
    .line 51
    if-nez v0, :cond_5

    .line 52
    .line 53
    invoke-virtual {v6, p1}, Ll2/t;->h(Z)Z

    .line 54
    .line 55
    .line 56
    move-result v0

    .line 57
    if-eqz v0, :cond_4

    .line 58
    .line 59
    const/16 v0, 0x100

    .line 60
    .line 61
    goto :goto_3

    .line 62
    :cond_4
    const/16 v0, 0x80

    .line 63
    .line 64
    :goto_3
    or-int/2addr p4, v0

    .line 65
    :cond_5
    and-int/lit16 v0, p5, 0xc00

    .line 66
    .line 67
    const/16 v1, 0x800

    .line 68
    .line 69
    if-nez v0, :cond_7

    .line 70
    .line 71
    invoke-virtual {v6, p2}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 72
    .line 73
    .line 74
    move-result v0

    .line 75
    if-eqz v0, :cond_6

    .line 76
    .line 77
    move v0, v1

    .line 78
    goto :goto_4

    .line 79
    :cond_6
    const/16 v0, 0x400

    .line 80
    .line 81
    :goto_4
    or-int/2addr p4, v0

    .line 82
    :cond_7
    and-int/lit16 v0, p5, 0x6000

    .line 83
    .line 84
    if-nez v0, :cond_9

    .line 85
    .line 86
    invoke-virtual {v6, p3}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 87
    .line 88
    .line 89
    move-result v0

    .line 90
    if-eqz v0, :cond_8

    .line 91
    .line 92
    const/16 v0, 0x4000

    .line 93
    .line 94
    goto :goto_5

    .line 95
    :cond_8
    const/16 v0, 0x2000

    .line 96
    .line 97
    :goto_5
    or-int/2addr p4, v0

    .line 98
    :cond_9
    and-int/lit16 v0, p4, 0x2493

    .line 99
    .line 100
    const/16 v2, 0x2492

    .line 101
    .line 102
    const/4 v3, 0x0

    .line 103
    const/4 v4, 0x1

    .line 104
    if-eq v0, v2, :cond_a

    .line 105
    .line 106
    move v0, v4

    .line 107
    goto :goto_6

    .line 108
    :cond_a
    move v0, v3

    .line 109
    :goto_6
    and-int/lit8 v2, p4, 0x1

    .line 110
    .line 111
    invoke-virtual {v6, v2, v0}, Ll2/t;->O(IZ)Z

    .line 112
    .line 113
    .line 114
    move-result v0

    .line 115
    if-eqz v0, :cond_10

    .line 116
    .line 117
    const v0, 0x7f12144c

    .line 118
    .line 119
    .line 120
    invoke-static {v6, v0}, Ljp/ga;->d(Ll2/o;I)Ljava/lang/String;

    .line 121
    .line 122
    .line 123
    move-result-object v5

    .line 124
    const v0, 0x7f08033d

    .line 125
    .line 126
    .line 127
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 128
    .line 129
    .line 130
    move-result-object v0

    .line 131
    if-eqz p1, :cond_b

    .line 132
    .line 133
    goto :goto_7

    .line 134
    :cond_b
    const/4 v0, 0x0

    .line 135
    :goto_7
    if-eqz v0, :cond_c

    .line 136
    .line 137
    invoke-virtual {v0}, Ljava/lang/Integer;->intValue()I

    .line 138
    .line 139
    .line 140
    move-result v0

    .line 141
    goto :goto_8

    .line 142
    :cond_c
    const v0, 0x7f080333

    .line 143
    .line 144
    .line 145
    :goto_8
    sget-object v2, Lj91/a;->a:Ll2/u2;

    .line 146
    .line 147
    invoke-virtual {v6, v2}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 148
    .line 149
    .line 150
    move-result-object v2

    .line 151
    check-cast v2, Lj91/c;

    .line 152
    .line 153
    iget v2, v2, Lj91/c;->c:F

    .line 154
    .line 155
    sget-object v7, Lx2/p;->b:Lx2/p;

    .line 156
    .line 157
    const/4 v8, 0x0

    .line 158
    invoke-static {v7, v8, v2, v4}, Landroidx/compose/foundation/layout/a;->o(Lx2/s;FFI)Lx2/s;

    .line 159
    .line 160
    .line 161
    move-result-object v2

    .line 162
    const-string v7, "trip_detail_waypoints_show_all"

    .line 163
    .line 164
    invoke-static {v2, v7}, Landroidx/compose/ui/platform/a;->a(Lx2/s;Ljava/lang/String;)Lx2/s;

    .line 165
    .line 166
    .line 167
    move-result-object v7

    .line 168
    and-int/lit16 v2, p4, 0x1c00

    .line 169
    .line 170
    if-ne v2, v1, :cond_d

    .line 171
    .line 172
    move v3, v4

    .line 173
    :cond_d
    invoke-virtual {v6}, Ll2/t;->L()Ljava/lang/Object;

    .line 174
    .line 175
    .line 176
    move-result-object v1

    .line 177
    if-nez v3, :cond_e

    .line 178
    .line 179
    sget-object v2, Ll2/n;->a:Ll2/x0;

    .line 180
    .line 181
    if-ne v1, v2, :cond_f

    .line 182
    .line 183
    :cond_e
    new-instance v1, Lha0/f;

    .line 184
    .line 185
    const/16 v2, 0x14

    .line 186
    .line 187
    invoke-direct {v1, p2, v2}, Lha0/f;-><init>(Lay0/a;I)V

    .line 188
    .line 189
    .line 190
    invoke-virtual {v6, v1}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 191
    .line 192
    .line 193
    :cond_f
    move-object v3, v1

    .line 194
    check-cast v3, Lay0/a;

    .line 195
    .line 196
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 197
    .line 198
    .line 199
    move-result-object v4

    .line 200
    const/4 v1, 0x0

    .line 201
    const/16 v2, 0x8

    .line 202
    .line 203
    const/4 v8, 0x0

    .line 204
    invoke-static/range {v1 .. v8}, Li91/j0;->w0(IILay0/a;Ljava/lang/Integer;Ljava/lang/String;Ll2/o;Lx2/s;Z)V

    .line 205
    .line 206
    .line 207
    new-instance v0, Li50/j;

    .line 208
    .line 209
    const/16 v1, 0x12

    .line 210
    .line 211
    invoke-direct {v0, v1, p0, p3}, Li50/j;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 212
    .line 213
    .line 214
    const v1, -0x573ac9a2

    .line 215
    .line 216
    .line 217
    invoke-static {v1, v6, v0}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 218
    .line 219
    .line 220
    move-result-object v0

    .line 221
    and-int/lit8 v1, p4, 0xe

    .line 222
    .line 223
    const/high16 v2, 0x180000

    .line 224
    .line 225
    or-int/2addr v1, v2

    .line 226
    shr-int/lit8 p4, p4, 0x3

    .line 227
    .line 228
    and-int/lit8 p4, p4, 0x70

    .line 229
    .line 230
    or-int v8, v1, p4

    .line 231
    .line 232
    const/16 v9, 0x1e

    .line 233
    .line 234
    const/4 v2, 0x0

    .line 235
    const/4 v3, 0x0

    .line 236
    const/4 v4, 0x0

    .line 237
    const/4 v5, 0x0

    .line 238
    move v1, p1

    .line 239
    move-object v7, v6

    .line 240
    move-object v6, v0

    .line 241
    invoke-static/range {v1 .. v9}, Landroidx/compose/animation/b;->e(ZLx2/s;Lb1/t0;Lb1/u0;Ljava/lang/String;Lt2/b;Ll2/o;II)V

    .line 242
    .line 243
    .line 244
    move-object v6, v7

    .line 245
    goto :goto_9

    .line 246
    :cond_10
    move v1, p1

    .line 247
    invoke-virtual {v6}, Ll2/t;->R()V

    .line 248
    .line 249
    .line 250
    :goto_9
    invoke-virtual {v6}, Ll2/t;->s()Ll2/u1;

    .line 251
    .line 252
    .line 253
    move-result-object v0

    .line 254
    if-eqz v0, :cond_11

    .line 255
    .line 256
    move-object p1, p0

    .line 257
    new-instance p0, Lbl/d;

    .line 258
    .line 259
    move-object p4, p3

    .line 260
    move-object p3, p2

    .line 261
    move p2, v1

    .line 262
    invoke-direct/range {p0 .. p5}, Lbl/d;-><init>(Ljava/util/List;ZLay0/a;Lay0/k;I)V

    .line 263
    .line 264
    .line 265
    iput-object p0, v0, Ll2/u1;->d:Lay0/n;

    .line 266
    .line 267
    :cond_11
    return-void
.end method

.method public static final j(Ljava/lang/String;Lay0/a;Ll2/b1;Ll2/o;I)V
    .locals 11

    .line 1
    const-string v0, "onBack"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "topBarHeight"

    .line 7
    .line 8
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    move-object v8, p3

    .line 12
    check-cast v8, Ll2/t;

    .line 13
    .line 14
    const p3, 0x5d6c91d

    .line 15
    .line 16
    .line 17
    invoke-virtual {v8, p3}, Ll2/t;->a0(I)Ll2/t;

    .line 18
    .line 19
    .line 20
    invoke-virtual {v8, p0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 21
    .line 22
    .line 23
    move-result p3

    .line 24
    if-eqz p3, :cond_0

    .line 25
    .line 26
    const/4 p3, 0x4

    .line 27
    goto :goto_0

    .line 28
    :cond_0
    const/4 p3, 0x2

    .line 29
    :goto_0
    or-int/2addr p3, p4

    .line 30
    invoke-virtual {v8, p1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 31
    .line 32
    .line 33
    move-result v0

    .line 34
    if-eqz v0, :cond_1

    .line 35
    .line 36
    const/16 v0, 0x20

    .line 37
    .line 38
    goto :goto_1

    .line 39
    :cond_1
    const/16 v0, 0x10

    .line 40
    .line 41
    :goto_1
    or-int/2addr p3, v0

    .line 42
    and-int/lit16 v0, p3, 0x93

    .line 43
    .line 44
    const/16 v1, 0x92

    .line 45
    .line 46
    const/4 v2, 0x1

    .line 47
    if-eq v0, v1, :cond_2

    .line 48
    .line 49
    move v0, v2

    .line 50
    goto :goto_2

    .line 51
    :cond_2
    const/4 v0, 0x0

    .line 52
    :goto_2
    and-int/2addr p3, v2

    .line 53
    invoke-virtual {v8, p3, v0}, Ll2/t;->O(IZ)Z

    .line 54
    .line 55
    .line 56
    move-result p3

    .line 57
    if-eqz p3, :cond_5

    .line 58
    .line 59
    if-nez p0, :cond_3

    .line 60
    .line 61
    const-string p3, ""

    .line 62
    .line 63
    move-object v2, p3

    .line 64
    goto :goto_3

    .line 65
    :cond_3
    move-object v2, p0

    .line 66
    :goto_3
    new-instance v4, Li91/w2;

    .line 67
    .line 68
    const/4 p3, 0x3

    .line 69
    invoke-direct {v4, p1, p3}, Li91/w2;-><init>(Lay0/a;I)V

    .line 70
    .line 71
    .line 72
    invoke-virtual {v8}, Ll2/t;->L()Ljava/lang/Object;

    .line 73
    .line 74
    .line 75
    move-result-object p3

    .line 76
    sget-object v0, Ll2/n;->a:Ll2/x0;

    .line 77
    .line 78
    if-ne p3, v0, :cond_4

    .line 79
    .line 80
    new-instance p3, Lle/b;

    .line 81
    .line 82
    const/4 v0, 0x1

    .line 83
    invoke-direct {p3, p2, v0}, Lle/b;-><init>(Ll2/b1;I)V

    .line 84
    .line 85
    .line 86
    invoke-virtual {v8, p3}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 87
    .line 88
    .line 89
    :cond_4
    check-cast p3, Lay0/k;

    .line 90
    .line 91
    sget-object v0, Lx2/p;->b:Lx2/p;

    .line 92
    .line 93
    invoke-static {v0, p3}, Landroidx/compose/ui/layout/a;->d(Lx2/s;Lay0/k;)Lx2/s;

    .line 94
    .line 95
    .line 96
    move-result-object v1

    .line 97
    const/high16 v9, 0x6000000

    .line 98
    .line 99
    const/16 v10, 0x2bc

    .line 100
    .line 101
    const/4 v3, 0x0

    .line 102
    const/4 v5, 0x0

    .line 103
    const/4 v6, 0x1

    .line 104
    const/4 v7, 0x0

    .line 105
    invoke-static/range {v1 .. v10}, Li91/o4;->b(Lx2/s;Ljava/lang/String;Ljava/lang/String;Landroidx/datastore/preferences/protobuf/k;Ljava/util/List;ZLay0/a;Ll2/o;II)V

    .line 106
    .line 107
    .line 108
    goto :goto_4

    .line 109
    :cond_5
    invoke-virtual {v8}, Ll2/t;->R()V

    .line 110
    .line 111
    .line 112
    :goto_4
    invoke-virtual {v8}, Ll2/t;->s()Ll2/u1;

    .line 113
    .line 114
    .line 115
    move-result-object p3

    .line 116
    if-eqz p3, :cond_6

    .line 117
    .line 118
    new-instance v0, Li91/k3;

    .line 119
    .line 120
    const/16 v2, 0xf

    .line 121
    .line 122
    move-object v3, p0

    .line 123
    move-object v4, p1

    .line 124
    move-object v5, p2

    .line 125
    move v1, p4

    .line 126
    invoke-direct/range {v0 .. v5}, Li91/k3;-><init>(IILjava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)V

    .line 127
    .line 128
    .line 129
    iput-object v0, p3, Ll2/u1;->d:Lay0/n;

    .line 130
    .line 131
    :cond_6
    return-void
.end method

.method public static final k(Lm70/p;ZLay0/a;Lay0/k;Ll2/o;I)V
    .locals 13

    .line 1
    const-string v0, "trip"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "onToggleWaypointsOverview"

    .line 7
    .line 8
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    move-object/from16 v5, p4

    .line 12
    .line 13
    check-cast v5, Ll2/t;

    .line 14
    .line 15
    const v0, 0x1a422b7d

    .line 16
    .line 17
    .line 18
    invoke-virtual {v5, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 19
    .line 20
    .line 21
    invoke-virtual {v5, p0}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 22
    .line 23
    .line 24
    move-result v0

    .line 25
    const/4 v1, 0x2

    .line 26
    if-eqz v0, :cond_0

    .line 27
    .line 28
    const/4 v0, 0x4

    .line 29
    goto :goto_0

    .line 30
    :cond_0
    move v0, v1

    .line 31
    :goto_0
    or-int v0, p5, v0

    .line 32
    .line 33
    invoke-virtual {v5, p1}, Ll2/t;->h(Z)Z

    .line 34
    .line 35
    .line 36
    move-result v2

    .line 37
    if-eqz v2, :cond_1

    .line 38
    .line 39
    const/16 v2, 0x20

    .line 40
    .line 41
    goto :goto_1

    .line 42
    :cond_1
    const/16 v2, 0x10

    .line 43
    .line 44
    :goto_1
    or-int/2addr v0, v2

    .line 45
    invoke-virtual {v5, p2}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 46
    .line 47
    .line 48
    move-result v2

    .line 49
    if-eqz v2, :cond_2

    .line 50
    .line 51
    const/16 v2, 0x100

    .line 52
    .line 53
    goto :goto_2

    .line 54
    :cond_2
    const/16 v2, 0x80

    .line 55
    .line 56
    :goto_2
    or-int/2addr v0, v2

    .line 57
    move-object/from16 v10, p3

    .line 58
    .line 59
    invoke-virtual {v5, v10}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 60
    .line 61
    .line 62
    move-result v2

    .line 63
    if-eqz v2, :cond_3

    .line 64
    .line 65
    const/16 v2, 0x800

    .line 66
    .line 67
    goto :goto_3

    .line 68
    :cond_3
    const/16 v2, 0x400

    .line 69
    .line 70
    :goto_3
    or-int/2addr v0, v2

    .line 71
    and-int/lit16 v2, v0, 0x493

    .line 72
    .line 73
    const/16 v3, 0x492

    .line 74
    .line 75
    const/4 v4, 0x0

    .line 76
    const/4 v8, 0x1

    .line 77
    if-eq v2, v3, :cond_4

    .line 78
    .line 79
    move v2, v8

    .line 80
    goto :goto_4

    .line 81
    :cond_4
    move v2, v4

    .line 82
    :goto_4
    and-int/lit8 v3, v0, 0x1

    .line 83
    .line 84
    invoke-virtual {v5, v3, v2}, Ll2/t;->O(IZ)Z

    .line 85
    .line 86
    .line 87
    move-result v2

    .line 88
    if-eqz v2, :cond_8

    .line 89
    .line 90
    sget-object v2, Lj91/a;->a:Ll2/u2;

    .line 91
    .line 92
    invoke-virtual {v5, v2}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 93
    .line 94
    .line 95
    move-result-object v2

    .line 96
    check-cast v2, Lj91/c;

    .line 97
    .line 98
    iget v2, v2, Lj91/c;->j:F

    .line 99
    .line 100
    const/4 v3, 0x0

    .line 101
    sget-object v6, Lx2/p;->b:Lx2/p;

    .line 102
    .line 103
    invoke-static {v6, v2, v3, v1}, Landroidx/compose/foundation/layout/a;->o(Lx2/s;FFI)Lx2/s;

    .line 104
    .line 105
    .line 106
    move-result-object v1

    .line 107
    sget-object v2, Lk1/j;->c:Lk1/e;

    .line 108
    .line 109
    sget-object v3, Lx2/c;->p:Lx2/h;

    .line 110
    .line 111
    invoke-static {v2, v3, v5, v4}, Lk1/r;->a(Lk1/i;Lx2/d;Ll2/o;I)Lk1/s;

    .line 112
    .line 113
    .line 114
    move-result-object v2

    .line 115
    iget-wide v3, v5, Ll2/t;->T:J

    .line 116
    .line 117
    invoke-static {v3, v4}, Ljava/lang/Long;->hashCode(J)I

    .line 118
    .line 119
    .line 120
    move-result v3

    .line 121
    invoke-virtual {v5}, Ll2/t;->m()Ll2/p1;

    .line 122
    .line 123
    .line 124
    move-result-object v4

    .line 125
    invoke-static {v5, v1}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 126
    .line 127
    .line 128
    move-result-object v1

    .line 129
    sget-object v6, Lv3/k;->m1:Lv3/j;

    .line 130
    .line 131
    invoke-virtual {v6}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 132
    .line 133
    .line 134
    sget-object v6, Lv3/j;->b:Lv3/i;

    .line 135
    .line 136
    invoke-virtual {v5}, Ll2/t;->c0()V

    .line 137
    .line 138
    .line 139
    iget-boolean v7, v5, Ll2/t;->S:Z

    .line 140
    .line 141
    if-eqz v7, :cond_5

    .line 142
    .line 143
    invoke-virtual {v5, v6}, Ll2/t;->l(Lay0/a;)V

    .line 144
    .line 145
    .line 146
    goto :goto_5

    .line 147
    :cond_5
    invoke-virtual {v5}, Ll2/t;->m0()V

    .line 148
    .line 149
    .line 150
    :goto_5
    sget-object v6, Lv3/j;->g:Lv3/h;

    .line 151
    .line 152
    invoke-static {v6, v2, v5}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 153
    .line 154
    .line 155
    sget-object v2, Lv3/j;->f:Lv3/h;

    .line 156
    .line 157
    invoke-static {v2, v4, v5}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 158
    .line 159
    .line 160
    sget-object v2, Lv3/j;->j:Lv3/h;

    .line 161
    .line 162
    iget-boolean v4, v5, Ll2/t;->S:Z

    .line 163
    .line 164
    if-nez v4, :cond_6

    .line 165
    .line 166
    invoke-virtual {v5}, Ll2/t;->L()Ljava/lang/Object;

    .line 167
    .line 168
    .line 169
    move-result-object v4

    .line 170
    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 171
    .line 172
    .line 173
    move-result-object v6

    .line 174
    invoke-static {v4, v6}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 175
    .line 176
    .line 177
    move-result v4

    .line 178
    if-nez v4, :cond_7

    .line 179
    .line 180
    :cond_6
    invoke-static {v3, v5, v3, v2}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 181
    .line 182
    .line 183
    :cond_7
    sget-object v2, Lv3/j;->d:Lv3/h;

    .line 184
    .line 185
    invoke-static {v2, v1, v5}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 186
    .line 187
    .line 188
    iget-object v1, p0, Lm70/p;->b:Ljava/lang/String;

    .line 189
    .line 190
    iget-object v2, p0, Lm70/p;->c:Ljava/lang/String;

    .line 191
    .line 192
    const/4 v7, 0x6

    .line 193
    invoke-static {v1, v2, v5, v7}, Ln70/m;->c(Ljava/lang/String;Ljava/lang/String;Ll2/o;I)V

    .line 194
    .line 195
    .line 196
    iget-object v1, p0, Lm70/p;->k:Ljava/lang/Object;

    .line 197
    .line 198
    shl-int/lit8 v0, v0, 0x3

    .line 199
    .line 200
    and-int/lit16 v2, v0, 0x380

    .line 201
    .line 202
    or-int/2addr v2, v7

    .line 203
    and-int/lit16 v3, v0, 0x1c00

    .line 204
    .line 205
    or-int/2addr v2, v3

    .line 206
    const v3, 0xe000

    .line 207
    .line 208
    .line 209
    and-int/2addr v0, v3

    .line 210
    or-int v6, v2, v0

    .line 211
    .line 212
    move v2, p1

    .line 213
    move-object v3, p2

    .line 214
    move-object v4, v10

    .line 215
    invoke-static/range {v1 .. v6}, Ln70/m;->i(Ljava/util/List;ZLay0/a;Lay0/k;Ll2/o;I)V

    .line 216
    .line 217
    .line 218
    iget-object v1, p0, Lm70/p;->d:Ljava/lang/String;

    .line 219
    .line 220
    iget-object v2, p0, Lm70/p;->e:Ljava/lang/String;

    .line 221
    .line 222
    iget-object v3, p0, Lm70/p;->f:Ljava/lang/String;

    .line 223
    .line 224
    iget-object v4, p0, Lm70/p;->g:Ljava/lang/String;

    .line 225
    .line 226
    move-object v6, v5

    .line 227
    iget-object v5, p0, Lm70/p;->h:Ljava/lang/String;

    .line 228
    .line 229
    invoke-static/range {v1 .. v7}, Ln70/m;->h(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ll2/o;I)V

    .line 230
    .line 231
    .line 232
    move-object v5, v6

    .line 233
    iget-object v0, p0, Lm70/p;->i:Llx0/l;

    .line 234
    .line 235
    invoke-static {v0, v5, v7}, Ln70/m;->b(Llx0/l;Ll2/o;I)V

    .line 236
    .line 237
    .line 238
    iget-object v0, p0, Lm70/p;->j:Llx0/l;

    .line 239
    .line 240
    invoke-static {v0, v5, v7}, Ln70/m;->g(Llx0/l;Ll2/o;I)V

    .line 241
    .line 242
    .line 243
    invoke-virtual {v5, v8}, Ll2/t;->q(Z)V

    .line 244
    .line 245
    .line 246
    goto :goto_6

    .line 247
    :cond_8
    invoke-virtual {v5}, Ll2/t;->R()V

    .line 248
    .line 249
    .line 250
    :goto_6
    invoke-virtual {v5}, Ll2/t;->s()Ll2/u1;

    .line 251
    .line 252
    .line 253
    move-result-object v0

    .line 254
    if-eqz v0, :cond_9

    .line 255
    .line 256
    new-instance v6, Lb71/l;

    .line 257
    .line 258
    const/16 v12, 0x9

    .line 259
    .line 260
    move-object v7, p0

    .line 261
    move v8, p1

    .line 262
    move-object v9, p2

    .line 263
    move-object/from16 v10, p3

    .line 264
    .line 265
    move/from16 v11, p5

    .line 266
    .line 267
    invoke-direct/range {v6 .. v12}, Lb71/l;-><init>(Ljava/lang/Object;ZLay0/a;Ljava/lang/Object;II)V

    .line 268
    .line 269
    .line 270
    iput-object v6, v0, Ll2/u1;->d:Lay0/n;

    .line 271
    .line 272
    :cond_9
    return-void
.end method
