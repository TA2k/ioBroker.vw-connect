.class public abstract Lkp/h0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Lx2/s;Ljava/lang/String;ZLh71/w;Le71/a;Lay0/a;Ll2/o;II)V
    .locals 13

    .line 1
    move-object/from16 v4, p3

    .line 2
    .line 3
    move-object/from16 v7, p5

    .line 4
    .line 5
    move/from16 v12, p7

    .line 6
    .line 7
    const-string v0, "modifier"

    .line 8
    .line 9
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    const-string v0, "colors"

    .line 13
    .line 14
    invoke-static {v4, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    const-string v0, "onClick"

    .line 18
    .line 19
    invoke-static {v7, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 20
    .line 21
    .line 22
    move-object/from16 v9, p6

    .line 23
    .line 24
    check-cast v9, Ll2/t;

    .line 25
    .line 26
    const v0, -0x613e0a14

    .line 27
    .line 28
    .line 29
    invoke-virtual {v9, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 30
    .line 31
    .line 32
    and-int/lit8 v0, v12, 0x6

    .line 33
    .line 34
    if-nez v0, :cond_1

    .line 35
    .line 36
    invoke-virtual {v9, p0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 37
    .line 38
    .line 39
    move-result v0

    .line 40
    if-eqz v0, :cond_0

    .line 41
    .line 42
    const/4 v0, 0x4

    .line 43
    goto :goto_0

    .line 44
    :cond_0
    const/4 v0, 0x2

    .line 45
    :goto_0
    or-int/2addr v0, v12

    .line 46
    goto :goto_1

    .line 47
    :cond_1
    move v0, v12

    .line 48
    :goto_1
    or-int/lit8 v0, v0, 0x30

    .line 49
    .line 50
    and-int/lit16 v1, v12, 0x180

    .line 51
    .line 52
    if-nez v1, :cond_3

    .line 53
    .line 54
    invoke-virtual {v9, p1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 55
    .line 56
    .line 57
    move-result v1

    .line 58
    if-eqz v1, :cond_2

    .line 59
    .line 60
    const/16 v1, 0x100

    .line 61
    .line 62
    goto :goto_2

    .line 63
    :cond_2
    const/16 v1, 0x80

    .line 64
    .line 65
    :goto_2
    or-int/2addr v0, v1

    .line 66
    :cond_3
    and-int/lit8 v1, p8, 0x8

    .line 67
    .line 68
    if-eqz v1, :cond_4

    .line 69
    .line 70
    or-int/lit16 v0, v0, 0xc00

    .line 71
    .line 72
    goto :goto_4

    .line 73
    :cond_4
    and-int/lit16 v2, v12, 0xc00

    .line 74
    .line 75
    if-nez v2, :cond_6

    .line 76
    .line 77
    invoke-virtual {v9, p2}, Ll2/t;->h(Z)Z

    .line 78
    .line 79
    .line 80
    move-result v3

    .line 81
    if-eqz v3, :cond_5

    .line 82
    .line 83
    const/16 v3, 0x800

    .line 84
    .line 85
    goto :goto_3

    .line 86
    :cond_5
    const/16 v3, 0x400

    .line 87
    .line 88
    :goto_3
    or-int/2addr v0, v3

    .line 89
    :cond_6
    :goto_4
    and-int/lit16 v3, v12, 0x6000

    .line 90
    .line 91
    if-nez v3, :cond_8

    .line 92
    .line 93
    invoke-virtual {v9, v4}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 94
    .line 95
    .line 96
    move-result v3

    .line 97
    if-eqz v3, :cond_7

    .line 98
    .line 99
    const/16 v3, 0x4000

    .line 100
    .line 101
    goto :goto_5

    .line 102
    :cond_7
    const/16 v3, 0x2000

    .line 103
    .line 104
    :goto_5
    or-int/2addr v0, v3

    .line 105
    :cond_8
    const/high16 v3, 0x30000

    .line 106
    .line 107
    and-int/2addr v3, v12

    .line 108
    if-nez v3, :cond_9

    .line 109
    .line 110
    const/high16 v3, 0x10000

    .line 111
    .line 112
    or-int/2addr v0, v3

    .line 113
    :cond_9
    const/high16 v3, 0x180000

    .line 114
    .line 115
    and-int/2addr v3, v12

    .line 116
    if-nez v3, :cond_b

    .line 117
    .line 118
    invoke-virtual {v9, v7}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 119
    .line 120
    .line 121
    move-result v3

    .line 122
    if-eqz v3, :cond_a

    .line 123
    .line 124
    const/high16 v3, 0x100000

    .line 125
    .line 126
    goto :goto_6

    .line 127
    :cond_a
    const/high16 v3, 0x80000

    .line 128
    .line 129
    :goto_6
    or-int/2addr v0, v3

    .line 130
    :cond_b
    const v3, 0x92493

    .line 131
    .line 132
    .line 133
    and-int/2addr v3, v0

    .line 134
    const v5, 0x92492

    .line 135
    .line 136
    .line 137
    const/4 v6, 0x1

    .line 138
    if-eq v3, v5, :cond_c

    .line 139
    .line 140
    move v3, v6

    .line 141
    goto :goto_7

    .line 142
    :cond_c
    const/4 v3, 0x0

    .line 143
    :goto_7
    and-int/lit8 v5, v0, 0x1

    .line 144
    .line 145
    invoke-virtual {v9, v5, v3}, Ll2/t;->O(IZ)Z

    .line 146
    .line 147
    .line 148
    move-result v3

    .line 149
    if-eqz v3, :cond_12

    .line 150
    .line 151
    invoke-virtual {v9}, Ll2/t;->T()V

    .line 152
    .line 153
    .line 154
    and-int/lit8 v3, v12, 0x1

    .line 155
    .line 156
    const v5, -0x70001

    .line 157
    .line 158
    .line 159
    if-eqz v3, :cond_e

    .line 160
    .line 161
    invoke-virtual {v9}, Ll2/t;->y()Z

    .line 162
    .line 163
    .line 164
    move-result v3

    .line 165
    if-eqz v3, :cond_d

    .line 166
    .line 167
    goto :goto_8

    .line 168
    :cond_d
    invoke-virtual {v9}, Ll2/t;->R()V

    .line 169
    .line 170
    .line 171
    and-int/2addr v0, v5

    .line 172
    move v2, p2

    .line 173
    move-object/from16 v5, p4

    .line 174
    .line 175
    goto :goto_a

    .line 176
    :cond_e
    :goto_8
    if-eqz v1, :cond_f

    .line 177
    .line 178
    move v2, v6

    .line 179
    goto :goto_9

    .line 180
    :cond_f
    move v2, p2

    .line 181
    :goto_9
    invoke-static {v9}, Lkp/h0;->d(Ll2/o;)Le71/a;

    .line 182
    .line 183
    .line 184
    move-result-object v1

    .line 185
    and-int/2addr v0, v5

    .line 186
    move-object v5, v1

    .line 187
    :goto_a
    invoke-virtual {v9}, Ll2/t;->r()V

    .line 188
    .line 189
    .line 190
    invoke-virtual {v9}, Ll2/t;->L()Ljava/lang/Object;

    .line 191
    .line 192
    .line 193
    move-result-object v1

    .line 194
    sget-object v3, Ll2/n;->a:Ll2/x0;

    .line 195
    .line 196
    if-ne v1, v3, :cond_10

    .line 197
    .line 198
    new-instance v1, Lz81/g;

    .line 199
    .line 200
    const/4 v6, 0x2

    .line 201
    invoke-direct {v1, v6}, Lz81/g;-><init>(I)V

    .line 202
    .line 203
    .line 204
    invoke-virtual {v9, v1}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 205
    .line 206
    .line 207
    :cond_10
    move-object v6, v1

    .line 208
    check-cast v6, Lay0/a;

    .line 209
    .line 210
    invoke-virtual {v9}, Ll2/t;->L()Ljava/lang/Object;

    .line 211
    .line 212
    .line 213
    move-result-object v1

    .line 214
    if-ne v1, v3, :cond_11

    .line 215
    .line 216
    new-instance v1, Lz81/g;

    .line 217
    .line 218
    const/4 v3, 0x2

    .line 219
    invoke-direct {v1, v3}, Lz81/g;-><init>(I)V

    .line 220
    .line 221
    .line 222
    invoke-virtual {v9, v1}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 223
    .line 224
    .line 225
    :cond_11
    move-object v8, v1

    .line 226
    check-cast v8, Lay0/a;

    .line 227
    .line 228
    and-int/lit8 v1, v0, 0xe

    .line 229
    .line 230
    const v3, 0x30c06000

    .line 231
    .line 232
    .line 233
    or-int/2addr v1, v3

    .line 234
    and-int/lit8 v3, v0, 0x70

    .line 235
    .line 236
    or-int/2addr v1, v3

    .line 237
    and-int/lit16 v3, v0, 0x380

    .line 238
    .line 239
    or-int/2addr v1, v3

    .line 240
    and-int/lit16 v3, v0, 0x1c00

    .line 241
    .line 242
    or-int/2addr v1, v3

    .line 243
    shl-int/lit8 v3, v0, 0x3

    .line 244
    .line 245
    const/high16 v10, 0x70000

    .line 246
    .line 247
    and-int/2addr v3, v10

    .line 248
    or-int/2addr v1, v3

    .line 249
    const/high16 v3, 0xe000000

    .line 250
    .line 251
    shl-int/lit8 v0, v0, 0x6

    .line 252
    .line 253
    and-int/2addr v0, v3

    .line 254
    or-int v10, v1, v0

    .line 255
    .line 256
    const/4 v11, 0x0

    .line 257
    const/4 v3, 0x0

    .line 258
    move-object v0, p0

    .line 259
    move-object v1, p1

    .line 260
    invoke-static/range {v0 .. v11}, Lkp/h0;->b(Lx2/s;Ljava/lang/String;ZZLh71/w;Le71/a;Lay0/a;Lay0/a;Lay0/a;Ll2/o;II)V

    .line 261
    .line 262
    .line 263
    move v3, v2

    .line 264
    goto :goto_b

    .line 265
    :cond_12
    invoke-virtual {v9}, Ll2/t;->R()V

    .line 266
    .line 267
    .line 268
    move v3, p2

    .line 269
    move-object/from16 v5, p4

    .line 270
    .line 271
    :goto_b
    invoke-virtual {v9}, Ll2/t;->s()Ll2/u1;

    .line 272
    .line 273
    .line 274
    move-result-object v9

    .line 275
    if-eqz v9, :cond_13

    .line 276
    .line 277
    new-instance v0, Le71/j;

    .line 278
    .line 279
    move-object v1, p0

    .line 280
    move-object v2, p1

    .line 281
    move-object/from16 v4, p3

    .line 282
    .line 283
    move-object/from16 v6, p5

    .line 284
    .line 285
    move/from16 v8, p8

    .line 286
    .line 287
    move v7, v12

    .line 288
    invoke-direct/range {v0 .. v8}, Le71/j;-><init>(Lx2/s;Ljava/lang/String;ZLh71/w;Le71/a;Lay0/a;II)V

    .line 289
    .line 290
    .line 291
    iput-object v0, v9, Ll2/u1;->d:Lay0/n;

    .line 292
    .line 293
    :cond_13
    return-void
.end method

.method public static final b(Lx2/s;Ljava/lang/String;ZZLh71/w;Le71/a;Lay0/a;Lay0/a;Lay0/a;Ll2/o;II)V
    .locals 17

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v5, p4

    .line 4
    .line 5
    move-object/from16 v7, p6

    .line 6
    .line 7
    move-object/from16 v8, p7

    .line 8
    .line 9
    move-object/from16 v9, p8

    .line 10
    .line 11
    move/from16 v10, p10

    .line 12
    .line 13
    const-string v1, "modifier"

    .line 14
    .line 15
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 16
    .line 17
    .line 18
    const-string v1, "colors"

    .line 19
    .line 20
    invoke-static {v5, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 21
    .line 22
    .line 23
    const-string v1, "onTouchDown"

    .line 24
    .line 25
    invoke-static {v7, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 26
    .line 27
    .line 28
    const-string v1, "onTouchUp"

    .line 29
    .line 30
    invoke-static {v8, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 31
    .line 32
    .line 33
    const-string v1, "onTouchCanceled"

    .line 34
    .line 35
    invoke-static {v9, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 36
    .line 37
    .line 38
    move-object/from16 v11, p9

    .line 39
    .line 40
    check-cast v11, Ll2/t;

    .line 41
    .line 42
    const v1, -0x531c9050

    .line 43
    .line 44
    .line 45
    invoke-virtual {v11, v1}, Ll2/t;->a0(I)Ll2/t;

    .line 46
    .line 47
    .line 48
    and-int/lit8 v1, v10, 0x6

    .line 49
    .line 50
    if-nez v1, :cond_1

    .line 51
    .line 52
    invoke-virtual {v11, v0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 53
    .line 54
    .line 55
    move-result v1

    .line 56
    if-eqz v1, :cond_0

    .line 57
    .line 58
    const/4 v1, 0x4

    .line 59
    goto :goto_0

    .line 60
    :cond_0
    const/4 v1, 0x2

    .line 61
    :goto_0
    or-int/2addr v1, v10

    .line 62
    goto :goto_1

    .line 63
    :cond_1
    move v1, v10

    .line 64
    :goto_1
    and-int/lit8 v2, p11, 0x2

    .line 65
    .line 66
    if-eqz v2, :cond_2

    .line 67
    .line 68
    or-int/lit8 v1, v1, 0x30

    .line 69
    .line 70
    goto :goto_3

    .line 71
    :cond_2
    and-int/lit8 v2, v10, 0x30

    .line 72
    .line 73
    if-nez v2, :cond_4

    .line 74
    .line 75
    const/4 v2, 0x0

    .line 76
    invoke-virtual {v11, v2}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 77
    .line 78
    .line 79
    move-result v2

    .line 80
    if-eqz v2, :cond_3

    .line 81
    .line 82
    const/16 v2, 0x20

    .line 83
    .line 84
    goto :goto_2

    .line 85
    :cond_3
    const/16 v2, 0x10

    .line 86
    .line 87
    :goto_2
    or-int/2addr v1, v2

    .line 88
    :cond_4
    :goto_3
    and-int/lit16 v2, v10, 0x180

    .line 89
    .line 90
    move-object/from16 v6, p1

    .line 91
    .line 92
    if-nez v2, :cond_6

    .line 93
    .line 94
    invoke-virtual {v11, v6}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 95
    .line 96
    .line 97
    move-result v2

    .line 98
    if-eqz v2, :cond_5

    .line 99
    .line 100
    const/16 v2, 0x100

    .line 101
    .line 102
    goto :goto_4

    .line 103
    :cond_5
    const/16 v2, 0x80

    .line 104
    .line 105
    :goto_4
    or-int/2addr v1, v2

    .line 106
    :cond_6
    and-int/lit16 v2, v10, 0xc00

    .line 107
    .line 108
    move/from16 v4, p2

    .line 109
    .line 110
    if-nez v2, :cond_8

    .line 111
    .line 112
    invoke-virtual {v11, v4}, Ll2/t;->h(Z)Z

    .line 113
    .line 114
    .line 115
    move-result v2

    .line 116
    if-eqz v2, :cond_7

    .line 117
    .line 118
    const/16 v2, 0x800

    .line 119
    .line 120
    goto :goto_5

    .line 121
    :cond_7
    const/16 v2, 0x400

    .line 122
    .line 123
    :goto_5
    or-int/2addr v1, v2

    .line 124
    :cond_8
    and-int/lit8 v2, p11, 0x10

    .line 125
    .line 126
    if-eqz v2, :cond_a

    .line 127
    .line 128
    or-int/lit16 v1, v1, 0x6000

    .line 129
    .line 130
    :cond_9
    move/from16 v3, p3

    .line 131
    .line 132
    goto :goto_7

    .line 133
    :cond_a
    and-int/lit16 v3, v10, 0x6000

    .line 134
    .line 135
    if-nez v3, :cond_9

    .line 136
    .line 137
    move/from16 v3, p3

    .line 138
    .line 139
    invoke-virtual {v11, v3}, Ll2/t;->h(Z)Z

    .line 140
    .line 141
    .line 142
    move-result v12

    .line 143
    if-eqz v12, :cond_b

    .line 144
    .line 145
    const/16 v12, 0x4000

    .line 146
    .line 147
    goto :goto_6

    .line 148
    :cond_b
    const/16 v12, 0x2000

    .line 149
    .line 150
    :goto_6
    or-int/2addr v1, v12

    .line 151
    :goto_7
    const/high16 v12, 0x30000

    .line 152
    .line 153
    and-int/2addr v12, v10

    .line 154
    if-nez v12, :cond_d

    .line 155
    .line 156
    invoke-virtual {v11, v5}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 157
    .line 158
    .line 159
    move-result v12

    .line 160
    if-eqz v12, :cond_c

    .line 161
    .line 162
    const/high16 v12, 0x20000

    .line 163
    .line 164
    goto :goto_8

    .line 165
    :cond_c
    const/high16 v12, 0x10000

    .line 166
    .line 167
    :goto_8
    or-int/2addr v1, v12

    .line 168
    :cond_d
    const/high16 v12, 0x180000

    .line 169
    .line 170
    and-int v13, v10, v12

    .line 171
    .line 172
    if-nez v13, :cond_10

    .line 173
    .line 174
    and-int/lit8 v13, p11, 0x40

    .line 175
    .line 176
    if-nez v13, :cond_e

    .line 177
    .line 178
    move-object/from16 v13, p5

    .line 179
    .line 180
    invoke-virtual {v11, v13}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 181
    .line 182
    .line 183
    move-result v14

    .line 184
    if-eqz v14, :cond_f

    .line 185
    .line 186
    const/high16 v14, 0x100000

    .line 187
    .line 188
    goto :goto_9

    .line 189
    :cond_e
    move-object/from16 v13, p5

    .line 190
    .line 191
    :cond_f
    const/high16 v14, 0x80000

    .line 192
    .line 193
    :goto_9
    or-int/2addr v1, v14

    .line 194
    goto :goto_a

    .line 195
    :cond_10
    move-object/from16 v13, p5

    .line 196
    .line 197
    :goto_a
    const/high16 v14, 0xc00000

    .line 198
    .line 199
    and-int/2addr v14, v10

    .line 200
    if-nez v14, :cond_12

    .line 201
    .line 202
    invoke-virtual {v11, v7}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 203
    .line 204
    .line 205
    move-result v14

    .line 206
    if-eqz v14, :cond_11

    .line 207
    .line 208
    const/high16 v14, 0x800000

    .line 209
    .line 210
    goto :goto_b

    .line 211
    :cond_11
    const/high16 v14, 0x400000

    .line 212
    .line 213
    :goto_b
    or-int/2addr v1, v14

    .line 214
    :cond_12
    const/high16 v14, 0x6000000

    .line 215
    .line 216
    and-int/2addr v14, v10

    .line 217
    if-nez v14, :cond_14

    .line 218
    .line 219
    invoke-virtual {v11, v8}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 220
    .line 221
    .line 222
    move-result v14

    .line 223
    if-eqz v14, :cond_13

    .line 224
    .line 225
    const/high16 v14, 0x4000000

    .line 226
    .line 227
    goto :goto_c

    .line 228
    :cond_13
    const/high16 v14, 0x2000000

    .line 229
    .line 230
    :goto_c
    or-int/2addr v1, v14

    .line 231
    :cond_14
    const/high16 v14, 0x30000000

    .line 232
    .line 233
    and-int/2addr v14, v10

    .line 234
    if-nez v14, :cond_16

    .line 235
    .line 236
    invoke-virtual {v11, v9}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 237
    .line 238
    .line 239
    move-result v14

    .line 240
    if-eqz v14, :cond_15

    .line 241
    .line 242
    const/high16 v14, 0x20000000

    .line 243
    .line 244
    goto :goto_d

    .line 245
    :cond_15
    const/high16 v14, 0x10000000

    .line 246
    .line 247
    :goto_d
    or-int/2addr v1, v14

    .line 248
    :cond_16
    const v14, 0x12492493

    .line 249
    .line 250
    .line 251
    and-int/2addr v14, v1

    .line 252
    const v15, 0x12492492

    .line 253
    .line 254
    .line 255
    const/16 v16, 0x0

    .line 256
    .line 257
    if-eq v14, v15, :cond_17

    .line 258
    .line 259
    const/4 v14, 0x1

    .line 260
    goto :goto_e

    .line 261
    :cond_17
    move/from16 v14, v16

    .line 262
    .line 263
    :goto_e
    and-int/lit8 v15, v1, 0x1

    .line 264
    .line 265
    invoke-virtual {v11, v15, v14}, Ll2/t;->O(IZ)Z

    .line 266
    .line 267
    .line 268
    move-result v14

    .line 269
    if-eqz v14, :cond_1d

    .line 270
    .line 271
    invoke-virtual {v11}, Ll2/t;->T()V

    .line 272
    .line 273
    .line 274
    and-int/lit8 v14, v10, 0x1

    .line 275
    .line 276
    const v15, -0x380001

    .line 277
    .line 278
    .line 279
    if-eqz v14, :cond_1a

    .line 280
    .line 281
    invoke-virtual {v11}, Ll2/t;->y()Z

    .line 282
    .line 283
    .line 284
    move-result v14

    .line 285
    if-eqz v14, :cond_18

    .line 286
    .line 287
    goto :goto_10

    .line 288
    :cond_18
    invoke-virtual {v11}, Ll2/t;->R()V

    .line 289
    .line 290
    .line 291
    and-int/lit8 v2, p11, 0x40

    .line 292
    .line 293
    if-eqz v2, :cond_19

    .line 294
    .line 295
    and-int/2addr v1, v15

    .line 296
    :cond_19
    move v2, v3

    .line 297
    move-object v5, v13

    .line 298
    :goto_f
    move v13, v1

    .line 299
    goto :goto_12

    .line 300
    :cond_1a
    :goto_10
    if-eqz v2, :cond_1b

    .line 301
    .line 302
    goto :goto_11

    .line 303
    :cond_1b
    move/from16 v16, v3

    .line 304
    .line 305
    :goto_11
    and-int/lit8 v2, p11, 0x40

    .line 306
    .line 307
    if-eqz v2, :cond_1c

    .line 308
    .line 309
    invoke-static {v11}, Lkp/h0;->d(Ll2/o;)Le71/a;

    .line 310
    .line 311
    .line 312
    move-result-object v2

    .line 313
    and-int/2addr v1, v15

    .line 314
    move v13, v1

    .line 315
    move-object v5, v2

    .line 316
    move/from16 v2, v16

    .line 317
    .line 318
    goto :goto_12

    .line 319
    :cond_1c
    move-object v5, v13

    .line 320
    move/from16 v2, v16

    .line 321
    .line 322
    goto :goto_f

    .line 323
    :goto_12
    invoke-virtual {v11}, Ll2/t;->r()V

    .line 324
    .line 325
    .line 326
    new-instance v1, Le71/k;

    .line 327
    .line 328
    move-object/from16 v3, p4

    .line 329
    .line 330
    invoke-direct/range {v1 .. v6}, Le71/k;-><init>(ZLh71/w;ZLe71/a;Ljava/lang/String;)V

    .line 331
    .line 332
    .line 333
    move/from16 v16, v2

    .line 334
    .line 335
    move-object v14, v5

    .line 336
    const v2, 0x28bc2eae

    .line 337
    .line 338
    .line 339
    invoke-static {v2, v11, v1}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 340
    .line 341
    .line 342
    move-result-object v6

    .line 343
    and-int/lit8 v1, v13, 0xe

    .line 344
    .line 345
    or-int/2addr v1, v12

    .line 346
    shr-int/lit8 v2, v13, 0x6

    .line 347
    .line 348
    and-int/lit8 v2, v2, 0x70

    .line 349
    .line 350
    or-int/2addr v1, v2

    .line 351
    shr-int/lit8 v2, v13, 0x9

    .line 352
    .line 353
    and-int/lit16 v2, v2, 0x380

    .line 354
    .line 355
    or-int/2addr v1, v2

    .line 356
    shr-int/lit8 v2, v13, 0xc

    .line 357
    .line 358
    and-int/lit16 v3, v2, 0x1c00

    .line 359
    .line 360
    or-int/2addr v1, v3

    .line 361
    const v3, 0xe000

    .line 362
    .line 363
    .line 364
    and-int/2addr v3, v2

    .line 365
    or-int/2addr v1, v3

    .line 366
    const/high16 v3, 0x70000

    .line 367
    .line 368
    and-int/2addr v2, v3

    .line 369
    or-int/2addr v1, v2

    .line 370
    move-object/from16 v2, p4

    .line 371
    .line 372
    move-object v3, v7

    .line 373
    move-object v4, v8

    .line 374
    move-object v5, v9

    .line 375
    move-object v7, v11

    .line 376
    move v8, v1

    .line 377
    move/from16 v1, p2

    .line 378
    .line 379
    invoke-static/range {v0 .. v8}, Lkp/h0;->c(Lx2/s;ZLh71/w;Lay0/a;Lay0/a;Lay0/a;Lt2/b;Ll2/o;I)V

    .line 380
    .line 381
    .line 382
    move-object v6, v14

    .line 383
    move/from16 v4, v16

    .line 384
    .line 385
    goto :goto_13

    .line 386
    :cond_1d
    move-object v7, v11

    .line 387
    invoke-virtual {v7}, Ll2/t;->R()V

    .line 388
    .line 389
    .line 390
    move v4, v3

    .line 391
    move-object v6, v13

    .line 392
    :goto_13
    invoke-virtual {v7}, Ll2/t;->s()Ll2/u1;

    .line 393
    .line 394
    .line 395
    move-result-object v12

    .line 396
    if-eqz v12, :cond_1e

    .line 397
    .line 398
    new-instance v0, Le71/l;

    .line 399
    .line 400
    move-object/from16 v1, p0

    .line 401
    .line 402
    move-object/from16 v2, p1

    .line 403
    .line 404
    move/from16 v3, p2

    .line 405
    .line 406
    move-object/from16 v5, p4

    .line 407
    .line 408
    move-object/from16 v7, p6

    .line 409
    .line 410
    move-object/from16 v8, p7

    .line 411
    .line 412
    move-object/from16 v9, p8

    .line 413
    .line 414
    move/from16 v11, p11

    .line 415
    .line 416
    invoke-direct/range {v0 .. v11}, Le71/l;-><init>(Lx2/s;Ljava/lang/String;ZZLh71/w;Le71/a;Lay0/a;Lay0/a;Lay0/a;II)V

    .line 417
    .line 418
    .line 419
    iput-object v0, v12, Ll2/u1;->d:Lay0/n;

    .line 420
    .line 421
    :cond_1e
    return-void
.end method

.method public static final c(Lx2/s;ZLh71/w;Lay0/a;Lay0/a;Lay0/a;Lt2/b;Ll2/o;I)V
    .locals 11

    .line 1
    move-object/from16 v4, p5

    .line 2
    .line 3
    move-object/from16 v8, p6

    .line 4
    .line 5
    move/from16 v9, p8

    .line 6
    .line 7
    const-string v0, "modifier"

    .line 8
    .line 9
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    const-string v0, "colors"

    .line 13
    .line 14
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    const-string v0, "onTouchDown"

    .line 18
    .line 19
    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 20
    .line 21
    .line 22
    const-string v0, "onTouchUp"

    .line 23
    .line 24
    invoke-static {p4, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 25
    .line 26
    .line 27
    const-string v0, "onTouchCanceled"

    .line 28
    .line 29
    invoke-static {v4, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 30
    .line 31
    .line 32
    move-object/from16 v6, p7

    .line 33
    .line 34
    check-cast v6, Ll2/t;

    .line 35
    .line 36
    const v0, 0x5853153e

    .line 37
    .line 38
    .line 39
    invoke-virtual {v6, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 40
    .line 41
    .line 42
    and-int/lit8 v0, v9, 0x6

    .line 43
    .line 44
    if-nez v0, :cond_1

    .line 45
    .line 46
    invoke-virtual {v6, p0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 47
    .line 48
    .line 49
    move-result v0

    .line 50
    if-eqz v0, :cond_0

    .line 51
    .line 52
    const/4 v0, 0x4

    .line 53
    goto :goto_0

    .line 54
    :cond_0
    const/4 v0, 0x2

    .line 55
    :goto_0
    or-int/2addr v0, v9

    .line 56
    goto :goto_1

    .line 57
    :cond_1
    move v0, v9

    .line 58
    :goto_1
    and-int/lit8 v1, v9, 0x30

    .line 59
    .line 60
    if-nez v1, :cond_3

    .line 61
    .line 62
    invoke-virtual {v6, p1}, Ll2/t;->h(Z)Z

    .line 63
    .line 64
    .line 65
    move-result v1

    .line 66
    if-eqz v1, :cond_2

    .line 67
    .line 68
    const/16 v1, 0x20

    .line 69
    .line 70
    goto :goto_2

    .line 71
    :cond_2
    const/16 v1, 0x10

    .line 72
    .line 73
    :goto_2
    or-int/2addr v0, v1

    .line 74
    :cond_3
    and-int/lit16 v1, v9, 0x180

    .line 75
    .line 76
    if-nez v1, :cond_5

    .line 77
    .line 78
    invoke-virtual {v6, p2}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 79
    .line 80
    .line 81
    move-result v1

    .line 82
    if-eqz v1, :cond_4

    .line 83
    .line 84
    const/16 v1, 0x100

    .line 85
    .line 86
    goto :goto_3

    .line 87
    :cond_4
    const/16 v1, 0x80

    .line 88
    .line 89
    :goto_3
    or-int/2addr v0, v1

    .line 90
    :cond_5
    and-int/lit16 v1, v9, 0xc00

    .line 91
    .line 92
    if-nez v1, :cond_7

    .line 93
    .line 94
    invoke-virtual {v6, p3}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 95
    .line 96
    .line 97
    move-result v1

    .line 98
    if-eqz v1, :cond_6

    .line 99
    .line 100
    const/16 v1, 0x800

    .line 101
    .line 102
    goto :goto_4

    .line 103
    :cond_6
    const/16 v1, 0x400

    .line 104
    .line 105
    :goto_4
    or-int/2addr v0, v1

    .line 106
    :cond_7
    and-int/lit16 v1, v9, 0x6000

    .line 107
    .line 108
    if-nez v1, :cond_9

    .line 109
    .line 110
    invoke-virtual {v6, p4}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 111
    .line 112
    .line 113
    move-result v1

    .line 114
    if-eqz v1, :cond_8

    .line 115
    .line 116
    const/16 v1, 0x4000

    .line 117
    .line 118
    goto :goto_5

    .line 119
    :cond_8
    const/16 v1, 0x2000

    .line 120
    .line 121
    :goto_5
    or-int/2addr v0, v1

    .line 122
    :cond_9
    const/high16 v1, 0x30000

    .line 123
    .line 124
    and-int v5, v9, v1

    .line 125
    .line 126
    if-nez v5, :cond_b

    .line 127
    .line 128
    invoke-virtual {v6, v4}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 129
    .line 130
    .line 131
    move-result v5

    .line 132
    if-eqz v5, :cond_a

    .line 133
    .line 134
    const/high16 v5, 0x20000

    .line 135
    .line 136
    goto :goto_6

    .line 137
    :cond_a
    const/high16 v5, 0x10000

    .line 138
    .line 139
    :goto_6
    or-int/2addr v0, v5

    .line 140
    :cond_b
    const/high16 v5, 0x180000

    .line 141
    .line 142
    and-int/2addr v5, v9

    .line 143
    if-nez v5, :cond_d

    .line 144
    .line 145
    invoke-virtual {v6, v8}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 146
    .line 147
    .line 148
    move-result v5

    .line 149
    if-eqz v5, :cond_c

    .line 150
    .line 151
    const/high16 v5, 0x100000

    .line 152
    .line 153
    goto :goto_7

    .line 154
    :cond_c
    const/high16 v5, 0x80000

    .line 155
    .line 156
    :goto_7
    or-int/2addr v0, v5

    .line 157
    :cond_d
    const v5, 0x92493

    .line 158
    .line 159
    .line 160
    and-int/2addr v5, v0

    .line 161
    const v7, 0x92492

    .line 162
    .line 163
    .line 164
    if-eq v5, v7, :cond_e

    .line 165
    .line 166
    const/4 v5, 0x1

    .line 167
    goto :goto_8

    .line 168
    :cond_e
    const/4 v5, 0x0

    .line 169
    :goto_8
    and-int/lit8 v7, v0, 0x1

    .line 170
    .line 171
    invoke-virtual {v6, v7, v5}, Ll2/t;->O(IZ)Z

    .line 172
    .line 173
    .line 174
    move-result v5

    .line 175
    if-eqz v5, :cond_f

    .line 176
    .line 177
    new-instance v5, Le71/h;

    .line 178
    .line 179
    invoke-direct {v5, p2, v8}, Le71/h;-><init>(Lh71/w;Lt2/b;)V

    .line 180
    .line 181
    .line 182
    const v7, -0x5781dc29

    .line 183
    .line 184
    .line 185
    invoke-static {v7, v6, v5}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 186
    .line 187
    .line 188
    move-result-object v5

    .line 189
    and-int/lit8 v7, v0, 0xe

    .line 190
    .line 191
    or-int/2addr v1, v7

    .line 192
    and-int/lit8 v7, v0, 0x70

    .line 193
    .line 194
    or-int/2addr v1, v7

    .line 195
    shr-int/lit8 v0, v0, 0x3

    .line 196
    .line 197
    and-int/lit16 v7, v0, 0x380

    .line 198
    .line 199
    or-int/2addr v1, v7

    .line 200
    and-int/lit16 v7, v0, 0x1c00

    .line 201
    .line 202
    or-int/2addr v1, v7

    .line 203
    const v7, 0xe000

    .line 204
    .line 205
    .line 206
    and-int/2addr v0, v7

    .line 207
    or-int v7, v1, v0

    .line 208
    .line 209
    move-object v0, p0

    .line 210
    move v1, p1

    .line 211
    move-object v2, p3

    .line 212
    move-object v3, p4

    .line 213
    invoke-static/range {v0 .. v7}, Lkp/g0;->a(Lx2/s;ZLay0/a;Lay0/a;Lay0/a;Lt2/b;Ll2/o;I)V

    .line 214
    .line 215
    .line 216
    goto :goto_9

    .line 217
    :cond_f
    invoke-virtual {v6}, Ll2/t;->R()V

    .line 218
    .line 219
    .line 220
    :goto_9
    invoke-virtual {v6}, Ll2/t;->s()Ll2/u1;

    .line 221
    .line 222
    .line 223
    move-result-object v10

    .line 224
    if-eqz v10, :cond_10

    .line 225
    .line 226
    new-instance v0, Le71/i;

    .line 227
    .line 228
    move-object v1, p0

    .line 229
    move v2, p1

    .line 230
    move-object v3, p2

    .line 231
    move-object v4, p3

    .line 232
    move-object v5, p4

    .line 233
    move-object/from16 v6, p5

    .line 234
    .line 235
    move-object v7, v8

    .line 236
    move v8, v9

    .line 237
    invoke-direct/range {v0 .. v8}, Le71/i;-><init>(Lx2/s;ZLh71/w;Lay0/a;Lay0/a;Lay0/a;Lt2/b;I)V

    .line 238
    .line 239
    .line 240
    iput-object v0, v10, Ll2/u1;->d:Lay0/n;

    .line 241
    .line 242
    :cond_10
    return-void
.end method

.method public static final d(Ll2/o;)Le71/a;
    .locals 3

    .line 1
    new-instance v0, Le71/a;

    .line 2
    .line 3
    sget-object v1, Lj91/j;->a:Ll2/u2;

    .line 4
    .line 5
    check-cast p0, Ll2/t;

    .line 6
    .line 7
    invoke-virtual {p0, v1}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 8
    .line 9
    .line 10
    move-result-object v1

    .line 11
    check-cast v1, Lj91/f;

    .line 12
    .line 13
    invoke-virtual {v1}, Lj91/f;->b()Lg4/p0;

    .line 14
    .line 15
    .line 16
    move-result-object v1

    .line 17
    sget-object v2, Lh71/u;->a:Ll2/u2;

    .line 18
    .line 19
    invoke-virtual {p0, v2}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 20
    .line 21
    .line 22
    move-result-object p0

    .line 23
    check-cast p0, Lh71/t;

    .line 24
    .line 25
    iget p0, p0, Lh71/t;->f:F

    .line 26
    .line 27
    invoke-direct {v0, v1, p0}, Le71/a;-><init>(Lg4/p0;F)V

    .line 28
    .line 29
    .line 30
    return-object v0
.end method

.method public static final e(Lyy0/c2;Ljava/lang/String;Ljava/lang/String;)V
    .locals 9

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "configId"

    .line 7
    .line 8
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    const-string v0, "code"

    .line 12
    .line 13
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    :cond_0
    invoke-virtual {p0}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 17
    .line 18
    .line 19
    move-result-object v0

    .line 20
    move-object v1, v0

    .line 21
    check-cast v1, Lrh/v;

    .line 22
    .line 23
    invoke-virtual {p0}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 24
    .line 25
    .line 26
    move-result-object v2

    .line 27
    check-cast v2, Lrh/v;

    .line 28
    .line 29
    iget-object v2, v2, Lrh/v;->b:Ljava/util/List;

    .line 30
    .line 31
    check-cast v2, Ljava/lang/Iterable;

    .line 32
    .line 33
    new-instance v3, Ljava/util/ArrayList;

    .line 34
    .line 35
    const/16 v4, 0xa

    .line 36
    .line 37
    invoke-static {v2, v4}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 38
    .line 39
    .line 40
    move-result v4

    .line 41
    invoke-direct {v3, v4}, Ljava/util/ArrayList;-><init>(I)V

    .line 42
    .line 43
    .line 44
    invoke-interface {v2}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 45
    .line 46
    .line 47
    move-result-object v2

    .line 48
    :goto_0
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    .line 49
    .line 50
    .line 51
    move-result v4

    .line 52
    if-eqz v4, :cond_2

    .line 53
    .line 54
    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 55
    .line 56
    .line 57
    move-result-object v4

    .line 58
    check-cast v4, Lrh/d;

    .line 59
    .line 60
    iget-object v5, v4, Lrh/d;->a:Ljava/lang/String;

    .line 61
    .line 62
    invoke-static {v5, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 63
    .line 64
    .line 65
    move-result v5

    .line 66
    if-eqz v5, :cond_1

    .line 67
    .line 68
    const/4 v5, 0x0

    .line 69
    const/16 v6, 0xf5

    .line 70
    .line 71
    invoke-static {v4, p2, v5, v6}, Lrh/d;->a(Lrh/d;Ljava/lang/String;ZI)Lrh/d;

    .line 72
    .line 73
    .line 74
    move-result-object v4

    .line 75
    :cond_1
    invoke-virtual {v3, v4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 76
    .line 77
    .line 78
    goto :goto_0

    .line 79
    :cond_2
    const/4 v7, 0x0

    .line 80
    const/16 v8, 0x7d

    .line 81
    .line 82
    const/4 v2, 0x0

    .line 83
    const/4 v4, 0x0

    .line 84
    const/4 v5, 0x0

    .line 85
    const/4 v6, 0x0

    .line 86
    invoke-static/range {v1 .. v8}, Lrh/v;->a(Lrh/v;ZLjava/util/ArrayList;ZLlc/l;Lrh/h;Ljava/lang/String;I)Lrh/v;

    .line 87
    .line 88
    .line 89
    move-result-object v1

    .line 90
    invoke-virtual {p0, v0, v1}, Lyy0/c2;->i(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 91
    .line 92
    .line 93
    move-result v0

    .line 94
    if-eqz v0, :cond_0

    .line 95
    .line 96
    return-void
.end method

.method public static final f(Lyy0/c2;)V
    .locals 9

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    :cond_0
    invoke-virtual {p0}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 7
    .line 8
    .line 9
    move-result-object v0

    .line 10
    move-object v1, v0

    .line 11
    check-cast v1, Lrh/v;

    .line 12
    .line 13
    const/4 v7, 0x0

    .line 14
    const/16 v8, 0x6f

    .line 15
    .line 16
    const/4 v2, 0x0

    .line 17
    const/4 v3, 0x0

    .line 18
    const/4 v4, 0x0

    .line 19
    const/4 v5, 0x0

    .line 20
    sget-object v6, Lrh/f;->a:Lrh/f;

    .line 21
    .line 22
    invoke-static/range {v1 .. v8}, Lrh/v;->a(Lrh/v;ZLjava/util/ArrayList;ZLlc/l;Lrh/h;Ljava/lang/String;I)Lrh/v;

    .line 23
    .line 24
    .line 25
    move-result-object v1

    .line 26
    invoke-virtual {p0, v0, v1}, Lyy0/c2;->i(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 27
    .line 28
    .line 29
    move-result v0

    .line 30
    if-eqz v0, :cond_0

    .line 31
    .line 32
    return-void
.end method
