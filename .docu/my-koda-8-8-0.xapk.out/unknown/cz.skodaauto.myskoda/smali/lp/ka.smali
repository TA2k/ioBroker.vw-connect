.class public abstract Llp/ka;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Ljava/util/ArrayList;JLsp/d;Ljava/util/List;Lsp/d;ZFLay0/k;Ll2/o;III)V
    .locals 24

    .line 1
    move-object/from16 v10, p9

    .line 2
    .line 3
    check-cast v10, Ll2/t;

    .line 4
    .line 5
    const v0, -0x7e0020c3

    .line 6
    .line 7
    .line 8
    invoke-virtual {v10, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 9
    .line 10
    .line 11
    move-object/from16 v12, p0

    .line 12
    .line 13
    invoke-virtual {v10, v12}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 14
    .line 15
    .line 16
    move-result v0

    .line 17
    const/4 v1, 0x2

    .line 18
    const/4 v2, 0x4

    .line 19
    if-eqz v0, :cond_0

    .line 20
    .line 21
    move v0, v2

    .line 22
    goto :goto_0

    .line 23
    :cond_0
    move v0, v1

    .line 24
    :goto_0
    or-int v0, p10, v0

    .line 25
    .line 26
    or-int/lit8 v0, v0, 0x30

    .line 27
    .line 28
    move-wide/from16 v13, p1

    .line 29
    .line 30
    invoke-virtual {v10, v13, v14}, Ll2/t;->f(J)Z

    .line 31
    .line 32
    .line 33
    move-result v3

    .line 34
    if-eqz v3, :cond_1

    .line 35
    .line 36
    const/16 v3, 0x100

    .line 37
    .line 38
    goto :goto_1

    .line 39
    :cond_1
    const/16 v3, 0x80

    .line 40
    .line 41
    :goto_1
    or-int/2addr v0, v3

    .line 42
    const v3, 0x36400

    .line 43
    .line 44
    .line 45
    or-int/2addr v3, v0

    .line 46
    and-int/lit8 v4, p12, 0x40

    .line 47
    .line 48
    if-eqz v4, :cond_2

    .line 49
    .line 50
    const v3, 0x1b6400

    .line 51
    .line 52
    .line 53
    or-int/2addr v0, v3

    .line 54
    move v3, v0

    .line 55
    move-object/from16 v0, p4

    .line 56
    .line 57
    goto :goto_3

    .line 58
    :cond_2
    move-object/from16 v0, p4

    .line 59
    .line 60
    invoke-virtual {v10, v0}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 61
    .line 62
    .line 63
    move-result v5

    .line 64
    if-eqz v5, :cond_3

    .line 65
    .line 66
    const/high16 v5, 0x100000

    .line 67
    .line 68
    goto :goto_2

    .line 69
    :cond_3
    const/high16 v5, 0x80000

    .line 70
    .line 71
    :goto_2
    or-int/2addr v3, v5

    .line 72
    :goto_3
    const/high16 v5, 0x36400000

    .line 73
    .line 74
    or-int/2addr v3, v5

    .line 75
    and-int/lit8 v5, p11, 0x6

    .line 76
    .line 77
    move/from16 v8, p7

    .line 78
    .line 79
    if-nez v5, :cond_5

    .line 80
    .line 81
    invoke-virtual {v10, v8}, Ll2/t;->d(F)Z

    .line 82
    .line 83
    .line 84
    move-result v5

    .line 85
    if-eqz v5, :cond_4

    .line 86
    .line 87
    move v1, v2

    .line 88
    :cond_4
    or-int v1, p11, v1

    .line 89
    .line 90
    goto :goto_4

    .line 91
    :cond_5
    move/from16 v1, p11

    .line 92
    .line 93
    :goto_4
    or-int/lit16 v1, v1, 0x1b0

    .line 94
    .line 95
    const v2, 0x12492493

    .line 96
    .line 97
    .line 98
    and-int/2addr v2, v3

    .line 99
    const v5, 0x12492492

    .line 100
    .line 101
    .line 102
    const/4 v6, 0x1

    .line 103
    if-ne v2, v5, :cond_7

    .line 104
    .line 105
    and-int/lit16 v2, v1, 0x93

    .line 106
    .line 107
    const/16 v5, 0x92

    .line 108
    .line 109
    if-eq v2, v5, :cond_6

    .line 110
    .line 111
    goto :goto_5

    .line 112
    :cond_6
    const/4 v2, 0x0

    .line 113
    goto :goto_6

    .line 114
    :cond_7
    :goto_5
    move v2, v6

    .line 115
    :goto_6
    and-int/lit8 v5, v3, 0x1

    .line 116
    .line 117
    invoke-virtual {v10, v5, v2}, Ll2/t;->O(IZ)Z

    .line 118
    .line 119
    .line 120
    move-result v2

    .line 121
    if-eqz v2, :cond_c

    .line 122
    .line 123
    invoke-virtual {v10}, Ll2/t;->T()V

    .line 124
    .line 125
    .line 126
    and-int/lit8 v2, p10, 0x1

    .line 127
    .line 128
    const v5, -0x1c01c01

    .line 129
    .line 130
    .line 131
    if-eqz v2, :cond_9

    .line 132
    .line 133
    invoke-virtual {v10}, Ll2/t;->y()Z

    .line 134
    .line 135
    .line 136
    move-result v2

    .line 137
    if-eqz v2, :cond_8

    .line 138
    .line 139
    goto :goto_8

    .line 140
    :cond_8
    invoke-virtual {v10}, Ll2/t;->R()V

    .line 141
    .line 142
    .line 143
    and-int v2, v3, v5

    .line 144
    .line 145
    move-object/from16 v4, p3

    .line 146
    .line 147
    move-object/from16 v6, p5

    .line 148
    .line 149
    move/from16 v7, p6

    .line 150
    .line 151
    move-object/from16 v9, p8

    .line 152
    .line 153
    :goto_7
    move-object v5, v0

    .line 154
    goto :goto_9

    .line 155
    :cond_9
    :goto_8
    new-instance v2, Lsp/c;

    .line 156
    .line 157
    invoke-direct {v2}, Lsp/c;-><init>()V

    .line 158
    .line 159
    .line 160
    if-eqz v4, :cond_a

    .line 161
    .line 162
    const/4 v0, 0x0

    .line 163
    :cond_a
    new-instance v4, Lsp/c;

    .line 164
    .line 165
    invoke-direct {v4}, Lsp/c;-><init>()V

    .line 166
    .line 167
    .line 168
    and-int/2addr v3, v5

    .line 169
    invoke-virtual {v10}, Ll2/t;->L()Ljava/lang/Object;

    .line 170
    .line 171
    .line 172
    move-result-object v5

    .line 173
    sget-object v7, Ll2/n;->a:Ll2/x0;

    .line 174
    .line 175
    if-ne v5, v7, :cond_b

    .line 176
    .line 177
    new-instance v5, Luu/r;

    .line 178
    .line 179
    const/16 v7, 0x9

    .line 180
    .line 181
    invoke-direct {v5, v7}, Luu/r;-><init>(I)V

    .line 182
    .line 183
    .line 184
    invoke-virtual {v10, v5}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 185
    .line 186
    .line 187
    :cond_b
    check-cast v5, Lay0/k;

    .line 188
    .line 189
    move-object v9, v5

    .line 190
    move v7, v6

    .line 191
    move-object v6, v4

    .line 192
    move-object v4, v2

    .line 193
    move v2, v3

    .line 194
    goto :goto_7

    .line 195
    :goto_9
    invoke-virtual {v10}, Ll2/t;->r()V

    .line 196
    .line 197
    .line 198
    and-int/lit8 v0, v2, 0xe

    .line 199
    .line 200
    shl-int/lit8 v2, v2, 0x3

    .line 201
    .line 202
    or-int/lit16 v0, v0, 0x180

    .line 203
    .line 204
    and-int/lit16 v3, v2, 0x1c00

    .line 205
    .line 206
    or-int/2addr v0, v3

    .line 207
    const/high16 v3, 0x1b0000

    .line 208
    .line 209
    or-int/2addr v0, v3

    .line 210
    const/high16 v3, 0x1c00000

    .line 211
    .line 212
    and-int/2addr v2, v3

    .line 213
    or-int/2addr v0, v2

    .line 214
    const/high16 v2, 0x30000000

    .line 215
    .line 216
    or-int v11, v0, v2

    .line 217
    .line 218
    shl-int/lit8 v0, v1, 0x3

    .line 219
    .line 220
    and-int/lit8 v0, v0, 0x70

    .line 221
    .line 222
    or-int/lit16 v0, v0, 0xd86

    .line 223
    .line 224
    const/4 v1, 0x0

    .line 225
    move-object v2, v12

    .line 226
    move v12, v0

    .line 227
    move-object v0, v2

    .line 228
    move-wide v2, v13

    .line 229
    invoke-static/range {v0 .. v12}, Llp/ka;->b(Ljava/util/ArrayList;Ljava/util/List;JLsp/d;Ljava/util/List;Lsp/d;ZFLay0/k;Ll2/o;II)V

    .line 230
    .line 231
    .line 232
    move-object v15, v4

    .line 233
    move-object/from16 v16, v5

    .line 234
    .line 235
    move-object/from16 v17, v6

    .line 236
    .line 237
    move/from16 v18, v7

    .line 238
    .line 239
    move-object/from16 v20, v9

    .line 240
    .line 241
    goto :goto_a

    .line 242
    :cond_c
    invoke-virtual {v10}, Ll2/t;->R()V

    .line 243
    .line 244
    .line 245
    move-object/from16 v15, p3

    .line 246
    .line 247
    move-object/from16 v17, p5

    .line 248
    .line 249
    move/from16 v18, p6

    .line 250
    .line 251
    move-object/from16 v20, p8

    .line 252
    .line 253
    move-object/from16 v16, v0

    .line 254
    .line 255
    :goto_a
    invoke-virtual {v10}, Ll2/t;->s()Ll2/u1;

    .line 256
    .line 257
    .line 258
    move-result-object v0

    .line 259
    if-eqz v0, :cond_d

    .line 260
    .line 261
    new-instance v11, Luu/r1;

    .line 262
    .line 263
    move-object/from16 v12, p0

    .line 264
    .line 265
    move-wide/from16 v13, p1

    .line 266
    .line 267
    move/from16 v19, p7

    .line 268
    .line 269
    move/from16 v21, p10

    .line 270
    .line 271
    move/from16 v22, p11

    .line 272
    .line 273
    move/from16 v23, p12

    .line 274
    .line 275
    invoke-direct/range {v11 .. v23}, Luu/r1;-><init>(Ljava/util/ArrayList;JLsp/d;Ljava/util/List;Lsp/d;ZFLay0/k;III)V

    .line 276
    .line 277
    .line 278
    iput-object v11, v0, Ll2/u1;->d:Lay0/n;

    .line 279
    .line 280
    :cond_d
    return-void
.end method

.method public static final b(Ljava/util/ArrayList;Ljava/util/List;JLsp/d;Ljava/util/List;Lsp/d;ZFLay0/k;Ll2/o;II)V
    .locals 24

    .line 1
    move-object/from16 v3, p0

    .line 2
    .line 3
    move-wide/from16 v5, p2

    .line 4
    .line 5
    move-object/from16 v7, p4

    .line 6
    .line 7
    move-object/from16 v8, p5

    .line 8
    .line 9
    move-object/from16 v9, p6

    .line 10
    .line 11
    move-object/from16 v10, p9

    .line 12
    .line 13
    move/from16 v12, p11

    .line 14
    .line 15
    move/from16 v13, p12

    .line 16
    .line 17
    const/4 v0, 0x0

    .line 18
    invoke-static {v0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 19
    .line 20
    .line 21
    move-result-object v14

    .line 22
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 23
    .line 24
    .line 25
    move-result-object v15

    .line 26
    move-object/from16 v1, p10

    .line 27
    .line 28
    check-cast v1, Ll2/t;

    .line 29
    .line 30
    const v2, -0x5c836dbd

    .line 31
    .line 32
    .line 33
    invoke-virtual {v1, v2}, Ll2/t;->a0(I)Ll2/t;

    .line 34
    .line 35
    .line 36
    iget-object v2, v1, Ll2/t;->a:Leb/j0;

    .line 37
    .line 38
    and-int/lit8 v4, v12, 0x6

    .line 39
    .line 40
    if-nez v4, :cond_1

    .line 41
    .line 42
    invoke-virtual {v1, v3}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 43
    .line 44
    .line 45
    move-result v4

    .line 46
    if-eqz v4, :cond_0

    .line 47
    .line 48
    const/4 v4, 0x4

    .line 49
    goto :goto_0

    .line 50
    :cond_0
    const/4 v4, 0x2

    .line 51
    :goto_0
    or-int/2addr v4, v12

    .line 52
    goto :goto_1

    .line 53
    :cond_1
    move v4, v12

    .line 54
    :goto_1
    or-int/lit8 v4, v4, 0x30

    .line 55
    .line 56
    and-int/lit16 v11, v12, 0x180

    .line 57
    .line 58
    const/16 v16, 0x80

    .line 59
    .line 60
    move-object/from16 v17, v2

    .line 61
    .line 62
    if-nez v11, :cond_3

    .line 63
    .line 64
    invoke-virtual {v1, v0}, Ll2/t;->h(Z)Z

    .line 65
    .line 66
    .line 67
    move-result v11

    .line 68
    if-eqz v11, :cond_2

    .line 69
    .line 70
    const/16 v11, 0x100

    .line 71
    .line 72
    goto :goto_2

    .line 73
    :cond_2
    move/from16 v11, v16

    .line 74
    .line 75
    :goto_2
    or-int/2addr v4, v11

    .line 76
    :cond_3
    and-int/lit16 v11, v12, 0xc00

    .line 77
    .line 78
    const/16 v18, 0x400

    .line 79
    .line 80
    if-nez v11, :cond_5

    .line 81
    .line 82
    invoke-virtual {v1, v5, v6}, Ll2/t;->f(J)Z

    .line 83
    .line 84
    .line 85
    move-result v11

    .line 86
    if-eqz v11, :cond_4

    .line 87
    .line 88
    const/16 v11, 0x800

    .line 89
    .line 90
    goto :goto_3

    .line 91
    :cond_4
    move/from16 v11, v18

    .line 92
    .line 93
    :goto_3
    or-int/2addr v4, v11

    .line 94
    :cond_5
    and-int/lit16 v11, v12, 0x6000

    .line 95
    .line 96
    if-nez v11, :cond_7

    .line 97
    .line 98
    invoke-virtual {v1, v7}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 99
    .line 100
    .line 101
    move-result v11

    .line 102
    if-eqz v11, :cond_6

    .line 103
    .line 104
    const/16 v11, 0x4000

    .line 105
    .line 106
    goto :goto_4

    .line 107
    :cond_6
    const/16 v11, 0x2000

    .line 108
    .line 109
    :goto_4
    or-int/2addr v4, v11

    .line 110
    :cond_7
    const/high16 v11, 0x30000

    .line 111
    .line 112
    and-int/2addr v11, v12

    .line 113
    if-nez v11, :cond_9

    .line 114
    .line 115
    invoke-virtual {v1, v0}, Ll2/t;->h(Z)Z

    .line 116
    .line 117
    .line 118
    move-result v11

    .line 119
    if-eqz v11, :cond_8

    .line 120
    .line 121
    const/high16 v11, 0x20000

    .line 122
    .line 123
    goto :goto_5

    .line 124
    :cond_8
    const/high16 v11, 0x10000

    .line 125
    .line 126
    :goto_5
    or-int/2addr v4, v11

    .line 127
    :cond_9
    const/high16 v11, 0x180000

    .line 128
    .line 129
    and-int/2addr v11, v12

    .line 130
    if-nez v11, :cond_b

    .line 131
    .line 132
    invoke-virtual {v1, v0}, Ll2/t;->e(I)Z

    .line 133
    .line 134
    .line 135
    move-result v11

    .line 136
    if-eqz v11, :cond_a

    .line 137
    .line 138
    const/high16 v11, 0x100000

    .line 139
    .line 140
    goto :goto_6

    .line 141
    :cond_a
    const/high16 v11, 0x80000

    .line 142
    .line 143
    :goto_6
    or-int/2addr v4, v11

    .line 144
    :cond_b
    const/high16 v11, 0xc00000

    .line 145
    .line 146
    and-int/2addr v11, v12

    .line 147
    if-nez v11, :cond_d

    .line 148
    .line 149
    invoke-virtual {v1, v8}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 150
    .line 151
    .line 152
    move-result v11

    .line 153
    if-eqz v11, :cond_c

    .line 154
    .line 155
    const/high16 v11, 0x800000

    .line 156
    .line 157
    goto :goto_7

    .line 158
    :cond_c
    const/high16 v11, 0x400000

    .line 159
    .line 160
    :goto_7
    or-int/2addr v4, v11

    .line 161
    :cond_d
    const/high16 v11, 0x6000000

    .line 162
    .line 163
    and-int v19, v12, v11

    .line 164
    .line 165
    if-nez v19, :cond_f

    .line 166
    .line 167
    invoke-virtual {v1, v9}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 168
    .line 169
    .line 170
    move-result v19

    .line 171
    if-eqz v19, :cond_e

    .line 172
    .line 173
    const/high16 v19, 0x4000000

    .line 174
    .line 175
    goto :goto_8

    .line 176
    :cond_e
    const/high16 v19, 0x2000000

    .line 177
    .line 178
    :goto_8
    or-int v4, v4, v19

    .line 179
    .line 180
    :cond_f
    const/high16 v19, 0x30000000

    .line 181
    .line 182
    and-int v19, v12, v19

    .line 183
    .line 184
    const/4 v0, 0x0

    .line 185
    if-nez v19, :cond_11

    .line 186
    .line 187
    invoke-virtual {v1, v0}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 188
    .line 189
    .line 190
    move-result v19

    .line 191
    if-eqz v19, :cond_10

    .line 192
    .line 193
    const/high16 v19, 0x20000000

    .line 194
    .line 195
    goto :goto_9

    .line 196
    :cond_10
    const/high16 v19, 0x10000000

    .line 197
    .line 198
    :goto_9
    or-int v4, v4, v19

    .line 199
    .line 200
    :cond_11
    and-int/lit8 v19, v13, 0x6

    .line 201
    .line 202
    if-nez v19, :cond_13

    .line 203
    .line 204
    move/from16 v19, v11

    .line 205
    .line 206
    move/from16 v11, p7

    .line 207
    .line 208
    invoke-virtual {v1, v11}, Ll2/t;->h(Z)Z

    .line 209
    .line 210
    .line 211
    move-result v21

    .line 212
    if-eqz v21, :cond_12

    .line 213
    .line 214
    const/16 v21, 0x4

    .line 215
    .line 216
    goto :goto_a

    .line 217
    :cond_12
    const/16 v21, 0x2

    .line 218
    .line 219
    :goto_a
    or-int v21, v13, v21

    .line 220
    .line 221
    goto :goto_b

    .line 222
    :cond_13
    move/from16 v19, v11

    .line 223
    .line 224
    move/from16 v11, p7

    .line 225
    .line 226
    move/from16 v21, v13

    .line 227
    .line 228
    :goto_b
    and-int/lit8 v22, v13, 0x30

    .line 229
    .line 230
    move/from16 v0, p8

    .line 231
    .line 232
    if-nez v22, :cond_15

    .line 233
    .line 234
    invoke-virtual {v1, v0}, Ll2/t;->d(F)Z

    .line 235
    .line 236
    .line 237
    move-result v23

    .line 238
    if-eqz v23, :cond_14

    .line 239
    .line 240
    const/16 v23, 0x20

    .line 241
    .line 242
    goto :goto_c

    .line 243
    :cond_14
    const/16 v23, 0x10

    .line 244
    .line 245
    :goto_c
    or-int v21, v21, v23

    .line 246
    .line 247
    :cond_15
    and-int/lit16 v2, v13, 0x180

    .line 248
    .line 249
    const/4 v12, 0x0

    .line 250
    if-nez v2, :cond_17

    .line 251
    .line 252
    invoke-virtual {v1, v12}, Ll2/t;->d(F)Z

    .line 253
    .line 254
    .line 255
    move-result v2

    .line 256
    if-eqz v2, :cond_16

    .line 257
    .line 258
    const/16 v16, 0x100

    .line 259
    .line 260
    :cond_16
    or-int v21, v21, v16

    .line 261
    .line 262
    :cond_17
    and-int/lit16 v2, v13, 0xc00

    .line 263
    .line 264
    if-nez v2, :cond_19

    .line 265
    .line 266
    invoke-virtual {v1, v10}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 267
    .line 268
    .line 269
    move-result v2

    .line 270
    if-eqz v2, :cond_18

    .line 271
    .line 272
    const/16 v18, 0x800

    .line 273
    .line 274
    :cond_18
    or-int v21, v21, v18

    .line 275
    .line 276
    :cond_19
    move/from16 v2, v21

    .line 277
    .line 278
    const v16, 0x12492493

    .line 279
    .line 280
    .line 281
    move/from16 v18, v12

    .line 282
    .line 283
    and-int v12, v4, v16

    .line 284
    .line 285
    const v0, 0x12492492

    .line 286
    .line 287
    .line 288
    if-ne v12, v0, :cond_1b

    .line 289
    .line 290
    and-int/lit16 v0, v2, 0x493

    .line 291
    .line 292
    const/16 v12, 0x492

    .line 293
    .line 294
    if-eq v0, v12, :cond_1a

    .line 295
    .line 296
    goto :goto_d

    .line 297
    :cond_1a
    const/4 v0, 0x0

    .line 298
    goto :goto_e

    .line 299
    :cond_1b
    :goto_d
    const/4 v0, 0x1

    .line 300
    :goto_e
    and-int/lit8 v12, v4, 0x1

    .line 301
    .line 302
    invoke-virtual {v1, v12, v0}, Ll2/t;->O(IZ)Z

    .line 303
    .line 304
    .line 305
    move-result v0

    .line 306
    if-eqz v0, :cond_32

    .line 307
    .line 308
    invoke-virtual {v1}, Ll2/t;->T()V

    .line 309
    .line 310
    .line 311
    and-int/lit8 v0, p11, 0x1

    .line 312
    .line 313
    if-eqz v0, :cond_1d

    .line 314
    .line 315
    invoke-virtual {v1}, Ll2/t;->y()Z

    .line 316
    .line 317
    .line 318
    move-result v0

    .line 319
    if-eqz v0, :cond_1c

    .line 320
    .line 321
    goto :goto_f

    .line 322
    :cond_1c
    invoke-virtual {v1}, Ll2/t;->R()V

    .line 323
    .line 324
    .line 325
    move-object/from16 v0, p1

    .line 326
    .line 327
    goto :goto_10

    .line 328
    :cond_1d
    :goto_f
    sget-object v0, Lmx0/s;->d:Lmx0/s;

    .line 329
    .line 330
    :goto_10
    invoke-virtual {v1}, Ll2/t;->r()V

    .line 331
    .line 332
    .line 333
    move-object/from16 v12, v17

    .line 334
    .line 335
    check-cast v12, Luu/x;

    .line 336
    .line 337
    invoke-virtual {v1, v12}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 338
    .line 339
    .line 340
    move-result v16

    .line 341
    invoke-virtual {v1, v3}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 342
    .line 343
    .line 344
    move-result v21

    .line 345
    or-int v16, v16, v21

    .line 346
    .line 347
    invoke-virtual {v1, v0}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 348
    .line 349
    .line 350
    move-result v21

    .line 351
    or-int v16, v16, v21

    .line 352
    .line 353
    and-int/lit16 v13, v4, 0x380

    .line 354
    .line 355
    move-object/from16 p1, v0

    .line 356
    .line 357
    const/16 v0, 0x100

    .line 358
    .line 359
    if-ne v13, v0, :cond_1e

    .line 360
    .line 361
    const/4 v0, 0x1

    .line 362
    goto :goto_11

    .line 363
    :cond_1e
    const/4 v0, 0x0

    .line 364
    :goto_11
    or-int v0, v16, v0

    .line 365
    .line 366
    and-int/lit16 v13, v4, 0x1c00

    .line 367
    .line 368
    move/from16 v16, v0

    .line 369
    .line 370
    const/16 v0, 0x800

    .line 371
    .line 372
    if-ne v13, v0, :cond_1f

    .line 373
    .line 374
    const/4 v0, 0x1

    .line 375
    goto :goto_12

    .line 376
    :cond_1f
    const/4 v0, 0x0

    .line 377
    :goto_12
    or-int v0, v16, v0

    .line 378
    .line 379
    const v13, 0xe000

    .line 380
    .line 381
    .line 382
    and-int/2addr v13, v4

    .line 383
    xor-int/lit16 v13, v13, 0x6000

    .line 384
    .line 385
    move/from16 v16, v0

    .line 386
    .line 387
    const/16 v0, 0x4000

    .line 388
    .line 389
    if-le v13, v0, :cond_20

    .line 390
    .line 391
    invoke-virtual {v1, v7}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 392
    .line 393
    .line 394
    move-result v13

    .line 395
    if-nez v13, :cond_21

    .line 396
    .line 397
    :cond_20
    and-int/lit16 v13, v4, 0x6000

    .line 398
    .line 399
    if-ne v13, v0, :cond_22

    .line 400
    .line 401
    :cond_21
    const/4 v0, 0x1

    .line 402
    goto :goto_13

    .line 403
    :cond_22
    const/4 v0, 0x0

    .line 404
    :goto_13
    or-int v0, v16, v0

    .line 405
    .line 406
    const/high16 v13, 0x70000

    .line 407
    .line 408
    and-int/2addr v13, v4

    .line 409
    move/from16 v16, v0

    .line 410
    .line 411
    const/high16 v0, 0x20000

    .line 412
    .line 413
    if-ne v13, v0, :cond_23

    .line 414
    .line 415
    const/4 v0, 0x1

    .line 416
    goto :goto_14

    .line 417
    :cond_23
    const/4 v0, 0x0

    .line 418
    :goto_14
    or-int v0, v16, v0

    .line 419
    .line 420
    const/high16 v13, 0x380000

    .line 421
    .line 422
    and-int/2addr v13, v4

    .line 423
    move/from16 v16, v0

    .line 424
    .line 425
    const/high16 v0, 0x100000

    .line 426
    .line 427
    if-ne v13, v0, :cond_24

    .line 428
    .line 429
    const/4 v0, 0x1

    .line 430
    goto :goto_15

    .line 431
    :cond_24
    const/4 v0, 0x0

    .line 432
    :goto_15
    or-int v0, v16, v0

    .line 433
    .line 434
    invoke-virtual {v1, v8}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 435
    .line 436
    .line 437
    move-result v13

    .line 438
    or-int/2addr v0, v13

    .line 439
    const/high16 v13, 0xe000000

    .line 440
    .line 441
    and-int/2addr v13, v4

    .line 442
    xor-int v13, v13, v19

    .line 443
    .line 444
    move/from16 v16, v0

    .line 445
    .line 446
    const/high16 v0, 0x4000000

    .line 447
    .line 448
    if-le v13, v0, :cond_25

    .line 449
    .line 450
    invoke-virtual {v1, v9}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 451
    .line 452
    .line 453
    move-result v13

    .line 454
    if-nez v13, :cond_26

    .line 455
    .line 456
    :cond_25
    and-int v4, v4, v19

    .line 457
    .line 458
    if-ne v4, v0, :cond_27

    .line 459
    .line 460
    :cond_26
    const/4 v0, 0x1

    .line 461
    goto :goto_16

    .line 462
    :cond_27
    const/4 v0, 0x0

    .line 463
    :goto_16
    or-int v0, v16, v0

    .line 464
    .line 465
    and-int/lit8 v4, v2, 0xe

    .line 466
    .line 467
    const/4 v13, 0x4

    .line 468
    if-ne v4, v13, :cond_28

    .line 469
    .line 470
    const/4 v4, 0x1

    .line 471
    goto :goto_17

    .line 472
    :cond_28
    const/4 v4, 0x0

    .line 473
    :goto_17
    or-int/2addr v0, v4

    .line 474
    and-int/lit8 v4, v2, 0x70

    .line 475
    .line 476
    const/16 v13, 0x20

    .line 477
    .line 478
    if-ne v4, v13, :cond_29

    .line 479
    .line 480
    const/4 v4, 0x1

    .line 481
    goto :goto_18

    .line 482
    :cond_29
    const/4 v4, 0x0

    .line 483
    :goto_18
    or-int/2addr v0, v4

    .line 484
    and-int/lit16 v4, v2, 0x380

    .line 485
    .line 486
    const/16 v13, 0x100

    .line 487
    .line 488
    if-ne v4, v13, :cond_2a

    .line 489
    .line 490
    const/4 v4, 0x1

    .line 491
    goto :goto_19

    .line 492
    :cond_2a
    const/4 v4, 0x0

    .line 493
    :goto_19
    or-int/2addr v0, v4

    .line 494
    const/4 v4, 0x0

    .line 495
    invoke-virtual {v1, v4}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 496
    .line 497
    .line 498
    move-result v13

    .line 499
    or-int/2addr v0, v13

    .line 500
    and-int/lit16 v2, v2, 0x1c00

    .line 501
    .line 502
    const/16 v13, 0x800

    .line 503
    .line 504
    if-ne v2, v13, :cond_2b

    .line 505
    .line 506
    const/16 v20, 0x1

    .line 507
    .line 508
    goto :goto_1a

    .line 509
    :cond_2b
    const/16 v20, 0x0

    .line 510
    .line 511
    :goto_1a
    or-int v0, v0, v20

    .line 512
    .line 513
    invoke-virtual {v1}, Ll2/t;->L()Ljava/lang/Object;

    .line 514
    .line 515
    .line 516
    move-result-object v2

    .line 517
    if-nez v0, :cond_2d

    .line 518
    .line 519
    sget-object v0, Ll2/n;->a:Ll2/x0;

    .line 520
    .line 521
    if-ne v2, v0, :cond_2c

    .line 522
    .line 523
    goto :goto_1b

    .line 524
    :cond_2c
    move-object/from16 v4, p1

    .line 525
    .line 526
    move-object v12, v1

    .line 527
    move-object/from16 v13, v17

    .line 528
    .line 529
    goto :goto_1c

    .line 530
    :cond_2d
    :goto_1b
    new-instance v0, Luu/u1;

    .line 531
    .line 532
    move-object v2, v12

    .line 533
    move-object v12, v1

    .line 534
    move-object v1, v2

    .line 535
    move-object/from16 v4, p1

    .line 536
    .line 537
    move-object v2, v10

    .line 538
    move v10, v11

    .line 539
    move-object/from16 v13, v17

    .line 540
    .line 541
    move/from16 v11, p8

    .line 542
    .line 543
    invoke-direct/range {v0 .. v11}, Luu/u1;-><init>(Luu/x;Lay0/k;Ljava/util/ArrayList;Ljava/util/List;JLsp/d;Ljava/util/List;Lsp/d;ZF)V

    .line 544
    .line 545
    .line 546
    move-object v10, v2

    .line 547
    invoke-virtual {v12, v0}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 548
    .line 549
    .line 550
    move-object v2, v0

    .line 551
    :goto_1c
    check-cast v2, Lay0/a;

    .line 552
    .line 553
    instance-of v0, v13, Luu/x;

    .line 554
    .line 555
    if-eqz v0, :cond_31

    .line 556
    .line 557
    invoke-virtual {v12}, Ll2/t;->W()V

    .line 558
    .line 559
    .line 560
    iget-boolean v0, v12, Ll2/t;->S:Z

    .line 561
    .line 562
    if-eqz v0, :cond_2e

    .line 563
    .line 564
    invoke-virtual {v12, v2}, Ll2/t;->l(Lay0/a;)V

    .line 565
    .line 566
    .line 567
    goto :goto_1d

    .line 568
    :cond_2e
    invoke-virtual {v12}, Ll2/t;->m0()V

    .line 569
    .line 570
    .line 571
    :goto_1d
    new-instance v0, Luu/s1;

    .line 572
    .line 573
    const/4 v1, 0x4

    .line 574
    invoke-direct {v0, v1}, Luu/s1;-><init>(I)V

    .line 575
    .line 576
    .line 577
    invoke-static {v0, v10, v12}, Ll2/b;->w(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 578
    .line 579
    .line 580
    new-instance v0, Luu/f1;

    .line 581
    .line 582
    const/16 v1, 0x16

    .line 583
    .line 584
    invoke-direct {v0, v1}, Luu/f1;-><init>(I)V

    .line 585
    .line 586
    .line 587
    invoke-static {v0, v3, v12}, Ll2/b;->w(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 588
    .line 589
    .line 590
    new-instance v0, Luu/f1;

    .line 591
    .line 592
    const/16 v1, 0x17

    .line 593
    .line 594
    invoke-direct {v0, v1}, Luu/f1;-><init>(I)V

    .line 595
    .line 596
    .line 597
    invoke-static {v0, v4, v12}, Ll2/b;->w(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 598
    .line 599
    .line 600
    new-instance v0, Luu/f1;

    .line 601
    .line 602
    const/16 v1, 0x18

    .line 603
    .line 604
    invoke-direct {v0, v1}, Luu/f1;-><init>(I)V

    .line 605
    .line 606
    .line 607
    invoke-static {v0, v14, v12}, Ll2/b;->w(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 608
    .line 609
    .line 610
    new-instance v0, Le3/s;

    .line 611
    .line 612
    invoke-direct {v0, v5, v6}, Le3/s;-><init>(J)V

    .line 613
    .line 614
    .line 615
    sget-object v1, Luu/l;->m:Luu/l;

    .line 616
    .line 617
    invoke-static {v1, v0, v12}, Ll2/b;->w(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 618
    .line 619
    .line 620
    new-instance v0, Luu/f1;

    .line 621
    .line 622
    const/16 v1, 0x19

    .line 623
    .line 624
    invoke-direct {v0, v1}, Luu/f1;-><init>(I)V

    .line 625
    .line 626
    .line 627
    invoke-static {v0, v7, v12}, Ll2/b;->w(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 628
    .line 629
    .line 630
    new-instance v0, Luu/f1;

    .line 631
    .line 632
    const/16 v1, 0x1a

    .line 633
    .line 634
    invoke-direct {v0, v1}, Luu/f1;-><init>(I)V

    .line 635
    .line 636
    .line 637
    invoke-static {v0, v14, v12}, Ll2/b;->w(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 638
    .line 639
    .line 640
    new-instance v0, Luu/f1;

    .line 641
    .line 642
    const/16 v1, 0x1b

    .line 643
    .line 644
    invoke-direct {v0, v1}, Luu/f1;-><init>(I)V

    .line 645
    .line 646
    .line 647
    iget-boolean v1, v12, Ll2/t;->S:Z

    .line 648
    .line 649
    if-nez v1, :cond_2f

    .line 650
    .line 651
    invoke-virtual {v12}, Ll2/t;->L()Ljava/lang/Object;

    .line 652
    .line 653
    .line 654
    move-result-object v2

    .line 655
    invoke-static {v2, v15}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 656
    .line 657
    .line 658
    move-result v2

    .line 659
    if-nez v2, :cond_30

    .line 660
    .line 661
    :cond_2f
    invoke-virtual {v12, v15}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 662
    .line 663
    .line 664
    if-nez v1, :cond_30

    .line 665
    .line 666
    invoke-virtual {v12, v15, v0}, Ll2/t;->b(Ljava/lang/Object;Lay0/n;)V

    .line 667
    .line 668
    .line 669
    :cond_30
    new-instance v0, Luu/f1;

    .line 670
    .line 671
    const/16 v1, 0x1c

    .line 672
    .line 673
    invoke-direct {v0, v1}, Luu/f1;-><init>(I)V

    .line 674
    .line 675
    .line 676
    invoke-static {v0, v8, v12}, Ll2/b;->w(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 677
    .line 678
    .line 679
    new-instance v0, Luu/f1;

    .line 680
    .line 681
    const/16 v1, 0x1d

    .line 682
    .line 683
    invoke-direct {v0, v1}, Luu/f1;-><init>(I)V

    .line 684
    .line 685
    .line 686
    invoke-static {v0, v9, v12}, Ll2/b;->w(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 687
    .line 688
    .line 689
    new-instance v0, Luu/s1;

    .line 690
    .line 691
    const/4 v1, 0x0

    .line 692
    invoke-direct {v0, v1}, Luu/s1;-><init>(I)V

    .line 693
    .line 694
    .line 695
    const/4 v1, 0x0

    .line 696
    invoke-static {v0, v1, v12}, Ll2/b;->w(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 697
    .line 698
    .line 699
    invoke-static/range {p7 .. p7}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 700
    .line 701
    .line 702
    move-result-object v0

    .line 703
    new-instance v1, Luu/s1;

    .line 704
    .line 705
    const/4 v2, 0x1

    .line 706
    invoke-direct {v1, v2}, Luu/s1;-><init>(I)V

    .line 707
    .line 708
    .line 709
    invoke-static {v1, v0, v12}, Ll2/b;->w(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 710
    .line 711
    .line 712
    invoke-static/range {p8 .. p8}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 713
    .line 714
    .line 715
    move-result-object v0

    .line 716
    new-instance v1, Luu/s1;

    .line 717
    .line 718
    const/4 v2, 0x2

    .line 719
    invoke-direct {v1, v2}, Luu/s1;-><init>(I)V

    .line 720
    .line 721
    .line 722
    invoke-static {v1, v0, v12}, Ll2/b;->w(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 723
    .line 724
    .line 725
    invoke-static/range {v18 .. v18}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 726
    .line 727
    .line 728
    move-result-object v0

    .line 729
    new-instance v1, Luu/s1;

    .line 730
    .line 731
    const/4 v2, 0x3

    .line 732
    invoke-direct {v1, v2}, Luu/s1;-><init>(I)V

    .line 733
    .line 734
    .line 735
    invoke-static {v1, v0, v12}, Ll2/b;->w(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 736
    .line 737
    .line 738
    const/4 v0, 0x1

    .line 739
    invoke-virtual {v12, v0}, Ll2/t;->q(Z)V

    .line 740
    .line 741
    .line 742
    move-object v2, v4

    .line 743
    goto :goto_1e

    .line 744
    :cond_31
    const/4 v1, 0x0

    .line 745
    invoke-static {}, Ll2/b;->l()V

    .line 746
    .line 747
    .line 748
    throw v1

    .line 749
    :cond_32
    move-object v12, v1

    .line 750
    invoke-virtual {v12}, Ll2/t;->R()V

    .line 751
    .line 752
    .line 753
    move-object/from16 v2, p1

    .line 754
    .line 755
    :goto_1e
    invoke-virtual {v12}, Ll2/t;->s()Ll2/u1;

    .line 756
    .line 757
    .line 758
    move-result-object v13

    .line 759
    if-eqz v13, :cond_33

    .line 760
    .line 761
    new-instance v0, Luu/t1;

    .line 762
    .line 763
    move/from16 v11, p11

    .line 764
    .line 765
    move/from16 v12, p12

    .line 766
    .line 767
    move-object v1, v3

    .line 768
    move-wide v3, v5

    .line 769
    move-object v5, v7

    .line 770
    move-object v6, v8

    .line 771
    move-object v7, v9

    .line 772
    move/from16 v8, p7

    .line 773
    .line 774
    move/from16 v9, p8

    .line 775
    .line 776
    invoke-direct/range {v0 .. v12}, Luu/t1;-><init>(Ljava/util/ArrayList;Ljava/util/List;JLsp/d;Ljava/util/List;Lsp/d;ZFLay0/k;II)V

    .line 777
    .line 778
    .line 779
    iput-object v0, v13, Ll2/u1;->d:Lay0/n;

    .line 780
    .line 781
    :cond_33
    return-void
.end method

.method public static final c(Ljava/lang/String;Lxh/e;Lzb/s0;Ll2/o;I)V
    .locals 19

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
    move-object/from16 v9, p3

    .line 8
    .line 9
    check-cast v9, Ll2/t;

    .line 10
    .line 11
    const v0, 0x28b95320

    .line 12
    .line 13
    .line 14
    invoke-virtual {v9, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 15
    .line 16
    .line 17
    invoke-virtual {v9, v1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 18
    .line 19
    .line 20
    move-result v0

    .line 21
    const/4 v4, 0x4

    .line 22
    if-eqz v0, :cond_0

    .line 23
    .line 24
    move v0, v4

    .line 25
    goto :goto_0

    .line 26
    :cond_0
    const/4 v0, 0x2

    .line 27
    :goto_0
    or-int v0, p4, v0

    .line 28
    .line 29
    invoke-virtual {v9, v2}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 30
    .line 31
    .line 32
    move-result v5

    .line 33
    const/16 v6, 0x20

    .line 34
    .line 35
    if-eqz v5, :cond_1

    .line 36
    .line 37
    move v5, v6

    .line 38
    goto :goto_1

    .line 39
    :cond_1
    const/16 v5, 0x10

    .line 40
    .line 41
    :goto_1
    or-int/2addr v0, v5

    .line 42
    invoke-virtual {v9, v3}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 43
    .line 44
    .line 45
    move-result v5

    .line 46
    const/16 v7, 0x100

    .line 47
    .line 48
    if-eqz v5, :cond_2

    .line 49
    .line 50
    move v5, v7

    .line 51
    goto :goto_2

    .line 52
    :cond_2
    const/16 v5, 0x80

    .line 53
    .line 54
    :goto_2
    or-int/2addr v0, v5

    .line 55
    and-int/lit16 v5, v0, 0x93

    .line 56
    .line 57
    const/16 v8, 0x92

    .line 58
    .line 59
    const/4 v10, 0x1

    .line 60
    const/4 v11, 0x0

    .line 61
    if-eq v5, v8, :cond_3

    .line 62
    .line 63
    move v5, v10

    .line 64
    goto :goto_3

    .line 65
    :cond_3
    move v5, v11

    .line 66
    :goto_3
    and-int/lit8 v8, v0, 0x1

    .line 67
    .line 68
    invoke-virtual {v9, v8, v5}, Ll2/t;->O(IZ)Z

    .line 69
    .line 70
    .line 71
    move-result v5

    .line 72
    if-eqz v5, :cond_e

    .line 73
    .line 74
    and-int/lit8 v5, v0, 0xe

    .line 75
    .line 76
    if-ne v5, v4, :cond_4

    .line 77
    .line 78
    move v4, v10

    .line 79
    goto :goto_4

    .line 80
    :cond_4
    move v4, v11

    .line 81
    :goto_4
    and-int/lit8 v5, v0, 0x70

    .line 82
    .line 83
    if-ne v5, v6, :cond_5

    .line 84
    .line 85
    move v5, v10

    .line 86
    goto :goto_5

    .line 87
    :cond_5
    move v5, v11

    .line 88
    :goto_5
    or-int/2addr v4, v5

    .line 89
    and-int/lit16 v0, v0, 0x380

    .line 90
    .line 91
    if-ne v0, v7, :cond_6

    .line 92
    .line 93
    goto :goto_6

    .line 94
    :cond_6
    move v10, v11

    .line 95
    :goto_6
    or-int v0, v4, v10

    .line 96
    .line 97
    invoke-virtual {v9}, Ll2/t;->L()Ljava/lang/Object;

    .line 98
    .line 99
    .line 100
    move-result-object v4

    .line 101
    sget-object v10, Ll2/n;->a:Ll2/x0;

    .line 102
    .line 103
    if-nez v0, :cond_7

    .line 104
    .line 105
    if-ne v4, v10, :cond_8

    .line 106
    .line 107
    :cond_7
    new-instance v4, Lhh/a;

    .line 108
    .line 109
    const/4 v0, 0x1

    .line 110
    invoke-direct {v4, v1, v2, v3, v0}, Lhh/a;-><init>(Ljava/lang/String;Lxh/e;Lzb/s0;I)V

    .line 111
    .line 112
    .line 113
    invoke-virtual {v9, v4}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 114
    .line 115
    .line 116
    :cond_8
    check-cast v4, Lay0/k;

    .line 117
    .line 118
    sget-object v0, Lw3/q1;->a:Ll2/u2;

    .line 119
    .line 120
    invoke-virtual {v9, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 121
    .line 122
    .line 123
    move-result-object v0

    .line 124
    check-cast v0, Ljava/lang/Boolean;

    .line 125
    .line 126
    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 127
    .line 128
    .line 129
    move-result v0

    .line 130
    if-eqz v0, :cond_9

    .line 131
    .line 132
    const v0, -0x105bcaaa

    .line 133
    .line 134
    .line 135
    invoke-virtual {v9, v0}, Ll2/t;->Y(I)V

    .line 136
    .line 137
    .line 138
    invoke-virtual {v9, v11}, Ll2/t;->q(Z)V

    .line 139
    .line 140
    .line 141
    const/4 v0, 0x0

    .line 142
    goto :goto_7

    .line 143
    :cond_9
    const v0, 0x31054eee

    .line 144
    .line 145
    .line 146
    invoke-virtual {v9, v0}, Ll2/t;->Y(I)V

    .line 147
    .line 148
    .line 149
    sget-object v0, Lzb/x;->a:Ll2/u2;

    .line 150
    .line 151
    invoke-virtual {v9, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 152
    .line 153
    .line 154
    move-result-object v0

    .line 155
    check-cast v0, Lhi/a;

    .line 156
    .line 157
    invoke-virtual {v9, v11}, Ll2/t;->q(Z)V

    .line 158
    .line 159
    .line 160
    :goto_7
    new-instance v7, Laf/a;

    .line 161
    .line 162
    const/16 v5, 0x14

    .line 163
    .line 164
    invoke-direct {v7, v0, v4, v5}, Laf/a;-><init>(Lhi/a;Lay0/k;I)V

    .line 165
    .line 166
    .line 167
    invoke-static {v9}, Lq7/a;->a(Ll2/o;)Landroidx/lifecycle/i1;

    .line 168
    .line 169
    .line 170
    move-result-object v5

    .line 171
    if-eqz v5, :cond_d

    .line 172
    .line 173
    instance-of v0, v5, Landroidx/lifecycle/k;

    .line 174
    .line 175
    if-eqz v0, :cond_a

    .line 176
    .line 177
    move-object v0, v5

    .line 178
    check-cast v0, Landroidx/lifecycle/k;

    .line 179
    .line 180
    invoke-interface {v0}, Landroidx/lifecycle/k;->getDefaultViewModelCreationExtras()Lp7/c;

    .line 181
    .line 182
    .line 183
    move-result-object v0

    .line 184
    :goto_8
    move-object v8, v0

    .line 185
    goto :goto_9

    .line 186
    :cond_a
    sget-object v0, Lp7/a;->b:Lp7/a;

    .line 187
    .line 188
    goto :goto_8

    .line 189
    :goto_9
    const-class v0, Lih/d;

    .line 190
    .line 191
    sget-object v4, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 192
    .line 193
    invoke-virtual {v4, v0}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 194
    .line 195
    .line 196
    move-result-object v4

    .line 197
    const/4 v6, 0x0

    .line 198
    invoke-static/range {v4 .. v9}, Ljp/se;->b(Lhy0/d;Landroidx/lifecycle/i1;Ljava/lang/String;Landroidx/lifecycle/e1;Lp7/c;Ll2/o;)Landroidx/lifecycle/b1;

    .line 199
    .line 200
    .line 201
    move-result-object v0

    .line 202
    move-object v13, v0

    .line 203
    check-cast v13, Lih/d;

    .line 204
    .line 205
    invoke-static {v9}, Leh/a;->b(Ll2/o;)Leh/n;

    .line 206
    .line 207
    .line 208
    move-result-object v0

    .line 209
    iget-object v4, v13, Lih/d;->i:Lyy0/l1;

    .line 210
    .line 211
    invoke-static {v4, v9}, Ljp/b2;->c(Lyy0/a2;Ll2/o;)Ll2/b1;

    .line 212
    .line 213
    .line 214
    move-result-object v4

    .line 215
    invoke-interface {v4}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 216
    .line 217
    .line 218
    move-result-object v4

    .line 219
    check-cast v4, Llc/q;

    .line 220
    .line 221
    invoke-virtual {v9, v13}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 222
    .line 223
    .line 224
    move-result v5

    .line 225
    invoke-virtual {v9}, Ll2/t;->L()Ljava/lang/Object;

    .line 226
    .line 227
    .line 228
    move-result-object v6

    .line 229
    if-nez v5, :cond_b

    .line 230
    .line 231
    if-ne v6, v10, :cond_c

    .line 232
    .line 233
    :cond_b
    new-instance v11, Li40/u2;

    .line 234
    .line 235
    const/16 v17, 0x0

    .line 236
    .line 237
    const/16 v18, 0x1d

    .line 238
    .line 239
    const/4 v12, 0x1

    .line 240
    const-class v14, Lih/d;

    .line 241
    .line 242
    const-string v15, "onUiEvent"

    .line 243
    .line 244
    const-string v16, "onUiEvent(Lcariad/charging/multicharge/kitten/wallboxes/presentation/detail2/WallboxDetailUiEvent;)V"

    .line 245
    .line 246
    invoke-direct/range {v11 .. v18}, Li40/u2;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 247
    .line 248
    .line 249
    invoke-virtual {v9, v11}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 250
    .line 251
    .line 252
    move-object v6, v11

    .line 253
    :cond_c
    check-cast v6, Lhy0/g;

    .line 254
    .line 255
    check-cast v6, Lay0/k;

    .line 256
    .line 257
    const/16 v5, 0x8

    .line 258
    .line 259
    invoke-interface {v0, v4, v6, v9, v5}, Leh/n;->L(Llc/q;Lay0/k;Ll2/o;I)V

    .line 260
    .line 261
    .line 262
    goto :goto_a

    .line 263
    :cond_d
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 264
    .line 265
    const-string v1, "No ViewModelStoreOwner was provided via LocalViewModelStoreOwner"

    .line 266
    .line 267
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 268
    .line 269
    .line 270
    throw v0

    .line 271
    :cond_e
    invoke-virtual {v9}, Ll2/t;->R()V

    .line 272
    .line 273
    .line 274
    :goto_a
    invoke-virtual {v9}, Ll2/t;->s()Ll2/u1;

    .line 275
    .line 276
    .line 277
    move-result-object v6

    .line 278
    if-eqz v6, :cond_f

    .line 279
    .line 280
    new-instance v0, Lhh/b;

    .line 281
    .line 282
    const/4 v5, 0x1

    .line 283
    move/from16 v4, p4

    .line 284
    .line 285
    invoke-direct/range {v0 .. v5}, Lhh/b;-><init>(Ljava/lang/String;Lxh/e;Lzb/s0;II)V

    .line 286
    .line 287
    .line 288
    iput-object v0, v6, Ll2/u1;->d:Lay0/n;

    .line 289
    .line 290
    :cond_f
    return-void
.end method
