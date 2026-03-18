.class public abstract Lkp/g7;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Lx2/s;Le3/n0;JJFLt2/b;Ll2/o;II)V
    .locals 18

    .line 1
    move-wide/from16 v5, p4

    .line 2
    .line 3
    move/from16 v9, p9

    .line 4
    .line 5
    move-object/from16 v0, p8

    .line 6
    .line 7
    check-cast v0, Ll2/t;

    .line 8
    .line 9
    const v1, 0xa6081e7

    .line 10
    .line 11
    .line 12
    invoke-virtual {v0, v1}, Ll2/t;->a0(I)Ll2/t;

    .line 13
    .line 14
    .line 15
    and-int/lit8 v1, v9, 0x6

    .line 16
    .line 17
    move-object/from16 v11, p0

    .line 18
    .line 19
    if-nez v1, :cond_1

    .line 20
    .line 21
    invoke-virtual {v0, v11}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 22
    .line 23
    .line 24
    move-result v1

    .line 25
    if-eqz v1, :cond_0

    .line 26
    .line 27
    const/4 v1, 0x4

    .line 28
    goto :goto_0

    .line 29
    :cond_0
    const/4 v1, 0x2

    .line 30
    :goto_0
    or-int/2addr v1, v9

    .line 31
    goto :goto_1

    .line 32
    :cond_1
    move v1, v9

    .line 33
    :goto_1
    and-int/lit8 v2, p10, 0x2

    .line 34
    .line 35
    if-eqz v2, :cond_3

    .line 36
    .line 37
    or-int/lit8 v1, v1, 0x30

    .line 38
    .line 39
    :cond_2
    move-object/from16 v3, p1

    .line 40
    .line 41
    goto :goto_3

    .line 42
    :cond_3
    and-int/lit8 v3, v9, 0x30

    .line 43
    .line 44
    if-nez v3, :cond_2

    .line 45
    .line 46
    move-object/from16 v3, p1

    .line 47
    .line 48
    invoke-virtual {v0, v3}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 49
    .line 50
    .line 51
    move-result v4

    .line 52
    if-eqz v4, :cond_4

    .line 53
    .line 54
    const/16 v4, 0x20

    .line 55
    .line 56
    goto :goto_2

    .line 57
    :cond_4
    const/16 v4, 0x10

    .line 58
    .line 59
    :goto_2
    or-int/2addr v1, v4

    .line 60
    :goto_3
    and-int/lit16 v4, v9, 0x180

    .line 61
    .line 62
    move-wide/from16 v13, p2

    .line 63
    .line 64
    if-nez v4, :cond_6

    .line 65
    .line 66
    invoke-virtual {v0, v13, v14}, Ll2/t;->f(J)Z

    .line 67
    .line 68
    .line 69
    move-result v4

    .line 70
    if-eqz v4, :cond_5

    .line 71
    .line 72
    const/16 v4, 0x100

    .line 73
    .line 74
    goto :goto_4

    .line 75
    :cond_5
    const/16 v4, 0x80

    .line 76
    .line 77
    :goto_4
    or-int/2addr v1, v4

    .line 78
    :cond_6
    and-int/lit16 v4, v9, 0xc00

    .line 79
    .line 80
    if-nez v4, :cond_8

    .line 81
    .line 82
    invoke-virtual {v0, v5, v6}, Ll2/t;->f(J)Z

    .line 83
    .line 84
    .line 85
    move-result v4

    .line 86
    if-eqz v4, :cond_7

    .line 87
    .line 88
    const/16 v4, 0x800

    .line 89
    .line 90
    goto :goto_5

    .line 91
    :cond_7
    const/16 v4, 0x400

    .line 92
    .line 93
    :goto_5
    or-int/2addr v1, v4

    .line 94
    :cond_8
    and-int/lit8 v4, p10, 0x10

    .line 95
    .line 96
    if-eqz v4, :cond_9

    .line 97
    .line 98
    or-int/lit16 v1, v1, 0x6000

    .line 99
    .line 100
    goto :goto_7

    .line 101
    :cond_9
    and-int/lit16 v4, v9, 0x6000

    .line 102
    .line 103
    if-nez v4, :cond_b

    .line 104
    .line 105
    const/4 v4, 0x0

    .line 106
    invoke-virtual {v0, v4}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 107
    .line 108
    .line 109
    move-result v4

    .line 110
    if-eqz v4, :cond_a

    .line 111
    .line 112
    const/16 v4, 0x4000

    .line 113
    .line 114
    goto :goto_6

    .line 115
    :cond_a
    const/16 v4, 0x2000

    .line 116
    .line 117
    :goto_6
    or-int/2addr v1, v4

    .line 118
    :cond_b
    :goto_7
    and-int/lit8 v4, p10, 0x20

    .line 119
    .line 120
    const/high16 v7, 0x30000

    .line 121
    .line 122
    if-eqz v4, :cond_d

    .line 123
    .line 124
    or-int/2addr v1, v7

    .line 125
    :cond_c
    move/from16 v7, p6

    .line 126
    .line 127
    goto :goto_9

    .line 128
    :cond_d
    and-int/2addr v7, v9

    .line 129
    if-nez v7, :cond_c

    .line 130
    .line 131
    move/from16 v7, p6

    .line 132
    .line 133
    invoke-virtual {v0, v7}, Ll2/t;->d(F)Z

    .line 134
    .line 135
    .line 136
    move-result v8

    .line 137
    if-eqz v8, :cond_e

    .line 138
    .line 139
    const/high16 v8, 0x20000

    .line 140
    .line 141
    goto :goto_8

    .line 142
    :cond_e
    const/high16 v8, 0x10000

    .line 143
    .line 144
    :goto_8
    or-int/2addr v1, v8

    .line 145
    :goto_9
    const/high16 v8, 0x180000

    .line 146
    .line 147
    and-int/2addr v8, v9

    .line 148
    if-nez v8, :cond_10

    .line 149
    .line 150
    move-object/from16 v8, p7

    .line 151
    .line 152
    invoke-virtual {v0, v8}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 153
    .line 154
    .line 155
    move-result v10

    .line 156
    if-eqz v10, :cond_f

    .line 157
    .line 158
    const/high16 v10, 0x100000

    .line 159
    .line 160
    goto :goto_a

    .line 161
    :cond_f
    const/high16 v10, 0x80000

    .line 162
    .line 163
    :goto_a
    or-int/2addr v1, v10

    .line 164
    goto :goto_b

    .line 165
    :cond_10
    move-object/from16 v8, p7

    .line 166
    .line 167
    :goto_b
    const v10, 0x92493

    .line 168
    .line 169
    .line 170
    and-int/2addr v10, v1

    .line 171
    const v12, 0x92492

    .line 172
    .line 173
    .line 174
    const/4 v15, 0x0

    .line 175
    const/16 v16, 0x1

    .line 176
    .line 177
    if-eq v10, v12, :cond_11

    .line 178
    .line 179
    move/from16 v10, v16

    .line 180
    .line 181
    goto :goto_c

    .line 182
    :cond_11
    move v10, v15

    .line 183
    :goto_c
    and-int/lit8 v1, v1, 0x1

    .line 184
    .line 185
    invoke-virtual {v0, v1, v10}, Ll2/t;->O(IZ)Z

    .line 186
    .line 187
    .line 188
    move-result v1

    .line 189
    if-eqz v1, :cond_16

    .line 190
    .line 191
    invoke-virtual {v0}, Ll2/t;->T()V

    .line 192
    .line 193
    .line 194
    and-int/lit8 v1, v9, 0x1

    .line 195
    .line 196
    if-eqz v1, :cond_13

    .line 197
    .line 198
    invoke-virtual {v0}, Ll2/t;->y()Z

    .line 199
    .line 200
    .line 201
    move-result v1

    .line 202
    if-eqz v1, :cond_12

    .line 203
    .line 204
    goto :goto_e

    .line 205
    :cond_12
    invoke-virtual {v0}, Ll2/t;->R()V

    .line 206
    .line 207
    .line 208
    move-object v12, v3

    .line 209
    :goto_d
    move/from16 v16, v7

    .line 210
    .line 211
    goto :goto_10

    .line 212
    :cond_13
    :goto_e
    if-eqz v2, :cond_14

    .line 213
    .line 214
    sget-object v1, Le3/j0;->a:Le3/i0;

    .line 215
    .line 216
    goto :goto_f

    .line 217
    :cond_14
    move-object v1, v3

    .line 218
    :goto_f
    if-eqz v4, :cond_15

    .line 219
    .line 220
    int-to-float v2, v15

    .line 221
    move-object v12, v1

    .line 222
    move/from16 v16, v2

    .line 223
    .line 224
    goto :goto_10

    .line 225
    :cond_15
    move-object v12, v1

    .line 226
    goto :goto_d

    .line 227
    :goto_10
    invoke-virtual {v0}, Ll2/t;->r()V

    .line 228
    .line 229
    .line 230
    sget-object v1, Lf2/y;->b:Ll2/e0;

    .line 231
    .line 232
    invoke-virtual {v0, v1}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 233
    .line 234
    .line 235
    move-result-object v2

    .line 236
    check-cast v2, Lt4/f;

    .line 237
    .line 238
    iget v2, v2, Lt4/f;->d:F

    .line 239
    .line 240
    add-float v15, v2, v16

    .line 241
    .line 242
    sget-object v2, Lf2/k;->a:Ll2/e0;

    .line 243
    .line 244
    invoke-static {v5, v6, v2}, Lf2/m0;->s(JLl2/e0;)Ll2/t1;

    .line 245
    .line 246
    .line 247
    move-result-object v2

    .line 248
    new-instance v3, Lt4/f;

    .line 249
    .line 250
    invoke-direct {v3, v15}, Lt4/f;-><init>(F)V

    .line 251
    .line 252
    .line 253
    invoke-virtual {v1, v3}, Ll2/e0;->a(Ljava/lang/Object;)Ll2/t1;

    .line 254
    .line 255
    .line 256
    move-result-object v1

    .line 257
    filled-new-array {v2, v1}, [Ll2/t1;

    .line 258
    .line 259
    .line 260
    move-result-object v1

    .line 261
    new-instance v10, Lf2/q0;

    .line 262
    .line 263
    move-object/from16 v17, v8

    .line 264
    .line 265
    invoke-direct/range {v10 .. v17}, Lf2/q0;-><init>(Lx2/s;Le3/n0;JFFLt2/b;)V

    .line 266
    .line 267
    .line 268
    const v2, -0x7776e959

    .line 269
    .line 270
    .line 271
    invoke-static {v2, v0, v10}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 272
    .line 273
    .line 274
    move-result-object v2

    .line 275
    const/16 v3, 0x38

    .line 276
    .line 277
    invoke-static {v1, v2, v0, v3}, Ll2/b;->b([Ll2/t1;Lay0/n;Ll2/o;I)V

    .line 278
    .line 279
    .line 280
    move-object v2, v12

    .line 281
    move/from16 v7, v16

    .line 282
    .line 283
    goto :goto_11

    .line 284
    :cond_16
    invoke-virtual {v0}, Ll2/t;->R()V

    .line 285
    .line 286
    .line 287
    move-object v2, v3

    .line 288
    :goto_11
    invoke-virtual {v0}, Ll2/t;->s()Ll2/u1;

    .line 289
    .line 290
    .line 291
    move-result-object v11

    .line 292
    if-eqz v11, :cond_17

    .line 293
    .line 294
    new-instance v0, Lf2/n0;

    .line 295
    .line 296
    move-object/from16 v1, p0

    .line 297
    .line 298
    move-wide/from16 v3, p2

    .line 299
    .line 300
    move-object/from16 v8, p7

    .line 301
    .line 302
    move/from16 v10, p10

    .line 303
    .line 304
    invoke-direct/range {v0 .. v10}, Lf2/n0;-><init>(Lx2/s;Le3/n0;JJFLt2/b;II)V

    .line 305
    .line 306
    .line 307
    iput-object v0, v11, Ll2/u1;->d:Lay0/n;

    .line 308
    .line 309
    :cond_17
    return-void
.end method

.method public static final b(Lay0/a;Lx2/s;ZLe3/n0;JJFLi1/l;Lt2/b;Ll2/o;II)V
    .locals 20

    .line 1
    move-wide/from16 v7, p6

    .line 2
    .line 3
    move/from16 v9, p8

    .line 4
    .line 5
    move/from16 v0, p12

    .line 6
    .line 7
    move-object/from16 v1, p11

    .line 8
    .line 9
    check-cast v1, Ll2/t;

    .line 10
    .line 11
    const v2, 0x7fa1c77a

    .line 12
    .line 13
    .line 14
    invoke-virtual {v1, v2}, Ll2/t;->a0(I)Ll2/t;

    .line 15
    .line 16
    .line 17
    and-int/lit8 v2, v0, 0x6

    .line 18
    .line 19
    if-nez v2, :cond_1

    .line 20
    .line 21
    move-object/from16 v2, p0

    .line 22
    .line 23
    invoke-virtual {v1, v2}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 24
    .line 25
    .line 26
    move-result v3

    .line 27
    if-eqz v3, :cond_0

    .line 28
    .line 29
    const/4 v3, 0x4

    .line 30
    goto :goto_0

    .line 31
    :cond_0
    const/4 v3, 0x2

    .line 32
    :goto_0
    or-int/2addr v3, v0

    .line 33
    goto :goto_1

    .line 34
    :cond_1
    move-object/from16 v2, p0

    .line 35
    .line 36
    move v3, v0

    .line 37
    :goto_1
    and-int/lit8 v4, v0, 0x30

    .line 38
    .line 39
    move-object/from16 v10, p1

    .line 40
    .line 41
    if-nez v4, :cond_3

    .line 42
    .line 43
    invoke-virtual {v1, v10}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 44
    .line 45
    .line 46
    move-result v4

    .line 47
    if-eqz v4, :cond_2

    .line 48
    .line 49
    const/16 v4, 0x20

    .line 50
    .line 51
    goto :goto_2

    .line 52
    :cond_2
    const/16 v4, 0x10

    .line 53
    .line 54
    :goto_2
    or-int/2addr v3, v4

    .line 55
    :cond_3
    and-int/lit8 v4, p13, 0x4

    .line 56
    .line 57
    if-eqz v4, :cond_5

    .line 58
    .line 59
    or-int/lit16 v3, v3, 0x180

    .line 60
    .line 61
    :cond_4
    move/from16 v5, p2

    .line 62
    .line 63
    goto :goto_4

    .line 64
    :cond_5
    and-int/lit16 v5, v0, 0x180

    .line 65
    .line 66
    if-nez v5, :cond_4

    .line 67
    .line 68
    move/from16 v5, p2

    .line 69
    .line 70
    invoke-virtual {v1, v5}, Ll2/t;->h(Z)Z

    .line 71
    .line 72
    .line 73
    move-result v6

    .line 74
    if-eqz v6, :cond_6

    .line 75
    .line 76
    const/16 v6, 0x100

    .line 77
    .line 78
    goto :goto_3

    .line 79
    :cond_6
    const/16 v6, 0x80

    .line 80
    .line 81
    :goto_3
    or-int/2addr v3, v6

    .line 82
    :goto_4
    and-int/lit16 v6, v0, 0xc00

    .line 83
    .line 84
    move-object/from16 v11, p3

    .line 85
    .line 86
    if-nez v6, :cond_8

    .line 87
    .line 88
    invoke-virtual {v1, v11}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 89
    .line 90
    .line 91
    move-result v6

    .line 92
    if-eqz v6, :cond_7

    .line 93
    .line 94
    const/16 v6, 0x800

    .line 95
    .line 96
    goto :goto_5

    .line 97
    :cond_7
    const/16 v6, 0x400

    .line 98
    .line 99
    :goto_5
    or-int/2addr v3, v6

    .line 100
    :cond_8
    and-int/lit16 v6, v0, 0x6000

    .line 101
    .line 102
    move-wide/from16 v12, p4

    .line 103
    .line 104
    if-nez v6, :cond_a

    .line 105
    .line 106
    invoke-virtual {v1, v12, v13}, Ll2/t;->f(J)Z

    .line 107
    .line 108
    .line 109
    move-result v6

    .line 110
    if-eqz v6, :cond_9

    .line 111
    .line 112
    const/16 v6, 0x4000

    .line 113
    .line 114
    goto :goto_6

    .line 115
    :cond_9
    const/16 v6, 0x2000

    .line 116
    .line 117
    :goto_6
    or-int/2addr v3, v6

    .line 118
    :cond_a
    const/high16 v6, 0x30000

    .line 119
    .line 120
    and-int/2addr v6, v0

    .line 121
    if-nez v6, :cond_c

    .line 122
    .line 123
    invoke-virtual {v1, v7, v8}, Ll2/t;->f(J)Z

    .line 124
    .line 125
    .line 126
    move-result v6

    .line 127
    if-eqz v6, :cond_b

    .line 128
    .line 129
    const/high16 v6, 0x20000

    .line 130
    .line 131
    goto :goto_7

    .line 132
    :cond_b
    const/high16 v6, 0x10000

    .line 133
    .line 134
    :goto_7
    or-int/2addr v3, v6

    .line 135
    :cond_c
    and-int/lit8 v6, p13, 0x40

    .line 136
    .line 137
    const/high16 v14, 0x180000

    .line 138
    .line 139
    if-eqz v6, :cond_d

    .line 140
    .line 141
    or-int/2addr v3, v14

    .line 142
    goto :goto_9

    .line 143
    :cond_d
    and-int v6, v0, v14

    .line 144
    .line 145
    if-nez v6, :cond_f

    .line 146
    .line 147
    const/4 v6, 0x0

    .line 148
    invoke-virtual {v1, v6}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 149
    .line 150
    .line 151
    move-result v6

    .line 152
    if-eqz v6, :cond_e

    .line 153
    .line 154
    const/high16 v6, 0x100000

    .line 155
    .line 156
    goto :goto_8

    .line 157
    :cond_e
    const/high16 v6, 0x80000

    .line 158
    .line 159
    :goto_8
    or-int/2addr v3, v6

    .line 160
    :cond_f
    :goto_9
    const/high16 v6, 0xc00000

    .line 161
    .line 162
    and-int/2addr v6, v0

    .line 163
    if-nez v6, :cond_11

    .line 164
    .line 165
    invoke-virtual {v1, v9}, Ll2/t;->d(F)Z

    .line 166
    .line 167
    .line 168
    move-result v6

    .line 169
    if-eqz v6, :cond_10

    .line 170
    .line 171
    const/high16 v6, 0x800000

    .line 172
    .line 173
    goto :goto_a

    .line 174
    :cond_10
    const/high16 v6, 0x400000

    .line 175
    .line 176
    :goto_a
    or-int/2addr v3, v6

    .line 177
    :cond_11
    const/high16 v6, 0x6000000

    .line 178
    .line 179
    and-int/2addr v6, v0

    .line 180
    if-nez v6, :cond_13

    .line 181
    .line 182
    move-object/from16 v6, p9

    .line 183
    .line 184
    invoke-virtual {v1, v6}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 185
    .line 186
    .line 187
    move-result v14

    .line 188
    if-eqz v14, :cond_12

    .line 189
    .line 190
    const/high16 v14, 0x4000000

    .line 191
    .line 192
    goto :goto_b

    .line 193
    :cond_12
    const/high16 v14, 0x2000000

    .line 194
    .line 195
    :goto_b
    or-int/2addr v3, v14

    .line 196
    goto :goto_c

    .line 197
    :cond_13
    move-object/from16 v6, p9

    .line 198
    .line 199
    :goto_c
    const/high16 v14, 0x30000000

    .line 200
    .line 201
    and-int/2addr v14, v0

    .line 202
    if-nez v14, :cond_15

    .line 203
    .line 204
    move-object/from16 v14, p10

    .line 205
    .line 206
    invoke-virtual {v1, v14}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 207
    .line 208
    .line 209
    move-result v15

    .line 210
    if-eqz v15, :cond_14

    .line 211
    .line 212
    const/high16 v15, 0x20000000

    .line 213
    .line 214
    goto :goto_d

    .line 215
    :cond_14
    const/high16 v15, 0x10000000

    .line 216
    .line 217
    :goto_d
    or-int/2addr v3, v15

    .line 218
    goto :goto_e

    .line 219
    :cond_15
    move-object/from16 v14, p10

    .line 220
    .line 221
    :goto_e
    const v15, 0x12492493

    .line 222
    .line 223
    .line 224
    and-int/2addr v15, v3

    .line 225
    const v0, 0x12492492

    .line 226
    .line 227
    .line 228
    const/16 v16, 0x1

    .line 229
    .line 230
    if-eq v15, v0, :cond_16

    .line 231
    .line 232
    move/from16 v0, v16

    .line 233
    .line 234
    goto :goto_f

    .line 235
    :cond_16
    const/4 v0, 0x0

    .line 236
    :goto_f
    and-int/lit8 v3, v3, 0x1

    .line 237
    .line 238
    invoke-virtual {v1, v3, v0}, Ll2/t;->O(IZ)Z

    .line 239
    .line 240
    .line 241
    move-result v0

    .line 242
    if-eqz v0, :cond_1a

    .line 243
    .line 244
    invoke-virtual {v1}, Ll2/t;->T()V

    .line 245
    .line 246
    .line 247
    and-int/lit8 v0, p12, 0x1

    .line 248
    .line 249
    if-eqz v0, :cond_19

    .line 250
    .line 251
    invoke-virtual {v1}, Ll2/t;->y()Z

    .line 252
    .line 253
    .line 254
    move-result v0

    .line 255
    if-eqz v0, :cond_17

    .line 256
    .line 257
    goto :goto_11

    .line 258
    :cond_17
    invoke-virtual {v1}, Ll2/t;->R()V

    .line 259
    .line 260
    .line 261
    :cond_18
    :goto_10
    move/from16 v17, v5

    .line 262
    .line 263
    goto :goto_12

    .line 264
    :cond_19
    :goto_11
    if-eqz v4, :cond_18

    .line 265
    .line 266
    move/from16 v5, v16

    .line 267
    .line 268
    goto :goto_10

    .line 269
    :goto_12
    invoke-virtual {v1}, Ll2/t;->r()V

    .line 270
    .line 271
    .line 272
    sget-object v0, Lf2/y;->b:Ll2/e0;

    .line 273
    .line 274
    invoke-virtual {v1, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 275
    .line 276
    .line 277
    move-result-object v3

    .line 278
    check-cast v3, Lt4/f;

    .line 279
    .line 280
    iget v3, v3, Lt4/f;->d:F

    .line 281
    .line 282
    add-float/2addr v3, v9

    .line 283
    sget-object v4, Lf2/k;->a:Ll2/e0;

    .line 284
    .line 285
    invoke-static {v7, v8, v4}, Lf2/m0;->s(JLl2/e0;)Ll2/t1;

    .line 286
    .line 287
    .line 288
    move-result-object v4

    .line 289
    new-instance v5, Lt4/f;

    .line 290
    .line 291
    invoke-direct {v5, v3}, Lt4/f;-><init>(F)V

    .line 292
    .line 293
    .line 294
    invoke-virtual {v0, v5}, Ll2/e0;->a(Ljava/lang/Object;)Ll2/t1;

    .line 295
    .line 296
    .line 297
    move-result-object v0

    .line 298
    filled-new-array {v4, v0}, [Ll2/t1;

    .line 299
    .line 300
    .line 301
    move-result-object v0

    .line 302
    new-instance v9, Lf2/r0;

    .line 303
    .line 304
    move/from16 v15, p8

    .line 305
    .line 306
    move-object/from16 v18, v2

    .line 307
    .line 308
    move-object/from16 v16, v6

    .line 309
    .line 310
    move-object/from16 v19, v14

    .line 311
    .line 312
    move v14, v3

    .line 313
    invoke-direct/range {v9 .. v19}, Lf2/r0;-><init>(Lx2/s;Le3/n0;JFFLi1/l;ZLay0/a;Lt2/b;)V

    .line 314
    .line 315
    .line 316
    const v2, -0x694c4546

    .line 317
    .line 318
    .line 319
    invoke-static {v2, v1, v9}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 320
    .line 321
    .line 322
    move-result-object v2

    .line 323
    const/16 v3, 0x38

    .line 324
    .line 325
    invoke-static {v0, v2, v1, v3}, Ll2/b;->b([Ll2/t1;Lay0/n;Ll2/o;I)V

    .line 326
    .line 327
    .line 328
    move/from16 v3, v17

    .line 329
    .line 330
    goto :goto_13

    .line 331
    :cond_1a
    invoke-virtual {v1}, Ll2/t;->R()V

    .line 332
    .line 333
    .line 334
    move v3, v5

    .line 335
    :goto_13
    invoke-virtual {v1}, Ll2/t;->s()Ll2/u1;

    .line 336
    .line 337
    .line 338
    move-result-object v14

    .line 339
    if-eqz v14, :cond_1b

    .line 340
    .line 341
    new-instance v0, Lf2/o0;

    .line 342
    .line 343
    move-object/from16 v1, p0

    .line 344
    .line 345
    move-object/from16 v2, p1

    .line 346
    .line 347
    move-object/from16 v4, p3

    .line 348
    .line 349
    move-wide/from16 v5, p4

    .line 350
    .line 351
    move/from16 v9, p8

    .line 352
    .line 353
    move-object/from16 v10, p9

    .line 354
    .line 355
    move-object/from16 v11, p10

    .line 356
    .line 357
    move/from16 v12, p12

    .line 358
    .line 359
    move/from16 v13, p13

    .line 360
    .line 361
    invoke-direct/range {v0 .. v13}, Lf2/o0;-><init>(Lay0/a;Lx2/s;ZLe3/n0;JJFLi1/l;Lt2/b;II)V

    .line 362
    .line 363
    .line 364
    iput-object v0, v14, Ll2/u1;->d:Lay0/n;

    .line 365
    .line 366
    :cond_1b
    return-void
.end method

.method public static final c(FJLe3/n0;Lx2/s;)Lx2/s;
    .locals 9

    .line 1
    const-wide/16 v6, 0x0

    .line 2
    .line 3
    const/16 v8, 0x18

    .line 4
    .line 5
    const/4 v3, 0x0

    .line 6
    const-wide/16 v4, 0x0

    .line 7
    .line 8
    move v1, p0

    .line 9
    move-object v2, p3

    .line 10
    move-object v0, p4

    .line 11
    invoke-static/range {v0 .. v8}, Ljp/ea;->b(Lx2/s;FLe3/n0;ZJJI)Lx2/s;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    sget-object p3, Lx2/p;->b:Lx2/p;

    .line 16
    .line 17
    invoke-interface {p0, p3}, Lx2/s;->g(Lx2/s;)Lx2/s;

    .line 18
    .line 19
    .line 20
    move-result-object p0

    .line 21
    invoke-static {p0, p1, p2, v2}, Landroidx/compose/foundation/a;->b(Lx2/s;JLe3/n0;)Lx2/s;

    .line 22
    .line 23
    .line 24
    move-result-object p0

    .line 25
    invoke-static {p0, v2}, Ljp/ba;->c(Lx2/s;Le3/n0;)Lx2/s;

    .line 26
    .line 27
    .line 28
    move-result-object p0

    .line 29
    return-object p0
.end method

.method public static final d(JLf2/q;FLl2/t;)J
    .locals 3

    .line 1
    sget-object v0, Lf2/h;->a:Ll2/u2;

    .line 2
    .line 3
    invoke-virtual {p4, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v1

    .line 7
    check-cast v1, Lf2/g;

    .line 8
    .line 9
    invoke-virtual {v1}, Lf2/g;->c()J

    .line 10
    .line 11
    .line 12
    move-result-wide v1

    .line 13
    invoke-static {p0, p1, v1, v2}, Le3/s;->c(JJ)Z

    .line 14
    .line 15
    .line 16
    move-result v1

    .line 17
    const/4 v2, 0x0

    .line 18
    if-eqz v1, :cond_1

    .line 19
    .line 20
    if-eqz p2, :cond_1

    .line 21
    .line 22
    const p2, -0x4307f3b6

    .line 23
    .line 24
    .line 25
    invoke-virtual {p4, p2}, Ll2/t;->Y(I)V

    .line 26
    .line 27
    .line 28
    const p2, -0x648f4fbd

    .line 29
    .line 30
    .line 31
    invoke-virtual {p4, p2}, Ll2/t;->Y(I)V

    .line 32
    .line 33
    .line 34
    invoke-virtual {p4, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 35
    .line 36
    .line 37
    move-result-object p2

    .line 38
    check-cast p2, Lf2/g;

    .line 39
    .line 40
    int-to-float v0, v2

    .line 41
    invoke-static {p3, v0}, Ljava/lang/Float;->compare(FF)I

    .line 42
    .line 43
    .line 44
    move-result v0

    .line 45
    if-lez v0, :cond_0

    .line 46
    .line 47
    invoke-virtual {p2}, Lf2/g;->d()Z

    .line 48
    .line 49
    .line 50
    move-result p2

    .line 51
    if-nez p2, :cond_0

    .line 52
    .line 53
    const p2, -0x414d36ea

    .line 54
    .line 55
    .line 56
    invoke-virtual {p4, p2}, Ll2/t;->Y(I)V

    .line 57
    .line 58
    .line 59
    sget-object p2, Lf2/y;->a:Ll2/u2;

    .line 60
    .line 61
    const/4 p2, 0x1

    .line 62
    int-to-float p2, p2

    .line 63
    add-float/2addr p3, p2

    .line 64
    float-to-double p2, p3

    .line 65
    invoke-static {p2, p3}, Ljava/lang/Math;->log(D)D

    .line 66
    .line 67
    .line 68
    move-result-wide p2

    .line 69
    double-to-float p2, p2

    .line 70
    const/high16 p3, 0x40900000    # 4.5f

    .line 71
    .line 72
    mul-float/2addr p2, p3

    .line 73
    const/high16 p3, 0x40000000    # 2.0f

    .line 74
    .line 75
    add-float/2addr p2, p3

    .line 76
    const/high16 p3, 0x42c80000    # 100.0f

    .line 77
    .line 78
    div-float/2addr p2, p3

    .line 79
    invoke-static {p0, p1, p4}, Lf2/h;->a(JLl2/o;)J

    .line 80
    .line 81
    .line 82
    move-result-wide v0

    .line 83
    invoke-static {v0, v1, p2}, Le3/s;->b(JF)J

    .line 84
    .line 85
    .line 86
    move-result-wide p2

    .line 87
    invoke-static {p2, p3, p0, p1}, Le3/j0;->l(JJ)J

    .line 88
    .line 89
    .line 90
    move-result-wide p0

    .line 91
    invoke-virtual {p4, v2}, Ll2/t;->q(Z)V

    .line 92
    .line 93
    .line 94
    goto :goto_0

    .line 95
    :cond_0
    const p2, -0x414b19de

    .line 96
    .line 97
    .line 98
    invoke-virtual {p4, p2}, Ll2/t;->Y(I)V

    .line 99
    .line 100
    .line 101
    invoke-virtual {p4, v2}, Ll2/t;->q(Z)V

    .line 102
    .line 103
    .line 104
    :goto_0
    invoke-virtual {p4, v2}, Ll2/t;->q(Z)V

    .line 105
    .line 106
    .line 107
    invoke-virtual {p4, v2}, Ll2/t;->q(Z)V

    .line 108
    .line 109
    .line 110
    return-wide p0

    .line 111
    :cond_1
    const p2, -0x4306e9ab

    .line 112
    .line 113
    .line 114
    invoke-virtual {p4, p2}, Ll2/t;->Y(I)V

    .line 115
    .line 116
    .line 117
    invoke-virtual {p4, v2}, Ll2/t;->q(Z)V

    .line 118
    .line 119
    .line 120
    return-wide p0
.end method

.method public static final e(Law0/h;)Le91/b;
    .locals 8

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-static {p0}, Lo5/c;->c(Law0/h;)Lkw0/b;

    .line 7
    .line 8
    .line 9
    move-result-object v0

    .line 10
    invoke-interface {v0}, Lkw0/b;->getAttributes()Lvw0/d;

    .line 11
    .line 12
    .line 13
    move-result-object v1

    .line 14
    invoke-static {v1}, Lkp/g7;->f(Lvw0/d;)Le91/b;

    .line 15
    .line 16
    .line 17
    move-result-object v1

    .line 18
    new-instance v2, Le91/c;

    .line 19
    .line 20
    const-string v3, "ktorHttpResponseURL"

    .line 21
    .line 22
    invoke-direct {v2, v3}, Le91/c;-><init>(Ljava/lang/String;)V

    .line 23
    .line 24
    .line 25
    invoke-interface {v0}, Lkw0/b;->getUrl()Low0/f0;

    .line 26
    .line 27
    .line 28
    move-result-object v0

    .line 29
    invoke-virtual {v1, v2, v0}, Le91/b;->a(Le91/c;Ljava/lang/Object;)V

    .line 30
    .line 31
    .line 32
    new-instance v0, Le91/c;

    .line 33
    .line 34
    const-string v2, "ktorHttpResponseHeaders"

    .line 35
    .line 36
    invoke-direct {v0, v2}, Le91/c;-><init>(Ljava/lang/String;)V

    .line 37
    .line 38
    .line 39
    sget-object v2, Lvz0/d;->d:Lvz0/c;

    .line 40
    .line 41
    invoke-interface {p0}, Low0/r;->a()Low0/m;

    .line 42
    .line 43
    .line 44
    move-result-object v3

    .line 45
    invoke-interface {v3}, Lvw0/j;->a()Ljava/util/Set;

    .line 46
    .line 47
    .line 48
    move-result-object v3

    .line 49
    check-cast v3, Ljava/lang/Iterable;

    .line 50
    .line 51
    const/16 v4, 0xa

    .line 52
    .line 53
    invoke-static {v3, v4}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 54
    .line 55
    .line 56
    move-result v4

    .line 57
    invoke-static {v4}, Lmx0/x;->k(I)I

    .line 58
    .line 59
    .line 60
    move-result v4

    .line 61
    const/16 v5, 0x10

    .line 62
    .line 63
    if-ge v4, v5, :cond_0

    .line 64
    .line 65
    move v4, v5

    .line 66
    :cond_0
    new-instance v5, Ljava/util/LinkedHashMap;

    .line 67
    .line 68
    invoke-direct {v5, v4}, Ljava/util/LinkedHashMap;-><init>(I)V

    .line 69
    .line 70
    .line 71
    invoke-interface {v3}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 72
    .line 73
    .line 74
    move-result-object v3

    .line 75
    :goto_0
    invoke-interface {v3}, Ljava/util/Iterator;->hasNext()Z

    .line 76
    .line 77
    .line 78
    move-result v4

    .line 79
    if-eqz v4, :cond_1

    .line 80
    .line 81
    invoke-interface {v3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 82
    .line 83
    .line 84
    move-result-object v4

    .line 85
    check-cast v4, Ljava/util/Map$Entry;

    .line 86
    .line 87
    invoke-interface {v4}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 88
    .line 89
    .line 90
    move-result-object v6

    .line 91
    invoke-interface {v4}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 92
    .line 93
    .line 94
    move-result-object v4

    .line 95
    invoke-interface {v5, v6, v4}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 96
    .line 97
    .line 98
    goto :goto_0

    .line 99
    :cond_1
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 100
    .line 101
    .line 102
    new-instance v3, Luz0/e0;

    .line 103
    .line 104
    sget-object v4, Luz0/q1;->a:Luz0/q1;

    .line 105
    .line 106
    new-instance v6, Luz0/d;

    .line 107
    .line 108
    const/4 v7, 0x0

    .line 109
    invoke-direct {v6, v4, v7}, Luz0/d;-><init>(Lqz0/a;I)V

    .line 110
    .line 111
    .line 112
    const/4 v7, 0x1

    .line 113
    invoke-direct {v3, v4, v6, v7}, Luz0/e0;-><init>(Lqz0/a;Lqz0/a;I)V

    .line 114
    .line 115
    .line 116
    invoke-virtual {v2, v3, v5}, Lvz0/d;->d(Lqz0/a;Ljava/lang/Object;)Ljava/lang/String;

    .line 117
    .line 118
    .line 119
    move-result-object v2

    .line 120
    invoke-virtual {v1, v0, v2}, Le91/b;->a(Le91/c;Ljava/lang/Object;)V

    .line 121
    .line 122
    .line 123
    new-instance v0, Le91/c;

    .line 124
    .line 125
    const-string v2, "ktorHttpResponseStatusCode"

    .line 126
    .line 127
    invoke-direct {v0, v2}, Le91/c;-><init>(Ljava/lang/String;)V

    .line 128
    .line 129
    .line 130
    invoke-virtual {p0}, Law0/h;->c()Low0/v;

    .line 131
    .line 132
    .line 133
    move-result-object p0

    .line 134
    iget p0, p0, Low0/v;->d:I

    .line 135
    .line 136
    invoke-static {p0}, Ljava/lang/String;->valueOf(I)Ljava/lang/String;

    .line 137
    .line 138
    .line 139
    move-result-object p0

    .line 140
    invoke-virtual {v1, v0, p0}, Le91/b;->a(Le91/c;Ljava/lang/Object;)V

    .line 141
    .line 142
    .line 143
    return-object v1
.end method

.method public static final f(Lvw0/d;)Le91/b;
    .locals 4

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    new-instance v0, Le91/b;

    .line 7
    .line 8
    invoke-direct {v0}, Le91/b;-><init>()V

    .line 9
    .line 10
    .line 11
    new-instance v1, Le91/c;

    .line 12
    .line 13
    const-string v2, "httpRequestUUID"

    .line 14
    .line 15
    invoke-direct {v1, v2}, Le91/c;-><init>(Ljava/lang/String;)V

    .line 16
    .line 17
    .line 18
    sget-object v2, Ls51/a;->a:Lvw0/a;

    .line 19
    .line 20
    monitor-enter p0

    .line 21
    :try_start_0
    sget-object v2, Ls51/a;->b:Lvw0/a;

    .line 22
    .line 23
    invoke-virtual {p0, v2}, Lvw0/d;->d(Lvw0/a;)Ljava/lang/Object;

    .line 24
    .line 25
    .line 26
    move-result-object v3

    .line 27
    check-cast v3, Ljava/lang/String;

    .line 28
    .line 29
    if-nez v3, :cond_0

    .line 30
    .line 31
    invoke-static {}, Ljp/wc;->d()Loy0/b;

    .line 32
    .line 33
    .line 34
    move-result-object v3

    .line 35
    invoke-virtual {v3}, Loy0/b;->toString()Ljava/lang/String;

    .line 36
    .line 37
    .line 38
    move-result-object v3

    .line 39
    invoke-virtual {p0, v2, v3}, Lvw0/d;->e(Lvw0/a;Ljava/lang/Object;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 40
    .line 41
    .line 42
    goto :goto_0

    .line 43
    :catchall_0
    move-exception v0

    .line 44
    goto :goto_1

    .line 45
    :cond_0
    :goto_0
    monitor-exit p0

    .line 46
    invoke-virtual {v0, v1, v3}, Le91/b;->a(Le91/c;Ljava/lang/Object;)V

    .line 47
    .line 48
    .line 49
    monitor-enter p0

    .line 50
    :try_start_1
    sget-object v1, Ls51/a;->a:Lvw0/a;

    .line 51
    .line 52
    invoke-virtual {p0, v1}, Lvw0/d;->d(Lvw0/a;)Ljava/lang/Object;

    .line 53
    .line 54
    .line 55
    move-result-object v1

    .line 56
    check-cast v1, Ljava/lang/String;
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 57
    .line 58
    monitor-exit p0

    .line 59
    if-eqz v1, :cond_1

    .line 60
    .line 61
    new-instance p0, Le91/c;

    .line 62
    .line 63
    const-string v2, "httpUniqueRequestIdentifier"

    .line 64
    .line 65
    invoke-direct {p0, v2}, Le91/c;-><init>(Ljava/lang/String;)V

    .line 66
    .line 67
    .line 68
    invoke-virtual {v0, p0, v1}, Le91/b;->a(Le91/c;Ljava/lang/Object;)V

    .line 69
    .line 70
    .line 71
    :cond_1
    return-object v0

    .line 72
    :catchall_1
    move-exception v0

    .line 73
    monitor-exit p0

    .line 74
    throw v0

    .line 75
    :goto_1
    monitor-exit p0

    .line 76
    throw v0
.end method
