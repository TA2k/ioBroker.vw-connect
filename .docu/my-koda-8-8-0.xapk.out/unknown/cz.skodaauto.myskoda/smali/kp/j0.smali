.class public abstract Lkp/j0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Lx2/s;ZLe71/g;Lh71/x;ZLjava/lang/Float;FLay0/a;Lay0/a;Lay0/a;Ll2/o;I)V
    .locals 18

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v8, p7

    .line 4
    .line 5
    move-object/from16 v9, p8

    .line 6
    .line 7
    move-object/from16 v4, p9

    .line 8
    .line 9
    move/from16 v11, p11

    .line 10
    .line 11
    const-string v1, "modifier"

    .line 12
    .line 13
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    const-string v1, "onTouchDown"

    .line 17
    .line 18
    invoke-static {v8, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    const-string v1, "onTouchUp"

    .line 22
    .line 23
    invoke-static {v9, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 24
    .line 25
    .line 26
    const-string v1, "onTouchCanceled"

    .line 27
    .line 28
    invoke-static {v4, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 29
    .line 30
    .line 31
    move-object/from16 v6, p10

    .line 32
    .line 33
    check-cast v6, Ll2/t;

    .line 34
    .line 35
    const v1, -0x437f3eac

    .line 36
    .line 37
    .line 38
    invoke-virtual {v6, v1}, Ll2/t;->a0(I)Ll2/t;

    .line 39
    .line 40
    .line 41
    and-int/lit8 v1, v11, 0x6

    .line 42
    .line 43
    if-nez v1, :cond_1

    .line 44
    .line 45
    invoke-virtual {v6, v0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 46
    .line 47
    .line 48
    move-result v1

    .line 49
    if-eqz v1, :cond_0

    .line 50
    .line 51
    const/4 v1, 0x4

    .line 52
    goto :goto_0

    .line 53
    :cond_0
    const/4 v1, 0x2

    .line 54
    :goto_0
    or-int/2addr v1, v11

    .line 55
    goto :goto_1

    .line 56
    :cond_1
    move v1, v11

    .line 57
    :goto_1
    and-int/lit8 v2, v11, 0x30

    .line 58
    .line 59
    if-nez v2, :cond_3

    .line 60
    .line 61
    move/from16 v2, p1

    .line 62
    .line 63
    invoke-virtual {v6, v2}, Ll2/t;->h(Z)Z

    .line 64
    .line 65
    .line 66
    move-result v3

    .line 67
    if-eqz v3, :cond_2

    .line 68
    .line 69
    const/16 v3, 0x20

    .line 70
    .line 71
    goto :goto_2

    .line 72
    :cond_2
    const/16 v3, 0x10

    .line 73
    .line 74
    :goto_2
    or-int/2addr v1, v3

    .line 75
    :goto_3
    move-object/from16 v3, p2

    .line 76
    .line 77
    goto :goto_4

    .line 78
    :cond_3
    move/from16 v2, p1

    .line 79
    .line 80
    goto :goto_3

    .line 81
    :goto_4
    invoke-virtual {v6, v3}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 82
    .line 83
    .line 84
    move-result v5

    .line 85
    if-eqz v5, :cond_4

    .line 86
    .line 87
    const/16 v5, 0x100

    .line 88
    .line 89
    goto :goto_5

    .line 90
    :cond_4
    const/16 v5, 0x80

    .line 91
    .line 92
    :goto_5
    or-int/2addr v1, v5

    .line 93
    move-object/from16 v15, p3

    .line 94
    .line 95
    invoke-virtual {v6, v15}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 96
    .line 97
    .line 98
    move-result v5

    .line 99
    if-eqz v5, :cond_5

    .line 100
    .line 101
    const/16 v5, 0x800

    .line 102
    .line 103
    goto :goto_6

    .line 104
    :cond_5
    const/16 v5, 0x400

    .line 105
    .line 106
    :goto_6
    or-int/2addr v1, v5

    .line 107
    and-int/lit16 v5, v11, 0x6000

    .line 108
    .line 109
    if-nez v5, :cond_7

    .line 110
    .line 111
    move/from16 v5, p4

    .line 112
    .line 113
    invoke-virtual {v6, v5}, Ll2/t;->h(Z)Z

    .line 114
    .line 115
    .line 116
    move-result v7

    .line 117
    if-eqz v7, :cond_6

    .line 118
    .line 119
    const/16 v7, 0x4000

    .line 120
    .line 121
    goto :goto_7

    .line 122
    :cond_6
    const/16 v7, 0x2000

    .line 123
    .line 124
    :goto_7
    or-int/2addr v1, v7

    .line 125
    goto :goto_8

    .line 126
    :cond_7
    move/from16 v5, p4

    .line 127
    .line 128
    :goto_8
    const/high16 v7, 0x30000

    .line 129
    .line 130
    and-int v10, v11, v7

    .line 131
    .line 132
    if-nez v10, :cond_9

    .line 133
    .line 134
    move-object/from16 v10, p5

    .line 135
    .line 136
    invoke-virtual {v6, v10}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 137
    .line 138
    .line 139
    move-result v12

    .line 140
    if-eqz v12, :cond_8

    .line 141
    .line 142
    const/high16 v12, 0x20000

    .line 143
    .line 144
    goto :goto_9

    .line 145
    :cond_8
    const/high16 v12, 0x10000

    .line 146
    .line 147
    :goto_9
    or-int/2addr v1, v12

    .line 148
    goto :goto_a

    .line 149
    :cond_9
    move-object/from16 v10, p5

    .line 150
    .line 151
    :goto_a
    invoke-virtual {v6, v8}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 152
    .line 153
    .line 154
    move-result v12

    .line 155
    if-eqz v12, :cond_a

    .line 156
    .line 157
    const/high16 v12, 0x800000

    .line 158
    .line 159
    goto :goto_b

    .line 160
    :cond_a
    const/high16 v12, 0x400000

    .line 161
    .line 162
    :goto_b
    or-int/2addr v1, v12

    .line 163
    invoke-virtual {v6, v9}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 164
    .line 165
    .line 166
    move-result v12

    .line 167
    if-eqz v12, :cond_b

    .line 168
    .line 169
    const/high16 v12, 0x4000000

    .line 170
    .line 171
    goto :goto_c

    .line 172
    :cond_b
    const/high16 v12, 0x2000000

    .line 173
    .line 174
    :goto_c
    or-int/2addr v1, v12

    .line 175
    invoke-virtual {v6, v4}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 176
    .line 177
    .line 178
    move-result v12

    .line 179
    if-eqz v12, :cond_c

    .line 180
    .line 181
    const/high16 v12, 0x20000000

    .line 182
    .line 183
    goto :goto_d

    .line 184
    :cond_c
    const/high16 v12, 0x10000000

    .line 185
    .line 186
    :goto_d
    or-int/2addr v1, v12

    .line 187
    const v12, 0x12492493

    .line 188
    .line 189
    .line 190
    and-int/2addr v12, v1

    .line 191
    const v13, 0x12492492

    .line 192
    .line 193
    .line 194
    if-eq v12, v13, :cond_d

    .line 195
    .line 196
    const/4 v12, 0x1

    .line 197
    goto :goto_e

    .line 198
    :cond_d
    const/4 v12, 0x0

    .line 199
    :goto_e
    and-int/lit8 v13, v1, 0x1

    .line 200
    .line 201
    invoke-virtual {v6, v13, v12}, Ll2/t;->O(IZ)Z

    .line 202
    .line 203
    .line 204
    move-result v12

    .line 205
    if-eqz v12, :cond_e

    .line 206
    .line 207
    new-instance v12, Le71/m;

    .line 208
    .line 209
    move/from16 v13, p6

    .line 210
    .line 211
    move-object/from16 v17, v3

    .line 212
    .line 213
    move v14, v5

    .line 214
    move-object/from16 v16, v10

    .line 215
    .line 216
    invoke-direct/range {v12 .. v17}, Le71/m;-><init>(FZLh71/x;Ljava/lang/Float;Le71/g;)V

    .line 217
    .line 218
    .line 219
    const v3, 0x5b117ad

    .line 220
    .line 221
    .line 222
    invoke-static {v3, v6, v12}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 223
    .line 224
    .line 225
    move-result-object v5

    .line 226
    and-int/lit8 v3, v1, 0xe

    .line 227
    .line 228
    or-int/2addr v3, v7

    .line 229
    and-int/lit8 v7, v1, 0x70

    .line 230
    .line 231
    or-int/2addr v3, v7

    .line 232
    shr-int/lit8 v1, v1, 0xf

    .line 233
    .line 234
    and-int/lit16 v7, v1, 0x380

    .line 235
    .line 236
    or-int/2addr v3, v7

    .line 237
    and-int/lit16 v7, v1, 0x1c00

    .line 238
    .line 239
    or-int/2addr v3, v7

    .line 240
    const v7, 0xe000

    .line 241
    .line 242
    .line 243
    and-int/2addr v1, v7

    .line 244
    or-int v7, v3, v1

    .line 245
    .line 246
    move v1, v2

    .line 247
    move-object v2, v8

    .line 248
    move-object v3, v9

    .line 249
    invoke-static/range {v0 .. v7}, Lkp/g0;->a(Lx2/s;ZLay0/a;Lay0/a;Lay0/a;Lt2/b;Ll2/o;I)V

    .line 250
    .line 251
    .line 252
    goto :goto_f

    .line 253
    :cond_e
    invoke-virtual {v6}, Ll2/t;->R()V

    .line 254
    .line 255
    .line 256
    :goto_f
    invoke-virtual {v6}, Ll2/t;->s()Ll2/u1;

    .line 257
    .line 258
    .line 259
    move-result-object v12

    .line 260
    if-eqz v12, :cond_f

    .line 261
    .line 262
    new-instance v0, Le71/n;

    .line 263
    .line 264
    move-object/from16 v1, p0

    .line 265
    .line 266
    move/from16 v2, p1

    .line 267
    .line 268
    move-object/from16 v3, p2

    .line 269
    .line 270
    move-object/from16 v4, p3

    .line 271
    .line 272
    move/from16 v5, p4

    .line 273
    .line 274
    move-object/from16 v6, p5

    .line 275
    .line 276
    move/from16 v7, p6

    .line 277
    .line 278
    move-object/from16 v8, p7

    .line 279
    .line 280
    move-object/from16 v9, p8

    .line 281
    .line 282
    move-object/from16 v10, p9

    .line 283
    .line 284
    invoke-direct/range {v0 .. v11}, Le71/n;-><init>(Lx2/s;ZLe71/g;Lh71/x;ZLjava/lang/Float;FLay0/a;Lay0/a;Lay0/a;I)V

    .line 285
    .line 286
    .line 287
    iput-object v0, v12, Ll2/u1;->d:Lay0/n;

    .line 288
    .line 289
    :cond_f
    return-void
.end method

.method public static final b(Lcariad/charging/multicharge/retrofit/coroutineAdapter/NetworkResponse;)Ljava/lang/Object;
    .locals 2

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-static {p0}, Lrc/c;->a(Lcariad/charging/multicharge/retrofit/coroutineAdapter/NetworkResponse;)Ljava/lang/Object;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    invoke-static {p0}, Llx0/o;->a(Ljava/lang/Object;)Ljava/lang/Throwable;

    .line 11
    .line 12
    .line 13
    move-result-object v0

    .line 14
    if-nez v0, :cond_0

    .line 15
    .line 16
    return-object p0

    .line 17
    :cond_0
    instance-of p0, v0, Lrc/a;

    .line 18
    .line 19
    if-eqz p0, :cond_1

    .line 20
    .line 21
    move-object p0, v0

    .line 22
    check-cast p0, Lrc/a;

    .line 23
    .line 24
    goto :goto_0

    .line 25
    :cond_1
    const/4 p0, 0x0

    .line 26
    :goto_0
    if-eqz p0, :cond_3

    .line 27
    .line 28
    iget-object p0, p0, Lrc/a;->e:Ltb/c;

    .line 29
    .line 30
    if-eqz p0, :cond_3

    .line 31
    .line 32
    new-instance v1, Lri/e;

    .line 33
    .line 34
    iget-object p0, p0, Ltb/c;->a:Ljava/lang/String;

    .line 35
    .line 36
    if-nez p0, :cond_2

    .line 37
    .line 38
    move-object p0, v0

    .line 39
    check-cast p0, Lrc/a;

    .line 40
    .line 41
    iget-object p0, p0, Lrc/a;->g:Ljava/lang/String;

    .line 42
    .line 43
    if-nez p0, :cond_2

    .line 44
    .line 45
    const-string p0, "-missing-message-"

    .line 46
    .line 47
    :cond_2
    check-cast v0, Lrc/a;

    .line 48
    .line 49
    invoke-direct {v1, p0}, Lri/e;-><init>(Ljava/lang/String;)V

    .line 50
    .line 51
    .line 52
    move-object v0, v1

    .line 53
    :cond_3
    invoke-static {v0}, Lps/t1;->a(Ljava/lang/Throwable;)Llx0/n;

    .line 54
    .line 55
    .line 56
    move-result-object p0

    .line 57
    return-object p0
.end method
