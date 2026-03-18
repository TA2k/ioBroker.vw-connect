.class public final Lh2/f3;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/o;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/lang/String;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/String;I)V
    .locals 0

    .line 1
    iput p2, p0, Lh2/f3;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lh2/f3;->e:Ljava/lang/String;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 27

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Lh2/f3;->d:I

    .line 4
    .line 5
    packed-switch v1, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    move-object/from16 v1, p1

    .line 9
    .line 10
    check-cast v1, Lk1/h1;

    .line 11
    .line 12
    move-object/from16 v1, p2

    .line 13
    .line 14
    check-cast v1, Ll2/o;

    .line 15
    .line 16
    move-object/from16 v2, p3

    .line 17
    .line 18
    check-cast v2, Ljava/lang/Number;

    .line 19
    .line 20
    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    .line 21
    .line 22
    .line 23
    move-result v2

    .line 24
    and-int/lit8 v3, v2, 0x11

    .line 25
    .line 26
    const/16 v4, 0x10

    .line 27
    .line 28
    const/4 v5, 0x1

    .line 29
    if-eq v3, v4, :cond_0

    .line 30
    .line 31
    move v3, v5

    .line 32
    goto :goto_0

    .line 33
    :cond_0
    const/4 v3, 0x0

    .line 34
    :goto_0
    and-int/2addr v2, v5

    .line 35
    check-cast v1, Ll2/t;

    .line 36
    .line 37
    invoke-virtual {v1, v2, v3}, Ll2/t;->O(IZ)Z

    .line 38
    .line 39
    .line 40
    move-result v2

    .line 41
    if-eqz v2, :cond_1

    .line 42
    .line 43
    const/16 v25, 0x0

    .line 44
    .line 45
    const v26, 0x3fffe

    .line 46
    .line 47
    .line 48
    iget-object v4, v0, Lh2/f3;->e:Ljava/lang/String;

    .line 49
    .line 50
    const/4 v5, 0x0

    .line 51
    const-wide/16 v6, 0x0

    .line 52
    .line 53
    const-wide/16 v8, 0x0

    .line 54
    .line 55
    const/4 v10, 0x0

    .line 56
    const-wide/16 v11, 0x0

    .line 57
    .line 58
    const/4 v13, 0x0

    .line 59
    const/4 v14, 0x0

    .line 60
    const-wide/16 v15, 0x0

    .line 61
    .line 62
    const/16 v17, 0x0

    .line 63
    .line 64
    const/16 v18, 0x0

    .line 65
    .line 66
    const/16 v19, 0x0

    .line 67
    .line 68
    const/16 v20, 0x0

    .line 69
    .line 70
    const/16 v21, 0x0

    .line 71
    .line 72
    const/16 v22, 0x0

    .line 73
    .line 74
    const/16 v24, 0x0

    .line 75
    .line 76
    move-object/from16 v23, v1

    .line 77
    .line 78
    invoke-static/range {v4 .. v26}, Lh2/rb;->b(Ljava/lang/String;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZIILay0/k;Lg4/p0;Ll2/o;III)V

    .line 79
    .line 80
    .line 81
    goto :goto_1

    .line 82
    :cond_1
    move-object/from16 v23, v1

    .line 83
    .line 84
    invoke-virtual/range {v23 .. v23}, Ll2/t;->R()V

    .line 85
    .line 86
    .line 87
    :goto_1
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 88
    .line 89
    return-object v0

    .line 90
    :pswitch_0
    move-object/from16 v1, p1

    .line 91
    .line 92
    check-cast v1, Lh2/xb;

    .line 93
    .line 94
    move-object/from16 v2, p2

    .line 95
    .line 96
    check-cast v2, Ll2/o;

    .line 97
    .line 98
    move-object/from16 v3, p3

    .line 99
    .line 100
    check-cast v3, Ljava/lang/Number;

    .line 101
    .line 102
    invoke-virtual {v3}, Ljava/lang/Number;->intValue()I

    .line 103
    .line 104
    .line 105
    move-result v3

    .line 106
    and-int/lit8 v4, v3, 0x6

    .line 107
    .line 108
    if-nez v4, :cond_4

    .line 109
    .line 110
    and-int/lit8 v4, v3, 0x8

    .line 111
    .line 112
    if-nez v4, :cond_2

    .line 113
    .line 114
    move-object v4, v2

    .line 115
    check-cast v4, Ll2/t;

    .line 116
    .line 117
    invoke-virtual {v4, v1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 118
    .line 119
    .line 120
    move-result v4

    .line 121
    goto :goto_2

    .line 122
    :cond_2
    move-object v4, v2

    .line 123
    check-cast v4, Ll2/t;

    .line 124
    .line 125
    invoke-virtual {v4, v1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 126
    .line 127
    .line 128
    move-result v4

    .line 129
    :goto_2
    if-eqz v4, :cond_3

    .line 130
    .line 131
    const/4 v4, 0x4

    .line 132
    goto :goto_3

    .line 133
    :cond_3
    const/4 v4, 0x2

    .line 134
    :goto_3
    or-int/2addr v3, v4

    .line 135
    :cond_4
    and-int/lit8 v4, v3, 0x13

    .line 136
    .line 137
    const/16 v5, 0x12

    .line 138
    .line 139
    if-eq v4, v5, :cond_5

    .line 140
    .line 141
    const/4 v4, 0x1

    .line 142
    goto :goto_4

    .line 143
    :cond_5
    const/4 v4, 0x0

    .line 144
    :goto_4
    and-int/lit8 v5, v3, 0x1

    .line 145
    .line 146
    move-object v12, v2

    .line 147
    check-cast v12, Ll2/t;

    .line 148
    .line 149
    invoke-virtual {v12, v5, v4}, Ll2/t;->O(IZ)Z

    .line 150
    .line 151
    .line 152
    move-result v2

    .line 153
    if-eqz v2, :cond_6

    .line 154
    .line 155
    new-instance v2, Lh2/u1;

    .line 156
    .line 157
    iget-object v0, v0, Lh2/f3;->e:Ljava/lang/String;

    .line 158
    .line 159
    const/4 v4, 0x4

    .line 160
    invoke-direct {v2, v0, v4}, Lh2/u1;-><init>(Ljava/lang/String;I)V

    .line 161
    .line 162
    .line 163
    const v0, -0x3b99a1f7

    .line 164
    .line 165
    .line 166
    invoke-static {v0, v12, v2}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 167
    .line 168
    .line 169
    move-result-object v11

    .line 170
    and-int/lit8 v0, v3, 0xe

    .line 171
    .line 172
    const/high16 v2, 0x30000000

    .line 173
    .line 174
    or-int v13, v0, v2

    .line 175
    .line 176
    const/4 v2, 0x0

    .line 177
    const/4 v3, 0x0

    .line 178
    const/4 v4, 0x0

    .line 179
    const-wide/16 v5, 0x0

    .line 180
    .line 181
    const-wide/16 v7, 0x0

    .line 182
    .line 183
    const/4 v9, 0x0

    .line 184
    const/4 v10, 0x0

    .line 185
    invoke-static/range {v1 .. v13}, Lh2/vb;->a(Lh2/xb;Lx2/s;FLe3/n0;JJFFLt2/b;Ll2/o;I)V

    .line 186
    .line 187
    .line 188
    goto :goto_5

    .line 189
    :cond_6
    invoke-virtual {v12}, Ll2/t;->R()V

    .line 190
    .line 191
    .line 192
    :goto_5
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 193
    .line 194
    return-object v0

    .line 195
    :pswitch_1
    move-object/from16 v1, p1

    .line 196
    .line 197
    check-cast v1, Lh2/xb;

    .line 198
    .line 199
    move-object/from16 v2, p2

    .line 200
    .line 201
    check-cast v2, Ll2/o;

    .line 202
    .line 203
    move-object/from16 v3, p3

    .line 204
    .line 205
    check-cast v3, Ljava/lang/Number;

    .line 206
    .line 207
    invoke-virtual {v3}, Ljava/lang/Number;->intValue()I

    .line 208
    .line 209
    .line 210
    move-result v3

    .line 211
    and-int/lit8 v4, v3, 0x6

    .line 212
    .line 213
    if-nez v4, :cond_9

    .line 214
    .line 215
    and-int/lit8 v4, v3, 0x8

    .line 216
    .line 217
    if-nez v4, :cond_7

    .line 218
    .line 219
    move-object v4, v2

    .line 220
    check-cast v4, Ll2/t;

    .line 221
    .line 222
    invoke-virtual {v4, v1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 223
    .line 224
    .line 225
    move-result v4

    .line 226
    goto :goto_6

    .line 227
    :cond_7
    move-object v4, v2

    .line 228
    check-cast v4, Ll2/t;

    .line 229
    .line 230
    invoke-virtual {v4, v1}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 231
    .line 232
    .line 233
    move-result v4

    .line 234
    :goto_6
    if-eqz v4, :cond_8

    .line 235
    .line 236
    const/4 v4, 0x4

    .line 237
    goto :goto_7

    .line 238
    :cond_8
    const/4 v4, 0x2

    .line 239
    :goto_7
    or-int/2addr v3, v4

    .line 240
    :cond_9
    and-int/lit8 v4, v3, 0x13

    .line 241
    .line 242
    const/16 v5, 0x12

    .line 243
    .line 244
    if-eq v4, v5, :cond_a

    .line 245
    .line 246
    const/4 v4, 0x1

    .line 247
    goto :goto_8

    .line 248
    :cond_a
    const/4 v4, 0x0

    .line 249
    :goto_8
    and-int/lit8 v5, v3, 0x1

    .line 250
    .line 251
    move-object v12, v2

    .line 252
    check-cast v12, Ll2/t;

    .line 253
    .line 254
    invoke-virtual {v12, v5, v4}, Ll2/t;->O(IZ)Z

    .line 255
    .line 256
    .line 257
    move-result v2

    .line 258
    if-eqz v2, :cond_b

    .line 259
    .line 260
    new-instance v2, Lh2/u1;

    .line 261
    .line 262
    iget-object v0, v0, Lh2/f3;->e:Ljava/lang/String;

    .line 263
    .line 264
    const/4 v4, 0x1

    .line 265
    invoke-direct {v2, v0, v4}, Lh2/u1;-><init>(Ljava/lang/String;I)V

    .line 266
    .line 267
    .line 268
    const v0, 0x719a85bc

    .line 269
    .line 270
    .line 271
    invoke-static {v0, v12, v2}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 272
    .line 273
    .line 274
    move-result-object v11

    .line 275
    and-int/lit8 v0, v3, 0xe

    .line 276
    .line 277
    const/high16 v2, 0x30000000

    .line 278
    .line 279
    or-int v13, v0, v2

    .line 280
    .line 281
    const/4 v2, 0x0

    .line 282
    const/4 v3, 0x0

    .line 283
    const/4 v4, 0x0

    .line 284
    const-wide/16 v5, 0x0

    .line 285
    .line 286
    const-wide/16 v7, 0x0

    .line 287
    .line 288
    const/4 v9, 0x0

    .line 289
    const/4 v10, 0x0

    .line 290
    invoke-static/range {v1 .. v13}, Lh2/vb;->a(Lh2/xb;Lx2/s;FLe3/n0;JJFFLt2/b;Ll2/o;I)V

    .line 291
    .line 292
    .line 293
    goto :goto_9

    .line 294
    :cond_b
    invoke-virtual {v12}, Ll2/t;->R()V

    .line 295
    .line 296
    .line 297
    :goto_9
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 298
    .line 299
    return-object v0

    .line 300
    nop

    .line 301
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
