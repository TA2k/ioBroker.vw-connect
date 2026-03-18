.class public abstract Ljp/m1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static a:Ljava/lang/Boolean;


# direct methods
.method public static final a(Law/w;Landroid/widget/FrameLayout$LayoutParams;ZLaw/v;Lay0/k;Lay0/k;Law/b;Law/a;Lay0/k;Ll2/o;I)V
    .locals 17

    .line 1
    move-object/from16 v1, p0

    .line 2
    .line 3
    move-object/from16 v7, p3

    .line 4
    .line 5
    move-object/from16 v8, p5

    .line 6
    .line 7
    move-object/from16 v6, p6

    .line 8
    .line 9
    move-object/from16 v14, p9

    .line 10
    .line 11
    check-cast v14, Ll2/t;

    .line 12
    .line 13
    const v0, -0x5e130a5

    .line 14
    .line 15
    .line 16
    invoke-virtual {v14, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 17
    .line 18
    .line 19
    iget-object v0, v1, Law/w;->h:Ll2/j1;

    .line 20
    .line 21
    invoke-virtual {v0}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 22
    .line 23
    .line 24
    move-result-object v0

    .line 25
    check-cast v0, Landroid/webkit/WebView;

    .line 26
    .line 27
    const/4 v9, 0x0

    .line 28
    if-eqz p2, :cond_0

    .line 29
    .line 30
    iget-object v2, v7, Law/v;->b:Ll2/j1;

    .line 31
    .line 32
    invoke-virtual {v2}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 33
    .line 34
    .line 35
    move-result-object v2

    .line 36
    check-cast v2, Ljava/lang/Boolean;

    .line 37
    .line 38
    invoke-virtual {v2}, Ljava/lang/Boolean;->booleanValue()Z

    .line 39
    .line 40
    .line 41
    move-result v2

    .line 42
    if-eqz v2, :cond_0

    .line 43
    .line 44
    const/4 v2, 0x1

    .line 45
    goto :goto_0

    .line 46
    :cond_0
    move v2, v9

    .line 47
    :goto_0
    new-instance v3, Law/k;

    .line 48
    .line 49
    const/4 v4, 0x0

    .line 50
    invoke-direct {v3, v0, v4}, Law/k;-><init>(Landroid/webkit/WebView;I)V

    .line 51
    .line 52
    .line 53
    invoke-static {v2, v3, v14, v9, v9}, Ljp/tb;->a(ZLay0/a;Ll2/o;II)V

    .line 54
    .line 55
    .line 56
    const v2, -0x6c032e5

    .line 57
    .line 58
    .line 59
    invoke-virtual {v14, v2}, Ll2/t;->Z(I)V

    .line 60
    .line 61
    .line 62
    if-nez v0, :cond_1

    .line 63
    .line 64
    goto :goto_1

    .line 65
    :cond_1
    new-instance v2, Law/l;

    .line 66
    .line 67
    const/4 v3, 0x0

    .line 68
    const/4 v4, 0x0

    .line 69
    invoke-direct {v2, v7, v0, v4, v3}, Law/l;-><init>(Law/v;Landroid/webkit/WebView;Lkotlin/coroutines/Continuation;I)V

    .line 70
    .line 71
    .line 72
    invoke-static {v0, v7, v2, v14}, Ll2/l0;->e(Ljava/lang/Object;Ljava/lang/Object;Lay0/n;Ll2/o;)V

    .line 73
    .line 74
    .line 75
    new-instance v2, La50/c;

    .line 76
    .line 77
    const/4 v3, 0x6

    .line 78
    invoke-direct {v2, v3, v1, v0, v4}, La50/c;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 79
    .line 80
    .line 81
    invoke-static {v0, v1, v2, v14}, Ll2/l0;->e(Ljava/lang/Object;Ljava/lang/Object;Lay0/n;Ll2/o;)V

    .line 82
    .line 83
    .line 84
    :goto_1
    invoke-virtual {v14, v9}, Ll2/t;->q(Z)V

    .line 85
    .line 86
    .line 87
    invoke-virtual {v6}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 88
    .line 89
    .line 90
    iput-object v1, v6, Law/b;->a:Law/w;

    .line 91
    .line 92
    const-string v0, "<set-?>"

    .line 93
    .line 94
    invoke-static {v7, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 95
    .line 96
    .line 97
    iput-object v7, v6, Law/b;->b:Law/v;

    .line 98
    .line 99
    invoke-virtual/range {p7 .. p7}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 100
    .line 101
    .line 102
    move-object/from16 v5, p7

    .line 103
    .line 104
    iput-object v1, v5, Law/a;->a:Law/w;

    .line 105
    .line 106
    new-instance v0, Law/n;

    .line 107
    .line 108
    move-object/from16 v3, p1

    .line 109
    .line 110
    move-object/from16 v2, p4

    .line 111
    .line 112
    move-object v4, v1

    .line 113
    move-object/from16 v1, p8

    .line 114
    .line 115
    invoke-direct/range {v0 .. v6}, Law/n;-><init>(Lay0/k;Lay0/k;Landroid/widget/FrameLayout$LayoutParams;Law/w;Law/a;Law/b;)V

    .line 116
    .line 117
    .line 118
    const v1, 0x44faf204

    .line 119
    .line 120
    .line 121
    invoke-virtual {v14, v1}, Ll2/t;->Z(I)V

    .line 122
    .line 123
    .line 124
    invoke-virtual {v14, v8}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 125
    .line 126
    .line 127
    move-result v1

    .line 128
    invoke-virtual {v14}, Ll2/t;->L()Ljava/lang/Object;

    .line 129
    .line 130
    .line 131
    move-result-object v2

    .line 132
    if-nez v1, :cond_2

    .line 133
    .line 134
    sget-object v1, Ll2/n;->a:Ll2/x0;

    .line 135
    .line 136
    if-ne v2, v1, :cond_3

    .line 137
    .line 138
    :cond_2
    new-instance v2, Law/o;

    .line 139
    .line 140
    const/4 v1, 0x0

    .line 141
    invoke-direct {v2, v1, v8}, Law/o;-><init>(ILay0/k;)V

    .line 142
    .line 143
    .line 144
    invoke-virtual {v14, v2}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 145
    .line 146
    .line 147
    :cond_3
    invoke-virtual {v14, v9}, Ll2/t;->q(Z)V

    .line 148
    .line 149
    .line 150
    move-object v12, v2

    .line 151
    check-cast v12, Lay0/k;

    .line 152
    .line 153
    shr-int/lit8 v1, p10, 0x3

    .line 154
    .line 155
    and-int/lit8 v15, v1, 0x70

    .line 156
    .line 157
    const/16 v16, 0x14

    .line 158
    .line 159
    sget-object v10, Lx2/p;->b:Lx2/p;

    .line 160
    .line 161
    const/4 v11, 0x0

    .line 162
    const/4 v13, 0x0

    .line 163
    move-object v9, v0

    .line 164
    invoke-static/range {v9 .. v16}, Landroidx/compose/ui/viewinterop/a;->b(Lay0/k;Lx2/s;Lay0/k;Lay0/k;Lay0/k;Ll2/o;II)V

    .line 165
    .line 166
    .line 167
    invoke-virtual {v14}, Ll2/t;->s()Ll2/u1;

    .line 168
    .line 169
    .line 170
    move-result-object v11

    .line 171
    if-nez v11, :cond_4

    .line 172
    .line 173
    return-void

    .line 174
    :cond_4
    new-instance v0, Law/p;

    .line 175
    .line 176
    move-object/from16 v1, p0

    .line 177
    .line 178
    move-object/from16 v2, p1

    .line 179
    .line 180
    move/from16 v3, p2

    .line 181
    .line 182
    move-object/from16 v5, p4

    .line 183
    .line 184
    move-object/from16 v9, p8

    .line 185
    .line 186
    move/from16 v10, p10

    .line 187
    .line 188
    move-object v4, v7

    .line 189
    move-object v6, v8

    .line 190
    move-object/from16 v7, p6

    .line 191
    .line 192
    move-object/from16 v8, p7

    .line 193
    .line 194
    invoke-direct/range {v0 .. v10}, Law/p;-><init>(Law/w;Landroid/widget/FrameLayout$LayoutParams;ZLaw/v;Lay0/k;Lay0/k;Law/b;Law/a;Lay0/k;I)V

    .line 195
    .line 196
    .line 197
    iput-object v0, v11, Ll2/u1;->d:Lay0/n;

    .line 198
    .line 199
    return-void
.end method

.method public static final b(Law/w;Lx2/s;ZLaw/v;Lay0/k;Lay0/k;Law/b;Law/a;Lay0/k;Ll2/o;I)V
    .locals 16

    .line 1
    move-object/from16 v4, p9

    .line 2
    .line 3
    check-cast v4, Ll2/t;

    .line 4
    .line 5
    const v0, 0x47ffea6d

    .line 6
    .line 7
    .line 8
    invoke-virtual {v4, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 9
    .line 10
    .line 11
    move-object/from16 v6, p0

    .line 12
    .line 13
    invoke-virtual {v4, v6}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 14
    .line 15
    .line 16
    move-result v0

    .line 17
    if-eqz v0, :cond_0

    .line 18
    .line 19
    const/4 v0, 0x4

    .line 20
    goto :goto_0

    .line 21
    :cond_0
    const/4 v0, 0x2

    .line 22
    :goto_0
    or-int v0, p10, v0

    .line 23
    .line 24
    const v1, 0x4b0580

    .line 25
    .line 26
    .line 27
    or-int/2addr v0, v1

    .line 28
    move-object/from16 v13, p8

    .line 29
    .line 30
    invoke-virtual {v4, v13}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 31
    .line 32
    .line 33
    move-result v1

    .line 34
    if-eqz v1, :cond_1

    .line 35
    .line 36
    const/high16 v1, 0x4000000

    .line 37
    .line 38
    goto :goto_1

    .line 39
    :cond_1
    const/high16 v1, 0x2000000

    .line 40
    .line 41
    :goto_1
    or-int/2addr v0, v1

    .line 42
    const v1, 0xb6db6db

    .line 43
    .line 44
    .line 45
    and-int/2addr v1, v0

    .line 46
    const v2, 0x2492492

    .line 47
    .line 48
    .line 49
    if-ne v1, v2, :cond_3

    .line 50
    .line 51
    invoke-virtual {v4}, Ll2/t;->A()Z

    .line 52
    .line 53
    .line 54
    move-result v1

    .line 55
    if-nez v1, :cond_2

    .line 56
    .line 57
    goto :goto_2

    .line 58
    :cond_2
    invoke-virtual {v4}, Ll2/t;->R()V

    .line 59
    .line 60
    .line 61
    move/from16 v8, p2

    .line 62
    .line 63
    move-object/from16 v9, p3

    .line 64
    .line 65
    move-object/from16 v11, p5

    .line 66
    .line 67
    move-object/from16 v12, p6

    .line 68
    .line 69
    move-object/from16 v13, p7

    .line 70
    .line 71
    goto/16 :goto_6

    .line 72
    .line 73
    :cond_3
    :goto_2
    invoke-virtual {v4}, Ll2/t;->T()V

    .line 74
    .line 75
    .line 76
    and-int/lit8 v1, p10, 0x1

    .line 77
    .line 78
    const v2, -0x1f81c01

    .line 79
    .line 80
    .line 81
    if-eqz v1, :cond_5

    .line 82
    .line 83
    invoke-virtual {v4}, Ll2/t;->y()Z

    .line 84
    .line 85
    .line 86
    move-result v1

    .line 87
    if-eqz v1, :cond_4

    .line 88
    .line 89
    goto :goto_4

    .line 90
    :cond_4
    invoke-virtual {v4}, Ll2/t;->R()V

    .line 91
    .line 92
    .line 93
    and-int/2addr v0, v2

    .line 94
    move/from16 v7, p2

    .line 95
    .line 96
    move-object/from16 v8, p3

    .line 97
    .line 98
    move-object/from16 v10, p5

    .line 99
    .line 100
    move-object/from16 v11, p6

    .line 101
    .line 102
    move-object/from16 v12, p7

    .line 103
    .line 104
    :goto_3
    move v14, v0

    .line 105
    goto/16 :goto_5

    .line 106
    .line 107
    :cond_5
    :goto_4
    const v1, -0xbbfe6e1

    .line 108
    .line 109
    .line 110
    invoke-virtual {v4, v1}, Ll2/t;->Z(I)V

    .line 111
    .line 112
    .line 113
    const v1, 0x2e20b340

    .line 114
    .line 115
    .line 116
    invoke-virtual {v4, v1}, Ll2/t;->Z(I)V

    .line 117
    .line 118
    .line 119
    const v1, -0x1d58f75c

    .line 120
    .line 121
    .line 122
    invoke-virtual {v4, v1}, Ll2/t;->Z(I)V

    .line 123
    .line 124
    .line 125
    invoke-virtual {v4}, Ll2/t;->L()Ljava/lang/Object;

    .line 126
    .line 127
    .line 128
    move-result-object v1

    .line 129
    sget-object v3, Ll2/n;->a:Ll2/x0;

    .line 130
    .line 131
    if-ne v1, v3, :cond_6

    .line 132
    .line 133
    invoke-static {v4}, Ll2/l0;->h(Ll2/o;)Lvy0/b0;

    .line 134
    .line 135
    .line 136
    move-result-object v1

    .line 137
    new-instance v5, Ll2/d0;

    .line 138
    .line 139
    invoke-direct {v5, v1}, Ll2/d0;-><init>(Lvy0/b0;)V

    .line 140
    .line 141
    .line 142
    invoke-virtual {v4, v5}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 143
    .line 144
    .line 145
    move-object v1, v5

    .line 146
    :cond_6
    const/4 v5, 0x0

    .line 147
    invoke-virtual {v4, v5}, Ll2/t;->q(Z)V

    .line 148
    .line 149
    .line 150
    check-cast v1, Ll2/d0;

    .line 151
    .line 152
    iget-object v1, v1, Ll2/d0;->d:Lvy0/b0;

    .line 153
    .line 154
    invoke-virtual {v4, v5}, Ll2/t;->q(Z)V

    .line 155
    .line 156
    .line 157
    const v7, 0x44faf204

    .line 158
    .line 159
    .line 160
    invoke-virtual {v4, v7}, Ll2/t;->Z(I)V

    .line 161
    .line 162
    .line 163
    invoke-virtual {v4, v1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 164
    .line 165
    .line 166
    move-result v7

    .line 167
    invoke-virtual {v4}, Ll2/t;->L()Ljava/lang/Object;

    .line 168
    .line 169
    .line 170
    move-result-object v8

    .line 171
    if-nez v7, :cond_7

    .line 172
    .line 173
    if-ne v8, v3, :cond_8

    .line 174
    .line 175
    :cond_7
    new-instance v8, Law/v;

    .line 176
    .line 177
    invoke-direct {v8, v1}, Law/v;-><init>(Lvy0/b0;)V

    .line 178
    .line 179
    .line 180
    invoke-virtual {v4, v8}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 181
    .line 182
    .line 183
    :cond_8
    invoke-virtual {v4, v5}, Ll2/t;->q(Z)V

    .line 184
    .line 185
    .line 186
    move-object v1, v8

    .line 187
    check-cast v1, Law/v;

    .line 188
    .line 189
    invoke-virtual {v4, v5}, Ll2/t;->q(Z)V

    .line 190
    .line 191
    .line 192
    const v3, -0x1d58f75c

    .line 193
    .line 194
    .line 195
    invoke-virtual {v4, v3}, Ll2/t;->Z(I)V

    .line 196
    .line 197
    .line 198
    invoke-virtual {v4}, Ll2/t;->L()Ljava/lang/Object;

    .line 199
    .line 200
    .line 201
    move-result-object v5

    .line 202
    sget-object v7, Ll2/n;->a:Ll2/x0;

    .line 203
    .line 204
    if-ne v5, v7, :cond_9

    .line 205
    .line 206
    new-instance v5, Law/b;

    .line 207
    .line 208
    invoke-direct {v5}, Landroid/webkit/WebViewClient;-><init>()V

    .line 209
    .line 210
    .line 211
    invoke-virtual {v4, v5}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 212
    .line 213
    .line 214
    :cond_9
    const/4 v8, 0x0

    .line 215
    invoke-virtual {v4, v8}, Ll2/t;->q(Z)V

    .line 216
    .line 217
    .line 218
    check-cast v5, Law/b;

    .line 219
    .line 220
    invoke-virtual {v4, v3}, Ll2/t;->Z(I)V

    .line 221
    .line 222
    .line 223
    invoke-virtual {v4}, Ll2/t;->L()Ljava/lang/Object;

    .line 224
    .line 225
    .line 226
    move-result-object v3

    .line 227
    if-ne v3, v7, :cond_a

    .line 228
    .line 229
    new-instance v3, Law/a;

    .line 230
    .line 231
    invoke-direct {v3}, Landroid/webkit/WebChromeClient;-><init>()V

    .line 232
    .line 233
    .line 234
    invoke-virtual {v4, v3}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 235
    .line 236
    .line 237
    :cond_a
    invoke-virtual {v4, v8}, Ll2/t;->q(Z)V

    .line 238
    .line 239
    .line 240
    check-cast v3, Law/a;

    .line 241
    .line 242
    and-int/2addr v0, v2

    .line 243
    const/4 v2, 0x1

    .line 244
    sget-object v7, Law/q;->g:Law/q;

    .line 245
    .line 246
    move-object v8, v1

    .line 247
    move-object v12, v3

    .line 248
    move-object v11, v5

    .line 249
    move-object v10, v7

    .line 250
    move v7, v2

    .line 251
    goto/16 :goto_3

    .line 252
    .line 253
    :goto_5
    invoke-virtual {v4}, Ll2/t;->r()V

    .line 254
    .line 255
    .line 256
    new-instance v5, Law/r;

    .line 257
    .line 258
    move-object/from16 v9, p4

    .line 259
    .line 260
    invoke-direct/range {v5 .. v14}, Law/r;-><init>(Law/w;ZLaw/v;Lay0/k;Lay0/k;Law/b;Law/a;Lay0/k;I)V

    .line 261
    .line 262
    .line 263
    const v0, -0x3eb870bd

    .line 264
    .line 265
    .line 266
    invoke-static {v0, v4, v5}, Lt2/c;->b(ILl2/o;Llx0/e;)Lt2/b;

    .line 267
    .line 268
    .line 269
    move-result-object v3

    .line 270
    const/16 v5, 0xc06

    .line 271
    .line 272
    const/4 v6, 0x6

    .line 273
    const/4 v1, 0x0

    .line 274
    const/4 v2, 0x0

    .line 275
    move-object/from16 v0, p1

    .line 276
    .line 277
    invoke-static/range {v0 .. v6}, Lk1/d;->a(Lx2/s;Lx2/e;ZLt2/b;Ll2/o;II)V

    .line 278
    .line 279
    .line 280
    move-object v9, v8

    .line 281
    move-object v13, v12

    .line 282
    move v8, v7

    .line 283
    move-object v12, v11

    .line 284
    move-object v11, v10

    .line 285
    :goto_6
    invoke-virtual {v4}, Ll2/t;->s()Ll2/u1;

    .line 286
    .line 287
    .line 288
    move-result-object v0

    .line 289
    if-nez v0, :cond_b

    .line 290
    .line 291
    return-void

    .line 292
    :cond_b
    new-instance v5, Law/s;

    .line 293
    .line 294
    move-object/from16 v6, p0

    .line 295
    .line 296
    move-object/from16 v7, p1

    .line 297
    .line 298
    move-object/from16 v10, p4

    .line 299
    .line 300
    move-object/from16 v14, p8

    .line 301
    .line 302
    move/from16 v15, p10

    .line 303
    .line 304
    invoke-direct/range {v5 .. v15}, Law/s;-><init>(Law/w;Lx2/s;ZLaw/v;Lay0/k;Lay0/k;Law/b;Law/a;Lay0/k;I)V

    .line 305
    .line 306
    .line 307
    iput-object v5, v0, Ll2/u1;->d:Lay0/n;

    .line 308
    .line 309
    return-void
.end method

.method public static c(Lnx0/i;)Lnx0/i;
    .locals 1

    .line 1
    iget-object v0, p0, Lnx0/i;->d:Lnx0/f;

    .line 2
    .line 3
    invoke-virtual {v0}, Lnx0/f;->b()Lnx0/f;

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0}, Lmx0/i;->size()I

    .line 7
    .line 8
    .line 9
    move-result v0

    .line 10
    if-lez v0, :cond_0

    .line 11
    .line 12
    return-object p0

    .line 13
    :cond_0
    sget-object p0, Lnx0/i;->e:Lnx0/i;

    .line 14
    .line 15
    return-object p0
.end method

.method public static d(Landroid/content/Context;)Z
    .locals 4

    .line 1
    sget-object v0, Ljp/m1;->a:Ljava/lang/Boolean;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    return p0

    .line 10
    :cond_0
    const/4 v0, 0x0

    .line 11
    :try_start_0
    invoke-virtual {p0}, Landroid/content/Context;->getPackageManager()Landroid/content/pm/PackageManager;

    .line 12
    .line 13
    .line 14
    move-result-object v1

    .line 15
    invoke-virtual {p0}, Landroid/content/Context;->getPackageName()Ljava/lang/String;

    .line 16
    .line 17
    .line 18
    move-result-object p0

    .line 19
    const/16 v2, 0x80

    .line 20
    .line 21
    invoke-virtual {v1, p0, v2}, Landroid/content/pm/PackageManager;->getApplicationInfo(Ljava/lang/String;I)Landroid/content/pm/ApplicationInfo;

    .line 22
    .line 23
    .line 24
    move-result-object p0

    .line 25
    iget-object p0, p0, Landroid/content/pm/ApplicationInfo;->metaData:Landroid/os/Bundle;

    .line 26
    .line 27
    const-string v1, "firebase_performance_logcat_enabled"

    .line 28
    .line 29
    invoke-virtual {p0, v1, v0}, Landroid/os/BaseBundle;->getBoolean(Ljava/lang/String;Z)Z

    .line 30
    .line 31
    .line 32
    move-result p0

    .line 33
    invoke-static {p0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 34
    .line 35
    .line 36
    move-result-object p0

    .line 37
    sput-object p0, Ljp/m1;->a:Ljava/lang/Boolean;

    .line 38
    .line 39
    invoke-virtual {p0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 40
    .line 41
    .line 42
    move-result p0
    :try_end_0
    .catch Landroid/content/pm/PackageManager$NameNotFoundException; {:try_start_0 .. :try_end_0} :catch_0
    .catch Ljava/lang/NullPointerException; {:try_start_0 .. :try_end_0} :catch_0

    .line 43
    return p0

    .line 44
    :catch_0
    move-exception p0

    .line 45
    invoke-static {}, Lst/a;->d()Lst/a;

    .line 46
    .line 47
    .line 48
    move-result-object v1

    .line 49
    new-instance v2, Ljava/lang/StringBuilder;

    .line 50
    .line 51
    const-string v3, "No perf logcat meta data found "

    .line 52
    .line 53
    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 54
    .line 55
    .line 56
    invoke-virtual {p0}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    .line 57
    .line 58
    .line 59
    move-result-object p0

    .line 60
    invoke-virtual {v2, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 61
    .line 62
    .line 63
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 64
    .line 65
    .line 66
    move-result-object p0

    .line 67
    invoke-virtual {v1, p0}, Lst/a;->a(Ljava/lang/String;)V

    .line 68
    .line 69
    .line 70
    return v0
.end method

.method public static e(Ljava/util/Set;Ljava/lang/Object;)Ljava/util/LinkedHashSet;
    .locals 6

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    new-instance v0, Ljava/util/LinkedHashSet;

    .line 7
    .line 8
    invoke-interface {p0}, Ljava/util/Set;->size()I

    .line 9
    .line 10
    .line 11
    move-result v1

    .line 12
    invoke-static {v1}, Lmx0/x;->k(I)I

    .line 13
    .line 14
    .line 15
    move-result v1

    .line 16
    invoke-direct {v0, v1}, Ljava/util/LinkedHashSet;-><init>(I)V

    .line 17
    .line 18
    .line 19
    check-cast p0, Ljava/lang/Iterable;

    .line 20
    .line 21
    invoke-interface {p0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 22
    .line 23
    .line 24
    move-result-object p0

    .line 25
    const/4 v1, 0x0

    .line 26
    move v2, v1

    .line 27
    :cond_0
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 28
    .line 29
    .line 30
    move-result v3

    .line 31
    if-eqz v3, :cond_2

    .line 32
    .line 33
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 34
    .line 35
    .line 36
    move-result-object v3

    .line 37
    const/4 v4, 0x1

    .line 38
    if-nez v2, :cond_1

    .line 39
    .line 40
    invoke-static {v3, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 41
    .line 42
    .line 43
    move-result v5

    .line 44
    if-eqz v5, :cond_1

    .line 45
    .line 46
    move v2, v4

    .line 47
    move v4, v1

    .line 48
    :cond_1
    if-eqz v4, :cond_0

    .line 49
    .line 50
    invoke-interface {v0, v3}, Ljava/util/Collection;->add(Ljava/lang/Object;)Z

    .line 51
    .line 52
    .line 53
    goto :goto_0

    .line 54
    :cond_2
    return-object v0
.end method

.method public static f(Ljava/util/Set;Ljava/lang/Iterable;)Ljava/util/Set;
    .locals 3

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "elements"

    .line 7
    .line 8
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    invoke-static {p1}, Lmx0/q;->B(Ljava/lang/Iterable;)Ljava/util/Collection;

    .line 12
    .line 13
    .line 14
    move-result-object p1

    .line 15
    invoke-interface {p1}, Ljava/util/Collection;->isEmpty()Z

    .line 16
    .line 17
    .line 18
    move-result v0

    .line 19
    if-eqz v0, :cond_0

    .line 20
    .line 21
    check-cast p0, Ljava/lang/Iterable;

    .line 22
    .line 23
    invoke-static {p0}, Lmx0/q;->C0(Ljava/lang/Iterable;)Ljava/util/Set;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    return-object p0

    .line 28
    :cond_0
    instance-of v0, p1, Ljava/util/Set;

    .line 29
    .line 30
    if-eqz v0, :cond_3

    .line 31
    .line 32
    check-cast p0, Ljava/lang/Iterable;

    .line 33
    .line 34
    new-instance v0, Ljava/util/LinkedHashSet;

    .line 35
    .line 36
    invoke-direct {v0}, Ljava/util/LinkedHashSet;-><init>()V

    .line 37
    .line 38
    .line 39
    invoke-interface {p0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 40
    .line 41
    .line 42
    move-result-object p0

    .line 43
    :cond_1
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 44
    .line 45
    .line 46
    move-result v1

    .line 47
    if-eqz v1, :cond_2

    .line 48
    .line 49
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 50
    .line 51
    .line 52
    move-result-object v1

    .line 53
    move-object v2, p1

    .line 54
    check-cast v2, Ljava/util/Set;

    .line 55
    .line 56
    invoke-interface {v2, v1}, Ljava/util/Set;->contains(Ljava/lang/Object;)Z

    .line 57
    .line 58
    .line 59
    move-result v2

    .line 60
    if-nez v2, :cond_1

    .line 61
    .line 62
    invoke-interface {v0, v1}, Ljava/util/Collection;->add(Ljava/lang/Object;)Z

    .line 63
    .line 64
    .line 65
    goto :goto_0

    .line 66
    :cond_2
    return-object v0

    .line 67
    :cond_3
    new-instance v0, Ljava/util/LinkedHashSet;

    .line 68
    .line 69
    check-cast p0, Ljava/util/Collection;

    .line 70
    .line 71
    invoke-direct {v0, p0}, Ljava/util/LinkedHashSet;-><init>(Ljava/util/Collection;)V

    .line 72
    .line 73
    .line 74
    invoke-virtual {v0, p1}, Ljava/util/AbstractCollection;->removeAll(Ljava/util/Collection;)Z

    .line 75
    .line 76
    .line 77
    return-object v0
.end method

.method public static varargs g([Ljava/lang/Object;)Ljava/util/Set;
    .locals 2

    .line 1
    new-instance v0, Ljava/util/LinkedHashSet;

    .line 2
    .line 3
    array-length v1, p0

    .line 4
    invoke-static {v1}, Lmx0/x;->k(I)I

    .line 5
    .line 6
    .line 7
    move-result v1

    .line 8
    invoke-direct {v0, v1}, Ljava/util/LinkedHashSet;-><init>(I)V

    .line 9
    .line 10
    .line 11
    invoke-static {p0, v0}, Lmx0/n;->V([Ljava/lang/Object;Ljava/util/LinkedHashSet;)V

    .line 12
    .line 13
    .line 14
    return-object v0
.end method

.method public static h(Ljava/util/Set;Ljava/lang/Iterable;)Ljava/util/LinkedHashSet;
    .locals 2

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "elements"

    .line 7
    .line 8
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    instance-of v0, p1, Ljava/util/Collection;

    .line 12
    .line 13
    if-eqz v0, :cond_0

    .line 14
    .line 15
    move-object v0, p1

    .line 16
    check-cast v0, Ljava/util/Collection;

    .line 17
    .line 18
    invoke-interface {v0}, Ljava/util/Collection;->size()I

    .line 19
    .line 20
    .line 21
    move-result v0

    .line 22
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 23
    .line 24
    .line 25
    move-result-object v0

    .line 26
    goto :goto_0

    .line 27
    :cond_0
    const/4 v0, 0x0

    .line 28
    :goto_0
    if-eqz v0, :cond_1

    .line 29
    .line 30
    invoke-virtual {v0}, Ljava/lang/Number;->intValue()I

    .line 31
    .line 32
    .line 33
    move-result v0

    .line 34
    invoke-interface {p0}, Ljava/util/Set;->size()I

    .line 35
    .line 36
    .line 37
    move-result v1

    .line 38
    add-int/2addr v1, v0

    .line 39
    goto :goto_1

    .line 40
    :cond_1
    invoke-interface {p0}, Ljava/util/Set;->size()I

    .line 41
    .line 42
    .line 43
    move-result v0

    .line 44
    mul-int/lit8 v1, v0, 0x2

    .line 45
    .line 46
    :goto_1
    invoke-static {v1}, Lmx0/x;->k(I)I

    .line 47
    .line 48
    .line 49
    move-result v0

    .line 50
    new-instance v1, Ljava/util/LinkedHashSet;

    .line 51
    .line 52
    invoke-direct {v1, v0}, Ljava/util/LinkedHashSet;-><init>(I)V

    .line 53
    .line 54
    .line 55
    check-cast p0, Ljava/util/Collection;

    .line 56
    .line 57
    invoke-virtual {v1, p0}, Ljava/util/AbstractCollection;->addAll(Ljava/util/Collection;)Z

    .line 58
    .line 59
    .line 60
    invoke-static {p1, v1}, Lmx0/q;->w(Ljava/lang/Iterable;Ljava/util/Collection;)V

    .line 61
    .line 62
    .line 63
    return-object v1
.end method

.method public static i(Ljava/util/Set;Ljava/lang/Object;)Ljava/util/LinkedHashSet;
    .locals 2

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    new-instance v0, Ljava/util/LinkedHashSet;

    .line 7
    .line 8
    invoke-interface {p0}, Ljava/util/Set;->size()I

    .line 9
    .line 10
    .line 11
    move-result v1

    .line 12
    add-int/lit8 v1, v1, 0x1

    .line 13
    .line 14
    invoke-static {v1}, Lmx0/x;->k(I)I

    .line 15
    .line 16
    .line 17
    move-result v1

    .line 18
    invoke-direct {v0, v1}, Ljava/util/LinkedHashSet;-><init>(I)V

    .line 19
    .line 20
    .line 21
    check-cast p0, Ljava/util/Collection;

    .line 22
    .line 23
    invoke-virtual {v0, p0}, Ljava/util/AbstractCollection;->addAll(Ljava/util/Collection;)Z

    .line 24
    .line 25
    .line 26
    invoke-virtual {v0, p1}, Ljava/util/AbstractCollection;->add(Ljava/lang/Object;)Z

    .line 27
    .line 28
    .line 29
    return-object v0
.end method

.method public static j(J)I
    .locals 2

    .line 1
    const-wide/32 v0, 0x7fffffff

    .line 2
    .line 3
    .line 4
    cmp-long v0, p0, v0

    .line 5
    .line 6
    if-lez v0, :cond_0

    .line 7
    .line 8
    const p0, 0x7fffffff

    .line 9
    .line 10
    .line 11
    return p0

    .line 12
    :cond_0
    const-wide/32 v0, -0x80000000

    .line 13
    .line 14
    .line 15
    cmp-long v0, p0, v0

    .line 16
    .line 17
    if-gez v0, :cond_1

    .line 18
    .line 19
    const/high16 p0, -0x80000000

    .line 20
    .line 21
    return p0

    .line 22
    :cond_1
    long-to-int p0, p0

    .line 23
    return p0
.end method

.method public static k(Ljava/lang/Object;)Ljava/util/Set;
    .locals 1

    .line 1
    invoke-static {p0}, Ljava/util/Collections;->singleton(Ljava/lang/Object;)Ljava/util/Set;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    const-string v0, "singleton(...)"

    .line 6
    .line 7
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    return-object p0
.end method

.method public static varargs l([Ljava/lang/Object;)Ljava/util/Set;
    .locals 4

    .line 1
    const-string v0, "elements"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    new-instance v0, Ljava/util/LinkedHashSet;

    .line 7
    .line 8
    invoke-direct {v0}, Ljava/util/LinkedHashSet;-><init>()V

    .line 9
    .line 10
    .line 11
    array-length v1, p0

    .line 12
    const/4 v2, 0x0

    .line 13
    :goto_0
    if-ge v2, v1, :cond_1

    .line 14
    .line 15
    aget-object v3, p0, v2

    .line 16
    .line 17
    if-eqz v3, :cond_0

    .line 18
    .line 19
    invoke-interface {v0, v3}, Ljava/util/Collection;->add(Ljava/lang/Object;)Z

    .line 20
    .line 21
    .line 22
    :cond_0
    add-int/lit8 v2, v2, 0x1

    .line 23
    .line 24
    goto :goto_0

    .line 25
    :cond_1
    return-object v0
.end method
