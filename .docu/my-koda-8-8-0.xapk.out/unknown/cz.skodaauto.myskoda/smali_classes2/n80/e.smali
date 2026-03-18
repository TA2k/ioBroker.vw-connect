.class public abstract Ln80/e;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:F


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    const/16 v0, 0x7a

    .line 2
    .line 3
    int-to-float v0, v0

    .line 4
    sput v0, Ln80/e;->a:F

    .line 5
    .line 6
    return-void
.end method

.method public static final a(Ll2/o;I)V
    .locals 14

    .line 1
    move-object v5, p0

    .line 2
    check-cast v5, Ll2/t;

    .line 3
    .line 4
    const p0, -0x47a9747b

    .line 5
    .line 6
    .line 7
    invoke-virtual {v5, p0}, Ll2/t;->a0(I)Ll2/t;

    .line 8
    .line 9
    .line 10
    const/4 p0, 0x1

    .line 11
    const/4 v0, 0x0

    .line 12
    if-eqz p1, :cond_0

    .line 13
    .line 14
    move v1, p0

    .line 15
    goto :goto_0

    .line 16
    :cond_0
    move v1, v0

    .line 17
    :goto_0
    and-int/lit8 v2, p1, 0x1

    .line 18
    .line 19
    invoke-virtual {v5, v2, v1}, Ll2/t;->O(IZ)Z

    .line 20
    .line 21
    .line 22
    move-result v1

    .line 23
    if-eqz v1, :cond_b

    .line 24
    .line 25
    const v1, -0x6040e0aa

    .line 26
    .line 27
    .line 28
    invoke-virtual {v5, v1}, Ll2/t;->Y(I)V

    .line 29
    .line 30
    .line 31
    invoke-static {v5}, Lq7/a;->a(Ll2/o;)Landroidx/lifecycle/i1;

    .line 32
    .line 33
    .line 34
    move-result-object v1

    .line 35
    if-eqz v1, :cond_a

    .line 36
    .line 37
    invoke-static {v1}, Ljp/ib;->a(Landroidx/lifecycle/i1;)Lp7/c;

    .line 38
    .line 39
    .line 40
    move-result-object v9

    .line 41
    invoke-static {v5}, Lw11/c;->b(Ll2/o;)Lk21/a;

    .line 42
    .line 43
    .line 44
    move-result-object v11

    .line 45
    const-class v2, Lm80/h;

    .line 46
    .line 47
    sget-object v3, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 48
    .line 49
    invoke-virtual {v3, v2}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 50
    .line 51
    .line 52
    move-result-object v6

    .line 53
    invoke-interface {v1}, Landroidx/lifecycle/i1;->getViewModelStore()Landroidx/lifecycle/h1;

    .line 54
    .line 55
    .line 56
    move-result-object v7

    .line 57
    const/4 v8, 0x0

    .line 58
    const/4 v10, 0x0

    .line 59
    const/4 v12, 0x0

    .line 60
    invoke-static/range {v6 .. v12}, Ljp/lb;->a(Lhy0/d;Landroidx/lifecycle/h1;Ljava/lang/String;Lp7/c;Lh21/b;Lk21/a;Lay0/a;)Landroidx/lifecycle/b1;

    .line 61
    .line 62
    .line 63
    move-result-object v1

    .line 64
    invoke-virtual {v5, v0}, Ll2/t;->q(Z)V

    .line 65
    .line 66
    .line 67
    check-cast v1, Lql0/j;

    .line 68
    .line 69
    invoke-static {v1, v5, v0, p0}, Lkp/x5;->b(Lql0/j;Ll2/o;II)V

    .line 70
    .line 71
    .line 72
    move-object v8, v1

    .line 73
    check-cast v8, Lm80/h;

    .line 74
    .line 75
    iget-object v1, v8, Lql0/j;->g:Lyy0/l1;

    .line 76
    .line 77
    const/4 v2, 0x0

    .line 78
    invoke-static {v1, v2, v5, p0}, Ll2/b;->f(Lyy0/a2;Lwy0/c;Ll2/o;I)Ll2/b1;

    .line 79
    .line 80
    .line 81
    move-result-object p0

    .line 82
    invoke-interface {p0}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 83
    .line 84
    .line 85
    move-result-object v1

    .line 86
    check-cast v1, Lm80/g;

    .line 87
    .line 88
    iget-boolean v1, v1, Lm80/g;->a:Z

    .line 89
    .line 90
    if-eqz v1, :cond_1

    .line 91
    .line 92
    const p0, -0x60a6ff59

    .line 93
    .line 94
    .line 95
    invoke-virtual {v5, p0}, Ll2/t;->Y(I)V

    .line 96
    .line 97
    .line 98
    const/4 p0, 0x3

    .line 99
    invoke-static {v2, v2, v5, v0, p0}, Lxf0/y1;->c(Lx2/s;Ljava/lang/String;Ll2/o;II)V

    .line 100
    .line 101
    .line 102
    invoke-virtual {v5, v0}, Ll2/t;->q(Z)V

    .line 103
    .line 104
    .line 105
    invoke-virtual {v5}, Ll2/t;->s()Ll2/u1;

    .line 106
    .line 107
    .line 108
    move-result-object p0

    .line 109
    if-eqz p0, :cond_c

    .line 110
    .line 111
    new-instance v0, Ln70/c0;

    .line 112
    .line 113
    const/16 v1, 0xc

    .line 114
    .line 115
    invoke-direct {v0, p1, v1}, Ln70/c0;-><init>(II)V

    .line 116
    .line 117
    .line 118
    :goto_1
    iput-object v0, p0, Ll2/u1;->d:Lay0/n;

    .line 119
    .line 120
    return-void

    .line 121
    :cond_1
    const v1, -0x60cb5dc3

    .line 122
    .line 123
    .line 124
    invoke-virtual {v5, v1}, Ll2/t;->Y(I)V

    .line 125
    .line 126
    .line 127
    invoke-virtual {v5, v0}, Ll2/t;->q(Z)V

    .line 128
    .line 129
    .line 130
    invoke-interface {p0}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 131
    .line 132
    .line 133
    move-result-object p0

    .line 134
    move-object v0, p0

    .line 135
    check-cast v0, Lm80/g;

    .line 136
    .line 137
    invoke-virtual {v5, v8}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 138
    .line 139
    .line 140
    move-result p0

    .line 141
    invoke-virtual {v5}, Ll2/t;->L()Ljava/lang/Object;

    .line 142
    .line 143
    .line 144
    move-result-object v1

    .line 145
    sget-object v2, Ll2/n;->a:Ll2/x0;

    .line 146
    .line 147
    if-nez p0, :cond_2

    .line 148
    .line 149
    if-ne v1, v2, :cond_3

    .line 150
    .line 151
    :cond_2
    new-instance v6, Ln80/d;

    .line 152
    .line 153
    const/4 v12, 0x0

    .line 154
    const/4 v13, 0x1

    .line 155
    const/4 v7, 0x0

    .line 156
    const-class v9, Lm80/h;

    .line 157
    .line 158
    const-string v10, "onShowRedirectConfirmation"

    .line 159
    .line 160
    const-string v11, "onShowRedirectConfirmation()V"

    .line 161
    .line 162
    invoke-direct/range {v6 .. v13}, Ln80/d;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 163
    .line 164
    .line 165
    invoke-virtual {v5, v6}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 166
    .line 167
    .line 168
    move-object v1, v6

    .line 169
    :cond_3
    check-cast v1, Lhy0/g;

    .line 170
    .line 171
    check-cast v1, Lay0/a;

    .line 172
    .line 173
    invoke-virtual {v5, v8}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 174
    .line 175
    .line 176
    move-result p0

    .line 177
    invoke-virtual {v5}, Ll2/t;->L()Ljava/lang/Object;

    .line 178
    .line 179
    .line 180
    move-result-object v3

    .line 181
    if-nez p0, :cond_4

    .line 182
    .line 183
    if-ne v3, v2, :cond_5

    .line 184
    .line 185
    :cond_4
    new-instance v6, Ln80/d;

    .line 186
    .line 187
    const/4 v12, 0x0

    .line 188
    const/4 v13, 0x2

    .line 189
    const/4 v7, 0x0

    .line 190
    const-class v9, Lm80/h;

    .line 191
    .line 192
    const-string v10, "onHideRedirectConfirmation"

    .line 193
    .line 194
    const-string v11, "onHideRedirectConfirmation()V"

    .line 195
    .line 196
    invoke-direct/range {v6 .. v13}, Ln80/d;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 197
    .line 198
    .line 199
    invoke-virtual {v5, v6}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 200
    .line 201
    .line 202
    move-object v3, v6

    .line 203
    :cond_5
    check-cast v3, Lhy0/g;

    .line 204
    .line 205
    check-cast v3, Lay0/a;

    .line 206
    .line 207
    invoke-virtual {v5, v8}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 208
    .line 209
    .line 210
    move-result p0

    .line 211
    invoke-virtual {v5}, Ll2/t;->L()Ljava/lang/Object;

    .line 212
    .line 213
    .line 214
    move-result-object v4

    .line 215
    if-nez p0, :cond_6

    .line 216
    .line 217
    if-ne v4, v2, :cond_7

    .line 218
    .line 219
    :cond_6
    new-instance v6, Ln80/d;

    .line 220
    .line 221
    const/4 v12, 0x0

    .line 222
    const/4 v13, 0x3

    .line 223
    const/4 v7, 0x0

    .line 224
    const-class v9, Lm80/h;

    .line 225
    .line 226
    const-string v10, "onOpenPortal"

    .line 227
    .line 228
    const-string v11, "onOpenPortal()V"

    .line 229
    .line 230
    invoke-direct/range {v6 .. v13}, Ln80/d;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 231
    .line 232
    .line 233
    invoke-virtual {v5, v6}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 234
    .line 235
    .line 236
    move-object v4, v6

    .line 237
    :cond_7
    check-cast v4, Lhy0/g;

    .line 238
    .line 239
    check-cast v4, Lay0/a;

    .line 240
    .line 241
    invoke-virtual {v5, v8}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 242
    .line 243
    .line 244
    move-result p0

    .line 245
    invoke-virtual {v5}, Ll2/t;->L()Ljava/lang/Object;

    .line 246
    .line 247
    .line 248
    move-result-object v6

    .line 249
    if-nez p0, :cond_8

    .line 250
    .line 251
    if-ne v6, v2, :cond_9

    .line 252
    .line 253
    :cond_8
    new-instance v6, Ln80/d;

    .line 254
    .line 255
    const/4 v12, 0x0

    .line 256
    const/4 v13, 0x4

    .line 257
    const/4 v7, 0x0

    .line 258
    const-class v9, Lm80/h;

    .line 259
    .line 260
    const-string v10, "onBack"

    .line 261
    .line 262
    const-string v11, "onBack()V"

    .line 263
    .line 264
    invoke-direct/range {v6 .. v13}, Ln80/d;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 265
    .line 266
    .line 267
    invoke-virtual {v5, v6}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 268
    .line 269
    .line 270
    :cond_9
    check-cast v6, Lhy0/g;

    .line 271
    .line 272
    check-cast v6, Lay0/a;

    .line 273
    .line 274
    move-object v2, v3

    .line 275
    move-object v3, v4

    .line 276
    move-object v4, v6

    .line 277
    const/4 v6, 0x0

    .line 278
    invoke-static/range {v0 .. v6}, Ln80/e;->b(Lm80/g;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Ll2/o;I)V

    .line 279
    .line 280
    .line 281
    goto :goto_2

    .line 282
    :cond_a
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 283
    .line 284
    const-string p1, "No ViewModelStoreOwner was provided via LocalViewModelStoreOwner"

    .line 285
    .line 286
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 287
    .line 288
    .line 289
    throw p0

    .line 290
    :cond_b
    invoke-virtual {v5}, Ll2/t;->R()V

    .line 291
    .line 292
    .line 293
    :goto_2
    invoke-virtual {v5}, Ll2/t;->s()Ll2/u1;

    .line 294
    .line 295
    .line 296
    move-result-object p0

    .line 297
    if-eqz p0, :cond_c

    .line 298
    .line 299
    new-instance v0, Ln70/c0;

    .line 300
    .line 301
    const/16 v1, 0xd

    .line 302
    .line 303
    invoke-direct {v0, p1, v1}, Ln70/c0;-><init>(II)V

    .line 304
    .line 305
    .line 306
    goto/16 :goto_1

    .line 307
    .line 308
    :cond_c
    return-void
.end method

.method public static final b(Lm80/g;Lay0/a;Lay0/a;Lay0/a;Lay0/a;Ll2/o;I)V
    .locals 22

    .line 1
    move-object/from16 v1, p0

    .line 2
    .line 3
    move-object/from16 v6, p1

    .line 4
    .line 5
    move-object/from16 v11, p5

    .line 6
    .line 7
    check-cast v11, Ll2/t;

    .line 8
    .line 9
    const v0, 0x39321924

    .line 10
    .line 11
    .line 12
    invoke-virtual {v11, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 13
    .line 14
    .line 15
    invoke-virtual {v11, v1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 16
    .line 17
    .line 18
    move-result v0

    .line 19
    if-eqz v0, :cond_0

    .line 20
    .line 21
    const/4 v0, 0x4

    .line 22
    goto :goto_0

    .line 23
    :cond_0
    const/4 v0, 0x2

    .line 24
    :goto_0
    or-int v0, p6, v0

    .line 25
    .line 26
    invoke-virtual {v11, v6}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 27
    .line 28
    .line 29
    move-result v2

    .line 30
    if-eqz v2, :cond_1

    .line 31
    .line 32
    const/16 v2, 0x20

    .line 33
    .line 34
    goto :goto_1

    .line 35
    :cond_1
    const/16 v2, 0x10

    .line 36
    .line 37
    :goto_1
    or-int/2addr v0, v2

    .line 38
    move-object/from16 v3, p2

    .line 39
    .line 40
    invoke-virtual {v11, v3}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 41
    .line 42
    .line 43
    move-result v2

    .line 44
    if-eqz v2, :cond_2

    .line 45
    .line 46
    const/16 v2, 0x100

    .line 47
    .line 48
    goto :goto_2

    .line 49
    :cond_2
    const/16 v2, 0x80

    .line 50
    .line 51
    :goto_2
    or-int/2addr v0, v2

    .line 52
    move-object/from16 v4, p3

    .line 53
    .line 54
    invoke-virtual {v11, v4}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 55
    .line 56
    .line 57
    move-result v2

    .line 58
    if-eqz v2, :cond_3

    .line 59
    .line 60
    const/16 v2, 0x800

    .line 61
    .line 62
    goto :goto_3

    .line 63
    :cond_3
    const/16 v2, 0x400

    .line 64
    .line 65
    :goto_3
    or-int/2addr v0, v2

    .line 66
    move-object/from16 v2, p4

    .line 67
    .line 68
    invoke-virtual {v11, v2}, Ll2/t;->i(Ljava/lang/Object;)Z

    .line 69
    .line 70
    .line 71
    move-result v5

    .line 72
    if-eqz v5, :cond_4

    .line 73
    .line 74
    const/16 v5, 0x4000

    .line 75
    .line 76
    goto :goto_4

    .line 77
    :cond_4
    const/16 v5, 0x2000

    .line 78
    .line 79
    :goto_4
    or-int/2addr v0, v5

    .line 80
    and-int/lit16 v5, v0, 0x2493

    .line 81
    .line 82
    const/16 v7, 0x2492

    .line 83
    .line 84
    const/4 v8, 0x1

    .line 85
    if-eq v5, v7, :cond_5

    .line 86
    .line 87
    move v5, v8

    .line 88
    goto :goto_5

    .line 89
    :cond_5
    const/4 v5, 0x0

    .line 90
    :goto_5
    and-int/2addr v0, v8

    .line 91
    invoke-virtual {v11, v0, v5}, Ll2/t;->O(IZ)Z

    .line 92
    .line 93
    .line 94
    move-result v0

    .line 95
    if-eqz v0, :cond_7

    .line 96
    .line 97
    invoke-virtual {v11}, Ll2/t;->L()Ljava/lang/Object;

    .line 98
    .line 99
    .line 100
    move-result-object v0

    .line 101
    sget-object v5, Ll2/n;->a:Ll2/x0;

    .line 102
    .line 103
    if-ne v0, v5, :cond_6

    .line 104
    .line 105
    sget-object v0, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 106
    .line 107
    invoke-static {v0}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 108
    .line 109
    .line 110
    move-result-object v0

    .line 111
    invoke-virtual {v11, v0}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 112
    .line 113
    .line 114
    :cond_6
    check-cast v0, Ll2/b1;

    .line 115
    .line 116
    new-instance v5, Ln70/v;

    .line 117
    .line 118
    const/4 v7, 0x5

    .line 119
    invoke-direct {v5, v6, v7}, Ln70/v;-><init>(Lay0/a;I)V

    .line 120
    .line 121
    .line 122
    const v7, 0x47efe869

    .line 123
    .line 124
    .line 125
    invoke-static {v7, v11, v5}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 126
    .line 127
    .line 128
    move-result-object v9

    .line 129
    move-object v1, v0

    .line 130
    new-instance v0, Lb50/d;

    .line 131
    .line 132
    move-object v5, v3

    .line 133
    move-object/from16 v3, p0

    .line 134
    .line 135
    invoke-direct/range {v0 .. v5}, Lb50/d;-><init>(Ll2/b1;Lay0/a;Lm80/g;Lay0/a;Lay0/a;)V

    .line 136
    .line 137
    .line 138
    move-object v1, v3

    .line 139
    const v2, -0x580c8dcd

    .line 140
    .line 141
    .line 142
    invoke-static {v2, v11, v0}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 143
    .line 144
    .line 145
    move-result-object v18

    .line 146
    const v20, 0x30000180

    .line 147
    .line 148
    .line 149
    const/16 v21, 0x1fb

    .line 150
    .line 151
    const/4 v7, 0x0

    .line 152
    const/4 v8, 0x0

    .line 153
    const/4 v10, 0x0

    .line 154
    move-object/from16 v19, v11

    .line 155
    .line 156
    const/4 v11, 0x0

    .line 157
    const/4 v12, 0x0

    .line 158
    const-wide/16 v13, 0x0

    .line 159
    .line 160
    const-wide/16 v15, 0x0

    .line 161
    .line 162
    const/16 v17, 0x0

    .line 163
    .line 164
    invoke-static/range {v7 .. v21}, Lh2/c8;->a(Lx2/s;Lay0/n;Lay0/n;Lay0/n;Lay0/n;IJJLk1/q1;Lay0/o;Ll2/o;II)V

    .line 165
    .line 166
    .line 167
    iget-object v7, v1, Lm80/g;->c:Ler0/g;

    .line 168
    .line 169
    const/16 v13, 0xe

    .line 170
    .line 171
    const/4 v9, 0x0

    .line 172
    move-object/from16 v11, v19

    .line 173
    .line 174
    invoke-static/range {v7 .. v13}, Lgr0/a;->e(Ler0/g;Lx2/s;Lay0/a;Lay0/a;Ll2/o;II)V

    .line 175
    .line 176
    .line 177
    goto :goto_6

    .line 178
    :cond_7
    move-object/from16 v19, v11

    .line 179
    .line 180
    invoke-virtual/range {v19 .. v19}, Ll2/t;->R()V

    .line 181
    .line 182
    .line 183
    :goto_6
    invoke-virtual/range {v19 .. v19}, Ll2/t;->s()Ll2/u1;

    .line 184
    .line 185
    .line 186
    move-result-object v8

    .line 187
    if-eqz v8, :cond_8

    .line 188
    .line 189
    new-instance v0, Lb10/c;

    .line 190
    .line 191
    const/16 v7, 0x1a

    .line 192
    .line 193
    move-object/from16 v3, p2

    .line 194
    .line 195
    move-object/from16 v4, p3

    .line 196
    .line 197
    move-object/from16 v5, p4

    .line 198
    .line 199
    move-object v2, v6

    .line 200
    move/from16 v6, p6

    .line 201
    .line 202
    invoke-direct/range {v0 .. v7}, Lb10/c;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;II)V

    .line 203
    .line 204
    .line 205
    iput-object v0, v8, Ll2/u1;->d:Lay0/n;

    .line 206
    .line 207
    :cond_8
    return-void
.end method
