.class public final Ly9/g;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lt7/j0;
.implements Landroid/view/View$OnClickListener;
.implements Landroid/widget/PopupWindow$OnDismissListener;


# instance fields
.field public final synthetic d:Ly9/r;


# direct methods
.method public constructor <init>(Ly9/r;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Ly9/g;->d:Ly9/r;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final l(Lt7/i0;)V
    .locals 4

    .line 1
    const/4 v0, 0x4

    .line 2
    const/4 v1, 0x5

    .line 3
    const/16 v2, 0xd

    .line 4
    .line 5
    filled-new-array {v0, v1, v2}, [I

    .line 6
    .line 7
    .line 8
    move-result-object v3

    .line 9
    invoke-virtual {p1, v3}, Lt7/i0;->a([I)Z

    .line 10
    .line 11
    .line 12
    move-result v3

    .line 13
    iget-object p0, p0, Ly9/g;->d:Ly9/r;

    .line 14
    .line 15
    if-eqz v3, :cond_0

    .line 16
    .line 17
    invoke-virtual {p0}, Ly9/r;->q()V

    .line 18
    .line 19
    .line 20
    :cond_0
    const/4 v3, 0x7

    .line 21
    filled-new-array {v0, v1, v3, v2}, [I

    .line 22
    .line 23
    .line 24
    move-result-object v0

    .line 25
    invoke-virtual {p1, v0}, Lt7/i0;->a([I)Z

    .line 26
    .line 27
    .line 28
    move-result v0

    .line 29
    if-eqz v0, :cond_1

    .line 30
    .line 31
    invoke-virtual {p0}, Ly9/r;->s()V

    .line 32
    .line 33
    .line 34
    :cond_1
    const/16 v0, 0x8

    .line 35
    .line 36
    filled-new-array {v0, v2}, [I

    .line 37
    .line 38
    .line 39
    move-result-object v0

    .line 40
    invoke-virtual {p1, v0}, Lt7/i0;->a([I)Z

    .line 41
    .line 42
    .line 43
    move-result v0

    .line 44
    if-eqz v0, :cond_2

    .line 45
    .line 46
    invoke-virtual {p0}, Ly9/r;->t()V

    .line 47
    .line 48
    .line 49
    :cond_2
    const/16 v0, 0x9

    .line 50
    .line 51
    filled-new-array {v0, v2}, [I

    .line 52
    .line 53
    .line 54
    move-result-object v0

    .line 55
    invoke-virtual {p1, v0}, Lt7/i0;->a([I)Z

    .line 56
    .line 57
    .line 58
    move-result v0

    .line 59
    if-eqz v0, :cond_3

    .line 60
    .line 61
    invoke-virtual {p0}, Ly9/r;->v()V

    .line 62
    .line 63
    .line 64
    :cond_3
    new-array v0, v3, [I

    .line 65
    .line 66
    fill-array-data v0, :array_0

    .line 67
    .line 68
    .line 69
    invoke-virtual {p1, v0}, Lt7/i0;->a([I)Z

    .line 70
    .line 71
    .line 72
    move-result v0

    .line 73
    if-eqz v0, :cond_4

    .line 74
    .line 75
    invoke-virtual {p0}, Ly9/r;->p()V

    .line 76
    .line 77
    .line 78
    :cond_4
    const/16 v0, 0xb

    .line 79
    .line 80
    const/4 v1, 0x0

    .line 81
    filled-new-array {v0, v1, v2}, [I

    .line 82
    .line 83
    .line 84
    move-result-object v0

    .line 85
    invoke-virtual {p1, v0}, Lt7/i0;->a([I)Z

    .line 86
    .line 87
    .line 88
    move-result v0

    .line 89
    if-eqz v0, :cond_5

    .line 90
    .line 91
    invoke-virtual {p0}, Ly9/r;->w()V

    .line 92
    .line 93
    .line 94
    :cond_5
    const/16 v0, 0xc

    .line 95
    .line 96
    filled-new-array {v0, v2}, [I

    .line 97
    .line 98
    .line 99
    move-result-object v0

    .line 100
    invoke-virtual {p1, v0}, Lt7/i0;->a([I)Z

    .line 101
    .line 102
    .line 103
    move-result v0

    .line 104
    if-eqz v0, :cond_6

    .line 105
    .line 106
    invoke-virtual {p0}, Ly9/r;->r()V

    .line 107
    .line 108
    .line 109
    :cond_6
    const/4 v0, 0x2

    .line 110
    filled-new-array {v0, v2}, [I

    .line 111
    .line 112
    .line 113
    move-result-object v0

    .line 114
    invoke-virtual {p1, v0}, Lt7/i0;->a([I)Z

    .line 115
    .line 116
    .line 117
    move-result p1

    .line 118
    if-eqz p1, :cond_7

    .line 119
    .line 120
    invoke-virtual {p0}, Ly9/r;->x()V

    .line 121
    .line 122
    .line 123
    :cond_7
    return-void

    .line 124
    nop

    .line 125
    :array_0
    .array-data 4
        0x8
        0x9
        0xb
        0x0
        0x10
        0x11
        0xd
    .end array-data
.end method

.method public final onClick(Landroid/view/View;)V
    .locals 11

    .line 1
    iget-object p0, p0, Ly9/g;->d:Ly9/r;

    .line 2
    .line 3
    iget-object v0, p0, Ly9/r;->F:Landroid/widget/ImageView;

    .line 4
    .line 5
    iget-object v1, p0, Ly9/r;->K:Landroid/view/View;

    .line 6
    .line 7
    iget-object v2, p0, Ly9/r;->J:Landroid/view/View;

    .line 8
    .line 9
    iget-object v3, p0, Ly9/r;->I:Landroid/view/View;

    .line 10
    .line 11
    iget-object v4, p0, Ly9/r;->d:Ly9/w;

    .line 12
    .line 13
    iget-object v5, p0, Ly9/r;->B1:Lt7/l0;

    .line 14
    .line 15
    if-nez v5, :cond_0

    .line 16
    .line 17
    goto/16 :goto_3

    .line 18
    .line 19
    :cond_0
    invoke-virtual {v4}, Ly9/w;->g()V

    .line 20
    .line 21
    .line 22
    iget-object v6, p0, Ly9/r;->w:Landroid/widget/ImageView;

    .line 23
    .line 24
    const/16 v7, 0x9

    .line 25
    .line 26
    if-ne v6, p1, :cond_1

    .line 27
    .line 28
    check-cast v5, Lap0/o;

    .line 29
    .line 30
    invoke-virtual {v5, v7}, Lap0/o;->I(I)Z

    .line 31
    .line 32
    .line 33
    move-result p0

    .line 34
    if-eqz p0, :cond_11

    .line 35
    .line 36
    invoke-virtual {v5}, Lap0/o;->Q()V

    .line 37
    .line 38
    .line 39
    return-void

    .line 40
    :cond_1
    iget-object v6, p0, Ly9/r;->v:Landroid/widget/ImageView;

    .line 41
    .line 42
    if-ne v6, p1, :cond_2

    .line 43
    .line 44
    check-cast v5, Lap0/o;

    .line 45
    .line 46
    const/4 p0, 0x7

    .line 47
    invoke-virtual {v5, p0}, Lap0/o;->I(I)Z

    .line 48
    .line 49
    .line 50
    move-result p0

    .line 51
    if-eqz p0, :cond_11

    .line 52
    .line 53
    invoke-virtual {v5}, Lap0/o;->S()V

    .line 54
    .line 55
    .line 56
    return-void

    .line 57
    :cond_2
    iget-object v6, p0, Ly9/r;->y:Landroid/view/View;

    .line 58
    .line 59
    const/16 v8, 0xc

    .line 60
    .line 61
    if-ne v6, p1, :cond_3

    .line 62
    .line 63
    move-object p0, v5

    .line 64
    check-cast p0, La8/i0;

    .line 65
    .line 66
    invoke-virtual {p0}, La8/i0;->o0()I

    .line 67
    .line 68
    .line 69
    move-result p0

    .line 70
    const/4 p1, 0x4

    .line 71
    if-eq p0, p1, :cond_11

    .line 72
    .line 73
    check-cast v5, Lap0/o;

    .line 74
    .line 75
    invoke-virtual {v5, v8}, Lap0/o;->I(I)Z

    .line 76
    .line 77
    .line 78
    move-result p0

    .line 79
    if-eqz p0, :cond_11

    .line 80
    .line 81
    move-object p0, v5

    .line 82
    check-cast p0, La8/i0;

    .line 83
    .line 84
    invoke-virtual {p0}, La8/i0;->L0()V

    .line 85
    .line 86
    .line 87
    iget-wide p0, p0, La8/i0;->A:J

    .line 88
    .line 89
    invoke-virtual {v5, v8, p0, p1}, Lap0/o;->R(IJ)V

    .line 90
    .line 91
    .line 92
    return-void

    .line 93
    :cond_3
    iget-object v6, p0, Ly9/r;->z:Landroid/view/View;

    .line 94
    .line 95
    if-ne v6, p1, :cond_4

    .line 96
    .line 97
    check-cast v5, Lap0/o;

    .line 98
    .line 99
    const/16 p0, 0xb

    .line 100
    .line 101
    invoke-virtual {v5, p0}, Lap0/o;->I(I)Z

    .line 102
    .line 103
    .line 104
    move-result p1

    .line 105
    if-eqz p1, :cond_11

    .line 106
    .line 107
    move-object p1, v5

    .line 108
    check-cast p1, La8/i0;

    .line 109
    .line 110
    invoke-virtual {p1}, La8/i0;->L0()V

    .line 111
    .line 112
    .line 113
    iget-wide v0, p1, La8/i0;->z:J

    .line 114
    .line 115
    neg-long v0, v0

    .line 116
    invoke-virtual {v5, p0, v0, v1}, Lap0/o;->R(IJ)V

    .line 117
    .line 118
    .line 119
    return-void

    .line 120
    :cond_4
    iget-object v6, p0, Ly9/r;->x:Landroid/widget/ImageView;

    .line 121
    .line 122
    const/4 v9, 0x0

    .line 123
    const/4 v10, 0x1

    .line 124
    if-ne v6, p1, :cond_6

    .line 125
    .line 126
    iget-boolean p0, p0, Ly9/r;->F1:Z

    .line 127
    .line 128
    invoke-static {v5, p0}, Lw7/w;->L(Lt7/l0;Z)Z

    .line 129
    .line 130
    .line 131
    move-result p0

    .line 132
    if-eqz p0, :cond_5

    .line 133
    .line 134
    invoke-static {v5}, Lw7/w;->w(Lt7/l0;)Z

    .line 135
    .line 136
    .line 137
    return-void

    .line 138
    :cond_5
    check-cast v5, Lap0/o;

    .line 139
    .line 140
    invoke-virtual {v5, v10}, Lap0/o;->I(I)Z

    .line 141
    .line 142
    .line 143
    move-result p0

    .line 144
    if-eqz p0, :cond_11

    .line 145
    .line 146
    check-cast v5, La8/i0;

    .line 147
    .line 148
    invoke-virtual {v5}, La8/i0;->L0()V

    .line 149
    .line 150
    .line 151
    invoke-virtual {v5, v10, v9}, La8/i0;->I0(IZ)V

    .line 152
    .line 153
    .line 154
    return-void

    .line 155
    :cond_6
    iget-object v6, p0, Ly9/r;->C:Landroid/widget/ImageView;

    .line 156
    .line 157
    if-ne v6, p1, :cond_c

    .line 158
    .line 159
    const/16 p1, 0xf

    .line 160
    .line 161
    move-object v0, v5

    .line 162
    check-cast v0, Lap0/o;

    .line 163
    .line 164
    invoke-virtual {v0, p1}, Lap0/o;->I(I)Z

    .line 165
    .line 166
    .line 167
    move-result p1

    .line 168
    if-eqz p1, :cond_11

    .line 169
    .line 170
    check-cast v5, La8/i0;

    .line 171
    .line 172
    invoke-virtual {v5}, La8/i0;->L0()V

    .line 173
    .line 174
    .line 175
    iget p1, v5, La8/i0;->K:I

    .line 176
    .line 177
    iget p0, p0, Ly9/r;->L1:I

    .line 178
    .line 179
    move v0, v10

    .line 180
    :goto_0
    const/4 v1, 0x2

    .line 181
    if-gt v0, v1, :cond_b

    .line 182
    .line 183
    add-int v2, p1, v0

    .line 184
    .line 185
    rem-int/lit8 v2, v2, 0x3

    .line 186
    .line 187
    if-eqz v2, :cond_a

    .line 188
    .line 189
    if-eq v2, v10, :cond_8

    .line 190
    .line 191
    if-eq v2, v1, :cond_7

    .line 192
    .line 193
    goto :goto_1

    .line 194
    :cond_7
    and-int/lit8 v1, p0, 0x2

    .line 195
    .line 196
    if-eqz v1, :cond_9

    .line 197
    .line 198
    goto :goto_2

    .line 199
    :cond_8
    and-int/lit8 v1, p0, 0x1

    .line 200
    .line 201
    if-eqz v1, :cond_9

    .line 202
    .line 203
    goto :goto_2

    .line 204
    :cond_9
    :goto_1
    add-int/lit8 v0, v0, 0x1

    .line 205
    .line 206
    goto :goto_0

    .line 207
    :cond_a
    :goto_2
    move p1, v2

    .line 208
    :cond_b
    invoke-virtual {v5, p1}, La8/i0;->C0(I)V

    .line 209
    .line 210
    .line 211
    return-void

    .line 212
    :cond_c
    iget-object v6, p0, Ly9/r;->D:Landroid/widget/ImageView;

    .line 213
    .line 214
    if-ne v6, p1, :cond_d

    .line 215
    .line 216
    const/16 p0, 0xe

    .line 217
    .line 218
    move-object p1, v5

    .line 219
    check-cast p1, Lap0/o;

    .line 220
    .line 221
    invoke-virtual {p1, p0}, Lap0/o;->I(I)Z

    .line 222
    .line 223
    .line 224
    move-result p0

    .line 225
    if-eqz p0, :cond_11

    .line 226
    .line 227
    check-cast v5, La8/i0;

    .line 228
    .line 229
    invoke-virtual {v5}, La8/i0;->L0()V

    .line 230
    .line 231
    .line 232
    iget-boolean p0, v5, La8/i0;->L:Z

    .line 233
    .line 234
    xor-int/2addr p0, v10

    .line 235
    iget-object p1, v5, La8/i0;->q:Le30/v;

    .line 236
    .line 237
    invoke-virtual {v5}, La8/i0;->L0()V

    .line 238
    .line 239
    .line 240
    iget-boolean v0, v5, La8/i0;->L:Z

    .line 241
    .line 242
    if-eq v0, p0, :cond_11

    .line 243
    .line 244
    iput-boolean p0, v5, La8/i0;->L:Z

    .line 245
    .line 246
    iget-object v0, v5, La8/i0;->p:La8/q0;

    .line 247
    .line 248
    iget-object v0, v0, La8/q0;->k:Lw7/t;

    .line 249
    .line 250
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 251
    .line 252
    .line 253
    invoke-static {}, Lw7/t;->b()Lw7/s;

    .line 254
    .line 255
    .line 256
    move-result-object v1

    .line 257
    iget-object v0, v0, Lw7/t;->a:Landroid/os/Handler;

    .line 258
    .line 259
    invoke-virtual {v0, v8, p0, v9}, Landroid/os/Handler;->obtainMessage(III)Landroid/os/Message;

    .line 260
    .line 261
    .line 262
    move-result-object v0

    .line 263
    iput-object v0, v1, Lw7/s;->a:Landroid/os/Message;

    .line 264
    .line 265
    invoke-virtual {v1}, Lw7/s;->b()V

    .line 266
    .line 267
    .line 268
    new-instance v0, La8/x;

    .line 269
    .line 270
    const/4 v1, 0x0

    .line 271
    invoke-direct {v0, v1, p0}, La8/x;-><init>(IZ)V

    .line 272
    .line 273
    .line 274
    invoke-virtual {p1, v7, v0}, Le30/v;->c(ILw7/j;)V

    .line 275
    .line 276
    .line 277
    invoke-virtual {v5}, La8/i0;->H0()V

    .line 278
    .line 279
    .line 280
    invoke-virtual {p1}, Le30/v;->b()V

    .line 281
    .line 282
    .line 283
    return-void

    .line 284
    :cond_d
    if-ne v3, p1, :cond_e

    .line 285
    .line 286
    invoke-virtual {v4}, Ly9/w;->f()V

    .line 287
    .line 288
    .line 289
    iget-object p1, p0, Ly9/r;->o:Ly9/m;

    .line 290
    .line 291
    invoke-virtual {p0, p1, v3}, Ly9/r;->e(Lka/y;Landroid/view/View;)V

    .line 292
    .line 293
    .line 294
    return-void

    .line 295
    :cond_e
    if-ne v2, p1, :cond_f

    .line 296
    .line 297
    invoke-virtual {v4}, Ly9/w;->f()V

    .line 298
    .line 299
    .line 300
    iget-object p1, p0, Ly9/r;->p:Ly9/j;

    .line 301
    .line 302
    invoke-virtual {p0, p1, v2}, Ly9/r;->e(Lka/y;Landroid/view/View;)V

    .line 303
    .line 304
    .line 305
    return-void

    .line 306
    :cond_f
    if-ne v1, p1, :cond_10

    .line 307
    .line 308
    invoke-virtual {v4}, Ly9/w;->f()V

    .line 309
    .line 310
    .line 311
    iget-object p1, p0, Ly9/r;->r:Ly9/f;

    .line 312
    .line 313
    invoke-virtual {p0, p1, v1}, Ly9/r;->e(Lka/y;Landroid/view/View;)V

    .line 314
    .line 315
    .line 316
    return-void

    .line 317
    :cond_10
    if-ne v0, p1, :cond_11

    .line 318
    .line 319
    invoke-virtual {v4}, Ly9/w;->f()V

    .line 320
    .line 321
    .line 322
    iget-object p1, p0, Ly9/r;->q:Ly9/f;

    .line 323
    .line 324
    invoke-virtual {p0, p1, v0}, Ly9/r;->e(Lka/y;Landroid/view/View;)V

    .line 325
    .line 326
    .line 327
    :cond_11
    :goto_3
    return-void
.end method

.method public final onDismiss()V
    .locals 1

    .line 1
    iget-object p0, p0, Ly9/g;->d:Ly9/r;

    .line 2
    .line 3
    iget-boolean v0, p0, Ly9/r;->R1:Z

    .line 4
    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    iget-object p0, p0, Ly9/r;->d:Ly9/w;

    .line 8
    .line 9
    invoke-virtual {p0}, Ly9/w;->g()V

    .line 10
    .line 11
    .line 12
    :cond_0
    return-void
.end method
