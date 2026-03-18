.class public final Lh2/v1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ll2/b1;


# direct methods
.method public synthetic constructor <init>(Ll2/b1;I)V
    .locals 0

    .line 1
    iput p2, p0, Lh2/v1;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lh2/v1;->e:Ll2/b1;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 30

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Lh2/v1;->d:I

    .line 4
    .line 5
    packed-switch v1, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    move-object/from16 v1, p1

    .line 9
    .line 10
    check-cast v1, Ll2/o;

    .line 11
    .line 12
    move-object/from16 v2, p2

    .line 13
    .line 14
    check-cast v2, Ljava/lang/Number;

    .line 15
    .line 16
    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    .line 17
    .line 18
    .line 19
    move-result v2

    .line 20
    and-int/lit8 v3, v2, 0x3

    .line 21
    .line 22
    const/4 v4, 0x2

    .line 23
    const/4 v5, 0x1

    .line 24
    const/4 v6, 0x0

    .line 25
    if-eq v3, v4, :cond_0

    .line 26
    .line 27
    move v3, v5

    .line 28
    goto :goto_0

    .line 29
    :cond_0
    move v3, v6

    .line 30
    :goto_0
    and-int/2addr v2, v5

    .line 31
    check-cast v1, Ll2/t;

    .line 32
    .line 33
    invoke-virtual {v1, v2, v3}, Ll2/t;->O(IZ)Z

    .line 34
    .line 35
    .line 36
    move-result v2

    .line 37
    if-eqz v2, :cond_5

    .line 38
    .line 39
    invoke-virtual {v1}, Ll2/t;->L()Ljava/lang/Object;

    .line 40
    .line 41
    .line 42
    move-result-object v2

    .line 43
    sget-object v3, Ll2/n;->a:Ll2/x0;

    .line 44
    .line 45
    if-ne v2, v3, :cond_1

    .line 46
    .line 47
    new-instance v2, Lh10/d;

    .line 48
    .line 49
    const/16 v3, 0xf

    .line 50
    .line 51
    invoke-direct {v2, v3}, Lh10/d;-><init>(I)V

    .line 52
    .line 53
    .line 54
    invoke-virtual {v1, v2}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 55
    .line 56
    .line 57
    :cond_1
    check-cast v2, Lay0/k;

    .line 58
    .line 59
    sget-object v3, Lx2/p;->b:Lx2/p;

    .line 60
    .line 61
    invoke-static {v3, v6, v2}, Ld4/n;->b(Lx2/s;ZLay0/k;)Lx2/s;

    .line 62
    .line 63
    .line 64
    move-result-object v2

    .line 65
    sget-object v3, Lx2/c;->d:Lx2/j;

    .line 66
    .line 67
    invoke-static {v3, v6}, Lk1/n;->d(Lx2/e;Z)Lt3/q0;

    .line 68
    .line 69
    .line 70
    move-result-object v3

    .line 71
    iget-wide v7, v1, Ll2/t;->T:J

    .line 72
    .line 73
    invoke-static {v7, v8}, Ljava/lang/Long;->hashCode(J)I

    .line 74
    .line 75
    .line 76
    move-result v4

    .line 77
    invoke-virtual {v1}, Ll2/t;->m()Ll2/p1;

    .line 78
    .line 79
    .line 80
    move-result-object v7

    .line 81
    invoke-static {v1, v2}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 82
    .line 83
    .line 84
    move-result-object v2

    .line 85
    sget-object v8, Lv3/k;->m1:Lv3/j;

    .line 86
    .line 87
    invoke-virtual {v8}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 88
    .line 89
    .line 90
    sget-object v8, Lv3/j;->b:Lv3/i;

    .line 91
    .line 92
    invoke-virtual {v1}, Ll2/t;->c0()V

    .line 93
    .line 94
    .line 95
    iget-boolean v9, v1, Ll2/t;->S:Z

    .line 96
    .line 97
    if-eqz v9, :cond_2

    .line 98
    .line 99
    invoke-virtual {v1, v8}, Ll2/t;->l(Lay0/a;)V

    .line 100
    .line 101
    .line 102
    goto :goto_1

    .line 103
    :cond_2
    invoke-virtual {v1}, Ll2/t;->m0()V

    .line 104
    .line 105
    .line 106
    :goto_1
    sget-object v8, Lv3/j;->g:Lv3/h;

    .line 107
    .line 108
    invoke-static {v8, v3, v1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 109
    .line 110
    .line 111
    sget-object v3, Lv3/j;->f:Lv3/h;

    .line 112
    .line 113
    invoke-static {v3, v7, v1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 114
    .line 115
    .line 116
    sget-object v3, Lv3/j;->j:Lv3/h;

    .line 117
    .line 118
    iget-boolean v7, v1, Ll2/t;->S:Z

    .line 119
    .line 120
    if-nez v7, :cond_3

    .line 121
    .line 122
    invoke-virtual {v1}, Ll2/t;->L()Ljava/lang/Object;

    .line 123
    .line 124
    .line 125
    move-result-object v7

    .line 126
    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 127
    .line 128
    .line 129
    move-result-object v8

    .line 130
    invoke-static {v7, v8}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 131
    .line 132
    .line 133
    move-result v7

    .line 134
    if-nez v7, :cond_4

    .line 135
    .line 136
    :cond_3
    invoke-static {v4, v1, v4, v3}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 137
    .line 138
    .line 139
    :cond_4
    sget-object v3, Lv3/j;->d:Lv3/h;

    .line 140
    .line 141
    invoke-static {v3, v2, v1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 142
    .line 143
    .line 144
    iget-object v0, v0, Lh2/v1;->e:Ll2/b1;

    .line 145
    .line 146
    invoke-interface {v0}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 147
    .line 148
    .line 149
    move-result-object v0

    .line 150
    check-cast v0, Lay0/n;

    .line 151
    .line 152
    invoke-static {v6, v0, v1, v5}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->u(ILay0/n;Ll2/t;Z)V

    .line 153
    .line 154
    .line 155
    goto :goto_2

    .line 156
    :cond_5
    invoke-virtual {v1}, Ll2/t;->R()V

    .line 157
    .line 158
    .line 159
    :goto_2
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 160
    .line 161
    return-object v0

    .line 162
    :pswitch_0
    move-object/from16 v1, p1

    .line 163
    .line 164
    check-cast v1, Ll2/o;

    .line 165
    .line 166
    move-object/from16 v2, p2

    .line 167
    .line 168
    check-cast v2, Ljava/lang/Number;

    .line 169
    .line 170
    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    .line 171
    .line 172
    .line 173
    move-result v2

    .line 174
    and-int/lit8 v3, v2, 0x3

    .line 175
    .line 176
    const/4 v4, 0x2

    .line 177
    const/4 v5, 0x1

    .line 178
    const/4 v6, 0x0

    .line 179
    if-eq v3, v4, :cond_6

    .line 180
    .line 181
    move v3, v5

    .line 182
    goto :goto_3

    .line 183
    :cond_6
    move v3, v6

    .line 184
    :goto_3
    and-int/2addr v2, v5

    .line 185
    check-cast v1, Ll2/t;

    .line 186
    .line 187
    invoke-virtual {v1, v2, v3}, Ll2/t;->O(IZ)Z

    .line 188
    .line 189
    .line 190
    move-result v2

    .line 191
    if-eqz v2, :cond_8

    .line 192
    .line 193
    iget-object v0, v0, Lh2/v1;->e:Ll2/b1;

    .line 194
    .line 195
    invoke-interface {v0}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 196
    .line 197
    .line 198
    move-result-object v2

    .line 199
    check-cast v2, Ljava/lang/CharSequence;

    .line 200
    .line 201
    invoke-static {v2}, Lly0/p;->M(Ljava/lang/CharSequence;)Z

    .line 202
    .line 203
    .line 204
    move-result v2

    .line 205
    if-nez v2, :cond_7

    .line 206
    .line 207
    const v2, -0x137e8fd9

    .line 208
    .line 209
    .line 210
    invoke-virtual {v1, v2}, Ll2/t;->Y(I)V

    .line 211
    .line 212
    .line 213
    invoke-interface {v0}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 214
    .line 215
    .line 216
    move-result-object v0

    .line 217
    move-object v7, v0

    .line 218
    check-cast v7, Ljava/lang/String;

    .line 219
    .line 220
    const/16 v28, 0x0

    .line 221
    .line 222
    const v29, 0x3fffe

    .line 223
    .line 224
    .line 225
    const/4 v8, 0x0

    .line 226
    const-wide/16 v9, 0x0

    .line 227
    .line 228
    const-wide/16 v11, 0x0

    .line 229
    .line 230
    const/4 v13, 0x0

    .line 231
    const-wide/16 v14, 0x0

    .line 232
    .line 233
    const/16 v16, 0x0

    .line 234
    .line 235
    const/16 v17, 0x0

    .line 236
    .line 237
    const-wide/16 v18, 0x0

    .line 238
    .line 239
    const/16 v20, 0x0

    .line 240
    .line 241
    const/16 v21, 0x0

    .line 242
    .line 243
    const/16 v22, 0x0

    .line 244
    .line 245
    const/16 v23, 0x0

    .line 246
    .line 247
    const/16 v24, 0x0

    .line 248
    .line 249
    const/16 v25, 0x0

    .line 250
    .line 251
    const/16 v27, 0x0

    .line 252
    .line 253
    move-object/from16 v26, v1

    .line 254
    .line 255
    invoke-static/range {v7 .. v29}, Lh2/rb;->b(Ljava/lang/String;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZIILay0/k;Lg4/p0;Ll2/o;III)V

    .line 256
    .line 257
    .line 258
    :goto_4
    invoke-virtual {v1, v6}, Ll2/t;->q(Z)V

    .line 259
    .line 260
    .line 261
    goto :goto_5

    .line 262
    :cond_7
    const v0, -0x5c531c70

    .line 263
    .line 264
    .line 265
    invoke-virtual {v1, v0}, Ll2/t;->Y(I)V

    .line 266
    .line 267
    .line 268
    goto :goto_4

    .line 269
    :cond_8
    invoke-virtual {v1}, Ll2/t;->R()V

    .line 270
    .line 271
    .line 272
    :goto_5
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 273
    .line 274
    return-object v0

    .line 275
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
