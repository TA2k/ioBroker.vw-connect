.class public final Lf2/b0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lx2/s;

.field public final synthetic f:Le1/n1;

.field public final synthetic g:Lt2/b;


# direct methods
.method public synthetic constructor <init>(Lx2/s;Le1/n1;Lt2/b;I)V
    .locals 0

    .line 1
    iput p4, p0, Lf2/b0;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lf2/b0;->e:Lx2/s;

    .line 4
    .line 5
    iput-object p2, p0, Lf2/b0;->f:Le1/n1;

    .line 6
    .line 7
    iput-object p3, p0, Lf2/b0;->g:Lt2/b;

    .line 8
    .line 9
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 10
    .line 11
    .line 12
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 11

    .line 1
    iget v0, p0, Lf2/b0;->d:I

    .line 2
    .line 3
    sget-object v1, Llx0/b0;->a:Llx0/b0;

    .line 4
    .line 5
    const/4 v2, 0x6

    .line 6
    sget-object v3, Lk1/t;->a:Lk1/t;

    .line 7
    .line 8
    iget-object v4, p0, Lf2/b0;->g:Lt2/b;

    .line 9
    .line 10
    const/16 v5, 0xe

    .line 11
    .line 12
    iget-object v6, p0, Lf2/b0;->f:Le1/n1;

    .line 13
    .line 14
    const/4 v7, 0x0

    .line 15
    iget-object p0, p0, Lf2/b0;->e:Lx2/s;

    .line 16
    .line 17
    const/4 v8, 0x2

    .line 18
    const/4 v9, 0x1

    .line 19
    const/4 v10, 0x0

    .line 20
    packed-switch v0, :pswitch_data_0

    .line 21
    .line 22
    .line 23
    check-cast p1, Ll2/o;

    .line 24
    .line 25
    check-cast p2, Ljava/lang/Number;

    .line 26
    .line 27
    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    .line 28
    .line 29
    .line 30
    move-result p2

    .line 31
    and-int/lit8 v0, p2, 0x3

    .line 32
    .line 33
    if-eq v0, v8, :cond_0

    .line 34
    .line 35
    move v0, v9

    .line 36
    goto :goto_0

    .line 37
    :cond_0
    move v0, v10

    .line 38
    :goto_0
    and-int/2addr p2, v9

    .line 39
    check-cast p1, Ll2/t;

    .line 40
    .line 41
    invoke-virtual {p1, p2, v0}, Ll2/t;->O(IZ)Z

    .line 42
    .line 43
    .line 44
    move-result p2

    .line 45
    if-eqz p2, :cond_4

    .line 46
    .line 47
    sget p2, Lh2/q5;->d:F

    .line 48
    .line 49
    invoke-static {p0, v7, p2, v9}, Landroidx/compose/foundation/layout/a;->o(Lx2/s;FFI)Lx2/s;

    .line 50
    .line 51
    .line 52
    move-result-object p0

    .line 53
    sget-object p2, Lk1/r0;->d:Lk1/r0;

    .line 54
    .line 55
    invoke-static {p0}, Landroidx/compose/foundation/layout/a;->r(Lx2/s;)Lx2/s;

    .line 56
    .line 57
    .line 58
    move-result-object p0

    .line 59
    invoke-static {p0, v6, v5}, Lkp/n;->d(Lx2/s;Le1/n1;I)Lx2/s;

    .line 60
    .line 61
    .line 62
    move-result-object p0

    .line 63
    sget-object p2, Lk1/j;->c:Lk1/e;

    .line 64
    .line 65
    sget-object v0, Lx2/c;->p:Lx2/h;

    .line 66
    .line 67
    invoke-static {p2, v0, p1, v10}, Lk1/r;->a(Lk1/i;Lx2/d;Ll2/o;I)Lk1/s;

    .line 68
    .line 69
    .line 70
    move-result-object p2

    .line 71
    iget-wide v5, p1, Ll2/t;->T:J

    .line 72
    .line 73
    invoke-static {v5, v6}, Ljava/lang/Long;->hashCode(J)I

    .line 74
    .line 75
    .line 76
    move-result v0

    .line 77
    invoke-virtual {p1}, Ll2/t;->m()Ll2/p1;

    .line 78
    .line 79
    .line 80
    move-result-object v5

    .line 81
    invoke-static {p1, p0}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 82
    .line 83
    .line 84
    move-result-object p0

    .line 85
    sget-object v6, Lv3/k;->m1:Lv3/j;

    .line 86
    .line 87
    invoke-virtual {v6}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 88
    .line 89
    .line 90
    sget-object v6, Lv3/j;->b:Lv3/i;

    .line 91
    .line 92
    invoke-virtual {p1}, Ll2/t;->c0()V

    .line 93
    .line 94
    .line 95
    iget-boolean v7, p1, Ll2/t;->S:Z

    .line 96
    .line 97
    if-eqz v7, :cond_1

    .line 98
    .line 99
    invoke-virtual {p1, v6}, Ll2/t;->l(Lay0/a;)V

    .line 100
    .line 101
    .line 102
    goto :goto_1

    .line 103
    :cond_1
    invoke-virtual {p1}, Ll2/t;->m0()V

    .line 104
    .line 105
    .line 106
    :goto_1
    sget-object v6, Lv3/j;->g:Lv3/h;

    .line 107
    .line 108
    invoke-static {v6, p2, p1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 109
    .line 110
    .line 111
    sget-object p2, Lv3/j;->f:Lv3/h;

    .line 112
    .line 113
    invoke-static {p2, v5, p1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 114
    .line 115
    .line 116
    sget-object p2, Lv3/j;->j:Lv3/h;

    .line 117
    .line 118
    iget-boolean v5, p1, Ll2/t;->S:Z

    .line 119
    .line 120
    if-nez v5, :cond_2

    .line 121
    .line 122
    invoke-virtual {p1}, Ll2/t;->L()Ljava/lang/Object;

    .line 123
    .line 124
    .line 125
    move-result-object v5

    .line 126
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 127
    .line 128
    .line 129
    move-result-object v6

    .line 130
    invoke-static {v5, v6}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 131
    .line 132
    .line 133
    move-result v5

    .line 134
    if-nez v5, :cond_3

    .line 135
    .line 136
    :cond_2
    invoke-static {v0, p1, v0, p2}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 137
    .line 138
    .line 139
    :cond_3
    sget-object p2, Lv3/j;->d:Lv3/h;

    .line 140
    .line 141
    invoke-static {p2, p0, p1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 142
    .line 143
    .line 144
    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 145
    .line 146
    .line 147
    move-result-object p0

    .line 148
    invoke-virtual {v4, v3, p1, p0}, Lt2/b;->invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 149
    .line 150
    .line 151
    invoke-virtual {p1, v9}, Ll2/t;->q(Z)V

    .line 152
    .line 153
    .line 154
    goto :goto_2

    .line 155
    :cond_4
    invoke-virtual {p1}, Ll2/t;->R()V

    .line 156
    .line 157
    .line 158
    :goto_2
    return-object v1

    .line 159
    :pswitch_0
    check-cast p1, Ll2/o;

    .line 160
    .line 161
    check-cast p2, Ljava/lang/Number;

    .line 162
    .line 163
    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    .line 164
    .line 165
    .line 166
    move-result p2

    .line 167
    and-int/lit8 v0, p2, 0x3

    .line 168
    .line 169
    if-eq v0, v8, :cond_5

    .line 170
    .line 171
    move v0, v9

    .line 172
    goto :goto_3

    .line 173
    :cond_5
    move v0, v10

    .line 174
    :goto_3
    and-int/2addr p2, v9

    .line 175
    check-cast p1, Ll2/t;

    .line 176
    .line 177
    invoke-virtual {p1, p2, v0}, Ll2/t;->O(IZ)Z

    .line 178
    .line 179
    .line 180
    move-result p2

    .line 181
    if-eqz p2, :cond_9

    .line 182
    .line 183
    sget p2, Lf2/d0;->d:F

    .line 184
    .line 185
    invoke-static {p0, v7, p2, v9}, Landroidx/compose/foundation/layout/a;->o(Lx2/s;FFI)Lx2/s;

    .line 186
    .line 187
    .line 188
    move-result-object p0

    .line 189
    sget-object p2, Lk1/r0;->d:Lk1/r0;

    .line 190
    .line 191
    invoke-static {p0}, Landroidx/compose/foundation/layout/a;->r(Lx2/s;)Lx2/s;

    .line 192
    .line 193
    .line 194
    move-result-object p0

    .line 195
    invoke-static {p0, v6, v5}, Lkp/n;->d(Lx2/s;Le1/n1;I)Lx2/s;

    .line 196
    .line 197
    .line 198
    move-result-object p0

    .line 199
    sget-object p2, Lk1/j;->c:Lk1/e;

    .line 200
    .line 201
    sget-object v0, Lx2/c;->p:Lx2/h;

    .line 202
    .line 203
    invoke-static {p2, v0, p1, v10}, Lk1/r;->a(Lk1/i;Lx2/d;Ll2/o;I)Lk1/s;

    .line 204
    .line 205
    .line 206
    move-result-object p2

    .line 207
    iget-wide v5, p1, Ll2/t;->T:J

    .line 208
    .line 209
    invoke-static {v5, v6}, Ljava/lang/Long;->hashCode(J)I

    .line 210
    .line 211
    .line 212
    move-result v0

    .line 213
    invoke-virtual {p1}, Ll2/t;->m()Ll2/p1;

    .line 214
    .line 215
    .line 216
    move-result-object v5

    .line 217
    invoke-static {p1, p0}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 218
    .line 219
    .line 220
    move-result-object p0

    .line 221
    sget-object v6, Lv3/k;->m1:Lv3/j;

    .line 222
    .line 223
    invoke-virtual {v6}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 224
    .line 225
    .line 226
    sget-object v6, Lv3/j;->b:Lv3/i;

    .line 227
    .line 228
    invoke-virtual {p1}, Ll2/t;->c0()V

    .line 229
    .line 230
    .line 231
    iget-boolean v7, p1, Ll2/t;->S:Z

    .line 232
    .line 233
    if-eqz v7, :cond_6

    .line 234
    .line 235
    invoke-virtual {p1, v6}, Ll2/t;->l(Lay0/a;)V

    .line 236
    .line 237
    .line 238
    goto :goto_4

    .line 239
    :cond_6
    invoke-virtual {p1}, Ll2/t;->m0()V

    .line 240
    .line 241
    .line 242
    :goto_4
    sget-object v6, Lv3/j;->g:Lv3/h;

    .line 243
    .line 244
    invoke-static {v6, p2, p1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 245
    .line 246
    .line 247
    sget-object p2, Lv3/j;->f:Lv3/h;

    .line 248
    .line 249
    invoke-static {p2, v5, p1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 250
    .line 251
    .line 252
    sget-object p2, Lv3/j;->j:Lv3/h;

    .line 253
    .line 254
    iget-boolean v5, p1, Ll2/t;->S:Z

    .line 255
    .line 256
    if-nez v5, :cond_7

    .line 257
    .line 258
    invoke-virtual {p1}, Ll2/t;->L()Ljava/lang/Object;

    .line 259
    .line 260
    .line 261
    move-result-object v5

    .line 262
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 263
    .line 264
    .line 265
    move-result-object v6

    .line 266
    invoke-static {v5, v6}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 267
    .line 268
    .line 269
    move-result v5

    .line 270
    if-nez v5, :cond_8

    .line 271
    .line 272
    :cond_7
    invoke-static {v0, p1, v0, p2}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 273
    .line 274
    .line 275
    :cond_8
    sget-object p2, Lv3/j;->d:Lv3/h;

    .line 276
    .line 277
    invoke-static {p2, p0, p1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 278
    .line 279
    .line 280
    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 281
    .line 282
    .line 283
    move-result-object p0

    .line 284
    invoke-virtual {v4, v3, p1, p0}, Lt2/b;->invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 285
    .line 286
    .line 287
    invoke-virtual {p1, v9}, Ll2/t;->q(Z)V

    .line 288
    .line 289
    .line 290
    goto :goto_5

    .line 291
    :cond_9
    invoke-virtual {p1}, Ll2/t;->R()V

    .line 292
    .line 293
    .line 294
    :goto_5
    return-object v1

    .line 295
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
