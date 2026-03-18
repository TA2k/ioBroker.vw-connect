.class public final synthetic Lal/t;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/o;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Z

.field public final synthetic f:Lay0/k;


# direct methods
.method public synthetic constructor <init>(ILay0/k;Z)V
    .locals 0

    .line 1
    iput p1, p0, Lal/t;->d:I

    .line 2
    .line 3
    iput-boolean p3, p0, Lal/t;->e:Z

    .line 4
    .line 5
    iput-object p2, p0, Lal/t;->f:Lay0/k;

    .line 6
    .line 7
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 8
    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 7

    .line 1
    iget v0, p0, Lal/t;->d:I

    .line 2
    .line 3
    check-cast p1, Lx2/s;

    .line 4
    .line 5
    check-cast p2, Ll2/o;

    .line 6
    .line 7
    check-cast p3, Ljava/lang/Integer;

    .line 8
    .line 9
    invoke-virtual {p3}, Ljava/lang/Integer;->intValue()I

    .line 10
    .line 11
    .line 12
    move-result p3

    .line 13
    packed-switch v0, :pswitch_data_0

    .line 14
    .line 15
    .line 16
    const-string v0, "modifier"

    .line 17
    .line 18
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    and-int/lit8 v0, p3, 0x6

    .line 22
    .line 23
    if-nez v0, :cond_1

    .line 24
    .line 25
    move-object v0, p2

    .line 26
    check-cast v0, Ll2/t;

    .line 27
    .line 28
    invoke-virtual {v0, p1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 29
    .line 30
    .line 31
    move-result v0

    .line 32
    if-eqz v0, :cond_0

    .line 33
    .line 34
    const/4 v0, 0x4

    .line 35
    goto :goto_0

    .line 36
    :cond_0
    const/4 v0, 0x2

    .line 37
    :goto_0
    or-int/2addr p3, v0

    .line 38
    :cond_1
    and-int/lit8 v0, p3, 0x13

    .line 39
    .line 40
    const/16 v1, 0x12

    .line 41
    .line 42
    const/4 v2, 0x0

    .line 43
    const/4 v3, 0x1

    .line 44
    if-eq v0, v1, :cond_2

    .line 45
    .line 46
    move v0, v3

    .line 47
    goto :goto_1

    .line 48
    :cond_2
    move v0, v2

    .line 49
    :goto_1
    and-int/lit8 v1, p3, 0x1

    .line 50
    .line 51
    check-cast p2, Ll2/t;

    .line 52
    .line 53
    invoke-virtual {p2, v1, v0}, Ll2/t;->O(IZ)Z

    .line 54
    .line 55
    .line 56
    move-result v0

    .line 57
    if-eqz v0, :cond_9

    .line 58
    .line 59
    iget-boolean v0, p0, Lal/t;->e:Z

    .line 60
    .line 61
    if-ne v0, v3, :cond_3

    .line 62
    .line 63
    const v1, 0x79ffe4dd

    .line 64
    .line 65
    .line 66
    const v4, 0x7f120bac

    .line 67
    .line 68
    .line 69
    :goto_2
    invoke-static {v1, v4, p2, p2, v2}, Lvj/b;->B(IILl2/t;Ll2/t;Z)Ljava/lang/String;

    .line 70
    .line 71
    .line 72
    move-result-object v1

    .line 73
    goto :goto_3

    .line 74
    :cond_3
    if-nez v0, :cond_8

    .line 75
    .line 76
    const v1, 0x79fff25d

    .line 77
    .line 78
    .line 79
    const v4, 0x7f120baa

    .line 80
    .line 81
    .line 82
    goto :goto_2

    .line 83
    :goto_3
    and-int/lit8 p3, p3, 0xe

    .line 84
    .line 85
    invoke-static {p3, v1, p2, p1}, Ljp/nd;->f(ILjava/lang/String;Ll2/o;Lx2/s;)V

    .line 86
    .line 87
    .line 88
    const/16 v1, 0x8

    .line 89
    .line 90
    int-to-float v1, v1

    .line 91
    sget-object v4, Lx2/p;->b:Lx2/p;

    .line 92
    .line 93
    invoke-static {v4, v1}, Landroidx/compose/foundation/layout/d;->e(Lx2/s;F)Lx2/s;

    .line 94
    .line 95
    .line 96
    move-result-object v1

    .line 97
    invoke-static {p2, v1}, Lk1/d;->d(Ll2/o;Lx2/s;)V

    .line 98
    .line 99
    .line 100
    if-ne v0, v3, :cond_4

    .line 101
    .line 102
    const v0, -0x2b59e07

    .line 103
    .line 104
    .line 105
    const v1, 0x7f120bad

    .line 106
    .line 107
    .line 108
    :goto_4
    invoke-static {v0, v1, p2, p2, v2}, Lvj/b;->B(IILl2/t;Ll2/t;Z)Ljava/lang/String;

    .line 109
    .line 110
    .line 111
    move-result-object v0

    .line 112
    goto :goto_5

    .line 113
    :cond_4
    if-nez v0, :cond_7

    .line 114
    .line 115
    const v0, -0x2b59107

    .line 116
    .line 117
    .line 118
    const v1, 0x7f120bab

    .line 119
    .line 120
    .line 121
    goto :goto_4

    .line 122
    :goto_5
    invoke-static {p3, v0, p2, p1}, Ljp/nd;->c(ILjava/lang/String;Ll2/o;Lx2/s;)V

    .line 123
    .line 124
    .line 125
    const/16 v0, 0x20

    .line 126
    .line 127
    int-to-float v0, v0

    .line 128
    invoke-static {v4, v0}, Landroidx/compose/foundation/layout/d;->e(Lx2/s;F)Lx2/s;

    .line 129
    .line 130
    .line 131
    move-result-object v0

    .line 132
    invoke-static {p2, v0}, Lk1/d;->d(Ll2/o;Lx2/s;)V

    .line 133
    .line 134
    .line 135
    iget-object p0, p0, Lal/t;->f:Lay0/k;

    .line 136
    .line 137
    invoke-virtual {p2, p0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 138
    .line 139
    .line 140
    move-result v0

    .line 141
    invoke-virtual {p2}, Ll2/t;->L()Ljava/lang/Object;

    .line 142
    .line 143
    .line 144
    move-result-object v1

    .line 145
    if-nez v0, :cond_5

    .line 146
    .line 147
    sget-object v0, Ll2/n;->a:Ll2/x0;

    .line 148
    .line 149
    if-ne v1, v0, :cond_6

    .line 150
    .line 151
    :cond_5
    new-instance v1, Lak/n;

    .line 152
    .line 153
    const/16 v0, 0xa

    .line 154
    .line 155
    invoke-direct {v1, v0, p0}, Lak/n;-><init>(ILay0/k;)V

    .line 156
    .line 157
    .line 158
    invoke-virtual {p2, v1}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 159
    .line 160
    .line 161
    :cond_6
    check-cast v1, Lay0/a;

    .line 162
    .line 163
    invoke-static {p3, v1, p2, p1}, Lbl/a;->a(ILay0/a;Ll2/o;Lx2/s;)V

    .line 164
    .line 165
    .line 166
    goto :goto_6

    .line 167
    :cond_7
    const p0, -0x2b5aa35

    .line 168
    .line 169
    .line 170
    invoke-static {p0, p2, v2}, Lf2/m0;->b(ILl2/t;Z)La8/r0;

    .line 171
    .line 172
    .line 173
    move-result-object p0

    .line 174
    throw p0

    .line 175
    :cond_8
    const p0, 0x79ffd837

    .line 176
    .line 177
    .line 178
    invoke-static {p0, p2, v2}, Lf2/m0;->b(ILl2/t;Z)La8/r0;

    .line 179
    .line 180
    .line 181
    move-result-object p0

    .line 182
    throw p0

    .line 183
    :cond_9
    invoke-virtual {p2}, Ll2/t;->R()V

    .line 184
    .line 185
    .line 186
    :goto_6
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 187
    .line 188
    return-object p0

    .line 189
    :pswitch_0
    const-string v0, "modifier"

    .line 190
    .line 191
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 192
    .line 193
    .line 194
    and-int/lit8 v0, p3, 0x6

    .line 195
    .line 196
    if-nez v0, :cond_b

    .line 197
    .line 198
    move-object v0, p2

    .line 199
    check-cast v0, Ll2/t;

    .line 200
    .line 201
    invoke-virtual {v0, p1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 202
    .line 203
    .line 204
    move-result v0

    .line 205
    if-eqz v0, :cond_a

    .line 206
    .line 207
    const/4 v0, 0x4

    .line 208
    goto :goto_7

    .line 209
    :cond_a
    const/4 v0, 0x2

    .line 210
    :goto_7
    or-int/2addr p3, v0

    .line 211
    :cond_b
    and-int/lit8 v0, p3, 0x13

    .line 212
    .line 213
    const/16 v1, 0x12

    .line 214
    .line 215
    const/4 v2, 0x1

    .line 216
    if-eq v0, v1, :cond_c

    .line 217
    .line 218
    move v0, v2

    .line 219
    goto :goto_8

    .line 220
    :cond_c
    const/4 v0, 0x0

    .line 221
    :goto_8
    and-int/2addr p3, v2

    .line 222
    move-object v4, p2

    .line 223
    check-cast v4, Ll2/t;

    .line 224
    .line 225
    invoke-virtual {v4, p3, v0}, Ll2/t;->O(IZ)Z

    .line 226
    .line 227
    .line 228
    move-result p2

    .line 229
    if-eqz p2, :cond_d

    .line 230
    .line 231
    new-instance p2, Lal/r;

    .line 232
    .line 233
    iget-boolean p3, p0, Lal/t;->e:Z

    .line 234
    .line 235
    iget-object p0, p0, Lal/t;->f:Lay0/k;

    .line 236
    .line 237
    invoke-direct {p2, p3, p1, p0}, Lal/r;-><init>(ZLx2/s;Lay0/k;)V

    .line 238
    .line 239
    .line 240
    const v0, -0x6d43b357

    .line 241
    .line 242
    .line 243
    invoke-static {v0, v4, p2}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 244
    .line 245
    .line 246
    move-result-object v2

    .line 247
    new-instance p2, Lal/r;

    .line 248
    .line 249
    invoke-direct {p2, p1, p3, p0}, Lal/r;-><init>(Lx2/s;ZLay0/k;)V

    .line 250
    .line 251
    .line 252
    const p0, 0x23155448

    .line 253
    .line 254
    .line 255
    invoke-static {p0, v4, p2}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 256
    .line 257
    .line 258
    move-result-object v3

    .line 259
    const/16 v5, 0x1b0

    .line 260
    .line 261
    const/4 v6, 0x1

    .line 262
    const/4 v1, 0x0

    .line 263
    invoke-static/range {v1 .. v6}, Ljp/nd;->g(Lx2/s;Lt2/b;Lt2/b;Ll2/o;II)V

    .line 264
    .line 265
    .line 266
    goto :goto_9

    .line 267
    :cond_d
    invoke-virtual {v4}, Ll2/t;->R()V

    .line 268
    .line 269
    .line 270
    :goto_9
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 271
    .line 272
    return-object p0

    .line 273
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
