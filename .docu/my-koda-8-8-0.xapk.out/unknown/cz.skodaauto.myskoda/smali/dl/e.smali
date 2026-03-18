.class public final synthetic Ldl/e;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lrh/s;

.field public final synthetic f:Lay0/k;


# direct methods
.method public synthetic constructor <init>(Lrh/s;Lay0/k;I)V
    .locals 0

    .line 1
    iput p3, p0, Ldl/e;->d:I

    iput-object p1, p0, Ldl/e;->e:Lrh/s;

    iput-object p2, p0, Ldl/e;->f:Lay0/k;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Lrh/s;Lay0/k;II)V
    .locals 0

    .line 2
    iput p4, p0, Ldl/e;->d:I

    iput-object p1, p0, Ldl/e;->e:Lrh/s;

    iput-object p2, p0, Ldl/e;->f:Lay0/k;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 9

    .line 1
    iget v0, p0, Ldl/e;->d:I

    .line 2
    .line 3
    check-cast p1, Ll2/o;

    .line 4
    .line 5
    check-cast p2, Ljava/lang/Integer;

    .line 6
    .line 7
    packed-switch v0, :pswitch_data_0

    .line 8
    .line 9
    .line 10
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 11
    .line 12
    .line 13
    const/16 p2, 0x9

    .line 14
    .line 15
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 16
    .line 17
    .line 18
    move-result p2

    .line 19
    iget-object v0, p0, Ldl/e;->e:Lrh/s;

    .line 20
    .line 21
    iget-object p0, p0, Ldl/e;->f:Lay0/k;

    .line 22
    .line 23
    invoke-static {v0, p0, p1, p2}, Ldl/a;->a(Lrh/s;Lay0/k;Ll2/o;I)V

    .line 24
    .line 25
    .line 26
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 27
    .line 28
    return-object p0

    .line 29
    :pswitch_0
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 30
    .line 31
    .line 32
    move-result p2

    .line 33
    and-int/lit8 v0, p2, 0x3

    .line 34
    .line 35
    const/4 v1, 0x2

    .line 36
    const/4 v2, 0x1

    .line 37
    const/4 v3, 0x0

    .line 38
    if-eq v0, v1, :cond_0

    .line 39
    .line 40
    move v0, v2

    .line 41
    goto :goto_1

    .line 42
    :cond_0
    move v0, v3

    .line 43
    :goto_1
    and-int/2addr p2, v2

    .line 44
    check-cast p1, Ll2/t;

    .line 45
    .line 46
    invoke-virtual {p1, p2, v0}, Ll2/t;->O(IZ)Z

    .line 47
    .line 48
    .line 49
    move-result p2

    .line 50
    if-eqz p2, :cond_4

    .line 51
    .line 52
    iget-object p2, p0, Ldl/e;->e:Lrh/s;

    .line 53
    .line 54
    iget-boolean p2, p2, Lrh/s;->c:Z

    .line 55
    .line 56
    if-eqz p2, :cond_3

    .line 57
    .line 58
    const p2, -0x3f991548

    .line 59
    .line 60
    .line 61
    invoke-virtual {p1, p2}, Ll2/t;->Y(I)V

    .line 62
    .line 63
    .line 64
    iget-object p0, p0, Ldl/e;->f:Lay0/k;

    .line 65
    .line 66
    invoke-virtual {p1, p0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 67
    .line 68
    .line 69
    move-result p2

    .line 70
    invoke-virtual {p1}, Ll2/t;->L()Ljava/lang/Object;

    .line 71
    .line 72
    .line 73
    move-result-object v0

    .line 74
    if-nez p2, :cond_1

    .line 75
    .line 76
    sget-object p2, Ll2/n;->a:Ll2/x0;

    .line 77
    .line 78
    if-ne v0, p2, :cond_2

    .line 79
    .line 80
    :cond_1
    new-instance v0, Lak/n;

    .line 81
    .line 82
    const/16 p2, 0x16

    .line 83
    .line 84
    invoke-direct {v0, p2, p0}, Lak/n;-><init>(ILay0/k;)V

    .line 85
    .line 86
    .line 87
    invoke-virtual {p1, v0}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 88
    .line 89
    .line 90
    :cond_2
    check-cast v0, Lay0/a;

    .line 91
    .line 92
    sget-object p0, Ldl/a;->d:Lt2/b;

    .line 93
    .line 94
    const/16 p2, 0x30

    .line 95
    .line 96
    invoke-static {v0, p0, p1, p2}, Lzb/b;->f(Lay0/a;Lay0/n;Ll2/o;I)V

    .line 97
    .line 98
    .line 99
    :goto_2
    invoke-virtual {p1, v3}, Ll2/t;->q(Z)V

    .line 100
    .line 101
    .line 102
    goto :goto_3

    .line 103
    :cond_3
    const p0, -0x40018cd6

    .line 104
    .line 105
    .line 106
    invoke-virtual {p1, p0}, Ll2/t;->Y(I)V

    .line 107
    .line 108
    .line 109
    goto :goto_2

    .line 110
    :cond_4
    invoke-virtual {p1}, Ll2/t;->R()V

    .line 111
    .line 112
    .line 113
    :goto_3
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 114
    .line 115
    return-object p0

    .line 116
    :pswitch_1
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 117
    .line 118
    .line 119
    move-result p2

    .line 120
    and-int/lit8 v0, p2, 0x3

    .line 121
    .line 122
    const/4 v1, 0x2

    .line 123
    const/4 v2, 0x1

    .line 124
    if-eq v0, v1, :cond_5

    .line 125
    .line 126
    move v0, v2

    .line 127
    goto :goto_4

    .line 128
    :cond_5
    const/4 v0, 0x0

    .line 129
    :goto_4
    and-int/2addr p2, v2

    .line 130
    move-object v4, p1

    .line 131
    check-cast v4, Ll2/t;

    .line 132
    .line 133
    invoke-virtual {v4, p2, v0}, Ll2/t;->O(IZ)Z

    .line 134
    .line 135
    .line 136
    move-result p1

    .line 137
    if-eqz p1, :cond_6

    .line 138
    .line 139
    sget-object v2, Ldl/a;->c:Lt2/b;

    .line 140
    .line 141
    new-instance p1, Ldl/e;

    .line 142
    .line 143
    const/4 p2, 0x0

    .line 144
    iget-object v0, p0, Ldl/e;->e:Lrh/s;

    .line 145
    .line 146
    iget-object p0, p0, Ldl/e;->f:Lay0/k;

    .line 147
    .line 148
    invoke-direct {p1, v0, p0, p2}, Ldl/e;-><init>(Lrh/s;Lay0/k;I)V

    .line 149
    .line 150
    .line 151
    const p0, -0x52a6899f

    .line 152
    .line 153
    .line 154
    invoke-static {p0, v4, p1}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 155
    .line 156
    .line 157
    move-result-object v3

    .line 158
    const/16 v5, 0x1b0

    .line 159
    .line 160
    const/4 v6, 0x1

    .line 161
    const/4 v1, 0x0

    .line 162
    invoke-static/range {v1 .. v6}, Ljp/nd;->g(Lx2/s;Lt2/b;Lt2/b;Ll2/o;II)V

    .line 163
    .line 164
    .line 165
    goto :goto_5

    .line 166
    :cond_6
    invoke-virtual {v4}, Ll2/t;->R()V

    .line 167
    .line 168
    .line 169
    :goto_5
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 170
    .line 171
    return-object p0

    .line 172
    :pswitch_2
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 173
    .line 174
    .line 175
    const/16 p2, 0x9

    .line 176
    .line 177
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 178
    .line 179
    .line 180
    move-result p2

    .line 181
    iget-object v0, p0, Ldl/e;->e:Lrh/s;

    .line 182
    .line 183
    iget-object p0, p0, Ldl/e;->f:Lay0/k;

    .line 184
    .line 185
    invoke-static {v0, p0, p1, p2}, Ldl/a;->d(Lrh/s;Lay0/k;Ll2/o;I)V

    .line 186
    .line 187
    .line 188
    goto/16 :goto_0

    .line 189
    .line 190
    :pswitch_3
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 191
    .line 192
    .line 193
    move-result p2

    .line 194
    and-int/lit8 v0, p2, 0x3

    .line 195
    .line 196
    const/4 v1, 0x2

    .line 197
    const/4 v2, 0x1

    .line 198
    if-eq v0, v1, :cond_7

    .line 199
    .line 200
    move v0, v2

    .line 201
    goto :goto_6

    .line 202
    :cond_7
    const/4 v0, 0x0

    .line 203
    :goto_6
    and-int/2addr p2, v2

    .line 204
    move-object v6, p1

    .line 205
    check-cast v6, Ll2/t;

    .line 206
    .line 207
    invoke-virtual {v6, p2, v0}, Ll2/t;->O(IZ)Z

    .line 208
    .line 209
    .line 210
    move-result p1

    .line 211
    if-eqz p1, :cond_a

    .line 212
    .line 213
    const p1, 0x7f120bb6

    .line 214
    .line 215
    .line 216
    invoke-static {v6, p1}, Lzb/x;->d(Ll2/o;I)Ljava/lang/String;

    .line 217
    .line 218
    .line 219
    move-result-object v2

    .line 220
    iget-object p1, p0, Ldl/e;->e:Lrh/s;

    .line 221
    .line 222
    iget-boolean v3, p1, Lrh/s;->d:Z

    .line 223
    .line 224
    iget-object p0, p0, Ldl/e;->f:Lay0/k;

    .line 225
    .line 226
    invoke-virtual {v6, p0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 227
    .line 228
    .line 229
    move-result p1

    .line 230
    invoke-virtual {v6}, Ll2/t;->L()Ljava/lang/Object;

    .line 231
    .line 232
    .line 233
    move-result-object p2

    .line 234
    if-nez p1, :cond_8

    .line 235
    .line 236
    sget-object p1, Ll2/n;->a:Ll2/x0;

    .line 237
    .line 238
    if-ne p2, p1, :cond_9

    .line 239
    .line 240
    :cond_8
    new-instance p2, Lak/n;

    .line 241
    .line 242
    const/16 p1, 0x17

    .line 243
    .line 244
    invoke-direct {p2, p1, p0}, Lak/n;-><init>(ILay0/k;)V

    .line 245
    .line 246
    .line 247
    invoke-virtual {v6, p2}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 248
    .line 249
    .line 250
    :cond_9
    move-object v4, p2

    .line 251
    check-cast v4, Lay0/a;

    .line 252
    .line 253
    const/16 v7, 0x6006

    .line 254
    .line 255
    const/4 v8, 0x0

    .line 256
    sget-object v1, Lx2/p;->b:Lx2/p;

    .line 257
    .line 258
    const-string v5, "wallbox_onboarding_scan_cta"

    .line 259
    .line 260
    invoke-static/range {v1 .. v8}, Ljp/nd;->b(Lx2/s;Ljava/lang/String;ZLay0/a;Ljava/lang/String;Ll2/o;II)V

    .line 261
    .line 262
    .line 263
    goto :goto_7

    .line 264
    :cond_a
    invoke-virtual {v6}, Ll2/t;->R()V

    .line 265
    .line 266
    .line 267
    :goto_7
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 268
    .line 269
    return-object p0

    .line 270
    nop

    .line 271
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
