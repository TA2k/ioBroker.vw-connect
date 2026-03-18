.class public final synthetic Lbl/f;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Z

.field public final synthetic f:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Lh2/ra;Z)V
    .locals 1

    .line 1
    const/4 v0, 0x3

    iput v0, p0, Lbl/f;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lbl/f;->f:Ljava/lang/Object;

    iput-boolean p2, p0, Lbl/f;->e:Z

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/Object;ZII)V
    .locals 0

    .line 2
    iput p4, p0, Lbl/f;->d:I

    iput-object p1, p0, Lbl/f;->f:Ljava/lang/Object;

    iput-boolean p2, p0, Lbl/f;->e:Z

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(ZLjava/lang/Object;II)V
    .locals 0

    .line 3
    iput p4, p0, Lbl/f;->d:I

    iput-boolean p1, p0, Lbl/f;->e:Z

    iput-object p2, p0, Lbl/f;->f:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 3

    .line 1
    iget v0, p0, Lbl/f;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lbl/f;->f:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast v0, Lkd/c;

    .line 9
    .line 10
    check-cast p1, Ll2/o;

    .line 11
    .line 12
    check-cast p2, Ljava/lang/Integer;

    .line 13
    .line 14
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 15
    .line 16
    .line 17
    const/4 p2, 0x1

    .line 18
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 19
    .line 20
    .line 21
    move-result p2

    .line 22
    iget-boolean p0, p0, Lbl/f;->e:Z

    .line 23
    .line 24
    invoke-static {p0, v0, p1, p2}, Lyj/f;->f(ZLkd/c;Ll2/o;I)V

    .line 25
    .line 26
    .line 27
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 28
    .line 29
    return-object p0

    .line 30
    :pswitch_0
    iget-object v0, p0, Lbl/f;->f:Ljava/lang/Object;

    .line 31
    .line 32
    check-cast v0, Luj/b0;

    .line 33
    .line 34
    check-cast p1, Ll2/o;

    .line 35
    .line 36
    check-cast p2, Ljava/lang/Integer;

    .line 37
    .line 38
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 39
    .line 40
    .line 41
    const/4 p2, 0x1

    .line 42
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 43
    .line 44
    .line 45
    move-result p2

    .line 46
    iget-boolean p0, p0, Lbl/f;->e:Z

    .line 47
    .line 48
    invoke-virtual {v0, p0, p1, p2}, Luj/b0;->v0(ZLl2/o;I)V

    .line 49
    .line 50
    .line 51
    goto :goto_0

    .line 52
    :pswitch_1
    iget-object v0, p0, Lbl/f;->f:Ljava/lang/Object;

    .line 53
    .line 54
    check-cast v0, Luj/e;

    .line 55
    .line 56
    check-cast p1, Ll2/o;

    .line 57
    .line 58
    check-cast p2, Ljava/lang/Integer;

    .line 59
    .line 60
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 61
    .line 62
    .line 63
    const/4 p2, 0x1

    .line 64
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 65
    .line 66
    .line 67
    move-result p2

    .line 68
    iget-boolean p0, p0, Lbl/f;->e:Z

    .line 69
    .line 70
    invoke-virtual {v0, p0, p1, p2}, Luj/e;->v0(ZLl2/o;I)V

    .line 71
    .line 72
    .line 73
    goto :goto_0

    .line 74
    :pswitch_2
    iget-object v0, p0, Lbl/f;->f:Ljava/lang/Object;

    .line 75
    .line 76
    check-cast v0, Le2/w0;

    .line 77
    .line 78
    check-cast p1, Ll2/o;

    .line 79
    .line 80
    check-cast p2, Ljava/lang/Integer;

    .line 81
    .line 82
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 83
    .line 84
    .line 85
    const/4 p2, 0x1

    .line 86
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 87
    .line 88
    .line 89
    move-result p2

    .line 90
    iget-boolean p0, p0, Lbl/f;->e:Z

    .line 91
    .line 92
    invoke-static {v0, p0, p1, p2}, Lt1/l0;->j(Le2/w0;ZLl2/o;I)V

    .line 93
    .line 94
    .line 95
    goto :goto_0

    .line 96
    :pswitch_3
    iget-object v0, p0, Lbl/f;->f:Ljava/lang/Object;

    .line 97
    .line 98
    check-cast v0, Lm70/x0;

    .line 99
    .line 100
    check-cast p1, Ll2/o;

    .line 101
    .line 102
    check-cast p2, Ljava/lang/Integer;

    .line 103
    .line 104
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 105
    .line 106
    .line 107
    const/4 p2, 0x1

    .line 108
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 109
    .line 110
    .line 111
    move-result p2

    .line 112
    iget-boolean p0, p0, Lbl/f;->e:Z

    .line 113
    .line 114
    invoke-static {v0, p0, p1, p2}, Ln70/a;->g(Lm70/x0;ZLl2/o;I)V

    .line 115
    .line 116
    .line 117
    goto :goto_0

    .line 118
    :pswitch_4
    iget-object v0, p0, Lbl/f;->f:Ljava/lang/Object;

    .line 119
    .line 120
    check-cast v0, Lh2/ra;

    .line 121
    .line 122
    check-cast p1, Lt4/l;

    .line 123
    .line 124
    check-cast p2, Lt4/a;

    .line 125
    .line 126
    new-instance p2, Lc2/k;

    .line 127
    .line 128
    const/4 v1, 0x6

    .line 129
    invoke-direct {p2, v1}, Lc2/k;-><init>(I)V

    .line 130
    .line 131
    .line 132
    iget-wide v1, p1, Lt4/l;->a:J

    .line 133
    .line 134
    const/16 p1, 0x20

    .line 135
    .line 136
    shr-long/2addr v1, p1

    .line 137
    long-to-int p1, v1

    .line 138
    int-to-float p1, p1

    .line 139
    sget-object v1, Lh2/sa;->f:Lh2/sa;

    .line 140
    .line 141
    const/4 v2, 0x0

    .line 142
    invoke-virtual {p2, v1, v2}, Lc2/k;->o(Lh2/sa;F)V

    .line 143
    .line 144
    .line 145
    iget-boolean p0, p0, Lbl/f;->e:Z

    .line 146
    .line 147
    if-eqz p0, :cond_0

    .line 148
    .line 149
    sget-object p0, Lh2/sa;->d:Lh2/sa;

    .line 150
    .line 151
    invoke-virtual {p2, p0, p1}, Lc2/k;->o(Lh2/sa;F)V

    .line 152
    .line 153
    .line 154
    :cond_0
    sget-object p0, Lh2/sa;->e:Lh2/sa;

    .line 155
    .line 156
    neg-float p1, p1

    .line 157
    invoke-virtual {p2, p0, p1}, Lc2/k;->o(Lh2/sa;F)V

    .line 158
    .line 159
    .line 160
    new-instance p0, Lg1/z;

    .line 161
    .line 162
    iget-object p1, p2, Lc2/k;->e:Ljava/lang/Object;

    .line 163
    .line 164
    check-cast p1, Ljava/util/ArrayList;

    .line 165
    .line 166
    iget-object p2, p2, Lc2/k;->f:Ljava/lang/Object;

    .line 167
    .line 168
    check-cast p2, [F

    .line 169
    .line 170
    invoke-virtual {p1}, Ljava/util/ArrayList;->size()I

    .line 171
    .line 172
    .line 173
    move-result v1

    .line 174
    const-string v2, "<this>"

    .line 175
    .line 176
    invoke-static {p2, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 177
    .line 178
    .line 179
    array-length v2, p2

    .line 180
    invoke-static {v1, v2}, Lmx0/n;->p(II)V

    .line 181
    .line 182
    .line 183
    const/4 v2, 0x0

    .line 184
    invoke-static {p2, v2, v1}, Ljava/util/Arrays;->copyOfRange([FII)[F

    .line 185
    .line 186
    .line 187
    move-result-object p2

    .line 188
    const-string v1, "copyOfRange(...)"

    .line 189
    .line 190
    invoke-static {p2, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 191
    .line 192
    .line 193
    invoke-direct {p0, p1, p2}, Lg1/z;-><init>(Ljava/util/List;[F)V

    .line 194
    .line 195
    .line 196
    iget-object p1, v0, Lh2/ra;->a:Lg1/q;

    .line 197
    .line 198
    iget-object p1, p1, Lg1/q;->h:Ljava/lang/Object;

    .line 199
    .line 200
    check-cast p1, Ll2/h0;

    .line 201
    .line 202
    invoke-virtual {p1}, Ll2/h0;->getValue()Ljava/lang/Object;

    .line 203
    .line 204
    .line 205
    move-result-object p1

    .line 206
    check-cast p1, Lh2/sa;

    .line 207
    .line 208
    new-instance p2, Llx0/l;

    .line 209
    .line 210
    invoke-direct {p2, p0, p1}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 211
    .line 212
    .line 213
    return-object p2

    .line 214
    :pswitch_5
    iget-object v0, p0, Lbl/f;->f:Ljava/lang/Object;

    .line 215
    .line 216
    check-cast v0, Lba0/a;

    .line 217
    .line 218
    check-cast p1, Ll2/o;

    .line 219
    .line 220
    check-cast p2, Ljava/lang/Integer;

    .line 221
    .line 222
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 223
    .line 224
    .line 225
    const/4 p2, 0x1

    .line 226
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 227
    .line 228
    .line 229
    move-result p2

    .line 230
    iget-boolean p0, p0, Lbl/f;->e:Z

    .line 231
    .line 232
    invoke-static {v0, p0, p1, p2}, Lca0/b;->d(Lba0/a;ZLl2/o;I)V

    .line 233
    .line 234
    .line 235
    goto/16 :goto_0

    .line 236
    .line 237
    :pswitch_6
    iget-object v0, p0, Lbl/f;->f:Ljava/lang/Object;

    .line 238
    .line 239
    check-cast v0, Lp31/c;

    .line 240
    .line 241
    check-cast p1, Ll2/o;

    .line 242
    .line 243
    check-cast p2, Ljava/lang/Integer;

    .line 244
    .line 245
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 246
    .line 247
    .line 248
    const/4 p2, 0x1

    .line 249
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 250
    .line 251
    .line 252
    move-result p2

    .line 253
    iget-boolean p0, p0, Lbl/f;->e:Z

    .line 254
    .line 255
    invoke-static {v0, p0, p1, p2}, Ljp/xc;->b(Lp31/c;ZLl2/o;I)V

    .line 256
    .line 257
    .line 258
    goto/16 :goto_0

    .line 259
    .line 260
    :pswitch_7
    iget-object v0, p0, Lbl/f;->f:Ljava/lang/Object;

    .line 261
    .line 262
    check-cast v0, Lay0/k;

    .line 263
    .line 264
    check-cast p1, Ll2/o;

    .line 265
    .line 266
    check-cast p2, Ljava/lang/Integer;

    .line 267
    .line 268
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 269
    .line 270
    .line 271
    const/4 p2, 0x1

    .line 272
    invoke-static {p2}, Ll2/b;->x(I)I

    .line 273
    .line 274
    .line 275
    move-result p2

    .line 276
    iget-boolean p0, p0, Lbl/f;->e:Z

    .line 277
    .line 278
    invoke-static {p0, v0, p1, p2}, Lbl/a;->e(ZLay0/k;Ll2/o;I)V

    .line 279
    .line 280
    .line 281
    goto/16 :goto_0

    .line 282
    .line 283
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
