.class public final synthetic Lbl/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/o;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lnh/r;

.field public final synthetic f:Lay0/k;


# direct methods
.method public synthetic constructor <init>(Lnh/r;Lay0/k;I)V
    .locals 0

    .line 1
    iput p3, p0, Lbl/b;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lbl/b;->e:Lnh/r;

    .line 4
    .line 5
    iput-object p2, p0, Lbl/b;->f:Lay0/k;

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
    iget v0, p0, Lbl/b;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    move-object v1, p1

    .line 7
    check-cast v1, Lx2/s;

    .line 8
    .line 9
    check-cast p2, Ll2/o;

    .line 10
    .line 11
    check-cast p3, Ljava/lang/Integer;

    .line 12
    .line 13
    invoke-virtual {p3}, Ljava/lang/Integer;->intValue()I

    .line 14
    .line 15
    .line 16
    move-result p1

    .line 17
    const-string p3, "buttonAreaModifier"

    .line 18
    .line 19
    invoke-static {v1, p3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 20
    .line 21
    .line 22
    and-int/lit8 p3, p1, 0x6

    .line 23
    .line 24
    if-nez p3, :cond_1

    .line 25
    .line 26
    move-object p3, p2

    .line 27
    check-cast p3, Ll2/t;

    .line 28
    .line 29
    invoke-virtual {p3, v1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 30
    .line 31
    .line 32
    move-result p3

    .line 33
    if-eqz p3, :cond_0

    .line 34
    .line 35
    const/4 p3, 0x4

    .line 36
    goto :goto_0

    .line 37
    :cond_0
    const/4 p3, 0x2

    .line 38
    :goto_0
    or-int/2addr p1, p3

    .line 39
    :cond_1
    and-int/lit8 p3, p1, 0x13

    .line 40
    .line 41
    const/16 v0, 0x12

    .line 42
    .line 43
    if-eq p3, v0, :cond_2

    .line 44
    .line 45
    const/4 p3, 0x1

    .line 46
    goto :goto_1

    .line 47
    :cond_2
    const/4 p3, 0x0

    .line 48
    :goto_1
    and-int/lit8 v0, p1, 0x1

    .line 49
    .line 50
    move-object v4, p2

    .line 51
    check-cast v4, Ll2/t;

    .line 52
    .line 53
    invoke-virtual {v4, v0, p3}, Ll2/t;->O(IZ)Z

    .line 54
    .line 55
    .line 56
    move-result p2

    .line 57
    if-eqz p2, :cond_3

    .line 58
    .line 59
    sget-object p2, Lw3/h1;->i:Ll2/u2;

    .line 60
    .line 61
    invoke-virtual {v4, p2}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 62
    .line 63
    .line 64
    move-result-object p2

    .line 65
    check-cast p2, Lc3/j;

    .line 66
    .line 67
    sget-object v2, Lbl/a;->a:Lt2/b;

    .line 68
    .line 69
    new-instance p3, Laa/w;

    .line 70
    .line 71
    const/4 v0, 0x7

    .line 72
    iget-object v3, p0, Lbl/b;->e:Lnh/r;

    .line 73
    .line 74
    iget-object p0, p0, Lbl/b;->f:Lay0/k;

    .line 75
    .line 76
    invoke-direct {p3, v3, p2, p0, v0}, Laa/w;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 77
    .line 78
    .line 79
    const p0, 0x6150c24c

    .line 80
    .line 81
    .line 82
    invoke-static {p0, v4, p3}, Lt2/c;->f(ILl2/o;Llx0/e;)Lt2/b;

    .line 83
    .line 84
    .line 85
    move-result-object v3

    .line 86
    and-int/lit8 p0, p1, 0xe

    .line 87
    .line 88
    or-int/lit16 v5, p0, 0x1b0

    .line 89
    .line 90
    const/4 v6, 0x0

    .line 91
    invoke-static/range {v1 .. v6}, Ljp/nd;->g(Lx2/s;Lt2/b;Lt2/b;Ll2/o;II)V

    .line 92
    .line 93
    .line 94
    goto :goto_2

    .line 95
    :cond_3
    invoke-virtual {v4}, Ll2/t;->R()V

    .line 96
    .line 97
    .line 98
    :goto_2
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 99
    .line 100
    return-object p0

    .line 101
    :pswitch_0
    move-object v0, p1

    .line 102
    check-cast v0, Lx2/s;

    .line 103
    .line 104
    check-cast p2, Ll2/o;

    .line 105
    .line 106
    check-cast p3, Ljava/lang/Integer;

    .line 107
    .line 108
    invoke-virtual {p3}, Ljava/lang/Integer;->intValue()I

    .line 109
    .line 110
    .line 111
    move-result p1

    .line 112
    const-string p3, "modifier"

    .line 113
    .line 114
    invoke-static {v0, p3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 115
    .line 116
    .line 117
    and-int/lit8 p3, p1, 0x6

    .line 118
    .line 119
    if-nez p3, :cond_5

    .line 120
    .line 121
    move-object p3, p2

    .line 122
    check-cast p3, Ll2/t;

    .line 123
    .line 124
    invoke-virtual {p3, v0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 125
    .line 126
    .line 127
    move-result p3

    .line 128
    if-eqz p3, :cond_4

    .line 129
    .line 130
    const/4 p3, 0x4

    .line 131
    goto :goto_3

    .line 132
    :cond_4
    const/4 p3, 0x2

    .line 133
    :goto_3
    or-int/2addr p1, p3

    .line 134
    :cond_5
    and-int/lit8 p3, p1, 0x13

    .line 135
    .line 136
    const/16 v1, 0x12

    .line 137
    .line 138
    if-eq p3, v1, :cond_6

    .line 139
    .line 140
    const/4 p3, 0x1

    .line 141
    goto :goto_4

    .line 142
    :cond_6
    const/4 p3, 0x0

    .line 143
    :goto_4
    and-int/lit8 v1, p1, 0x1

    .line 144
    .line 145
    move-object v4, p2

    .line 146
    check-cast v4, Ll2/t;

    .line 147
    .line 148
    invoke-virtual {v4, v1, p3}, Ll2/t;->O(IZ)Z

    .line 149
    .line 150
    .line 151
    move-result p2

    .line 152
    if-eqz p2, :cond_9

    .line 153
    .line 154
    const p2, 0x7f120ba0

    .line 155
    .line 156
    .line 157
    invoke-static {v4, p2}, Lzb/x;->d(Ll2/o;I)Ljava/lang/String;

    .line 158
    .line 159
    .line 160
    move-result-object p2

    .line 161
    and-int/lit8 v5, p1, 0xe

    .line 162
    .line 163
    invoke-static {v5, p2, v4, v0}, Ljp/nd;->f(ILjava/lang/String;Ll2/o;Lx2/s;)V

    .line 164
    .line 165
    .line 166
    const/16 p1, 0x8

    .line 167
    .line 168
    int-to-float p1, p1

    .line 169
    sget-object p2, Lx2/p;->b:Lx2/p;

    .line 170
    .line 171
    invoke-static {p2, p1}, Landroidx/compose/foundation/layout/d;->e(Lx2/s;F)Lx2/s;

    .line 172
    .line 173
    .line 174
    move-result-object p1

    .line 175
    invoke-static {v4, p1}, Lk1/d;->d(Ll2/o;Lx2/s;)V

    .line 176
    .line 177
    .line 178
    const p1, 0x7f120bce

    .line 179
    .line 180
    .line 181
    invoke-static {v4, p1}, Lzb/x;->d(Ll2/o;I)Ljava/lang/String;

    .line 182
    .line 183
    .line 184
    move-result-object p1

    .line 185
    invoke-static {v5, p1, v4, v0}, Ljp/nd;->c(ILjava/lang/String;Ll2/o;Lx2/s;)V

    .line 186
    .line 187
    .line 188
    const/16 p1, 0x20

    .line 189
    .line 190
    int-to-float p1, p1

    .line 191
    invoke-static {p2, p1}, Landroidx/compose/foundation/layout/d;->e(Lx2/s;F)Lx2/s;

    .line 192
    .line 193
    .line 194
    move-result-object p1

    .line 195
    invoke-static {v4, p1}, Lk1/d;->d(Ll2/o;Lx2/s;)V

    .line 196
    .line 197
    .line 198
    iget-object p1, p0, Lbl/b;->e:Lnh/r;

    .line 199
    .line 200
    iget-object v1, p1, Lnh/r;->a:Ljava/lang/String;

    .line 201
    .line 202
    iget-boolean v2, p1, Lnh/r;->d:Z

    .line 203
    .line 204
    iget-object p0, p0, Lbl/b;->f:Lay0/k;

    .line 205
    .line 206
    invoke-virtual {v4, p0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 207
    .line 208
    .line 209
    move-result p1

    .line 210
    invoke-virtual {v4}, Ll2/t;->L()Ljava/lang/Object;

    .line 211
    .line 212
    .line 213
    move-result-object p2

    .line 214
    if-nez p1, :cond_7

    .line 215
    .line 216
    sget-object p1, Ll2/n;->a:Ll2/x0;

    .line 217
    .line 218
    if-ne p2, p1, :cond_8

    .line 219
    .line 220
    :cond_7
    new-instance p2, Laa/c0;

    .line 221
    .line 222
    const/4 p1, 0x7

    .line 223
    invoke-direct {p2, p1, p0}, Laa/c0;-><init>(ILay0/k;)V

    .line 224
    .line 225
    .line 226
    invoke-virtual {v4, p2}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 227
    .line 228
    .line 229
    :cond_8
    move-object v3, p2

    .line 230
    check-cast v3, Lay0/k;

    .line 231
    .line 232
    invoke-static/range {v0 .. v5}, Lbl/a;->c(Lx2/s;Ljava/lang/String;ZLay0/k;Ll2/o;I)V

    .line 233
    .line 234
    .line 235
    goto :goto_5

    .line 236
    :cond_9
    invoke-virtual {v4}, Ll2/t;->R()V

    .line 237
    .line 238
    .line 239
    :goto_5
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 240
    .line 241
    return-object p0

    .line 242
    nop

    .line 243
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
