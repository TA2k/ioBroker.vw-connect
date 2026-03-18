.class public final Ltv/d;
.super Lkotlin/jvm/internal/n;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/o;


# instance fields
.field public final synthetic f:I

.field public final synthetic g:Luv/q;


# direct methods
.method public synthetic constructor <init>(Luv/q;I)V
    .locals 0

    .line 1
    iput p2, p0, Ltv/d;->f:I

    .line 2
    .line 3
    iput-object p1, p0, Ltv/d;->g:Luv/q;

    .line 4
    .line 5
    const/4 p1, 0x3

    .line 6
    invoke-direct {p0, p1}, Lkotlin/jvm/internal/n;-><init>(I)V

    .line 7
    .line 8
    .line 9
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 7

    .line 1
    iget v0, p0, Ltv/d;->f:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    move-object v1, p1

    .line 7
    check-cast v1, Lvv/m0;

    .line 8
    .line 9
    move-object v4, p2

    .line 10
    check-cast v4, Ll2/o;

    .line 11
    .line 12
    check-cast p3, Ljava/lang/Number;

    .line 13
    .line 14
    invoke-virtual {p3}, Ljava/lang/Number;->intValue()I

    .line 15
    .line 16
    .line 17
    move-result p1

    .line 18
    const-string p2, "$this$cell"

    .line 19
    .line 20
    invoke-static {v1, p2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 21
    .line 22
    .line 23
    and-int/lit8 p2, p1, 0xe

    .line 24
    .line 25
    if-nez p2, :cond_1

    .line 26
    .line 27
    move-object p2, v4

    .line 28
    check-cast p2, Ll2/t;

    .line 29
    .line 30
    invoke-virtual {p2, v1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 31
    .line 32
    .line 33
    move-result p2

    .line 34
    if-eqz p2, :cond_0

    .line 35
    .line 36
    const/4 p2, 0x4

    .line 37
    goto :goto_0

    .line 38
    :cond_0
    const/4 p2, 0x2

    .line 39
    :goto_0
    or-int/2addr p1, p2

    .line 40
    :cond_1
    and-int/lit8 p2, p1, 0x5b

    .line 41
    .line 42
    const/16 p3, 0x12

    .line 43
    .line 44
    if-ne p2, p3, :cond_3

    .line 45
    .line 46
    move-object p2, v4

    .line 47
    check-cast p2, Ll2/t;

    .line 48
    .line 49
    invoke-virtual {p2}, Ll2/t;->A()Z

    .line 50
    .line 51
    .line 52
    move-result p3

    .line 53
    if-nez p3, :cond_2

    .line 54
    .line 55
    goto :goto_1

    .line 56
    :cond_2
    invoke-virtual {p2}, Ll2/t;->R()V

    .line 57
    .line 58
    .line 59
    goto :goto_2

    .line 60
    :cond_3
    :goto_1
    and-int/lit8 v5, p1, 0xe

    .line 61
    .line 62
    const/4 v6, 0x2

    .line 63
    iget-object v2, p0, Ltv/d;->g:Luv/q;

    .line 64
    .line 65
    const/4 v3, 0x0

    .line 66
    invoke-static/range {v1 .. v6}, Llp/k0;->a(Lvv/m0;Luv/q;Lx2/s;Ll2/o;II)V

    .line 67
    .line 68
    .line 69
    :goto_2
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 70
    .line 71
    return-object p0

    .line 72
    :pswitch_0
    move-object v0, p1

    .line 73
    check-cast v0, Lvv/m0;

    .line 74
    .line 75
    move-object v3, p2

    .line 76
    check-cast v3, Ll2/o;

    .line 77
    .line 78
    check-cast p3, Ljava/lang/Number;

    .line 79
    .line 80
    invoke-virtual {p3}, Ljava/lang/Number;->intValue()I

    .line 81
    .line 82
    .line 83
    move-result p1

    .line 84
    const-string p2, "$this$cell"

    .line 85
    .line 86
    invoke-static {v0, p2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 87
    .line 88
    .line 89
    and-int/lit8 p2, p1, 0xe

    .line 90
    .line 91
    if-nez p2, :cond_5

    .line 92
    .line 93
    move-object p2, v3

    .line 94
    check-cast p2, Ll2/t;

    .line 95
    .line 96
    invoke-virtual {p2, v0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 97
    .line 98
    .line 99
    move-result p2

    .line 100
    if-eqz p2, :cond_4

    .line 101
    .line 102
    const/4 p2, 0x4

    .line 103
    goto :goto_3

    .line 104
    :cond_4
    const/4 p2, 0x2

    .line 105
    :goto_3
    or-int/2addr p1, p2

    .line 106
    :cond_5
    and-int/lit8 p2, p1, 0x5b

    .line 107
    .line 108
    const/16 p3, 0x12

    .line 109
    .line 110
    if-ne p2, p3, :cond_7

    .line 111
    .line 112
    move-object p2, v3

    .line 113
    check-cast p2, Ll2/t;

    .line 114
    .line 115
    invoke-virtual {p2}, Ll2/t;->A()Z

    .line 116
    .line 117
    .line 118
    move-result p3

    .line 119
    if-nez p3, :cond_6

    .line 120
    .line 121
    goto :goto_4

    .line 122
    :cond_6
    invoke-virtual {p2}, Ll2/t;->R()V

    .line 123
    .line 124
    .line 125
    goto :goto_5

    .line 126
    :cond_7
    :goto_4
    and-int/lit8 v4, p1, 0xe

    .line 127
    .line 128
    const/4 v5, 0x2

    .line 129
    iget-object v1, p0, Ltv/d;->g:Luv/q;

    .line 130
    .line 131
    const/4 v2, 0x0

    .line 132
    invoke-static/range {v0 .. v5}, Llp/k0;->a(Lvv/m0;Luv/q;Lx2/s;Ll2/o;II)V

    .line 133
    .line 134
    .line 135
    :goto_5
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 136
    .line 137
    return-object p0

    .line 138
    :pswitch_1
    move-object v0, p1

    .line 139
    check-cast v0, Lvv/m0;

    .line 140
    .line 141
    move-object v3, p2

    .line 142
    check-cast v3, Ll2/o;

    .line 143
    .line 144
    check-cast p3, Ljava/lang/Number;

    .line 145
    .line 146
    invoke-virtual {p3}, Ljava/lang/Number;->intValue()I

    .line 147
    .line 148
    .line 149
    move-result p1

    .line 150
    const-string p2, "$this$Heading"

    .line 151
    .line 152
    invoke-static {v0, p2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 153
    .line 154
    .line 155
    and-int/lit8 p2, p1, 0xe

    .line 156
    .line 157
    if-nez p2, :cond_9

    .line 158
    .line 159
    move-object p2, v3

    .line 160
    check-cast p2, Ll2/t;

    .line 161
    .line 162
    invoke-virtual {p2, v0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 163
    .line 164
    .line 165
    move-result p2

    .line 166
    if-eqz p2, :cond_8

    .line 167
    .line 168
    const/4 p2, 0x4

    .line 169
    goto :goto_6

    .line 170
    :cond_8
    const/4 p2, 0x2

    .line 171
    :goto_6
    or-int/2addr p1, p2

    .line 172
    :cond_9
    and-int/lit8 p2, p1, 0x5b

    .line 173
    .line 174
    const/16 p3, 0x12

    .line 175
    .line 176
    if-ne p2, p3, :cond_b

    .line 177
    .line 178
    move-object p2, v3

    .line 179
    check-cast p2, Ll2/t;

    .line 180
    .line 181
    invoke-virtual {p2}, Ll2/t;->A()Z

    .line 182
    .line 183
    .line 184
    move-result p3

    .line 185
    if-nez p3, :cond_a

    .line 186
    .line 187
    goto :goto_7

    .line 188
    :cond_a
    invoke-virtual {p2}, Ll2/t;->R()V

    .line 189
    .line 190
    .line 191
    goto :goto_8

    .line 192
    :cond_b
    :goto_7
    sget-object p2, Ltv/c;->h:Ltv/c;

    .line 193
    .line 194
    const/4 p3, 0x0

    .line 195
    sget-object v1, Lx2/p;->b:Lx2/p;

    .line 196
    .line 197
    invoke-static {v1, p3, p2}, Ld4/n;->b(Lx2/s;ZLay0/k;)Lx2/s;

    .line 198
    .line 199
    .line 200
    move-result-object v2

    .line 201
    and-int/lit8 v4, p1, 0xe

    .line 202
    .line 203
    const/4 v5, 0x0

    .line 204
    iget-object v1, p0, Ltv/d;->g:Luv/q;

    .line 205
    .line 206
    invoke-static/range {v0 .. v5}, Llp/k0;->a(Lvv/m0;Luv/q;Lx2/s;Ll2/o;II)V

    .line 207
    .line 208
    .line 209
    :goto_8
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 210
    .line 211
    return-object p0

    .line 212
    :pswitch_2
    check-cast p1, Lvv/m0;

    .line 213
    .line 214
    check-cast p2, Ll2/o;

    .line 215
    .line 216
    check-cast p3, Ljava/lang/Number;

    .line 217
    .line 218
    invoke-virtual {p3}, Ljava/lang/Number;->intValue()I

    .line 219
    .line 220
    .line 221
    move-result p3

    .line 222
    const-string v0, "$this$BlockQuote"

    .line 223
    .line 224
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 225
    .line 226
    .line 227
    and-int/lit8 v0, p3, 0xe

    .line 228
    .line 229
    if-nez v0, :cond_d

    .line 230
    .line 231
    move-object v0, p2

    .line 232
    check-cast v0, Ll2/t;

    .line 233
    .line 234
    invoke-virtual {v0, p1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 235
    .line 236
    .line 237
    move-result v0

    .line 238
    if-eqz v0, :cond_c

    .line 239
    .line 240
    const/4 v0, 0x4

    .line 241
    goto :goto_9

    .line 242
    :cond_c
    const/4 v0, 0x2

    .line 243
    :goto_9
    or-int/2addr p3, v0

    .line 244
    :cond_d
    and-int/lit8 v0, p3, 0x5b

    .line 245
    .line 246
    const/16 v1, 0x12

    .line 247
    .line 248
    if-ne v0, v1, :cond_f

    .line 249
    .line 250
    move-object v0, p2

    .line 251
    check-cast v0, Ll2/t;

    .line 252
    .line 253
    invoke-virtual {v0}, Ll2/t;->A()Z

    .line 254
    .line 255
    .line 256
    move-result v1

    .line 257
    if-nez v1, :cond_e

    .line 258
    .line 259
    goto :goto_a

    .line 260
    :cond_e
    invoke-virtual {v0}, Ll2/t;->R()V

    .line 261
    .line 262
    .line 263
    goto :goto_b

    .line 264
    :cond_f
    :goto_a
    iget-object p0, p0, Ltv/d;->g:Luv/q;

    .line 265
    .line 266
    and-int/lit8 p3, p3, 0xe

    .line 267
    .line 268
    invoke-static {p1, p0, p2, p3}, Llp/i0;->d(Lvv/m0;Luv/q;Ll2/o;I)V

    .line 269
    .line 270
    .line 271
    :goto_b
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 272
    .line 273
    return-object p0

    .line 274
    nop

    .line 275
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
