.class public final synthetic Leh/i;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/p;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ll2/b1;

.field public final synthetic f:Lyj/b;


# direct methods
.method public synthetic constructor <init>(Ll2/b1;Lyj/b;I)V
    .locals 0

    .line 1
    iput p3, p0, Leh/i;->d:I

    iput-object p1, p0, Leh/i;->e:Ll2/b1;

    iput-object p2, p0, Leh/i;->f:Lyj/b;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Lyj/b;Ll2/b1;)V
    .locals 1

    .line 2
    const/4 v0, 0x4

    iput v0, p0, Leh/i;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Leh/i;->f:Lyj/b;

    iput-object p2, p0, Leh/i;->e:Ll2/b1;

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 6

    .line 1
    iget v0, p0, Leh/i;->d:I

    .line 2
    .line 3
    check-cast p1, Lb1/n;

    .line 4
    .line 5
    check-cast p2, Lz9/k;

    .line 6
    .line 7
    packed-switch v0, :pswitch_data_0

    .line 8
    .line 9
    .line 10
    move-object v4, p3

    .line 11
    check-cast v4, Ll2/o;

    .line 12
    .line 13
    check-cast p4, Ljava/lang/Integer;

    .line 14
    .line 15
    const-string p3, "$this$composable"

    .line 16
    .line 17
    const-string v0, "it"

    .line 18
    .line 19
    invoke-static {p4, p1, p3, p2, v0}, Lz9/c;->c(Ljava/lang/Integer;Lb1/n;Ljava/lang/String;Lz9/k;Ljava/lang/String;)V

    .line 20
    .line 21
    .line 22
    iget-object p1, p0, Leh/i;->e:Ll2/b1;

    .line 23
    .line 24
    invoke-interface {p1}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 25
    .line 26
    .line 27
    move-result-object p2

    .line 28
    check-cast p2, Ljd/a;

    .line 29
    .line 30
    iget-object v1, p2, Ljd/a;->a:Ljava/util/List;

    .line 31
    .line 32
    invoke-interface {p1}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 33
    .line 34
    .line 35
    move-result-object p2

    .line 36
    check-cast p2, Ljd/a;

    .line 37
    .line 38
    iget-object v2, p2, Ljd/a;->b:Lgz0/p;

    .line 39
    .line 40
    invoke-interface {p1}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 41
    .line 42
    .line 43
    move-result-object p1

    .line 44
    check-cast p1, Ljd/a;

    .line 45
    .line 46
    iget-object v3, p1, Ljd/a;->c:Lgz0/p;

    .line 47
    .line 48
    const/4 v5, 0x0

    .line 49
    iget-object v0, p0, Leh/i;->f:Lyj/b;

    .line 50
    .line 51
    invoke-static/range {v0 .. v5}, Llp/wb;->a(Lyj/b;Ljava/util/List;Lgz0/p;Lgz0/p;Ll2/o;I)V

    .line 52
    .line 53
    .line 54
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 55
    .line 56
    return-object p0

    .line 57
    :pswitch_0
    check-cast p3, Ll2/o;

    .line 58
    .line 59
    check-cast p4, Ljava/lang/Integer;

    .line 60
    .line 61
    invoke-virtual {p4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 62
    .line 63
    .line 64
    const-string p4, "$this$composable"

    .line 65
    .line 66
    invoke-static {p1, p4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 67
    .line 68
    .line 69
    const-string p1, "it"

    .line 70
    .line 71
    invoke-static {p2, p1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 72
    .line 73
    .line 74
    iget-object p1, p0, Leh/i;->e:Ll2/b1;

    .line 75
    .line 76
    invoke-interface {p1}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 77
    .line 78
    .line 79
    move-result-object p1

    .line 80
    check-cast p1, Ljava/lang/String;

    .line 81
    .line 82
    sget-object p2, Llx0/b0;->a:Llx0/b0;

    .line 83
    .line 84
    const/4 p4, 0x0

    .line 85
    check-cast p3, Ll2/t;

    .line 86
    .line 87
    if-nez p1, :cond_0

    .line 88
    .line 89
    const p1, -0x3ceb5324

    .line 90
    .line 91
    .line 92
    invoke-virtual {p3, p1}, Ll2/t;->Y(I)V

    .line 93
    .line 94
    .line 95
    invoke-virtual {p3, p4}, Ll2/t;->q(Z)V

    .line 96
    .line 97
    .line 98
    const/4 p1, 0x0

    .line 99
    goto :goto_0

    .line 100
    :cond_0
    const v0, -0x3ceb5323

    .line 101
    .line 102
    .line 103
    invoke-virtual {p3, v0}, Ll2/t;->Y(I)V

    .line 104
    .line 105
    .line 106
    invoke-static {p1, p3, p4}, Llp/ld;->b(Ljava/lang/String;Ll2/o;I)V

    .line 107
    .line 108
    .line 109
    invoke-virtual {p3, p4}, Ll2/t;->q(Z)V

    .line 110
    .line 111
    .line 112
    move-object p1, p2

    .line 113
    :goto_0
    if-nez p1, :cond_1

    .line 114
    .line 115
    iget-object p0, p0, Leh/i;->f:Lyj/b;

    .line 116
    .line 117
    invoke-virtual {p0}, Lyj/b;->invoke()Ljava/lang/Object;

    .line 118
    .line 119
    .line 120
    :cond_1
    return-object p2

    .line 121
    :pswitch_1
    check-cast p3, Ll2/o;

    .line 122
    .line 123
    check-cast p4, Ljava/lang/Integer;

    .line 124
    .line 125
    invoke-virtual {p4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 126
    .line 127
    .line 128
    const-string p4, "$this$composable"

    .line 129
    .line 130
    invoke-static {p1, p4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 131
    .line 132
    .line 133
    const-string p1, "it"

    .line 134
    .line 135
    invoke-static {p2, p1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 136
    .line 137
    .line 138
    iget-object p1, p0, Leh/i;->e:Ll2/b1;

    .line 139
    .line 140
    invoke-interface {p1}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 141
    .line 142
    .line 143
    move-result-object p1

    .line 144
    check-cast p1, Ldi/a;

    .line 145
    .line 146
    sget-object p2, Llx0/b0;->a:Llx0/b0;

    .line 147
    .line 148
    const/4 p4, 0x0

    .line 149
    check-cast p3, Ll2/t;

    .line 150
    .line 151
    if-nez p1, :cond_2

    .line 152
    .line 153
    const p1, 0xe5e977

    .line 154
    .line 155
    .line 156
    invoke-virtual {p3, p1}, Ll2/t;->Y(I)V

    .line 157
    .line 158
    .line 159
    invoke-virtual {p3, p4}, Ll2/t;->q(Z)V

    .line 160
    .line 161
    .line 162
    const/4 p1, 0x0

    .line 163
    goto :goto_1

    .line 164
    :cond_2
    const v0, 0xe5e978

    .line 165
    .line 166
    .line 167
    invoke-virtual {p3, v0}, Ll2/t;->Y(I)V

    .line 168
    .line 169
    .line 170
    invoke-static {p1, p3, p4}, Lkp/z7;->b(Ldi/a;Ll2/o;I)V

    .line 171
    .line 172
    .line 173
    invoke-virtual {p3, p4}, Ll2/t;->q(Z)V

    .line 174
    .line 175
    .line 176
    move-object p1, p2

    .line 177
    :goto_1
    if-nez p1, :cond_3

    .line 178
    .line 179
    iget-object p0, p0, Leh/i;->f:Lyj/b;

    .line 180
    .line 181
    invoke-virtual {p0}, Lyj/b;->invoke()Ljava/lang/Object;

    .line 182
    .line 183
    .line 184
    :cond_3
    return-object p2

    .line 185
    :pswitch_2
    check-cast p3, Ll2/o;

    .line 186
    .line 187
    check-cast p4, Ljava/lang/Integer;

    .line 188
    .line 189
    invoke-virtual {p4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 190
    .line 191
    .line 192
    const-string p4, "$this$composable"

    .line 193
    .line 194
    invoke-static {p1, p4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 195
    .line 196
    .line 197
    const-string p1, "it"

    .line 198
    .line 199
    invoke-static {p2, p1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 200
    .line 201
    .line 202
    iget-object p1, p0, Leh/i;->e:Ll2/b1;

    .line 203
    .line 204
    invoke-interface {p1}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 205
    .line 206
    .line 207
    move-result-object p1

    .line 208
    check-cast p1, Ldi/b;

    .line 209
    .line 210
    sget-object p2, Llx0/b0;->a:Llx0/b0;

    .line 211
    .line 212
    const/4 p4, 0x0

    .line 213
    check-cast p3, Ll2/t;

    .line 214
    .line 215
    if-nez p1, :cond_4

    .line 216
    .line 217
    const p1, 0x3eb6fe1c

    .line 218
    .line 219
    .line 220
    invoke-virtual {p3, p1}, Ll2/t;->Y(I)V

    .line 221
    .line 222
    .line 223
    invoke-virtual {p3, p4}, Ll2/t;->q(Z)V

    .line 224
    .line 225
    .line 226
    const/4 p1, 0x0

    .line 227
    goto :goto_2

    .line 228
    :cond_4
    const v0, 0x3eb6fe1d

    .line 229
    .line 230
    .line 231
    invoke-virtual {p3, v0}, Ll2/t;->Y(I)V

    .line 232
    .line 233
    .line 234
    invoke-static {p1, p3, p4}, Llp/uf;->a(Ldi/b;Ll2/o;I)V

    .line 235
    .line 236
    .line 237
    invoke-virtual {p3, p4}, Ll2/t;->q(Z)V

    .line 238
    .line 239
    .line 240
    move-object p1, p2

    .line 241
    :goto_2
    if-nez p1, :cond_5

    .line 242
    .line 243
    iget-object p0, p0, Leh/i;->f:Lyj/b;

    .line 244
    .line 245
    invoke-virtual {p0}, Lyj/b;->invoke()Ljava/lang/Object;

    .line 246
    .line 247
    .line 248
    :cond_5
    return-object p2

    .line 249
    :pswitch_3
    check-cast p3, Ll2/o;

    .line 250
    .line 251
    check-cast p4, Ljava/lang/Integer;

    .line 252
    .line 253
    const-string v0, "$this$composable"

    .line 254
    .line 255
    const-string v1, "it"

    .line 256
    .line 257
    invoke-static {p4, p1, v0, p2, v1}, Lz9/c;->c(Ljava/lang/Integer;Lb1/n;Ljava/lang/String;Lz9/k;Ljava/lang/String;)V

    .line 258
    .line 259
    .line 260
    iget-object p1, p0, Leh/i;->e:Ll2/b1;

    .line 261
    .line 262
    invoke-interface {p1}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 263
    .line 264
    .line 265
    move-result-object p1

    .line 266
    check-cast p1, Lai/a;

    .line 267
    .line 268
    const/4 p2, 0x0

    .line 269
    check-cast p3, Ll2/t;

    .line 270
    .line 271
    if-nez p1, :cond_6

    .line 272
    .line 273
    const p0, 0x35fb76f4

    .line 274
    .line 275
    .line 276
    invoke-virtual {p3, p0}, Ll2/t;->Y(I)V

    .line 277
    .line 278
    .line 279
    :goto_3
    invoke-virtual {p3, p2}, Ll2/t;->q(Z)V

    .line 280
    .line 281
    .line 282
    goto :goto_4

    .line 283
    :cond_6
    const p4, 0x35fb76f5

    .line 284
    .line 285
    .line 286
    invoke-virtual {p3, p4}, Ll2/t;->Y(I)V

    .line 287
    .line 288
    .line 289
    iget-object p0, p0, Leh/i;->f:Lyj/b;

    .line 290
    .line 291
    invoke-static {p1, p0, p3, p2}, Lkp/a8;->a(Lai/a;Lyj/b;Ll2/o;I)V

    .line 292
    .line 293
    .line 294
    goto :goto_3

    .line 295
    :goto_4
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 296
    .line 297
    return-object p0

    .line 298
    nop

    .line 299
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
