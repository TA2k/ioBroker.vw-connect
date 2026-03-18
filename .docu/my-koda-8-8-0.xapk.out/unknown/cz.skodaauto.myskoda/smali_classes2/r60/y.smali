.class public final Lr60/y;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lyy0/j;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lr60/a0;


# direct methods
.method public synthetic constructor <init>(Lr60/a0;I)V
    .locals 0

    .line 1
    iput p2, p0, Lr60/y;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lr60/y;->e:Lr60/a0;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final emit(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 12

    .line 1
    iget p2, p0, Lr60/y;->d:I

    .line 2
    .line 3
    packed-switch p2, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Lne0/t;

    .line 7
    .line 8
    instance-of p2, p1, Lne0/e;

    .line 9
    .line 10
    iget-object p0, p0, Lr60/y;->e:Lr60/a0;

    .line 11
    .line 12
    if-eqz p2, :cond_4

    .line 13
    .line 14
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 15
    .line 16
    .line 17
    move-result-object p1

    .line 18
    check-cast p1, Lr60/z;

    .line 19
    .line 20
    iget-boolean p1, p1, Lr60/z;->h:Z

    .line 21
    .line 22
    if-eqz p1, :cond_0

    .line 23
    .line 24
    iget-object p0, p0, Lr60/a0;->h:Ltr0/b;

    .line 25
    .line 26
    invoke-static {p0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 27
    .line 28
    .line 29
    goto :goto_0

    .line 30
    :cond_0
    iget-object p1, p0, Lr60/a0;->j:Lnn0/h;

    .line 31
    .line 32
    invoke-static {p1}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 33
    .line 34
    .line 35
    move-result-object p1

    .line 36
    sget-object p2, Lon0/c;->g:Lon0/c;

    .line 37
    .line 38
    if-ne p1, p2, :cond_3

    .line 39
    .line 40
    iget-object p1, p0, Lr60/a0;->s:Lnn0/g;

    .line 41
    .line 42
    invoke-static {p1}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 43
    .line 44
    .line 45
    move-result-object p1

    .line 46
    check-cast p1, Lon0/b;

    .line 47
    .line 48
    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    .line 49
    .line 50
    .line 51
    move-result p1

    .line 52
    if-eqz p1, :cond_2

    .line 53
    .line 54
    const/4 p2, 0x1

    .line 55
    if-ne p1, p2, :cond_1

    .line 56
    .line 57
    iget-object p0, p0, Lr60/a0;->u:Lp60/s;

    .line 58
    .line 59
    invoke-static {p0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 60
    .line 61
    .line 62
    goto :goto_0

    .line 63
    :cond_1
    new-instance p0, La8/r0;

    .line 64
    .line 65
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 66
    .line 67
    .line 68
    throw p0

    .line 69
    :cond_2
    iget-object p0, p0, Lr60/a0;->t:Lp60/j;

    .line 70
    .line 71
    invoke-static {p0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 72
    .line 73
    .line 74
    goto :goto_0

    .line 75
    :cond_3
    iget-object p0, p0, Lr60/a0;->l:Lp60/p;

    .line 76
    .line 77
    invoke-static {p0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 78
    .line 79
    .line 80
    goto :goto_0

    .line 81
    :cond_4
    instance-of p2, p1, Lne0/c;

    .line 82
    .line 83
    if-eqz p2, :cond_5

    .line 84
    .line 85
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 86
    .line 87
    .line 88
    move-result-object p2

    .line 89
    move-object v0, p2

    .line 90
    check-cast v0, Lr60/z;

    .line 91
    .line 92
    check-cast p1, Lne0/c;

    .line 93
    .line 94
    iget-object p2, p0, Lr60/a0;->q:Lij0/a;

    .line 95
    .line 96
    invoke-static {p1, p2}, Ljp/rf;->e(Lne0/c;Lij0/a;)Lql0/g;

    .line 97
    .line 98
    .line 99
    move-result-object v4

    .line 100
    const/4 v10, 0x0

    .line 101
    const/16 v11, 0x3f7

    .line 102
    .line 103
    const/4 v1, 0x0

    .line 104
    const/4 v2, 0x0

    .line 105
    const/4 v3, 0x0

    .line 106
    const/4 v5, 0x0

    .line 107
    const/4 v6, 0x0

    .line 108
    const/4 v7, 0x0

    .line 109
    const/4 v8, 0x0

    .line 110
    const/4 v9, 0x0

    .line 111
    invoke-static/range {v0 .. v11}, Lr60/z;->a(Lr60/z;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lql0/g;ZZZZLjava/lang/String;Ljava/lang/String;I)Lr60/z;

    .line 112
    .line 113
    .line 114
    move-result-object p1

    .line 115
    invoke-virtual {p0, p1}, Lql0/j;->g(Lql0/h;)V

    .line 116
    .line 117
    .line 118
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 119
    .line 120
    return-object p0

    .line 121
    :cond_5
    new-instance p0, La8/r0;

    .line 122
    .line 123
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 124
    .line 125
    .line 126
    throw p0

    .line 127
    :pswitch_0
    check-cast p1, Lne0/s;

    .line 128
    .line 129
    iget-object p0, p0, Lr60/y;->e:Lr60/a0;

    .line 130
    .line 131
    iget-object p2, p0, Lr60/a0;->p:Lp60/k0;

    .line 132
    .line 133
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 134
    .line 135
    .line 136
    move-result-object v0

    .line 137
    check-cast v0, Lr60/z;

    .line 138
    .line 139
    iget-object v0, v0, Lr60/z;->j:Ljava/lang/String;

    .line 140
    .line 141
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 142
    .line 143
    .line 144
    move-result-object v1

    .line 145
    check-cast v1, Lr60/z;

    .line 146
    .line 147
    iget-object v1, v1, Lr60/z;->b:Ljava/lang/String;

    .line 148
    .line 149
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 150
    .line 151
    .line 152
    invoke-virtual {v1, v0}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 153
    .line 154
    .line 155
    move-result p2

    .line 156
    if-nez p2, :cond_7

    .line 157
    .line 158
    if-nez v0, :cond_6

    .line 159
    .line 160
    goto :goto_1

    .line 161
    :cond_6
    const/4 p2, 0x0

    .line 162
    goto :goto_2

    .line 163
    :cond_7
    :goto_1
    const/4 p2, 0x1

    .line 164
    :goto_2
    if-eqz p2, :cond_c

    .line 165
    .line 166
    instance-of p2, p1, Lne0/e;

    .line 167
    .line 168
    if-eqz p2, :cond_9

    .line 169
    .line 170
    check-cast p1, Lne0/e;

    .line 171
    .line 172
    iget-object p1, p1, Lne0/e;->a:Ljava/lang/Object;

    .line 173
    .line 174
    check-cast p1, Lss0/k;

    .line 175
    .line 176
    iget-object p2, p1, Lss0/k;->c:Ljava/lang/String;

    .line 177
    .line 178
    if-nez p2, :cond_8

    .line 179
    .line 180
    const-string p2, ""

    .line 181
    .line 182
    :cond_8
    invoke-virtual {p0, p2}, Lr60/a0;->h(Ljava/lang/String;)V

    .line 183
    .line 184
    .line 185
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 186
    .line 187
    .line 188
    move-result-object p2

    .line 189
    move-object v0, p2

    .line 190
    check-cast v0, Lr60/z;

    .line 191
    .line 192
    iget-object v9, p1, Lss0/k;->a:Ljava/lang/String;

    .line 193
    .line 194
    const/4 v10, 0x0

    .line 195
    const/16 v11, 0x2bf

    .line 196
    .line 197
    const/4 v1, 0x0

    .line 198
    const/4 v2, 0x0

    .line 199
    const/4 v3, 0x0

    .line 200
    const/4 v4, 0x0

    .line 201
    const/4 v5, 0x0

    .line 202
    const/4 v6, 0x0

    .line 203
    const/4 v7, 0x0

    .line 204
    const/4 v8, 0x0

    .line 205
    invoke-static/range {v0 .. v11}, Lr60/z;->a(Lr60/z;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lql0/g;ZZZZLjava/lang/String;Ljava/lang/String;I)Lr60/z;

    .line 206
    .line 207
    .line 208
    move-result-object p1

    .line 209
    goto :goto_3

    .line 210
    :cond_9
    instance-of p2, p1, Lne0/c;

    .line 211
    .line 212
    if-eqz p2, :cond_a

    .line 213
    .line 214
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 215
    .line 216
    .line 217
    move-result-object p2

    .line 218
    move-object v0, p2

    .line 219
    check-cast v0, Lr60/z;

    .line 220
    .line 221
    check-cast p1, Lne0/c;

    .line 222
    .line 223
    iget-object p2, p0, Lr60/a0;->q:Lij0/a;

    .line 224
    .line 225
    invoke-static {p1, p2}, Ljp/rf;->e(Lne0/c;Lij0/a;)Lql0/g;

    .line 226
    .line 227
    .line 228
    move-result-object v4

    .line 229
    const/4 v10, 0x0

    .line 230
    const/16 v11, 0x3b7

    .line 231
    .line 232
    const/4 v1, 0x0

    .line 233
    const/4 v2, 0x0

    .line 234
    const/4 v3, 0x0

    .line 235
    const/4 v5, 0x0

    .line 236
    const/4 v6, 0x0

    .line 237
    const/4 v7, 0x0

    .line 238
    const/4 v8, 0x0

    .line 239
    const/4 v9, 0x0

    .line 240
    invoke-static/range {v0 .. v11}, Lr60/z;->a(Lr60/z;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lql0/g;ZZZZLjava/lang/String;Ljava/lang/String;I)Lr60/z;

    .line 241
    .line 242
    .line 243
    move-result-object p1

    .line 244
    goto :goto_3

    .line 245
    :cond_a
    instance-of p1, p1, Lne0/d;

    .line 246
    .line 247
    if-eqz p1, :cond_b

    .line 248
    .line 249
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 250
    .line 251
    .line 252
    move-result-object p1

    .line 253
    move-object v0, p1

    .line 254
    check-cast v0, Lr60/z;

    .line 255
    .line 256
    const/4 v10, 0x0

    .line 257
    const/16 v11, 0x3bf

    .line 258
    .line 259
    const/4 v1, 0x0

    .line 260
    const/4 v2, 0x0

    .line 261
    const/4 v3, 0x0

    .line 262
    const/4 v4, 0x0

    .line 263
    const/4 v5, 0x0

    .line 264
    const/4 v6, 0x0

    .line 265
    const/4 v7, 0x1

    .line 266
    const/4 v8, 0x0

    .line 267
    const/4 v9, 0x0

    .line 268
    invoke-static/range {v0 .. v11}, Lr60/z;->a(Lr60/z;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lql0/g;ZZZZLjava/lang/String;Ljava/lang/String;I)Lr60/z;

    .line 269
    .line 270
    .line 271
    move-result-object p1

    .line 272
    :goto_3
    invoke-virtual {p0, p1}, Lql0/j;->g(Lql0/h;)V

    .line 273
    .line 274
    .line 275
    goto :goto_4

    .line 276
    :cond_b
    new-instance p0, La8/r0;

    .line 277
    .line 278
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 279
    .line 280
    .line 281
    throw p0

    .line 282
    :cond_c
    :goto_4
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 283
    .line 284
    return-object p0

    .line 285
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
