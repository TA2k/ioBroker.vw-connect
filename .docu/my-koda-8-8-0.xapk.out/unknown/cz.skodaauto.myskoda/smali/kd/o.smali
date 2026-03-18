.class public final synthetic Lkd/o;
.super Lkotlin/jvm/internal/a;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/o;


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 6

    .line 1
    check-cast p1, Lzb/d0;

    .line 2
    .line 3
    move-object v2, p2

    .line 4
    check-cast v2, Ljava/util/List;

    .line 5
    .line 6
    check-cast p3, Lkotlin/coroutines/Continuation;

    .line 7
    .line 8
    iget-object p0, p0, Lkotlin/jvm/internal/a;->receiver:Ljava/lang/Object;

    .line 9
    .line 10
    check-cast p0, Lkd/p;

    .line 11
    .line 12
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 13
    .line 14
    .line 15
    sget-object p2, Llc/a;->d:Llc/c;

    .line 16
    .line 17
    instance-of p3, p1, Lzb/z;

    .line 18
    .line 19
    if-eqz p3, :cond_5

    .line 20
    .line 21
    check-cast p1, Lzb/z;

    .line 22
    .line 23
    iget-object p1, p1, Lzb/z;->a:Ljava/util/List;

    .line 24
    .line 25
    invoke-interface {p1}, Ljava/util/List;->isEmpty()Z

    .line 26
    .line 27
    .line 28
    move-result p3

    .line 29
    if-eqz p3, :cond_0

    .line 30
    .line 31
    invoke-interface {v2}, Ljava/util/List;->isEmpty()Z

    .line 32
    .line 33
    .line 34
    move-result p3

    .line 35
    if-eqz p3, :cond_0

    .line 36
    .line 37
    new-instance p0, Llc/q;

    .line 38
    .line 39
    invoke-direct {p0, p2}, Llc/q;-><init>(Ljava/lang/Object;)V

    .line 40
    .line 41
    .line 42
    return-object p0

    .line 43
    :cond_0
    invoke-interface {p1}, Ljava/util/List;->isEmpty()Z

    .line 44
    .line 45
    .line 46
    move-result p3

    .line 47
    if-eqz p3, :cond_4

    .line 48
    .line 49
    move-object p3, v2

    .line 50
    check-cast p3, Ljava/util/Collection;

    .line 51
    .line 52
    invoke-interface {p3}, Ljava/util/Collection;->isEmpty()Z

    .line 53
    .line 54
    .line 55
    move-result p3

    .line 56
    if-nez p3, :cond_4

    .line 57
    .line 58
    new-instance v1, Llc/q;

    .line 59
    .line 60
    invoke-direct {v1, p2}, Llc/q;-><init>(Ljava/lang/Object;)V

    .line 61
    .line 62
    .line 63
    move-object p1, v2

    .line 64
    check-cast p1, Ljava/lang/Iterable;

    .line 65
    .line 66
    instance-of p2, p1, Ljava/util/Collection;

    .line 67
    .line 68
    const/4 p3, 0x0

    .line 69
    if-eqz p2, :cond_2

    .line 70
    .line 71
    move-object p2, p1

    .line 72
    check-cast p2, Ljava/util/Collection;

    .line 73
    .line 74
    invoke-interface {p2}, Ljava/util/Collection;->isEmpty()Z

    .line 75
    .line 76
    .line 77
    move-result p2

    .line 78
    if-eqz p2, :cond_2

    .line 79
    .line 80
    :cond_1
    :goto_0
    move v3, p3

    .line 81
    goto :goto_1

    .line 82
    :cond_2
    invoke-interface {p1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 83
    .line 84
    .line 85
    move-result-object p1

    .line 86
    :cond_3
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 87
    .line 88
    .line 89
    move-result p2

    .line 90
    if-eqz p2, :cond_1

    .line 91
    .line 92
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 93
    .line 94
    .line 95
    move-result-object p2

    .line 96
    check-cast p2, Lkd/a;

    .line 97
    .line 98
    iget-boolean p2, p2, Lkd/a;->d:Z

    .line 99
    .line 100
    if-eqz p2, :cond_3

    .line 101
    .line 102
    const/4 p3, 0x1

    .line 103
    goto :goto_0

    .line 104
    :goto_1
    iget-boolean v4, p0, Lkd/p;->l:Z

    .line 105
    .line 106
    new-instance v0, Lkd/n;

    .line 107
    .line 108
    const/4 v5, 0x1

    .line 109
    invoke-direct/range {v0 .. v5}, Lkd/n;-><init>(Llc/q;Ljava/util/List;ZZZ)V

    .line 110
    .line 111
    .line 112
    new-instance p0, Llc/q;

    .line 113
    .line 114
    invoke-direct {p0, v0}, Llc/q;-><init>(Ljava/lang/Object;)V

    .line 115
    .line 116
    .line 117
    return-object p0

    .line 118
    :cond_4
    new-instance v0, Lkd/n;

    .line 119
    .line 120
    new-instance v1, Llc/q;

    .line 121
    .line 122
    invoke-direct {v1, p1}, Llc/q;-><init>(Ljava/lang/Object;)V

    .line 123
    .line 124
    .line 125
    iget-boolean v3, p0, Lkd/p;->l:Z

    .line 126
    .line 127
    const/4 v4, 0x1

    .line 128
    const/4 v5, 0x4

    .line 129
    invoke-direct/range {v0 .. v5}, Lkd/n;-><init>(Llc/q;Ljava/util/List;ZZI)V

    .line 130
    .line 131
    .line 132
    new-instance p0, Llc/q;

    .line 133
    .line 134
    invoke-direct {p0, v0}, Llc/q;-><init>(Ljava/lang/Object;)V

    .line 135
    .line 136
    .line 137
    return-object p0

    .line 138
    :cond_5
    instance-of p2, p1, Lzb/a0;

    .line 139
    .line 140
    if-eqz p2, :cond_6

    .line 141
    .line 142
    check-cast p1, Lzb/a0;

    .line 143
    .line 144
    iget-object p0, p1, Lzb/a0;->b:Ljava/lang/Throwable;

    .line 145
    .line 146
    invoke-static {p0}, Llc/c;->b(Ljava/lang/Throwable;)Llc/l;

    .line 147
    .line 148
    .line 149
    move-result-object p0

    .line 150
    new-instance p1, Llc/q;

    .line 151
    .line 152
    invoke-direct {p1, p0}, Llc/q;-><init>(Ljava/lang/Object;)V

    .line 153
    .line 154
    .line 155
    return-object p1

    .line 156
    :cond_6
    instance-of p2, p1, Lzb/b0;

    .line 157
    .line 158
    if-eqz p2, :cond_7

    .line 159
    .line 160
    new-instance v0, Lkd/n;

    .line 161
    .line 162
    check-cast p1, Lzb/b0;

    .line 163
    .line 164
    iget-object p1, p1, Lzb/b0;->a:Ljava/util/List;

    .line 165
    .line 166
    new-instance v1, Llc/q;

    .line 167
    .line 168
    invoke-direct {v1, p1}, Llc/q;-><init>(Ljava/lang/Object;)V

    .line 169
    .line 170
    .line 171
    iget-boolean v3, p0, Lkd/p;->l:Z

    .line 172
    .line 173
    const/4 v4, 0x1

    .line 174
    const/4 v5, 0x4

    .line 175
    invoke-direct/range {v0 .. v5}, Lkd/n;-><init>(Llc/q;Ljava/util/List;ZZI)V

    .line 176
    .line 177
    .line 178
    new-instance p0, Llc/q;

    .line 179
    .line 180
    invoke-direct {p0, v0}, Llc/q;-><init>(Ljava/lang/Object;)V

    .line 181
    .line 182
    .line 183
    return-object p0

    .line 184
    :cond_7
    instance-of p0, p1, Lzb/c0;

    .line 185
    .line 186
    if-eqz p0, :cond_9

    .line 187
    .line 188
    check-cast p1, Lzb/c0;

    .line 189
    .line 190
    iget-object p0, p1, Lzb/c0;->a:Ljava/util/List;

    .line 191
    .line 192
    invoke-interface {p0}, Ljava/util/List;->isEmpty()Z

    .line 193
    .line 194
    .line 195
    move-result p1

    .line 196
    if-eqz p1, :cond_8

    .line 197
    .line 198
    new-instance v0, Lkd/n;

    .line 199
    .line 200
    new-instance v1, Llc/q;

    .line 201
    .line 202
    sget-object p0, Llc/a;->c:Llc/c;

    .line 203
    .line 204
    invoke-direct {v1, p0}, Llc/q;-><init>(Ljava/lang/Object;)V

    .line 205
    .line 206
    .line 207
    const/4 v4, 0x0

    .line 208
    const/16 v5, 0xc

    .line 209
    .line 210
    const/4 v3, 0x0

    .line 211
    invoke-direct/range {v0 .. v5}, Lkd/n;-><init>(Llc/q;Ljava/util/List;ZZI)V

    .line 212
    .line 213
    .line 214
    new-instance p0, Llc/q;

    .line 215
    .line 216
    invoke-direct {p0, v0}, Llc/q;-><init>(Ljava/lang/Object;)V

    .line 217
    .line 218
    .line 219
    return-object p0

    .line 220
    :cond_8
    invoke-static {}, Ljp/k1;->f()Lnx0/c;

    .line 221
    .line 222
    .line 223
    move-result-object p1

    .line 224
    check-cast p0, Ljava/util/Collection;

    .line 225
    .line 226
    invoke-virtual {p1, p0}, Lnx0/c;->addAll(Ljava/util/Collection;)Z

    .line 227
    .line 228
    .line 229
    sget-object p0, Lkd/b;->a:Lkd/b;

    .line 230
    .line 231
    invoke-virtual {p1, p0}, Lnx0/c;->add(Ljava/lang/Object;)Z

    .line 232
    .line 233
    .line 234
    invoke-static {p1}, Ljp/k1;->d(Ljava/util/List;)Lnx0/c;

    .line 235
    .line 236
    .line 237
    move-result-object p0

    .line 238
    new-instance v0, Lkd/n;

    .line 239
    .line 240
    const-string p1, "value"

    .line 241
    .line 242
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 243
    .line 244
    .line 245
    new-instance v1, Llc/q;

    .line 246
    .line 247
    invoke-direct {v1, p0}, Llc/q;-><init>(Ljava/lang/Object;)V

    .line 248
    .line 249
    .line 250
    const/4 v4, 0x1

    .line 251
    const/16 v5, 0xc

    .line 252
    .line 253
    const/4 v3, 0x0

    .line 254
    invoke-direct/range {v0 .. v5}, Lkd/n;-><init>(Llc/q;Ljava/util/List;ZZI)V

    .line 255
    .line 256
    .line 257
    new-instance p0, Llc/q;

    .line 258
    .line 259
    invoke-direct {p0, v0}, Llc/q;-><init>(Ljava/lang/Object;)V

    .line 260
    .line 261
    .line 262
    return-object p0

    .line 263
    :cond_9
    new-instance p0, La8/r0;

    .line 264
    .line 265
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 266
    .line 267
    .line 268
    throw p0
.end method
