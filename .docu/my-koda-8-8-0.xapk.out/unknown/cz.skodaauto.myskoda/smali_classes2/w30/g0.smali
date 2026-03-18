.class public final Lw30/g0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lyy0/j;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lw30/j0;


# direct methods
.method public synthetic constructor <init>(Lw30/j0;I)V
    .locals 0

    .line 1
    iput p2, p0, Lw30/g0;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lw30/g0;->e:Lw30/j0;

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
    .locals 11

    .line 1
    iget p2, p0, Lw30/g0;->d:I

    .line 2
    .line 3
    packed-switch p2, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Lne0/s;

    .line 7
    .line 8
    instance-of p2, p1, Lne0/e;

    .line 9
    .line 10
    iget-object p0, p0, Lw30/g0;->e:Lw30/j0;

    .line 11
    .line 12
    if-eqz p2, :cond_0

    .line 13
    .line 14
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 15
    .line 16
    .line 17
    move-result-object p1

    .line 18
    move-object v0, p1

    .line 19
    check-cast v0, Lw30/i0;

    .line 20
    .line 21
    const/4 v8, 0x0

    .line 22
    const/16 v9, 0xf8

    .line 23
    .line 24
    const/4 v1, 0x0

    .line 25
    const/4 v2, 0x0

    .line 26
    const/4 v3, 0x0

    .line 27
    const/4 v4, 0x0

    .line 28
    const/4 v5, 0x0

    .line 29
    const/4 v6, 0x0

    .line 30
    const/4 v7, 0x0

    .line 31
    invoke-static/range {v0 .. v9}, Lw30/i0;->a(Lw30/i0;Lql0/g;ZZZLjava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;I)Lw30/i0;

    .line 32
    .line 33
    .line 34
    move-result-object p1

    .line 35
    invoke-virtual {p0, p1}, Lql0/j;->g(Lql0/h;)V

    .line 36
    .line 37
    .line 38
    goto :goto_0

    .line 39
    :cond_0
    instance-of p2, p1, Lne0/c;

    .line 40
    .line 41
    if-eqz p2, :cond_1

    .line 42
    .line 43
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 44
    .line 45
    .line 46
    move-result-object p2

    .line 47
    move-object v0, p2

    .line 48
    check-cast v0, Lw30/i0;

    .line 49
    .line 50
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 51
    .line 52
    .line 53
    move-result-object p2

    .line 54
    check-cast p2, Lw30/i0;

    .line 55
    .line 56
    iget-boolean p2, p2, Lw30/i0;->d:Z

    .line 57
    .line 58
    xor-int/lit8 v4, p2, 0x1

    .line 59
    .line 60
    const/4 v8, 0x0

    .line 61
    const/16 v9, 0xf1

    .line 62
    .line 63
    const/4 v1, 0x0

    .line 64
    const/4 v2, 0x0

    .line 65
    const/4 v3, 0x0

    .line 66
    const/4 v5, 0x0

    .line 67
    const/4 v6, 0x0

    .line 68
    const/4 v7, 0x0

    .line 69
    invoke-static/range {v0 .. v9}, Lw30/i0;->a(Lw30/i0;Lql0/g;ZZZLjava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;I)Lw30/i0;

    .line 70
    .line 71
    .line 72
    move-result-object p2

    .line 73
    invoke-virtual {p0, p2}, Lql0/j;->g(Lql0/h;)V

    .line 74
    .line 75
    .line 76
    check-cast p1, Lne0/c;

    .line 77
    .line 78
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 79
    .line 80
    .line 81
    move-result-object p2

    .line 82
    new-instance v0, Lvu/j;

    .line 83
    .line 84
    const/16 v1, 0xe

    .line 85
    .line 86
    const/4 v2, 0x0

    .line 87
    invoke-direct {v0, v1, p0, p1, v2}, Lvu/j;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 88
    .line 89
    .line 90
    const/4 p0, 0x3

    .line 91
    invoke-static {p2, v2, v2, v0, p0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 92
    .line 93
    .line 94
    goto :goto_0

    .line 95
    :cond_1
    instance-of p1, p1, Lne0/d;

    .line 96
    .line 97
    if-eqz p1, :cond_2

    .line 98
    .line 99
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 100
    .line 101
    .line 102
    move-result-object p1

    .line 103
    move-object v0, p1

    .line 104
    check-cast v0, Lw30/i0;

    .line 105
    .line 106
    const/4 v8, 0x0

    .line 107
    const/16 v9, 0xf8

    .line 108
    .line 109
    const/4 v1, 0x0

    .line 110
    const/4 v2, 0x0

    .line 111
    const/4 v3, 0x1

    .line 112
    const/4 v4, 0x0

    .line 113
    const/4 v5, 0x0

    .line 114
    const/4 v6, 0x0

    .line 115
    const/4 v7, 0x0

    .line 116
    invoke-static/range {v0 .. v9}, Lw30/i0;->a(Lw30/i0;Lql0/g;ZZZLjava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;I)Lw30/i0;

    .line 117
    .line 118
    .line 119
    move-result-object p1

    .line 120
    invoke-virtual {p0, p1}, Lql0/j;->g(Lql0/h;)V

    .line 121
    .line 122
    .line 123
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 124
    .line 125
    return-object p0

    .line 126
    :cond_2
    new-instance p0, La8/r0;

    .line 127
    .line 128
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 129
    .line 130
    .line 131
    throw p0

    .line 132
    :pswitch_0
    check-cast p1, Lne0/s;

    .line 133
    .line 134
    iget-object p0, p0, Lw30/g0;->e:Lw30/j0;

    .line 135
    .line 136
    iget-object p2, p0, Lw30/j0;->k:Lij0/a;

    .line 137
    .line 138
    instance-of v0, p1, Lne0/c;

    .line 139
    .line 140
    if-eqz v0, :cond_3

    .line 141
    .line 142
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 143
    .line 144
    .line 145
    move-result-object v0

    .line 146
    move-object v1, v0

    .line 147
    check-cast v1, Lw30/i0;

    .line 148
    .line 149
    check-cast p1, Lne0/c;

    .line 150
    .line 151
    invoke-static {p1, p2}, Ljp/rf;->e(Lne0/c;Lij0/a;)Lql0/g;

    .line 152
    .line 153
    .line 154
    move-result-object v2

    .line 155
    const/4 v9, 0x0

    .line 156
    const/16 v10, 0xfc

    .line 157
    .line 158
    const/4 v3, 0x0

    .line 159
    const/4 v4, 0x0

    .line 160
    const/4 v5, 0x0

    .line 161
    const/4 v6, 0x0

    .line 162
    const/4 v7, 0x0

    .line 163
    const/4 v8, 0x0

    .line 164
    invoke-static/range {v1 .. v10}, Lw30/i0;->a(Lw30/i0;Lql0/g;ZZZLjava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;I)Lw30/i0;

    .line 165
    .line 166
    .line 167
    move-result-object p1

    .line 168
    goto :goto_1

    .line 169
    :cond_3
    instance-of v0, p1, Lne0/d;

    .line 170
    .line 171
    if-eqz v0, :cond_4

    .line 172
    .line 173
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 174
    .line 175
    .line 176
    move-result-object p1

    .line 177
    move-object v0, p1

    .line 178
    check-cast v0, Lw30/i0;

    .line 179
    .line 180
    const/4 v8, 0x0

    .line 181
    const/16 v9, 0xfd

    .line 182
    .line 183
    const/4 v1, 0x0

    .line 184
    const/4 v2, 0x1

    .line 185
    const/4 v3, 0x0

    .line 186
    const/4 v4, 0x0

    .line 187
    const/4 v5, 0x0

    .line 188
    const/4 v6, 0x0

    .line 189
    const/4 v7, 0x0

    .line 190
    invoke-static/range {v0 .. v9}, Lw30/i0;->a(Lw30/i0;Lql0/g;ZZZLjava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;I)Lw30/i0;

    .line 191
    .line 192
    .line 193
    move-result-object p1

    .line 194
    goto :goto_1

    .line 195
    :cond_4
    instance-of v0, p1, Lne0/e;

    .line 196
    .line 197
    if-eqz v0, :cond_5

    .line 198
    .line 199
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 200
    .line 201
    .line 202
    move-result-object v0

    .line 203
    move-object v1, v0

    .line 204
    check-cast v1, Lw30/i0;

    .line 205
    .line 206
    check-cast p1, Lne0/e;

    .line 207
    .line 208
    iget-object p1, p1, Lne0/e;->a:Ljava/lang/Object;

    .line 209
    .line 210
    check-cast p1, Lv30/h;

    .line 211
    .line 212
    iget-object v8, p1, Lv30/h;->b:Ljava/lang/String;

    .line 213
    .line 214
    iget-object v6, p1, Lv30/h;->c:Ljava/lang/String;

    .line 215
    .line 216
    const/4 v0, 0x0

    .line 217
    new-array v0, v0, [Ljava/lang/Object;

    .line 218
    .line 219
    check-cast p2, Ljj0/f;

    .line 220
    .line 221
    const v2, 0x7f120711

    .line 222
    .line 223
    .line 224
    invoke-virtual {p2, v2, v0}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 225
    .line 226
    .line 227
    move-result-object v7

    .line 228
    iget-boolean v5, p1, Lv30/h;->a:Z

    .line 229
    .line 230
    const/4 v9, 0x0

    .line 231
    const/16 v10, 0x85

    .line 232
    .line 233
    const/4 v2, 0x0

    .line 234
    const/4 v3, 0x0

    .line 235
    const/4 v4, 0x0

    .line 236
    invoke-static/range {v1 .. v10}, Lw30/i0;->a(Lw30/i0;Lql0/g;ZZZLjava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;I)Lw30/i0;

    .line 237
    .line 238
    .line 239
    move-result-object p1

    .line 240
    :goto_1
    invoke-virtual {p0, p1}, Lql0/j;->g(Lql0/h;)V

    .line 241
    .line 242
    .line 243
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 244
    .line 245
    return-object p0

    .line 246
    :cond_5
    new-instance p0, La8/r0;

    .line 247
    .line 248
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 249
    .line 250
    .line 251
    throw p0

    .line 252
    nop

    .line 253
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
