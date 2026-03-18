.class public final Lw30/k0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lyy0/j;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lw30/n0;


# direct methods
.method public synthetic constructor <init>(Lw30/n0;I)V
    .locals 0

    .line 1
    iput p2, p0, Lw30/k0;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lw30/k0;->e:Lw30/n0;

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
    .locals 9

    .line 1
    iget p2, p0, Lw30/k0;->d:I

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
    iget-object p0, p0, Lw30/k0;->e:Lw30/n0;

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
    check-cast v0, Lw30/m0;

    .line 20
    .line 21
    const/4 v7, 0x0

    .line 22
    const/16 v8, 0x78

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
    invoke-static/range {v0 .. v8}, Lw30/m0;->a(Lw30/m0;Lql0/g;ZZZLjava/lang/String;Ljava/lang/String;Ljava/lang/String;I)Lw30/m0;

    .line 31
    .line 32
    .line 33
    move-result-object p1

    .line 34
    invoke-virtual {p0, p1}, Lql0/j;->g(Lql0/h;)V

    .line 35
    .line 36
    .line 37
    goto :goto_0

    .line 38
    :cond_0
    instance-of p2, p1, Lne0/c;

    .line 39
    .line 40
    if-eqz p2, :cond_1

    .line 41
    .line 42
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 43
    .line 44
    .line 45
    move-result-object p2

    .line 46
    move-object v0, p2

    .line 47
    check-cast v0, Lw30/m0;

    .line 48
    .line 49
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 50
    .line 51
    .line 52
    move-result-object p2

    .line 53
    check-cast p2, Lw30/m0;

    .line 54
    .line 55
    iget-boolean p2, p2, Lw30/m0;->d:Z

    .line 56
    .line 57
    xor-int/lit8 v4, p2, 0x1

    .line 58
    .line 59
    const/4 v7, 0x0

    .line 60
    const/16 v8, 0x71

    .line 61
    .line 62
    const/4 v1, 0x0

    .line 63
    const/4 v2, 0x0

    .line 64
    const/4 v3, 0x0

    .line 65
    const/4 v5, 0x0

    .line 66
    const/4 v6, 0x0

    .line 67
    invoke-static/range {v0 .. v8}, Lw30/m0;->a(Lw30/m0;Lql0/g;ZZZLjava/lang/String;Ljava/lang/String;Ljava/lang/String;I)Lw30/m0;

    .line 68
    .line 69
    .line 70
    move-result-object p2

    .line 71
    invoke-virtual {p0, p2}, Lql0/j;->g(Lql0/h;)V

    .line 72
    .line 73
    .line 74
    check-cast p1, Lne0/c;

    .line 75
    .line 76
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 77
    .line 78
    .line 79
    move-result-object p2

    .line 80
    new-instance v0, Lvu/j;

    .line 81
    .line 82
    const/16 v1, 0xf

    .line 83
    .line 84
    const/4 v2, 0x0

    .line 85
    invoke-direct {v0, v1, p0, p1, v2}, Lvu/j;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 86
    .line 87
    .line 88
    const/4 p0, 0x3

    .line 89
    invoke-static {p2, v2, v2, v0, p0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 90
    .line 91
    .line 92
    goto :goto_0

    .line 93
    :cond_1
    instance-of p1, p1, Lne0/d;

    .line 94
    .line 95
    if-eqz p1, :cond_2

    .line 96
    .line 97
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 98
    .line 99
    .line 100
    move-result-object p1

    .line 101
    move-object v0, p1

    .line 102
    check-cast v0, Lw30/m0;

    .line 103
    .line 104
    const/4 v7, 0x0

    .line 105
    const/16 v8, 0x78

    .line 106
    .line 107
    const/4 v1, 0x0

    .line 108
    const/4 v2, 0x0

    .line 109
    const/4 v3, 0x1

    .line 110
    const/4 v4, 0x0

    .line 111
    const/4 v5, 0x0

    .line 112
    const/4 v6, 0x0

    .line 113
    invoke-static/range {v0 .. v8}, Lw30/m0;->a(Lw30/m0;Lql0/g;ZZZLjava/lang/String;Ljava/lang/String;Ljava/lang/String;I)Lw30/m0;

    .line 114
    .line 115
    .line 116
    move-result-object p1

    .line 117
    invoke-virtual {p0, p1}, Lql0/j;->g(Lql0/h;)V

    .line 118
    .line 119
    .line 120
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 121
    .line 122
    return-object p0

    .line 123
    :cond_2
    new-instance p0, La8/r0;

    .line 124
    .line 125
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 126
    .line 127
    .line 128
    throw p0

    .line 129
    :pswitch_0
    check-cast p1, Lne0/s;

    .line 130
    .line 131
    instance-of p2, p1, Lne0/c;

    .line 132
    .line 133
    iget-object p0, p0, Lw30/k0;->e:Lw30/n0;

    .line 134
    .line 135
    if-eqz p2, :cond_3

    .line 136
    .line 137
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 138
    .line 139
    .line 140
    move-result-object p2

    .line 141
    move-object v0, p2

    .line 142
    check-cast v0, Lw30/m0;

    .line 143
    .line 144
    check-cast p1, Lne0/c;

    .line 145
    .line 146
    iget-object p2, p0, Lw30/n0;->k:Lij0/a;

    .line 147
    .line 148
    invoke-static {p1, p2}, Ljp/rf;->e(Lne0/c;Lij0/a;)Lql0/g;

    .line 149
    .line 150
    .line 151
    move-result-object v1

    .line 152
    const/4 v7, 0x0

    .line 153
    const/16 v8, 0x7c

    .line 154
    .line 155
    const/4 v2, 0x0

    .line 156
    const/4 v3, 0x0

    .line 157
    const/4 v4, 0x0

    .line 158
    const/4 v5, 0x0

    .line 159
    const/4 v6, 0x0

    .line 160
    invoke-static/range {v0 .. v8}, Lw30/m0;->a(Lw30/m0;Lql0/g;ZZZLjava/lang/String;Ljava/lang/String;Ljava/lang/String;I)Lw30/m0;

    .line 161
    .line 162
    .line 163
    move-result-object p1

    .line 164
    goto :goto_1

    .line 165
    :cond_3
    instance-of p2, p1, Lne0/d;

    .line 166
    .line 167
    if-eqz p2, :cond_4

    .line 168
    .line 169
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 170
    .line 171
    .line 172
    move-result-object p1

    .line 173
    move-object v0, p1

    .line 174
    check-cast v0, Lw30/m0;

    .line 175
    .line 176
    const/4 v7, 0x0

    .line 177
    const/16 v8, 0x7d

    .line 178
    .line 179
    const/4 v1, 0x0

    .line 180
    const/4 v2, 0x1

    .line 181
    const/4 v3, 0x0

    .line 182
    const/4 v4, 0x0

    .line 183
    const/4 v5, 0x0

    .line 184
    const/4 v6, 0x0

    .line 185
    invoke-static/range {v0 .. v8}, Lw30/m0;->a(Lw30/m0;Lql0/g;ZZZLjava/lang/String;Ljava/lang/String;Ljava/lang/String;I)Lw30/m0;

    .line 186
    .line 187
    .line 188
    move-result-object p1

    .line 189
    goto :goto_1

    .line 190
    :cond_4
    instance-of p2, p1, Lne0/e;

    .line 191
    .line 192
    if-eqz p2, :cond_5

    .line 193
    .line 194
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 195
    .line 196
    .line 197
    move-result-object p2

    .line 198
    move-object v0, p2

    .line 199
    check-cast v0, Lw30/m0;

    .line 200
    .line 201
    check-cast p1, Lne0/e;

    .line 202
    .line 203
    iget-object p1, p1, Lne0/e;->a:Ljava/lang/Object;

    .line 204
    .line 205
    check-cast p1, Lv30/h;

    .line 206
    .line 207
    iget-object v6, p1, Lv30/h;->b:Ljava/lang/String;

    .line 208
    .line 209
    iget-object v5, p1, Lv30/h;->c:Ljava/lang/String;

    .line 210
    .line 211
    iget-boolean v4, p1, Lv30/h;->a:Z

    .line 212
    .line 213
    const/4 v7, 0x0

    .line 214
    const/16 v8, 0x45

    .line 215
    .line 216
    const/4 v1, 0x0

    .line 217
    const/4 v2, 0x0

    .line 218
    const/4 v3, 0x0

    .line 219
    invoke-static/range {v0 .. v8}, Lw30/m0;->a(Lw30/m0;Lql0/g;ZZZLjava/lang/String;Ljava/lang/String;Ljava/lang/String;I)Lw30/m0;

    .line 220
    .line 221
    .line 222
    move-result-object p1

    .line 223
    :goto_1
    invoke-virtual {p0, p1}, Lql0/j;->g(Lql0/h;)V

    .line 224
    .line 225
    .line 226
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 227
    .line 228
    return-object p0

    .line 229
    :cond_5
    new-instance p0, La8/r0;

    .line 230
    .line 231
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 232
    .line 233
    .line 234
    throw p0

    .line 235
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
