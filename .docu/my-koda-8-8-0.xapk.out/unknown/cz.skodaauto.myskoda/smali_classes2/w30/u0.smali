.class public final Lw30/u0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lyy0/j;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lw30/x0;


# direct methods
.method public synthetic constructor <init>(Lw30/x0;I)V
    .locals 0

    .line 1
    iput p2, p0, Lw30/u0;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lw30/u0;->e:Lw30/x0;

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
    .locals 8

    .line 1
    iget p2, p0, Lw30/u0;->d:I

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
    iget-object p0, p0, Lw30/u0;->e:Lw30/x0;

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
    check-cast v0, Lw30/w0;

    .line 20
    .line 21
    const/4 v6, 0x0

    .line 22
    const/16 v7, 0x3a

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
    invoke-static/range {v0 .. v7}, Lw30/w0;->a(Lw30/w0;Lql0/g;ZZZLjava/lang/String;Ljava/lang/String;I)Lw30/w0;

    .line 30
    .line 31
    .line 32
    move-result-object p1

    .line 33
    invoke-virtual {p0, p1}, Lql0/j;->g(Lql0/h;)V

    .line 34
    .line 35
    .line 36
    goto :goto_0

    .line 37
    :cond_0
    instance-of p2, p1, Lne0/c;

    .line 38
    .line 39
    if-eqz p2, :cond_1

    .line 40
    .line 41
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 42
    .line 43
    .line 44
    move-result-object p2

    .line 45
    move-object v0, p2

    .line 46
    check-cast v0, Lw30/w0;

    .line 47
    .line 48
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 49
    .line 50
    .line 51
    move-result-object p2

    .line 52
    check-cast p2, Lw30/w0;

    .line 53
    .line 54
    iget-boolean p2, p2, Lw30/w0;->d:Z

    .line 55
    .line 56
    xor-int/lit8 v4, p2, 0x1

    .line 57
    .line 58
    const/4 v6, 0x0

    .line 59
    const/16 v7, 0x33

    .line 60
    .line 61
    const/4 v1, 0x0

    .line 62
    const/4 v2, 0x0

    .line 63
    const/4 v3, 0x0

    .line 64
    const/4 v5, 0x0

    .line 65
    invoke-static/range {v0 .. v7}, Lw30/w0;->a(Lw30/w0;Lql0/g;ZZZLjava/lang/String;Ljava/lang/String;I)Lw30/w0;

    .line 66
    .line 67
    .line 68
    move-result-object p2

    .line 69
    invoke-virtual {p0, p2}, Lql0/j;->g(Lql0/h;)V

    .line 70
    .line 71
    .line 72
    check-cast p1, Lne0/c;

    .line 73
    .line 74
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 75
    .line 76
    .line 77
    move-result-object p2

    .line 78
    new-instance v0, Lvu/j;

    .line 79
    .line 80
    const/16 v1, 0x12

    .line 81
    .line 82
    const/4 v2, 0x0

    .line 83
    invoke-direct {v0, v1, p0, p1, v2}, Lvu/j;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 84
    .line 85
    .line 86
    const/4 p0, 0x3

    .line 87
    invoke-static {p2, v2, v2, v0, p0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 88
    .line 89
    .line 90
    goto :goto_0

    .line 91
    :cond_1
    instance-of p1, p1, Lne0/d;

    .line 92
    .line 93
    if-eqz p1, :cond_2

    .line 94
    .line 95
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 96
    .line 97
    .line 98
    move-result-object p1

    .line 99
    move-object v0, p1

    .line 100
    check-cast v0, Lw30/w0;

    .line 101
    .line 102
    const/4 v6, 0x0

    .line 103
    const/16 v7, 0x3a

    .line 104
    .line 105
    const/4 v1, 0x0

    .line 106
    const/4 v2, 0x0

    .line 107
    const/4 v3, 0x1

    .line 108
    const/4 v4, 0x0

    .line 109
    const/4 v5, 0x0

    .line 110
    invoke-static/range {v0 .. v7}, Lw30/w0;->a(Lw30/w0;Lql0/g;ZZZLjava/lang/String;Ljava/lang/String;I)Lw30/w0;

    .line 111
    .line 112
    .line 113
    move-result-object p1

    .line 114
    invoke-virtual {p0, p1}, Lql0/j;->g(Lql0/h;)V

    .line 115
    .line 116
    .line 117
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 118
    .line 119
    return-object p0

    .line 120
    :cond_2
    new-instance p0, La8/r0;

    .line 121
    .line 122
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 123
    .line 124
    .line 125
    throw p0

    .line 126
    :pswitch_0
    check-cast p1, Lne0/s;

    .line 127
    .line 128
    instance-of p2, p1, Lne0/c;

    .line 129
    .line 130
    iget-object p0, p0, Lw30/u0;->e:Lw30/x0;

    .line 131
    .line 132
    if-eqz p2, :cond_3

    .line 133
    .line 134
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 135
    .line 136
    .line 137
    move-result-object p2

    .line 138
    move-object v0, p2

    .line 139
    check-cast v0, Lw30/w0;

    .line 140
    .line 141
    check-cast p1, Lne0/c;

    .line 142
    .line 143
    iget-object p2, p0, Lw30/x0;->k:Lij0/a;

    .line 144
    .line 145
    invoke-static {p1, p2}, Ljp/rf;->e(Lne0/c;Lij0/a;)Lql0/g;

    .line 146
    .line 147
    .line 148
    move-result-object v1

    .line 149
    const/4 v6, 0x0

    .line 150
    const/16 v7, 0x3c

    .line 151
    .line 152
    const/4 v2, 0x0

    .line 153
    const/4 v3, 0x0

    .line 154
    const/4 v4, 0x0

    .line 155
    const/4 v5, 0x0

    .line 156
    invoke-static/range {v0 .. v7}, Lw30/w0;->a(Lw30/w0;Lql0/g;ZZZLjava/lang/String;Ljava/lang/String;I)Lw30/w0;

    .line 157
    .line 158
    .line 159
    move-result-object p1

    .line 160
    goto :goto_1

    .line 161
    :cond_3
    instance-of p2, p1, Lne0/d;

    .line 162
    .line 163
    if-eqz p2, :cond_4

    .line 164
    .line 165
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 166
    .line 167
    .line 168
    move-result-object p1

    .line 169
    move-object v0, p1

    .line 170
    check-cast v0, Lw30/w0;

    .line 171
    .line 172
    const/4 v6, 0x0

    .line 173
    const/16 v7, 0x3d

    .line 174
    .line 175
    const/4 v1, 0x0

    .line 176
    const/4 v2, 0x1

    .line 177
    const/4 v3, 0x0

    .line 178
    const/4 v4, 0x0

    .line 179
    const/4 v5, 0x0

    .line 180
    invoke-static/range {v0 .. v7}, Lw30/w0;->a(Lw30/w0;Lql0/g;ZZZLjava/lang/String;Ljava/lang/String;I)Lw30/w0;

    .line 181
    .line 182
    .line 183
    move-result-object p1

    .line 184
    goto :goto_1

    .line 185
    :cond_4
    instance-of p2, p1, Lne0/e;

    .line 186
    .line 187
    if-eqz p2, :cond_5

    .line 188
    .line 189
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 190
    .line 191
    .line 192
    move-result-object p2

    .line 193
    move-object v0, p2

    .line 194
    check-cast v0, Lw30/w0;

    .line 195
    .line 196
    check-cast p1, Lne0/e;

    .line 197
    .line 198
    iget-object p1, p1, Lne0/e;->a:Ljava/lang/Object;

    .line 199
    .line 200
    check-cast p1, Lv30/j;

    .line 201
    .line 202
    iget-object v5, p1, Lv30/j;->b:Ljava/lang/String;

    .line 203
    .line 204
    iget-boolean v4, p1, Lv30/j;->a:Z

    .line 205
    .line 206
    const/4 v6, 0x0

    .line 207
    const/16 v7, 0x25

    .line 208
    .line 209
    const/4 v1, 0x0

    .line 210
    const/4 v2, 0x0

    .line 211
    const/4 v3, 0x0

    .line 212
    invoke-static/range {v0 .. v7}, Lw30/w0;->a(Lw30/w0;Lql0/g;ZZZLjava/lang/String;Ljava/lang/String;I)Lw30/w0;

    .line 213
    .line 214
    .line 215
    move-result-object p1

    .line 216
    :goto_1
    invoke-virtual {p0, p1}, Lql0/j;->g(Lql0/h;)V

    .line 217
    .line 218
    .line 219
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 220
    .line 221
    return-object p0

    .line 222
    :cond_5
    new-instance p0, La8/r0;

    .line 223
    .line 224
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 225
    .line 226
    .line 227
    throw p0

    .line 228
    nop

    .line 229
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
