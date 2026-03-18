.class public final Lw30/k;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lyy0/j;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lw30/n;


# direct methods
.method public synthetic constructor <init>(Lw30/n;I)V
    .locals 0

    .line 1
    iput p2, p0, Lw30/k;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lw30/k;->e:Lw30/n;

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
    .locals 6

    .line 1
    iget p2, p0, Lw30/k;->d:I

    .line 2
    .line 3
    packed-switch p2, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Lne0/s;

    .line 7
    .line 8
    instance-of p2, p1, Lne0/d;

    .line 9
    .line 10
    iget-object p0, p0, Lw30/k;->e:Lw30/n;

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
    check-cast v0, Lw30/m;

    .line 20
    .line 21
    const/4 v4, 0x0

    .line 22
    const/16 v5, 0x1b

    .line 23
    .line 24
    const/4 v1, 0x0

    .line 25
    const/4 v2, 0x0

    .line 26
    const/4 v3, 0x1

    .line 27
    invoke-static/range {v0 .. v5}, Lw30/m;->a(Lw30/m;ZZZLql0/g;I)Lw30/m;

    .line 28
    .line 29
    .line 30
    move-result-object p1

    .line 31
    invoke-virtual {p0, p1}, Lql0/j;->g(Lql0/h;)V

    .line 32
    .line 33
    .line 34
    goto :goto_0

    .line 35
    :cond_0
    instance-of p2, p1, Lne0/c;

    .line 36
    .line 37
    if-eqz p2, :cond_1

    .line 38
    .line 39
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 40
    .line 41
    .line 42
    move-result-object p2

    .line 43
    move-object v0, p2

    .line 44
    check-cast v0, Lw30/m;

    .line 45
    .line 46
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 47
    .line 48
    .line 49
    move-result-object p2

    .line 50
    check-cast p2, Lw30/m;

    .line 51
    .line 52
    iget-boolean p2, p2, Lw30/m;->a:Z

    .line 53
    .line 54
    xor-int/lit8 v1, p2, 0x1

    .line 55
    .line 56
    const/4 v4, 0x0

    .line 57
    const/16 v5, 0x1a

    .line 58
    .line 59
    const/4 v2, 0x0

    .line 60
    const/4 v3, 0x0

    .line 61
    invoke-static/range {v0 .. v5}, Lw30/m;->a(Lw30/m;ZZZLql0/g;I)Lw30/m;

    .line 62
    .line 63
    .line 64
    move-result-object p2

    .line 65
    invoke-virtual {p0, p2}, Lql0/j;->g(Lql0/h;)V

    .line 66
    .line 67
    .line 68
    check-cast p1, Lne0/c;

    .line 69
    .line 70
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 71
    .line 72
    .line 73
    move-result-object p2

    .line 74
    new-instance v0, Lvu/j;

    .line 75
    .line 76
    const/16 v1, 0xb

    .line 77
    .line 78
    const/4 v2, 0x0

    .line 79
    invoke-direct {v0, v1, p0, p1, v2}, Lvu/j;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 80
    .line 81
    .line 82
    const/4 p0, 0x3

    .line 83
    invoke-static {p2, v2, v2, v0, p0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 84
    .line 85
    .line 86
    goto :goto_0

    .line 87
    :cond_1
    instance-of p1, p1, Lne0/e;

    .line 88
    .line 89
    if-eqz p1, :cond_2

    .line 90
    .line 91
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 92
    .line 93
    .line 94
    move-result-object p1

    .line 95
    move-object v0, p1

    .line 96
    check-cast v0, Lw30/m;

    .line 97
    .line 98
    const/4 v4, 0x0

    .line 99
    const/16 v5, 0xb

    .line 100
    .line 101
    const/4 v1, 0x0

    .line 102
    const/4 v2, 0x0

    .line 103
    const/4 v3, 0x0

    .line 104
    invoke-static/range {v0 .. v5}, Lw30/m;->a(Lw30/m;ZZZLql0/g;I)Lw30/m;

    .line 105
    .line 106
    .line 107
    move-result-object p1

    .line 108
    invoke-virtual {p0, p1}, Lql0/j;->g(Lql0/h;)V

    .line 109
    .line 110
    .line 111
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 112
    .line 113
    return-object p0

    .line 114
    :cond_2
    new-instance p0, La8/r0;

    .line 115
    .line 116
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 117
    .line 118
    .line 119
    throw p0

    .line 120
    :pswitch_0
    check-cast p1, Lne0/s;

    .line 121
    .line 122
    instance-of p2, p1, Lne0/e;

    .line 123
    .line 124
    iget-object p0, p0, Lw30/k;->e:Lw30/n;

    .line 125
    .line 126
    if-eqz p2, :cond_3

    .line 127
    .line 128
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 129
    .line 130
    .line 131
    move-result-object p2

    .line 132
    check-cast p2, Lw30/m;

    .line 133
    .line 134
    check-cast p1, Lne0/e;

    .line 135
    .line 136
    iget-object p1, p1, Lne0/e;->a:Ljava/lang/Object;

    .line 137
    .line 138
    check-cast p1, Lv30/d;

    .line 139
    .line 140
    iget-boolean v3, p1, Lv30/d;->a:Z

    .line 141
    .line 142
    iget-object v1, p1, Lv30/d;->b:Ljava/lang/String;

    .line 143
    .line 144
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 145
    .line 146
    .line 147
    const-string p1, "consentLink"

    .line 148
    .line 149
    invoke-static {v1, p1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 150
    .line 151
    .line 152
    new-instance v0, Lw30/m;

    .line 153
    .line 154
    const/4 v2, 0x0

    .line 155
    const/4 v4, 0x0

    .line 156
    const/4 v5, 0x0

    .line 157
    invoke-direct/range {v0 .. v5}, Lw30/m;-><init>(Ljava/lang/String;Lql0/g;ZZZ)V

    .line 158
    .line 159
    .line 160
    goto :goto_1

    .line 161
    :cond_3
    instance-of p2, p1, Lne0/c;

    .line 162
    .line 163
    if-eqz p2, :cond_4

    .line 164
    .line 165
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 166
    .line 167
    .line 168
    move-result-object p2

    .line 169
    move-object v0, p2

    .line 170
    check-cast v0, Lw30/m;

    .line 171
    .line 172
    check-cast p1, Lne0/c;

    .line 173
    .line 174
    iget-object p2, p0, Lw30/n;->h:Lij0/a;

    .line 175
    .line 176
    invoke-static {p1, p2}, Ljp/rf;->e(Lne0/c;Lij0/a;)Lql0/g;

    .line 177
    .line 178
    .line 179
    move-result-object v4

    .line 180
    const/16 v5, 0x9

    .line 181
    .line 182
    const/4 v1, 0x0

    .line 183
    const/4 v2, 0x0

    .line 184
    const/4 v3, 0x0

    .line 185
    invoke-static/range {v0 .. v5}, Lw30/m;->a(Lw30/m;ZZZLql0/g;I)Lw30/m;

    .line 186
    .line 187
    .line 188
    move-result-object v0

    .line 189
    goto :goto_1

    .line 190
    :cond_4
    instance-of p1, p1, Lne0/d;

    .line 191
    .line 192
    if-eqz p1, :cond_5

    .line 193
    .line 194
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 195
    .line 196
    .line 197
    move-result-object p1

    .line 198
    move-object v0, p1

    .line 199
    check-cast v0, Lw30/m;

    .line 200
    .line 201
    const/4 v4, 0x0

    .line 202
    const/16 v5, 0x9

    .line 203
    .line 204
    const/4 v1, 0x0

    .line 205
    const/4 v2, 0x1

    .line 206
    const/4 v3, 0x0

    .line 207
    invoke-static/range {v0 .. v5}, Lw30/m;->a(Lw30/m;ZZZLql0/g;I)Lw30/m;

    .line 208
    .line 209
    .line 210
    move-result-object v0

    .line 211
    :goto_1
    invoke-virtual {p0, v0}, Lql0/j;->g(Lql0/h;)V

    .line 212
    .line 213
    .line 214
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 215
    .line 216
    return-object p0

    .line 217
    :cond_5
    new-instance p0, La8/r0;

    .line 218
    .line 219
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 220
    .line 221
    .line 222
    throw p0

    .line 223
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
