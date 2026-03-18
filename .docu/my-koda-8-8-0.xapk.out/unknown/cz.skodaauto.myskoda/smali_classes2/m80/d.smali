.class public final Lm80/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lyy0/j;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lm80/e;


# direct methods
.method public synthetic constructor <init>(Lm80/e;I)V
    .locals 0

    .line 1
    iput p2, p0, Lm80/d;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lm80/d;->e:Lm80/e;

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
    iget p2, p0, Lm80/d;->d:I

    .line 2
    .line 3
    packed-switch p2, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Lne0/s;

    .line 7
    .line 8
    instance-of p2, p1, Lne0/c;

    .line 9
    .line 10
    iget-object p0, p0, Lm80/d;->e:Lm80/e;

    .line 11
    .line 12
    if-eqz p2, :cond_0

    .line 13
    .line 14
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 15
    .line 16
    .line 17
    move-result-object p2

    .line 18
    move-object v0, p2

    .line 19
    check-cast v0, Lm80/b;

    .line 20
    .line 21
    check-cast p1, Lne0/c;

    .line 22
    .line 23
    iget-object p2, p0, Lm80/e;->n:Lij0/a;

    .line 24
    .line 25
    invoke-static {p1, p2}, Ljp/rf;->e(Lne0/c;Lij0/a;)Lql0/g;

    .line 26
    .line 27
    .line 28
    move-result-object v4

    .line 29
    const/4 v5, 0x6

    .line 30
    const/4 v1, 0x0

    .line 31
    const/4 v2, 0x0

    .line 32
    const/4 v3, 0x0

    .line 33
    invoke-static/range {v0 .. v5}, Lm80/b;->a(Lm80/b;ZLl80/c;ZLql0/g;I)Lm80/b;

    .line 34
    .line 35
    .line 36
    move-result-object p1

    .line 37
    goto :goto_0

    .line 38
    :cond_0
    sget-object p2, Lne0/d;->a:Lne0/d;

    .line 39
    .line 40
    invoke-static {p1, p2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 41
    .line 42
    .line 43
    move-result p2

    .line 44
    if-eqz p2, :cond_1

    .line 45
    .line 46
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 47
    .line 48
    .line 49
    move-result-object p1

    .line 50
    move-object v0, p1

    .line 51
    check-cast v0, Lm80/b;

    .line 52
    .line 53
    const/4 v4, 0x0

    .line 54
    const/16 v5, 0xa

    .line 55
    .line 56
    const/4 v1, 0x1

    .line 57
    const/4 v2, 0x0

    .line 58
    const/4 v3, 0x0

    .line 59
    invoke-static/range {v0 .. v5}, Lm80/b;->a(Lm80/b;ZLl80/c;ZLql0/g;I)Lm80/b;

    .line 60
    .line 61
    .line 62
    move-result-object p1

    .line 63
    goto :goto_0

    .line 64
    :cond_1
    instance-of p1, p1, Lne0/e;

    .line 65
    .line 66
    if-eqz p1, :cond_2

    .line 67
    .line 68
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 69
    .line 70
    .line 71
    move-result-object p1

    .line 72
    move-object v0, p1

    .line 73
    check-cast v0, Lm80/b;

    .line 74
    .line 75
    const/4 v4, 0x0

    .line 76
    const/4 v5, 0x2

    .line 77
    const/4 v1, 0x0

    .line 78
    const/4 v2, 0x0

    .line 79
    const/4 v3, 0x0

    .line 80
    invoke-static/range {v0 .. v5}, Lm80/b;->a(Lm80/b;ZLl80/c;ZLql0/g;I)Lm80/b;

    .line 81
    .line 82
    .line 83
    move-result-object p1

    .line 84
    :goto_0
    invoke-virtual {p0, p1}, Lql0/j;->g(Lql0/h;)V

    .line 85
    .line 86
    .line 87
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 88
    .line 89
    return-object p0

    .line 90
    :cond_2
    new-instance p0, La8/r0;

    .line 91
    .line 92
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 93
    .line 94
    .line 95
    throw p0

    .line 96
    :pswitch_0
    check-cast p1, Lne0/s;

    .line 97
    .line 98
    instance-of p2, p1, Lne0/c;

    .line 99
    .line 100
    iget-object p0, p0, Lm80/d;->e:Lm80/e;

    .line 101
    .line 102
    if-eqz p2, :cond_3

    .line 103
    .line 104
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 105
    .line 106
    .line 107
    move-result-object p2

    .line 108
    move-object v0, p2

    .line 109
    check-cast v0, Lm80/b;

    .line 110
    .line 111
    check-cast p1, Lne0/c;

    .line 112
    .line 113
    iget-object p2, p0, Lm80/e;->n:Lij0/a;

    .line 114
    .line 115
    invoke-static {p1, p2}, Ljp/rf;->e(Lne0/c;Lij0/a;)Lql0/g;

    .line 116
    .line 117
    .line 118
    move-result-object v4

    .line 119
    const/4 v5, 0x4

    .line 120
    const/4 v1, 0x0

    .line 121
    const/4 v2, 0x0

    .line 122
    const/4 v3, 0x0

    .line 123
    invoke-static/range {v0 .. v5}, Lm80/b;->a(Lm80/b;ZLl80/c;ZLql0/g;I)Lm80/b;

    .line 124
    .line 125
    .line 126
    move-result-object p1

    .line 127
    goto :goto_1

    .line 128
    :cond_3
    sget-object p2, Lne0/d;->a:Lne0/d;

    .line 129
    .line 130
    invoke-static {p1, p2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 131
    .line 132
    .line 133
    move-result p2

    .line 134
    if-eqz p2, :cond_4

    .line 135
    .line 136
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 137
    .line 138
    .line 139
    move-result-object p1

    .line 140
    move-object v0, p1

    .line 141
    check-cast v0, Lm80/b;

    .line 142
    .line 143
    const/4 v4, 0x0

    .line 144
    const/16 v5, 0xc

    .line 145
    .line 146
    const/4 v1, 0x1

    .line 147
    const/4 v2, 0x0

    .line 148
    const/4 v3, 0x0

    .line 149
    invoke-static/range {v0 .. v5}, Lm80/b;->a(Lm80/b;ZLl80/c;ZLql0/g;I)Lm80/b;

    .line 150
    .line 151
    .line 152
    move-result-object p1

    .line 153
    goto :goto_1

    .line 154
    :cond_4
    instance-of p2, p1, Lne0/e;

    .line 155
    .line 156
    if-eqz p2, :cond_7

    .line 157
    .line 158
    check-cast p1, Lne0/e;

    .line 159
    .line 160
    iget-object p1, p1, Lne0/e;->a:Ljava/lang/Object;

    .line 161
    .line 162
    move-object v2, p1

    .line 163
    check-cast v2, Ll80/c;

    .line 164
    .line 165
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 166
    .line 167
    .line 168
    iget-object p1, v2, Ll80/c;->a:Ll80/b;

    .line 169
    .line 170
    sget-object p2, Ll80/b;->e:Ll80/b;

    .line 171
    .line 172
    if-ne p1, p2, :cond_5

    .line 173
    .line 174
    iget-object p1, p0, Lm80/e;->j:Lk80/e;

    .line 175
    .line 176
    invoke-static {p1}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 177
    .line 178
    .line 179
    :cond_5
    iget-object p1, v2, Ll80/c;->b:Ll80/a;

    .line 180
    .line 181
    if-nez p1, :cond_6

    .line 182
    .line 183
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 184
    .line 185
    .line 186
    move-result-object p1

    .line 187
    new-instance p2, Lm80/a;

    .line 188
    .line 189
    const/4 v0, 0x1

    .line 190
    const/4 v1, 0x0

    .line 191
    invoke-direct {p2, p0, v1, v0}, Lm80/a;-><init>(Lm80/e;Lkotlin/coroutines/Continuation;I)V

    .line 192
    .line 193
    .line 194
    const/4 v0, 0x3

    .line 195
    invoke-static {p1, v1, v1, p2, v0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 196
    .line 197
    .line 198
    :cond_6
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 199
    .line 200
    .line 201
    move-result-object p1

    .line 202
    move-object v0, p1

    .line 203
    check-cast v0, Lm80/b;

    .line 204
    .line 205
    const/4 v4, 0x0

    .line 206
    const/16 v5, 0xc

    .line 207
    .line 208
    const/4 v1, 0x0

    .line 209
    const/4 v3, 0x0

    .line 210
    invoke-static/range {v0 .. v5}, Lm80/b;->a(Lm80/b;ZLl80/c;ZLql0/g;I)Lm80/b;

    .line 211
    .line 212
    .line 213
    move-result-object p1

    .line 214
    :goto_1
    invoke-virtual {p0, p1}, Lql0/j;->g(Lql0/h;)V

    .line 215
    .line 216
    .line 217
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 218
    .line 219
    return-object p0

    .line 220
    :cond_7
    new-instance p0, La8/r0;

    .line 221
    .line 222
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 223
    .line 224
    .line 225
    throw p0

    .line 226
    nop

    .line 227
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
