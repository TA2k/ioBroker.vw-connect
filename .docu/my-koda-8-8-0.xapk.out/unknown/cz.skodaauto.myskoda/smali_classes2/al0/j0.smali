.class public final Lal0/j0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lyy0/i;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lzy0/j;


# direct methods
.method public synthetic constructor <init>(Lzy0/j;I)V
    .locals 0

    .line 1
    iput p2, p0, Lal0/j0;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lal0/j0;->e:Lzy0/j;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 2

    .line 1
    iget v0, p0, Lal0/j0;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance v0, Lpt0/i;

    .line 7
    .line 8
    const/16 v1, 0x14

    .line 9
    .line 10
    invoke-direct {v0, p1, v1}, Lpt0/i;-><init>(Lyy0/j;I)V

    .line 11
    .line 12
    .line 13
    iget-object p0, p0, Lal0/j0;->e:Lzy0/j;

    .line 14
    .line 15
    invoke-virtual {p0, v0, p2}, Lzy0/f;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 16
    .line 17
    .line 18
    move-result-object p0

    .line 19
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 20
    .line 21
    if-ne p0, p1, :cond_0

    .line 22
    .line 23
    goto :goto_0

    .line 24
    :cond_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 25
    .line 26
    :goto_0
    return-object p0

    .line 27
    :pswitch_0
    new-instance v0, Lpt0/i;

    .line 28
    .line 29
    const/16 v1, 0x11

    .line 30
    .line 31
    invoke-direct {v0, p1, v1}, Lpt0/i;-><init>(Lyy0/j;I)V

    .line 32
    .line 33
    .line 34
    iget-object p0, p0, Lal0/j0;->e:Lzy0/j;

    .line 35
    .line 36
    invoke-virtual {p0, v0, p2}, Lzy0/f;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 37
    .line 38
    .line 39
    move-result-object p0

    .line 40
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 41
    .line 42
    if-ne p0, p1, :cond_1

    .line 43
    .line 44
    goto :goto_1

    .line 45
    :cond_1
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 46
    .line 47
    :goto_1
    return-object p0

    .line 48
    :pswitch_1
    new-instance v0, Lpt0/i;

    .line 49
    .line 50
    const/16 v1, 0xf

    .line 51
    .line 52
    invoke-direct {v0, p1, v1}, Lpt0/i;-><init>(Lyy0/j;I)V

    .line 53
    .line 54
    .line 55
    iget-object p0, p0, Lal0/j0;->e:Lzy0/j;

    .line 56
    .line 57
    invoke-virtual {p0, v0, p2}, Lzy0/f;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 58
    .line 59
    .line 60
    move-result-object p0

    .line 61
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 62
    .line 63
    if-ne p0, p1, :cond_2

    .line 64
    .line 65
    goto :goto_2

    .line 66
    :cond_2
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 67
    .line 68
    :goto_2
    return-object p0

    .line 69
    :pswitch_2
    new-instance v0, Lpt0/i;

    .line 70
    .line 71
    const/4 v1, 0x2

    .line 72
    invoke-direct {v0, p1, v1}, Lpt0/i;-><init>(Lyy0/j;I)V

    .line 73
    .line 74
    .line 75
    iget-object p0, p0, Lal0/j0;->e:Lzy0/j;

    .line 76
    .line 77
    invoke-virtual {p0, v0, p2}, Lzy0/f;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 78
    .line 79
    .line 80
    move-result-object p0

    .line 81
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 82
    .line 83
    if-ne p0, p1, :cond_3

    .line 84
    .line 85
    goto :goto_3

    .line 86
    :cond_3
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 87
    .line 88
    :goto_3
    return-object p0

    .line 89
    :pswitch_3
    new-instance v0, Ln50/a1;

    .line 90
    .line 91
    const/16 v1, 0x8

    .line 92
    .line 93
    invoke-direct {v0, p1, v1}, Ln50/a1;-><init>(Lyy0/j;I)V

    .line 94
    .line 95
    .line 96
    iget-object p0, p0, Lal0/j0;->e:Lzy0/j;

    .line 97
    .line 98
    invoke-virtual {p0, v0, p2}, Lzy0/f;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 99
    .line 100
    .line 101
    move-result-object p0

    .line 102
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 103
    .line 104
    if-ne p0, p1, :cond_4

    .line 105
    .line 106
    goto :goto_4

    .line 107
    :cond_4
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 108
    .line 109
    :goto_4
    return-object p0

    .line 110
    :pswitch_4
    new-instance v0, Lkf0/x;

    .line 111
    .line 112
    const/16 v1, 0x8

    .line 113
    .line 114
    invoke-direct {v0, p1, v1}, Lkf0/x;-><init>(Lyy0/j;I)V

    .line 115
    .line 116
    .line 117
    iget-object p0, p0, Lal0/j0;->e:Lzy0/j;

    .line 118
    .line 119
    invoke-virtual {p0, v0, p2}, Lzy0/f;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 120
    .line 121
    .line 122
    move-result-object p0

    .line 123
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 124
    .line 125
    if-ne p0, p1, :cond_5

    .line 126
    .line 127
    goto :goto_5

    .line 128
    :cond_5
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 129
    .line 130
    :goto_5
    return-object p0

    .line 131
    :pswitch_5
    new-instance v0, Lhg/u;

    .line 132
    .line 133
    const/4 v1, 0x7

    .line 134
    invoke-direct {v0, p1, v1}, Lhg/u;-><init>(Lyy0/j;I)V

    .line 135
    .line 136
    .line 137
    iget-object p0, p0, Lal0/j0;->e:Lzy0/j;

    .line 138
    .line 139
    invoke-virtual {p0, v0, p2}, Lzy0/f;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 140
    .line 141
    .line 142
    move-result-object p0

    .line 143
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 144
    .line 145
    if-ne p0, p1, :cond_6

    .line 146
    .line 147
    goto :goto_6

    .line 148
    :cond_6
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 149
    .line 150
    :goto_6
    return-object p0

    .line 151
    :pswitch_6
    new-instance v0, Lcs0/s;

    .line 152
    .line 153
    const/16 v1, 0x8

    .line 154
    .line 155
    invoke-direct {v0, p1, v1}, Lcs0/s;-><init>(Lyy0/j;I)V

    .line 156
    .line 157
    .line 158
    iget-object p0, p0, Lal0/j0;->e:Lzy0/j;

    .line 159
    .line 160
    invoke-virtual {p0, v0, p2}, Lzy0/f;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 161
    .line 162
    .line 163
    move-result-object p0

    .line 164
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 165
    .line 166
    if-ne p0, p1, :cond_7

    .line 167
    .line 168
    goto :goto_7

    .line 169
    :cond_7
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 170
    .line 171
    :goto_7
    return-object p0

    .line 172
    :pswitch_7
    new-instance v0, La50/g;

    .line 173
    .line 174
    const/16 v1, 0x14

    .line 175
    .line 176
    invoke-direct {v0, p1, v1}, La50/g;-><init>(Lyy0/j;I)V

    .line 177
    .line 178
    .line 179
    iget-object p0, p0, Lal0/j0;->e:Lzy0/j;

    .line 180
    .line 181
    invoke-virtual {p0, v0, p2}, Lzy0/f;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 182
    .line 183
    .line 184
    move-result-object p0

    .line 185
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 186
    .line 187
    if-ne p0, p1, :cond_8

    .line 188
    .line 189
    goto :goto_8

    .line 190
    :cond_8
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 191
    .line 192
    :goto_8
    return-object p0

    .line 193
    :pswitch_8
    new-instance v0, La50/g;

    .line 194
    .line 195
    const/16 v1, 0x13

    .line 196
    .line 197
    invoke-direct {v0, p1, v1}, La50/g;-><init>(Lyy0/j;I)V

    .line 198
    .line 199
    .line 200
    iget-object p0, p0, Lal0/j0;->e:Lzy0/j;

    .line 201
    .line 202
    invoke-virtual {p0, v0, p2}, Lzy0/f;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 203
    .line 204
    .line 205
    move-result-object p0

    .line 206
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 207
    .line 208
    if-ne p0, p1, :cond_9

    .line 209
    .line 210
    goto :goto_9

    .line 211
    :cond_9
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 212
    .line 213
    :goto_9
    return-object p0

    .line 214
    :pswitch_9
    new-instance v0, La50/g;

    .line 215
    .line 216
    const/4 v1, 0x7

    .line 217
    invoke-direct {v0, p1, v1}, La50/g;-><init>(Lyy0/j;I)V

    .line 218
    .line 219
    .line 220
    iget-object p0, p0, Lal0/j0;->e:Lzy0/j;

    .line 221
    .line 222
    invoke-virtual {p0, v0, p2}, Lzy0/f;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 223
    .line 224
    .line 225
    move-result-object p0

    .line 226
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 227
    .line 228
    if-ne p0, p1, :cond_a

    .line 229
    .line 230
    goto :goto_a

    .line 231
    :cond_a
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 232
    .line 233
    :goto_a
    return-object p0

    .line 234
    nop

    .line 235
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_9
        :pswitch_8
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
