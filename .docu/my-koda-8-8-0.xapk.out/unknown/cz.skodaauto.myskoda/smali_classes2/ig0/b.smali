.class public final Lig0/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lyy0/j;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lyy0/j;

.field public final synthetic f:J


# direct methods
.method public synthetic constructor <init>(Lyy0/j;JI)V
    .locals 0

    .line 1
    iput p4, p0, Lig0/b;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lig0/b;->e:Lyy0/j;

    .line 4
    .line 5
    iput-wide p2, p0, Lig0/b;->f:J

    .line 6
    .line 7
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 8
    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final emit(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 8

    .line 1
    iget v0, p0, Lig0/b;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    instance-of v0, p2, Lig0/f;

    .line 7
    .line 8
    if-eqz v0, :cond_0

    .line 9
    .line 10
    move-object v0, p2

    .line 11
    check-cast v0, Lig0/f;

    .line 12
    .line 13
    iget v1, v0, Lig0/f;->e:I

    .line 14
    .line 15
    const/high16 v2, -0x80000000

    .line 16
    .line 17
    and-int v3, v1, v2

    .line 18
    .line 19
    if-eqz v3, :cond_0

    .line 20
    .line 21
    sub-int/2addr v1, v2

    .line 22
    iput v1, v0, Lig0/f;->e:I

    .line 23
    .line 24
    goto :goto_0

    .line 25
    :cond_0
    new-instance v0, Lig0/f;

    .line 26
    .line 27
    invoke-direct {v0, p0, p2}, Lig0/f;-><init>(Lig0/b;Lkotlin/coroutines/Continuation;)V

    .line 28
    .line 29
    .line 30
    :goto_0
    iget-object p2, v0, Lig0/f;->d:Ljava/lang/Object;

    .line 31
    .line 32
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 33
    .line 34
    iget v2, v0, Lig0/f;->e:I

    .line 35
    .line 36
    const/4 v3, 0x1

    .line 37
    if-eqz v2, :cond_2

    .line 38
    .line 39
    if-ne v2, v3, :cond_1

    .line 40
    .line 41
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 42
    .line 43
    .line 44
    goto :goto_1

    .line 45
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 46
    .line 47
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 48
    .line 49
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 50
    .line 51
    .line 52
    throw p0

    .line 53
    :cond_2
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 54
    .line 55
    .line 56
    move-object p2, p1

    .line 57
    check-cast p2, Llg0/i;

    .line 58
    .line 59
    iget-wide v4, p2, Llg0/i;->a:J

    .line 60
    .line 61
    iget-wide v6, p0, Lig0/b;->f:J

    .line 62
    .line 63
    cmp-long p2, v4, v6

    .line 64
    .line 65
    if-nez p2, :cond_3

    .line 66
    .line 67
    iput v3, v0, Lig0/f;->e:I

    .line 68
    .line 69
    iget-object p0, p0, Lig0/b;->e:Lyy0/j;

    .line 70
    .line 71
    invoke-interface {p0, p1, v0}, Lyy0/j;->emit(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 72
    .line 73
    .line 74
    move-result-object p0

    .line 75
    if-ne p0, v1, :cond_3

    .line 76
    .line 77
    goto :goto_2

    .line 78
    :cond_3
    :goto_1
    sget-object v1, Llx0/b0;->a:Llx0/b0;

    .line 79
    .line 80
    :goto_2
    return-object v1

    .line 81
    :pswitch_0
    instance-of v0, p2, Lig0/e;

    .line 82
    .line 83
    if-eqz v0, :cond_4

    .line 84
    .line 85
    move-object v0, p2

    .line 86
    check-cast v0, Lig0/e;

    .line 87
    .line 88
    iget v1, v0, Lig0/e;->e:I

    .line 89
    .line 90
    const/high16 v2, -0x80000000

    .line 91
    .line 92
    and-int v3, v1, v2

    .line 93
    .line 94
    if-eqz v3, :cond_4

    .line 95
    .line 96
    sub-int/2addr v1, v2

    .line 97
    iput v1, v0, Lig0/e;->e:I

    .line 98
    .line 99
    goto :goto_3

    .line 100
    :cond_4
    new-instance v0, Lig0/e;

    .line 101
    .line 102
    invoke-direct {v0, p0, p2}, Lig0/e;-><init>(Lig0/b;Lkotlin/coroutines/Continuation;)V

    .line 103
    .line 104
    .line 105
    :goto_3
    iget-object p2, v0, Lig0/e;->d:Ljava/lang/Object;

    .line 106
    .line 107
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 108
    .line 109
    iget v2, v0, Lig0/e;->e:I

    .line 110
    .line 111
    const/4 v3, 0x1

    .line 112
    if-eqz v2, :cond_6

    .line 113
    .line 114
    if-ne v2, v3, :cond_5

    .line 115
    .line 116
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 117
    .line 118
    .line 119
    goto :goto_4

    .line 120
    :cond_5
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 121
    .line 122
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 123
    .line 124
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 125
    .line 126
    .line 127
    throw p0

    .line 128
    :cond_6
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 129
    .line 130
    .line 131
    move-object p2, p1

    .line 132
    check-cast p2, Llg0/h;

    .line 133
    .line 134
    iget-wide v4, p2, Llg0/h;->a:J

    .line 135
    .line 136
    iget-wide v6, p0, Lig0/b;->f:J

    .line 137
    .line 138
    cmp-long p2, v4, v6

    .line 139
    .line 140
    if-nez p2, :cond_7

    .line 141
    .line 142
    iput v3, v0, Lig0/e;->e:I

    .line 143
    .line 144
    iget-object p0, p0, Lig0/b;->e:Lyy0/j;

    .line 145
    .line 146
    invoke-interface {p0, p1, v0}, Lyy0/j;->emit(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 147
    .line 148
    .line 149
    move-result-object p0

    .line 150
    if-ne p0, v1, :cond_7

    .line 151
    .line 152
    goto :goto_5

    .line 153
    :cond_7
    :goto_4
    sget-object v1, Llx0/b0;->a:Llx0/b0;

    .line 154
    .line 155
    :goto_5
    return-object v1

    .line 156
    :pswitch_1
    instance-of v0, p2, Lig0/a;

    .line 157
    .line 158
    if-eqz v0, :cond_8

    .line 159
    .line 160
    move-object v0, p2

    .line 161
    check-cast v0, Lig0/a;

    .line 162
    .line 163
    iget v1, v0, Lig0/a;->e:I

    .line 164
    .line 165
    const/high16 v2, -0x80000000

    .line 166
    .line 167
    and-int v3, v1, v2

    .line 168
    .line 169
    if-eqz v3, :cond_8

    .line 170
    .line 171
    sub-int/2addr v1, v2

    .line 172
    iput v1, v0, Lig0/a;->e:I

    .line 173
    .line 174
    goto :goto_6

    .line 175
    :cond_8
    new-instance v0, Lig0/a;

    .line 176
    .line 177
    invoke-direct {v0, p0, p2}, Lig0/a;-><init>(Lig0/b;Lkotlin/coroutines/Continuation;)V

    .line 178
    .line 179
    .line 180
    :goto_6
    iget-object p2, v0, Lig0/a;->d:Ljava/lang/Object;

    .line 181
    .line 182
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 183
    .line 184
    iget v2, v0, Lig0/a;->e:I

    .line 185
    .line 186
    const/4 v3, 0x1

    .line 187
    if-eqz v2, :cond_a

    .line 188
    .line 189
    if-ne v2, v3, :cond_9

    .line 190
    .line 191
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 192
    .line 193
    .line 194
    goto :goto_7

    .line 195
    :cond_9
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 196
    .line 197
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 198
    .line 199
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 200
    .line 201
    .line 202
    throw p0

    .line 203
    :cond_a
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 204
    .line 205
    .line 206
    move-object p2, p1

    .line 207
    check-cast p2, Llg0/g;

    .line 208
    .line 209
    iget-wide v4, p2, Llg0/g;->a:J

    .line 210
    .line 211
    iget-wide v6, p0, Lig0/b;->f:J

    .line 212
    .line 213
    cmp-long p2, v4, v6

    .line 214
    .line 215
    if-nez p2, :cond_b

    .line 216
    .line 217
    iput v3, v0, Lig0/a;->e:I

    .line 218
    .line 219
    iget-object p0, p0, Lig0/b;->e:Lyy0/j;

    .line 220
    .line 221
    invoke-interface {p0, p1, v0}, Lyy0/j;->emit(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 222
    .line 223
    .line 224
    move-result-object p0

    .line 225
    if-ne p0, v1, :cond_b

    .line 226
    .line 227
    goto :goto_8

    .line 228
    :cond_b
    :goto_7
    sget-object v1, Llx0/b0;->a:Llx0/b0;

    .line 229
    .line 230
    :goto_8
    return-object v1

    .line 231
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
