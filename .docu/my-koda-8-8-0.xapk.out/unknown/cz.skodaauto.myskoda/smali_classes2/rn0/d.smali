.class public final Lrn0/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lyy0/j;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lyy0/j;

.field public final synthetic f:Lun0/a;


# direct methods
.method public synthetic constructor <init>(Lyy0/j;Lun0/a;I)V
    .locals 0

    .line 1
    iput p3, p0, Lrn0/d;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lrn0/d;->e:Lyy0/j;

    .line 4
    .line 5
    iput-object p2, p0, Lrn0/d;->f:Lun0/a;

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
    .locals 5

    .line 1
    iget v0, p0, Lrn0/d;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    instance-of v0, p2, Ltn0/c;

    .line 7
    .line 8
    if-eqz v0, :cond_0

    .line 9
    .line 10
    move-object v0, p2

    .line 11
    check-cast v0, Ltn0/c;

    .line 12
    .line 13
    iget v1, v0, Ltn0/c;->e:I

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
    iput v1, v0, Ltn0/c;->e:I

    .line 23
    .line 24
    goto :goto_0

    .line 25
    :cond_0
    new-instance v0, Ltn0/c;

    .line 26
    .line 27
    invoke-direct {v0, p0, p2}, Ltn0/c;-><init>(Lrn0/d;Lkotlin/coroutines/Continuation;)V

    .line 28
    .line 29
    .line 30
    :goto_0
    iget-object p2, v0, Ltn0/c;->d:Ljava/lang/Object;

    .line 31
    .line 32
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 33
    .line 34
    iget v2, v0, Ltn0/c;->e:I

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
    goto :goto_2

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
    check-cast p1, Ljava/util/List;

    .line 57
    .line 58
    check-cast p1, Ljava/lang/Iterable;

    .line 59
    .line 60
    invoke-interface {p1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 61
    .line 62
    .line 63
    move-result-object p1

    .line 64
    :cond_3
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 65
    .line 66
    .line 67
    move-result p2

    .line 68
    if-eqz p2, :cond_4

    .line 69
    .line 70
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 71
    .line 72
    .line 73
    move-result-object p2

    .line 74
    move-object v2, p2

    .line 75
    check-cast v2, Lun0/b;

    .line 76
    .line 77
    iget-object v2, v2, Lun0/b;->a:Lun0/a;

    .line 78
    .line 79
    iget-object v4, p0, Lrn0/d;->f:Lun0/a;

    .line 80
    .line 81
    if-ne v2, v4, :cond_3

    .line 82
    .line 83
    goto :goto_1

    .line 84
    :cond_4
    const/4 p2, 0x0

    .line 85
    :goto_1
    iput v3, v0, Ltn0/c;->e:I

    .line 86
    .line 87
    iget-object p0, p0, Lrn0/d;->e:Lyy0/j;

    .line 88
    .line 89
    invoke-interface {p0, p2, v0}, Lyy0/j;->emit(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 90
    .line 91
    .line 92
    move-result-object p0

    .line 93
    if-ne p0, v1, :cond_5

    .line 94
    .line 95
    goto :goto_3

    .line 96
    :cond_5
    :goto_2
    sget-object v1, Llx0/b0;->a:Llx0/b0;

    .line 97
    .line 98
    :goto_3
    return-object v1

    .line 99
    :pswitch_0
    instance-of v0, p2, Lrn0/g;

    .line 100
    .line 101
    if-eqz v0, :cond_6

    .line 102
    .line 103
    move-object v0, p2

    .line 104
    check-cast v0, Lrn0/g;

    .line 105
    .line 106
    iget v1, v0, Lrn0/g;->e:I

    .line 107
    .line 108
    const/high16 v2, -0x80000000

    .line 109
    .line 110
    and-int v3, v1, v2

    .line 111
    .line 112
    if-eqz v3, :cond_6

    .line 113
    .line 114
    sub-int/2addr v1, v2

    .line 115
    iput v1, v0, Lrn0/g;->e:I

    .line 116
    .line 117
    goto :goto_4

    .line 118
    :cond_6
    new-instance v0, Lrn0/g;

    .line 119
    .line 120
    invoke-direct {v0, p0, p2}, Lrn0/g;-><init>(Lrn0/d;Lkotlin/coroutines/Continuation;)V

    .line 121
    .line 122
    .line 123
    :goto_4
    iget-object p2, v0, Lrn0/g;->d:Ljava/lang/Object;

    .line 124
    .line 125
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 126
    .line 127
    iget v2, v0, Lrn0/g;->e:I

    .line 128
    .line 129
    const/4 v3, 0x1

    .line 130
    if-eqz v2, :cond_8

    .line 131
    .line 132
    if-ne v2, v3, :cond_7

    .line 133
    .line 134
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 135
    .line 136
    .line 137
    goto :goto_5

    .line 138
    :cond_7
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 139
    .line 140
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 141
    .line 142
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 143
    .line 144
    .line 145
    throw p0

    .line 146
    :cond_8
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 147
    .line 148
    .line 149
    move-object p2, p1

    .line 150
    check-cast p2, Lun0/b;

    .line 151
    .line 152
    iget-object p2, p2, Lun0/b;->a:Lun0/a;

    .line 153
    .line 154
    iget-object v2, p0, Lrn0/d;->f:Lun0/a;

    .line 155
    .line 156
    if-ne p2, v2, :cond_9

    .line 157
    .line 158
    iput v3, v0, Lrn0/g;->e:I

    .line 159
    .line 160
    iget-object p0, p0, Lrn0/d;->e:Lyy0/j;

    .line 161
    .line 162
    invoke-interface {p0, p1, v0}, Lyy0/j;->emit(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 163
    .line 164
    .line 165
    move-result-object p0

    .line 166
    if-ne p0, v1, :cond_9

    .line 167
    .line 168
    goto :goto_6

    .line 169
    :cond_9
    :goto_5
    sget-object v1, Llx0/b0;->a:Llx0/b0;

    .line 170
    .line 171
    :goto_6
    return-object v1

    .line 172
    :pswitch_1
    instance-of v0, p2, Lrn0/c;

    .line 173
    .line 174
    if-eqz v0, :cond_a

    .line 175
    .line 176
    move-object v0, p2

    .line 177
    check-cast v0, Lrn0/c;

    .line 178
    .line 179
    iget v1, v0, Lrn0/c;->e:I

    .line 180
    .line 181
    const/high16 v2, -0x80000000

    .line 182
    .line 183
    and-int v3, v1, v2

    .line 184
    .line 185
    if-eqz v3, :cond_a

    .line 186
    .line 187
    sub-int/2addr v1, v2

    .line 188
    iput v1, v0, Lrn0/c;->e:I

    .line 189
    .line 190
    goto :goto_7

    .line 191
    :cond_a
    new-instance v0, Lrn0/c;

    .line 192
    .line 193
    invoke-direct {v0, p0, p2}, Lrn0/c;-><init>(Lrn0/d;Lkotlin/coroutines/Continuation;)V

    .line 194
    .line 195
    .line 196
    :goto_7
    iget-object p2, v0, Lrn0/c;->d:Ljava/lang/Object;

    .line 197
    .line 198
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 199
    .line 200
    iget v2, v0, Lrn0/c;->e:I

    .line 201
    .line 202
    const/4 v3, 0x1

    .line 203
    if-eqz v2, :cond_c

    .line 204
    .line 205
    if-ne v2, v3, :cond_b

    .line 206
    .line 207
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 208
    .line 209
    .line 210
    goto :goto_8

    .line 211
    :cond_b
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 212
    .line 213
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 214
    .line 215
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 216
    .line 217
    .line 218
    throw p0

    .line 219
    :cond_c
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 220
    .line 221
    .line 222
    move-object p2, p1

    .line 223
    check-cast p2, Lun0/b;

    .line 224
    .line 225
    iget-object p2, p2, Lun0/b;->a:Lun0/a;

    .line 226
    .line 227
    iget-object v2, p0, Lrn0/d;->f:Lun0/a;

    .line 228
    .line 229
    if-ne p2, v2, :cond_d

    .line 230
    .line 231
    iput v3, v0, Lrn0/c;->e:I

    .line 232
    .line 233
    iget-object p0, p0, Lrn0/d;->e:Lyy0/j;

    .line 234
    .line 235
    invoke-interface {p0, p1, v0}, Lyy0/j;->emit(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 236
    .line 237
    .line 238
    move-result-object p0

    .line 239
    if-ne p0, v1, :cond_d

    .line 240
    .line 241
    goto :goto_9

    .line 242
    :cond_d
    :goto_8
    sget-object v1, Llx0/b0;->a:Llx0/b0;

    .line 243
    .line 244
    :goto_9
    return-object v1

    .line 245
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
