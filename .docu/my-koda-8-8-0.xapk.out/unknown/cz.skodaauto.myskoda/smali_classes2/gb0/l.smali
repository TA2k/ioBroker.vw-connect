.class public final Lgb0/l;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# instance fields
.field public final a:Leb0/b;

.field public final b:Lgb0/c0;

.field public final c:Lif0/f0;

.field public final d:Len0/s;

.field public final e:Lrs0/b;


# direct methods
.method public constructor <init>(Leb0/b;Lgb0/c0;Lif0/f0;Len0/s;Lrs0/b;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lgb0/l;->a:Leb0/b;

    .line 5
    .line 6
    iput-object p2, p0, Lgb0/l;->b:Lgb0/c0;

    .line 7
    .line 8
    iput-object p3, p0, Lgb0/l;->c:Lif0/f0;

    .line 9
    .line 10
    iput-object p4, p0, Lgb0/l;->d:Len0/s;

    .line 11
    .line 12
    iput-object p5, p0, Lgb0/l;->e:Lrs0/b;

    .line 13
    .line 14
    return-void
.end method


# virtual methods
.method public final bridge synthetic a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Llx0/b0;

    .line 2
    .line 3
    invoke-virtual {p0, p2}, Lgb0/l;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 7

    .line 1
    instance-of v0, p1, Lgb0/k;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, Lgb0/k;

    .line 7
    .line 8
    iget v1, v0, Lgb0/k;->g:I

    .line 9
    .line 10
    const/high16 v2, -0x80000000

    .line 11
    .line 12
    and-int v3, v1, v2

    .line 13
    .line 14
    if-eqz v3, :cond_0

    .line 15
    .line 16
    sub-int/2addr v1, v2

    .line 17
    iput v1, v0, Lgb0/k;->g:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lgb0/k;

    .line 21
    .line 22
    invoke-direct {v0, p0, p1}, Lgb0/k;-><init>(Lgb0/l;Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p1, v0, Lgb0/k;->e:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lgb0/k;->g:I

    .line 30
    .line 31
    iget-object v3, p0, Lgb0/l;->d:Len0/s;

    .line 32
    .line 33
    iget-object v4, p0, Lgb0/l;->c:Lif0/f0;

    .line 34
    .line 35
    sget-object v5, Llx0/b0;->a:Llx0/b0;

    .line 36
    .line 37
    const/4 v6, 0x0

    .line 38
    packed-switch v2, :pswitch_data_0

    .line 39
    .line 40
    .line 41
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 42
    .line 43
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 44
    .line 45
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 46
    .line 47
    .line 48
    throw p0

    .line 49
    :pswitch_0
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 50
    .line 51
    .line 52
    goto/16 :goto_7

    .line 53
    .line 54
    :pswitch_1
    iget-object p0, v0, Lgb0/k;->d:Lss0/x;

    .line 55
    .line 56
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 57
    .line 58
    .line 59
    goto/16 :goto_5

    .line 60
    .line 61
    :pswitch_2
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 62
    .line 63
    .line 64
    goto/16 :goto_4

    .line 65
    .line 66
    :pswitch_3
    iget-object p0, v0, Lgb0/k;->d:Lss0/x;

    .line 67
    .line 68
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 69
    .line 70
    .line 71
    goto :goto_3

    .line 72
    :pswitch_4
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 73
    .line 74
    .line 75
    goto :goto_2

    .line 76
    :pswitch_5
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 77
    .line 78
    .line 79
    goto :goto_1

    .line 80
    :pswitch_6
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 81
    .line 82
    .line 83
    const/4 p1, 0x1

    .line 84
    iput p1, v0, Lgb0/k;->g:I

    .line 85
    .line 86
    iget-object p1, p0, Lgb0/l;->e:Lrs0/b;

    .line 87
    .line 88
    invoke-virtual {p1, v0}, Lrs0/b;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 89
    .line 90
    .line 91
    move-result-object p1

    .line 92
    if-ne p1, v1, :cond_1

    .line 93
    .line 94
    goto/16 :goto_6

    .line 95
    .line 96
    :cond_1
    :goto_1
    check-cast p1, Lne0/t;

    .line 97
    .line 98
    instance-of p1, p1, Lne0/c;

    .line 99
    .line 100
    if-eqz p1, :cond_9

    .line 101
    .line 102
    const/4 p1, 0x2

    .line 103
    iput p1, v0, Lgb0/k;->g:I

    .line 104
    .line 105
    iget-object p1, p0, Lgb0/l;->a:Leb0/b;

    .line 106
    .line 107
    invoke-virtual {p1, v0}, Leb0/b;->a(Lrx0/c;)Ljava/lang/Object;

    .line 108
    .line 109
    .line 110
    move-result-object p1

    .line 111
    if-ne p1, v1, :cond_2

    .line 112
    .line 113
    goto :goto_6

    .line 114
    :cond_2
    :goto_2
    check-cast p1, Lne0/t;

    .line 115
    .line 116
    instance-of v2, p1, Lne0/e;

    .line 117
    .line 118
    if-eqz v2, :cond_9

    .line 119
    .line 120
    check-cast p1, Lne0/e;

    .line 121
    .line 122
    iget-object p1, p1, Lne0/e;->a:Ljava/lang/Object;

    .line 123
    .line 124
    check-cast p1, Lss0/x;

    .line 125
    .line 126
    instance-of v2, p1, Lss0/k;

    .line 127
    .line 128
    iget-object p0, p0, Lgb0/l;->b:Lgb0/c0;

    .line 129
    .line 130
    if-eqz v2, :cond_5

    .line 131
    .line 132
    move-object v2, p1

    .line 133
    check-cast v2, Lss0/k;

    .line 134
    .line 135
    iget-object v2, v2, Lss0/k;->a:Ljava/lang/String;

    .line 136
    .line 137
    new-instance v3, Lss0/j0;

    .line 138
    .line 139
    invoke-direct {v3, v2}, Lss0/j0;-><init>(Ljava/lang/String;)V

    .line 140
    .line 141
    .line 142
    iput-object p1, v0, Lgb0/k;->d:Lss0/x;

    .line 143
    .line 144
    const/4 v2, 0x3

    .line 145
    iput v2, v0, Lgb0/k;->g:I

    .line 146
    .line 147
    invoke-virtual {p0, v3, v0}, Lgb0/c0;->b(Lss0/d0;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 148
    .line 149
    .line 150
    move-result-object p0

    .line 151
    if-ne p0, v1, :cond_3

    .line 152
    .line 153
    goto :goto_6

    .line 154
    :cond_3
    move-object p0, p1

    .line 155
    :goto_3
    check-cast p0, Lss0/k;

    .line 156
    .line 157
    iput-object v6, v0, Lgb0/k;->d:Lss0/x;

    .line 158
    .line 159
    const/4 p1, 0x4

    .line 160
    iput p1, v0, Lgb0/k;->g:I

    .line 161
    .line 162
    invoke-virtual {v4, p0, v0}, Lif0/f0;->f(Lss0/k;Lrx0/c;)Ljava/lang/Object;

    .line 163
    .line 164
    .line 165
    move-result-object p0

    .line 166
    if-ne p0, v1, :cond_4

    .line 167
    .line 168
    goto :goto_6

    .line 169
    :cond_4
    :goto_4
    iget-object p0, v4, Lif0/f0;->h:Lwe0/a;

    .line 170
    .line 171
    check-cast p0, Lwe0/c;

    .line 172
    .line 173
    invoke-virtual {p0}, Lwe0/c;->c()V

    .line 174
    .line 175
    .line 176
    return-object v5

    .line 177
    :cond_5
    instance-of v2, p1, Lss0/u;

    .line 178
    .line 179
    if-eqz v2, :cond_8

    .line 180
    .line 181
    move-object v2, p1

    .line 182
    check-cast v2, Lss0/u;

    .line 183
    .line 184
    iget-object v2, v2, Lss0/u;->a:Ljava/lang/String;

    .line 185
    .line 186
    new-instance v4, Lss0/g;

    .line 187
    .line 188
    invoke-direct {v4, v2}, Lss0/g;-><init>(Ljava/lang/String;)V

    .line 189
    .line 190
    .line 191
    iput-object p1, v0, Lgb0/k;->d:Lss0/x;

    .line 192
    .line 193
    const/4 v2, 0x5

    .line 194
    iput v2, v0, Lgb0/k;->g:I

    .line 195
    .line 196
    invoke-virtual {p0, v4, v0}, Lgb0/c0;->b(Lss0/d0;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 197
    .line 198
    .line 199
    move-result-object p0

    .line 200
    if-ne p0, v1, :cond_6

    .line 201
    .line 202
    goto :goto_6

    .line 203
    :cond_6
    move-object p0, p1

    .line 204
    :goto_5
    check-cast p0, Lss0/u;

    .line 205
    .line 206
    iput-object v6, v0, Lgb0/k;->d:Lss0/x;

    .line 207
    .line 208
    const/4 p1, 0x6

    .line 209
    iput p1, v0, Lgb0/k;->g:I

    .line 210
    .line 211
    invoke-virtual {v3, p0, v0}, Len0/s;->d(Lss0/u;Lrx0/c;)Ljava/lang/Object;

    .line 212
    .line 213
    .line 214
    move-result-object p0

    .line 215
    if-ne p0, v1, :cond_7

    .line 216
    .line 217
    :goto_6
    return-object v1

    .line 218
    :cond_7
    :goto_7
    iget-object p0, v3, Len0/s;->f:Lwe0/a;

    .line 219
    .line 220
    check-cast p0, Lwe0/c;

    .line 221
    .line 222
    invoke-virtual {p0}, Lwe0/c;->c()V

    .line 223
    .line 224
    .line 225
    return-object v5

    .line 226
    :cond_8
    new-instance p0, La8/r0;

    .line 227
    .line 228
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 229
    .line 230
    .line 231
    throw p0

    .line 232
    :cond_9
    return-object v5

    .line 233
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
