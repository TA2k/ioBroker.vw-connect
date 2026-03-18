.class public final Lm70/t0;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public synthetic e:Ljava/lang/Object;

.field public final synthetic f:Lm70/g1;

.field public final synthetic g:Lvy0/b0;


# direct methods
.method public synthetic constructor <init>(Lm70/g1;Lvy0/b0;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p4, p0, Lm70/t0;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lm70/t0;->f:Lm70/g1;

    .line 4
    .line 5
    iput-object p2, p0, Lm70/t0;->g:Lvy0/b0;

    .line 6
    .line 7
    const/4 p1, 0x2

    .line 8
    invoke-direct {p0, p1, p3}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 9
    .line 10
    .line 11
    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;
    .locals 3

    .line 1
    iget v0, p0, Lm70/t0;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance v0, Lm70/t0;

    .line 7
    .line 8
    iget-object v1, p0, Lm70/t0;->g:Lvy0/b0;

    .line 9
    .line 10
    const/4 v2, 0x1

    .line 11
    iget-object p0, p0, Lm70/t0;->f:Lm70/g1;

    .line 12
    .line 13
    invoke-direct {v0, p0, v1, p2, v2}, Lm70/t0;-><init>(Lm70/g1;Lvy0/b0;Lkotlin/coroutines/Continuation;I)V

    .line 14
    .line 15
    .line 16
    iput-object p1, v0, Lm70/t0;->e:Ljava/lang/Object;

    .line 17
    .line 18
    return-object v0

    .line 19
    :pswitch_0
    new-instance v0, Lm70/t0;

    .line 20
    .line 21
    iget-object v1, p0, Lm70/t0;->g:Lvy0/b0;

    .line 22
    .line 23
    const/4 v2, 0x0

    .line 24
    iget-object p0, p0, Lm70/t0;->f:Lm70/g1;

    .line 25
    .line 26
    invoke-direct {v0, p0, v1, p2, v2}, Lm70/t0;-><init>(Lm70/g1;Lvy0/b0;Lkotlin/coroutines/Continuation;I)V

    .line 27
    .line 28
    .line 29
    iput-object p1, v0, Lm70/t0;->e:Ljava/lang/Object;

    .line 30
    .line 31
    return-object v0

    .line 32
    nop

    .line 33
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Lm70/t0;->d:I

    .line 2
    .line 3
    check-cast p1, Lne0/s;

    .line 4
    .line 5
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 6
    .line 7
    packed-switch v0, :pswitch_data_0

    .line 8
    .line 9
    .line 10
    invoke-virtual {p0, p1, p2}, Lm70/t0;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Lm70/t0;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Lm70/t0;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    return-object p1

    .line 22
    :pswitch_0
    invoke-virtual {p0, p1, p2}, Lm70/t0;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 23
    .line 24
    .line 25
    move-result-object p0

    .line 26
    check-cast p0, Lm70/t0;

    .line 27
    .line 28
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 29
    .line 30
    invoke-virtual {p0, p1}, Lm70/t0;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 31
    .line 32
    .line 33
    return-object p1

    .line 34
    nop

    .line 35
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 17

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Lm70/t0;->d:I

    .line 4
    .line 5
    sget-object v2, Llx0/b0;->a:Llx0/b0;

    .line 6
    .line 7
    sget-object v3, Lne0/d;->a:Lne0/d;

    .line 8
    .line 9
    iget-object v4, v0, Lm70/t0;->f:Lm70/g1;

    .line 10
    .line 11
    const/4 v5, 0x0

    .line 12
    iget-object v6, v0, Lm70/t0;->g:Lvy0/b0;

    .line 13
    .line 14
    const/4 v7, 0x3

    .line 15
    iget-object v0, v0, Lm70/t0;->e:Ljava/lang/Object;

    .line 16
    .line 17
    check-cast v0, Lne0/s;

    .line 18
    .line 19
    packed-switch v1, :pswitch_data_0

    .line 20
    .line 21
    .line 22
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 23
    .line 24
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 25
    .line 26
    .line 27
    instance-of v1, v0, Lne0/e;

    .line 28
    .line 29
    if-eqz v1, :cond_0

    .line 30
    .line 31
    iget-object v1, v4, Lm70/g1;->v:Lkg0/d;

    .line 32
    .line 33
    check-cast v0, Lne0/e;

    .line 34
    .line 35
    iget-object v0, v0, Lne0/e;->a:Ljava/lang/Object;

    .line 36
    .line 37
    check-cast v0, Llg0/a;

    .line 38
    .line 39
    iget-wide v3, v0, Llg0/a;->a:J

    .line 40
    .line 41
    invoke-virtual {v1, v3, v4}, Lkg0/d;->a(J)Lyy0/m1;

    .line 42
    .line 43
    .line 44
    move-result-object v0

    .line 45
    invoke-static {v0, v6}, Lyy0/u;->B(Lyy0/i;Lvy0/b0;)Lvy0/x1;

    .line 46
    .line 47
    .line 48
    goto :goto_0

    .line 49
    :cond_0
    invoke-static {v0, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 50
    .line 51
    .line 52
    move-result v1

    .line 53
    if-eqz v1, :cond_1

    .line 54
    .line 55
    new-instance v0, Lm70/w0;

    .line 56
    .line 57
    const/4 v1, 0x1

    .line 58
    invoke-direct {v0, v4, v5, v1}, Lm70/w0;-><init>(Lm70/g1;Lkotlin/coroutines/Continuation;I)V

    .line 59
    .line 60
    .line 61
    invoke-static {v6, v5, v5, v0, v7}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 62
    .line 63
    .line 64
    goto :goto_0

    .line 65
    :cond_1
    instance-of v0, v0, Lne0/c;

    .line 66
    .line 67
    if-eqz v0, :cond_2

    .line 68
    .line 69
    new-instance v0, Lm70/w0;

    .line 70
    .line 71
    const/4 v1, 0x2

    .line 72
    invoke-direct {v0, v4, v5, v1}, Lm70/w0;-><init>(Lm70/g1;Lkotlin/coroutines/Continuation;I)V

    .line 73
    .line 74
    .line 75
    invoke-static {v6, v5, v5, v0, v7}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 76
    .line 77
    .line 78
    :goto_0
    return-object v2

    .line 79
    :cond_2
    new-instance v0, La8/r0;

    .line 80
    .line 81
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 82
    .line 83
    .line 84
    throw v0

    .line 85
    :pswitch_0
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 86
    .line 87
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 88
    .line 89
    .line 90
    invoke-static {v0, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 91
    .line 92
    .line 93
    move-result v1

    .line 94
    const-string v3, "<this>"

    .line 95
    .line 96
    if-eqz v1, :cond_3

    .line 97
    .line 98
    invoke-virtual {v4}, Lql0/j;->a()Lql0/h;

    .line 99
    .line 100
    .line 101
    move-result-object v0

    .line 102
    move-object v5, v0

    .line 103
    check-cast v5, Lm70/c1;

    .line 104
    .line 105
    sget-object v0, Lm70/s0;->a:Ljava/time/format/DateTimeFormatter;

    .line 106
    .line 107
    invoke-static {v5, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 108
    .line 109
    .line 110
    const/4 v15, 0x0

    .line 111
    const/16 v16, 0x3d3

    .line 112
    .line 113
    const/4 v6, 0x0

    .line 114
    const/4 v7, 0x0

    .line 115
    const/4 v8, 0x0

    .line 116
    const/4 v9, 0x1

    .line 117
    const/4 v10, 0x0

    .line 118
    sget-object v11, Lmx0/s;->d:Lmx0/s;

    .line 119
    .line 120
    const/4 v12, 0x0

    .line 121
    const/4 v13, 0x0

    .line 122
    const/4 v14, 0x0

    .line 123
    invoke-static/range {v5 .. v16}, Lm70/c1;->a(Lm70/c1;Llf0/i;Ler0/g;ZZZLjava/util/List;ZLl70/k;Ljava/lang/String;ZI)Lm70/c1;

    .line 124
    .line 125
    .line 126
    move-result-object v0

    .line 127
    invoke-virtual {v4, v0}, Lql0/j;->g(Lql0/h;)V

    .line 128
    .line 129
    .line 130
    goto :goto_1

    .line 131
    :cond_3
    instance-of v1, v0, Lne0/c;

    .line 132
    .line 133
    if-eqz v1, :cond_4

    .line 134
    .line 135
    invoke-virtual {v4}, Lql0/j;->a()Lql0/h;

    .line 136
    .line 137
    .line 138
    move-result-object v0

    .line 139
    move-object v5, v0

    .line 140
    check-cast v5, Lm70/c1;

    .line 141
    .line 142
    sget-object v0, Lm70/s0;->a:Ljava/time/format/DateTimeFormatter;

    .line 143
    .line 144
    invoke-static {v5, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 145
    .line 146
    .line 147
    const/4 v15, 0x0

    .line 148
    const/16 v16, 0x3f3

    .line 149
    .line 150
    const/4 v6, 0x0

    .line 151
    const/4 v7, 0x0

    .line 152
    const/4 v8, 0x1

    .line 153
    const/4 v9, 0x0

    .line 154
    const/4 v10, 0x0

    .line 155
    const/4 v11, 0x0

    .line 156
    const/4 v12, 0x0

    .line 157
    const/4 v13, 0x0

    .line 158
    const/4 v14, 0x0

    .line 159
    invoke-static/range {v5 .. v16}, Lm70/c1;->a(Lm70/c1;Llf0/i;Ler0/g;ZZZLjava/util/List;ZLl70/k;Ljava/lang/String;ZI)Lm70/c1;

    .line 160
    .line 161
    .line 162
    move-result-object v0

    .line 163
    invoke-virtual {v4, v0}, Lql0/j;->g(Lql0/h;)V

    .line 164
    .line 165
    .line 166
    goto :goto_1

    .line 167
    :cond_4
    instance-of v1, v0, Lne0/e;

    .line 168
    .line 169
    if-eqz v1, :cond_5

    .line 170
    .line 171
    new-instance v1, Lm70/i0;

    .line 172
    .line 173
    invoke-direct {v1, v7, v4, v0, v5}, Lm70/i0;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 174
    .line 175
    .line 176
    invoke-static {v6, v5, v5, v1, v7}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 177
    .line 178
    .line 179
    :goto_1
    return-object v2

    .line 180
    :cond_5
    new-instance v0, La8/r0;

    .line 181
    .line 182
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 183
    .line 184
    .line 185
    throw v0

    .line 186
    nop

    .line 187
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
