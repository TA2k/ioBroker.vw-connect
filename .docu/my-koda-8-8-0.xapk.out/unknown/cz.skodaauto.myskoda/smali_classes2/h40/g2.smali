.class public final Lh40/g2;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public final synthetic f:Lh40/i2;


# direct methods
.method public synthetic constructor <init>(Lh40/i2;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p3, p0, Lh40/g2;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lh40/g2;->f:Lh40/i2;

    .line 4
    .line 5
    const/4 p1, 0x2

    .line 6
    invoke-direct {p0, p1, p2}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 7
    .line 8
    .line 9
    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;
    .locals 1

    .line 1
    iget p1, p0, Lh40/g2;->d:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance p1, Lh40/g2;

    .line 7
    .line 8
    iget-object p0, p0, Lh40/g2;->f:Lh40/i2;

    .line 9
    .line 10
    const/4 v0, 0x1

    .line 11
    invoke-direct {p1, p0, p2, v0}, Lh40/g2;-><init>(Lh40/i2;Lkotlin/coroutines/Continuation;I)V

    .line 12
    .line 13
    .line 14
    return-object p1

    .line 15
    :pswitch_0
    new-instance p1, Lh40/g2;

    .line 16
    .line 17
    iget-object p0, p0, Lh40/g2;->f:Lh40/i2;

    .line 18
    .line 19
    const/4 v0, 0x0

    .line 20
    invoke-direct {p1, p0, p2, v0}, Lh40/g2;-><init>(Lh40/i2;Lkotlin/coroutines/Continuation;I)V

    .line 21
    .line 22
    .line 23
    return-object p1

    .line 24
    nop

    .line 25
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Lh40/g2;->d:I

    .line 2
    .line 3
    check-cast p1, Lvy0/b0;

    .line 4
    .line 5
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 6
    .line 7
    packed-switch v0, :pswitch_data_0

    .line 8
    .line 9
    .line 10
    invoke-virtual {p0, p1, p2}, Lh40/g2;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Lh40/g2;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Lh40/g2;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    invoke-virtual {p0, p1, p2}, Lh40/g2;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    check-cast p0, Lh40/g2;

    .line 28
    .line 29
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 30
    .line 31
    invoke-virtual {p0, p1}, Lh40/g2;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    return-object p0

    .line 36
    nop

    .line 37
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 12

    .line 1
    iget v0, p0, Lh40/g2;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 7
    .line 8
    iget v1, p0, Lh40/g2;->e:I

    .line 9
    .line 10
    const/4 v2, 0x1

    .line 11
    if-eqz v1, :cond_1

    .line 12
    .line 13
    if-ne v1, v2, :cond_0

    .line 14
    .line 15
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 16
    .line 17
    .line 18
    goto :goto_0

    .line 19
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 20
    .line 21
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 22
    .line 23
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 24
    .line 25
    .line 26
    throw p0

    .line 27
    :cond_1
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 28
    .line 29
    .line 30
    iget-object p1, p0, Lh40/g2;->f:Lh40/i2;

    .line 31
    .line 32
    invoke-virtual {p1}, Lql0/j;->a()Lql0/h;

    .line 33
    .line 34
    .line 35
    move-result-object v1

    .line 36
    move-object v3, v1

    .line 37
    check-cast v3, Lh40/h2;

    .line 38
    .line 39
    const/4 v9, 0x0

    .line 40
    const/16 v10, 0x3e

    .line 41
    .line 42
    const/4 v4, 0x1

    .line 43
    const/4 v5, 0x0

    .line 44
    const/4 v6, 0x0

    .line 45
    const/4 v7, 0x0

    .line 46
    const/4 v8, 0x0

    .line 47
    invoke-static/range {v3 .. v10}, Lh40/h2;->a(Lh40/h2;ZLql0/g;ZZLjava/util/ArrayList;Lh40/l3;I)Lh40/h2;

    .line 48
    .line 49
    .line 50
    move-result-object v1

    .line 51
    invoke-virtual {p1, v1}, Lql0/j;->g(Lql0/h;)V

    .line 52
    .line 53
    .line 54
    iget-object p1, p1, Lh40/i2;->k:Lf40/s;

    .line 55
    .line 56
    invoke-static {p1}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 57
    .line 58
    .line 59
    move-result-object p1

    .line 60
    check-cast p1, Lyy0/i;

    .line 61
    .line 62
    iput v2, p0, Lh40/g2;->e:I

    .line 63
    .line 64
    invoke-static {p1, p0}, Lyy0/u;->j(Lyy0/i;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 65
    .line 66
    .line 67
    move-result-object p0

    .line 68
    if-ne p0, v0, :cond_2

    .line 69
    .line 70
    goto :goto_1

    .line 71
    :cond_2
    :goto_0
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 72
    .line 73
    :goto_1
    return-object v0

    .line 74
    :pswitch_0
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 75
    .line 76
    iget v1, p0, Lh40/g2;->e:I

    .line 77
    .line 78
    iget-object v2, p0, Lh40/g2;->f:Lh40/i2;

    .line 79
    .line 80
    const/4 v3, 0x2

    .line 81
    const/4 v4, 0x1

    .line 82
    if-eqz v1, :cond_5

    .line 83
    .line 84
    if-eq v1, v4, :cond_4

    .line 85
    .line 86
    if-ne v1, v3, :cond_3

    .line 87
    .line 88
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 89
    .line 90
    .line 91
    goto :goto_3

    .line 92
    :cond_3
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 93
    .line 94
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 95
    .line 96
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 97
    .line 98
    .line 99
    throw p0

    .line 100
    :cond_4
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 101
    .line 102
    .line 103
    goto :goto_2

    .line 104
    :cond_5
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 105
    .line 106
    .line 107
    iget-object p1, v2, Lh40/i2;->j:Lf40/j1;

    .line 108
    .line 109
    iput v4, p0, Lh40/g2;->e:I

    .line 110
    .line 111
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 112
    .line 113
    .line 114
    iget-object v9, p1, Lf40/j1;->a:Lf40/a1;

    .line 115
    .line 116
    move-object v1, v9

    .line 117
    check-cast v1, Ld40/c;

    .line 118
    .line 119
    iget-object v4, v1, Ld40/c;->d:Lyy0/l1;

    .line 120
    .line 121
    iget-object v1, v1, Ld40/c;->b:Lez0/c;

    .line 122
    .line 123
    new-instance v5, La90/r;

    .line 124
    .line 125
    const/4 v6, 0x0

    .line 126
    const/16 v7, 0x8

    .line 127
    .line 128
    const-class v8, Lf40/a1;

    .line 129
    .line 130
    const-string v10, "isDataValid"

    .line 131
    .line 132
    const-string v11, "isDataValid()Z"

    .line 133
    .line 134
    invoke-direct/range {v5 .. v11}, La90/r;-><init>(IILjava/lang/Class;Ljava/lang/Object;Ljava/lang/String;Ljava/lang/String;)V

    .line 135
    .line 136
    .line 137
    new-instance v6, Lbq0/i;

    .line 138
    .line 139
    const/4 v7, 0x0

    .line 140
    const/16 v8, 0xb

    .line 141
    .line 142
    invoke-direct {v6, p1, v7, v8}, Lbq0/i;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 143
    .line 144
    .line 145
    invoke-static {v4, v1, v5, v6}, Lbb/j0;->h(Lyy0/i;Lez0/a;Lay0/a;Lay0/k;)Lne0/n;

    .line 146
    .line 147
    .line 148
    move-result-object p1

    .line 149
    if-ne p1, v0, :cond_6

    .line 150
    .line 151
    goto :goto_4

    .line 152
    :cond_6
    :goto_2
    check-cast p1, Lyy0/i;

    .line 153
    .line 154
    new-instance v1, La60/b;

    .line 155
    .line 156
    const/16 v4, 0x18

    .line 157
    .line 158
    invoke-direct {v1, v2, v4}, La60/b;-><init>(Lql0/j;I)V

    .line 159
    .line 160
    .line 161
    iput v3, p0, Lh40/g2;->e:I

    .line 162
    .line 163
    invoke-interface {p1, v1, p0}, Lyy0/i;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 164
    .line 165
    .line 166
    move-result-object p0

    .line 167
    if-ne p0, v0, :cond_7

    .line 168
    .line 169
    goto :goto_4

    .line 170
    :cond_7
    :goto_3
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 171
    .line 172
    :goto_4
    return-object v0

    .line 173
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
