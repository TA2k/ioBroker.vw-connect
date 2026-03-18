.class public final Lnz/f;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public synthetic f:Ljava/lang/Object;

.field public final synthetic g:Lnz/j;


# direct methods
.method public synthetic constructor <init>(Lnz/j;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p3, p0, Lnz/f;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lnz/f;->g:Lnz/j;

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
    .locals 2

    .line 1
    iget v0, p0, Lnz/f;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance v0, Lnz/f;

    .line 7
    .line 8
    iget-object p0, p0, Lnz/f;->g:Lnz/j;

    .line 9
    .line 10
    const/4 v1, 0x1

    .line 11
    invoke-direct {v0, p0, p2, v1}, Lnz/f;-><init>(Lnz/j;Lkotlin/coroutines/Continuation;I)V

    .line 12
    .line 13
    .line 14
    iput-object p1, v0, Lnz/f;->f:Ljava/lang/Object;

    .line 15
    .line 16
    return-object v0

    .line 17
    :pswitch_0
    new-instance v0, Lnz/f;

    .line 18
    .line 19
    iget-object p0, p0, Lnz/f;->g:Lnz/j;

    .line 20
    .line 21
    const/4 v1, 0x0

    .line 22
    invoke-direct {v0, p0, p2, v1}, Lnz/f;-><init>(Lnz/j;Lkotlin/coroutines/Continuation;I)V

    .line 23
    .line 24
    .line 25
    iput-object p1, v0, Lnz/f;->f:Ljava/lang/Object;

    .line 26
    .line 27
    return-object v0

    .line 28
    nop

    .line 29
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Lnz/f;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Lvy0/b0;

    .line 7
    .line 8
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 9
    .line 10
    invoke-virtual {p0, p1, p2}, Lnz/f;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Lnz/f;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Lnz/f;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    check-cast p1, Llx0/l;

    .line 24
    .line 25
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 26
    .line 27
    invoke-virtual {p0, p1, p2}, Lnz/f;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 28
    .line 29
    .line 30
    move-result-object p0

    .line 31
    check-cast p0, Lnz/f;

    .line 32
    .line 33
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 34
    .line 35
    invoke-virtual {p0, p1}, Lnz/f;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 36
    .line 37
    .line 38
    move-result-object p0

    .line 39
    return-object p0

    .line 40
    nop

    .line 41
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 10

    .line 1
    iget v0, p0, Lnz/f;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lnz/f;->f:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast v0, Lvy0/b0;

    .line 9
    .line 10
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 11
    .line 12
    iget v2, p0, Lnz/f;->e:I

    .line 13
    .line 14
    const/4 v3, 0x1

    .line 15
    iget-object v4, p0, Lnz/f;->g:Lnz/j;

    .line 16
    .line 17
    if-eqz v2, :cond_1

    .line 18
    .line 19
    if-ne v2, v3, :cond_0

    .line 20
    .line 21
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 22
    .line 23
    .line 24
    goto :goto_0

    .line 25
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 26
    .line 27
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 28
    .line 29
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 30
    .line 31
    .line 32
    throw p0

    .line 33
    :cond_1
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 34
    .line 35
    .line 36
    new-instance p1, Lnz/a;

    .line 37
    .line 38
    const/4 v2, 0x3

    .line 39
    invoke-direct {p1, v4, v2}, Lnz/a;-><init>(Lnz/j;I)V

    .line 40
    .line 41
    .line 42
    invoke-static {v0, p1}, Llp/nd;->h(Ljava/lang/Object;Lay0/a;)V

    .line 43
    .line 44
    .line 45
    iget-object p1, v4, Lnz/j;->n:Llz/s;

    .line 46
    .line 47
    const/4 v0, 0x0

    .line 48
    iput-object v0, p0, Lnz/f;->f:Ljava/lang/Object;

    .line 49
    .line 50
    iput v3, p0, Lnz/f;->e:I

    .line 51
    .line 52
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 53
    .line 54
    .line 55
    invoke-virtual {p1, p0}, Llz/s;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 56
    .line 57
    .line 58
    move-result-object p1

    .line 59
    if-ne p1, v1, :cond_2

    .line 60
    .line 61
    goto :goto_1

    .line 62
    :cond_2
    :goto_0
    check-cast p1, Lne0/t;

    .line 63
    .line 64
    instance-of p0, p1, Lne0/e;

    .line 65
    .line 66
    sget-object v1, Llx0/b0;->a:Llx0/b0;

    .line 67
    .line 68
    if-eqz p0, :cond_3

    .line 69
    .line 70
    check-cast p1, Lne0/e;

    .line 71
    .line 72
    iget-object p0, p1, Lne0/e;->a:Ljava/lang/Object;

    .line 73
    .line 74
    check-cast p0, Llx0/b0;

    .line 75
    .line 76
    invoke-virtual {v4}, Lql0/j;->a()Lql0/h;

    .line 77
    .line 78
    .line 79
    move-result-object p0

    .line 80
    check-cast p0, Lnz/e;

    .line 81
    .line 82
    iget-object p1, v4, Lnz/j;->l:Lij0/a;

    .line 83
    .line 84
    const/4 v0, 0x0

    .line 85
    invoke-static {p0, p1, v0}, Ljp/db;->g(Lnz/e;Lij0/a;Z)Lnz/e;

    .line 86
    .line 87
    .line 88
    move-result-object p0

    .line 89
    invoke-virtual {v4, p0}, Lql0/j;->g(Lql0/h;)V

    .line 90
    .line 91
    .line 92
    :cond_3
    :goto_1
    return-object v1

    .line 93
    :pswitch_0
    iget-object v0, p0, Lnz/f;->f:Ljava/lang/Object;

    .line 94
    .line 95
    check-cast v0, Llx0/l;

    .line 96
    .line 97
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 98
    .line 99
    iget v2, p0, Lnz/f;->e:I

    .line 100
    .line 101
    const/4 v3, 0x1

    .line 102
    if-eqz v2, :cond_5

    .line 103
    .line 104
    if-ne v2, v3, :cond_4

    .line 105
    .line 106
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 107
    .line 108
    .line 109
    goto :goto_2

    .line 110
    :cond_4
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 111
    .line 112
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 113
    .line 114
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 115
    .line 116
    .line 117
    throw p0

    .line 118
    :cond_5
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 119
    .line 120
    .line 121
    iget-object p1, v0, Llx0/l;->d:Ljava/lang/Object;

    .line 122
    .line 123
    move-object v7, p1

    .line 124
    check-cast v7, Lne0/s;

    .line 125
    .line 126
    iget-object p1, v0, Llx0/l;->e:Ljava/lang/Object;

    .line 127
    .line 128
    move-object v8, p1

    .line 129
    check-cast v8, Ljava/util/List;

    .line 130
    .line 131
    new-instance v4, Lh7/z;

    .line 132
    .line 133
    iget-object v6, p0, Lnz/f;->g:Lnz/j;

    .line 134
    .line 135
    const/16 v5, 0xf

    .line 136
    .line 137
    const/4 v9, 0x0

    .line 138
    invoke-direct/range {v4 .. v9}, Lh7/z;-><init>(ILjava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 139
    .line 140
    .line 141
    iput-object v9, p0, Lnz/f;->f:Ljava/lang/Object;

    .line 142
    .line 143
    iput v3, p0, Lnz/f;->e:I

    .line 144
    .line 145
    invoke-static {v4, p0}, Lvy0/e0;->o(Lay0/n;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 146
    .line 147
    .line 148
    move-result-object p0

    .line 149
    if-ne p0, v1, :cond_6

    .line 150
    .line 151
    goto :goto_3

    .line 152
    :cond_6
    :goto_2
    sget-object v1, Llx0/b0;->a:Llx0/b0;

    .line 153
    .line 154
    :goto_3
    return-object v1

    .line 155
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
