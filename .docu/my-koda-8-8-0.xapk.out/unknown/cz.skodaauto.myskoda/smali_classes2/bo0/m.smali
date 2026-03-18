.class public final Lbo0/m;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public final synthetic f:Lbo0/r;


# direct methods
.method public synthetic constructor <init>(Lbo0/r;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p3, p0, Lbo0/m;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lbo0/m;->f:Lbo0/r;

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
    iget p1, p0, Lbo0/m;->d:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance p1, Lbo0/m;

    .line 7
    .line 8
    iget-object p0, p0, Lbo0/m;->f:Lbo0/r;

    .line 9
    .line 10
    const/4 v0, 0x1

    .line 11
    invoke-direct {p1, p0, p2, v0}, Lbo0/m;-><init>(Lbo0/r;Lkotlin/coroutines/Continuation;I)V

    .line 12
    .line 13
    .line 14
    return-object p1

    .line 15
    :pswitch_0
    new-instance p1, Lbo0/m;

    .line 16
    .line 17
    iget-object p0, p0, Lbo0/m;->f:Lbo0/r;

    .line 18
    .line 19
    const/4 v0, 0x0

    .line 20
    invoke-direct {p1, p0, p2, v0}, Lbo0/m;-><init>(Lbo0/r;Lkotlin/coroutines/Continuation;I)V

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
    iget v0, p0, Lbo0/m;->d:I

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
    invoke-virtual {p0, p1, p2}, Lbo0/m;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Lbo0/m;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Lbo0/m;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    invoke-virtual {p0, p1, p2}, Lbo0/m;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    check-cast p0, Lbo0/m;

    .line 28
    .line 29
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 30
    .line 31
    invoke-virtual {p0, p1}, Lbo0/m;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

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
    .locals 18

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Lbo0/m;->d:I

    .line 4
    .line 5
    packed-switch v1, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 9
    .line 10
    iget v2, v0, Lbo0/m;->e:I

    .line 11
    .line 12
    sget-object v3, Llx0/b0;->a:Llx0/b0;

    .line 13
    .line 14
    const/4 v4, 0x1

    .line 15
    if-eqz v2, :cond_2

    .line 16
    .line 17
    if-ne v2, v4, :cond_1

    .line 18
    .line 19
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 20
    .line 21
    .line 22
    :cond_0
    move-object v1, v3

    .line 23
    goto :goto_1

    .line 24
    :cond_1
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 25
    .line 26
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 27
    .line 28
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 29
    .line 30
    .line 31
    throw v0

    .line 32
    :cond_2
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 33
    .line 34
    .line 35
    iget-object v2, v0, Lbo0/m;->f:Lbo0/r;

    .line 36
    .line 37
    iget-object v5, v2, Lbo0/r;->h:Lyn0/e;

    .line 38
    .line 39
    invoke-static {v5}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 40
    .line 41
    .line 42
    move-result-object v5

    .line 43
    check-cast v5, Lyy0/i;

    .line 44
    .line 45
    new-instance v6, La60/b;

    .line 46
    .line 47
    const/4 v7, 0x4

    .line 48
    invoke-direct {v6, v2, v7}, La60/b;-><init>(Lql0/j;I)V

    .line 49
    .line 50
    .line 51
    iput v4, v0, Lbo0/m;->e:I

    .line 52
    .line 53
    new-instance v2, Lwk0/o0;

    .line 54
    .line 55
    const/16 v4, 0x11

    .line 56
    .line 57
    invoke-direct {v2, v6, v4}, Lwk0/o0;-><init>(Lyy0/j;I)V

    .line 58
    .line 59
    .line 60
    invoke-interface {v5, v2, v0}, Lyy0/i;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 61
    .line 62
    .line 63
    move-result-object v0

    .line 64
    if-ne v0, v1, :cond_3

    .line 65
    .line 66
    goto :goto_0

    .line 67
    :cond_3
    move-object v0, v3

    .line 68
    :goto_0
    if-ne v0, v1, :cond_0

    .line 69
    .line 70
    :goto_1
    return-object v1

    .line 71
    :pswitch_0
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 72
    .line 73
    iget v2, v0, Lbo0/m;->e:I

    .line 74
    .line 75
    sget-object v3, Llx0/b0;->a:Llx0/b0;

    .line 76
    .line 77
    iget-object v4, v0, Lbo0/m;->f:Lbo0/r;

    .line 78
    .line 79
    const/4 v5, 0x1

    .line 80
    if-eqz v2, :cond_5

    .line 81
    .line 82
    if-ne v2, v5, :cond_4

    .line 83
    .line 84
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 85
    .line 86
    .line 87
    move-object/from16 v0, p1

    .line 88
    .line 89
    goto :goto_2

    .line 90
    :cond_4
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 91
    .line 92
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 93
    .line 94
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 95
    .line 96
    .line 97
    throw v0

    .line 98
    :cond_5
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 99
    .line 100
    .line 101
    iget-object v2, v4, Lbo0/r;->l:Lqf0/g;

    .line 102
    .line 103
    iput v5, v0, Lbo0/m;->e:I

    .line 104
    .line 105
    invoke-virtual {v2, v3, v0}, Lqf0/g;->a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 106
    .line 107
    .line 108
    move-result-object v0

    .line 109
    if-ne v0, v1, :cond_6

    .line 110
    .line 111
    goto :goto_3

    .line 112
    :cond_6
    :goto_2
    check-cast v0, Ljava/lang/Boolean;

    .line 113
    .line 114
    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 115
    .line 116
    .line 117
    move-result v15

    .line 118
    invoke-virtual {v4}, Lql0/j;->a()Lql0/h;

    .line 119
    .line 120
    .line 121
    move-result-object v0

    .line 122
    move-object v5, v0

    .line 123
    check-cast v5, Lbo0/q;

    .line 124
    .line 125
    const/16 v16, 0x0

    .line 126
    .line 127
    const/16 v17, 0x5ff

    .line 128
    .line 129
    const/4 v6, 0x0

    .line 130
    const/4 v7, 0x0

    .line 131
    const/4 v8, 0x0

    .line 132
    const/4 v9, 0x0

    .line 133
    const/4 v10, 0x0

    .line 134
    const/4 v11, 0x0

    .line 135
    const/4 v12, 0x0

    .line 136
    const/4 v13, 0x0

    .line 137
    const/4 v14, 0x0

    .line 138
    invoke-static/range {v5 .. v17}, Lbo0/q;->a(Lbo0/q;Ljava/lang/String;ZLjava/util/Set;Lbo0/p;ZZZZZZLjava/time/LocalTime;I)Lbo0/q;

    .line 139
    .line 140
    .line 141
    move-result-object v0

    .line 142
    invoke-virtual {v4, v0}, Lql0/j;->g(Lql0/h;)V

    .line 143
    .line 144
    .line 145
    move-object v1, v3

    .line 146
    :goto_3
    return-object v1

    .line 147
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
