.class public final Lg60/a;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public synthetic f:Ljava/lang/Object;

.field public final synthetic g:Lg60/i;


# direct methods
.method public synthetic constructor <init>(Lg60/i;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p3, p0, Lg60/a;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lg60/a;->g:Lg60/i;

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
    iget v0, p0, Lg60/a;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance v0, Lg60/a;

    .line 7
    .line 8
    iget-object p0, p0, Lg60/a;->g:Lg60/i;

    .line 9
    .line 10
    const/4 v1, 0x1

    .line 11
    invoke-direct {v0, p0, p2, v1}, Lg60/a;-><init>(Lg60/i;Lkotlin/coroutines/Continuation;I)V

    .line 12
    .line 13
    .line 14
    iput-object p1, v0, Lg60/a;->f:Ljava/lang/Object;

    .line 15
    .line 16
    return-object v0

    .line 17
    :pswitch_0
    new-instance v0, Lg60/a;

    .line 18
    .line 19
    iget-object p0, p0, Lg60/a;->g:Lg60/i;

    .line 20
    .line 21
    const/4 v1, 0x0

    .line 22
    invoke-direct {v0, p0, p2, v1}, Lg60/a;-><init>(Lg60/i;Lkotlin/coroutines/Continuation;I)V

    .line 23
    .line 24
    .line 25
    iput-object p1, v0, Lg60/a;->f:Ljava/lang/Object;

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
    iget v0, p0, Lg60/a;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Lne0/c;

    .line 7
    .line 8
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 9
    .line 10
    invoke-virtual {p0, p1, p2}, Lg60/a;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Lg60/a;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Lg60/a;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

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
    invoke-virtual {p0, p1, p2}, Lg60/a;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 28
    .line 29
    .line 30
    move-result-object p0

    .line 31
    check-cast p0, Lg60/a;

    .line 32
    .line 33
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 34
    .line 35
    invoke-virtual {p0, p1}, Lg60/a;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

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
    .locals 16

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Lg60/a;->d:I

    .line 4
    .line 5
    packed-switch v1, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    iget-object v1, v0, Lg60/a;->f:Ljava/lang/Object;

    .line 9
    .line 10
    check-cast v1, Lne0/c;

    .line 11
    .line 12
    sget-object v2, Lqx0/a;->d:Lqx0/a;

    .line 13
    .line 14
    iget v3, v0, Lg60/a;->e:I

    .line 15
    .line 16
    const/4 v4, 0x1

    .line 17
    iget-object v5, v0, Lg60/a;->g:Lg60/i;

    .line 18
    .line 19
    if-eqz v3, :cond_1

    .line 20
    .line 21
    if-ne v3, v4, :cond_0

    .line 22
    .line 23
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 24
    .line 25
    .line 26
    goto :goto_0

    .line 27
    :cond_0
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 28
    .line 29
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 30
    .line 31
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 32
    .line 33
    .line 34
    throw v0

    .line 35
    :cond_1
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 36
    .line 37
    .line 38
    iget-object v3, v5, Lg60/i;->l:Lko0/f;

    .line 39
    .line 40
    const/4 v6, 0x0

    .line 41
    iput-object v6, v0, Lg60/a;->f:Ljava/lang/Object;

    .line 42
    .line 43
    iput v4, v0, Lg60/a;->e:I

    .line 44
    .line 45
    invoke-virtual {v3, v1, v0}, Lko0/f;->b(Lne0/c;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 46
    .line 47
    .line 48
    move-result-object v0

    .line 49
    if-ne v0, v2, :cond_2

    .line 50
    .line 51
    goto :goto_1

    .line 52
    :cond_2
    :goto_0
    invoke-virtual {v5}, Lql0/j;->a()Lql0/h;

    .line 53
    .line 54
    .line 55
    move-result-object v0

    .line 56
    move-object v6, v0

    .line 57
    check-cast v6, Lg60/e;

    .line 58
    .line 59
    invoke-virtual {v5}, Lql0/j;->a()Lql0/h;

    .line 60
    .line 61
    .line 62
    move-result-object v0

    .line 63
    check-cast v0, Lg60/e;

    .line 64
    .line 65
    iget-object v0, v0, Lg60/e;->d:Lg60/c;

    .line 66
    .line 67
    const/4 v1, 0x0

    .line 68
    invoke-static {v0, v1, v1}, Lg60/c;->a(Lg60/c;ZZ)Lg60/c;

    .line 69
    .line 70
    .line 71
    move-result-object v9

    .line 72
    const/4 v14, 0x0

    .line 73
    const/16 v15, 0x1f7

    .line 74
    .line 75
    const/4 v7, 0x0

    .line 76
    const/4 v8, 0x0

    .line 77
    const/4 v10, 0x0

    .line 78
    const/4 v11, 0x0

    .line 79
    const/4 v12, 0x0

    .line 80
    const/4 v13, 0x0

    .line 81
    invoke-static/range {v6 .. v15}, Lg60/e;->a(Lg60/e;ZZLg60/c;ZLg60/d;Lql0/g;ZZI)Lg60/e;

    .line 82
    .line 83
    .line 84
    move-result-object v0

    .line 85
    invoke-virtual {v5, v0}, Lql0/j;->g(Lql0/h;)V

    .line 86
    .line 87
    .line 88
    sget-object v2, Llx0/b0;->a:Llx0/b0;

    .line 89
    .line 90
    :goto_1
    return-object v2

    .line 91
    :pswitch_0
    iget-object v1, v0, Lg60/a;->f:Ljava/lang/Object;

    .line 92
    .line 93
    check-cast v1, Llx0/l;

    .line 94
    .line 95
    sget-object v2, Lqx0/a;->d:Lqx0/a;

    .line 96
    .line 97
    iget v3, v0, Lg60/a;->e:I

    .line 98
    .line 99
    const/4 v4, 0x1

    .line 100
    if-eqz v3, :cond_4

    .line 101
    .line 102
    if-ne v3, v4, :cond_3

    .line 103
    .line 104
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 105
    .line 106
    .line 107
    goto :goto_2

    .line 108
    :cond_3
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 109
    .line 110
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 111
    .line 112
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 113
    .line 114
    .line 115
    throw v0

    .line 116
    :cond_4
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 117
    .line 118
    .line 119
    iget-object v3, v1, Llx0/l;->d:Ljava/lang/Object;

    .line 120
    .line 121
    check-cast v3, Lne0/s;

    .line 122
    .line 123
    iget-object v1, v1, Llx0/l;->e:Ljava/lang/Object;

    .line 124
    .line 125
    check-cast v1, Lcn0/c;

    .line 126
    .line 127
    const/4 v5, 0x0

    .line 128
    iput-object v5, v0, Lg60/a;->f:Ljava/lang/Object;

    .line 129
    .line 130
    iput v4, v0, Lg60/a;->e:I

    .line 131
    .line 132
    iget-object v4, v0, Lg60/a;->g:Lg60/i;

    .line 133
    .line 134
    invoke-static {v4, v3, v1, v0}, Lg60/i;->j(Lg60/i;Lne0/s;Lcn0/c;Lrx0/c;)Ljava/lang/Object;

    .line 135
    .line 136
    .line 137
    move-result-object v0

    .line 138
    if-ne v0, v2, :cond_5

    .line 139
    .line 140
    goto :goto_3

    .line 141
    :cond_5
    :goto_2
    sget-object v2, Llx0/b0;->a:Llx0/b0;

    .line 142
    .line 143
    :goto_3
    return-object v2

    .line 144
    nop

    .line 145
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
