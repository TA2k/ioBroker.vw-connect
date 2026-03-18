.class public final Lla/g0;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public synthetic f:Ljava/lang/Object;

.field public final synthetic g:Lla/l0;


# direct methods
.method public synthetic constructor <init>(Lla/l0;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p3, p0, Lla/g0;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lla/g0;->g:Lla/l0;

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
    iget v0, p0, Lla/g0;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance v0, Lla/g0;

    .line 7
    .line 8
    iget-object p0, p0, Lla/g0;->g:Lla/l0;

    .line 9
    .line 10
    const/4 v1, 0x1

    .line 11
    invoke-direct {v0, p0, p2, v1}, Lla/g0;-><init>(Lla/l0;Lkotlin/coroutines/Continuation;I)V

    .line 12
    .line 13
    .line 14
    iput-object p1, v0, Lla/g0;->f:Ljava/lang/Object;

    .line 15
    .line 16
    return-object v0

    .line 17
    :pswitch_0
    new-instance v0, Lla/g0;

    .line 18
    .line 19
    iget-object p0, p0, Lla/g0;->g:Lla/l0;

    .line 20
    .line 21
    const/4 v1, 0x0

    .line 22
    invoke-direct {v0, p0, p2, v1}, Lla/g0;-><init>(Lla/l0;Lkotlin/coroutines/Continuation;I)V

    .line 23
    .line 24
    .line 25
    iput-object p1, v0, Lla/g0;->f:Ljava/lang/Object;

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
    iget v0, p0, Lla/g0;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Lla/c0;

    .line 7
    .line 8
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 9
    .line 10
    invoke-virtual {p0, p1, p2}, Lla/g0;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Lla/g0;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Lla/g0;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    check-cast p1, Lna/k;

    .line 24
    .line 25
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 26
    .line 27
    invoke-virtual {p0, p1, p2}, Lla/g0;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 28
    .line 29
    .line 30
    move-result-object p0

    .line 31
    check-cast p0, Lla/g0;

    .line 32
    .line 33
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 34
    .line 35
    invoke-virtual {p0, p1}, Lla/g0;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

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
    .locals 7

    .line 1
    iget v0, p0, Lla/g0;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 7
    .line 8
    iget v1, p0, Lla/g0;->e:I

    .line 9
    .line 10
    const/4 v2, 0x2

    .line 11
    const/4 v3, 0x1

    .line 12
    if-eqz v1, :cond_2

    .line 13
    .line 14
    if-eq v1, v3, :cond_1

    .line 15
    .line 16
    if-ne v1, v2, :cond_0

    .line 17
    .line 18
    :try_start_0
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_0
    .catch Landroid/database/SQLException; {:try_start_0 .. :try_end_0} :catch_0

    .line 19
    .line 20
    .line 21
    goto :goto_1

    .line 22
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 23
    .line 24
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 25
    .line 26
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 27
    .line 28
    .line 29
    throw p0

    .line 30
    :cond_1
    iget-object v1, p0, Lla/g0;->f:Ljava/lang/Object;

    .line 31
    .line 32
    check-cast v1, Lla/c0;

    .line 33
    .line 34
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 35
    .line 36
    .line 37
    goto :goto_0

    .line 38
    :cond_2
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 39
    .line 40
    .line 41
    iget-object p1, p0, Lla/g0;->f:Ljava/lang/Object;

    .line 42
    .line 43
    move-object v1, p1

    .line 44
    check-cast v1, Lla/c0;

    .line 45
    .line 46
    iput-object v1, p0, Lla/g0;->f:Ljava/lang/Object;

    .line 47
    .line 48
    iput v3, p0, Lla/g0;->e:I

    .line 49
    .line 50
    invoke-interface {v1, p0}, Lla/c0;->c(Lkotlin/coroutines/Continuation;)Ljava/lang/Boolean;

    .line 51
    .line 52
    .line 53
    move-result-object p1

    .line 54
    if-ne p1, v0, :cond_3

    .line 55
    .line 56
    goto :goto_3

    .line 57
    :cond_3
    :goto_0
    check-cast p1, Ljava/lang/Boolean;

    .line 58
    .line 59
    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 60
    .line 61
    .line 62
    move-result p1

    .line 63
    if-eqz p1, :cond_4

    .line 64
    .line 65
    goto :goto_2

    .line 66
    :cond_4
    :try_start_1
    sget-object p1, Lla/b0;->e:Lla/b0;

    .line 67
    .line 68
    new-instance v3, Lla/g0;

    .line 69
    .line 70
    iget-object v4, p0, Lla/g0;->g:Lla/l0;

    .line 71
    .line 72
    const/4 v5, 0x0

    .line 73
    const/4 v6, 0x0

    .line 74
    invoke-direct {v3, v4, v6, v5}, Lla/g0;-><init>(Lla/l0;Lkotlin/coroutines/Continuation;I)V

    .line 75
    .line 76
    .line 77
    iput-object v6, p0, Lla/g0;->f:Ljava/lang/Object;

    .line 78
    .line 79
    iput v2, p0, Lla/g0;->e:I

    .line 80
    .line 81
    invoke-interface {v1, p1, v3, p0}, Lla/c0;->b(Lla/b0;Lay0/n;Lrx0/i;)Ljava/lang/Object;

    .line 82
    .line 83
    .line 84
    move-result-object p1

    .line 85
    if-ne p1, v0, :cond_5

    .line 86
    .line 87
    goto :goto_3

    .line 88
    :cond_5
    :goto_1
    move-object v0, p1

    .line 89
    check-cast v0, Ljava/util/Set;
    :try_end_1
    .catch Landroid/database/SQLException; {:try_start_1 .. :try_end_1} :catch_0

    .line 90
    .line 91
    goto :goto_3

    .line 92
    :catch_0
    :goto_2
    sget-object v0, Lmx0/u;->d:Lmx0/u;

    .line 93
    .line 94
    :goto_3
    return-object v0

    .line 95
    :pswitch_0
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 96
    .line 97
    iget v1, p0, Lla/g0;->e:I

    .line 98
    .line 99
    const/4 v2, 0x1

    .line 100
    if-eqz v1, :cond_7

    .line 101
    .line 102
    if-ne v1, v2, :cond_6

    .line 103
    .line 104
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 105
    .line 106
    .line 107
    goto :goto_4

    .line 108
    :cond_6
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 109
    .line 110
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 111
    .line 112
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 113
    .line 114
    .line 115
    throw p0

    .line 116
    :cond_7
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 117
    .line 118
    .line 119
    iget-object p1, p0, Lla/g0;->f:Ljava/lang/Object;

    .line 120
    .line 121
    check-cast p1, Lna/k;

    .line 122
    .line 123
    iput v2, p0, Lla/g0;->e:I

    .line 124
    .line 125
    iget-object v1, p0, Lla/g0;->g:Lla/l0;

    .line 126
    .line 127
    invoke-static {v1, p1, p0}, Lla/l0;->a(Lla/l0;Lla/o;Lrx0/c;)Ljava/lang/Object;

    .line 128
    .line 129
    .line 130
    move-result-object p1

    .line 131
    if-ne p1, v0, :cond_8

    .line 132
    .line 133
    move-object p1, v0

    .line 134
    :cond_8
    :goto_4
    return-object p1

    .line 135
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
