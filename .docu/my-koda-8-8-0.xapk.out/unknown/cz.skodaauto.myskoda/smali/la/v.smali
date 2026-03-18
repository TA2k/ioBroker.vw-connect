.class public final Lla/v;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public final synthetic f:Lla/u;

.field public final synthetic g:Lay0/k;


# direct methods
.method public synthetic constructor <init>(ILay0/k;Lkotlin/coroutines/Continuation;Lla/u;)V
    .locals 0

    .line 1
    iput p1, p0, Lla/v;->d:I

    .line 2
    .line 3
    iput-object p4, p0, Lla/v;->f:Lla/u;

    .line 4
    .line 5
    iput-object p2, p0, Lla/v;->g:Lay0/k;

    .line 6
    .line 7
    const/4 p1, 0x1

    .line 8
    invoke-direct {p0, p1, p3}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 9
    .line 10
    .line 11
    return-void
.end method


# virtual methods
.method public final create(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;
    .locals 3

    .line 1
    iget v0, p0, Lla/v;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance v0, Lla/v;

    .line 7
    .line 8
    iget-object v1, p0, Lla/v;->g:Lay0/k;

    .line 9
    .line 10
    const/4 v2, 0x1

    .line 11
    iget-object p0, p0, Lla/v;->f:Lla/u;

    .line 12
    .line 13
    invoke-direct {v0, v2, v1, p1, p0}, Lla/v;-><init>(ILay0/k;Lkotlin/coroutines/Continuation;Lla/u;)V

    .line 14
    .line 15
    .line 16
    return-object v0

    .line 17
    :pswitch_0
    new-instance v0, Lla/v;

    .line 18
    .line 19
    iget-object v1, p0, Lla/v;->g:Lay0/k;

    .line 20
    .line 21
    const/4 v2, 0x0

    .line 22
    iget-object p0, p0, Lla/v;->f:Lla/u;

    .line 23
    .line 24
    invoke-direct {v0, v2, v1, p1, p0}, Lla/v;-><init>(ILay0/k;Lkotlin/coroutines/Continuation;Lla/u;)V

    .line 25
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

.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Lla/v;->d:I

    .line 2
    .line 3
    check-cast p1, Lkotlin/coroutines/Continuation;

    .line 4
    .line 5
    packed-switch v0, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    invoke-virtual {p0, p1}, Lla/v;->create(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    check-cast p0, Lla/v;

    .line 13
    .line 14
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 15
    .line 16
    invoke-virtual {p0, p1}, Lla/v;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 17
    .line 18
    .line 19
    move-result-object p0

    .line 20
    return-object p0

    .line 21
    :pswitch_0
    invoke-virtual {p0, p1}, Lla/v;->create(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 22
    .line 23
    .line 24
    move-result-object p0

    .line 25
    check-cast p0, Lla/v;

    .line 26
    .line 27
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 28
    .line 29
    invoke-virtual {p0, p1}, Lla/v;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 30
    .line 31
    .line 32
    move-result-object p0

    .line 33
    return-object p0

    .line 34
    nop

    .line 35
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 6

    .line 1
    iget v0, p0, Lla/v;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 7
    .line 8
    iget v1, p0, Lla/v;->e:I

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
    new-instance p1, Lqa/e;

    .line 31
    .line 32
    const/4 v1, 0x0

    .line 33
    const/4 v3, 0x0

    .line 34
    iget-object v4, p0, Lla/v;->g:Lay0/k;

    .line 35
    .line 36
    iget-object v5, p0, Lla/v;->f:Lla/u;

    .line 37
    .line 38
    invoke-direct {p1, v3, v4, v1, v5}, Lqa/e;-><init>(ILay0/k;Lkotlin/coroutines/Continuation;Lla/u;)V

    .line 39
    .line 40
    .line 41
    iput v2, p0, Lla/v;->e:I

    .line 42
    .line 43
    const/4 v1, 0x0

    .line 44
    invoke-virtual {v5, v1, p1, p0}, Lla/u;->r(ZLay0/n;Lrx0/c;)Ljava/lang/Object;

    .line 45
    .line 46
    .line 47
    move-result-object p1

    .line 48
    if-ne p1, v0, :cond_2

    .line 49
    .line 50
    move-object p1, v0

    .line 51
    :cond_2
    :goto_0
    return-object p1

    .line 52
    :pswitch_0
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 53
    .line 54
    iget v1, p0, Lla/v;->e:I

    .line 55
    .line 56
    const/4 v2, 0x1

    .line 57
    iget-object v3, p0, Lla/v;->f:Lla/u;

    .line 58
    .line 59
    if-eqz v1, :cond_4

    .line 60
    .line 61
    if-ne v1, v2, :cond_3

    .line 62
    .line 63
    :try_start_0
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 64
    .line 65
    .line 66
    goto :goto_1

    .line 67
    :catchall_0
    move-exception p0

    .line 68
    goto :goto_3

    .line 69
    :cond_3
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 70
    .line 71
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 72
    .line 73
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 74
    .line 75
    .line 76
    throw p0

    .line 77
    :cond_4
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 78
    .line 79
    .line 80
    invoke-virtual {v3}, Lla/u;->c()V

    .line 81
    .line 82
    .line 83
    :try_start_1
    iget-object p1, p0, Lla/v;->g:Lay0/k;

    .line 84
    .line 85
    iput v2, p0, Lla/v;->e:I

    .line 86
    .line 87
    invoke-interface {p1, p0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 88
    .line 89
    .line 90
    move-result-object p1

    .line 91
    if-ne p1, v0, :cond_5

    .line 92
    .line 93
    goto :goto_2

    .line 94
    :cond_5
    :goto_1
    invoke-virtual {v3}, Lla/u;->q()V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 95
    .line 96
    .line 97
    invoke-virtual {v3}, Lla/u;->g()V

    .line 98
    .line 99
    .line 100
    move-object v0, p1

    .line 101
    :goto_2
    return-object v0

    .line 102
    :goto_3
    invoke-virtual {v3}, Lla/u;->g()V

    .line 103
    .line 104
    .line 105
    throw p0

    .line 106
    nop

    .line 107
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
