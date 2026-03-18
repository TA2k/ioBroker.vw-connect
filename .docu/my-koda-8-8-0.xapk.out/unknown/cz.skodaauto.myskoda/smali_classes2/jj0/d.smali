.class public final Ljj0/d;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public final synthetic f:Lcz/skodaauto/myskoda/app/main/system/MainActivity;

.field public final synthetic g:Ljj0/e;


# direct methods
.method public synthetic constructor <init>(Lcz/skodaauto/myskoda/app/main/system/MainActivity;Ljj0/e;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p4, p0, Ljj0/d;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Ljj0/d;->f:Lcz/skodaauto/myskoda/app/main/system/MainActivity;

    .line 4
    .line 5
    iput-object p2, p0, Ljj0/d;->g:Ljj0/e;

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
    .locals 2

    .line 1
    iget p1, p0, Ljj0/d;->d:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance p1, Ljj0/d;

    .line 7
    .line 8
    iget-object v0, p0, Ljj0/d;->g:Ljj0/e;

    .line 9
    .line 10
    const/4 v1, 0x1

    .line 11
    iget-object p0, p0, Ljj0/d;->f:Lcz/skodaauto/myskoda/app/main/system/MainActivity;

    .line 12
    .line 13
    invoke-direct {p1, p0, v0, p2, v1}, Ljj0/d;-><init>(Lcz/skodaauto/myskoda/app/main/system/MainActivity;Ljj0/e;Lkotlin/coroutines/Continuation;I)V

    .line 14
    .line 15
    .line 16
    return-object p1

    .line 17
    :pswitch_0
    new-instance p1, Ljj0/d;

    .line 18
    .line 19
    iget-object v0, p0, Ljj0/d;->g:Ljj0/e;

    .line 20
    .line 21
    const/4 v1, 0x0

    .line 22
    iget-object p0, p0, Ljj0/d;->f:Lcz/skodaauto/myskoda/app/main/system/MainActivity;

    .line 23
    .line 24
    invoke-direct {p1, p0, v0, p2, v1}, Ljj0/d;-><init>(Lcz/skodaauto/myskoda/app/main/system/MainActivity;Ljj0/e;Lkotlin/coroutines/Continuation;I)V

    .line 25
    .line 26
    .line 27
    return-object p1

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
    iget v0, p0, Ljj0/d;->d:I

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
    invoke-virtual {p0, p1, p2}, Ljj0/d;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Ljj0/d;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Ljj0/d;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    invoke-virtual {p0, p1, p2}, Ljj0/d;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    check-cast p0, Ljj0/d;

    .line 28
    .line 29
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 30
    .line 31
    invoke-virtual {p0, p1}, Ljj0/d;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

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
    .locals 8

    .line 1
    iget v0, p0, Ljj0/d;->d:I

    .line 2
    .line 3
    sget-object v1, Llx0/b0;->a:Llx0/b0;

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    iget-object v3, p0, Ljj0/d;->g:Ljj0/e;

    .line 7
    .line 8
    iget-object v4, p0, Ljj0/d;->f:Lcz/skodaauto/myskoda/app/main/system/MainActivity;

    .line 9
    .line 10
    const-string v5, "call to \'resume\' before \'invoke\' with coroutine"

    .line 11
    .line 12
    const/4 v6, 0x1

    .line 13
    packed-switch v0, :pswitch_data_0

    .line 14
    .line 15
    .line 16
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 17
    .line 18
    iget v7, p0, Ljj0/d;->e:I

    .line 19
    .line 20
    if-eqz v7, :cond_1

    .line 21
    .line 22
    if-ne v7, v6, :cond_0

    .line 23
    .line 24
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 25
    .line 26
    .line 27
    goto :goto_0

    .line 28
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 29
    .line 30
    invoke-direct {p0, v5}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 31
    .line 32
    .line 33
    throw p0

    .line 34
    :cond_1
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 35
    .line 36
    .line 37
    sget-object p1, Landroidx/lifecycle/q;->d:Landroidx/lifecycle/q;

    .line 38
    .line 39
    new-instance p1, Ljj0/b;

    .line 40
    .line 41
    const/4 v5, 0x2

    .line 42
    invoke-direct {p1, v3, v2, v5}, Ljj0/b;-><init>(Ljj0/e;Lkotlin/coroutines/Continuation;I)V

    .line 43
    .line 44
    .line 45
    iput v6, p0, Ljj0/d;->e:I

    .line 46
    .line 47
    invoke-static {v4, p1, p0}, Landroidx/lifecycle/v0;->k(Landroidx/lifecycle/x;Lay0/n;Lrx0/i;)Ljava/lang/Object;

    .line 48
    .line 49
    .line 50
    move-result-object p0

    .line 51
    if-ne p0, v0, :cond_2

    .line 52
    .line 53
    move-object v1, v0

    .line 54
    :cond_2
    :goto_0
    return-object v1

    .line 55
    :pswitch_0
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 56
    .line 57
    iget v7, p0, Ljj0/d;->e:I

    .line 58
    .line 59
    if-eqz v7, :cond_4

    .line 60
    .line 61
    if-ne v7, v6, :cond_3

    .line 62
    .line 63
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 64
    .line 65
    .line 66
    goto :goto_1

    .line 67
    :cond_3
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 68
    .line 69
    invoke-direct {p0, v5}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 70
    .line 71
    .line 72
    throw p0

    .line 73
    :cond_4
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 74
    .line 75
    .line 76
    sget-object p1, Landroidx/lifecycle/q;->d:Landroidx/lifecycle/q;

    .line 77
    .line 78
    new-instance p1, Ljj0/b;

    .line 79
    .line 80
    invoke-direct {p1, v3, v2, v6}, Ljj0/b;-><init>(Ljj0/e;Lkotlin/coroutines/Continuation;I)V

    .line 81
    .line 82
    .line 83
    iput v6, p0, Ljj0/d;->e:I

    .line 84
    .line 85
    invoke-static {v4, p1, p0}, Landroidx/lifecycle/v0;->k(Landroidx/lifecycle/x;Lay0/n;Lrx0/i;)Ljava/lang/Object;

    .line 86
    .line 87
    .line 88
    move-result-object p0

    .line 89
    if-ne p0, v0, :cond_5

    .line 90
    .line 91
    move-object v1, v0

    .line 92
    :cond_5
    :goto_1
    return-object v1

    .line 93
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
