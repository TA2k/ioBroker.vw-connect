.class public final Lmg0/d;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public final synthetic f:Lmg0/e;

.field public final synthetic g:Lcz/skodaauto/myskoda/app/main/system/MainActivity;


# direct methods
.method public synthetic constructor <init>(Lmg0/e;Lcz/skodaauto/myskoda/app/main/system/MainActivity;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p4, p0, Lmg0/d;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lmg0/d;->f:Lmg0/e;

    .line 4
    .line 5
    iput-object p2, p0, Lmg0/d;->g:Lcz/skodaauto/myskoda/app/main/system/MainActivity;

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
    iget p1, p0, Lmg0/d;->d:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance p1, Lmg0/d;

    .line 7
    .line 8
    iget-object v0, p0, Lmg0/d;->g:Lcz/skodaauto/myskoda/app/main/system/MainActivity;

    .line 9
    .line 10
    const/4 v1, 0x1

    .line 11
    iget-object p0, p0, Lmg0/d;->f:Lmg0/e;

    .line 12
    .line 13
    invoke-direct {p1, p0, v0, p2, v1}, Lmg0/d;-><init>(Lmg0/e;Lcz/skodaauto/myskoda/app/main/system/MainActivity;Lkotlin/coroutines/Continuation;I)V

    .line 14
    .line 15
    .line 16
    return-object p1

    .line 17
    :pswitch_0
    new-instance p1, Lmg0/d;

    .line 18
    .line 19
    iget-object v0, p0, Lmg0/d;->g:Lcz/skodaauto/myskoda/app/main/system/MainActivity;

    .line 20
    .line 21
    const/4 v1, 0x0

    .line 22
    iget-object p0, p0, Lmg0/d;->f:Lmg0/e;

    .line 23
    .line 24
    invoke-direct {p1, p0, v0, p2, v1}, Lmg0/d;-><init>(Lmg0/e;Lcz/skodaauto/myskoda/app/main/system/MainActivity;Lkotlin/coroutines/Continuation;I)V

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
    iget v0, p0, Lmg0/d;->d:I

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
    invoke-virtual {p0, p1, p2}, Lmg0/d;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Lmg0/d;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Lmg0/d;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    sget-object p0, Lqx0/a;->d:Lqx0/a;

    .line 22
    .line 23
    return-object p0

    .line 24
    :pswitch_0
    invoke-virtual {p0, p1, p2}, Lmg0/d;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 25
    .line 26
    .line 27
    move-result-object p0

    .line 28
    check-cast p0, Lmg0/d;

    .line 29
    .line 30
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 31
    .line 32
    invoke-virtual {p0, p1}, Lmg0/d;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 33
    .line 34
    .line 35
    sget-object p0, Lqx0/a;->d:Lqx0/a;

    .line 36
    .line 37
    return-object p0

    .line 38
    nop

    .line 39
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 6

    .line 1
    iget v0, p0, Lmg0/d;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 7
    .line 8
    iget v1, p0, Lmg0/d;->e:I

    .line 9
    .line 10
    const/4 v2, 0x1

    .line 11
    if-eqz v1, :cond_1

    .line 12
    .line 13
    if-eq v1, v2, :cond_0

    .line 14
    .line 15
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 16
    .line 17
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 18
    .line 19
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 20
    .line 21
    .line 22
    throw p0

    .line 23
    :cond_0
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 24
    .line 25
    .line 26
    goto :goto_0

    .line 27
    :cond_1
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 28
    .line 29
    .line 30
    iget-object p1, p0, Lmg0/d;->f:Lmg0/e;

    .line 31
    .line 32
    iget-object v1, p1, Lmg0/e;->b:Lig0/g;

    .line 33
    .line 34
    iget-object v1, v1, Lig0/g;->h:Lyy0/k1;

    .line 35
    .line 36
    new-instance v3, Lmg0/c;

    .line 37
    .line 38
    iget-object v4, p0, Lmg0/d;->g:Lcz/skodaauto/myskoda/app/main/system/MainActivity;

    .line 39
    .line 40
    const/4 v5, 0x1

    .line 41
    invoke-direct {v3, p1, v4, v5}, Lmg0/c;-><init>(Lmg0/e;Lcz/skodaauto/myskoda/app/main/system/MainActivity;I)V

    .line 42
    .line 43
    .line 44
    iput v2, p0, Lmg0/d;->e:I

    .line 45
    .line 46
    iget-object p1, v1, Lyy0/k1;->d:Lyy0/n1;

    .line 47
    .line 48
    invoke-interface {p1, v3, p0}, Lyy0/i;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 49
    .line 50
    .line 51
    move-result-object p0

    .line 52
    if-ne p0, v0, :cond_2

    .line 53
    .line 54
    return-object v0

    .line 55
    :cond_2
    :goto_0
    new-instance p0, La8/r0;

    .line 56
    .line 57
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 58
    .line 59
    .line 60
    throw p0

    .line 61
    :pswitch_0
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 62
    .line 63
    iget v1, p0, Lmg0/d;->e:I

    .line 64
    .line 65
    const/4 v2, 0x1

    .line 66
    if-eqz v1, :cond_4

    .line 67
    .line 68
    if-eq v1, v2, :cond_3

    .line 69
    .line 70
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 71
    .line 72
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 73
    .line 74
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 75
    .line 76
    .line 77
    throw p0

    .line 78
    :cond_3
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 79
    .line 80
    .line 81
    goto :goto_1

    .line 82
    :cond_4
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 83
    .line 84
    .line 85
    iget-object p1, p0, Lmg0/d;->f:Lmg0/e;

    .line 86
    .line 87
    iget-object v1, p1, Lmg0/e;->b:Lig0/g;

    .line 88
    .line 89
    iget-object v1, v1, Lig0/g;->e:Lyy0/k1;

    .line 90
    .line 91
    new-instance v3, Lmg0/c;

    .line 92
    .line 93
    iget-object v4, p0, Lmg0/d;->g:Lcz/skodaauto/myskoda/app/main/system/MainActivity;

    .line 94
    .line 95
    const/4 v5, 0x0

    .line 96
    invoke-direct {v3, p1, v4, v5}, Lmg0/c;-><init>(Lmg0/e;Lcz/skodaauto/myskoda/app/main/system/MainActivity;I)V

    .line 97
    .line 98
    .line 99
    iput v2, p0, Lmg0/d;->e:I

    .line 100
    .line 101
    iget-object p1, v1, Lyy0/k1;->d:Lyy0/n1;

    .line 102
    .line 103
    invoke-interface {p1, v3, p0}, Lyy0/i;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 104
    .line 105
    .line 106
    move-result-object p0

    .line 107
    if-ne p0, v0, :cond_5

    .line 108
    .line 109
    return-object v0

    .line 110
    :cond_5
    :goto_1
    new-instance p0, La8/r0;

    .line 111
    .line 112
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 113
    .line 114
    .line 115
    throw p0

    .line 116
    nop

    .line 117
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
