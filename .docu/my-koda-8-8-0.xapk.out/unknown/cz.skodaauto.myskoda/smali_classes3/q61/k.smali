.class public final Lq61/k;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public final synthetic f:Ll2/b1;


# direct methods
.method public synthetic constructor <init>(Ll2/b1;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p3, p0, Lq61/k;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lq61/k;->f:Ll2/b1;

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
    iget v0, p0, Lq61/k;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance v0, Lq61/k;

    .line 7
    .line 8
    iget-object p0, p0, Lq61/k;->f:Ll2/b1;

    .line 9
    .line 10
    const/4 v1, 0x2

    .line 11
    invoke-direct {v0, p0, p2, v1}, Lq61/k;-><init>(Ll2/b1;Lkotlin/coroutines/Continuation;I)V

    .line 12
    .line 13
    .line 14
    check-cast p1, Ljava/lang/Number;

    .line 15
    .line 16
    invoke-virtual {p1}, Ljava/lang/Number;->intValue()I

    .line 17
    .line 18
    .line 19
    move-result p0

    .line 20
    iput p0, v0, Lq61/k;->e:I

    .line 21
    .line 22
    return-object v0

    .line 23
    :pswitch_0
    new-instance v0, Lq61/k;

    .line 24
    .line 25
    iget-object p0, p0, Lq61/k;->f:Ll2/b1;

    .line 26
    .line 27
    const/4 v1, 0x1

    .line 28
    invoke-direct {v0, p0, p2, v1}, Lq61/k;-><init>(Ll2/b1;Lkotlin/coroutines/Continuation;I)V

    .line 29
    .line 30
    .line 31
    check-cast p1, Ljava/lang/Number;

    .line 32
    .line 33
    invoke-virtual {p1}, Ljava/lang/Number;->intValue()I

    .line 34
    .line 35
    .line 36
    move-result p0

    .line 37
    iput p0, v0, Lq61/k;->e:I

    .line 38
    .line 39
    return-object v0

    .line 40
    :pswitch_1
    new-instance p1, Lq61/k;

    .line 41
    .line 42
    iget-object p0, p0, Lq61/k;->f:Ll2/b1;

    .line 43
    .line 44
    const/4 v0, 0x0

    .line 45
    invoke-direct {p1, p0, p2, v0}, Lq61/k;-><init>(Ll2/b1;Lkotlin/coroutines/Continuation;I)V

    .line 46
    .line 47
    .line 48
    return-object p1

    .line 49
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Lq61/k;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Ljava/lang/Number;

    .line 7
    .line 8
    invoke-virtual {p1}, Ljava/lang/Number;->intValue()I

    .line 9
    .line 10
    .line 11
    move-result p1

    .line 12
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 13
    .line 14
    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 15
    .line 16
    .line 17
    move-result-object p1

    .line 18
    invoke-virtual {p0, p1, p2}, Lq61/k;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    check-cast p0, Lq61/k;

    .line 23
    .line 24
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 25
    .line 26
    invoke-virtual {p0, p1}, Lq61/k;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 27
    .line 28
    .line 29
    return-object p1

    .line 30
    :pswitch_0
    check-cast p1, Ljava/lang/Number;

    .line 31
    .line 32
    invoke-virtual {p1}, Ljava/lang/Number;->intValue()I

    .line 33
    .line 34
    .line 35
    move-result p1

    .line 36
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 37
    .line 38
    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 39
    .line 40
    .line 41
    move-result-object p1

    .line 42
    invoke-virtual {p0, p1, p2}, Lq61/k;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 43
    .line 44
    .line 45
    move-result-object p0

    .line 46
    check-cast p0, Lq61/k;

    .line 47
    .line 48
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 49
    .line 50
    invoke-virtual {p0, p1}, Lq61/k;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 51
    .line 52
    .line 53
    return-object p1

    .line 54
    :pswitch_1
    check-cast p1, Lvy0/b0;

    .line 55
    .line 56
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 57
    .line 58
    invoke-virtual {p0, p1, p2}, Lq61/k;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 59
    .line 60
    .line 61
    move-result-object p0

    .line 62
    check-cast p0, Lq61/k;

    .line 63
    .line 64
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 65
    .line 66
    invoke-virtual {p0, p1}, Lq61/k;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 67
    .line 68
    .line 69
    move-result-object p0

    .line 70
    return-object p0

    .line 71
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 7

    .line 1
    iget v0, p0, Lq61/k;->d:I

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    sget-object v2, Llx0/b0;->a:Llx0/b0;

    .line 5
    .line 6
    const/4 v3, 0x1

    .line 7
    iget-object v4, p0, Lq61/k;->f:Ll2/b1;

    .line 8
    .line 9
    packed-switch v0, :pswitch_data_0

    .line 10
    .line 11
    .line 12
    iget p0, p0, Lq61/k;->e:I

    .line 13
    .line 14
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 15
    .line 16
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 17
    .line 18
    .line 19
    if-nez p0, :cond_0

    .line 20
    .line 21
    move v1, v3

    .line 22
    :cond_0
    invoke-static {v1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 23
    .line 24
    .line 25
    move-result-object p0

    .line 26
    invoke-interface {v4, p0}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 27
    .line 28
    .line 29
    return-object v2

    .line 30
    :pswitch_0
    iget p0, p0, Lq61/k;->e:I

    .line 31
    .line 32
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 33
    .line 34
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 35
    .line 36
    .line 37
    if-nez p0, :cond_1

    .line 38
    .line 39
    move v1, v3

    .line 40
    :cond_1
    invoke-static {v1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 41
    .line 42
    .line 43
    move-result-object p0

    .line 44
    invoke-interface {v4, p0}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 45
    .line 46
    .line 47
    return-object v2

    .line 48
    :pswitch_1
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 49
    .line 50
    iget v1, p0, Lq61/k;->e:I

    .line 51
    .line 52
    if-eqz v1, :cond_3

    .line 53
    .line 54
    if-ne v1, v3, :cond_2

    .line 55
    .line 56
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 57
    .line 58
    .line 59
    goto :goto_0

    .line 60
    :cond_2
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 61
    .line 62
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 63
    .line 64
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 65
    .line 66
    .line 67
    throw p0

    .line 68
    :cond_3
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 69
    .line 70
    .line 71
    sget p1, Lmy0/c;->g:I

    .line 72
    .line 73
    const/16 p1, 0x3e8

    .line 74
    .line 75
    sget-object v1, Lmy0/e;->g:Lmy0/e;

    .line 76
    .line 77
    invoke-static {p1, v1}, Lmy0/h;->s(ILmy0/e;)J

    .line 78
    .line 79
    .line 80
    move-result-wide v5

    .line 81
    iput v3, p0, Lq61/k;->e:I

    .line 82
    .line 83
    invoke-static {v5, v6, p0}, Lvy0/e0;->q(JLkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 84
    .line 85
    .line 86
    move-result-object p0

    .line 87
    if-ne p0, v0, :cond_4

    .line 88
    .line 89
    move-object v2, v0

    .line 90
    goto :goto_1

    .line 91
    :cond_4
    :goto_0
    sget-object p0, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 92
    .line 93
    invoke-interface {v4, p0}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 94
    .line 95
    .line 96
    :goto_1
    return-object v2

    .line 97
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
