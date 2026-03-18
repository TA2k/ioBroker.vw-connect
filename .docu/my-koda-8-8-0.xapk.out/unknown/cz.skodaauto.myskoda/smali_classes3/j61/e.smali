.class public final Lj61/e;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public synthetic f:Z

.field public final synthetic g:Ltechnology/cariad/cat/remoteparkassist/plugin/internal/ble/BLETransportFacade;


# direct methods
.method public synthetic constructor <init>(Ltechnology/cariad/cat/remoteparkassist/plugin/internal/ble/BLETransportFacade;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p3, p0, Lj61/e;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lj61/e;->g:Ltechnology/cariad/cat/remoteparkassist/plugin/internal/ble/BLETransportFacade;

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
    iget v0, p0, Lj61/e;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance v0, Lj61/e;

    .line 7
    .line 8
    iget-object p0, p0, Lj61/e;->g:Ltechnology/cariad/cat/remoteparkassist/plugin/internal/ble/BLETransportFacade;

    .line 9
    .line 10
    const/4 v1, 0x1

    .line 11
    invoke-direct {v0, p0, p2, v1}, Lj61/e;-><init>(Ltechnology/cariad/cat/remoteparkassist/plugin/internal/ble/BLETransportFacade;Lkotlin/coroutines/Continuation;I)V

    .line 12
    .line 13
    .line 14
    check-cast p1, Ljava/lang/Boolean;

    .line 15
    .line 16
    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 17
    .line 18
    .line 19
    move-result p0

    .line 20
    iput-boolean p0, v0, Lj61/e;->f:Z

    .line 21
    .line 22
    return-object v0

    .line 23
    :pswitch_0
    new-instance v0, Lj61/e;

    .line 24
    .line 25
    iget-object p0, p0, Lj61/e;->g:Ltechnology/cariad/cat/remoteparkassist/plugin/internal/ble/BLETransportFacade;

    .line 26
    .line 27
    const/4 v1, 0x0

    .line 28
    invoke-direct {v0, p0, p2, v1}, Lj61/e;-><init>(Ltechnology/cariad/cat/remoteparkassist/plugin/internal/ble/BLETransportFacade;Lkotlin/coroutines/Continuation;I)V

    .line 29
    .line 30
    .line 31
    check-cast p1, Ljava/lang/Boolean;

    .line 32
    .line 33
    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 34
    .line 35
    .line 36
    move-result p0

    .line 37
    iput-boolean p0, v0, Lj61/e;->f:Z

    .line 38
    .line 39
    return-object v0

    .line 40
    nop

    .line 41
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Lj61/e;->d:I

    .line 2
    .line 3
    check-cast p1, Ljava/lang/Boolean;

    .line 4
    .line 5
    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 6
    .line 7
    .line 8
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 9
    .line 10
    packed-switch v0, :pswitch_data_0

    .line 11
    .line 12
    .line 13
    invoke-virtual {p0, p1, p2}, Lj61/e;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    check-cast p0, Lj61/e;

    .line 18
    .line 19
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 20
    .line 21
    invoke-virtual {p0, p1}, Lj61/e;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 22
    .line 23
    .line 24
    move-result-object p0

    .line 25
    return-object p0

    .line 26
    :pswitch_0
    invoke-virtual {p0, p1, p2}, Lj61/e;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 27
    .line 28
    .line 29
    move-result-object p0

    .line 30
    check-cast p0, Lj61/e;

    .line 31
    .line 32
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 33
    .line 34
    invoke-virtual {p0, p1}, Lj61/e;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 35
    .line 36
    .line 37
    move-result-object p0

    .line 38
    return-object p0

    .line 39
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 5

    .line 1
    iget v0, p0, Lj61/e;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-boolean v0, p0, Lj61/e;->f:Z

    .line 7
    .line 8
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 9
    .line 10
    iget v2, p0, Lj61/e;->e:I

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
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 20
    .line 21
    .line 22
    :cond_0
    move-object v1, v3

    .line 23
    goto :goto_0

    .line 24
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 25
    .line 26
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 27
    .line 28
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 29
    .line 30
    .line 31
    throw p0

    .line 32
    :cond_2
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 33
    .line 34
    .line 35
    iget-object p1, p0, Lj61/e;->g:Ltechnology/cariad/cat/remoteparkassist/plugin/internal/ble/BLETransportFacade;

    .line 36
    .line 37
    invoke-static {p1}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/ble/BLETransportFacade;->access$get_isConnectable$p(Ltechnology/cariad/cat/remoteparkassist/plugin/internal/ble/BLETransportFacade;)Lyy0/j1;

    .line 38
    .line 39
    .line 40
    move-result-object p1

    .line 41
    invoke-static {v0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 42
    .line 43
    .line 44
    move-result-object v2

    .line 45
    iput-boolean v0, p0, Lj61/e;->f:Z

    .line 46
    .line 47
    iput v4, p0, Lj61/e;->e:I

    .line 48
    .line 49
    check-cast p1, Lyy0/c2;

    .line 50
    .line 51
    invoke-virtual {p1, v2, p0}, Lyy0/c2;->emit(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 52
    .line 53
    .line 54
    if-ne v3, v1, :cond_0

    .line 55
    .line 56
    :goto_0
    return-object v1

    .line 57
    :pswitch_0
    iget-boolean v0, p0, Lj61/e;->f:Z

    .line 58
    .line 59
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 60
    .line 61
    iget v2, p0, Lj61/e;->e:I

    .line 62
    .line 63
    sget-object v3, Llx0/b0;->a:Llx0/b0;

    .line 64
    .line 65
    const/4 v4, 0x1

    .line 66
    if-eqz v2, :cond_5

    .line 67
    .line 68
    if-ne v2, v4, :cond_4

    .line 69
    .line 70
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 71
    .line 72
    .line 73
    :cond_3
    move-object v1, v3

    .line 74
    goto :goto_1

    .line 75
    :cond_4
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 76
    .line 77
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 78
    .line 79
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 80
    .line 81
    .line 82
    throw p0

    .line 83
    :cond_5
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 84
    .line 85
    .line 86
    iget-object p1, p0, Lj61/e;->g:Ltechnology/cariad/cat/remoteparkassist/plugin/internal/ble/BLETransportFacade;

    .line 87
    .line 88
    invoke-static {p1}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/ble/BLETransportFacade;->access$get_isTransportEnabled$p(Ltechnology/cariad/cat/remoteparkassist/plugin/internal/ble/BLETransportFacade;)Lyy0/j1;

    .line 89
    .line 90
    .line 91
    move-result-object p1

    .line 92
    invoke-static {v0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 93
    .line 94
    .line 95
    move-result-object v2

    .line 96
    iput-boolean v0, p0, Lj61/e;->f:Z

    .line 97
    .line 98
    iput v4, p0, Lj61/e;->e:I

    .line 99
    .line 100
    check-cast p1, Lyy0/c2;

    .line 101
    .line 102
    invoke-virtual {p1, v2, p0}, Lyy0/c2;->emit(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 103
    .line 104
    .line 105
    if-ne v3, v1, :cond_3

    .line 106
    .line 107
    :goto_1
    return-object v1

    .line 108
    nop

    .line 109
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
