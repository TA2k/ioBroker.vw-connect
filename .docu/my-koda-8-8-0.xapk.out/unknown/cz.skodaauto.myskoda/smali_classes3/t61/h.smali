.class public final Lt61/h;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public d:I

.field public synthetic e:Ljava/lang/Object;

.field public final synthetic f:Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;

.field public final synthetic g:Ljava/util/Set;


# direct methods
.method public constructor <init>(Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;Ljava/util/Set;Lkotlin/coroutines/Continuation;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lt61/h;->f:Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;

    .line 2
    .line 3
    iput-object p2, p0, Lt61/h;->g:Ljava/util/Set;

    .line 4
    .line 5
    const/4 p1, 0x2

    .line 6
    invoke-direct {p0, p1, p3}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 7
    .line 8
    .line 9
    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;
    .locals 2

    .line 1
    new-instance v0, Lt61/h;

    .line 2
    .line 3
    iget-object v1, p0, Lt61/h;->f:Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;

    .line 4
    .line 5
    iget-object p0, p0, Lt61/h;->g:Ljava/util/Set;

    .line 6
    .line 7
    invoke-direct {v0, v1, p0, p2}, Lt61/h;-><init>(Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;Ljava/util/Set;Lkotlin/coroutines/Continuation;)V

    .line 8
    .line 9
    .line 10
    iput-object p1, v0, Lt61/h;->e:Ljava/lang/Object;

    .line 11
    .line 12
    return-object v0
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Lvy0/b0;

    .line 2
    .line 3
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 4
    .line 5
    invoke-virtual {p0, p1, p2}, Lt61/h;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    check-cast p0, Lt61/h;

    .line 10
    .line 11
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 12
    .line 13
    invoke-virtual {p0, p1}, Lt61/h;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    return-object p0
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 5

    .line 1
    iget-object v0, p0, Lt61/h;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Lvy0/b0;

    .line 4
    .line 5
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 6
    .line 7
    iget v2, p0, Lt61/h;->d:I

    .line 8
    .line 9
    iget-object v3, p0, Lt61/h;->f:Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;

    .line 10
    .line 11
    const/4 v4, 0x1

    .line 12
    if-eqz v2, :cond_1

    .line 13
    .line 14
    if-ne v2, v4, :cond_0

    .line 15
    .line 16
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 17
    .line 18
    .line 19
    check-cast p1, Llx0/o;

    .line 20
    .line 21
    iget-object p0, p1, Llx0/o;->d:Ljava/lang/Object;

    .line 22
    .line 23
    goto :goto_0

    .line 24
    :cond_0
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
    :cond_1
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 33
    .line 34
    .line 35
    invoke-virtual {v3}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;->getBleTransport()Ltechnology/cariad/cat/genx/VehicleAntennaTransport;

    .line 36
    .line 37
    .line 38
    move-result-object p1

    .line 39
    invoke-static {v3}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;->access$getConnectionDelegate$p(Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;)Lt61/i;

    .line 40
    .line 41
    .line 42
    move-result-object v2

    .line 43
    iput-object v0, p0, Lt61/h;->e:Ljava/lang/Object;

    .line 44
    .line 45
    iput v4, p0, Lt61/h;->d:I

    .line 46
    .line 47
    iget-object v4, p0, Lt61/h;->g:Ljava/util/Set;

    .line 48
    .line 49
    invoke-interface {p1, v2, v4, p0}, Ltechnology/cariad/cat/genx/VehicleAntennaTransport;->connect-0E7RQCE(Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Connection$Delegate;Ljava/util/Set;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 50
    .line 51
    .line 52
    move-result-object p0

    .line 53
    if-ne p0, v1, :cond_2

    .line 54
    .line 55
    return-object v1

    .line 56
    :cond_2
    :goto_0
    invoke-static {p0}, Llx0/o;->a(Ljava/lang/Object;)Ljava/lang/Throwable;

    .line 57
    .line 58
    .line 59
    move-result-object p1

    .line 60
    if-nez p1, :cond_3

    .line 61
    .line 62
    check-cast p0, Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Connection;

    .line 63
    .line 64
    invoke-virtual {v3, p0}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;->setConnection$remoteparkassistplugin_release(Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Connection;)V

    .line 65
    .line 66
    .line 67
    invoke-static {v3}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;->access$getShouldDisconnectAfterConnectionFinished$p(Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;)Z

    .line 68
    .line 69
    .line 70
    move-result p0

    .line 71
    if-eqz p0, :cond_4

    .line 72
    .line 73
    invoke-virtual {v3}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;->disconnect()V

    .line 74
    .line 75
    .line 76
    goto :goto_1

    .line 77
    :cond_3
    new-instance p0, Lt61/g;

    .line 78
    .line 79
    const/4 v1, 0x0

    .line 80
    invoke-direct {p0, v1, v3, p1}, Lt61/g;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 81
    .line 82
    .line 83
    const/4 p1, 0x0

    .line 84
    invoke-static {v0, p1, p0}, Llp/i1;->c(Ljava/lang/Object;Ljava/io/IOException;Lay0/a;)V

    .line 85
    .line 86
    .line 87
    sget-object p0, Lk71/c;->f:Lk71/c;

    .line 88
    .line 89
    invoke-static {v3, p0}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;->access$setConnectionStatus(Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;Lk71/c;)V

    .line 90
    .line 91
    .line 92
    :cond_4
    :goto_1
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 93
    .line 94
    return-object p0
.end method
