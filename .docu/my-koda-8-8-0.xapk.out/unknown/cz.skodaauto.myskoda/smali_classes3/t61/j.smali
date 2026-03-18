.class public final Lt61/j;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public d:I

.field public synthetic e:Ljava/lang/Object;

.field public final synthetic f:Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Connection;

.field public final synthetic g:Ltechnology/cariad/cat/genx/protocol/Address;

.field public final synthetic h:B

.field public final synthetic i:Z

.field public final synthetic j:[B

.field public final synthetic k:Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;


# direct methods
.method public constructor <init>(Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Connection;Ltechnology/cariad/cat/genx/protocol/Address;BZ[BLtechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;Lkotlin/coroutines/Continuation;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lt61/j;->f:Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Connection;

    .line 2
    .line 3
    iput-object p2, p0, Lt61/j;->g:Ltechnology/cariad/cat/genx/protocol/Address;

    .line 4
    .line 5
    iput-byte p3, p0, Lt61/j;->h:B

    .line 6
    .line 7
    iput-boolean p4, p0, Lt61/j;->i:Z

    .line 8
    .line 9
    iput-object p5, p0, Lt61/j;->j:[B

    .line 10
    .line 11
    iput-object p6, p0, Lt61/j;->k:Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;

    .line 12
    .line 13
    const/4 p1, 0x2

    .line 14
    invoke-direct {p0, p1, p7}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 15
    .line 16
    .line 17
    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;
    .locals 8

    .line 1
    new-instance v0, Lt61/j;

    .line 2
    .line 3
    iget-object v5, p0, Lt61/j;->j:[B

    .line 4
    .line 5
    iget-object v6, p0, Lt61/j;->k:Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;

    .line 6
    .line 7
    iget-object v1, p0, Lt61/j;->f:Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Connection;

    .line 8
    .line 9
    iget-object v2, p0, Lt61/j;->g:Ltechnology/cariad/cat/genx/protocol/Address;

    .line 10
    .line 11
    iget-byte v3, p0, Lt61/j;->h:B

    .line 12
    .line 13
    iget-boolean v4, p0, Lt61/j;->i:Z

    .line 14
    .line 15
    move-object v7, p2

    .line 16
    invoke-direct/range {v0 .. v7}, Lt61/j;-><init>(Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Connection;Ltechnology/cariad/cat/genx/protocol/Address;BZ[BLtechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;Lkotlin/coroutines/Continuation;)V

    .line 17
    .line 18
    .line 19
    iput-object p1, v0, Lt61/j;->e:Ljava/lang/Object;

    .line 20
    .line 21
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
    invoke-virtual {p0, p1, p2}, Lt61/j;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    check-cast p0, Lt61/j;

    .line 10
    .line 11
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 12
    .line 13
    invoke-virtual {p0, p1}, Lt61/j;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    return-object p0
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 9

    .line 1
    iget-object v0, p0, Lt61/j;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Lvy0/b0;

    .line 4
    .line 5
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 6
    .line 7
    iget v2, p0, Lt61/j;->d:I

    .line 8
    .line 9
    iget-object v4, p0, Lt61/j;->j:[B

    .line 10
    .line 11
    iget-object v5, p0, Lt61/j;->g:Ltechnology/cariad/cat/genx/protocol/Address;

    .line 12
    .line 13
    const/4 v3, 0x1

    .line 14
    if-eqz v2, :cond_1

    .line 15
    .line 16
    if-ne v2, v3, :cond_0

    .line 17
    .line 18
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 19
    .line 20
    .line 21
    check-cast p1, Llx0/o;

    .line 22
    .line 23
    iget-object p1, p1, Llx0/o;->d:Ljava/lang/Object;

    .line 24
    .line 25
    goto :goto_1

    .line 26
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 27
    .line 28
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 29
    .line 30
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

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
    new-instance p1, Ltechnology/cariad/cat/genx/protocol/Message;

    .line 38
    .line 39
    iget-byte v2, p0, Lt61/j;->h:B

    .line 40
    .line 41
    if-ne v2, v3, :cond_2

    .line 42
    .line 43
    sget-object v2, Ltechnology/cariad/cat/genx/protocol/Priority;->MIDDLE:Ltechnology/cariad/cat/genx/protocol/Priority;

    .line 44
    .line 45
    goto :goto_0

    .line 46
    :cond_2
    const/4 v6, 0x2

    .line 47
    if-ne v2, v6, :cond_3

    .line 48
    .line 49
    sget-object v2, Ltechnology/cariad/cat/genx/protocol/Priority;->HIGH:Ltechnology/cariad/cat/genx/protocol/Priority;

    .line 50
    .line 51
    goto :goto_0

    .line 52
    :cond_3
    const/4 v6, 0x3

    .line 53
    if-ne v2, v6, :cond_4

    .line 54
    .line 55
    sget-object v2, Ltechnology/cariad/cat/genx/protocol/Priority;->HIGHEST:Ltechnology/cariad/cat/genx/protocol/Priority;

    .line 56
    .line 57
    goto :goto_0

    .line 58
    :cond_4
    sget-object v2, Ltechnology/cariad/cat/genx/protocol/Priority;->LOW:Ltechnology/cariad/cat/genx/protocol/Priority;

    .line 59
    .line 60
    :goto_0
    iget-boolean v6, p0, Lt61/j;->i:Z

    .line 61
    .line 62
    invoke-direct {p1, v5, v2, v6, v4}, Ltechnology/cariad/cat/genx/protocol/Message;-><init>(Ltechnology/cariad/cat/genx/protocol/Address;Ltechnology/cariad/cat/genx/protocol/Priority;Z[B)V

    .line 63
    .line 64
    .line 65
    iput-object v0, p0, Lt61/j;->e:Ljava/lang/Object;

    .line 66
    .line 67
    iput v3, p0, Lt61/j;->d:I

    .line 68
    .line 69
    iget-object v2, p0, Lt61/j;->f:Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Connection;

    .line 70
    .line 71
    invoke-interface {v2, p1, p0}, Ltechnology/cariad/cat/genx/VehicleAntennaTransport$Connection;->send-gIAlu-s(Ltechnology/cariad/cat/genx/protocol/Message;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 72
    .line 73
    .line 74
    move-result-object p1

    .line 75
    if-ne p1, v1, :cond_5

    .line 76
    .line 77
    return-object v1

    .line 78
    :cond_5
    :goto_1
    invoke-static {p1}, Llx0/o;->a(Ljava/lang/Object;)Ljava/lang/Throwable;

    .line 79
    .line 80
    .line 81
    move-result-object v7

    .line 82
    if-eqz v7, :cond_6

    .line 83
    .line 84
    new-instance v3, Lal/i;

    .line 85
    .line 86
    const/4 v8, 0x7

    .line 87
    iget-object v6, p0, Lt61/j;->k:Ltechnology/cariad/cat/remoteparkassist/plugin/internal/rpa/util/RPACommunicator;

    .line 88
    .line 89
    invoke-direct/range {v3 .. v8}, Lal/i;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 90
    .line 91
    .line 92
    const/4 p0, 0x0

    .line 93
    invoke-static {v0, p0, v3}, Llp/i1;->c(Ljava/lang/Object;Ljava/io/IOException;Lay0/a;)V

    .line 94
    .line 95
    .line 96
    :cond_6
    new-instance p0, Llx0/o;

    .line 97
    .line 98
    invoke-direct {p0, p1}, Llx0/o;-><init>(Ljava/lang/Object;)V

    .line 99
    .line 100
    .line 101
    return-object p0
.end method
