.class public final Li61/h;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public d:I

.field public synthetic e:Ljava/lang/Object;

.field public final synthetic f:Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAStarterImpl;


# direct methods
.method public constructor <init>(Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAStarterImpl;Lkotlin/coroutines/Continuation;)V
    .locals 0

    .line 1
    iput-object p1, p0, Li61/h;->f:Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAStarterImpl;

    .line 2
    .line 3
    const/4 p1, 0x2

    .line 4
    invoke-direct {p0, p1, p2}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 5
    .line 6
    .line 7
    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;
    .locals 1

    .line 1
    new-instance v0, Li61/h;

    .line 2
    .line 3
    iget-object p0, p0, Li61/h;->f:Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAStarterImpl;

    .line 4
    .line 5
    invoke-direct {v0, p0, p2}, Li61/h;-><init>(Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAStarterImpl;Lkotlin/coroutines/Continuation;)V

    .line 6
    .line 7
    .line 8
    iput-object p1, v0, Li61/h;->e:Ljava/lang/Object;

    .line 9
    .line 10
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
    invoke-virtual {p0, p1, p2}, Li61/h;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    check-cast p0, Li61/h;

    .line 10
    .line 11
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 12
    .line 13
    invoke-virtual {p0, p1}, Li61/h;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

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
    iget-object v0, p0, Li61/h;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Lvy0/b0;

    .line 4
    .line 5
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 6
    .line 7
    iget v2, p0, Li61/h;->d:I

    .line 8
    .line 9
    iget-object v3, p0, Li61/h;->f:Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAStarterImpl;

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
    invoke-static {v3}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAStarterImpl;->access$getVehicleAntenna$p(Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAStarterImpl;)Ltechnology/cariad/cat/genx/VehicleAntenna$Outer;

    .line 36
    .line 37
    .line 38
    move-result-object p1

    .line 39
    iput-object v0, p0, Li61/h;->e:Ljava/lang/Object;

    .line 40
    .line 41
    iput v4, p0, Li61/h;->d:I

    .line 42
    .line 43
    invoke-interface {p1, p0}, Ltechnology/cariad/cat/genx/VehicleAntenna$Outer;->bleTransport-IoAF18A(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 44
    .line 45
    .line 46
    move-result-object p0

    .line 47
    if-ne p0, v1, :cond_2

    .line 48
    .line 49
    return-object v1

    .line 50
    :cond_2
    :goto_0
    invoke-static {p0}, Llx0/o;->a(Ljava/lang/Object;)Ljava/lang/Throwable;

    .line 51
    .line 52
    .line 53
    move-result-object p1

    .line 54
    if-nez p1, :cond_3

    .line 55
    .line 56
    check-cast p0, Ltechnology/cariad/cat/genx/VehicleAntennaTransport;

    .line 57
    .line 58
    invoke-static {v3}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAStarterImpl;->access$getBleTransportFacade$p(Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAStarterImpl;)Ltechnology/cariad/cat/remoteparkassist/plugin/internal/ble/BLETransportFacade;

    .line 59
    .line 60
    .line 61
    move-result-object p1

    .line 62
    invoke-virtual {p1, p0}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/ble/BLETransportFacade;->updateTransport(Ltechnology/cariad/cat/genx/VehicleAntennaTransport;)V

    .line 63
    .line 64
    .line 65
    goto :goto_1

    .line 66
    :cond_3
    new-instance p0, Lbp0/e;

    .line 67
    .line 68
    const/4 v1, 0x3

    .line 69
    invoke-direct {p0, p1, v1}, Lbp0/e;-><init>(Ljava/lang/Throwable;I)V

    .line 70
    .line 71
    .line 72
    const/4 p1, 0x0

    .line 73
    invoke-static {v0, p1, p0}, Llp/i1;->c(Ljava/lang/Object;Ljava/io/IOException;Lay0/a;)V

    .line 74
    .line 75
    .line 76
    invoke-static {v3}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAStarterImpl;->access$getBleTransportFacade$p(Ltechnology/cariad/cat/remoteparkassist/plugin/internal/RPAStarterImpl;)Ltechnology/cariad/cat/remoteparkassist/plugin/internal/ble/BLETransportFacade;

    .line 77
    .line 78
    .line 79
    move-result-object p0

    .line 80
    invoke-virtual {p0, p1}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/ble/BLETransportFacade;->updateTransport(Ltechnology/cariad/cat/genx/VehicleAntennaTransport;)V

    .line 81
    .line 82
    .line 83
    :goto_1
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 84
    .line 85
    return-object p0
.end method
