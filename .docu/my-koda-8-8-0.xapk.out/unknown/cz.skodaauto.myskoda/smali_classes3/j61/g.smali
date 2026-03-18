.class public final Lj61/g;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public d:I

.field public synthetic e:Ljava/lang/Object;

.field public final synthetic f:Ltechnology/cariad/cat/remoteparkassist/plugin/internal/ble/BLETransportFacade;


# direct methods
.method public constructor <init>(Ltechnology/cariad/cat/remoteparkassist/plugin/internal/ble/BLETransportFacade;Lkotlin/coroutines/Continuation;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lj61/g;->f:Ltechnology/cariad/cat/remoteparkassist/plugin/internal/ble/BLETransportFacade;

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
    new-instance v0, Lj61/g;

    .line 2
    .line 3
    iget-object p0, p0, Lj61/g;->f:Ltechnology/cariad/cat/remoteparkassist/plugin/internal/ble/BLETransportFacade;

    .line 4
    .line 5
    invoke-direct {v0, p0, p2}, Lj61/g;-><init>(Ltechnology/cariad/cat/remoteparkassist/plugin/internal/ble/BLETransportFacade;Lkotlin/coroutines/Continuation;)V

    .line 6
    .line 7
    .line 8
    iput-object p1, v0, Lj61/g;->e:Ljava/lang/Object;

    .line 9
    .line 10
    return-object v0
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Ltechnology/cariad/cat/genx/protocol/data/LinkParameters$ResponseValues;

    .line 2
    .line 3
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 4
    .line 5
    invoke-virtual {p0, p1, p2}, Lj61/g;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    check-cast p0, Lj61/g;

    .line 10
    .line 11
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 12
    .line 13
    invoke-virtual {p0, p1}, Lj61/g;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    return-object p0
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 4

    .line 1
    iget-object v0, p0, Lj61/g;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Ltechnology/cariad/cat/genx/protocol/data/LinkParameters$ResponseValues;

    .line 4
    .line 5
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 6
    .line 7
    iget v2, p0, Lj61/g;->d:I

    .line 8
    .line 9
    const/4 v3, 0x1

    .line 10
    if-eqz v2, :cond_1

    .line 11
    .line 12
    if-ne v2, v3, :cond_0

    .line 13
    .line 14
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 15
    .line 16
    .line 17
    goto :goto_0

    .line 18
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 19
    .line 20
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 21
    .line 22
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 23
    .line 24
    .line 25
    throw p0

    .line 26
    :cond_1
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 27
    .line 28
    .line 29
    iget-object p1, p0, Lj61/g;->f:Ltechnology/cariad/cat/remoteparkassist/plugin/internal/ble/BLETransportFacade;

    .line 30
    .line 31
    invoke-static {p1}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/ble/BLETransportFacade;->access$get_linkParameters$p(Ltechnology/cariad/cat/remoteparkassist/plugin/internal/ble/BLETransportFacade;)Lyy0/i1;

    .line 32
    .line 33
    .line 34
    move-result-object p1

    .line 35
    const/4 v2, 0x0

    .line 36
    iput-object v2, p0, Lj61/g;->e:Ljava/lang/Object;

    .line 37
    .line 38
    iput v3, p0, Lj61/g;->d:I

    .line 39
    .line 40
    invoke-interface {p1, v0, p0}, Lyy0/i1;->emit(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 41
    .line 42
    .line 43
    move-result-object p0

    .line 44
    if-ne p0, v1, :cond_2

    .line 45
    .line 46
    return-object v1

    .line 47
    :cond_2
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 48
    .line 49
    return-object p0
.end method
