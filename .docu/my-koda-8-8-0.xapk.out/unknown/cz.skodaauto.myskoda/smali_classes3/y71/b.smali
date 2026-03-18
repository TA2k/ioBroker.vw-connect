.class public final Ly71/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lt71/b;


# instance fields
.field public a:Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;


# virtual methods
.method public final lifecycleDidChange(Lt71/a;)V
    .locals 1

    .line 1
    const-string v0, "status"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Ly71/b;->a:Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;

    .line 7
    .line 8
    if-eqz p0, :cond_0

    .line 9
    .line 10
    invoke-interface {p0, p1}, Lt71/b;->lifecycleDidChange(Lt71/a;)V

    .line 11
    .line 12
    .line 13
    :cond_0
    return-void
.end method

.method public final safetyInstructionDidChange(Lt71/a;)V
    .locals 1

    .line 1
    const-string v0, "status"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Ly71/b;->a:Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;

    .line 7
    .line 8
    if-eqz p0, :cond_0

    .line 9
    .line 10
    invoke-interface {p0, p1}, Lt71/b;->safetyInstructionDidChange(Lt71/a;)V

    .line 11
    .line 12
    .line 13
    :cond_0
    return-void
.end method

.method public final screenDidChange(Lt71/a;)V
    .locals 1

    .line 1
    const-string v0, "status"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Ly71/b;->a:Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;

    .line 7
    .line 8
    if-eqz p0, :cond_0

    .line 9
    .line 10
    invoke-interface {p0, p1}, Lt71/b;->screenDidChange(Lt71/a;)V

    .line 11
    .line 12
    .line 13
    :cond_0
    return-void
.end method

.method public final sideEffectTriggered(Lt71/a;)V
    .locals 1

    .line 1
    const-string v0, "status"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Ly71/b;->a:Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;

    .line 7
    .line 8
    if-eqz p0, :cond_0

    .line 9
    .line 10
    invoke-interface {p0, p1}, Lt71/b;->sideEffectTriggered(Lt71/a;)V

    .line 11
    .line 12
    .line 13
    :cond_0
    return-void
.end method

.method public final touchPositionDidChange(Lt71/a;)V
    .locals 1

    .line 1
    const-string v0, "status"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Ly71/b;->a:Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;

    .line 7
    .line 8
    if-eqz p0, :cond_0

    .line 9
    .line 10
    invoke-interface {p0, p1}, Lt71/b;->touchPositionDidChange(Lt71/a;)V

    .line 11
    .line 12
    .line 13
    :cond_0
    return-void
.end method

.method public final userActionDidChange(Lt71/a;)V
    .locals 0

    .line 1
    iget-object p0, p0, Ly71/b;->a:Ltechnology/cariad/cat/remoteparkassistcoremeb/core/common/service/ServiceCommunication;

    .line 2
    .line 3
    if-eqz p0, :cond_0

    .line 4
    .line 5
    invoke-interface {p0, p1}, Lt71/b;->userActionDidChange(Lt71/a;)V

    .line 6
    .line 7
    .line 8
    :cond_0
    return-void
.end method
