.class public abstract Lpt0/n;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/KeyStatusPPE;)Z
    .locals 2

    .line 1
    sget-object v0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/KeyStatusPPE;->KEY_OUT_OF_RANGE:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/KeyStatusPPE;

    .line 2
    .line 3
    sget-object v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/KeyStatusPPE;->KEY_INVALID:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/KeyStatusPPE;

    .line 4
    .line 5
    filled-new-array {v0, v1}, [Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/KeyStatusPPE;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    invoke-static {v0}, Lmx0/n;->h0([Ljava/lang/Object;)Ljava/util/Set;

    .line 10
    .line 11
    .line 12
    move-result-object v0

    .line 13
    check-cast v0, Ljava/lang/Iterable;

    .line 14
    .line 15
    invoke-static {v0, p0}, Lmx0/q;->A(Ljava/lang/Iterable;Ljava/lang/Object;)Z

    .line 16
    .line 17
    .line 18
    move-result p0

    .line 19
    return p0
.end method

.method public static final b(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StoppingReasonStatusPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ObstacleDetectedStatusPPE;Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/KeyStatusPPE;)Z
    .locals 2

    .line 1
    const-string v0, "stoppingReasonStatus"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-static {}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ObstacleDetectedStatusPPE;->getEntries()Lsx0/a;

    .line 7
    .line 8
    .line 9
    move-result-object v0

    .line 10
    invoke-static {v0}, Lmx0/q;->C0(Ljava/lang/Iterable;)Ljava/util/Set;

    .line 11
    .line 12
    .line 13
    move-result-object v0

    .line 14
    sget-object v1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ObstacleDetectedStatusPPE;->NOT_DETECTED:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/ObstacleDetectedStatusPPE;

    .line 15
    .line 16
    invoke-static {v0, v1}, Ljp/m1;->e(Ljava/util/Set;Ljava/lang/Object;)Ljava/util/LinkedHashSet;

    .line 17
    .line 18
    .line 19
    move-result-object v0

    .line 20
    invoke-static {v0, p1}, Lmx0/q;->A(Ljava/lang/Iterable;Ljava/lang/Object;)Z

    .line 21
    .line 22
    .line 23
    move-result p1

    .line 24
    if-nez p1, :cond_1

    .line 25
    .line 26
    invoke-static {p2}, Lpt0/n;->a(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/KeyStatusPPE;)Z

    .line 27
    .line 28
    .line 29
    move-result p1

    .line 30
    if-nez p1, :cond_1

    .line 31
    .line 32
    invoke-static {}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StoppingReasonStatusPPE;->getEntries()Lsx0/a;

    .line 33
    .line 34
    .line 35
    move-result-object p1

    .line 36
    invoke-static {p1}, Lmx0/q;->C0(Ljava/lang/Iterable;)Ljava/util/Set;

    .line 37
    .line 38
    .line 39
    move-result-object p1

    .line 40
    sget-object p2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StoppingReasonStatusPPE;->NO_REASON:Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StoppingReasonStatusPPE;

    .line 41
    .line 42
    invoke-static {p1, p2}, Ljp/m1;->e(Ljava/util/Set;Ljava/lang/Object;)Ljava/util/LinkedHashSet;

    .line 43
    .line 44
    .line 45
    move-result-object p1

    .line 46
    invoke-interface {p1, p0}, Ljava/util/Set;->contains(Ljava/lang/Object;)Z

    .line 47
    .line 48
    .line 49
    move-result p0

    .line 50
    if-eqz p0, :cond_0

    .line 51
    .line 52
    goto :goto_0

    .line 53
    :cond_0
    const/4 p0, 0x0

    .line 54
    return p0

    .line 55
    :cond_1
    :goto_0
    const/4 p0, 0x1

    .line 56
    return p0
.end method

.method public static final c(Ljava/lang/Object;Ljava/lang/Object;)Llx0/l;
    .locals 1

    .line 1
    new-instance v0, Llx0/l;

    .line 2
    .line 3
    invoke-direct {v0, p0, p1}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 4
    .line 5
    .line 6
    return-object v0
.end method
