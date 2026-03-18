.class public abstract Lkotlin/jvm/internal/y;
.super Lkotlin/jvm/internal/a0;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lhy0/y;


# virtual methods
.method public final computeReflected()Lhy0/c;
    .locals 1

    .line 1
    sget-object v0, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 2
    .line 3
    invoke-virtual {v0, p0}, Lkotlin/jvm/internal/h0;->property2(Lkotlin/jvm/internal/y;)Lhy0/y;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final bridge synthetic getGetter()Lhy0/s;
    .locals 0

    .line 1
    invoke-virtual {p0}, Lkotlin/jvm/internal/y;->getGetter()Lhy0/x;

    move-result-object p0

    return-object p0
.end method

.method public final getGetter()Lhy0/x;
    .locals 0

    .line 2
    invoke-virtual {p0}, Lkotlin/jvm/internal/a0;->getReflected()Lhy0/z;

    move-result-object p0

    check-cast p0, Lhy0/y;

    invoke-interface {p0}, Lhy0/y;->getGetter()Lhy0/x;

    move-result-object p0

    return-object p0
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p0, Lkotlin/jvm/internal/z;

    .line 2
    .line 3
    invoke-virtual {p0}, Lkotlin/jvm/internal/y;->getGetter()Lhy0/x;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    filled-new-array {p1, p2}, [Ljava/lang/Object;

    .line 8
    .line 9
    .line 10
    move-result-object p1

    .line 11
    invoke-interface {p0, p1}, Lhy0/c;->call([Ljava/lang/Object;)Ljava/lang/Object;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    return-object p0
.end method
