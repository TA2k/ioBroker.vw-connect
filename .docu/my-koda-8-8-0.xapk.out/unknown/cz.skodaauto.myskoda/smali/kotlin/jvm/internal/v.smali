.class public abstract Lkotlin/jvm/internal/v;
.super Lkotlin/jvm/internal/a0;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lhy0/u;


# virtual methods
.method public final computeReflected()Lhy0/c;
    .locals 1

    .line 1
    sget-object v0, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 2
    .line 3
    invoke-virtual {v0, p0}, Lkotlin/jvm/internal/h0;->property0(Lkotlin/jvm/internal/v;)Lhy0/u;

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
    invoke-virtual {p0}, Lkotlin/jvm/internal/v;->getGetter()Lhy0/t;

    move-result-object p0

    return-object p0
.end method

.method public final getGetter()Lhy0/t;
    .locals 0

    .line 2
    invoke-virtual {p0}, Lkotlin/jvm/internal/a0;->getReflected()Lhy0/z;

    move-result-object p0

    check-cast p0, Lhy0/u;

    invoke-interface {p0}, Lhy0/u;->getGetter()Lhy0/t;

    move-result-object p0

    return-object p0
.end method

.method public final invoke()Ljava/lang/Object;
    .locals 0

    .line 1
    invoke-interface {p0}, Lhy0/u;->get()Ljava/lang/Object;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method
