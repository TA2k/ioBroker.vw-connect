.class public abstract Ljp/s1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(ZLn1/n;I)I
    .locals 0

    .line 1
    if-eqz p0, :cond_0

    .line 2
    .line 3
    iget-object p0, p1, Ln1/n;->m:Ljava/lang/Object;

    .line 4
    .line 5
    invoke-interface {p0, p2}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    check-cast p0, Ln1/o;

    .line 10
    .line 11
    iget p0, p0, Ln1/o;->u:I

    .line 12
    .line 13
    return p0

    .line 14
    :cond_0
    iget-object p0, p1, Ln1/n;->m:Ljava/lang/Object;

    .line 15
    .line 16
    invoke-interface {p0, p2}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 17
    .line 18
    .line 19
    move-result-object p0

    .line 20
    check-cast p0, Ln1/o;

    .line 21
    .line 22
    iget p0, p0, Ln1/o;->v:I

    .line 23
    .line 24
    return p0
.end method
