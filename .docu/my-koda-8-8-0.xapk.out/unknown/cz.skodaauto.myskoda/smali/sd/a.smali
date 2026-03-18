.class public final Lsd/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/util/Comparator;


# virtual methods
.method public final compare(Ljava/lang/Object;Ljava/lang/Object;)I
    .locals 0

    .line 1
    check-cast p1, Lpd/e0;

    .line 2
    .line 3
    iget-object p0, p1, Lpd/e0;->d:Lgz0/p;

    .line 4
    .line 5
    check-cast p2, Lpd/e0;

    .line 6
    .line 7
    iget-object p1, p2, Lpd/e0;->d:Lgz0/p;

    .line 8
    .line 9
    invoke-static {p0, p1}, Ljp/vc;->c(Ljava/lang/Comparable;Ljava/lang/Comparable;)I

    .line 10
    .line 11
    .line 12
    move-result p0

    .line 13
    return p0
.end method
