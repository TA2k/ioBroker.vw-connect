.class public final Lpw0/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public a:Ljava/util/ArrayList;


# virtual methods
.method public final a(I)I
    .locals 1

    .line 1
    iget-object p0, p0, Lpw0/c;->a:Ljava/util/ArrayList;

    .line 2
    .line 3
    div-int/lit16 v0, p1, 0x300

    .line 4
    .line 5
    invoke-virtual {p0, v0}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    check-cast p0, [I

    .line 10
    .line 11
    rem-int/lit16 p1, p1, 0x300

    .line 12
    .line 13
    aget p0, p0, p1

    .line 14
    .line 15
    return p0
.end method

.method public final b(II)V
    .locals 1

    .line 1
    iget-object p0, p0, Lpw0/c;->a:Ljava/util/ArrayList;

    .line 2
    .line 3
    div-int/lit16 v0, p1, 0x300

    .line 4
    .line 5
    invoke-virtual {p0, v0}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    check-cast p0, [I

    .line 10
    .line 11
    rem-int/lit16 p1, p1, 0x300

    .line 12
    .line 13
    aput p2, p0, p1

    .line 14
    .line 15
    return-void
.end method
