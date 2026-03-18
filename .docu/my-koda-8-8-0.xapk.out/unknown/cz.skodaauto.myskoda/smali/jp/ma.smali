.class public abstract Ljp/ma;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(ZLij0/a;)Ljava/lang/String;
    .locals 2

    .line 1
    const/4 v0, 0x1

    .line 2
    const/4 v1, 0x0

    .line 3
    if-ne p0, v0, :cond_0

    .line 4
    .line 5
    new-array p0, v1, [Ljava/lang/Object;

    .line 6
    .line 7
    check-cast p1, Ljj0/f;

    .line 8
    .line 9
    const v0, 0x7f121559

    .line 10
    .line 11
    .line 12
    invoke-virtual {p1, v0, p0}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 13
    .line 14
    .line 15
    move-result-object p0

    .line 16
    return-object p0

    .line 17
    :cond_0
    if-nez p0, :cond_1

    .line 18
    .line 19
    new-array p0, v1, [Ljava/lang/Object;

    .line 20
    .line 21
    check-cast p1, Ljj0/f;

    .line 22
    .line 23
    const v0, 0x7f12155a

    .line 24
    .line 25
    .line 26
    invoke-virtual {p1, v0, p0}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 27
    .line 28
    .line 29
    move-result-object p0

    .line 30
    return-object p0

    .line 31
    :cond_1
    new-instance p0, La8/r0;

    .line 32
    .line 33
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 34
    .line 35
    .line 36
    throw p0
.end method
