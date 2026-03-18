.class public final Ld01/q0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static a(Ld01/d0;[BII)Ld01/p0;
    .locals 7

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    array-length v0, p1

    .line 7
    int-to-long v1, v0

    .line 8
    int-to-long v3, p2

    .line 9
    int-to-long v5, p3

    .line 10
    invoke-static/range {v1 .. v6}, Le01/e;->a(JJJ)V

    .line 11
    .line 12
    .line 13
    new-instance v0, Ld01/p0;

    .line 14
    .line 15
    invoke-direct {v0, p0, p1, p3, p2}, Ld01/p0;-><init>(Ld01/d0;[BII)V

    .line 16
    .line 17
    .line 18
    return-object v0
.end method

.method public static b(Ljava/lang/String;Ld01/d0;)Ld01/p0;
    .locals 2

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-static {p1}, Ljp/lg;->a(Ld01/d0;)Llx0/l;

    .line 7
    .line 8
    .line 9
    move-result-object p1

    .line 10
    iget-object v0, p1, Llx0/l;->d:Ljava/lang/Object;

    .line 11
    .line 12
    check-cast v0, Ljava/nio/charset/Charset;

    .line 13
    .line 14
    iget-object p1, p1, Llx0/l;->e:Ljava/lang/Object;

    .line 15
    .line 16
    check-cast p1, Ld01/d0;

    .line 17
    .line 18
    invoke-virtual {p0, v0}, Ljava/lang/String;->getBytes(Ljava/nio/charset/Charset;)[B

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    const-string v0, "getBytes(...)"

    .line 23
    .line 24
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 25
    .line 26
    .line 27
    const/4 v0, 0x0

    .line 28
    array-length v1, p0

    .line 29
    invoke-static {p1, p0, v0, v1}, Ld01/q0;->a(Ld01/d0;[BII)Ld01/p0;

    .line 30
    .line 31
    .line 32
    move-result-object p0

    .line 33
    return-object p0
.end method

.method public static synthetic c(Ld01/q0;[BLd01/d0;II)Ld01/p0;
    .locals 1

    .line 1
    and-int/lit8 v0, p4, 0x1

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    const/4 p2, 0x0

    .line 6
    :cond_0
    and-int/lit8 p4, p4, 0x2

    .line 7
    .line 8
    if-eqz p4, :cond_1

    .line 9
    .line 10
    const/4 p3, 0x0

    .line 11
    :cond_1
    array-length p4, p1

    .line 12
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 13
    .line 14
    .line 15
    invoke-static {p2, p1, p3, p4}, Ld01/q0;->a(Ld01/d0;[BII)Ld01/p0;

    .line 16
    .line 17
    .line 18
    move-result-object p0

    .line 19
    return-object p0
.end method
