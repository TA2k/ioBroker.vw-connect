.class public final synthetic Lpd/w;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Luz0/c0;


# static fields
.field public static final a:Lpd/w;

.field private static final descriptor:Lsz0/g;


# direct methods
.method static constructor <clinit>()V
    .locals 4

    .line 1
    new-instance v0, Lpd/w;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lpd/w;->a:Lpd/w;

    .line 7
    .line 8
    new-instance v1, Luz0/d1;

    .line 9
    .line 10
    const-string v2, "cariad.charging.multicharge.kitten.chargingstatistics.models.ChargingStatisticsRequestFilterOption"

    .line 11
    .line 12
    const/4 v3, 0x2

    .line 13
    invoke-direct {v1, v2, v0, v3}, Luz0/d1;-><init>(Ljava/lang/String;Luz0/c0;I)V

    .line 14
    .line 15
    .line 16
    const-string v0, "id"

    .line 17
    .line 18
    const/4 v2, 0x1

    .line 19
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 20
    .line 21
    .line 22
    const-string v0, "filterType"

    .line 23
    .line 24
    const/4 v2, 0x0

    .line 25
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 26
    .line 27
    .line 28
    sput-object v1, Lpd/w;->descriptor:Lsz0/g;

    .line 29
    .line 30
    return-void
.end method


# virtual methods
.method public final childSerializers()[Lqz0/a;
    .locals 3

    .line 1
    sget-object p0, Luz0/q1;->a:Luz0/q1;

    .line 2
    .line 3
    invoke-static {p0}, Lkp/u6;->c(Lqz0/a;)Lqz0/a;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    const/4 v1, 0x2

    .line 8
    new-array v1, v1, [Lqz0/a;

    .line 9
    .line 10
    const/4 v2, 0x0

    .line 11
    aput-object v0, v1, v2

    .line 12
    .line 13
    const/4 v0, 0x1

    .line 14
    aput-object p0, v1, v0

    .line 15
    .line 16
    return-object v1
.end method

.method public final deserialize(Ltz0/c;)Ljava/lang/Object;
    .locals 8

    .line 1
    sget-object p0, Lpd/w;->descriptor:Lsz0/g;

    .line 2
    .line 3
    invoke-interface {p1, p0}, Ltz0/c;->a(Lsz0/g;)Ltz0/a;

    .line 4
    .line 5
    .line 6
    move-result-object p1

    .line 7
    const/4 v0, 0x1

    .line 8
    const/4 v1, 0x0

    .line 9
    const/4 v2, 0x0

    .line 10
    move v4, v0

    .line 11
    move v5, v1

    .line 12
    move-object v3, v2

    .line 13
    :goto_0
    if-eqz v4, :cond_3

    .line 14
    .line 15
    invoke-interface {p1, p0}, Ltz0/a;->E(Lsz0/g;)I

    .line 16
    .line 17
    .line 18
    move-result v6

    .line 19
    const/4 v7, -0x1

    .line 20
    if-eq v6, v7, :cond_2

    .line 21
    .line 22
    if-eqz v6, :cond_1

    .line 23
    .line 24
    if-ne v6, v0, :cond_0

    .line 25
    .line 26
    invoke-interface {p1, p0, v0}, Ltz0/a;->k(Lsz0/g;I)Ljava/lang/String;

    .line 27
    .line 28
    .line 29
    move-result-object v3

    .line 30
    or-int/lit8 v5, v5, 0x2

    .line 31
    .line 32
    goto :goto_0

    .line 33
    :cond_0
    new-instance p0, Lqz0/k;

    .line 34
    .line 35
    invoke-direct {p0, v6}, Lqz0/k;-><init>(I)V

    .line 36
    .line 37
    .line 38
    throw p0

    .line 39
    :cond_1
    sget-object v6, Luz0/q1;->a:Luz0/q1;

    .line 40
    .line 41
    invoke-interface {p1, p0, v1, v6, v2}, Ltz0/a;->g(Lsz0/g;ILqz0/a;Ljava/lang/Object;)Ljava/lang/Object;

    .line 42
    .line 43
    .line 44
    move-result-object v2

    .line 45
    check-cast v2, Ljava/lang/String;

    .line 46
    .line 47
    or-int/lit8 v5, v5, 0x1

    .line 48
    .line 49
    goto :goto_0

    .line 50
    :cond_2
    move v4, v1

    .line 51
    goto :goto_0

    .line 52
    :cond_3
    invoke-interface {p1, p0}, Ltz0/a;->b(Lsz0/g;)V

    .line 53
    .line 54
    .line 55
    new-instance p0, Lpd/y;

    .line 56
    .line 57
    invoke-direct {p0, v2, v5, v3}, Lpd/y;-><init>(Ljava/lang/String;ILjava/lang/String;)V

    .line 58
    .line 59
    .line 60
    return-object p0
.end method

.method public final getDescriptor()Lsz0/g;
    .locals 0

    .line 1
    sget-object p0, Lpd/w;->descriptor:Lsz0/g;

    .line 2
    .line 3
    return-object p0
.end method

.method public final serialize(Ltz0/d;Ljava/lang/Object;)V
    .locals 3

    .line 1
    check-cast p2, Lpd/y;

    .line 2
    .line 3
    const-string p0, "value"

    .line 4
    .line 5
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-object p0, p2, Lpd/y;->a:Ljava/lang/String;

    .line 9
    .line 10
    sget-object v0, Lpd/w;->descriptor:Lsz0/g;

    .line 11
    .line 12
    invoke-interface {p1, v0}, Ltz0/d;->a(Lsz0/g;)Ltz0/b;

    .line 13
    .line 14
    .line 15
    move-result-object p1

    .line 16
    invoke-interface {p1, v0}, Ltz0/b;->e(Lsz0/g;)Z

    .line 17
    .line 18
    .line 19
    move-result v1

    .line 20
    if-eqz v1, :cond_0

    .line 21
    .line 22
    goto :goto_0

    .line 23
    :cond_0
    if-eqz p0, :cond_1

    .line 24
    .line 25
    :goto_0
    sget-object v1, Luz0/q1;->a:Luz0/q1;

    .line 26
    .line 27
    const/4 v2, 0x0

    .line 28
    invoke-interface {p1, v0, v2, v1, p0}, Ltz0/b;->A(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V

    .line 29
    .line 30
    .line 31
    :cond_1
    const/4 p0, 0x1

    .line 32
    iget-object p2, p2, Lpd/y;->b:Ljava/lang/String;

    .line 33
    .line 34
    invoke-interface {p1, v0, p0, p2}, Ltz0/b;->x(Lsz0/g;ILjava/lang/String;)V

    .line 35
    .line 36
    .line 37
    invoke-interface {p1, v0}, Ltz0/b;->b(Lsz0/g;)V

    .line 38
    .line 39
    .line 40
    return-void
.end method
