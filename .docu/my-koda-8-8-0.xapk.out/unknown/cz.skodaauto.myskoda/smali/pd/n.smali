.class public final synthetic Lpd/n;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Luz0/c0;


# static fields
.field public static final a:Lpd/n;

.field private static final descriptor:Lsz0/g;


# direct methods
.method static constructor <clinit>()V
    .locals 4

    .line 1
    new-instance v0, Lpd/n;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lpd/n;->a:Lpd/n;

    .line 7
    .line 8
    new-instance v1, Luz0/d1;

    .line 9
    .line 10
    const-string v2, "cariad.charging.multicharge.kitten.chargingstatistics.models.ChargingStatisticsFilterOption"

    .line 11
    .line 12
    const/4 v3, 0x3

    .line 13
    invoke-direct {v1, v2, v0, v3}, Luz0/d1;-><init>(Ljava/lang/String;Luz0/c0;I)V

    .line 14
    .line 15
    .line 16
    const-string v0, "id"

    .line 17
    .line 18
    const/4 v2, 0x0

    .line 19
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 20
    .line 21
    .line 22
    const-string v0, "label"

    .line 23
    .line 24
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 25
    .line 26
    .line 27
    const-string v0, "filterType"

    .line 28
    .line 29
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 30
    .line 31
    .line 32
    sput-object v1, Lpd/n;->descriptor:Lsz0/g;

    .line 33
    .line 34
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
    const/4 v1, 0x3

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
    const/4 v0, 0x2

    .line 17
    aput-object p0, v1, v0

    .line 18
    .line 19
    return-object v1
.end method

.method public final deserialize(Ltz0/c;)Ljava/lang/Object;
    .locals 9

    .line 1
    sget-object p0, Lpd/n;->descriptor:Lsz0/g;

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
    move v5, v0

    .line 11
    move v6, v1

    .line 12
    move-object v3, v2

    .line 13
    move-object v4, v3

    .line 14
    :goto_0
    if-eqz v5, :cond_4

    .line 15
    .line 16
    invoke-interface {p1, p0}, Ltz0/a;->E(Lsz0/g;)I

    .line 17
    .line 18
    .line 19
    move-result v7

    .line 20
    const/4 v8, -0x1

    .line 21
    if-eq v7, v8, :cond_3

    .line 22
    .line 23
    if-eqz v7, :cond_2

    .line 24
    .line 25
    if-eq v7, v0, :cond_1

    .line 26
    .line 27
    const/4 v4, 0x2

    .line 28
    if-ne v7, v4, :cond_0

    .line 29
    .line 30
    invoke-interface {p1, p0, v4}, Ltz0/a;->k(Lsz0/g;I)Ljava/lang/String;

    .line 31
    .line 32
    .line 33
    move-result-object v4

    .line 34
    or-int/lit8 v6, v6, 0x4

    .line 35
    .line 36
    goto :goto_0

    .line 37
    :cond_0
    new-instance p0, Lqz0/k;

    .line 38
    .line 39
    invoke-direct {p0, v7}, Lqz0/k;-><init>(I)V

    .line 40
    .line 41
    .line 42
    throw p0

    .line 43
    :cond_1
    invoke-interface {p1, p0, v0}, Ltz0/a;->k(Lsz0/g;I)Ljava/lang/String;

    .line 44
    .line 45
    .line 46
    move-result-object v3

    .line 47
    or-int/lit8 v6, v6, 0x2

    .line 48
    .line 49
    goto :goto_0

    .line 50
    :cond_2
    sget-object v7, Luz0/q1;->a:Luz0/q1;

    .line 51
    .line 52
    invoke-interface {p1, p0, v1, v7, v2}, Ltz0/a;->g(Lsz0/g;ILqz0/a;Ljava/lang/Object;)Ljava/lang/Object;

    .line 53
    .line 54
    .line 55
    move-result-object v2

    .line 56
    check-cast v2, Ljava/lang/String;

    .line 57
    .line 58
    or-int/lit8 v6, v6, 0x1

    .line 59
    .line 60
    goto :goto_0

    .line 61
    :cond_3
    move v5, v1

    .line 62
    goto :goto_0

    .line 63
    :cond_4
    invoke-interface {p1, p0}, Ltz0/a;->b(Lsz0/g;)V

    .line 64
    .line 65
    .line 66
    new-instance p0, Lpd/p;

    .line 67
    .line 68
    invoke-direct {p0, v6, v2, v3, v4}, Lpd/p;-><init>(ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 69
    .line 70
    .line 71
    return-object p0
.end method

.method public final getDescriptor()Lsz0/g;
    .locals 0

    .line 1
    sget-object p0, Lpd/n;->descriptor:Lsz0/g;

    .line 2
    .line 3
    return-object p0
.end method

.method public final serialize(Ltz0/d;Ljava/lang/Object;)V
    .locals 3

    .line 1
    check-cast p2, Lpd/p;

    .line 2
    .line 3
    const-string p0, "value"

    .line 4
    .line 5
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    sget-object p0, Lpd/n;->descriptor:Lsz0/g;

    .line 9
    .line 10
    invoke-interface {p1, p0}, Ltz0/d;->a(Lsz0/g;)Ltz0/b;

    .line 11
    .line 12
    .line 13
    move-result-object p1

    .line 14
    sget-object v0, Luz0/q1;->a:Luz0/q1;

    .line 15
    .line 16
    iget-object v1, p2, Lpd/p;->a:Ljava/lang/String;

    .line 17
    .line 18
    const/4 v2, 0x0

    .line 19
    invoke-interface {p1, p0, v2, v0, v1}, Ltz0/b;->A(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V

    .line 20
    .line 21
    .line 22
    const/4 v0, 0x1

    .line 23
    iget-object v1, p2, Lpd/p;->b:Ljava/lang/String;

    .line 24
    .line 25
    invoke-interface {p1, p0, v0, v1}, Ltz0/b;->x(Lsz0/g;ILjava/lang/String;)V

    .line 26
    .line 27
    .line 28
    const/4 v0, 0x2

    .line 29
    iget-object p2, p2, Lpd/p;->c:Ljava/lang/String;

    .line 30
    .line 31
    invoke-interface {p1, p0, v0, p2}, Ltz0/b;->x(Lsz0/g;ILjava/lang/String;)V

    .line 32
    .line 33
    .line 34
    invoke-interface {p1, p0}, Ltz0/b;->b(Lsz0/g;)V

    .line 35
    .line 36
    .line 37
    return-void
.end method
