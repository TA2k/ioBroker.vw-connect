.class public final synthetic Lcd/j;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Luz0/c0;


# static fields
.field public static final a:Lcd/j;

.field private static final descriptor:Lsz0/g;


# direct methods
.method static constructor <clinit>()V
    .locals 4

    .line 1
    new-instance v0, Lcd/j;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lcd/j;->a:Lcd/j;

    .line 7
    .line 8
    new-instance v1, Luz0/d1;

    .line 9
    .line 10
    const-string v2, "cariad.charging.multicharge.kitten.charginghistory.models.home.HomeChargingHistoryRequest"

    .line 11
    .line 12
    const/4 v3, 0x3

    .line 13
    invoke-direct {v1, v2, v0, v3}, Luz0/d1;-><init>(Ljava/lang/String;Luz0/c0;I)V

    .line 14
    .line 15
    .line 16
    const-string v0, "lastRecordCreatedAt"

    .line 17
    .line 18
    const/4 v2, 0x1

    .line 19
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 20
    .line 21
    .line 22
    const-string v0, "filteredBy"

    .line 23
    .line 24
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 25
    .line 26
    .line 27
    const-string v0, "retrieveFilters"

    .line 28
    .line 29
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 30
    .line 31
    .line 32
    sput-object v1, Lcd/j;->descriptor:Lsz0/g;

    .line 33
    .line 34
    return-void
.end method


# virtual methods
.method public final childSerializers()[Lqz0/a;
    .locals 4

    .line 1
    sget-object p0, Lmz0/f;->a:Lmz0/f;

    .line 2
    .line 3
    invoke-static {p0}, Lkp/u6;->c(Lqz0/a;)Lqz0/a;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    sget-object v0, Lcd/l;->a:Lcd/l;

    .line 8
    .line 9
    invoke-static {v0}, Lkp/u6;->c(Lqz0/a;)Lqz0/a;

    .line 10
    .line 11
    .line 12
    move-result-object v0

    .line 13
    sget-object v1, Luz0/g;->a:Luz0/g;

    .line 14
    .line 15
    invoke-static {v1}, Lkp/u6;->c(Lqz0/a;)Lqz0/a;

    .line 16
    .line 17
    .line 18
    move-result-object v1

    .line 19
    const/4 v2, 0x3

    .line 20
    new-array v2, v2, [Lqz0/a;

    .line 21
    .line 22
    const/4 v3, 0x0

    .line 23
    aput-object p0, v2, v3

    .line 24
    .line 25
    const/4 p0, 0x1

    .line 26
    aput-object v0, v2, p0

    .line 27
    .line 28
    const/4 p0, 0x2

    .line 29
    aput-object v1, v2, p0

    .line 30
    .line 31
    return-object v2
.end method

.method public final deserialize(Ltz0/c;)Ljava/lang/Object;
    .locals 9

    .line 1
    sget-object p0, Lcd/j;->descriptor:Lsz0/g;

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
    const/4 v8, 0x2

    .line 28
    if-ne v7, v8, :cond_0

    .line 29
    .line 30
    sget-object v7, Luz0/g;->a:Luz0/g;

    .line 31
    .line 32
    invoke-interface {p1, p0, v8, v7, v4}, Ltz0/a;->g(Lsz0/g;ILqz0/a;Ljava/lang/Object;)Ljava/lang/Object;

    .line 33
    .line 34
    .line 35
    move-result-object v4

    .line 36
    check-cast v4, Ljava/lang/Boolean;

    .line 37
    .line 38
    or-int/lit8 v6, v6, 0x4

    .line 39
    .line 40
    goto :goto_0

    .line 41
    :cond_0
    new-instance p0, Lqz0/k;

    .line 42
    .line 43
    invoke-direct {p0, v7}, Lqz0/k;-><init>(I)V

    .line 44
    .line 45
    .line 46
    throw p0

    .line 47
    :cond_1
    sget-object v7, Lcd/l;->a:Lcd/l;

    .line 48
    .line 49
    invoke-interface {p1, p0, v0, v7, v3}, Ltz0/a;->g(Lsz0/g;ILqz0/a;Ljava/lang/Object;)Ljava/lang/Object;

    .line 50
    .line 51
    .line 52
    move-result-object v3

    .line 53
    check-cast v3, Lcd/n;

    .line 54
    .line 55
    or-int/lit8 v6, v6, 0x2

    .line 56
    .line 57
    goto :goto_0

    .line 58
    :cond_2
    sget-object v7, Lmz0/f;->a:Lmz0/f;

    .line 59
    .line 60
    invoke-interface {p1, p0, v1, v7, v2}, Ltz0/a;->g(Lsz0/g;ILqz0/a;Ljava/lang/Object;)Ljava/lang/Object;

    .line 61
    .line 62
    .line 63
    move-result-object v2

    .line 64
    check-cast v2, Lgz0/p;

    .line 65
    .line 66
    or-int/lit8 v6, v6, 0x1

    .line 67
    .line 68
    goto :goto_0

    .line 69
    :cond_3
    move v5, v1

    .line 70
    goto :goto_0

    .line 71
    :cond_4
    invoke-interface {p1, p0}, Ltz0/a;->b(Lsz0/g;)V

    .line 72
    .line 73
    .line 74
    new-instance p0, Lcd/o;

    .line 75
    .line 76
    invoke-direct {p0, v6, v2, v3, v4}, Lcd/o;-><init>(ILgz0/p;Lcd/n;Ljava/lang/Boolean;)V

    .line 77
    .line 78
    .line 79
    return-object p0
.end method

.method public final getDescriptor()Lsz0/g;
    .locals 0

    .line 1
    sget-object p0, Lcd/j;->descriptor:Lsz0/g;

    .line 2
    .line 3
    return-object p0
.end method

.method public final serialize(Ltz0/d;Ljava/lang/Object;)V
    .locals 4

    .line 1
    check-cast p2, Lcd/o;

    .line 2
    .line 3
    const-string p0, "value"

    .line 4
    .line 5
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-object p0, p2, Lcd/o;->c:Ljava/lang/Boolean;

    .line 9
    .line 10
    iget-object v0, p2, Lcd/o;->b:Lcd/n;

    .line 11
    .line 12
    iget-object p2, p2, Lcd/o;->a:Lgz0/p;

    .line 13
    .line 14
    sget-object v1, Lcd/j;->descriptor:Lsz0/g;

    .line 15
    .line 16
    invoke-interface {p1, v1}, Ltz0/d;->a(Lsz0/g;)Ltz0/b;

    .line 17
    .line 18
    .line 19
    move-result-object p1

    .line 20
    invoke-interface {p1, v1}, Ltz0/b;->e(Lsz0/g;)Z

    .line 21
    .line 22
    .line 23
    move-result v2

    .line 24
    if-eqz v2, :cond_0

    .line 25
    .line 26
    goto :goto_0

    .line 27
    :cond_0
    if-eqz p2, :cond_1

    .line 28
    .line 29
    :goto_0
    sget-object v2, Lmz0/f;->a:Lmz0/f;

    .line 30
    .line 31
    const/4 v3, 0x0

    .line 32
    invoke-interface {p1, v1, v3, v2, p2}, Ltz0/b;->A(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V

    .line 33
    .line 34
    .line 35
    :cond_1
    invoke-interface {p1, v1}, Ltz0/b;->e(Lsz0/g;)Z

    .line 36
    .line 37
    .line 38
    move-result p2

    .line 39
    if-eqz p2, :cond_2

    .line 40
    .line 41
    goto :goto_1

    .line 42
    :cond_2
    if-eqz v0, :cond_3

    .line 43
    .line 44
    :goto_1
    sget-object p2, Lcd/l;->a:Lcd/l;

    .line 45
    .line 46
    const/4 v2, 0x1

    .line 47
    invoke-interface {p1, v1, v2, p2, v0}, Ltz0/b;->A(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V

    .line 48
    .line 49
    .line 50
    :cond_3
    invoke-interface {p1, v1}, Ltz0/b;->e(Lsz0/g;)Z

    .line 51
    .line 52
    .line 53
    move-result p2

    .line 54
    if-eqz p2, :cond_4

    .line 55
    .line 56
    goto :goto_2

    .line 57
    :cond_4
    if-eqz p0, :cond_5

    .line 58
    .line 59
    :goto_2
    sget-object p2, Luz0/g;->a:Luz0/g;

    .line 60
    .line 61
    const/4 v0, 0x2

    .line 62
    invoke-interface {p1, v1, v0, p2, p0}, Ltz0/b;->A(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V

    .line 63
    .line 64
    .line 65
    :cond_5
    invoke-interface {p1, v1}, Ltz0/b;->b(Lsz0/g;)V

    .line 66
    .line 67
    .line 68
    return-void
.end method
