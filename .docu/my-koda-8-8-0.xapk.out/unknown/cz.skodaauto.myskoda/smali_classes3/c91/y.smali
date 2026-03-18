.class public final synthetic Lc91/y;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Luz0/c0;


# static fields
.field public static final a:Lc91/y;

.field private static final descriptor:Lsz0/g;


# direct methods
.method static constructor <clinit>()V
    .locals 4

    .line 1
    new-instance v0, Lc91/y;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lc91/y;->a:Lc91/y;

    .line 7
    .line 8
    new-instance v1, Luz0/d1;

    .line 9
    .line 10
    const-string v2, "technology.cariad.cat.telemetry.serialization.PersistableSpanData"

    .line 11
    .line 12
    const/4 v3, 0x4

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
    const-string v0, "spans"

    .line 23
    .line 24
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 25
    .line 26
    .line 27
    const-string v0, "creationTimeStamp"

    .line 28
    .line 29
    const/4 v2, 0x1

    .line 30
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 31
    .line 32
    .line 33
    const-string v0, "retryCount"

    .line 34
    .line 35
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 36
    .line 37
    .line 38
    sput-object v1, Lc91/y;->descriptor:Lsz0/g;

    .line 39
    .line 40
    return-void
.end method


# virtual methods
.method public final childSerializers()[Lqz0/a;
    .locals 3

    .line 1
    sget-object p0, Lc91/a0;->e:[Llx0/i;

    .line 2
    .line 3
    const/4 v0, 0x4

    .line 4
    new-array v0, v0, [Lqz0/a;

    .line 5
    .line 6
    const/4 v1, 0x0

    .line 7
    sget-object v2, Luz0/q1;->a:Luz0/q1;

    .line 8
    .line 9
    aput-object v2, v0, v1

    .line 10
    .line 11
    const/4 v1, 0x1

    .line 12
    aget-object p0, p0, v1

    .line 13
    .line 14
    invoke-interface {p0}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 15
    .line 16
    .line 17
    move-result-object p0

    .line 18
    aput-object p0, v0, v1

    .line 19
    .line 20
    const/4 p0, 0x2

    .line 21
    sget-object v1, Luz0/q0;->a:Luz0/q0;

    .line 22
    .line 23
    aput-object v1, v0, p0

    .line 24
    .line 25
    const/4 p0, 0x3

    .line 26
    sget-object v1, Luz0/k0;->a:Luz0/k0;

    .line 27
    .line 28
    aput-object v1, v0, p0

    .line 29
    .line 30
    return-object v0
.end method

.method public final deserialize(Ltz0/c;)Ljava/lang/Object;
    .locals 13

    .line 1
    sget-object p0, Lc91/y;->descriptor:Lsz0/g;

    .line 2
    .line 3
    invoke-interface {p1, p0}, Ltz0/c;->a(Lsz0/g;)Ltz0/a;

    .line 4
    .line 5
    .line 6
    move-result-object p1

    .line 7
    sget-object v0, Lc91/a0;->e:[Llx0/i;

    .line 8
    .line 9
    const/4 v1, 0x1

    .line 10
    const/4 v2, 0x0

    .line 11
    const/4 v3, 0x0

    .line 12
    const-wide/16 v4, 0x0

    .line 13
    .line 14
    move v7, v2

    .line 15
    move v12, v7

    .line 16
    move-object v8, v3

    .line 17
    move-object v9, v8

    .line 18
    move-wide v10, v4

    .line 19
    move v3, v1

    .line 20
    :goto_0
    if-eqz v3, :cond_5

    .line 21
    .line 22
    invoke-interface {p1, p0}, Ltz0/a;->E(Lsz0/g;)I

    .line 23
    .line 24
    .line 25
    move-result v4

    .line 26
    const/4 v5, -0x1

    .line 27
    if-eq v4, v5, :cond_4

    .line 28
    .line 29
    if-eqz v4, :cond_3

    .line 30
    .line 31
    if-eq v4, v1, :cond_2

    .line 32
    .line 33
    const/4 v5, 0x2

    .line 34
    if-eq v4, v5, :cond_1

    .line 35
    .line 36
    const/4 v5, 0x3

    .line 37
    if-ne v4, v5, :cond_0

    .line 38
    .line 39
    invoke-interface {p1, p0, v5}, Ltz0/a;->l(Lsz0/g;I)I

    .line 40
    .line 41
    .line 42
    move-result v12

    .line 43
    or-int/lit8 v7, v7, 0x8

    .line 44
    .line 45
    goto :goto_0

    .line 46
    :cond_0
    new-instance p0, Lqz0/k;

    .line 47
    .line 48
    invoke-direct {p0, v4}, Lqz0/k;-><init>(I)V

    .line 49
    .line 50
    .line 51
    throw p0

    .line 52
    :cond_1
    invoke-interface {p1, p0, v5}, Ltz0/a;->A(Lsz0/g;I)J

    .line 53
    .line 54
    .line 55
    move-result-wide v10

    .line 56
    or-int/lit8 v7, v7, 0x4

    .line 57
    .line 58
    goto :goto_0

    .line 59
    :cond_2
    aget-object v4, v0, v1

    .line 60
    .line 61
    invoke-interface {v4}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 62
    .line 63
    .line 64
    move-result-object v4

    .line 65
    check-cast v4, Lqz0/a;

    .line 66
    .line 67
    invoke-interface {p1, p0, v1, v4, v9}, Ltz0/a;->r(Lsz0/g;ILqz0/a;Ljava/lang/Object;)Ljava/lang/Object;

    .line 68
    .line 69
    .line 70
    move-result-object v4

    .line 71
    move-object v9, v4

    .line 72
    check-cast v9, Ljava/util/List;

    .line 73
    .line 74
    or-int/lit8 v7, v7, 0x2

    .line 75
    .line 76
    goto :goto_0

    .line 77
    :cond_3
    invoke-interface {p1, p0, v2}, Ltz0/a;->k(Lsz0/g;I)Ljava/lang/String;

    .line 78
    .line 79
    .line 80
    move-result-object v8

    .line 81
    or-int/lit8 v7, v7, 0x1

    .line 82
    .line 83
    goto :goto_0

    .line 84
    :cond_4
    move v3, v2

    .line 85
    goto :goto_0

    .line 86
    :cond_5
    invoke-interface {p1, p0}, Ltz0/a;->b(Lsz0/g;)V

    .line 87
    .line 88
    .line 89
    new-instance v6, Lc91/a0;

    .line 90
    .line 91
    invoke-direct/range {v6 .. v12}, Lc91/a0;-><init>(ILjava/lang/String;Ljava/util/List;JI)V

    .line 92
    .line 93
    .line 94
    return-object v6
.end method

.method public final getDescriptor()Lsz0/g;
    .locals 0

    .line 1
    sget-object p0, Lc91/y;->descriptor:Lsz0/g;

    .line 2
    .line 3
    return-object p0
.end method

.method public final serialize(Ltz0/d;Ljava/lang/Object;)V
    .locals 6

    .line 1
    check-cast p2, Lc91/a0;

    .line 2
    .line 3
    const-string p0, "value"

    .line 4
    .line 5
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    sget-object p0, Lc91/y;->descriptor:Lsz0/g;

    .line 9
    .line 10
    invoke-interface {p1, p0}, Ltz0/d;->a(Lsz0/g;)Ltz0/b;

    .line 11
    .line 12
    .line 13
    move-result-object p1

    .line 14
    sget-object v0, Lc91/a0;->e:[Llx0/i;

    .line 15
    .line 16
    iget-object v1, p2, Lc91/a0;->a:Ljava/lang/String;

    .line 17
    .line 18
    iget v2, p2, Lc91/a0;->d:I

    .line 19
    .line 20
    iget-wide v3, p2, Lc91/a0;->c:J

    .line 21
    .line 22
    const/4 v5, 0x0

    .line 23
    invoke-interface {p1, p0, v5, v1}, Ltz0/b;->x(Lsz0/g;ILjava/lang/String;)V

    .line 24
    .line 25
    .line 26
    const/4 v1, 0x1

    .line 27
    aget-object v0, v0, v1

    .line 28
    .line 29
    invoke-interface {v0}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 30
    .line 31
    .line 32
    move-result-object v0

    .line 33
    check-cast v0, Lqz0/a;

    .line 34
    .line 35
    iget-object p2, p2, Lc91/a0;->b:Ljava/util/List;

    .line 36
    .line 37
    invoke-interface {p1, p0, v1, v0, p2}, Ltz0/b;->k(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V

    .line 38
    .line 39
    .line 40
    invoke-interface {p1, p0}, Ltz0/b;->e(Lsz0/g;)Z

    .line 41
    .line 42
    .line 43
    move-result p2

    .line 44
    if-eqz p2, :cond_0

    .line 45
    .line 46
    goto :goto_0

    .line 47
    :cond_0
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    .line 48
    .line 49
    .line 50
    move-result-wide v0

    .line 51
    cmp-long p2, v3, v0

    .line 52
    .line 53
    if-eqz p2, :cond_1

    .line 54
    .line 55
    :goto_0
    const/4 p2, 0x2

    .line 56
    invoke-interface {p1, p0, p2, v3, v4}, Ltz0/b;->z(Lsz0/g;IJ)V

    .line 57
    .line 58
    .line 59
    :cond_1
    invoke-interface {p1, p0}, Ltz0/b;->e(Lsz0/g;)Z

    .line 60
    .line 61
    .line 62
    move-result p2

    .line 63
    if-eqz p2, :cond_2

    .line 64
    .line 65
    goto :goto_1

    .line 66
    :cond_2
    if-eqz v2, :cond_3

    .line 67
    .line 68
    :goto_1
    const/4 p2, 0x3

    .line 69
    invoke-interface {p1, p2, v2, p0}, Ltz0/b;->n(IILsz0/g;)V

    .line 70
    .line 71
    .line 72
    :cond_3
    invoke-interface {p1, p0}, Ltz0/b;->b(Lsz0/g;)V

    .line 73
    .line 74
    .line 75
    return-void
.end method
