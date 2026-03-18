.class public final synthetic Ldc/r;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Luz0/c0;


# static fields
.field public static final a:Ldc/r;

.field private static final descriptor:Lsz0/g;


# direct methods
.method static constructor <clinit>()V
    .locals 4

    .line 1
    new-instance v0, Ldc/r;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Ldc/r;->a:Ldc/r;

    .line 7
    .line 8
    new-instance v1, Luz0/d1;

    .line 9
    .line 10
    const-string v2, "cariad.charging.multicharge.common.presentation.consent.models.ConsentInitResponse"

    .line 11
    .line 12
    const/4 v3, 0x3

    .line 13
    invoke-direct {v1, v2, v0, v3}, Luz0/d1;-><init>(Ljava/lang/String;Luz0/c0;I)V

    .line 14
    .line 15
    .line 16
    const-string v0, "documents"

    .line 17
    .line 18
    const/4 v2, 0x0

    .line 19
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 20
    .line 21
    .line 22
    const-string v0, "countrySelection"

    .line 23
    .line 24
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 25
    .line 26
    .line 27
    const-string v0, "preSelectedCountry"

    .line 28
    .line 29
    const/4 v2, 0x1

    .line 30
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 31
    .line 32
    .line 33
    sput-object v1, Ldc/r;->descriptor:Lsz0/g;

    .line 34
    .line 35
    return-void
.end method


# virtual methods
.method public final childSerializers()[Lqz0/a;
    .locals 3

    .line 1
    sget-object p0, Ldc/t;->d:[Llx0/i;

    .line 2
    .line 3
    const/4 v0, 0x3

    .line 4
    new-array v0, v0, [Lqz0/a;

    .line 5
    .line 6
    const/4 v1, 0x0

    .line 7
    aget-object v2, p0, v1

    .line 8
    .line 9
    invoke-interface {v2}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 10
    .line 11
    .line 12
    move-result-object v2

    .line 13
    aput-object v2, v0, v1

    .line 14
    .line 15
    const/4 v1, 0x1

    .line 16
    aget-object p0, p0, v1

    .line 17
    .line 18
    invoke-interface {p0}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    aput-object p0, v0, v1

    .line 23
    .line 24
    sget-object p0, Luz0/q1;->a:Luz0/q1;

    .line 25
    .line 26
    invoke-static {p0}, Lkp/u6;->c(Lqz0/a;)Lqz0/a;

    .line 27
    .line 28
    .line 29
    move-result-object p0

    .line 30
    const/4 v1, 0x2

    .line 31
    aput-object p0, v0, v1

    .line 32
    .line 33
    return-object v0
.end method

.method public final deserialize(Ltz0/c;)Ljava/lang/Object;
    .locals 10

    .line 1
    sget-object p0, Ldc/r;->descriptor:Lsz0/g;

    .line 2
    .line 3
    invoke-interface {p1, p0}, Ltz0/c;->a(Lsz0/g;)Ltz0/a;

    .line 4
    .line 5
    .line 6
    move-result-object p1

    .line 7
    sget-object v0, Ldc/t;->d:[Llx0/i;

    .line 8
    .line 9
    const/4 v1, 0x1

    .line 10
    const/4 v2, 0x0

    .line 11
    const/4 v3, 0x0

    .line 12
    move v6, v1

    .line 13
    move v7, v2

    .line 14
    move-object v4, v3

    .line 15
    move-object v5, v4

    .line 16
    :goto_0
    if-eqz v6, :cond_4

    .line 17
    .line 18
    invoke-interface {p1, p0}, Ltz0/a;->E(Lsz0/g;)I

    .line 19
    .line 20
    .line 21
    move-result v8

    .line 22
    const/4 v9, -0x1

    .line 23
    if-eq v8, v9, :cond_3

    .line 24
    .line 25
    if-eqz v8, :cond_2

    .line 26
    .line 27
    if-eq v8, v1, :cond_1

    .line 28
    .line 29
    const/4 v9, 0x2

    .line 30
    if-ne v8, v9, :cond_0

    .line 31
    .line 32
    sget-object v8, Luz0/q1;->a:Luz0/q1;

    .line 33
    .line 34
    invoke-interface {p1, p0, v9, v8, v5}, Ltz0/a;->g(Lsz0/g;ILqz0/a;Ljava/lang/Object;)Ljava/lang/Object;

    .line 35
    .line 36
    .line 37
    move-result-object v5

    .line 38
    check-cast v5, Ljava/lang/String;

    .line 39
    .line 40
    or-int/lit8 v7, v7, 0x4

    .line 41
    .line 42
    goto :goto_0

    .line 43
    :cond_0
    new-instance p0, Lqz0/k;

    .line 44
    .line 45
    invoke-direct {p0, v8}, Lqz0/k;-><init>(I)V

    .line 46
    .line 47
    .line 48
    throw p0

    .line 49
    :cond_1
    aget-object v8, v0, v1

    .line 50
    .line 51
    invoke-interface {v8}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 52
    .line 53
    .line 54
    move-result-object v8

    .line 55
    check-cast v8, Lqz0/a;

    .line 56
    .line 57
    invoke-interface {p1, p0, v1, v8, v4}, Ltz0/a;->r(Lsz0/g;ILqz0/a;Ljava/lang/Object;)Ljava/lang/Object;

    .line 58
    .line 59
    .line 60
    move-result-object v4

    .line 61
    check-cast v4, Ljava/util/List;

    .line 62
    .line 63
    or-int/lit8 v7, v7, 0x2

    .line 64
    .line 65
    goto :goto_0

    .line 66
    :cond_2
    aget-object v8, v0, v2

    .line 67
    .line 68
    invoke-interface {v8}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 69
    .line 70
    .line 71
    move-result-object v8

    .line 72
    check-cast v8, Lqz0/a;

    .line 73
    .line 74
    invoke-interface {p1, p0, v2, v8, v3}, Ltz0/a;->r(Lsz0/g;ILqz0/a;Ljava/lang/Object;)Ljava/lang/Object;

    .line 75
    .line 76
    .line 77
    move-result-object v3

    .line 78
    check-cast v3, Ljava/util/List;

    .line 79
    .line 80
    or-int/lit8 v7, v7, 0x1

    .line 81
    .line 82
    goto :goto_0

    .line 83
    :cond_3
    move v6, v2

    .line 84
    goto :goto_0

    .line 85
    :cond_4
    invoke-interface {p1, p0}, Ltz0/a;->b(Lsz0/g;)V

    .line 86
    .line 87
    .line 88
    new-instance p0, Ldc/t;

    .line 89
    .line 90
    invoke-direct {p0, v7, v5, v3, v4}, Ldc/t;-><init>(ILjava/lang/String;Ljava/util/List;Ljava/util/List;)V

    .line 91
    .line 92
    .line 93
    return-object p0
.end method

.method public final getDescriptor()Lsz0/g;
    .locals 0

    .line 1
    sget-object p0, Ldc/r;->descriptor:Lsz0/g;

    .line 2
    .line 3
    return-object p0
.end method

.method public final serialize(Ltz0/d;Ljava/lang/Object;)V
    .locals 5

    .line 1
    check-cast p2, Ldc/t;

    .line 2
    .line 3
    const-string p0, "value"

    .line 4
    .line 5
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    sget-object p0, Ldc/r;->descriptor:Lsz0/g;

    .line 9
    .line 10
    invoke-interface {p1, p0}, Ltz0/d;->a(Lsz0/g;)Ltz0/b;

    .line 11
    .line 12
    .line 13
    move-result-object p1

    .line 14
    sget-object v0, Ldc/t;->d:[Llx0/i;

    .line 15
    .line 16
    const/4 v1, 0x0

    .line 17
    aget-object v2, v0, v1

    .line 18
    .line 19
    invoke-interface {v2}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 20
    .line 21
    .line 22
    move-result-object v2

    .line 23
    check-cast v2, Lqz0/a;

    .line 24
    .line 25
    iget-object v3, p2, Ldc/t;->a:Ljava/util/List;

    .line 26
    .line 27
    iget-object v4, p2, Ldc/t;->c:Ljava/lang/String;

    .line 28
    .line 29
    invoke-interface {p1, p0, v1, v2, v3}, Ltz0/b;->k(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V

    .line 30
    .line 31
    .line 32
    const/4 v1, 0x1

    .line 33
    aget-object v0, v0, v1

    .line 34
    .line 35
    invoke-interface {v0}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 36
    .line 37
    .line 38
    move-result-object v0

    .line 39
    check-cast v0, Lqz0/a;

    .line 40
    .line 41
    iget-object p2, p2, Ldc/t;->b:Ljava/util/List;

    .line 42
    .line 43
    invoke-interface {p1, p0, v1, v0, p2}, Ltz0/b;->k(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V

    .line 44
    .line 45
    .line 46
    invoke-interface {p1, p0}, Ltz0/b;->e(Lsz0/g;)Z

    .line 47
    .line 48
    .line 49
    move-result p2

    .line 50
    if-eqz p2, :cond_0

    .line 51
    .line 52
    goto :goto_0

    .line 53
    :cond_0
    if-eqz v4, :cond_1

    .line 54
    .line 55
    :goto_0
    sget-object p2, Luz0/q1;->a:Luz0/q1;

    .line 56
    .line 57
    const/4 v0, 0x2

    .line 58
    invoke-interface {p1, p0, v0, p2, v4}, Ltz0/b;->A(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V

    .line 59
    .line 60
    .line 61
    :cond_1
    invoke-interface {p1, p0}, Ltz0/b;->b(Lsz0/g;)V

    .line 62
    .line 63
    .line 64
    return-void
.end method
