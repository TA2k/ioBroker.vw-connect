.class public final synthetic Lhu/x0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Luz0/c0;


# static fields
.field public static final a:Lhu/x0;

.field private static final descriptor:Lsz0/g;


# direct methods
.method static constructor <clinit>()V
    .locals 4

    .line 1
    new-instance v0, Lhu/x0;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lhu/x0;->a:Lhu/x0;

    .line 7
    .line 8
    new-instance v1, Luz0/d1;

    .line 9
    .line 10
    const-string v2, "com.google.firebase.sessions.Time"

    .line 11
    .line 12
    const/4 v3, 0x3

    .line 13
    invoke-direct {v1, v2, v0, v3}, Luz0/d1;-><init>(Ljava/lang/String;Luz0/c0;I)V

    .line 14
    .line 15
    .line 16
    const-string v0, "ms"

    .line 17
    .line 18
    const/4 v2, 0x0

    .line 19
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 20
    .line 21
    .line 22
    const-string v0, "us"

    .line 23
    .line 24
    const/4 v2, 0x1

    .line 25
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 26
    .line 27
    .line 28
    const-string v0, "seconds"

    .line 29
    .line 30
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 31
    .line 32
    .line 33
    sput-object v1, Lhu/x0;->descriptor:Lsz0/g;

    .line 34
    .line 35
    return-void
.end method


# virtual methods
.method public final childSerializers()[Lqz0/a;
    .locals 2

    .line 1
    const/4 p0, 0x3

    .line 2
    new-array p0, p0, [Lqz0/a;

    .line 3
    .line 4
    sget-object v0, Luz0/q0;->a:Luz0/q0;

    .line 5
    .line 6
    const/4 v1, 0x0

    .line 7
    aput-object v0, p0, v1

    .line 8
    .line 9
    const/4 v1, 0x1

    .line 10
    aput-object v0, p0, v1

    .line 11
    .line 12
    const/4 v1, 0x2

    .line 13
    aput-object v0, p0, v1

    .line 14
    .line 15
    return-object p0
.end method

.method public final deserialize(Ltz0/c;)Ljava/lang/Object;
    .locals 12

    .line 1
    sget-object p0, Lhu/x0;->descriptor:Lsz0/g;

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
    const-wide/16 v2, 0x0

    .line 10
    .line 11
    move v9, v1

    .line 12
    move-wide v5, v2

    .line 13
    move-wide v7, v5

    .line 14
    move-wide v10, v7

    .line 15
    move v2, v0

    .line 16
    :goto_0
    if-eqz v2, :cond_4

    .line 17
    .line 18
    invoke-interface {p1, p0}, Ltz0/a;->E(Lsz0/g;)I

    .line 19
    .line 20
    .line 21
    move-result v3

    .line 22
    const/4 v4, -0x1

    .line 23
    if-eq v3, v4, :cond_3

    .line 24
    .line 25
    if-eqz v3, :cond_2

    .line 26
    .line 27
    if-eq v3, v0, :cond_1

    .line 28
    .line 29
    const/4 v4, 0x2

    .line 30
    if-ne v3, v4, :cond_0

    .line 31
    .line 32
    invoke-interface {p1, p0, v4}, Ltz0/a;->A(Lsz0/g;I)J

    .line 33
    .line 34
    .line 35
    move-result-wide v10

    .line 36
    or-int/lit8 v9, v9, 0x4

    .line 37
    .line 38
    goto :goto_0

    .line 39
    :cond_0
    new-instance p0, Lqz0/k;

    .line 40
    .line 41
    invoke-direct {p0, v3}, Lqz0/k;-><init>(I)V

    .line 42
    .line 43
    .line 44
    throw p0

    .line 45
    :cond_1
    invoke-interface {p1, p0, v0}, Ltz0/a;->A(Lsz0/g;I)J

    .line 46
    .line 47
    .line 48
    move-result-wide v7

    .line 49
    or-int/lit8 v9, v9, 0x2

    .line 50
    .line 51
    goto :goto_0

    .line 52
    :cond_2
    invoke-interface {p1, p0, v1}, Ltz0/a;->A(Lsz0/g;I)J

    .line 53
    .line 54
    .line 55
    move-result-wide v5

    .line 56
    or-int/lit8 v9, v9, 0x1

    .line 57
    .line 58
    goto :goto_0

    .line 59
    :cond_3
    move v2, v1

    .line 60
    goto :goto_0

    .line 61
    :cond_4
    invoke-interface {p1, p0}, Ltz0/a;->b(Lsz0/g;)V

    .line 62
    .line 63
    .line 64
    new-instance v4, Lhu/z0;

    .line 65
    .line 66
    invoke-direct/range {v4 .. v11}, Lhu/z0;-><init>(JJIJ)V

    .line 67
    .line 68
    .line 69
    return-object v4
.end method

.method public final getDescriptor()Lsz0/g;
    .locals 0

    .line 1
    sget-object p0, Lhu/x0;->descriptor:Lsz0/g;

    .line 2
    .line 3
    return-object p0
.end method

.method public final serialize(Ltz0/d;Ljava/lang/Object;)V
    .locals 9

    .line 1
    check-cast p2, Lhu/z0;

    .line 2
    .line 3
    const-string p0, "value"

    .line 4
    .line 5
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    sget-object p0, Lhu/x0;->descriptor:Lsz0/g;

    .line 9
    .line 10
    invoke-interface {p1, p0}, Ltz0/d;->a(Lsz0/g;)Ltz0/b;

    .line 11
    .line 12
    .line 13
    move-result-object p1

    .line 14
    iget-wide v0, p2, Lhu/z0;->a:J

    .line 15
    .line 16
    iget-wide v2, p2, Lhu/z0;->c:J

    .line 17
    .line 18
    iget-wide v4, p2, Lhu/z0;->b:J

    .line 19
    .line 20
    const/4 p2, 0x0

    .line 21
    invoke-interface {p1, p0, p2, v0, v1}, Ltz0/b;->z(Lsz0/g;IJ)V

    .line 22
    .line 23
    .line 24
    invoke-interface {p1, p0}, Ltz0/b;->e(Lsz0/g;)Z

    .line 25
    .line 26
    .line 27
    move-result p2

    .line 28
    const/16 v6, 0x3e8

    .line 29
    .line 30
    if-eqz p2, :cond_0

    .line 31
    .line 32
    goto :goto_0

    .line 33
    :cond_0
    int-to-long v7, v6

    .line 34
    mul-long/2addr v7, v0

    .line 35
    cmp-long p2, v4, v7

    .line 36
    .line 37
    if-eqz p2, :cond_1

    .line 38
    .line 39
    :goto_0
    const/4 p2, 0x1

    .line 40
    invoke-interface {p1, p0, p2, v4, v5}, Ltz0/b;->z(Lsz0/g;IJ)V

    .line 41
    .line 42
    .line 43
    :cond_1
    invoke-interface {p1, p0}, Ltz0/b;->e(Lsz0/g;)Z

    .line 44
    .line 45
    .line 46
    move-result p2

    .line 47
    if-eqz p2, :cond_2

    .line 48
    .line 49
    goto :goto_1

    .line 50
    :cond_2
    int-to-long v4, v6

    .line 51
    div-long/2addr v0, v4

    .line 52
    cmp-long p2, v2, v0

    .line 53
    .line 54
    if-eqz p2, :cond_3

    .line 55
    .line 56
    :goto_1
    const/4 p2, 0x2

    .line 57
    invoke-interface {p1, p0, p2, v2, v3}, Ltz0/b;->z(Lsz0/g;IJ)V

    .line 58
    .line 59
    .line 60
    :cond_3
    invoke-interface {p1, p0}, Ltz0/b;->b(Lsz0/g;)V

    .line 61
    .line 62
    .line 63
    return-void
.end method

.method public final typeParametersSerializers()[Lqz0/a;
    .locals 0

    .line 1
    sget-object p0, Luz0/b1;->b:[Lqz0/a;

    .line 2
    .line 3
    return-object p0
.end method
