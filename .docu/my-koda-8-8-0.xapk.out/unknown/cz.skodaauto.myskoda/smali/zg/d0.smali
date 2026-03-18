.class public final synthetic Lzg/d0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Luz0/c0;


# static fields
.field public static final a:Lzg/d0;

.field private static final descriptor:Lsz0/g;


# direct methods
.method static constructor <clinit>()V
    .locals 4

    .line 1
    new-instance v0, Lzg/d0;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lzg/d0;->a:Lzg/d0;

    .line 7
    .line 8
    new-instance v1, Luz0/d1;

    .line 9
    .line 10
    const-string v2, "cariad.charging.multicharge.kitten.wallboxes.models.ChargingStationRenameRequest"

    .line 11
    .line 12
    const/4 v3, 0x1

    .line 13
    invoke-direct {v1, v2, v0, v3}, Luz0/d1;-><init>(Ljava/lang/String;Luz0/c0;I)V

    .line 14
    .line 15
    .line 16
    const-string v0, "name"

    .line 17
    .line 18
    const/4 v2, 0x0

    .line 19
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 20
    .line 21
    .line 22
    sput-object v1, Lzg/d0;->descriptor:Lsz0/g;

    .line 23
    .line 24
    return-void
.end method


# virtual methods
.method public final childSerializers()[Lqz0/a;
    .locals 2

    .line 1
    const/4 p0, 0x1

    .line 2
    new-array p0, p0, [Lqz0/a;

    .line 3
    .line 4
    sget-object v0, Luz0/q1;->a:Luz0/q1;

    .line 5
    .line 6
    const/4 v1, 0x0

    .line 7
    aput-object v0, p0, v1

    .line 8
    .line 9
    return-object p0
.end method

.method public final deserialize(Ltz0/c;)Ljava/lang/Object;
    .locals 7

    .line 1
    sget-object p0, Lzg/d0;->descriptor:Lsz0/g;

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
    move v3, v0

    .line 11
    move v4, v1

    .line 12
    :goto_0
    if-eqz v3, :cond_2

    .line 13
    .line 14
    invoke-interface {p1, p0}, Ltz0/a;->E(Lsz0/g;)I

    .line 15
    .line 16
    .line 17
    move-result v5

    .line 18
    const/4 v6, -0x1

    .line 19
    if-eq v5, v6, :cond_1

    .line 20
    .line 21
    if-nez v5, :cond_0

    .line 22
    .line 23
    invoke-interface {p1, p0, v1}, Ltz0/a;->k(Lsz0/g;I)Ljava/lang/String;

    .line 24
    .line 25
    .line 26
    move-result-object v2

    .line 27
    move v4, v0

    .line 28
    goto :goto_0

    .line 29
    :cond_0
    new-instance p0, Lqz0/k;

    .line 30
    .line 31
    invoke-direct {p0, v5}, Lqz0/k;-><init>(I)V

    .line 32
    .line 33
    .line 34
    throw p0

    .line 35
    :cond_1
    move v3, v1

    .line 36
    goto :goto_0

    .line 37
    :cond_2
    invoke-interface {p1, p0}, Ltz0/a;->b(Lsz0/g;)V

    .line 38
    .line 39
    .line 40
    new-instance p0, Lzg/f0;

    .line 41
    .line 42
    invoke-direct {p0, v4, v2}, Lzg/f0;-><init>(ILjava/lang/String;)V

    .line 43
    .line 44
    .line 45
    return-object p0
.end method

.method public final getDescriptor()Lsz0/g;
    .locals 0

    .line 1
    sget-object p0, Lzg/d0;->descriptor:Lsz0/g;

    .line 2
    .line 3
    return-object p0
.end method

.method public final serialize(Ltz0/d;Ljava/lang/Object;)V
    .locals 1

    .line 1
    check-cast p2, Lzg/f0;

    .line 2
    .line 3
    const-string p0, "value"

    .line 4
    .line 5
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    sget-object p0, Lzg/d0;->descriptor:Lsz0/g;

    .line 9
    .line 10
    invoke-interface {p1, p0}, Ltz0/d;->a(Lsz0/g;)Ltz0/b;

    .line 11
    .line 12
    .line 13
    move-result-object p1

    .line 14
    const/4 v0, 0x0

    .line 15
    iget-object p2, p2, Lzg/f0;->a:Ljava/lang/String;

    .line 16
    .line 17
    invoke-interface {p1, p0, v0, p2}, Ltz0/b;->x(Lsz0/g;ILjava/lang/String;)V

    .line 18
    .line 19
    .line 20
    invoke-interface {p1, p0}, Ltz0/b;->b(Lsz0/g;)V

    .line 21
    .line 22
    .line 23
    return-void
.end method
