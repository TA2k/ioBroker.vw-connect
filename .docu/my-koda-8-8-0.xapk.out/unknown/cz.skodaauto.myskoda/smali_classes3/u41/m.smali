.class public final synthetic Lu41/m;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Luz0/c0;


# instance fields
.field public final synthetic a:Lqz0/a;

.field private final descriptor:Lsz0/g;


# direct methods
.method public constructor <init>(Lqz0/a;)V
    .locals 3

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Luz0/f0;

    .line 5
    .line 6
    const-string v1, "technology.cariad.cat.capabilities.Parameters"

    .line 7
    .line 8
    invoke-direct {v0, v1, p0}, Luz0/f0;-><init>(Ljava/lang/String;Luz0/c0;)V

    .line 9
    .line 10
    .line 11
    const-string v1, "parameters"

    .line 12
    .line 13
    const/4 v2, 0x0

    .line 14
    invoke-virtual {v0, v1, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 15
    .line 16
    .line 17
    iput-object v0, p0, Lu41/m;->descriptor:Lsz0/g;

    .line 18
    .line 19
    iput-object p1, p0, Lu41/m;->a:Lqz0/a;

    .line 20
    .line 21
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
    sget-object v0, Lw41/b;->a:Lw41/b;

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
    .locals 0

    .line 1
    iget-object p0, p0, Lu41/m;->descriptor:Lsz0/g;

    .line 2
    .line 3
    invoke-interface {p1, p0}, Ltz0/c;->C(Lsz0/g;)Ltz0/c;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    sget-object p1, Lw41/b;->a:Lw41/b;

    .line 8
    .line 9
    invoke-interface {p0, p1}, Ltz0/c;->d(Lqz0/a;)Ljava/lang/Object;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    check-cast p0, Ljava/util/Map;

    .line 14
    .line 15
    const-string p1, "parameters"

    .line 16
    .line 17
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 18
    .line 19
    .line 20
    new-instance p1, Lu41/o;

    .line 21
    .line 22
    invoke-direct {p1, p0}, Lu41/o;-><init>(Ljava/util/Map;)V

    .line 23
    .line 24
    .line 25
    return-object p1
.end method

.method public final getDescriptor()Lsz0/g;
    .locals 0

    .line 1
    iget-object p0, p0, Lu41/m;->descriptor:Lsz0/g;

    .line 2
    .line 3
    return-object p0
.end method

.method public final serialize(Ltz0/d;Ljava/lang/Object;)V
    .locals 1

    .line 1
    check-cast p2, Lu41/o;

    .line 2
    .line 3
    iget-object p2, p2, Lu41/o;->a:Ljava/util/Map;

    .line 4
    .line 5
    const-string v0, "$v$c$technology-cariad-cat-capabilities-Parameters$-value$0"

    .line 6
    .line 7
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    iget-object p0, p0, Lu41/m;->descriptor:Lsz0/g;

    .line 11
    .line 12
    invoke-interface {p1, p0}, Ltz0/d;->j(Lsz0/g;)Ltz0/d;

    .line 13
    .line 14
    .line 15
    move-result-object p0

    .line 16
    if-nez p0, :cond_0

    .line 17
    .line 18
    return-void

    .line 19
    :cond_0
    sget-object p1, Lw41/b;->a:Lw41/b;

    .line 20
    .line 21
    invoke-interface {p0, p1, p2}, Ltz0/d;->D(Lqz0/a;Ljava/lang/Object;)V

    .line 22
    .line 23
    .line 24
    return-void
.end method

.method public final typeParametersSerializers()[Lqz0/a;
    .locals 2

    .line 1
    const/4 v0, 0x1

    .line 2
    new-array v0, v0, [Lqz0/a;

    .line 3
    .line 4
    const/4 v1, 0x0

    .line 5
    iget-object p0, p0, Lu41/m;->a:Lqz0/a;

    .line 6
    .line 7
    aput-object p0, v0, v1

    .line 8
    .line 9
    return-object v0
.end method
