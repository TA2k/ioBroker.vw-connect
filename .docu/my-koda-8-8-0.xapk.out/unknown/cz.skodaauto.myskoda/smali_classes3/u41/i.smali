.class public final synthetic Lu41/i;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Luz0/c0;


# static fields
.field public static final a:Lu41/i;

.field private static final descriptor:Lsz0/g;


# direct methods
.method static constructor <clinit>()V
    .locals 3

    .line 1
    new-instance v0, Lu41/i;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lu41/i;->a:Lu41/i;

    .line 7
    .line 8
    new-instance v1, Luz0/f0;

    .line 9
    .line 10
    const-string v2, "technology.cariad.cat.capabilities.Operation.Identifier"

    .line 11
    .line 12
    invoke-direct {v1, v2, v0}, Luz0/f0;-><init>(Ljava/lang/String;Luz0/c0;)V

    .line 13
    .line 14
    .line 15
    const-string v0, "rawValue"

    .line 16
    .line 17
    const/4 v2, 0x0

    .line 18
    invoke-virtual {v1, v0, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 19
    .line 20
    .line 21
    sput-object v1, Lu41/i;->descriptor:Lsz0/g;

    .line 22
    .line 23
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
    .locals 0

    .line 1
    sget-object p0, Lu41/i;->descriptor:Lsz0/g;

    .line 2
    .line 3
    invoke-interface {p1, p0}, Ltz0/c;->C(Lsz0/g;)Ltz0/c;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    invoke-interface {p0}, Ltz0/c;->x()Ljava/lang/String;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    const-string p1, "rawValue"

    .line 12
    .line 13
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    new-instance p1, Lu41/k;

    .line 17
    .line 18
    invoke-direct {p1, p0}, Lu41/k;-><init>(Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    return-object p1
.end method

.method public final getDescriptor()Lsz0/g;
    .locals 0

    .line 1
    sget-object p0, Lu41/i;->descriptor:Lsz0/g;

    .line 2
    .line 3
    return-object p0
.end method

.method public final serialize(Ltz0/d;Ljava/lang/Object;)V
    .locals 0

    .line 1
    check-cast p2, Lu41/k;

    .line 2
    .line 3
    iget-object p0, p2, Lu41/k;->a:Ljava/lang/String;

    .line 4
    .line 5
    const-string p2, "$v$c$technology-cariad-cat-capabilities-Operation-Identifier$-value$0"

    .line 6
    .line 7
    invoke-static {p0, p2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    sget-object p2, Lu41/i;->descriptor:Lsz0/g;

    .line 11
    .line 12
    invoke-interface {p1, p2}, Ltz0/d;->j(Lsz0/g;)Ltz0/d;

    .line 13
    .line 14
    .line 15
    move-result-object p1

    .line 16
    if-nez p1, :cond_0

    .line 17
    .line 18
    return-void

    .line 19
    :cond_0
    invoke-interface {p1, p0}, Ltz0/d;->E(Ljava/lang/String;)V

    .line 20
    .line 21
    .line 22
    return-void
.end method
