.class public final Lvz0/p;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lqz0/a;


# static fields
.field public static final a:Lvz0/p;

.field public static final b:Lsz0/h;


# direct methods
.method static constructor <clinit>()V
    .locals 4

    .line 1
    new-instance v0, Lvz0/p;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lvz0/p;->a:Lvz0/p;

    .line 7
    .line 8
    sget-object v0, Lsz0/c;->c:Lsz0/c;

    .line 9
    .line 10
    const/4 v1, 0x0

    .line 11
    new-array v1, v1, [Lsz0/g;

    .line 12
    .line 13
    new-instance v2, Lvb/a;

    .line 14
    .line 15
    const/16 v3, 0x13

    .line 16
    .line 17
    invoke-direct {v2, v3}, Lvb/a;-><init>(I)V

    .line 18
    .line 19
    .line 20
    const-string v3, "kotlinx.serialization.json.JsonElement"

    .line 21
    .line 22
    invoke-static {v3, v0, v1, v2}, Lkp/x8;->d(Ljava/lang/String;Lkp/y8;[Lsz0/g;Lay0/k;)Lsz0/h;

    .line 23
    .line 24
    .line 25
    move-result-object v0

    .line 26
    sput-object v0, Lvz0/p;->b:Lsz0/h;

    .line 27
    .line 28
    return-void
.end method


# virtual methods
.method public final deserialize(Ltz0/c;)Ljava/lang/Object;
    .locals 0

    .line 1
    invoke-static {p1}, Llp/qc;->b(Ltz0/c;)Lvz0/l;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    invoke-interface {p0}, Lvz0/l;->h()Lvz0/n;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0
.end method

.method public final getDescriptor()Lsz0/g;
    .locals 0

    .line 1
    sget-object p0, Lvz0/p;->b:Lsz0/h;

    .line 2
    .line 3
    return-object p0
.end method

.method public final serialize(Ltz0/d;Ljava/lang/Object;)V
    .locals 0

    .line 1
    check-cast p2, Lvz0/n;

    .line 2
    .line 3
    const-string p0, "value"

    .line 4
    .line 5
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    invoke-static {p1}, Llp/qc;->a(Ltz0/d;)V

    .line 9
    .line 10
    .line 11
    instance-of p0, p2, Lvz0/e0;

    .line 12
    .line 13
    if-eqz p0, :cond_0

    .line 14
    .line 15
    sget-object p0, Lvz0/f0;->a:Lvz0/f0;

    .line 16
    .line 17
    invoke-interface {p1, p0, p2}, Ltz0/d;->D(Lqz0/a;Ljava/lang/Object;)V

    .line 18
    .line 19
    .line 20
    return-void

    .line 21
    :cond_0
    instance-of p0, p2, Lvz0/a0;

    .line 22
    .line 23
    if-eqz p0, :cond_1

    .line 24
    .line 25
    sget-object p0, Lvz0/c0;->a:Lvz0/c0;

    .line 26
    .line 27
    invoke-interface {p1, p0, p2}, Ltz0/d;->D(Lqz0/a;Ljava/lang/Object;)V

    .line 28
    .line 29
    .line 30
    return-void

    .line 31
    :cond_1
    instance-of p0, p2, Lvz0/f;

    .line 32
    .line 33
    if-eqz p0, :cond_2

    .line 34
    .line 35
    sget-object p0, Lvz0/h;->a:Lvz0/h;

    .line 36
    .line 37
    invoke-interface {p1, p0, p2}, Ltz0/d;->D(Lqz0/a;Ljava/lang/Object;)V

    .line 38
    .line 39
    .line 40
    return-void

    .line 41
    :cond_2
    new-instance p0, La8/r0;

    .line 42
    .line 43
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 44
    .line 45
    .line 46
    throw p0
.end method
