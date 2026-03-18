.class public final Lvz0/f0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lqz0/a;


# static fields
.field public static final a:Lvz0/f0;

.field public static final b:Lsz0/h;


# direct methods
.method static constructor <clinit>()V
    .locals 3

    .line 1
    new-instance v0, Lvz0/f0;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lvz0/f0;->a:Lvz0/f0;

    .line 7
    .line 8
    sget-object v0, Lsz0/e;->j:Lsz0/e;

    .line 9
    .line 10
    const/4 v1, 0x0

    .line 11
    new-array v1, v1, [Lsz0/g;

    .line 12
    .line 13
    const-string v2, "kotlinx.serialization.json.JsonPrimitive"

    .line 14
    .line 15
    invoke-static {v2, v0, v1}, Lkp/x8;->e(Ljava/lang/String;Lkp/y8;[Lsz0/g;)Lsz0/h;

    .line 16
    .line 17
    .line 18
    move-result-object v0

    .line 19
    sput-object v0, Lvz0/f0;->b:Lsz0/h;

    .line 20
    .line 21
    return-void
.end method


# virtual methods
.method public final deserialize(Ltz0/c;)Ljava/lang/Object;
    .locals 2

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
    instance-of p1, p0, Lvz0/e0;

    .line 10
    .line 11
    if-eqz p1, :cond_0

    .line 12
    .line 13
    check-cast p0, Lvz0/e0;

    .line 14
    .line 15
    return-object p0

    .line 16
    :cond_0
    new-instance p1, Ljava/lang/StringBuilder;

    .line 17
    .line 18
    const-string v0, "Unexpected JSON element, expected JsonPrimitive, had "

    .line 19
    .line 20
    invoke-direct {p1, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 21
    .line 22
    .line 23
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 24
    .line 25
    .line 26
    move-result-object v0

    .line 27
    sget-object v1, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 28
    .line 29
    invoke-static {v1, v0, p1}, Lia/b;->i(Lkotlin/jvm/internal/h0;Ljava/lang/Class;Ljava/lang/StringBuilder;)Ljava/lang/String;

    .line 30
    .line 31
    .line 32
    move-result-object p1

    .line 33
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 34
    .line 35
    .line 36
    move-result-object p0

    .line 37
    const/4 v0, -0x1

    .line 38
    invoke-static {v0, p0, p1}, Lwz0/p;->c(ILjava/lang/CharSequence;Ljava/lang/String;)Lwz0/l;

    .line 39
    .line 40
    .line 41
    move-result-object p0

    .line 42
    throw p0
.end method

.method public final getDescriptor()Lsz0/g;
    .locals 0

    .line 1
    sget-object p0, Lvz0/f0;->b:Lsz0/h;

    .line 2
    .line 3
    return-object p0
.end method

.method public final serialize(Ltz0/d;Ljava/lang/Object;)V
    .locals 0

    .line 1
    check-cast p2, Lvz0/e0;

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
    instance-of p0, p2, Lvz0/x;

    .line 12
    .line 13
    if-eqz p0, :cond_0

    .line 14
    .line 15
    sget-object p0, Lvz0/y;->a:Lvz0/y;

    .line 16
    .line 17
    sget-object p2, Lvz0/x;->INSTANCE:Lvz0/x;

    .line 18
    .line 19
    invoke-interface {p1, p0, p2}, Ltz0/d;->D(Lqz0/a;Ljava/lang/Object;)V

    .line 20
    .line 21
    .line 22
    return-void

    .line 23
    :cond_0
    sget-object p0, Lvz0/v;->a:Lvz0/v;

    .line 24
    .line 25
    check-cast p2, Lvz0/u;

    .line 26
    .line 27
    invoke-interface {p1, p0, p2}, Ltz0/d;->D(Lqz0/a;Ljava/lang/Object;)V

    .line 28
    .line 29
    .line 30
    return-void
.end method
