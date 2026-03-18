.class public final Lvz0/y;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lqz0/a;


# static fields
.field public static final a:Lvz0/y;

.field public static final b:Lsz0/h;


# direct methods
.method static constructor <clinit>()V
    .locals 3

    .line 1
    new-instance v0, Lvz0/y;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lvz0/y;->a:Lvz0/y;

    .line 7
    .line 8
    const/4 v0, 0x0

    .line 9
    new-array v0, v0, [Lsz0/g;

    .line 10
    .line 11
    const-string v1, "kotlinx.serialization.json.JsonNull"

    .line 12
    .line 13
    sget-object v2, Lsz0/j;->b:Lsz0/j;

    .line 14
    .line 15
    invoke-static {v1, v2, v0}, Lkp/x8;->e(Ljava/lang/String;Lkp/y8;[Lsz0/g;)Lsz0/h;

    .line 16
    .line 17
    .line 18
    move-result-object v0

    .line 19
    sput-object v0, Lvz0/y;->b:Lsz0/h;

    .line 20
    .line 21
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
    invoke-interface {p1}, Ltz0/c;->y()Z

    .line 5
    .line 6
    .line 7
    move-result p0

    .line 8
    if-nez p0, :cond_0

    .line 9
    .line 10
    sget-object p0, Lvz0/x;->INSTANCE:Lvz0/x;

    .line 11
    .line 12
    return-object p0

    .line 13
    :cond_0
    new-instance p0, Lwz0/l;

    .line 14
    .line 15
    const-string p1, "Expected \'null\' literal"

    .line 16
    .line 17
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 18
    .line 19
    .line 20
    throw p0
.end method

.method public final getDescriptor()Lsz0/g;
    .locals 0

    .line 1
    sget-object p0, Lvz0/y;->b:Lsz0/h;

    .line 2
    .line 3
    return-object p0
.end method

.method public final serialize(Ltz0/d;Ljava/lang/Object;)V
    .locals 0

    .line 1
    check-cast p2, Lvz0/x;

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
    invoke-interface {p1}, Ltz0/d;->p()V

    .line 12
    .line 13
    .line 14
    return-void
.end method
