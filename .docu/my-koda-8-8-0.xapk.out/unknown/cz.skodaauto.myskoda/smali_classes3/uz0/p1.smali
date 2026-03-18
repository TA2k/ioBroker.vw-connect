.class public final Luz0/p1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lqz0/a;


# static fields
.field public static final a:Luz0/p1;

.field public static final b:Luz0/h1;


# direct methods
.method static constructor <clinit>()V
    .locals 3

    .line 1
    new-instance v0, Luz0/p1;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Luz0/p1;->a:Luz0/p1;

    .line 7
    .line 8
    new-instance v0, Luz0/h1;

    .line 9
    .line 10
    const-string v1, "kotlin.Short"

    .line 11
    .line 12
    sget-object v2, Lsz0/e;->i:Lsz0/e;

    .line 13
    .line 14
    invoke-direct {v0, v1, v2}, Luz0/h1;-><init>(Ljava/lang/String;Lsz0/f;)V

    .line 15
    .line 16
    .line 17
    sput-object v0, Luz0/p1;->b:Luz0/h1;

    .line 18
    .line 19
    return-void
.end method


# virtual methods
.method public final deserialize(Ltz0/c;)Ljava/lang/Object;
    .locals 0

    .line 1
    invoke-interface {p1}, Ltz0/c;->o()S

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    invoke-static {p0}, Ljava/lang/Short;->valueOf(S)Ljava/lang/Short;

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
    sget-object p0, Luz0/p1;->b:Luz0/h1;

    .line 2
    .line 3
    return-object p0
.end method

.method public final serialize(Ltz0/d;Ljava/lang/Object;)V
    .locals 0

    .line 1
    check-cast p2, Ljava/lang/Number;

    .line 2
    .line 3
    invoke-virtual {p2}, Ljava/lang/Number;->shortValue()S

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    invoke-interface {p1, p0}, Ltz0/d;->r(S)V

    .line 8
    .line 9
    .line 10
    return-void
.end method
