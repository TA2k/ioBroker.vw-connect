.class public abstract Lhz0/e2;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Lhz0/l0;

.field public static final b:Llx0/q;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lhz0/l0;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, v1, v1}, Lhz0/l0;-><init>(Ljava/lang/Integer;Ljava/lang/Integer;)V

    .line 5
    .line 6
    .line 7
    sput-object v0, Lhz0/e2;->a:Lhz0/l0;

    .line 8
    .line 9
    new-instance v0, Lhz/a;

    .line 10
    .line 11
    const/16 v1, 0xb

    .line 12
    .line 13
    invoke-direct {v0, v1}, Lhz/a;-><init>(I)V

    .line 14
    .line 15
    .line 16
    invoke-static {v0}, Lpm/a;->d(Lay0/a;)Llx0/q;

    .line 17
    .line 18
    .line 19
    move-result-object v0

    .line 20
    sput-object v0, Lhz0/e2;->b:Llx0/q;

    .line 21
    .line 22
    return-void
.end method

.method public static final a(Ljava/lang/Object;Ljava/lang/String;)V
    .locals 3

    .line 1
    if-eqz p0, :cond_0

    .line 2
    .line 3
    return-void

    .line 4
    :cond_0
    new-instance p0, Lgz0/a;

    .line 5
    .line 6
    const-string v0, " from the given input: the field "

    .line 7
    .line 8
    const-string v1, " is missing"

    .line 9
    .line 10
    const-string v2, "Can not create a "

    .line 11
    .line 12
    invoke-static {v2, p1, v0, p1, v1}, Lu/w;->g(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 13
    .line 14
    .line 15
    move-result-object p1

    .line 16
    const/4 v0, 0x0

    .line 17
    invoke-direct {p0, p1, v0}, Lgz0/a;-><init>(Ljava/lang/String;I)V

    .line 18
    .line 19
    .line 20
    throw p0
.end method
