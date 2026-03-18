.class public final Leb/f;
.super Lvy0/x;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final e:Leb/f;

.field public static final f:Lcz0/e;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Leb/f;

    .line 2
    .line 3
    invoke-direct {v0}, Lvy0/x;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Leb/f;->e:Leb/f;

    .line 7
    .line 8
    sget-object v0, Lvy0/p0;->a:Lcz0/e;

    .line 9
    .line 10
    sput-object v0, Leb/f;->f:Lcz0/e;

    .line 11
    .line 12
    return-void
.end method


# virtual methods
.method public final T(Lpx0/g;Ljava/lang/Runnable;)V
    .locals 0

    .line 1
    const-string p0, "context"

    .line 2
    .line 3
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string p0, "block"

    .line 7
    .line 8
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    sget-object p0, Leb/f;->f:Lcz0/e;

    .line 12
    .line 13
    invoke-virtual {p0, p1, p2}, Lcz0/h;->T(Lpx0/g;Ljava/lang/Runnable;)V

    .line 14
    .line 15
    .line 16
    return-void
.end method

.method public final V(Lpx0/g;)Z
    .locals 0

    .line 1
    const-string p0, "context"

    .line 2
    .line 3
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    sget-object p0, Leb/f;->f:Lcz0/e;

    .line 7
    .line 8
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 9
    .line 10
    .line 11
    const/4 p0, 0x0

    .line 12
    xor-int/lit8 p0, p0, 0x1

    .line 13
    .line 14
    return p0
.end method
