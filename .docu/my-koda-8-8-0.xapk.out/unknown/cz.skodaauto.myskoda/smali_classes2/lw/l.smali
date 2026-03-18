.class public final Llw/l;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method static synthetic constructor <clinit>()V
    .locals 0

    .line 1
    return-void
.end method

.method public static a(ILay0/k;)Llw/k;
    .locals 1

    .line 1
    and-int/lit8 p0, p0, 0x1

    .line 2
    .line 3
    if-eqz p0, :cond_0

    .line 4
    .line 5
    sget-object p1, Llw/o;->d:Llw/o;

    .line 6
    .line 7
    :cond_0
    const-string p0, "step"

    .line 8
    .line 9
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    new-instance p0, Llw/k;

    .line 13
    .line 14
    new-instance v0, Llw/k;

    .line 15
    .line 16
    invoke-direct {v0, p1}, Llw/k;-><init>(Ljava/lang/Object;)V

    .line 17
    .line 18
    .line 19
    invoke-direct {p0, v0}, Llw/k;-><init>(Ljava/lang/Object;)V

    .line 20
    .line 21
    .line 22
    return-object p0
.end method
