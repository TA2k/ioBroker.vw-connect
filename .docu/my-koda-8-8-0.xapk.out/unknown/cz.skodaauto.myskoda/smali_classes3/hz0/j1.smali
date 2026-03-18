.class public final synthetic Lhz0/j1;
.super Lkotlin/jvm/internal/r;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final d:Lhz0/j1;


# direct methods
.method static constructor <clinit>()V
    .locals 5

    .line 1
    new-instance v0, Lhz0/j1;

    .line 2
    .line 3
    const-string v1, "getAmPm()Lkotlinx/datetime/format/AmPmMarker;"

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    const-class v3, Lhz0/i1;

    .line 7
    .line 8
    const-string v4, "amPm"

    .line 9
    .line 10
    invoke-direct {v0, v3, v4, v1, v2}, Lkotlin/jvm/internal/r;-><init>(Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;I)V

    .line 11
    .line 12
    .line 13
    sput-object v0, Lhz0/j1;->d:Lhz0/j1;

    .line 14
    .line 15
    return-void
.end method


# virtual methods
.method public final get(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Lhz0/i1;

    .line 2
    .line 3
    invoke-interface {p1}, Lhz0/i1;->o()Lhz0/h;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final set(Ljava/lang/Object;Ljava/lang/Object;)V
    .locals 0

    .line 1
    check-cast p1, Lhz0/i1;

    .line 2
    .line 3
    check-cast p2, Lhz0/h;

    .line 4
    .line 5
    invoke-interface {p1, p2}, Lhz0/i1;->j(Lhz0/h;)V

    .line 6
    .line 7
    .line 8
    return-void
.end method
