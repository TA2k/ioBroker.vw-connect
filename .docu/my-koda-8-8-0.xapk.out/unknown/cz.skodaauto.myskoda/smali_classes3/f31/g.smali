.class public final Lf31/g;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Ljava/time/Clock;


# direct methods
.method public constructor <init>()V
    .locals 2

    .line 1
    invoke-static {}, Ljava/time/Clock;->systemDefaultZone()Ljava/time/Clock;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    const-string v1, "systemDefaultZone(...)"

    .line 6
    .line 7
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 11
    .line 12
    .line 13
    iput-object v0, p0, Lf31/g;->a:Ljava/time/Clock;

    .line 14
    .line 15
    return-void
.end method
