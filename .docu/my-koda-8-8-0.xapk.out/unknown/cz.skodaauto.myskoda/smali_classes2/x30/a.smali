.class public final Lx30/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Lsc0/a;

.field public final b:Llx0/q;


# direct methods
.method public constructor <init>(Lsc0/a;)V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lx30/a;->a:Lsc0/a;

    .line 5
    .line 6
    new-instance p1, Lu2/a;

    .line 7
    .line 8
    const/16 v0, 0x15

    .line 9
    .line 10
    invoke-direct {p1, p0, v0}, Lu2/a;-><init>(Ljava/lang/Object;I)V

    .line 11
    .line 12
    .line 13
    invoke-static {p1}, Lpm/a;->d(Lay0/a;)Llx0/q;

    .line 14
    .line 15
    .line 16
    move-result-object p1

    .line 17
    iput-object p1, p0, Lx30/a;->b:Llx0/q;

    .line 18
    .line 19
    return-void
.end method
