.class public final Lbp0/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Lxo0/a;

.field public final b:Llx0/q;


# direct methods
.method public constructor <init>(Lxo0/a;)V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lbp0/d;->a:Lxo0/a;

    .line 5
    .line 6
    new-instance p1, Lay/b;

    .line 7
    .line 8
    const/16 v0, 0xa

    .line 9
    .line 10
    invoke-direct {p1, v0}, Lay/b;-><init>(I)V

    .line 11
    .line 12
    .line 13
    invoke-static {p1}, Lpm/a;->d(Lay0/a;)Llx0/q;

    .line 14
    .line 15
    .line 16
    move-result-object p1

    .line 17
    iput-object p1, p0, Lbp0/d;->b:Llx0/q;

    .line 18
    .line 19
    return-void
.end method
