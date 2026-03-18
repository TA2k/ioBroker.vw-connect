.class public final Lp1/l;
.super Lo1/y;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final c:Lay0/p;

.field public final d:Lay0/k;

.field public final e:Lbb/g0;


# direct methods
.method public constructor <init>(Lay0/p;Lay0/k;I)V
    .locals 3

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lp1/l;->c:Lay0/p;

    .line 5
    .line 6
    iput-object p2, p0, Lp1/l;->d:Lay0/k;

    .line 7
    .line 8
    new-instance v0, Lbb/g0;

    .line 9
    .line 10
    const/16 v1, 0xd

    .line 11
    .line 12
    const/4 v2, 0x0

    .line 13
    invoke-direct {v0, v2, v1}, Lbb/g0;-><init>(BI)V

    .line 14
    .line 15
    .line 16
    new-instance v1, Lp1/i;

    .line 17
    .line 18
    invoke-direct {v1, p2, p1}, Lp1/i;-><init>(Lay0/k;Lay0/p;)V

    .line 19
    .line 20
    .line 21
    invoke-virtual {v0, p3, v1}, Lbb/g0;->b(ILo1/q;)V

    .line 22
    .line 23
    .line 24
    iput-object v0, p0, Lp1/l;->e:Lbb/g0;

    .line 25
    .line 26
    return-void
.end method


# virtual methods
.method public final k()Lbb/g0;
    .locals 0

    .line 1
    iget-object p0, p0, Lp1/l;->e:Lbb/g0;

    .line 2
    .line 3
    return-object p0
.end method
