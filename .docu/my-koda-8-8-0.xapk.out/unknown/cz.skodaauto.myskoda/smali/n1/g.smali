.class public final Ln1/g;
.super Lo1/y;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final e:Lmo0/a;


# instance fields
.field public final c:Lca/m;

.field public final d:Lbb/g0;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lmo0/a;

    .line 2
    .line 3
    const/4 v1, 0x6

    .line 4
    invoke-direct {v0, v1}, Lmo0/a;-><init>(I)V

    .line 5
    .line 6
    .line 7
    sput-object v0, Ln1/g;->e:Lmo0/a;

    .line 8
    .line 9
    return-void
.end method

.method public constructor <init>(Lay0/k;)V
    .locals 3

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Lca/m;

    .line 5
    .line 6
    invoke-direct {v0, p0}, Lca/m;-><init>(Ln1/g;)V

    .line 7
    .line 8
    .line 9
    iput-object v0, p0, Ln1/g;->c:Lca/m;

    .line 10
    .line 11
    new-instance v0, Lbb/g0;

    .line 12
    .line 13
    const/16 v1, 0xd

    .line 14
    .line 15
    const/4 v2, 0x0

    .line 16
    invoke-direct {v0, v2, v1}, Lbb/g0;-><init>(BI)V

    .line 17
    .line 18
    .line 19
    iput-object v0, p0, Ln1/g;->d:Lbb/g0;

    .line 20
    .line 21
    invoke-interface {p1, p0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 22
    .line 23
    .line 24
    return-void
.end method


# virtual methods
.method public final k()Lbb/g0;
    .locals 0

    .line 1
    iget-object p0, p0, Ln1/g;->d:Lbb/g0;

    .line 2
    .line 3
    return-object p0
.end method
