.class public final Lpo/b;
.super Lko/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final n:Lc2/k;


# direct methods
.method static constructor <clinit>()V
    .locals 4

    .line 1
    new-instance v0, Lko/d;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    new-instance v1, Lbp/l;

    .line 7
    .line 8
    const/4 v2, 0x4

    .line 9
    invoke-direct {v1, v2}, Lbp/l;-><init>(I)V

    .line 10
    .line 11
    .line 12
    new-instance v2, Lc2/k;

    .line 13
    .line 14
    const-string v3, "ClientTelemetry.API"

    .line 15
    .line 16
    invoke-direct {v2, v3, v1, v0}, Lc2/k;-><init>(Ljava/lang/String;Llp/wd;Lko/d;)V

    .line 17
    .line 18
    .line 19
    sput-object v2, Lpo/b;->n:Lc2/k;

    .line 20
    .line 21
    return-void
.end method


# virtual methods
.method public final f(Lno/p;)Laq/t;
    .locals 3

    .line 1
    invoke-static {}, Lhr/b0;->e()Lh6/i;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    sget-object v1, Lcp/b;->a:Ljo/d;

    .line 6
    .line 7
    filled-new-array {v1}, [Ljo/d;

    .line 8
    .line 9
    .line 10
    move-result-object v1

    .line 11
    iput-object v1, v0, Lh6/i;->e:Ljava/lang/Object;

    .line 12
    .line 13
    const/4 v1, 0x0

    .line 14
    iput-boolean v1, v0, Lh6/i;->c:Z

    .line 15
    .line 16
    new-instance v1, Lh6/e;

    .line 17
    .line 18
    const/16 v2, 0x1a

    .line 19
    .line 20
    invoke-direct {v1, p1, v2}, Lh6/e;-><init>(Ljava/lang/Object;I)V

    .line 21
    .line 22
    .line 23
    iput-object v1, v0, Lh6/i;->d:Ljava/lang/Object;

    .line 24
    .line 25
    invoke-virtual {v0}, Lh6/i;->a()Lbp/s;

    .line 26
    .line 27
    .line 28
    move-result-object p1

    .line 29
    const/4 v0, 0x2

    .line 30
    invoke-virtual {p0, v0, p1}, Lko/i;->e(ILhr/b0;)Laq/t;

    .line 31
    .line 32
    .line 33
    move-result-object p0

    .line 34
    return-object p0
.end method
