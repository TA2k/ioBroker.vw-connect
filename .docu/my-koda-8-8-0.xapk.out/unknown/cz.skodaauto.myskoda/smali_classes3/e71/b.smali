.class public final Le71/b;
.super Li3/c;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final i:J

.field public final j:Lay0/k;

.field public final k:J


# direct methods
.method public constructor <init>(JLay0/k;)V
    .locals 1

    .line 1
    const-string v0, "style"

    .line 2
    .line 3
    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-direct {p0}, Li3/c;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-wide p1, p0, Le71/b;->i:J

    .line 10
    .line 11
    iput-object p3, p0, Le71/b;->j:Lay0/k;

    .line 12
    .line 13
    const-wide p1, 0x7fc000007fc00000L    # 2.247117487993712E307

    .line 14
    .line 15
    .line 16
    .line 17
    .line 18
    iput-wide p1, p0, Le71/b;->k:J

    .line 19
    .line 20
    return-void
.end method


# virtual methods
.method public final g()J
    .locals 2

    .line 1
    iget-wide v0, p0, Le71/b;->k:J

    .line 2
    .line 3
    return-wide v0
.end method

.method public final i(Lg3/d;)V
    .locals 9

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Le71/b;->j:Lay0/k;

    .line 7
    .line 8
    invoke-interface {v0, p1}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 9
    .line 10
    .line 11
    move-result-object v0

    .line 12
    move-object v7, v0

    .line 13
    check-cast v7, Lg3/e;

    .line 14
    .line 15
    const/16 v8, 0x6e

    .line 16
    .line 17
    iget-wide v2, p0, Le71/b;->i:J

    .line 18
    .line 19
    const/4 v4, 0x0

    .line 20
    const-wide/16 v5, 0x0

    .line 21
    .line 22
    move-object v1, p1

    .line 23
    invoke-static/range {v1 .. v8}, Lg3/d;->u0(Lg3/d;JFJLg3/e;I)V

    .line 24
    .line 25
    .line 26
    return-void
.end method
