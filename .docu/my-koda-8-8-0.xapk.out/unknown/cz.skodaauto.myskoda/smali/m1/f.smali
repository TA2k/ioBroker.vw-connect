.class public final Lm1/f;
.super Lo1/y;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final c:Lbb/g0;

.field public d:Landroidx/collection/a0;


# direct methods
.method public constructor <init>(Lay0/k;)V
    .locals 3

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Lbb/g0;

    .line 5
    .line 6
    const/16 v1, 0xd

    .line 7
    .line 8
    const/4 v2, 0x0

    .line 9
    invoke-direct {v0, v2, v1}, Lbb/g0;-><init>(BI)V

    .line 10
    .line 11
    .line 12
    iput-object v0, p0, Lm1/f;->c:Lbb/g0;

    .line 13
    .line 14
    invoke-interface {p1, p0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 15
    .line 16
    .line 17
    return-void
.end method

.method public static synthetic o(Lm1/f;Lay0/o;I)V
    .locals 0

    .line 1
    and-int/lit8 p2, p2, 0x1

    .line 2
    .line 3
    if-eqz p2, :cond_0

    .line 4
    .line 5
    const/4 p2, 0x0

    .line 6
    goto :goto_0

    .line 7
    :cond_0
    const-string p2, "daily_reward"

    .line 8
    .line 9
    :goto_0
    invoke-virtual {p0, p2, p1}, Lm1/f;->n(Ljava/lang/Object;Lay0/o;)V

    .line 10
    .line 11
    .line 12
    return-void
.end method

.method public static synthetic q(Lm1/f;ILt2/b;)V
    .locals 2

    .line 1
    sget-object v0, Lm1/n;->d:Lm1/n;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-virtual {p0, p1, v1, v0, p2}, Lm1/f;->p(ILay0/k;Lay0/k;Lt2/b;)V

    .line 5
    .line 6
    .line 7
    return-void
.end method

.method public static r(Lm1/f;Lt2/b;)V
    .locals 3

    .line 1
    iget-object v0, p0, Lm1/f;->c:Lbb/g0;

    .line 2
    .line 3
    iget-object v1, p0, Lm1/f;->d:Landroidx/collection/a0;

    .line 4
    .line 5
    if-nez v1, :cond_0

    .line 6
    .line 7
    new-instance v1, Landroidx/collection/a0;

    .line 8
    .line 9
    invoke-direct {v1}, Landroidx/collection/a0;-><init>()V

    .line 10
    .line 11
    .line 12
    iput-object v1, p0, Lm1/f;->d:Landroidx/collection/a0;

    .line 13
    .line 14
    :cond_0
    iget v2, v0, Lbb/g0;->e:I

    .line 15
    .line 16
    invoke-virtual {v1, v2}, Landroidx/collection/a0;->a(I)V

    .line 17
    .line 18
    .line 19
    iget v0, v0, Lbb/g0;->e:I

    .line 20
    .line 21
    new-instance v1, Lm1/e;

    .line 22
    .line 23
    invoke-direct {v1, p1, v0}, Lm1/e;-><init>(Lt2/b;I)V

    .line 24
    .line 25
    .line 26
    new-instance p1, Lt2/b;

    .line 27
    .line 28
    const/4 v0, 0x1

    .line 29
    const v2, -0x5eb1942e

    .line 30
    .line 31
    .line 32
    invoke-direct {p1, v1, v0, v2}, Lt2/b;-><init>(Ljava/lang/Object;ZI)V

    .line 33
    .line 34
    .line 35
    const/4 v0, 0x0

    .line 36
    invoke-virtual {p0, v0, p1}, Lm1/f;->n(Ljava/lang/Object;Lay0/o;)V

    .line 37
    .line 38
    .line 39
    return-void
.end method


# virtual methods
.method public final k()Lbb/g0;
    .locals 0

    .line 1
    iget-object p0, p0, Lm1/f;->c:Lbb/g0;

    .line 2
    .line 3
    return-object p0
.end method

.method public final n(Ljava/lang/Object;Lay0/o;)V
    .locals 5

    .line 1
    new-instance v0, Lm1/d;

    .line 2
    .line 3
    if-eqz p1, :cond_0

    .line 4
    .line 5
    new-instance v1, Lca/k;

    .line 6
    .line 7
    const/4 v2, 0x2

    .line 8
    invoke-direct {v1, p1, v2}, Lca/k;-><init>(Ljava/lang/Object;I)V

    .line 9
    .line 10
    .line 11
    goto :goto_0

    .line 12
    :cond_0
    const/4 v1, 0x0

    .line 13
    :goto_0
    new-instance p1, Lkq0/a;

    .line 14
    .line 15
    const/16 v2, 0x19

    .line 16
    .line 17
    invoke-direct {p1, v2}, Lkq0/a;-><init>(I)V

    .line 18
    .line 19
    .line 20
    new-instance v2, Lb60/h;

    .line 21
    .line 22
    const/4 v3, 0x5

    .line 23
    invoke-direct {v2, p2, v3}, Lb60/h;-><init>(Ljava/lang/Object;I)V

    .line 24
    .line 25
    .line 26
    new-instance p2, Lt2/b;

    .line 27
    .line 28
    const/4 v3, 0x1

    .line 29
    const v4, -0x331bf287

    .line 30
    .line 31
    .line 32
    invoke-direct {p2, v2, v3, v4}, Lt2/b;-><init>(Ljava/lang/Object;ZI)V

    .line 33
    .line 34
    .line 35
    invoke-direct {v0, v1, p1, p2}, Lm1/d;-><init>(Lay0/k;Lay0/k;Lt2/b;)V

    .line 36
    .line 37
    .line 38
    iget-object p0, p0, Lm1/f;->c:Lbb/g0;

    .line 39
    .line 40
    invoke-virtual {p0, v3, v0}, Lbb/g0;->b(ILo1/q;)V

    .line 41
    .line 42
    .line 43
    return-void
.end method

.method public final p(ILay0/k;Lay0/k;Lt2/b;)V
    .locals 1

    .line 1
    new-instance v0, Lm1/d;

    .line 2
    .line 3
    invoke-direct {v0, p2, p3, p4}, Lm1/d;-><init>(Lay0/k;Lay0/k;Lt2/b;)V

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lm1/f;->c:Lbb/g0;

    .line 7
    .line 8
    invoke-virtual {p0, p1, v0}, Lbb/g0;->b(ILo1/q;)V

    .line 9
    .line 10
    .line 11
    return-void
.end method
