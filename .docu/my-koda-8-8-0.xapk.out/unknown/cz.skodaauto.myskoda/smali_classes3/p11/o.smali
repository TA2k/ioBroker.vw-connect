.class public final Lp11/o;
.super Lq11/c;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final f:Lp11/o;


# direct methods
.method static constructor <clinit>()V
    .locals 3

    .line 1
    new-instance v0, Lp11/o;

    .line 2
    .line 3
    sget-object v1, Lp11/m;->v1:Lp11/m;

    .line 4
    .line 5
    iget-object v1, v1, Lp11/b;->J:Ln11/a;

    .line 6
    .line 7
    sget-object v2, Ln11/b;->i:Ln11/b;

    .line 8
    .line 9
    invoke-direct {v0, v1, v2}, Lq11/c;-><init>(Ln11/a;Ln11/b;)V

    .line 10
    .line 11
    .line 12
    sput-object v0, Lp11/o;->f:Lp11/o;

    .line 13
    .line 14
    return-void
.end method


# virtual methods
.method public final a(IJ)J
    .locals 0

    .line 1
    iget-object p0, p0, Lq11/c;->e:Ln11/a;

    .line 2
    .line 3
    invoke-virtual {p0, p1, p2, p3}, Ln11/a;->a(IJ)J

    .line 4
    .line 5
    .line 6
    move-result-wide p0

    .line 7
    return-wide p0
.end method

.method public final b(J)I
    .locals 0

    .line 1
    iget-object p0, p0, Lq11/c;->e:Ln11/a;

    .line 2
    .line 3
    invoke-virtual {p0, p1, p2}, Ln11/a;->b(J)I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    if-gez p0, :cond_0

    .line 8
    .line 9
    neg-int p0, p0

    .line 10
    :cond_0
    return p0
.end method

.method public final l()I
    .locals 0

    .line 1
    iget-object p0, p0, Lq11/c;->e:Ln11/a;

    .line 2
    .line 3
    invoke-virtual {p0}, Ln11/a;->l()I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public final o()I
    .locals 0

    .line 1
    const/4 p0, 0x0

    .line 2
    return p0
.end method

.method public final p()Ln11/g;
    .locals 0

    .line 1
    sget-object p0, Lp11/m;->v1:Lp11/m;

    .line 2
    .line 3
    iget-object p0, p0, Lp11/b;->q:Ln11/g;

    .line 4
    .line 5
    return-object p0
.end method

.method public final t(J)J
    .locals 0

    .line 1
    iget-object p0, p0, Lq11/c;->e:Ln11/a;

    .line 2
    .line 3
    invoke-virtual {p0, p1, p2}, Ln11/a;->t(J)J

    .line 4
    .line 5
    .line 6
    move-result-wide p0

    .line 7
    return-wide p0
.end method

.method public final u(J)J
    .locals 0

    .line 1
    iget-object p0, p0, Lq11/c;->e:Ln11/a;

    .line 2
    .line 3
    invoke-virtual {p0, p1, p2}, Ln11/a;->u(J)J

    .line 4
    .line 5
    .line 6
    move-result-wide p0

    .line 7
    return-wide p0
.end method

.method public final v(IJ)J
    .locals 3

    .line 1
    iget-object v0, p0, Lq11/c;->e:Ln11/a;

    .line 2
    .line 3
    invoke-virtual {v0}, Ln11/a;->l()I

    .line 4
    .line 5
    .line 6
    move-result v1

    .line 7
    const/4 v2, 0x0

    .line 8
    invoke-static {p0, p1, v2, v1}, Ljp/je;->g(Ln11/a;III)V

    .line 9
    .line 10
    .line 11
    invoke-virtual {v0, p2, p3}, Ln11/a;->b(J)I

    .line 12
    .line 13
    .line 14
    move-result p0

    .line 15
    if-gez p0, :cond_0

    .line 16
    .line 17
    neg-int p1, p1

    .line 18
    :cond_0
    invoke-virtual {v0, p1, p2, p3}, Ln11/a;->v(IJ)J

    .line 19
    .line 20
    .line 21
    move-result-wide p0

    .line 22
    return-wide p0
.end method
