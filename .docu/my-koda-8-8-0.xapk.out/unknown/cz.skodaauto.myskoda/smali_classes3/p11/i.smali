.class public final Lp11/i;
.super Lq11/a;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final e:Lp11/m;


# direct methods
.method public constructor <init>(Lp11/m;)V
    .locals 1

    .line 1
    sget-object v0, Ln11/b;->h:Ln11/b;

    .line 2
    .line 3
    invoke-direct {p0, v0}, Lq11/a;-><init>(Ln11/b;)V

    .line 4
    .line 5
    .line 6
    iput-object p1, p0, Lp11/i;->e:Lp11/m;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final b(J)I
    .locals 0

    .line 1
    iget-object p0, p0, Lp11/i;->e:Lp11/m;

    .line 2
    .line 3
    invoke-virtual {p0, p1, p2}, Lp11/e;->X(J)I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    if-gtz p0, :cond_0

    .line 8
    .line 9
    const/4 p0, 0x0

    .line 10
    return p0

    .line 11
    :cond_0
    const/4 p0, 0x1

    .line 12
    return p0
.end method

.method public final f(ILjava/util/Locale;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p2}, Lp11/j;->b(Ljava/util/Locale;)Lp11/j;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    iget-object p0, p0, Lp11/j;->a:[Ljava/lang/String;

    .line 6
    .line 7
    aget-object p0, p0, p1

    .line 8
    .line 9
    return-object p0
.end method

.method public final i()Ln11/g;
    .locals 0

    .line 1
    sget-object p0, Ln11/h;->f:Ln11/h;

    .line 2
    .line 3
    invoke-static {p0}, Lq11/n;->g(Ln11/h;)Lq11/n;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final k(Ljava/util/Locale;)I
    .locals 0

    .line 1
    invoke-static {p1}, Lp11/j;->b(Ljava/util/Locale;)Lp11/j;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    iget p0, p0, Lp11/j;->j:I

    .line 6
    .line 7
    return p0
.end method

.method public final l()I
    .locals 0

    .line 1
    const/4 p0, 0x1

    .line 2
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
    const/4 p0, 0x0

    .line 2
    return-object p0
.end method

.method public final u(J)J
    .locals 2

    .line 1
    invoke-virtual {p0, p1, p2}, Lp11/i;->b(J)I

    .line 2
    .line 3
    .line 4
    move-result p1

    .line 5
    const/4 p2, 0x1

    .line 6
    if-ne p1, p2, :cond_0

    .line 7
    .line 8
    iget-object p0, p0, Lp11/i;->e:Lp11/m;

    .line 9
    .line 10
    const-wide/16 v0, 0x0

    .line 11
    .line 12
    invoke-virtual {p0, p2, v0, v1}, Lp11/g;->e0(IJ)J

    .line 13
    .line 14
    .line 15
    move-result-wide p0

    .line 16
    return-wide p0

    .line 17
    :cond_0
    const-wide/high16 p0, -0x8000000000000000L

    .line 18
    .line 19
    return-wide p0
.end method

.method public final v(IJ)J
    .locals 2

    .line 1
    const/4 v0, 0x0

    .line 2
    const/4 v1, 0x1

    .line 3
    invoke-static {p0, p1, v0, v1}, Ljp/je;->g(Ln11/a;III)V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0, p2, p3}, Lp11/i;->b(J)I

    .line 7
    .line 8
    .line 9
    move-result v0

    .line 10
    if-eq v0, p1, :cond_0

    .line 11
    .line 12
    iget-object p0, p0, Lp11/i;->e:Lp11/m;

    .line 13
    .line 14
    invoke-virtual {p0, p2, p3}, Lp11/e;->X(J)I

    .line 15
    .line 16
    .line 17
    move-result p1

    .line 18
    neg-int p1, p1

    .line 19
    invoke-virtual {p0, p1, p2, p3}, Lp11/g;->e0(IJ)J

    .line 20
    .line 21
    .line 22
    move-result-wide p0

    .line 23
    return-wide p0

    .line 24
    :cond_0
    return-wide p2
.end method

.method public final w(JLjava/lang/String;Ljava/util/Locale;)J
    .locals 0

    .line 1
    invoke-static {p4}, Lp11/j;->b(Ljava/util/Locale;)Lp11/j;

    .line 2
    .line 3
    .line 4
    move-result-object p4

    .line 5
    iget-object p4, p4, Lp11/j;->g:Ljava/util/TreeMap;

    .line 6
    .line 7
    invoke-virtual {p4, p3}, Ljava/util/TreeMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 8
    .line 9
    .line 10
    move-result-object p4

    .line 11
    check-cast p4, Ljava/lang/Integer;

    .line 12
    .line 13
    if-eqz p4, :cond_0

    .line 14
    .line 15
    invoke-virtual {p4}, Ljava/lang/Integer;->intValue()I

    .line 16
    .line 17
    .line 18
    move-result p3

    .line 19
    invoke-virtual {p0, p3, p1, p2}, Lp11/i;->v(IJ)J

    .line 20
    .line 21
    .line 22
    move-result-wide p0

    .line 23
    return-wide p0

    .line 24
    :cond_0
    new-instance p0, Ln11/i;

    .line 25
    .line 26
    sget-object p1, Ln11/b;->h:Ln11/b;

    .line 27
    .line 28
    invoke-direct {p0, p1, p3}, Ln11/i;-><init>(Ln11/b;Ljava/lang/String;)V

    .line 29
    .line 30
    .line 31
    throw p0
.end method
