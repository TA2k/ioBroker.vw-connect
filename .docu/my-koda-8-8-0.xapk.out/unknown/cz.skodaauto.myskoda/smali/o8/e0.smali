.class public final Lo8/e0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lo8/o;


# instance fields
.field public final a:I

.field public final b:I

.field public final c:Ljava/lang/String;

.field public d:I

.field public e:I

.field public f:Lo8/q;

.field public g:Lo8/i0;


# direct methods
.method public constructor <init>(IILjava/lang/String;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput p1, p0, Lo8/e0;->a:I

    .line 5
    .line 6
    iput p2, p0, Lo8/e0;->b:I

    .line 7
    .line 8
    iput-object p3, p0, Lo8/e0;->c:Ljava/lang/String;

    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final a(Lo8/p;)Z
    .locals 5

    .line 1
    const/4 v0, 0x1

    .line 2
    const/4 v1, 0x0

    .line 3
    iget v2, p0, Lo8/e0;->b:I

    .line 4
    .line 5
    iget p0, p0, Lo8/e0;->a:I

    .line 6
    .line 7
    const/4 v3, -0x1

    .line 8
    if-eq p0, v3, :cond_0

    .line 9
    .line 10
    if-eq v2, v3, :cond_0

    .line 11
    .line 12
    move v3, v0

    .line 13
    goto :goto_0

    .line 14
    :cond_0
    move v3, v1

    .line 15
    :goto_0
    invoke-static {v3}, Lw7/a;->j(Z)V

    .line 16
    .line 17
    .line 18
    new-instance v3, Lw7/p;

    .line 19
    .line 20
    invoke-direct {v3, v2}, Lw7/p;-><init>(I)V

    .line 21
    .line 22
    .line 23
    iget-object v4, v3, Lw7/p;->a:[B

    .line 24
    .line 25
    check-cast p1, Lo8/l;

    .line 26
    .line 27
    invoke-virtual {p1, v4, v1, v2, v1}, Lo8/l;->b([BIIZ)Z

    .line 28
    .line 29
    .line 30
    invoke-virtual {v3}, Lw7/p;->C()I

    .line 31
    .line 32
    .line 33
    move-result p1

    .line 34
    if-ne p1, p0, :cond_1

    .line 35
    .line 36
    return v0

    .line 37
    :cond_1
    return v1
.end method

.method public final b()V
    .locals 0

    .line 1
    return-void
.end method

.method public final c(Lo8/q;)V
    .locals 3

    .line 1
    iput-object p1, p0, Lo8/e0;->f:Lo8/q;

    .line 2
    .line 3
    const/16 v0, 0x400

    .line 4
    .line 5
    const/4 v1, 0x4

    .line 6
    invoke-interface {p1, v0, v1}, Lo8/q;->q(II)Lo8/i0;

    .line 7
    .line 8
    .line 9
    move-result-object p1

    .line 10
    iput-object p1, p0, Lo8/e0;->g:Lo8/i0;

    .line 11
    .line 12
    new-instance v0, Lt7/n;

    .line 13
    .line 14
    invoke-direct {v0}, Lt7/n;-><init>()V

    .line 15
    .line 16
    .line 17
    iget-object v1, p0, Lo8/e0;->c:Ljava/lang/String;

    .line 18
    .line 19
    invoke-static {v1}, Lt7/d0;->m(Ljava/lang/String;)Ljava/lang/String;

    .line 20
    .line 21
    .line 22
    move-result-object v2

    .line 23
    iput-object v2, v0, Lt7/n;->l:Ljava/lang/String;

    .line 24
    .line 25
    invoke-static {v1}, Lt7/d0;->m(Ljava/lang/String;)Ljava/lang/String;

    .line 26
    .line 27
    .line 28
    move-result-object v1

    .line 29
    iput-object v1, v0, Lt7/n;->m:Ljava/lang/String;

    .line 30
    .line 31
    invoke-static {v0, p1}, Lf2/m0;->x(Lt7/n;Lo8/i0;)V

    .line 32
    .line 33
    .line 34
    iget-object p1, p0, Lo8/e0;->f:Lo8/q;

    .line 35
    .line 36
    invoke-interface {p1}, Lo8/q;->m()V

    .line 37
    .line 38
    .line 39
    iget-object p1, p0, Lo8/e0;->f:Lo8/q;

    .line 40
    .line 41
    new-instance v0, Lo8/f0;

    .line 42
    .line 43
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 44
    .line 45
    .line 46
    invoke-interface {p1, v0}, Lo8/q;->c(Lo8/c0;)V

    .line 47
    .line 48
    .line 49
    const/4 p1, 0x1

    .line 50
    iput p1, p0, Lo8/e0;->e:I

    .line 51
    .line 52
    return-void
.end method

.method public final d(JJ)V
    .locals 0

    .line 1
    const-wide/16 p3, 0x0

    .line 2
    .line 3
    cmp-long p1, p1, p3

    .line 4
    .line 5
    const/4 p2, 0x1

    .line 6
    if-eqz p1, :cond_1

    .line 7
    .line 8
    iget p1, p0, Lo8/e0;->e:I

    .line 9
    .line 10
    if-ne p1, p2, :cond_0

    .line 11
    .line 12
    goto :goto_0

    .line 13
    :cond_0
    return-void

    .line 14
    :cond_1
    :goto_0
    iput p2, p0, Lo8/e0;->e:I

    .line 15
    .line 16
    const/4 p1, 0x0

    .line 17
    iput p1, p0, Lo8/e0;->d:I

    .line 18
    .line 19
    return-void
.end method

.method public final h(Lo8/p;Lo8/s;)I
    .locals 9

    .line 1
    iget p2, p0, Lo8/e0;->e:I

    .line 2
    .line 3
    const/4 v0, -0x1

    .line 4
    const/4 v1, 0x2

    .line 5
    const/4 v2, 0x1

    .line 6
    if-eq p2, v2, :cond_1

    .line 7
    .line 8
    if-ne p2, v1, :cond_0

    .line 9
    .line 10
    return v0

    .line 11
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 12
    .line 13
    invoke-direct {p0}, Ljava/lang/IllegalStateException;-><init>()V

    .line 14
    .line 15
    .line 16
    throw p0

    .line 17
    :cond_1
    iget-object p2, p0, Lo8/e0;->g:Lo8/i0;

    .line 18
    .line 19
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 20
    .line 21
    .line 22
    const/16 v3, 0x400

    .line 23
    .line 24
    invoke-interface {p2, p1, v3, v2}, Lo8/i0;->d(Lt7/g;IZ)I

    .line 25
    .line 26
    .line 27
    move-result p1

    .line 28
    const/4 p2, 0x0

    .line 29
    if-ne p1, v0, :cond_2

    .line 30
    .line 31
    iput v1, p0, Lo8/e0;->e:I

    .line 32
    .line 33
    iget-object v2, p0, Lo8/e0;->g:Lo8/i0;

    .line 34
    .line 35
    iget v6, p0, Lo8/e0;->d:I

    .line 36
    .line 37
    const/4 v7, 0x0

    .line 38
    const/4 v8, 0x0

    .line 39
    const-wide/16 v3, 0x0

    .line 40
    .line 41
    const/4 v5, 0x1

    .line 42
    invoke-interface/range {v2 .. v8}, Lo8/i0;->b(JIIILo8/h0;)V

    .line 43
    .line 44
    .line 45
    iput p2, p0, Lo8/e0;->d:I

    .line 46
    .line 47
    return p2

    .line 48
    :cond_2
    iget v0, p0, Lo8/e0;->d:I

    .line 49
    .line 50
    add-int/2addr v0, p1

    .line 51
    iput v0, p0, Lo8/e0;->d:I

    .line 52
    .line 53
    return p2
.end method
