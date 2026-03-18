.class public final Ln1/y;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lo1/r0;


# instance fields
.field public final synthetic a:Ln1/v;


# direct methods
.method public constructor <init>(Ln1/v;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Ln1/y;->a:Ln1/v;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final a()I
    .locals 1

    .line 1
    iget-object p0, p0, Ln1/y;->a:Ln1/v;

    .line 2
    .line 3
    invoke-virtual {p0}, Ln1/v;->g()Ln1/n;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    iget v0, v0, Ln1/n;->n:I

    .line 8
    .line 9
    neg-int v0, v0

    .line 10
    invoke-virtual {p0}, Ln1/v;->g()Ln1/n;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    iget p0, p0, Ln1/n;->r:I

    .line 15
    .line 16
    add-int/2addr v0, p0

    .line 17
    return v0
.end method

.method public final b()F
    .locals 2

    .line 1
    iget-object p0, p0, Ln1/y;->a:Ln1/v;

    .line 2
    .line 3
    iget-object v0, p0, Ln1/v;->d:Lm1/o;

    .line 4
    .line 5
    iget-object v0, v0, Lm1/o;->b:Ll2/g1;

    .line 6
    .line 7
    invoke-virtual {v0}, Ll2/g1;->o()I

    .line 8
    .line 9
    .line 10
    move-result v0

    .line 11
    iget-object v1, p0, Ln1/v;->d:Lm1/o;

    .line 12
    .line 13
    iget-object v1, v1, Lm1/o;->c:Ll2/g1;

    .line 14
    .line 15
    invoke-virtual {v1}, Ll2/g1;->o()I

    .line 16
    .line 17
    .line 18
    move-result v1

    .line 19
    invoke-virtual {p0}, Ln1/v;->d()Z

    .line 20
    .line 21
    .line 22
    move-result p0

    .line 23
    if-eqz p0, :cond_0

    .line 24
    .line 25
    mul-int/lit16 v0, v0, 0x1f4

    .line 26
    .line 27
    add-int/2addr v0, v1

    .line 28
    int-to-float p0, v0

    .line 29
    const/16 v0, 0x64

    .line 30
    .line 31
    int-to-float v0, v0

    .line 32
    add-float/2addr p0, v0

    .line 33
    return p0

    .line 34
    :cond_0
    mul-int/lit16 v0, v0, 0x1f4

    .line 35
    .line 36
    add-int/2addr v0, v1

    .line 37
    int-to-float p0, v0

    .line 38
    return p0
.end method

.method public final c()Ld4/b;
    .locals 1

    .line 1
    new-instance p0, Ld4/b;

    .line 2
    .line 3
    const/4 v0, -0x1

    .line 4
    invoke-direct {p0, v0, v0}, Ld4/b;-><init>(II)V

    .line 5
    .line 6
    .line 7
    return-object p0
.end method

.method public final d()I
    .locals 4

    .line 1
    iget-object p0, p0, Ln1/y;->a:Ln1/v;

    .line 2
    .line 3
    invoke-virtual {p0}, Ln1/v;->g()Ln1/n;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    iget-object v0, v0, Ln1/n;->q:Lg1/w1;

    .line 8
    .line 9
    sget-object v1, Lg1/w1;->d:Lg1/w1;

    .line 10
    .line 11
    if-ne v0, v1, :cond_0

    .line 12
    .line 13
    invoke-virtual {p0}, Ln1/v;->g()Ln1/n;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    invoke-virtual {p0}, Ln1/n;->e()J

    .line 18
    .line 19
    .line 20
    move-result-wide v0

    .line 21
    const-wide v2, 0xffffffffL

    .line 22
    .line 23
    .line 24
    .line 25
    .line 26
    and-long/2addr v0, v2

    .line 27
    :goto_0
    long-to-int p0, v0

    .line 28
    return p0

    .line 29
    :cond_0
    invoke-virtual {p0}, Ln1/v;->g()Ln1/n;

    .line 30
    .line 31
    .line 32
    move-result-object p0

    .line 33
    invoke-virtual {p0}, Ln1/n;->e()J

    .line 34
    .line 35
    .line 36
    move-result-wide v0

    .line 37
    const/16 p0, 0x20

    .line 38
    .line 39
    shr-long/2addr v0, p0

    .line 40
    goto :goto_0
.end method

.method public final e()F
    .locals 1

    .line 1
    iget-object p0, p0, Ln1/y;->a:Ln1/v;

    .line 2
    .line 3
    iget-object v0, p0, Ln1/v;->d:Lm1/o;

    .line 4
    .line 5
    iget-object v0, v0, Lm1/o;->b:Ll2/g1;

    .line 6
    .line 7
    invoke-virtual {v0}, Ll2/g1;->o()I

    .line 8
    .line 9
    .line 10
    move-result v0

    .line 11
    iget-object p0, p0, Ln1/v;->d:Lm1/o;

    .line 12
    .line 13
    iget-object p0, p0, Lm1/o;->c:Ll2/g1;

    .line 14
    .line 15
    invoke-virtual {p0}, Ll2/g1;->o()I

    .line 16
    .line 17
    .line 18
    move-result p0

    .line 19
    mul-int/lit16 v0, v0, 0x1f4

    .line 20
    .line 21
    add-int/2addr v0, p0

    .line 22
    int-to-float p0, v0

    .line 23
    return p0
.end method

.method public final f(ILg90/b;)Ljava/lang/Object;
    .locals 2

    .line 1
    sget-object v0, Ln1/v;->w:Lu2/l;

    .line 2
    .line 3
    iget-object p0, p0, Ln1/y;->a:Ln1/v;

    .line 4
    .line 5
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 6
    .line 7
    .line 8
    new-instance v0, Ln00/f;

    .line 9
    .line 10
    const/4 v1, 0x0

    .line 11
    invoke-direct {v0, p0, p1, v1}, Ln00/f;-><init>(Ln1/v;ILkotlin/coroutines/Continuation;)V

    .line 12
    .line 13
    .line 14
    sget-object p1, Le1/w0;->d:Le1/w0;

    .line 15
    .line 16
    invoke-virtual {p0, p1, v0, p2}, Ln1/v;->c(Le1/w0;Lay0/n;Lrx0/c;)Ljava/lang/Object;

    .line 17
    .line 18
    .line 19
    move-result-object p0

    .line 20
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 21
    .line 22
    sget-object p2, Llx0/b0;->a:Llx0/b0;

    .line 23
    .line 24
    if-ne p0, p1, :cond_0

    .line 25
    .line 26
    goto :goto_0

    .line 27
    :cond_0
    move-object p0, p2

    .line 28
    :goto_0
    if-ne p0, p1, :cond_1

    .line 29
    .line 30
    return-object p0

    .line 31
    :cond_1
    return-object p2
.end method
