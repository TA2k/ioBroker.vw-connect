.class public final Lh2/l8;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lo3/a;


# instance fields
.field public final synthetic d:Lh2/r8;

.field public final synthetic e:Lay0/k;


# direct methods
.method public constructor <init>(Lh2/r8;Lay0/k;)V
    .locals 1

    .line 1
    sget-object v0, Lg1/w1;->d:Lg1/w1;

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    iput-object p1, p0, Lh2/l8;->d:Lh2/r8;

    .line 7
    .line 8
    iput-object p2, p0, Lh2/l8;->e:Lay0/k;

    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final P(IJJ)J
    .locals 0

    .line 1
    const/4 p2, 0x1

    .line 2
    if-ne p1, p2, :cond_1

    .line 3
    .line 4
    iget-object p1, p0, Lh2/l8;->d:Lh2/r8;

    .line 5
    .line 6
    iget-object p1, p1, Lh2/r8;->e:Li2/p;

    .line 7
    .line 8
    sget-object p2, Lg1/w1;->d:Lg1/w1;

    .line 9
    .line 10
    const-wide p2, 0xffffffffL

    .line 11
    .line 12
    .line 13
    .line 14
    .line 15
    and-long/2addr p2, p4

    .line 16
    long-to-int p2, p2

    .line 17
    invoke-static {p2}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 18
    .line 19
    .line 20
    move-result p2

    .line 21
    invoke-virtual {p1, p2}, Li2/p;->e(F)F

    .line 22
    .line 23
    .line 24
    move-result p2

    .line 25
    iget-object p1, p1, Li2/p;->j:Ll2/f1;

    .line 26
    .line 27
    invoke-virtual {p1}, Ll2/f1;->o()F

    .line 28
    .line 29
    .line 30
    move-result p3

    .line 31
    invoke-static {p3}, Ljava/lang/Float;->isNaN(F)Z

    .line 32
    .line 33
    .line 34
    move-result p3

    .line 35
    if-eqz p3, :cond_0

    .line 36
    .line 37
    const/4 p3, 0x0

    .line 38
    goto :goto_0

    .line 39
    :cond_0
    invoke-virtual {p1}, Ll2/f1;->o()F

    .line 40
    .line 41
    .line 42
    move-result p3

    .line 43
    :goto_0
    invoke-virtual {p1, p2}, Ll2/f1;->p(F)V

    .line 44
    .line 45
    .line 46
    sub-float/2addr p2, p3

    .line 47
    invoke-virtual {p0, p2}, Lh2/l8;->a(F)J

    .line 48
    .line 49
    .line 50
    move-result-wide p0

    .line 51
    return-wide p0

    .line 52
    :cond_1
    const-wide/16 p0, 0x0

    .line 53
    .line 54
    return-wide p0
.end method

.method public final a(F)J
    .locals 4

    .line 1
    sget-object p0, Lg1/w1;->d:Lg1/w1;

    .line 2
    .line 3
    sget-object p0, Lg1/w1;->d:Lg1/w1;

    .line 4
    .line 5
    const/4 p0, 0x0

    .line 6
    invoke-static {p0}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 7
    .line 8
    .line 9
    move-result p0

    .line 10
    int-to-long v0, p0

    .line 11
    invoke-static {p1}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 12
    .line 13
    .line 14
    move-result p0

    .line 15
    int-to-long p0, p0

    .line 16
    const/16 v2, 0x20

    .line 17
    .line 18
    shl-long/2addr v0, v2

    .line 19
    const-wide v2, 0xffffffffL

    .line 20
    .line 21
    .line 22
    .line 23
    .line 24
    and-long/2addr p0, v2

    .line 25
    or-long/2addr p0, v0

    .line 26
    return-wide p0
.end method

.method public final i(JJLkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 0

    .line 1
    sget-object p1, Lg1/w1;->d:Lg1/w1;

    .line 2
    .line 3
    invoke-static {p3, p4}, Lt4/q;->c(J)F

    .line 4
    .line 5
    .line 6
    move-result p1

    .line 7
    new-instance p2, Ljava/lang/Float;

    .line 8
    .line 9
    invoke-direct {p2, p1}, Ljava/lang/Float;-><init>(F)V

    .line 10
    .line 11
    .line 12
    iget-object p0, p0, Lh2/l8;->e:Lay0/k;

    .line 13
    .line 14
    invoke-interface {p0, p2}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 15
    .line 16
    .line 17
    new-instance p0, Lt4/q;

    .line 18
    .line 19
    invoke-direct {p0, p3, p4}, Lt4/q;-><init>(J)V

    .line 20
    .line 21
    .line 22
    return-object p0
.end method

.method public final y0(JLkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 3

    .line 1
    sget-object p3, Lg1/w1;->d:Lg1/w1;

    .line 2
    .line 3
    invoke-static {p1, p2}, Lt4/q;->c(J)F

    .line 4
    .line 5
    .line 6
    move-result p3

    .line 7
    iget-object v0, p0, Lh2/l8;->d:Lh2/r8;

    .line 8
    .line 9
    iget-object v1, v0, Lh2/r8;->e:Li2/p;

    .line 10
    .line 11
    invoke-virtual {v1}, Li2/p;->f()F

    .line 12
    .line 13
    .line 14
    move-result v1

    .line 15
    iget-object v0, v0, Lh2/r8;->e:Li2/p;

    .line 16
    .line 17
    invoke-virtual {v0}, Li2/p;->d()Li2/u0;

    .line 18
    .line 19
    .line 20
    move-result-object v0

    .line 21
    invoke-virtual {v0}, Li2/u0;->c()F

    .line 22
    .line 23
    .line 24
    move-result v0

    .line 25
    const/4 v2, 0x0

    .line 26
    cmpg-float v2, p3, v2

    .line 27
    .line 28
    if-gez v2, :cond_0

    .line 29
    .line 30
    cmpl-float v0, v1, v0

    .line 31
    .line 32
    if-lez v0, :cond_0

    .line 33
    .line 34
    new-instance v0, Ljava/lang/Float;

    .line 35
    .line 36
    invoke-direct {v0, p3}, Ljava/lang/Float;-><init>(F)V

    .line 37
    .line 38
    .line 39
    iget-object p0, p0, Lh2/l8;->e:Lay0/k;

    .line 40
    .line 41
    invoke-interface {p0, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 42
    .line 43
    .line 44
    goto :goto_0

    .line 45
    :cond_0
    const-wide/16 p1, 0x0

    .line 46
    .line 47
    :goto_0
    new-instance p0, Lt4/q;

    .line 48
    .line 49
    invoke-direct {p0, p1, p2}, Lt4/q;-><init>(J)V

    .line 50
    .line 51
    .line 52
    return-object p0
.end method

.method public final z(IJ)J
    .locals 2

    .line 1
    sget-object v0, Lg1/w1;->d:Lg1/w1;

    .line 2
    .line 3
    const-wide v0, 0xffffffffL

    .line 4
    .line 5
    .line 6
    .line 7
    .line 8
    and-long/2addr p2, v0

    .line 9
    long-to-int p2, p2

    .line 10
    invoke-static {p2}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 11
    .line 12
    .line 13
    move-result p2

    .line 14
    const/4 p3, 0x0

    .line 15
    cmpg-float v0, p2, p3

    .line 16
    .line 17
    if-gez v0, :cond_1

    .line 18
    .line 19
    const/4 v0, 0x1

    .line 20
    if-ne p1, v0, :cond_1

    .line 21
    .line 22
    iget-object p1, p0, Lh2/l8;->d:Lh2/r8;

    .line 23
    .line 24
    iget-object p1, p1, Lh2/r8;->e:Li2/p;

    .line 25
    .line 26
    invoke-virtual {p1, p2}, Li2/p;->e(F)F

    .line 27
    .line 28
    .line 29
    move-result p2

    .line 30
    iget-object p1, p1, Li2/p;->j:Ll2/f1;

    .line 31
    .line 32
    invoke-virtual {p1}, Ll2/f1;->o()F

    .line 33
    .line 34
    .line 35
    move-result v0

    .line 36
    invoke-static {v0}, Ljava/lang/Float;->isNaN(F)Z

    .line 37
    .line 38
    .line 39
    move-result v0

    .line 40
    if-eqz v0, :cond_0

    .line 41
    .line 42
    goto :goto_0

    .line 43
    :cond_0
    invoke-virtual {p1}, Ll2/f1;->o()F

    .line 44
    .line 45
    .line 46
    move-result p3

    .line 47
    :goto_0
    invoke-virtual {p1, p2}, Ll2/f1;->p(F)V

    .line 48
    .line 49
    .line 50
    sub-float/2addr p2, p3

    .line 51
    invoke-virtual {p0, p2}, Lh2/l8;->a(F)J

    .line 52
    .line 53
    .line 54
    move-result-wide p0

    .line 55
    return-wide p0

    .line 56
    :cond_1
    const-wide/16 p0, 0x0

    .line 57
    .line 58
    return-wide p0
.end method
