.class public final Lh2/p9;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/o;


# instance fields
.field public synthetic d:J

.field public final synthetic e:Lh2/s9;


# direct methods
.method public constructor <init>(Lh2/s9;Lkotlin/coroutines/Continuation;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lh2/p9;->e:Lh2/s9;

    .line 2
    .line 3
    const/4 p1, 0x3

    .line 4
    invoke-direct {p0, p1, p2}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 5
    .line 6
    .line 7
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    check-cast p1, Lg1/z1;

    .line 2
    .line 3
    check-cast p2, Ld3/b;

    .line 4
    .line 5
    iget-wide p1, p2, Ld3/b;->a:J

    .line 6
    .line 7
    check-cast p3, Lkotlin/coroutines/Continuation;

    .line 8
    .line 9
    new-instance v0, Lh2/p9;

    .line 10
    .line 11
    iget-object p0, p0, Lh2/p9;->e:Lh2/s9;

    .line 12
    .line 13
    invoke-direct {v0, p0, p3}, Lh2/p9;-><init>(Lh2/s9;Lkotlin/coroutines/Continuation;)V

    .line 14
    .line 15
    .line 16
    iput-wide p1, v0, Lh2/p9;->d:J

    .line 17
    .line 18
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 19
    .line 20
    invoke-virtual {v0, p0}, Lh2/p9;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 21
    .line 22
    .line 23
    return-object p0
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 4

    .line 1
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 2
    .line 3
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 4
    .line 5
    .line 6
    iget-wide v0, p0, Lh2/p9;->d:J

    .line 7
    .line 8
    iget-object p0, p0, Lh2/p9;->e:Lh2/s9;

    .line 9
    .line 10
    iget-object p1, p0, Lh2/s9;->m:Lg1/w1;

    .line 11
    .line 12
    sget-object v2, Lg1/w1;->d:Lg1/w1;

    .line 13
    .line 14
    if-ne p1, v2, :cond_0

    .line 15
    .line 16
    const-wide v2, 0xffffffffL

    .line 17
    .line 18
    .line 19
    .line 20
    .line 21
    and-long/2addr v0, v2

    .line 22
    long-to-int p1, v0

    .line 23
    invoke-static {p1}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 24
    .line 25
    .line 26
    move-result p1

    .line 27
    goto :goto_0

    .line 28
    :cond_0
    iget-boolean p1, p0, Lh2/s9;->j:Z

    .line 29
    .line 30
    const/16 v2, 0x20

    .line 31
    .line 32
    if-eqz p1, :cond_1

    .line 33
    .line 34
    iget-object p1, p0, Lh2/s9;->h:Ll2/g1;

    .line 35
    .line 36
    invoke-virtual {p1}, Ll2/g1;->o()I

    .line 37
    .line 38
    .line 39
    move-result p1

    .line 40
    int-to-float p1, p1

    .line 41
    shr-long/2addr v0, v2

    .line 42
    long-to-int v0, v0

    .line 43
    invoke-static {v0}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 44
    .line 45
    .line 46
    move-result v0

    .line 47
    sub-float/2addr p1, v0

    .line 48
    goto :goto_0

    .line 49
    :cond_1
    shr-long/2addr v0, v2

    .line 50
    long-to-int p1, v0

    .line 51
    invoke-static {p1}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 52
    .line 53
    .line 54
    move-result p1

    .line 55
    :goto_0
    iget-object v0, p0, Lh2/s9;->p:Ll2/f1;

    .line 56
    .line 57
    invoke-virtual {v0}, Ll2/f1;->o()F

    .line 58
    .line 59
    .line 60
    move-result v0

    .line 61
    sub-float/2addr p1, v0

    .line 62
    iget-object p0, p0, Lh2/s9;->q:Ll2/f1;

    .line 63
    .line 64
    invoke-virtual {p0, p1}, Ll2/f1;->p(F)V

    .line 65
    .line 66
    .line 67
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 68
    .line 69
    return-object p0
.end method
