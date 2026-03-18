.class public final Ls1/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Le3/n0;


# instance fields
.field public final a:Li40/s;


# direct methods
.method public constructor <init>(Li40/s;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Ls1/c;->a:Li40/s;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final a(JLt4/m;Lt4/c;)Le3/g0;
    .locals 2

    .line 1
    invoke-static {}, Le3/l;->a()Le3/i;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    const-string p4, "<unused var>"

    .line 6
    .line 7
    invoke-static {p3, p4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    const/4 p3, 0x0

    .line 11
    invoke-virtual {p0, p3, p3}, Le3/i;->h(FF)V

    .line 12
    .line 13
    .line 14
    const/16 p4, 0x20

    .line 15
    .line 16
    shr-long v0, p1, p4

    .line 17
    .line 18
    long-to-int v0, v0

    .line 19
    invoke-static {v0}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 20
    .line 21
    .line 22
    move-result v0

    .line 23
    invoke-virtual {p0, v0, p3}, Le3/i;->g(FF)V

    .line 24
    .line 25
    .line 26
    shr-long v0, p1, p4

    .line 27
    .line 28
    long-to-int p4, v0

    .line 29
    invoke-static {p4}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 30
    .line 31
    .line 32
    move-result p4

    .line 33
    const/high16 v0, 0x40000000    # 2.0f

    .line 34
    .line 35
    div-float/2addr p4, v0

    .line 36
    const-wide v0, 0xffffffffL

    .line 37
    .line 38
    .line 39
    .line 40
    .line 41
    and-long/2addr p1, v0

    .line 42
    long-to-int p1, p1

    .line 43
    invoke-static {p1}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 44
    .line 45
    .line 46
    move-result p1

    .line 47
    invoke-virtual {p0, p4, p1}, Le3/i;->g(FF)V

    .line 48
    .line 49
    .line 50
    invoke-virtual {p0, p3, p3}, Le3/i;->g(FF)V

    .line 51
    .line 52
    .line 53
    invoke-virtual {p0}, Le3/i;->e()V

    .line 54
    .line 55
    .line 56
    new-instance p1, Le3/d0;

    .line 57
    .line 58
    invoke-direct {p1, p0}, Le3/d0;-><init>(Le3/i;)V

    .line 59
    .line 60
    .line 61
    return-object p1
.end method

.method public final equals(Ljava/lang/Object;)Z
    .locals 2

    .line 1
    if-ne p0, p1, :cond_0

    .line 2
    .line 3
    goto :goto_1

    .line 4
    :cond_0
    instance-of v0, p1, Ls1/c;

    .line 5
    .line 6
    const/4 v1, 0x0

    .line 7
    if-eqz v0, :cond_1

    .line 8
    .line 9
    check-cast p1, Ls1/c;

    .line 10
    .line 11
    goto :goto_0

    .line 12
    :cond_1
    move-object p1, v1

    .line 13
    :goto_0
    if-eqz p1, :cond_2

    .line 14
    .line 15
    iget-object v1, p1, Ls1/c;->a:Li40/s;

    .line 16
    .line 17
    :cond_2
    iget-object p0, p0, Ls1/c;->a:Li40/s;

    .line 18
    .line 19
    if-ne v1, p0, :cond_3

    .line 20
    .line 21
    :goto_1
    const/4 p0, 0x1

    .line 22
    return p0

    .line 23
    :cond_3
    const/4 p0, 0x0

    .line 24
    return p0
.end method

.method public final hashCode()I
    .locals 0

    .line 1
    iget-object p0, p0, Ls1/c;->a:Li40/s;

    .line 2
    .line 3
    invoke-virtual {p0}, Ljava/lang/Object;->hashCode()I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method
