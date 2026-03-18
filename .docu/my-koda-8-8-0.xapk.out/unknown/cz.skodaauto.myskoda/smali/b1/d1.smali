.class public final Lb1/d1;
.super Lkotlin/jvm/internal/n;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic f:J

.field public final synthetic g:I

.field public final synthetic h:I

.field public final synthetic i:Lt3/s0;

.field public final synthetic j:Lt3/e1;


# direct methods
.method public constructor <init>(Lb1/e1;JIILt3/s0;Lt3/e1;)V
    .locals 0

    .line 1
    iput-wide p2, p0, Lb1/d1;->f:J

    .line 2
    .line 3
    iput p4, p0, Lb1/d1;->g:I

    .line 4
    .line 5
    iput p5, p0, Lb1/d1;->h:I

    .line 6
    .line 7
    iput-object p6, p0, Lb1/d1;->i:Lt3/s0;

    .line 8
    .line 9
    iput-object p7, p0, Lb1/d1;->j:Lt3/e1;

    .line 10
    .line 11
    const/4 p1, 0x1

    .line 12
    invoke-direct {p0, p1}, Lkotlin/jvm/internal/n;-><init>(I)V

    .line 13
    .line 14
    .line 15
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 11

    .line 1
    check-cast p1, Lt3/d1;

    .line 2
    .line 3
    iget v0, p0, Lb1/d1;->g:I

    .line 4
    .line 5
    int-to-long v0, v0

    .line 6
    const/16 v2, 0x20

    .line 7
    .line 8
    shl-long/2addr v0, v2

    .line 9
    iget v3, p0, Lb1/d1;->h:I

    .line 10
    .line 11
    int-to-long v3, v3

    .line 12
    const-wide v5, 0xffffffffL

    .line 13
    .line 14
    .line 15
    .line 16
    .line 17
    and-long/2addr v3, v5

    .line 18
    or-long/2addr v0, v3

    .line 19
    iget-object v3, p0, Lb1/d1;->i:Lt3/s0;

    .line 20
    .line 21
    invoke-interface {v3}, Lt3/t;->getLayoutDirection()Lt4/m;

    .line 22
    .line 23
    .line 24
    move-result-object v3

    .line 25
    shr-long v7, v0, v2

    .line 26
    .line 27
    long-to-int v4, v7

    .line 28
    iget-wide v7, p0, Lb1/d1;->f:J

    .line 29
    .line 30
    shr-long v9, v7, v2

    .line 31
    .line 32
    long-to-int v9, v9

    .line 33
    sub-int/2addr v4, v9

    .line 34
    int-to-float v4, v4

    .line 35
    const/high16 v9, 0x40000000    # 2.0f

    .line 36
    .line 37
    div-float/2addr v4, v9

    .line 38
    and-long/2addr v0, v5

    .line 39
    long-to-int v0, v0

    .line 40
    and-long/2addr v7, v5

    .line 41
    long-to-int v1, v7

    .line 42
    sub-int/2addr v0, v1

    .line 43
    int-to-float v0, v0

    .line 44
    div-float/2addr v0, v9

    .line 45
    sget-object v1, Lt4/m;->d:Lt4/m;

    .line 46
    .line 47
    const/high16 v7, -0x40800000    # -1.0f

    .line 48
    .line 49
    if-ne v3, v1, :cond_0

    .line 50
    .line 51
    move v1, v7

    .line 52
    goto :goto_0

    .line 53
    :cond_0
    const/4 v1, -0x1

    .line 54
    int-to-float v1, v1

    .line 55
    mul-float/2addr v1, v7

    .line 56
    :goto_0
    const/4 v3, 0x1

    .line 57
    int-to-float v3, v3

    .line 58
    add-float/2addr v1, v3

    .line 59
    mul-float/2addr v1, v4

    .line 60
    add-float/2addr v3, v7

    .line 61
    mul-float/2addr v3, v0

    .line 62
    invoke-static {v1}, Ljava/lang/Math;->round(F)I

    .line 63
    .line 64
    .line 65
    move-result v0

    .line 66
    invoke-static {v3}, Ljava/lang/Math;->round(F)I

    .line 67
    .line 68
    .line 69
    move-result v1

    .line 70
    int-to-long v3, v0

    .line 71
    shl-long v2, v3, v2

    .line 72
    .line 73
    int-to-long v0, v1

    .line 74
    and-long/2addr v0, v5

    .line 75
    or-long/2addr v0, v2

    .line 76
    iget-object p0, p0, Lb1/d1;->j:Lt3/e1;

    .line 77
    .line 78
    invoke-static {p1, p0, v0, v1}, Lt3/d1;->i(Lt3/d1;Lt3/e1;J)V

    .line 79
    .line 80
    .line 81
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 82
    .line 83
    return-object p0
.end method
