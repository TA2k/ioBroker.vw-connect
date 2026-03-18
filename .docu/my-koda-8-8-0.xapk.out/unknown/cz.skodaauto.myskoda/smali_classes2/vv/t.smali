.class public final Lvv/t;
.super Lkotlin/jvm/internal/n;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic f:I

.field public final synthetic g:Ljava/util/List;

.field public final synthetic h:Ljava/util/List;

.field public final synthetic i:Lt3/s0;

.field public final synthetic j:F

.field public final synthetic k:Lt3/e1;


# direct methods
.method public constructor <init>(ILjava/util/List;Ljava/util/List;Lt3/s0;FLt3/e1;)V
    .locals 0

    .line 1
    iput p1, p0, Lvv/t;->f:I

    .line 2
    .line 3
    iput-object p2, p0, Lvv/t;->g:Ljava/util/List;

    .line 4
    .line 5
    iput-object p3, p0, Lvv/t;->h:Ljava/util/List;

    .line 6
    .line 7
    iput-object p4, p0, Lvv/t;->i:Lt3/s0;

    .line 8
    .line 9
    iput p5, p0, Lvv/t;->j:F

    .line 10
    .line 11
    iput-object p6, p0, Lvv/t;->k:Lt3/e1;

    .line 12
    .line 13
    const/4 p1, 0x1

    .line 14
    invoke-direct {p0, p1}, Lkotlin/jvm/internal/n;-><init>(I)V

    .line 15
    .line 16
    .line 17
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 14

    .line 1
    check-cast p1, Lt3/d1;

    .line 2
    .line 3
    const-string v0, "$this$layout"

    .line 4
    .line 5
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    const/4 v0, 0x0

    .line 9
    move v1, v0

    .line 10
    move v2, v1

    .line 11
    :goto_0
    iget v3, p0, Lvv/t;->f:I

    .line 12
    .line 13
    if-ge v1, v3, :cond_1

    .line 14
    .line 15
    iget-object v3, p0, Lvv/t;->g:Ljava/util/List;

    .line 16
    .line 17
    invoke-interface {v3, v1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 18
    .line 19
    .line 20
    move-result-object v3

    .line 21
    check-cast v3, Lt3/e1;

    .line 22
    .line 23
    iget-object v4, p0, Lvv/t;->h:Ljava/util/List;

    .line 24
    .line 25
    invoke-interface {v4, v1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 26
    .line 27
    .line 28
    move-result-object v4

    .line 29
    check-cast v4, Lt3/e1;

    .line 30
    .line 31
    iget v5, v3, Lt3/e1;->e:I

    .line 32
    .line 33
    iget v6, v4, Lt3/e1;->e:I

    .line 34
    .line 35
    invoke-static {v5, v6}, Ljava/lang/Math;->max(II)I

    .line 36
    .line 37
    .line 38
    move-result v5

    .line 39
    iget v6, p0, Lvv/t;->j:F

    .line 40
    .line 41
    iget-object v7, p0, Lvv/t;->i:Lt3/s0;

    .line 42
    .line 43
    invoke-interface {v7, v6}, Lt4/c;->Q(F)I

    .line 44
    .line 45
    .line 46
    move-result v6

    .line 47
    add-int/2addr v6, v5

    .line 48
    invoke-interface {v7}, Lt3/t;->getLayoutDirection()Lt4/m;

    .line 49
    .line 50
    .line 51
    move-result-object v5

    .line 52
    int-to-float v7, v0

    .line 53
    const/high16 v8, 0x40000000    # 2.0f

    .line 54
    .line 55
    div-float/2addr v7, v8

    .line 56
    sget-object v8, Lt4/m;->d:Lt4/m;

    .line 57
    .line 58
    const/high16 v9, 0x3f800000    # 1.0f

    .line 59
    .line 60
    if-ne v5, v8, :cond_0

    .line 61
    .line 62
    goto :goto_1

    .line 63
    :cond_0
    const/4 v5, -0x1

    .line 64
    int-to-float v5, v5

    .line 65
    mul-float/2addr v9, v5

    .line 66
    :goto_1
    const/4 v5, 0x1

    .line 67
    int-to-float v5, v5

    .line 68
    add-float/2addr v9, v5

    .line 69
    mul-float/2addr v9, v7

    .line 70
    const/high16 v8, -0x40800000    # -1.0f

    .line 71
    .line 72
    add-float/2addr v5, v8

    .line 73
    mul-float/2addr v5, v7

    .line 74
    invoke-static {v9}, Ljava/lang/Math;->round(F)I

    .line 75
    .line 76
    .line 77
    move-result v7

    .line 78
    invoke-static {v5}, Ljava/lang/Math;->round(F)I

    .line 79
    .line 80
    .line 81
    move-result v5

    .line 82
    int-to-long v7, v7

    .line 83
    const/16 v9, 0x20

    .line 84
    .line 85
    shl-long/2addr v7, v9

    .line 86
    int-to-long v10, v5

    .line 87
    const-wide v12, 0xffffffffL

    .line 88
    .line 89
    .line 90
    .line 91
    .line 92
    and-long/2addr v10, v12

    .line 93
    or-long/2addr v7, v10

    .line 94
    shr-long v9, v7, v9

    .line 95
    .line 96
    long-to-int v5, v9

    .line 97
    and-long/2addr v7, v12

    .line 98
    long-to-int v7, v7

    .line 99
    add-int/2addr v7, v2

    .line 100
    invoke-static {p1, v3, v5, v7}, Lt3/d1;->l(Lt3/d1;Lt3/e1;II)V

    .line 101
    .line 102
    .line 103
    iget-object v3, p0, Lvv/t;->k:Lt3/e1;

    .line 104
    .line 105
    iget v3, v3, Lt3/e1;->d:I

    .line 106
    .line 107
    invoke-static {p1, v4, v3, v2}, Lt3/d1;->l(Lt3/d1;Lt3/e1;II)V

    .line 108
    .line 109
    .line 110
    add-int/2addr v2, v6

    .line 111
    add-int/lit8 v1, v1, 0x1

    .line 112
    .line 113
    goto :goto_0

    .line 114
    :cond_1
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 115
    .line 116
    return-object p0
.end method
