.class public final synthetic Lh2/l7;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:F

.field public final synthetic f:Lay0/a;

.field public final synthetic g:J

.field public final synthetic h:J

.field public final synthetic i:Lay0/k;


# direct methods
.method public synthetic constructor <init>(IFLay0/a;JJLay0/k;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput p1, p0, Lh2/l7;->d:I

    .line 5
    .line 6
    iput p2, p0, Lh2/l7;->e:F

    .line 7
    .line 8
    iput-object p3, p0, Lh2/l7;->f:Lay0/a;

    .line 9
    .line 10
    iput-wide p4, p0, Lh2/l7;->g:J

    .line 11
    .line 12
    iput-wide p6, p0, Lh2/l7;->h:J

    .line 13
    .line 14
    iput-object p8, p0, Lh2/l7;->i:Lay0/k;

    .line 15
    .line 16
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 9

    .line 1
    move-object v0, p1

    .line 2
    check-cast v0, Lg3/d;

    .line 3
    .line 4
    invoke-interface {v0}, Lg3/d;->e()J

    .line 5
    .line 6
    .line 7
    move-result-wide v1

    .line 8
    const-wide v3, 0xffffffffL

    .line 9
    .line 10
    .line 11
    .line 12
    .line 13
    and-long/2addr v1, v3

    .line 14
    long-to-int p1, v1

    .line 15
    invoke-static {p1}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 16
    .line 17
    .line 18
    move-result v5

    .line 19
    iget v6, p0, Lh2/l7;->d:I

    .line 20
    .line 21
    iget p1, p0, Lh2/l7;->e:F

    .line 22
    .line 23
    const/16 v1, 0x20

    .line 24
    .line 25
    if-nez v6, :cond_0

    .line 26
    .line 27
    goto :goto_0

    .line 28
    :cond_0
    invoke-interface {v0}, Lg3/d;->e()J

    .line 29
    .line 30
    .line 31
    move-result-wide v7

    .line 32
    and-long v2, v7, v3

    .line 33
    .line 34
    long-to-int v2, v2

    .line 35
    invoke-static {v2}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 36
    .line 37
    .line 38
    move-result v2

    .line 39
    invoke-interface {v0}, Lg3/d;->e()J

    .line 40
    .line 41
    .line 42
    move-result-wide v3

    .line 43
    shr-long/2addr v3, v1

    .line 44
    long-to-int v3, v3

    .line 45
    invoke-static {v3}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 46
    .line 47
    .line 48
    move-result v3

    .line 49
    cmpl-float v2, v2, v3

    .line 50
    .line 51
    if-lez v2, :cond_1

    .line 52
    .line 53
    goto :goto_0

    .line 54
    :cond_1
    invoke-interface {v0, v5}, Lt4/c;->o0(F)F

    .line 55
    .line 56
    .line 57
    move-result v2

    .line 58
    add-float/2addr p1, v2

    .line 59
    :goto_0
    invoke-interface {v0}, Lg3/d;->e()J

    .line 60
    .line 61
    .line 62
    move-result-wide v2

    .line 63
    shr-long v1, v2, v1

    .line 64
    .line 65
    long-to-int v1, v1

    .line 66
    invoke-static {v1}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 67
    .line 68
    .line 69
    move-result v1

    .line 70
    invoke-interface {v0, v1}, Lt4/c;->o0(F)F

    .line 71
    .line 72
    .line 73
    move-result v1

    .line 74
    div-float/2addr p1, v1

    .line 75
    iget-object v1, p0, Lh2/l7;->f:Lay0/a;

    .line 76
    .line 77
    invoke-interface {v1}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 78
    .line 79
    .line 80
    move-result-object v1

    .line 81
    check-cast v1, Ljava/lang/Number;

    .line 82
    .line 83
    invoke-virtual {v1}, Ljava/lang/Number;->floatValue()F

    .line 84
    .line 85
    .line 86
    move-result v7

    .line 87
    invoke-static {v7, p1}, Ljava/lang/Math;->min(FF)F

    .line 88
    .line 89
    .line 90
    move-result p1

    .line 91
    add-float v1, p1, v7

    .line 92
    .line 93
    const/high16 p1, 0x3f800000    # 1.0f

    .line 94
    .line 95
    cmpg-float p1, v1, p1

    .line 96
    .line 97
    if-gtz p1, :cond_2

    .line 98
    .line 99
    const/high16 v2, 0x3f800000    # 1.0f

    .line 100
    .line 101
    iget-wide v3, p0, Lh2/l7;->g:J

    .line 102
    .line 103
    invoke-static/range {v0 .. v6}, Lh2/n7;->f(Lg3/d;FFJFI)V

    .line 104
    .line 105
    .line 106
    :cond_2
    const/4 v1, 0x0

    .line 107
    iget-wide v3, p0, Lh2/l7;->h:J

    .line 108
    .line 109
    move v2, v7

    .line 110
    invoke-static/range {v0 .. v6}, Lh2/n7;->f(Lg3/d;FFJFI)V

    .line 111
    .line 112
    .line 113
    iget-object p0, p0, Lh2/l7;->i:Lay0/k;

    .line 114
    .line 115
    invoke-interface {p0, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 116
    .line 117
    .line 118
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 119
    .line 120
    return-object p0
.end method
