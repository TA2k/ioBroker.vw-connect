.class public final synthetic Lh2/bc;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:Lt3/e1;

.field public final synthetic e:I

.field public final synthetic f:Lt3/e1;

.field public final synthetic g:Lt3/e1;

.field public final synthetic h:J

.field public final synthetic i:Lt3/s0;

.field public final synthetic j:Lh2/cc;


# direct methods
.method public synthetic constructor <init>(Lt3/e1;ILt3/e1;Lt3/e1;JLt3/s0;Lh2/cc;II)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lh2/bc;->d:Lt3/e1;

    .line 5
    .line 6
    iput p2, p0, Lh2/bc;->e:I

    .line 7
    .line 8
    iput-object p3, p0, Lh2/bc;->f:Lt3/e1;

    .line 9
    .line 10
    iput-object p4, p0, Lh2/bc;->g:Lt3/e1;

    .line 11
    .line 12
    iput-wide p5, p0, Lh2/bc;->h:J

    .line 13
    .line 14
    iput-object p7, p0, Lh2/bc;->i:Lt3/s0;

    .line 15
    .line 16
    iput-object p8, p0, Lh2/bc;->j:Lh2/cc;

    .line 17
    .line 18
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 11

    .line 1
    check-cast p1, Lt3/d1;

    .line 2
    .line 3
    iget-object v0, p0, Lh2/bc;->d:Lt3/e1;

    .line 4
    .line 5
    iget v1, v0, Lt3/e1;->e:I

    .line 6
    .line 7
    iget v2, p0, Lh2/bc;->e:I

    .line 8
    .line 9
    sub-int v1, v2, v1

    .line 10
    .line 11
    div-int/lit8 v1, v1, 0x2

    .line 12
    .line 13
    const/4 v3, 0x0

    .line 14
    invoke-static {p1, v0, v3, v1}, Lt3/d1;->l(Lt3/d1;Lt3/e1;II)V

    .line 15
    .line 16
    .line 17
    sget v1, Lh2/q;->c:F

    .line 18
    .line 19
    iget-object v4, p0, Lh2/bc;->i:Lt3/s0;

    .line 20
    .line 21
    invoke-interface {v4, v1}, Lt4/c;->Q(F)I

    .line 22
    .line 23
    .line 24
    move-result v1

    .line 25
    iget v0, v0, Lt3/e1;->d:I

    .line 26
    .line 27
    invoke-static {v1, v0}, Ljava/lang/Math;->max(II)I

    .line 28
    .line 29
    .line 30
    move-result v0

    .line 31
    iget-object v1, p0, Lh2/bc;->g:Lt3/e1;

    .line 32
    .line 33
    iget v4, v1, Lt3/e1;->d:I

    .line 34
    .line 35
    iget-object v5, p0, Lh2/bc;->f:Lt3/e1;

    .line 36
    .line 37
    iget v6, v5, Lt3/e1;->d:I

    .line 38
    .line 39
    iget-wide v7, p0, Lh2/bc;->h:J

    .line 40
    .line 41
    invoke-static {v7, v8}, Lt4/a;->h(J)I

    .line 42
    .line 43
    .line 44
    move-result v9

    .line 45
    sget-object v10, Lt4/m;->d:Lt4/m;

    .line 46
    .line 47
    sub-int/2addr v9, v6

    .line 48
    int-to-float v6, v9

    .line 49
    const/high16 v9, 0x40000000    # 2.0f

    .line 50
    .line 51
    div-float/2addr v6, v9

    .line 52
    sget-object v9, Lt4/m;->d:Lt4/m;

    .line 53
    .line 54
    const/4 v9, 0x1

    .line 55
    int-to-float v9, v9

    .line 56
    const/high16 v10, -0x40800000    # -1.0f

    .line 57
    .line 58
    add-float/2addr v9, v10

    .line 59
    mul-float/2addr v9, v6

    .line 60
    invoke-static {v9}, Ljava/lang/Math;->round(F)I

    .line 61
    .line 62
    .line 63
    move-result v6

    .line 64
    if-ge v6, v0, :cond_0

    .line 65
    .line 66
    sub-int/2addr v0, v6

    .line 67
    :goto_0
    add-int/2addr v6, v0

    .line 68
    goto :goto_1

    .line 69
    :cond_0
    iget v0, v5, Lt3/e1;->d:I

    .line 70
    .line 71
    add-int/2addr v0, v6

    .line 72
    invoke-static {v7, v8}, Lt4/a;->h(J)I

    .line 73
    .line 74
    .line 75
    move-result v9

    .line 76
    sub-int/2addr v9, v4

    .line 77
    if-le v0, v9, :cond_1

    .line 78
    .line 79
    invoke-static {v7, v8}, Lt4/a;->h(J)I

    .line 80
    .line 81
    .line 82
    move-result v0

    .line 83
    sub-int/2addr v0, v4

    .line 84
    iget v4, v5, Lt3/e1;->d:I

    .line 85
    .line 86
    add-int/2addr v4, v6

    .line 87
    sub-int/2addr v0, v4

    .line 88
    goto :goto_0

    .line 89
    :cond_1
    :goto_1
    iget-object p0, p0, Lh2/bc;->j:Lh2/cc;

    .line 90
    .line 91
    iget-object p0, p0, Lh2/cc;->b:Lk1/i;

    .line 92
    .line 93
    sget-object v0, Lk1/j;->e:Lk1/f;

    .line 94
    .line 95
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 96
    .line 97
    .line 98
    move-result v0

    .line 99
    if-eqz v0, :cond_2

    .line 100
    .line 101
    iget p0, v5, Lt3/e1;->e:I

    .line 102
    .line 103
    sub-int p0, v2, p0

    .line 104
    .line 105
    div-int/lit8 v3, p0, 0x2

    .line 106
    .line 107
    goto :goto_2

    .line 108
    :cond_2
    sget-object v0, Lk1/j;->d:Lk1/e;

    .line 109
    .line 110
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 111
    .line 112
    .line 113
    move-result p0

    .line 114
    if-eqz p0, :cond_3

    .line 115
    .line 116
    iget p0, v5, Lt3/e1;->e:I

    .line 117
    .line 118
    sub-int v3, v2, p0

    .line 119
    .line 120
    :cond_3
    :goto_2
    invoke-static {p1, v5, v6, v3}, Lt3/d1;->l(Lt3/d1;Lt3/e1;II)V

    .line 121
    .line 122
    .line 123
    invoke-static {v7, v8}, Lt4/a;->h(J)I

    .line 124
    .line 125
    .line 126
    move-result p0

    .line 127
    iget v0, v1, Lt3/e1;->d:I

    .line 128
    .line 129
    sub-int/2addr p0, v0

    .line 130
    iget v0, v1, Lt3/e1;->e:I

    .line 131
    .line 132
    sub-int/2addr v2, v0

    .line 133
    div-int/lit8 v2, v2, 0x2

    .line 134
    .line 135
    invoke-static {p1, v1, p0, v2}, Lt3/d1;->l(Lt3/d1;Lt3/e1;II)V

    .line 136
    .line 137
    .line 138
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 139
    .line 140
    return-object p0
.end method
