.class public final synthetic Li91/q3;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/o;


# instance fields
.field public final synthetic d:F

.field public final synthetic e:Lgy0/f;

.field public final synthetic f:I

.field public final synthetic g:Ljava/lang/String;


# direct methods
.method public synthetic constructor <init>(FLgy0/f;ILjava/lang/String;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput p1, p0, Li91/q3;->d:F

    .line 5
    .line 6
    iput-object p2, p0, Li91/q3;->e:Lgy0/f;

    .line 7
    .line 8
    iput p3, p0, Li91/q3;->f:I

    .line 9
    .line 10
    iput-object p4, p0, Li91/q3;->g:Ljava/lang/String;

    .line 11
    .line 12
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 6

    .line 1
    check-cast p1, Lb1/a0;

    .line 2
    .line 3
    check-cast p2, Ll2/o;

    .line 4
    .line 5
    check-cast p3, Ljava/lang/Integer;

    .line 6
    .line 7
    invoke-virtual {p3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 8
    .line 9
    .line 10
    const-string p3, "$this$AnimatedVisibility"

    .line 11
    .line 12
    invoke-static {p1, p3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 13
    .line 14
    .line 15
    iget p1, p0, Li91/q3;->f:I

    .line 16
    .line 17
    int-to-float p3, p1

    .line 18
    sget-object v0, Lw3/h1;->h:Ll2/u2;

    .line 19
    .line 20
    check-cast p2, Ll2/t;

    .line 21
    .line 22
    invoke-virtual {p2, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 23
    .line 24
    .line 25
    move-result-object v0

    .line 26
    check-cast v0, Lt4/c;

    .line 27
    .line 28
    sget v1, Li91/u3;->b:F

    .line 29
    .line 30
    invoke-interface {v0, v1}, Lt4/c;->w0(F)F

    .line 31
    .line 32
    .line 33
    move-result v0

    .line 34
    sub-float/2addr p3, v0

    .line 35
    const/4 v1, 0x0

    .line 36
    invoke-static {p3, v1}, Ljava/lang/Math;->max(FF)F

    .line 37
    .line 38
    .line 39
    move-result p3

    .line 40
    invoke-static {v0, p3}, Ljava/lang/Math;->min(FF)F

    .line 41
    .line 42
    .line 43
    move-result v2

    .line 44
    sub-float/2addr p3, v2

    .line 45
    iget-object v2, p0, Li91/q3;->e:Lgy0/f;

    .line 46
    .line 47
    invoke-interface {v2}, Lgy0/g;->e()Ljava/lang/Comparable;

    .line 48
    .line 49
    .line 50
    move-result-object v3

    .line 51
    check-cast v3, Ljava/lang/Number;

    .line 52
    .line 53
    invoke-virtual {v3}, Ljava/lang/Number;->floatValue()F

    .line 54
    .line 55
    .line 56
    move-result v3

    .line 57
    invoke-interface {v2}, Lgy0/g;->g()Ljava/lang/Comparable;

    .line 58
    .line 59
    .line 60
    move-result-object v2

    .line 61
    check-cast v2, Ljava/lang/Number;

    .line 62
    .line 63
    invoke-virtual {v2}, Ljava/lang/Number;->floatValue()F

    .line 64
    .line 65
    .line 66
    move-result v2

    .line 67
    iget v4, p0, Li91/q3;->d:F

    .line 68
    .line 69
    invoke-static {v4, v3, v2}, Lkp/r9;->d(FFF)F

    .line 70
    .line 71
    .line 72
    move-result v4

    .line 73
    sub-float/2addr v2, v3

    .line 74
    cmpg-float v5, v2, v1

    .line 75
    .line 76
    if-nez v5, :cond_0

    .line 77
    .line 78
    move v4, v1

    .line 79
    goto :goto_0

    .line 80
    :cond_0
    sub-float/2addr v4, v3

    .line 81
    div-float/2addr v4, v2

    .line 82
    :goto_0
    const/high16 v2, 0x3f800000    # 1.0f

    .line 83
    .line 84
    invoke-static {v4, v1, v2}, Lkp/r9;->d(FFF)F

    .line 85
    .line 86
    .line 87
    move-result v1

    .line 88
    mul-float/2addr v1, p3

    .line 89
    add-float/2addr v1, v0

    .line 90
    invoke-static {v1}, Lcy0/a;->i(F)I

    .line 91
    .line 92
    .line 93
    move-result p3

    .line 94
    invoke-virtual {p2, p1}, Ll2/t;->e(I)Z

    .line 95
    .line 96
    .line 97
    move-result v0

    .line 98
    invoke-virtual {p2, p3}, Ll2/t;->e(I)Z

    .line 99
    .line 100
    .line 101
    move-result v1

    .line 102
    or-int/2addr v0, v1

    .line 103
    invoke-virtual {p2}, Ll2/t;->L()Ljava/lang/Object;

    .line 104
    .line 105
    .line 106
    move-result-object v1

    .line 107
    if-nez v0, :cond_1

    .line 108
    .line 109
    sget-object v0, Ll2/n;->a:Ll2/x0;

    .line 110
    .line 111
    if-ne v1, v0, :cond_2

    .line 112
    .line 113
    :cond_1
    new-instance v1, Li40/l2;

    .line 114
    .line 115
    const/4 v0, 0x1

    .line 116
    invoke-direct {v1, p1, p3, v0}, Li40/l2;-><init>(III)V

    .line 117
    .line 118
    .line 119
    invoke-virtual {p2, v1}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 120
    .line 121
    .line 122
    :cond_2
    check-cast v1, Lay0/o;

    .line 123
    .line 124
    sget-object p1, Lx2/p;->b:Lx2/p;

    .line 125
    .line 126
    invoke-static {p1, v1}, Landroidx/compose/ui/layout/a;->b(Lx2/s;Lay0/o;)Lx2/s;

    .line 127
    .line 128
    .line 129
    move-result-object p1

    .line 130
    const/4 p3, 0x0

    .line 131
    iget-object p0, p0, Li91/q3;->g:Ljava/lang/String;

    .line 132
    .line 133
    invoke-static {p3, p0, p2, p1}, Li91/u3;->f(ILjava/lang/String;Ll2/o;Lx2/s;)V

    .line 134
    .line 135
    .line 136
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 137
    .line 138
    return-object p0
.end method
