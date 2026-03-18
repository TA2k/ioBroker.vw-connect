.class public final Lka/i;
.super Lka/i0;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final synthetic a:Lka/k;


# direct methods
.method public constructor <init>(Lka/k;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lka/i;->a:Lka/k;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final b(Landroidx/recyclerview/widget/RecyclerView;II)V
    .locals 7

    .line 1
    invoke-virtual {p1}, Landroidx/recyclerview/widget/RecyclerView;->computeHorizontalScrollOffset()I

    .line 2
    .line 3
    .line 4
    move-result p2

    .line 5
    invoke-virtual {p1}, Landroidx/recyclerview/widget/RecyclerView;->computeVerticalScrollOffset()I

    .line 6
    .line 7
    .line 8
    move-result p1

    .line 9
    iget-object p0, p0, Lka/i;->a:Lka/k;

    .line 10
    .line 11
    iget p3, p0, Lka/k;->a:I

    .line 12
    .line 13
    iget-object v0, p0, Lka/k;->s:Landroidx/recyclerview/widget/RecyclerView;

    .line 14
    .line 15
    invoke-virtual {v0}, Landroidx/recyclerview/widget/RecyclerView;->computeVerticalScrollRange()I

    .line 16
    .line 17
    .line 18
    move-result v0

    .line 19
    iget v1, p0, Lka/k;->r:I

    .line 20
    .line 21
    sub-int v2, v0, v1

    .line 22
    .line 23
    const/4 v3, 0x0

    .line 24
    const/4 v4, 0x1

    .line 25
    if-lez v2, :cond_0

    .line 26
    .line 27
    if-lt v1, p3, :cond_0

    .line 28
    .line 29
    move v2, v4

    .line 30
    goto :goto_0

    .line 31
    :cond_0
    move v2, v3

    .line 32
    :goto_0
    iput-boolean v2, p0, Lka/k;->t:Z

    .line 33
    .line 34
    iget-object v2, p0, Lka/k;->s:Landroidx/recyclerview/widget/RecyclerView;

    .line 35
    .line 36
    invoke-virtual {v2}, Landroidx/recyclerview/widget/RecyclerView;->computeHorizontalScrollRange()I

    .line 37
    .line 38
    .line 39
    move-result v2

    .line 40
    iget v5, p0, Lka/k;->q:I

    .line 41
    .line 42
    sub-int v6, v2, v5

    .line 43
    .line 44
    if-lez v6, :cond_1

    .line 45
    .line 46
    if-lt v5, p3, :cond_1

    .line 47
    .line 48
    move p3, v4

    .line 49
    goto :goto_1

    .line 50
    :cond_1
    move p3, v3

    .line 51
    :goto_1
    iput-boolean p3, p0, Lka/k;->u:Z

    .line 52
    .line 53
    iget-boolean v6, p0, Lka/k;->t:Z

    .line 54
    .line 55
    if-nez v6, :cond_2

    .line 56
    .line 57
    if-nez p3, :cond_2

    .line 58
    .line 59
    iget p1, p0, Lka/k;->v:I

    .line 60
    .line 61
    if-eqz p1, :cond_5

    .line 62
    .line 63
    invoke-virtual {p0, v3}, Lka/k;->f(I)V

    .line 64
    .line 65
    .line 66
    return-void

    .line 67
    :cond_2
    const/high16 p3, 0x40000000    # 2.0f

    .line 68
    .line 69
    if-eqz v6, :cond_3

    .line 70
    .line 71
    int-to-float p1, p1

    .line 72
    int-to-float v3, v1

    .line 73
    div-float v6, v3, p3

    .line 74
    .line 75
    add-float/2addr v6, p1

    .line 76
    mul-float/2addr v6, v3

    .line 77
    int-to-float p1, v0

    .line 78
    div-float/2addr v6, p1

    .line 79
    float-to-int p1, v6

    .line 80
    iput p1, p0, Lka/k;->l:I

    .line 81
    .line 82
    mul-int p1, v1, v1

    .line 83
    .line 84
    div-int/2addr p1, v0

    .line 85
    invoke-static {v1, p1}, Ljava/lang/Math;->min(II)I

    .line 86
    .line 87
    .line 88
    move-result p1

    .line 89
    iput p1, p0, Lka/k;->k:I

    .line 90
    .line 91
    :cond_3
    iget-boolean p1, p0, Lka/k;->u:Z

    .line 92
    .line 93
    if-eqz p1, :cond_4

    .line 94
    .line 95
    int-to-float p1, p2

    .line 96
    int-to-float p2, v5

    .line 97
    div-float p3, p2, p3

    .line 98
    .line 99
    add-float/2addr p3, p1

    .line 100
    mul-float/2addr p3, p2

    .line 101
    int-to-float p1, v2

    .line 102
    div-float/2addr p3, p1

    .line 103
    float-to-int p1, p3

    .line 104
    iput p1, p0, Lka/k;->o:I

    .line 105
    .line 106
    mul-int p1, v5, v5

    .line 107
    .line 108
    div-int/2addr p1, v2

    .line 109
    invoke-static {v5, p1}, Ljava/lang/Math;->min(II)I

    .line 110
    .line 111
    .line 112
    move-result p1

    .line 113
    iput p1, p0, Lka/k;->n:I

    .line 114
    .line 115
    :cond_4
    iget p1, p0, Lka/k;->v:I

    .line 116
    .line 117
    if-eqz p1, :cond_6

    .line 118
    .line 119
    if-ne p1, v4, :cond_5

    .line 120
    .line 121
    goto :goto_2

    .line 122
    :cond_5
    return-void

    .line 123
    :cond_6
    :goto_2
    invoke-virtual {p0, v4}, Lka/k;->f(I)V

    .line 124
    .line 125
    .line 126
    return-void
.end method
