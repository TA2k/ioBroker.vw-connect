.class public final Lw4/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lt3/q0;


# instance fields
.field public final synthetic a:Lw4/o;

.field public final synthetic b:Lv3/h0;


# direct methods
.method public constructor <init>(Lw4/o;Lv3/h0;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lw4/d;->a:Lw4/o;

    .line 5
    .line 6
    iput-object p2, p0, Lw4/d;->b:Lv3/h0;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final a(Lt3/t;Ljava/util/List;I)I
    .locals 1

    .line 1
    const/4 p1, 0x0

    .line 2
    invoke-static {p1, p1}, Landroid/view/View$MeasureSpec;->makeMeasureSpec(II)I

    .line 3
    .line 4
    .line 5
    move-result p2

    .line 6
    iget-object p0, p0, Lw4/d;->a:Lw4/o;

    .line 7
    .line 8
    invoke-virtual {p0}, Lw4/g;->getLayoutParams()Landroid/view/ViewGroup$LayoutParams;

    .line 9
    .line 10
    .line 11
    move-result-object v0

    .line 12
    invoke-static {v0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 13
    .line 14
    .line 15
    iget v0, v0, Landroid/view/ViewGroup$LayoutParams;->height:I

    .line 16
    .line 17
    invoke-static {p0, p1, p3, v0}, Lw4/g;->k(Lw4/o;III)I

    .line 18
    .line 19
    .line 20
    move-result p1

    .line 21
    invoke-virtual {p0, p2, p1}, Landroid/view/View;->measure(II)V

    .line 22
    .line 23
    .line 24
    invoke-virtual {p0}, Landroid/view/View;->getMeasuredWidth()I

    .line 25
    .line 26
    .line 27
    move-result p0

    .line 28
    return p0
.end method

.method public final b(Lt3/s0;Ljava/util/List;J)Lt3/r0;
    .locals 4

    .line 1
    iget-object p2, p0, Lw4/d;->a:Lw4/o;

    .line 2
    .line 3
    invoke-virtual {p2}, Landroid/view/ViewGroup;->getChildCount()I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    sget-object v1, Lmx0/t;->d:Lmx0/t;

    .line 8
    .line 9
    if-nez v0, :cond_0

    .line 10
    .line 11
    invoke-static {p3, p4}, Lt4/a;->j(J)I

    .line 12
    .line 13
    .line 14
    move-result p0

    .line 15
    invoke-static {p3, p4}, Lt4/a;->i(J)I

    .line 16
    .line 17
    .line 18
    move-result p2

    .line 19
    sget-object p3, Lw4/b;->h:Lw4/b;

    .line 20
    .line 21
    invoke-interface {p1, p0, p2, v1, p3}, Lt3/s0;->c0(IILjava/util/Map;Lay0/k;)Lt3/r0;

    .line 22
    .line 23
    .line 24
    move-result-object p0

    .line 25
    return-object p0

    .line 26
    :cond_0
    invoke-static {p3, p4}, Lt4/a;->j(J)I

    .line 27
    .line 28
    .line 29
    move-result v0

    .line 30
    const/4 v2, 0x0

    .line 31
    if-eqz v0, :cond_1

    .line 32
    .line 33
    invoke-virtual {p2, v2}, Landroid/view/ViewGroup;->getChildAt(I)Landroid/view/View;

    .line 34
    .line 35
    .line 36
    move-result-object v0

    .line 37
    invoke-static {p3, p4}, Lt4/a;->j(J)I

    .line 38
    .line 39
    .line 40
    move-result v3

    .line 41
    invoke-virtual {v0, v3}, Landroid/view/View;->setMinimumWidth(I)V

    .line 42
    .line 43
    .line 44
    :cond_1
    invoke-static {p3, p4}, Lt4/a;->i(J)I

    .line 45
    .line 46
    .line 47
    move-result v0

    .line 48
    if-eqz v0, :cond_2

    .line 49
    .line 50
    invoke-virtual {p2, v2}, Landroid/view/ViewGroup;->getChildAt(I)Landroid/view/View;

    .line 51
    .line 52
    .line 53
    move-result-object v0

    .line 54
    invoke-static {p3, p4}, Lt4/a;->i(J)I

    .line 55
    .line 56
    .line 57
    move-result v2

    .line 58
    invoke-virtual {v0, v2}, Landroid/view/View;->setMinimumHeight(I)V

    .line 59
    .line 60
    .line 61
    :cond_2
    invoke-static {p3, p4}, Lt4/a;->j(J)I

    .line 62
    .line 63
    .line 64
    move-result v0

    .line 65
    invoke-static {p3, p4}, Lt4/a;->h(J)I

    .line 66
    .line 67
    .line 68
    move-result v2

    .line 69
    invoke-virtual {p2}, Lw4/g;->getLayoutParams()Landroid/view/ViewGroup$LayoutParams;

    .line 70
    .line 71
    .line 72
    move-result-object v3

    .line 73
    invoke-static {v3}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 74
    .line 75
    .line 76
    iget v3, v3, Landroid/view/ViewGroup$LayoutParams;->width:I

    .line 77
    .line 78
    invoke-static {p2, v0, v2, v3}, Lw4/g;->k(Lw4/o;III)I

    .line 79
    .line 80
    .line 81
    move-result v0

    .line 82
    invoke-static {p3, p4}, Lt4/a;->i(J)I

    .line 83
    .line 84
    .line 85
    move-result v2

    .line 86
    invoke-static {p3, p4}, Lt4/a;->g(J)I

    .line 87
    .line 88
    .line 89
    move-result p3

    .line 90
    invoke-virtual {p2}, Lw4/g;->getLayoutParams()Landroid/view/ViewGroup$LayoutParams;

    .line 91
    .line 92
    .line 93
    move-result-object p4

    .line 94
    invoke-static {p4}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 95
    .line 96
    .line 97
    iget p4, p4, Landroid/view/ViewGroup$LayoutParams;->height:I

    .line 98
    .line 99
    invoke-static {p2, v2, p3, p4}, Lw4/g;->k(Lw4/o;III)I

    .line 100
    .line 101
    .line 102
    move-result p3

    .line 103
    invoke-virtual {p2, v0, p3}, Landroid/view/View;->measure(II)V

    .line 104
    .line 105
    .line 106
    invoke-virtual {p2}, Landroid/view/View;->getMeasuredWidth()I

    .line 107
    .line 108
    .line 109
    move-result p3

    .line 110
    invoke-virtual {p2}, Landroid/view/View;->getMeasuredHeight()I

    .line 111
    .line 112
    .line 113
    move-result p4

    .line 114
    new-instance v0, Lw4/c;

    .line 115
    .line 116
    iget-object p0, p0, Lw4/d;->b:Lv3/h0;

    .line 117
    .line 118
    const/4 v2, 0x1

    .line 119
    invoke-direct {v0, p2, p0, v2}, Lw4/c;-><init>(Lw4/o;Lv3/h0;I)V

    .line 120
    .line 121
    .line 122
    invoke-interface {p1, p3, p4, v1, v0}, Lt3/s0;->c0(IILjava/util/Map;Lay0/k;)Lt3/r0;

    .line 123
    .line 124
    .line 125
    move-result-object p0

    .line 126
    return-object p0
.end method

.method public final c(Lt3/t;Ljava/util/List;I)I
    .locals 0

    .line 1
    iget-object p0, p0, Lw4/d;->a:Lw4/o;

    .line 2
    .line 3
    invoke-virtual {p0}, Lw4/g;->getLayoutParams()Landroid/view/ViewGroup$LayoutParams;

    .line 4
    .line 5
    .line 6
    move-result-object p1

    .line 7
    invoke-static {p1}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 8
    .line 9
    .line 10
    iget p1, p1, Landroid/view/ViewGroup$LayoutParams;->width:I

    .line 11
    .line 12
    const/4 p2, 0x0

    .line 13
    invoke-static {p0, p2, p3, p1}, Lw4/g;->k(Lw4/o;III)I

    .line 14
    .line 15
    .line 16
    move-result p1

    .line 17
    invoke-static {p2, p2}, Landroid/view/View$MeasureSpec;->makeMeasureSpec(II)I

    .line 18
    .line 19
    .line 20
    move-result p2

    .line 21
    invoke-virtual {p0, p1, p2}, Landroid/view/View;->measure(II)V

    .line 22
    .line 23
    .line 24
    invoke-virtual {p0}, Landroid/view/View;->getMeasuredHeight()I

    .line 25
    .line 26
    .line 27
    move-result p0

    .line 28
    return p0
.end method

.method public final d(Lt3/t;Ljava/util/List;I)I
    .locals 0

    .line 1
    iget-object p0, p0, Lw4/d;->a:Lw4/o;

    .line 2
    .line 3
    invoke-virtual {p0}, Lw4/g;->getLayoutParams()Landroid/view/ViewGroup$LayoutParams;

    .line 4
    .line 5
    .line 6
    move-result-object p1

    .line 7
    invoke-static {p1}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 8
    .line 9
    .line 10
    iget p1, p1, Landroid/view/ViewGroup$LayoutParams;->width:I

    .line 11
    .line 12
    const/4 p2, 0x0

    .line 13
    invoke-static {p0, p2, p3, p1}, Lw4/g;->k(Lw4/o;III)I

    .line 14
    .line 15
    .line 16
    move-result p1

    .line 17
    invoke-static {p2, p2}, Landroid/view/View$MeasureSpec;->makeMeasureSpec(II)I

    .line 18
    .line 19
    .line 20
    move-result p2

    .line 21
    invoke-virtual {p0, p1, p2}, Landroid/view/View;->measure(II)V

    .line 22
    .line 23
    .line 24
    invoke-virtual {p0}, Landroid/view/View;->getMeasuredHeight()I

    .line 25
    .line 26
    .line 27
    move-result p0

    .line 28
    return p0
.end method

.method public final e(Lt3/t;Ljava/util/List;I)I
    .locals 1

    .line 1
    const/4 p1, 0x0

    .line 2
    invoke-static {p1, p1}, Landroid/view/View$MeasureSpec;->makeMeasureSpec(II)I

    .line 3
    .line 4
    .line 5
    move-result p2

    .line 6
    iget-object p0, p0, Lw4/d;->a:Lw4/o;

    .line 7
    .line 8
    invoke-virtual {p0}, Lw4/g;->getLayoutParams()Landroid/view/ViewGroup$LayoutParams;

    .line 9
    .line 10
    .line 11
    move-result-object v0

    .line 12
    invoke-static {v0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 13
    .line 14
    .line 15
    iget v0, v0, Landroid/view/ViewGroup$LayoutParams;->height:I

    .line 16
    .line 17
    invoke-static {p0, p1, p3, v0}, Lw4/g;->k(Lw4/o;III)I

    .line 18
    .line 19
    .line 20
    move-result p1

    .line 21
    invoke-virtual {p0, p2, p1}, Landroid/view/View;->measure(II)V

    .line 22
    .line 23
    .line 24
    invoke-virtual {p0}, Landroid/view/View;->getMeasuredWidth()I

    .line 25
    .line 26
    .line 27
    move-result p0

    .line 28
    return p0
.end method
