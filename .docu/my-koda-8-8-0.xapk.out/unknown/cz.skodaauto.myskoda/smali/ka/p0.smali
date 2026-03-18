.class public final Lka/p0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public a:I

.field public b:I

.field public c:I

.field public d:I

.field public e:Landroid/view/animation/Interpolator;

.field public f:Z

.field public g:I


# virtual methods
.method public final a(Landroidx/recyclerview/widget/RecyclerView;)V
    .locals 6

    .line 1
    iget v0, p0, Lka/p0;->d:I

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    if-ltz v0, :cond_0

    .line 5
    .line 6
    const/4 v2, -0x1

    .line 7
    iput v2, p0, Lka/p0;->d:I

    .line 8
    .line 9
    invoke-virtual {p1, v0}, Landroidx/recyclerview/widget/RecyclerView;->N(I)V

    .line 10
    .line 11
    .line 12
    iput-boolean v1, p0, Lka/p0;->f:Z

    .line 13
    .line 14
    return-void

    .line 15
    :cond_0
    iget-boolean v0, p0, Lka/p0;->f:Z

    .line 16
    .line 17
    if-eqz v0, :cond_5

    .line 18
    .line 19
    iget-object v0, p0, Lka/p0;->e:Landroid/view/animation/Interpolator;

    .line 20
    .line 21
    const/4 v2, 0x1

    .line 22
    if-eqz v0, :cond_2

    .line 23
    .line 24
    iget v3, p0, Lka/p0;->c:I

    .line 25
    .line 26
    if-lt v3, v2, :cond_1

    .line 27
    .line 28
    goto :goto_0

    .line 29
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 30
    .line 31
    const-string p1, "If you provide an interpolator, you must set a positive duration"

    .line 32
    .line 33
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 34
    .line 35
    .line 36
    throw p0

    .line 37
    :cond_2
    :goto_0
    iget v3, p0, Lka/p0;->c:I

    .line 38
    .line 39
    if-lt v3, v2, :cond_4

    .line 40
    .line 41
    iget-object p1, p1, Landroidx/recyclerview/widget/RecyclerView;->e0:Lka/u0;

    .line 42
    .line 43
    iget v4, p0, Lka/p0;->a:I

    .line 44
    .line 45
    iget v5, p0, Lka/p0;->b:I

    .line 46
    .line 47
    invoke-virtual {p1, v4, v5, v3, v0}, Lka/u0;->c(IIILandroid/view/animation/Interpolator;)V

    .line 48
    .line 49
    .line 50
    iget p1, p0, Lka/p0;->g:I

    .line 51
    .line 52
    add-int/2addr p1, v2

    .line 53
    iput p1, p0, Lka/p0;->g:I

    .line 54
    .line 55
    const/16 v0, 0xa

    .line 56
    .line 57
    if-le p1, v0, :cond_3

    .line 58
    .line 59
    const-string p1, "RecyclerView"

    .line 60
    .line 61
    const-string v0, "Smooth Scroll action is being updated too frequently. Make sure you are not changing it unless necessary"

    .line 62
    .line 63
    invoke-static {p1, v0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I

    .line 64
    .line 65
    .line 66
    :cond_3
    iput-boolean v1, p0, Lka/p0;->f:Z

    .line 67
    .line 68
    return-void

    .line 69
    :cond_4
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 70
    .line 71
    const-string p1, "Scroll duration must be a positive number"

    .line 72
    .line 73
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 74
    .line 75
    .line 76
    throw p0

    .line 77
    :cond_5
    iput v1, p0, Lka/p0;->g:I

    .line 78
    .line 79
    return-void
.end method
