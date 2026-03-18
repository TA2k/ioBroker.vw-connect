.class public final Lka/x;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final synthetic a:Landroidx/recyclerview/widget/RecyclerView;


# direct methods
.method public synthetic constructor <init>(Landroidx/recyclerview/widget/RecyclerView;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lka/x;->a:Landroidx/recyclerview/widget/RecyclerView;

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public a(Lka/v0;Lb8/i;Lb8/i;)V
    .locals 7

    .line 1
    iget-object p0, p0, Lka/x;->a:Landroidx/recyclerview/widget/RecyclerView;

    .line 2
    .line 3
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 4
    .line 5
    .line 6
    const/4 v0, 0x0

    .line 7
    invoke-virtual {p1, v0}, Lka/v0;->n(Z)V

    .line 8
    .line 9
    .line 10
    iget-object v0, p0, Landroidx/recyclerview/widget/RecyclerView;->M:Lka/c0;

    .line 11
    .line 12
    move-object v1, v0

    .line 13
    check-cast v1, Lka/h;

    .line 14
    .line 15
    if-eqz p2, :cond_0

    .line 16
    .line 17
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 18
    .line 19
    .line 20
    iget v3, p2, Lb8/i;->b:I

    .line 21
    .line 22
    iget v5, p3, Lb8/i;->b:I

    .line 23
    .line 24
    if-ne v3, v5, :cond_1

    .line 25
    .line 26
    iget v0, p2, Lb8/i;->c:I

    .line 27
    .line 28
    iget v2, p3, Lb8/i;->c:I

    .line 29
    .line 30
    if-eq v0, v2, :cond_0

    .line 31
    .line 32
    goto :goto_0

    .line 33
    :cond_0
    move-object v2, p1

    .line 34
    goto :goto_1

    .line 35
    :cond_1
    :goto_0
    iget v4, p2, Lb8/i;->c:I

    .line 36
    .line 37
    iget v6, p3, Lb8/i;->c:I

    .line 38
    .line 39
    move-object v2, p1

    .line 40
    invoke-virtual/range {v1 .. v6}, Lka/h;->g(Lka/v0;IIII)Z

    .line 41
    .line 42
    .line 43
    move-result p1

    .line 44
    goto :goto_2

    .line 45
    :goto_1
    invoke-virtual {v1, v2}, Lka/h;->l(Lka/v0;)V

    .line 46
    .line 47
    .line 48
    iget-object p1, v2, Lka/v0;->a:Landroid/view/View;

    .line 49
    .line 50
    const/4 p2, 0x0

    .line 51
    invoke-virtual {p1, p2}, Landroid/view/View;->setAlpha(F)V

    .line 52
    .line 53
    .line 54
    iget-object p1, v1, Lka/h;->i:Ljava/util/ArrayList;

    .line 55
    .line 56
    invoke-virtual {p1, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 57
    .line 58
    .line 59
    const/4 p1, 0x1

    .line 60
    :goto_2
    if-eqz p1, :cond_2

    .line 61
    .line 62
    invoke-virtual {p0}, Landroidx/recyclerview/widget/RecyclerView;->T()V

    .line 63
    .line 64
    .line 65
    :cond_2
    return-void
.end method

.method public b(Lka/v0;Lb8/i;Lb8/i;)V
    .locals 7

    .line 1
    iget-object p0, p0, Lka/x;->a:Landroidx/recyclerview/widget/RecyclerView;

    .line 2
    .line 3
    iget-object v0, p0, Landroidx/recyclerview/widget/RecyclerView;->f:Lka/l0;

    .line 4
    .line 5
    invoke-virtual {v0, p1}, Lka/l0;->m(Lka/v0;)V

    .line 6
    .line 7
    .line 8
    invoke-virtual {p0, p1}, Landroidx/recyclerview/widget/RecyclerView;->f(Lka/v0;)V

    .line 9
    .line 10
    .line 11
    const/4 v0, 0x0

    .line 12
    invoke-virtual {p1, v0}, Lka/v0;->n(Z)V

    .line 13
    .line 14
    .line 15
    iget-object v0, p0, Landroidx/recyclerview/widget/RecyclerView;->M:Lka/c0;

    .line 16
    .line 17
    move-object v1, v0

    .line 18
    check-cast v1, Lka/h;

    .line 19
    .line 20
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 21
    .line 22
    .line 23
    iget v3, p2, Lb8/i;->b:I

    .line 24
    .line 25
    iget v4, p2, Lb8/i;->c:I

    .line 26
    .line 27
    iget-object p2, p1, Lka/v0;->a:Landroid/view/View;

    .line 28
    .line 29
    if-nez p3, :cond_0

    .line 30
    .line 31
    invoke-virtual {p2}, Landroid/view/View;->getLeft()I

    .line 32
    .line 33
    .line 34
    move-result v0

    .line 35
    :goto_0
    move v5, v0

    .line 36
    goto :goto_1

    .line 37
    :cond_0
    iget v0, p3, Lb8/i;->b:I

    .line 38
    .line 39
    goto :goto_0

    .line 40
    :goto_1
    if-nez p3, :cond_1

    .line 41
    .line 42
    invoke-virtual {p2}, Landroid/view/View;->getTop()I

    .line 43
    .line 44
    .line 45
    move-result p3

    .line 46
    :goto_2
    move v6, p3

    .line 47
    goto :goto_3

    .line 48
    :cond_1
    iget p3, p3, Lb8/i;->c:I

    .line 49
    .line 50
    goto :goto_2

    .line 51
    :goto_3
    invoke-virtual {p1}, Lka/v0;->h()Z

    .line 52
    .line 53
    .line 54
    move-result p3

    .line 55
    if-nez p3, :cond_2

    .line 56
    .line 57
    if-ne v3, v5, :cond_3

    .line 58
    .line 59
    if-eq v4, v6, :cond_2

    .line 60
    .line 61
    goto :goto_4

    .line 62
    :cond_2
    move-object v2, p1

    .line 63
    goto :goto_5

    .line 64
    :cond_3
    :goto_4
    invoke-virtual {p2}, Landroid/view/View;->getWidth()I

    .line 65
    .line 66
    .line 67
    move-result p3

    .line 68
    add-int/2addr p3, v5

    .line 69
    invoke-virtual {p2}, Landroid/view/View;->getHeight()I

    .line 70
    .line 71
    .line 72
    move-result v0

    .line 73
    add-int/2addr v0, v6

    .line 74
    invoke-virtual {p2, v5, v6, p3, v0}, Landroid/view/View;->layout(IIII)V

    .line 75
    .line 76
    .line 77
    move-object v2, p1

    .line 78
    invoke-virtual/range {v1 .. v6}, Lka/h;->g(Lka/v0;IIII)Z

    .line 79
    .line 80
    .line 81
    move-result p1

    .line 82
    goto :goto_6

    .line 83
    :goto_5
    invoke-virtual {v1, v2}, Lka/h;->l(Lka/v0;)V

    .line 84
    .line 85
    .line 86
    iget-object p1, v1, Lka/h;->h:Ljava/util/ArrayList;

    .line 87
    .line 88
    invoke-virtual {p1, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 89
    .line 90
    .line 91
    const/4 p1, 0x1

    .line 92
    :goto_6
    if-eqz p1, :cond_4

    .line 93
    .line 94
    invoke-virtual {p0}, Landroidx/recyclerview/widget/RecyclerView;->T()V

    .line 95
    .line 96
    .line 97
    :cond_4
    return-void
.end method
