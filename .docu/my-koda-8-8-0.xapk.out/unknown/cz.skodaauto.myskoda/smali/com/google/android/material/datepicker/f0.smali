.class public final Lcom/google/android/material/datepicker/f0;
.super Lka/y;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final d:Lcom/google/android/material/datepicker/c;

.field public final e:Lcom/google/android/material/datepicker/i;

.field public final f:La0/j;

.field public final g:I


# direct methods
.method public constructor <init>(Landroid/view/ContextThemeWrapper;Lcom/google/android/material/datepicker/i;Lcom/google/android/material/datepicker/c;La0/j;)V
    .locals 3

    .line 1
    invoke-direct {p0}, Lka/y;-><init>()V

    .line 2
    .line 3
    .line 4
    iget-object v0, p3, Lcom/google/android/material/datepicker/c;->d:Lcom/google/android/material/datepicker/b0;

    .line 5
    .line 6
    iget-object v1, p3, Lcom/google/android/material/datepicker/c;->e:Lcom/google/android/material/datepicker/b0;

    .line 7
    .line 8
    iget-object v2, p3, Lcom/google/android/material/datepicker/c;->g:Lcom/google/android/material/datepicker/b0;

    .line 9
    .line 10
    invoke-virtual {v0, v2}, Lcom/google/android/material/datepicker/b0;->a(Lcom/google/android/material/datepicker/b0;)I

    .line 11
    .line 12
    .line 13
    move-result v0

    .line 14
    if-gtz v0, :cond_3

    .line 15
    .line 16
    invoke-virtual {v2, v1}, Lcom/google/android/material/datepicker/b0;->a(Lcom/google/android/material/datepicker/b0;)I

    .line 17
    .line 18
    .line 19
    move-result v0

    .line 20
    if-gtz v0, :cond_2

    .line 21
    .line 22
    sget v0, Lcom/google/android/material/datepicker/c0;->f:I

    .line 23
    .line 24
    invoke-virtual {p1}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    .line 25
    .line 26
    .line 27
    move-result-object v1

    .line 28
    const v2, 0x7f0703ec

    .line 29
    .line 30
    .line 31
    invoke-virtual {v1, v2}, Landroid/content/res/Resources;->getDimensionPixelSize(I)I

    .line 32
    .line 33
    .line 34
    move-result v1

    .line 35
    mul-int/2addr v1, v0

    .line 36
    const v0, 0x101020d

    .line 37
    .line 38
    .line 39
    invoke-static {p1, v0}, Lcom/google/android/material/datepicker/z;->n(Landroid/content/Context;I)Z

    .line 40
    .line 41
    .line 42
    move-result v0

    .line 43
    if-eqz v0, :cond_0

    .line 44
    .line 45
    invoke-virtual {p1}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    .line 46
    .line 47
    .line 48
    move-result-object p1

    .line 49
    invoke-virtual {p1, v2}, Landroid/content/res/Resources;->getDimensionPixelSize(I)I

    .line 50
    .line 51
    .line 52
    move-result p1

    .line 53
    goto :goto_0

    .line 54
    :cond_0
    const/4 p1, 0x0

    .line 55
    :goto_0
    add-int/2addr v1, p1

    .line 56
    iput v1, p0, Lcom/google/android/material/datepicker/f0;->g:I

    .line 57
    .line 58
    iput-object p3, p0, Lcom/google/android/material/datepicker/f0;->d:Lcom/google/android/material/datepicker/c;

    .line 59
    .line 60
    iput-object p2, p0, Lcom/google/android/material/datepicker/f0;->e:Lcom/google/android/material/datepicker/i;

    .line 61
    .line 62
    iput-object p4, p0, Lcom/google/android/material/datepicker/f0;->f:La0/j;

    .line 63
    .line 64
    iget-object p1, p0, Lka/y;->a:Lka/z;

    .line 65
    .line 66
    invoke-virtual {p1}, Lka/z;->a()Z

    .line 67
    .line 68
    .line 69
    move-result p1

    .line 70
    if-nez p1, :cond_1

    .line 71
    .line 72
    const/4 p1, 0x1

    .line 73
    iput-boolean p1, p0, Lka/y;->b:Z

    .line 74
    .line 75
    return-void

    .line 76
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 77
    .line 78
    const-string p1, "Cannot change whether this adapter has stable IDs while the adapter has registered observers."

    .line 79
    .line 80
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 81
    .line 82
    .line 83
    throw p0

    .line 84
    :cond_2
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 85
    .line 86
    const-string p1, "currentPage cannot be after lastPage"

    .line 87
    .line 88
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 89
    .line 90
    .line 91
    throw p0

    .line 92
    :cond_3
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 93
    .line 94
    const-string p1, "firstPage cannot be after currentPage"

    .line 95
    .line 96
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 97
    .line 98
    .line 99
    throw p0
.end method


# virtual methods
.method public final a()I
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/google/android/material/datepicker/f0;->d:Lcom/google/android/material/datepicker/c;

    .line 2
    .line 3
    iget p0, p0, Lcom/google/android/material/datepicker/c;->j:I

    .line 4
    .line 5
    return p0
.end method

.method public final b(I)J
    .locals 2

    .line 1
    iget-object p0, p0, Lcom/google/android/material/datepicker/f0;->d:Lcom/google/android/material/datepicker/c;

    .line 2
    .line 3
    iget-object p0, p0, Lcom/google/android/material/datepicker/c;->d:Lcom/google/android/material/datepicker/b0;

    .line 4
    .line 5
    iget-object p0, p0, Lcom/google/android/material/datepicker/b0;->d:Ljava/util/Calendar;

    .line 6
    .line 7
    invoke-static {p0}, Lcom/google/android/material/datepicker/n0;->c(Ljava/util/Calendar;)Ljava/util/Calendar;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    const/4 v0, 0x2

    .line 12
    invoke-virtual {p0, v0, p1}, Ljava/util/Calendar;->add(II)V

    .line 13
    .line 14
    .line 15
    const/4 p1, 0x5

    .line 16
    const/4 v1, 0x1

    .line 17
    invoke-virtual {p0, p1, v1}, Ljava/util/Calendar;->set(II)V

    .line 18
    .line 19
    .line 20
    invoke-static {p0}, Lcom/google/android/material/datepicker/n0;->c(Ljava/util/Calendar;)Ljava/util/Calendar;

    .line 21
    .line 22
    .line 23
    move-result-object p0

    .line 24
    invoke-virtual {p0, v0}, Ljava/util/Calendar;->get(I)I

    .line 25
    .line 26
    .line 27
    invoke-virtual {p0, v1}, Ljava/util/Calendar;->get(I)I

    .line 28
    .line 29
    .line 30
    const/4 v0, 0x7

    .line 31
    invoke-virtual {p0, v0}, Ljava/util/Calendar;->getMaximum(I)I

    .line 32
    .line 33
    .line 34
    invoke-virtual {p0, p1}, Ljava/util/Calendar;->getActualMaximum(I)I

    .line 35
    .line 36
    .line 37
    invoke-virtual {p0}, Ljava/util/Calendar;->getTimeInMillis()J

    .line 38
    .line 39
    .line 40
    invoke-virtual {p0}, Ljava/util/Calendar;->getTimeInMillis()J

    .line 41
    .line 42
    .line 43
    move-result-wide p0

    .line 44
    return-wide p0
.end method

.method public final c(Lka/v0;I)V
    .locals 4

    .line 1
    check-cast p1, Lcom/google/android/material/datepicker/e0;

    .line 2
    .line 3
    iget-object v0, p0, Lcom/google/android/material/datepicker/f0;->d:Lcom/google/android/material/datepicker/c;

    .line 4
    .line 5
    iget-object v1, v0, Lcom/google/android/material/datepicker/c;->d:Lcom/google/android/material/datepicker/b0;

    .line 6
    .line 7
    iget-object v1, v1, Lcom/google/android/material/datepicker/b0;->d:Ljava/util/Calendar;

    .line 8
    .line 9
    invoke-static {v1}, Lcom/google/android/material/datepicker/n0;->c(Ljava/util/Calendar;)Ljava/util/Calendar;

    .line 10
    .line 11
    .line 12
    move-result-object v1

    .line 13
    const/4 v2, 0x2

    .line 14
    invoke-virtual {v1, v2, p2}, Ljava/util/Calendar;->add(II)V

    .line 15
    .line 16
    .line 17
    new-instance p2, Lcom/google/android/material/datepicker/b0;

    .line 18
    .line 19
    invoke-direct {p2, v1}, Lcom/google/android/material/datepicker/b0;-><init>(Ljava/util/Calendar;)V

    .line 20
    .line 21
    .line 22
    iget-object v1, p1, Lcom/google/android/material/datepicker/e0;->u:Landroid/widget/TextView;

    .line 23
    .line 24
    invoke-virtual {p2}, Lcom/google/android/material/datepicker/b0;->h()Ljava/lang/String;

    .line 25
    .line 26
    .line 27
    move-result-object v2

    .line 28
    invoke-virtual {v1, v2}, Landroid/widget/TextView;->setText(Ljava/lang/CharSequence;)V

    .line 29
    .line 30
    .line 31
    iget-object p1, p1, Lcom/google/android/material/datepicker/e0;->v:Lcom/google/android/material/datepicker/MaterialCalendarGridView;

    .line 32
    .line 33
    const v1, 0x7f0a01fd

    .line 34
    .line 35
    .line 36
    invoke-virtual {p1, v1}, Landroid/view/View;->findViewById(I)Landroid/view/View;

    .line 37
    .line 38
    .line 39
    move-result-object p1

    .line 40
    check-cast p1, Lcom/google/android/material/datepicker/MaterialCalendarGridView;

    .line 41
    .line 42
    invoke-virtual {p1}, Lcom/google/android/material/datepicker/MaterialCalendarGridView;->a()Lcom/google/android/material/datepicker/c0;

    .line 43
    .line 44
    .line 45
    move-result-object v1

    .line 46
    if-eqz v1, :cond_2

    .line 47
    .line 48
    invoke-virtual {p1}, Lcom/google/android/material/datepicker/MaterialCalendarGridView;->a()Lcom/google/android/material/datepicker/c0;

    .line 49
    .line 50
    .line 51
    move-result-object v1

    .line 52
    iget-object v1, v1, Lcom/google/android/material/datepicker/c0;->a:Lcom/google/android/material/datepicker/b0;

    .line 53
    .line 54
    invoke-virtual {p2, v1}, Lcom/google/android/material/datepicker/b0;->equals(Ljava/lang/Object;)Z

    .line 55
    .line 56
    .line 57
    move-result v1

    .line 58
    if-eqz v1, :cond_2

    .line 59
    .line 60
    invoke-virtual {p1}, Landroid/view/View;->invalidate()V

    .line 61
    .line 62
    .line 63
    invoke-virtual {p1}, Lcom/google/android/material/datepicker/MaterialCalendarGridView;->a()Lcom/google/android/material/datepicker/c0;

    .line 64
    .line 65
    .line 66
    move-result-object p2

    .line 67
    iget-object v0, p2, Lcom/google/android/material/datepicker/c0;->b:Lcom/google/android/material/datepicker/i;

    .line 68
    .line 69
    iget-object v1, p2, Lcom/google/android/material/datepicker/c0;->c:Ljava/util/Collection;

    .line 70
    .line 71
    invoke-interface {v1}, Ljava/util/Collection;->iterator()Ljava/util/Iterator;

    .line 72
    .line 73
    .line 74
    move-result-object v1

    .line 75
    :goto_0
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 76
    .line 77
    .line 78
    move-result v2

    .line 79
    if-eqz v2, :cond_0

    .line 80
    .line 81
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 82
    .line 83
    .line 84
    move-result-object v2

    .line 85
    check-cast v2, Ljava/lang/Long;

    .line 86
    .line 87
    invoke-virtual {v2}, Ljava/lang/Long;->longValue()J

    .line 88
    .line 89
    .line 90
    move-result-wide v2

    .line 91
    invoke-virtual {p2, p1, v2, v3}, Lcom/google/android/material/datepicker/c0;->e(Lcom/google/android/material/datepicker/MaterialCalendarGridView;J)V

    .line 92
    .line 93
    .line 94
    goto :goto_0

    .line 95
    :cond_0
    if-eqz v0, :cond_3

    .line 96
    .line 97
    invoke-interface {v0}, Lcom/google/android/material/datepicker/i;->l0()Ljava/util/ArrayList;

    .line 98
    .line 99
    .line 100
    move-result-object v1

    .line 101
    invoke-virtual {v1}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 102
    .line 103
    .line 104
    move-result-object v1

    .line 105
    :goto_1
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 106
    .line 107
    .line 108
    move-result v2

    .line 109
    if-eqz v2, :cond_1

    .line 110
    .line 111
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 112
    .line 113
    .line 114
    move-result-object v2

    .line 115
    check-cast v2, Ljava/lang/Long;

    .line 116
    .line 117
    invoke-virtual {v2}, Ljava/lang/Long;->longValue()J

    .line 118
    .line 119
    .line 120
    move-result-wide v2

    .line 121
    invoke-virtual {p2, p1, v2, v3}, Lcom/google/android/material/datepicker/c0;->e(Lcom/google/android/material/datepicker/MaterialCalendarGridView;J)V

    .line 122
    .line 123
    .line 124
    goto :goto_1

    .line 125
    :cond_1
    invoke-interface {v0}, Lcom/google/android/material/datepicker/i;->l0()Ljava/util/ArrayList;

    .line 126
    .line 127
    .line 128
    move-result-object v0

    .line 129
    iput-object v0, p2, Lcom/google/android/material/datepicker/c0;->c:Ljava/util/Collection;

    .line 130
    .line 131
    goto :goto_2

    .line 132
    :cond_2
    new-instance v1, Lcom/google/android/material/datepicker/c0;

    .line 133
    .line 134
    iget-object v2, p0, Lcom/google/android/material/datepicker/f0;->e:Lcom/google/android/material/datepicker/i;

    .line 135
    .line 136
    invoke-direct {v1, p2, v2, v0}, Lcom/google/android/material/datepicker/c0;-><init>(Lcom/google/android/material/datepicker/b0;Lcom/google/android/material/datepicker/i;Lcom/google/android/material/datepicker/c;)V

    .line 137
    .line 138
    .line 139
    iget p2, p2, Lcom/google/android/material/datepicker/b0;->g:I

    .line 140
    .line 141
    invoke-virtual {p1, p2}, Landroid/widget/GridView;->setNumColumns(I)V

    .line 142
    .line 143
    .line 144
    invoke-virtual {p1, v1}, Lcom/google/android/material/datepicker/MaterialCalendarGridView;->setAdapter(Landroid/widget/ListAdapter;)V

    .line 145
    .line 146
    .line 147
    :cond_3
    :goto_2
    new-instance p2, Lcom/google/android/material/datepicker/d0;

    .line 148
    .line 149
    invoke-direct {p2, p0, p1}, Lcom/google/android/material/datepicker/d0;-><init>(Lcom/google/android/material/datepicker/f0;Lcom/google/android/material/datepicker/MaterialCalendarGridView;)V

    .line 150
    .line 151
    .line 152
    invoke-virtual {p1, p2}, Landroid/widget/AdapterView;->setOnItemClickListener(Landroid/widget/AdapterView$OnItemClickListener;)V

    .line 153
    .line 154
    .line 155
    return-void
.end method

.method public final d(Landroid/view/ViewGroup;)Lka/v0;
    .locals 3

    .line 1
    invoke-virtual {p1}, Landroid/view/View;->getContext()Landroid/content/Context;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    invoke-static {v0}, Landroid/view/LayoutInflater;->from(Landroid/content/Context;)Landroid/view/LayoutInflater;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    const v1, 0x7f0d02c9

    .line 10
    .line 11
    .line 12
    const/4 v2, 0x0

    .line 13
    invoke-virtual {v0, v1, p1, v2}, Landroid/view/LayoutInflater;->inflate(ILandroid/view/ViewGroup;Z)Landroid/view/View;

    .line 14
    .line 15
    .line 16
    move-result-object v0

    .line 17
    check-cast v0, Landroid/widget/LinearLayout;

    .line 18
    .line 19
    invoke-virtual {p1}, Landroid/view/View;->getContext()Landroid/content/Context;

    .line 20
    .line 21
    .line 22
    move-result-object p1

    .line 23
    const v1, 0x101020d

    .line 24
    .line 25
    .line 26
    invoke-static {p1, v1}, Lcom/google/android/material/datepicker/z;->n(Landroid/content/Context;I)Z

    .line 27
    .line 28
    .line 29
    move-result p1

    .line 30
    if-eqz p1, :cond_0

    .line 31
    .line 32
    new-instance p1, Lka/g0;

    .line 33
    .line 34
    const/4 v1, -0x1

    .line 35
    iget p0, p0, Lcom/google/android/material/datepicker/f0;->g:I

    .line 36
    .line 37
    invoke-direct {p1, v1, p0}, Lka/g0;-><init>(II)V

    .line 38
    .line 39
    .line 40
    invoke-virtual {v0, p1}, Landroid/view/View;->setLayoutParams(Landroid/view/ViewGroup$LayoutParams;)V

    .line 41
    .line 42
    .line 43
    new-instance p0, Lcom/google/android/material/datepicker/e0;

    .line 44
    .line 45
    const/4 p1, 0x1

    .line 46
    invoke-direct {p0, v0, p1}, Lcom/google/android/material/datepicker/e0;-><init>(Landroid/widget/LinearLayout;Z)V

    .line 47
    .line 48
    .line 49
    return-object p0

    .line 50
    :cond_0
    new-instance p0, Lcom/google/android/material/datepicker/e0;

    .line 51
    .line 52
    invoke-direct {p0, v0, v2}, Lcom/google/android/material/datepicker/e0;-><init>(Landroid/widget/LinearLayout;Z)V

    .line 53
    .line 54
    .line 55
    return-object p0
.end method
