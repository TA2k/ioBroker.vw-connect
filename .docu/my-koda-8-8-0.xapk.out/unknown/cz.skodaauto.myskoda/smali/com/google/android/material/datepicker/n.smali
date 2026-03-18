.class public final Lcom/google/android/material/datepicker/n;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/lang/Runnable;


# instance fields
.field public final synthetic d:I

.field public final e:I

.field public final f:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Object;II)V
    .locals 0

    .line 1
    iput p3, p0, Lcom/google/android/material/datepicker/n;->d:I

    iput-object p1, p0, Lcom/google/android/material/datepicker/n;->f:Ljava/lang/Object;

    iput p2, p0, Lcom/google/android/material/datepicker/n;->e:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public constructor <init>(Ljava/util/List;ILjava/lang/Throwable;)V
    .locals 0

    const/4 p3, 0x3

    iput p3, p0, Lcom/google/android/material/datepicker/n;->d:I

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 3
    const-string p3, "initCallbacks cannot be null"

    invoke-static {p1, p3}, Ljp/ed;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    new-instance p3, Ljava/util/ArrayList;

    invoke-direct {p3, p1}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    iput-object p3, p0, Lcom/google/android/material/datepicker/n;->f:Ljava/lang/Object;

    .line 5
    iput p2, p0, Lcom/google/android/material/datepicker/n;->e:I

    return-void
.end method


# virtual methods
.method public final run()V
    .locals 4

    .line 1
    iget v0, p0, Lcom/google/android/material/datepicker/n;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lcom/google/android/material/datepicker/n;->f:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast v0, Lj1/a;

    .line 9
    .line 10
    iget-object v0, v0, Lj1/a;->e:Ljava/lang/Object;

    .line 11
    .line 12
    check-cast v0, Lp5/b;

    .line 13
    .line 14
    if-eqz v0, :cond_0

    .line 15
    .line 16
    iget p0, p0, Lcom/google/android/material/datepicker/n;->e:I

    .line 17
    .line 18
    invoke-virtual {v0, p0}, Lp5/b;->h(I)V

    .line 19
    .line 20
    .line 21
    :cond_0
    return-void

    .line 22
    :pswitch_0
    iget-object v0, p0, Lcom/google/android/material/datepicker/n;->f:Ljava/lang/Object;

    .line 23
    .line 24
    check-cast v0, Ljava/util/ArrayList;

    .line 25
    .line 26
    invoke-virtual {v0}, Ljava/util/ArrayList;->size()I

    .line 27
    .line 28
    .line 29
    move-result v1

    .line 30
    iget p0, p0, Lcom/google/android/material/datepicker/n;->e:I

    .line 31
    .line 32
    const/4 v2, 0x1

    .line 33
    const/4 v3, 0x0

    .line 34
    if-eq p0, v2, :cond_1

    .line 35
    .line 36
    :goto_0
    if-ge v3, v1, :cond_2

    .line 37
    .line 38
    invoke-virtual {v0, v3}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 39
    .line 40
    .line 41
    move-result-object p0

    .line 42
    check-cast p0, Ls6/f;

    .line 43
    .line 44
    invoke-virtual {p0}, Ls6/f;->a()V

    .line 45
    .line 46
    .line 47
    add-int/lit8 v3, v3, 0x1

    .line 48
    .line 49
    goto :goto_0

    .line 50
    :cond_1
    :goto_1
    if-ge v3, v1, :cond_2

    .line 51
    .line 52
    invoke-virtual {v0, v3}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 53
    .line 54
    .line 55
    move-result-object p0

    .line 56
    check-cast p0, Ls6/f;

    .line 57
    .line 58
    invoke-virtual {p0}, Ls6/f;->b()V

    .line 59
    .line 60
    .line 61
    add-int/lit8 v3, v3, 0x1

    .line 62
    .line 63
    goto :goto_1

    .line 64
    :cond_2
    return-void

    .line 65
    :pswitch_1
    :try_start_0
    invoke-static {}, Ljava/lang/Math;->random()D

    .line 66
    .line 67
    .line 68
    move-result-wide v0

    .line 69
    const-wide v2, 0x407f400000000000L    # 500.0

    .line 70
    .line 71
    .line 72
    .line 73
    .line 74
    mul-double/2addr v0, v2

    .line 75
    add-double/2addr v0, v2

    .line 76
    double-to-long v0, v0

    .line 77
    invoke-static {v0, v1}, Ljava/lang/Thread;->sleep(J)V
    :try_end_0
    .catch Ljava/lang/InterruptedException; {:try_start_0 .. :try_end_0} :catch_0

    .line 78
    .line 79
    .line 80
    :catch_0
    iget-object v0, p0, Lcom/google/android/material/datepicker/n;->f:Ljava/lang/Object;

    .line 81
    .line 82
    check-cast v0, Lru/e;

    .line 83
    .line 84
    iget p0, p0, Lcom/google/android/material/datepicker/n;->e:I

    .line 85
    .line 86
    invoke-virtual {v0, p0}, Lru/e;->b0(I)Ljava/util/Set;

    .line 87
    .line 88
    .line 89
    return-void

    .line 90
    :pswitch_2
    iget-object v0, p0, Lcom/google/android/material/datepicker/n;->f:Ljava/lang/Object;

    .line 91
    .line 92
    check-cast v0, Llo/s;

    .line 93
    .line 94
    iget p0, p0, Lcom/google/android/material/datepicker/n;->e:I

    .line 95
    .line 96
    invoke-virtual {v0, p0}, Llo/s;->j(I)V

    .line 97
    .line 98
    .line 99
    return-void

    .line 100
    :pswitch_3
    iget-object v0, p0, Lcom/google/android/material/datepicker/n;->f:Ljava/lang/Object;

    .line 101
    .line 102
    check-cast v0, Lcom/google/android/material/datepicker/u;

    .line 103
    .line 104
    iget-object v0, v0, Lcom/google/android/material/datepicker/u;->l:Landroidx/recyclerview/widget/RecyclerView;

    .line 105
    .line 106
    iget-boolean v1, v0, Landroidx/recyclerview/widget/RecyclerView;->z:Z

    .line 107
    .line 108
    if-eqz v1, :cond_3

    .line 109
    .line 110
    goto :goto_2

    .line 111
    :cond_3
    iget-object v1, v0, Landroidx/recyclerview/widget/RecyclerView;->p:Lka/f0;

    .line 112
    .line 113
    if-nez v1, :cond_4

    .line 114
    .line 115
    const-string p0, "RecyclerView"

    .line 116
    .line 117
    const-string v0, "Cannot smooth scroll without a LayoutManager set. Call setLayoutManager with a non-null argument."

    .line 118
    .line 119
    invoke-static {p0, v0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I

    .line 120
    .line 121
    .line 122
    goto :goto_2

    .line 123
    :cond_4
    iget p0, p0, Lcom/google/android/material/datepicker/n;->e:I

    .line 124
    .line 125
    invoke-virtual {v1, v0, p0}, Lka/f0;->z0(Landroidx/recyclerview/widget/RecyclerView;I)V

    .line 126
    .line 127
    .line 128
    :goto_2
    return-void

    .line 129
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
