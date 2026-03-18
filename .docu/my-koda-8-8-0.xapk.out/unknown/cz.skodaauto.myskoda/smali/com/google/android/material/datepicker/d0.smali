.class public final Lcom/google/android/material/datepicker/d0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Landroid/widget/AdapterView$OnItemClickListener;


# instance fields
.field public final synthetic d:Lcom/google/android/material/datepicker/MaterialCalendarGridView;

.field public final synthetic e:Lcom/google/android/material/datepicker/f0;


# direct methods
.method public constructor <init>(Lcom/google/android/material/datepicker/f0;Lcom/google/android/material/datepicker/MaterialCalendarGridView;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lcom/google/android/material/datepicker/d0;->e:Lcom/google/android/material/datepicker/f0;

    .line 5
    .line 6
    iput-object p2, p0, Lcom/google/android/material/datepicker/d0;->d:Lcom/google/android/material/datepicker/MaterialCalendarGridView;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final onItemClick(Landroid/widget/AdapterView;Landroid/view/View;IJ)V
    .locals 0

    .line 1
    iget-object p1, p0, Lcom/google/android/material/datepicker/d0;->d:Lcom/google/android/material/datepicker/MaterialCalendarGridView;

    .line 2
    .line 3
    invoke-virtual {p1}, Lcom/google/android/material/datepicker/MaterialCalendarGridView;->a()Lcom/google/android/material/datepicker/c0;

    .line 4
    .line 5
    .line 6
    move-result-object p2

    .line 7
    invoke-virtual {p2}, Lcom/google/android/material/datepicker/c0;->a()I

    .line 8
    .line 9
    .line 10
    move-result p4

    .line 11
    if-lt p3, p4, :cond_1

    .line 12
    .line 13
    invoke-virtual {p2}, Lcom/google/android/material/datepicker/c0;->c()I

    .line 14
    .line 15
    .line 16
    move-result p2

    .line 17
    if-gt p3, p2, :cond_1

    .line 18
    .line 19
    iget-object p0, p0, Lcom/google/android/material/datepicker/d0;->e:Lcom/google/android/material/datepicker/f0;

    .line 20
    .line 21
    iget-object p0, p0, Lcom/google/android/material/datepicker/f0;->f:La0/j;

    .line 22
    .line 23
    invoke-virtual {p1}, Lcom/google/android/material/datepicker/MaterialCalendarGridView;->a()Lcom/google/android/material/datepicker/c0;

    .line 24
    .line 25
    .line 26
    move-result-object p1

    .line 27
    invoke-virtual {p1, p3}, Lcom/google/android/material/datepicker/c0;->b(I)Ljava/lang/Long;

    .line 28
    .line 29
    .line 30
    move-result-object p1

    .line 31
    invoke-virtual {p1}, Ljava/lang/Long;->longValue()J

    .line 32
    .line 33
    .line 34
    move-result-wide p1

    .line 35
    iget-object p0, p0, La0/j;->e:Ljava/lang/Object;

    .line 36
    .line 37
    check-cast p0, Lcom/google/android/material/datepicker/u;

    .line 38
    .line 39
    iget-object p3, p0, Lcom/google/android/material/datepicker/u;->g:Lcom/google/android/material/datepicker/c;

    .line 40
    .line 41
    iget-object p3, p3, Lcom/google/android/material/datepicker/c;->f:Lcom/google/android/material/datepicker/b;

    .line 42
    .line 43
    invoke-interface {p3, p1, p2}, Lcom/google/android/material/datepicker/b;->g(J)Z

    .line 44
    .line 45
    .line 46
    move-result p3

    .line 47
    if-eqz p3, :cond_1

    .line 48
    .line 49
    iget-object p3, p0, Lcom/google/android/material/datepicker/u;->f:Lcom/google/android/material/datepicker/i;

    .line 50
    .line 51
    invoke-interface {p3, p1, p2}, Lcom/google/android/material/datepicker/i;->r0(J)V

    .line 52
    .line 53
    .line 54
    iget-object p1, p0, Lcom/google/android/material/datepicker/g0;->d:Ljava/util/LinkedHashSet;

    .line 55
    .line 56
    invoke-virtual {p1}, Ljava/util/AbstractCollection;->iterator()Ljava/util/Iterator;

    .line 57
    .line 58
    .line 59
    move-result-object p1

    .line 60
    :goto_0
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 61
    .line 62
    .line 63
    move-result p2

    .line 64
    if-eqz p2, :cond_0

    .line 65
    .line 66
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 67
    .line 68
    .line 69
    move-result-object p2

    .line 70
    check-cast p2, Lcom/google/android/material/datepicker/x;

    .line 71
    .line 72
    iget-object p3, p0, Lcom/google/android/material/datepicker/u;->f:Lcom/google/android/material/datepicker/i;

    .line 73
    .line 74
    invoke-interface {p3}, Lcom/google/android/material/datepicker/i;->n0()Ljava/lang/Object;

    .line 75
    .line 76
    .line 77
    move-result-object p3

    .line 78
    invoke-virtual {p2, p3}, Lcom/google/android/material/datepicker/x;->b(Ljava/lang/Object;)V

    .line 79
    .line 80
    .line 81
    goto :goto_0

    .line 82
    :cond_0
    iget-object p1, p0, Lcom/google/android/material/datepicker/u;->l:Landroidx/recyclerview/widget/RecyclerView;

    .line 83
    .line 84
    invoke-virtual {p1}, Landroidx/recyclerview/widget/RecyclerView;->getAdapter()Lka/y;

    .line 85
    .line 86
    .line 87
    move-result-object p1

    .line 88
    iget-object p1, p1, Lka/y;->a:Lka/z;

    .line 89
    .line 90
    invoke-virtual {p1}, Lka/z;->b()V

    .line 91
    .line 92
    .line 93
    iget-object p0, p0, Lcom/google/android/material/datepicker/u;->k:Landroidx/recyclerview/widget/RecyclerView;

    .line 94
    .line 95
    if-eqz p0, :cond_1

    .line 96
    .line 97
    invoke-virtual {p0}, Landroidx/recyclerview/widget/RecyclerView;->getAdapter()Lka/y;

    .line 98
    .line 99
    .line 100
    move-result-object p0

    .line 101
    iget-object p0, p0, Lka/y;->a:Lka/z;

    .line 102
    .line 103
    invoke-virtual {p0}, Lka/z;->b()V

    .line 104
    .line 105
    .line 106
    :cond_1
    return-void
.end method
