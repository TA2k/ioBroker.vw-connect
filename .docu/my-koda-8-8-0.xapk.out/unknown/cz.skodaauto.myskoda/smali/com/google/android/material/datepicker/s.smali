.class public final Lcom/google/android/material/datepicker/s;
.super Lka/i0;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final synthetic a:Lcom/google/android/material/datepicker/f0;

.field public final synthetic b:Lcom/google/android/material/datepicker/u;


# direct methods
.method public constructor <init>(Lcom/google/android/material/datepicker/u;Lcom/google/android/material/datepicker/f0;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lcom/google/android/material/datepicker/s;->b:Lcom/google/android/material/datepicker/u;

    .line 5
    .line 6
    iput-object p2, p0, Lcom/google/android/material/datepicker/s;->a:Lcom/google/android/material/datepicker/f0;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final b(Landroidx/recyclerview/widget/RecyclerView;II)V
    .locals 4

    .line 1
    iget-object p1, p0, Lcom/google/android/material/datepicker/s;->a:Lcom/google/android/material/datepicker/f0;

    .line 2
    .line 3
    iget-object p1, p1, Lcom/google/android/material/datepicker/f0;->d:Lcom/google/android/material/datepicker/c;

    .line 4
    .line 5
    iget-object p0, p0, Lcom/google/android/material/datepicker/s;->b:Lcom/google/android/material/datepicker/u;

    .line 6
    .line 7
    if-gez p2, :cond_1

    .line 8
    .line 9
    iget-object p2, p0, Lcom/google/android/material/datepicker/u;->l:Landroidx/recyclerview/widget/RecyclerView;

    .line 10
    .line 11
    invoke-virtual {p2}, Landroidx/recyclerview/widget/RecyclerView;->getLayoutManager()Lka/f0;

    .line 12
    .line 13
    .line 14
    move-result-object p2

    .line 15
    check-cast p2, Landroidx/recyclerview/widget/LinearLayoutManager;

    .line 16
    .line 17
    const/4 p3, 0x0

    .line 18
    invoke-virtual {p2}, Lka/f0;->v()I

    .line 19
    .line 20
    .line 21
    move-result v0

    .line 22
    invoke-virtual {p2, p3, v0, p3}, Landroidx/recyclerview/widget/LinearLayoutManager;->O0(IIZ)Landroid/view/View;

    .line 23
    .line 24
    .line 25
    move-result-object p2

    .line 26
    if-nez p2, :cond_0

    .line 27
    .line 28
    const/4 p2, -0x1

    .line 29
    goto :goto_0

    .line 30
    :cond_0
    invoke-static {p2}, Lka/f0;->H(Landroid/view/View;)I

    .line 31
    .line 32
    .line 33
    move-result p2

    .line 34
    goto :goto_0

    .line 35
    :cond_1
    iget-object p2, p0, Lcom/google/android/material/datepicker/u;->l:Landroidx/recyclerview/widget/RecyclerView;

    .line 36
    .line 37
    invoke-virtual {p2}, Landroidx/recyclerview/widget/RecyclerView;->getLayoutManager()Lka/f0;

    .line 38
    .line 39
    .line 40
    move-result-object p2

    .line 41
    check-cast p2, Landroidx/recyclerview/widget/LinearLayoutManager;

    .line 42
    .line 43
    invoke-virtual {p2}, Landroidx/recyclerview/widget/LinearLayoutManager;->M0()I

    .line 44
    .line 45
    .line 46
    move-result p2

    .line 47
    :goto_0
    iget-object p3, p1, Lcom/google/android/material/datepicker/c;->d:Lcom/google/android/material/datepicker/b0;

    .line 48
    .line 49
    iget-object p3, p3, Lcom/google/android/material/datepicker/b0;->d:Ljava/util/Calendar;

    .line 50
    .line 51
    invoke-static {p3}, Lcom/google/android/material/datepicker/n0;->c(Ljava/util/Calendar;)Ljava/util/Calendar;

    .line 52
    .line 53
    .line 54
    move-result-object p3

    .line 55
    const/4 v0, 0x2

    .line 56
    invoke-virtual {p3, v0, p2}, Ljava/util/Calendar;->add(II)V

    .line 57
    .line 58
    .line 59
    new-instance v1, Lcom/google/android/material/datepicker/b0;

    .line 60
    .line 61
    invoke-direct {v1, p3}, Lcom/google/android/material/datepicker/b0;-><init>(Ljava/util/Calendar;)V

    .line 62
    .line 63
    .line 64
    iput-object v1, p0, Lcom/google/android/material/datepicker/u;->h:Lcom/google/android/material/datepicker/b0;

    .line 65
    .line 66
    iget-object p3, p0, Lcom/google/android/material/datepicker/u;->q:Lcom/google/android/material/button/MaterialButton;

    .line 67
    .line 68
    iget-object v2, p1, Lcom/google/android/material/datepicker/c;->d:Lcom/google/android/material/datepicker/b0;

    .line 69
    .line 70
    iget-object v2, v2, Lcom/google/android/material/datepicker/b0;->d:Ljava/util/Calendar;

    .line 71
    .line 72
    invoke-static {v2}, Lcom/google/android/material/datepicker/n0;->c(Ljava/util/Calendar;)Ljava/util/Calendar;

    .line 73
    .line 74
    .line 75
    move-result-object v2

    .line 76
    invoke-virtual {v2, v0, p2}, Ljava/util/Calendar;->add(II)V

    .line 77
    .line 78
    .line 79
    const/4 p2, 0x5

    .line 80
    const/4 v3, 0x1

    .line 81
    invoke-virtual {v2, p2, v3}, Ljava/util/Calendar;->set(II)V

    .line 82
    .line 83
    .line 84
    invoke-static {v2}, Lcom/google/android/material/datepicker/n0;->c(Ljava/util/Calendar;)Ljava/util/Calendar;

    .line 85
    .line 86
    .line 87
    move-result-object v2

    .line 88
    invoke-virtual {v2, v0}, Ljava/util/Calendar;->get(I)I

    .line 89
    .line 90
    .line 91
    invoke-virtual {v2, v3}, Ljava/util/Calendar;->get(I)I

    .line 92
    .line 93
    .line 94
    const/4 v0, 0x7

    .line 95
    invoke-virtual {v2, v0}, Ljava/util/Calendar;->getMaximum(I)I

    .line 96
    .line 97
    .line 98
    invoke-virtual {v2, p2}, Ljava/util/Calendar;->getActualMaximum(I)I

    .line 99
    .line 100
    .line 101
    invoke-virtual {v2}, Ljava/util/Calendar;->getTimeInMillis()J

    .line 102
    .line 103
    .line 104
    invoke-virtual {v2}, Ljava/util/Calendar;->getTimeInMillis()J

    .line 105
    .line 106
    .line 107
    move-result-wide v2

    .line 108
    invoke-static {}, Ljava/util/Locale;->getDefault()Ljava/util/Locale;

    .line 109
    .line 110
    .line 111
    move-result-object p2

    .line 112
    const-string v0, "yMMMM"

    .line 113
    .line 114
    invoke-static {v0, p2}, Lcom/google/android/material/datepicker/n0;->b(Ljava/lang/String;Ljava/util/Locale;)Landroid/icu/text/DateFormat;

    .line 115
    .line 116
    .line 117
    move-result-object p2

    .line 118
    new-instance v0, Ljava/util/Date;

    .line 119
    .line 120
    invoke-direct {v0, v2, v3}, Ljava/util/Date;-><init>(J)V

    .line 121
    .line 122
    .line 123
    invoke-virtual {p2, v0}, Landroid/icu/text/DateFormat;->format(Ljava/util/Date;)Ljava/lang/String;

    .line 124
    .line 125
    .line 126
    move-result-object p2

    .line 127
    invoke-virtual {p3, p2}, Landroid/widget/TextView;->setText(Ljava/lang/CharSequence;)V

    .line 128
    .line 129
    .line 130
    iget-object p1, p1, Lcom/google/android/material/datepicker/c;->d:Lcom/google/android/material/datepicker/b0;

    .line 131
    .line 132
    invoke-virtual {p1, v1}, Lcom/google/android/material/datepicker/b0;->i(Lcom/google/android/material/datepicker/b0;)I

    .line 133
    .line 134
    .line 135
    move-result p1

    .line 136
    invoke-virtual {p0, p1}, Lcom/google/android/material/datepicker/u;->l(I)V

    .line 137
    .line 138
    .line 139
    return-void
.end method
