.class public final Lcom/google/android/material/datepicker/q0;
.super Lka/y;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final d:Lcom/google/android/material/datepicker/u;


# direct methods
.method public constructor <init>(Lcom/google/android/material/datepicker/u;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Lka/y;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lcom/google/android/material/datepicker/q0;->d:Lcom/google/android/material/datepicker/u;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final a()I
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/google/android/material/datepicker/q0;->d:Lcom/google/android/material/datepicker/u;

    .line 2
    .line 3
    iget-object p0, p0, Lcom/google/android/material/datepicker/u;->g:Lcom/google/android/material/datepicker/c;

    .line 4
    .line 5
    iget p0, p0, Lcom/google/android/material/datepicker/c;->i:I

    .line 6
    .line 7
    return p0
.end method

.method public final c(Lka/v0;I)V
    .locals 7

    .line 1
    check-cast p1, Lcom/google/android/material/datepicker/p0;

    .line 2
    .line 3
    iget-object v0, p0, Lcom/google/android/material/datepicker/q0;->d:Lcom/google/android/material/datepicker/u;

    .line 4
    .line 5
    iget-object v1, v0, Lcom/google/android/material/datepicker/u;->g:Lcom/google/android/material/datepicker/c;

    .line 6
    .line 7
    iget-object v1, v1, Lcom/google/android/material/datepicker/c;->d:Lcom/google/android/material/datepicker/b0;

    .line 8
    .line 9
    iget v1, v1, Lcom/google/android/material/datepicker/b0;->f:I

    .line 10
    .line 11
    add-int/2addr v1, p2

    .line 12
    iget-object p1, p1, Lcom/google/android/material/datepicker/p0;->u:Landroid/widget/TextView;

    .line 13
    .line 14
    invoke-static {}, Ljava/util/Locale;->getDefault()Ljava/util/Locale;

    .line 15
    .line 16
    .line 17
    move-result-object p2

    .line 18
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 19
    .line 20
    .line 21
    move-result-object v2

    .line 22
    filled-new-array {v2}, [Ljava/lang/Object;

    .line 23
    .line 24
    .line 25
    move-result-object v2

    .line 26
    const-string v3, "%d"

    .line 27
    .line 28
    invoke-static {p2, v3, v2}, Ljava/lang/String;->format(Ljava/util/Locale;Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    .line 29
    .line 30
    .line 31
    move-result-object p2

    .line 32
    invoke-virtual {p1, p2}, Landroid/widget/TextView;->setText(Ljava/lang/CharSequence;)V

    .line 33
    .line 34
    .line 35
    invoke-virtual {p1}, Landroid/view/View;->getContext()Landroid/content/Context;

    .line 36
    .line 37
    .line 38
    move-result-object p2

    .line 39
    invoke-static {}, Lcom/google/android/material/datepicker/n0;->f()Ljava/util/Calendar;

    .line 40
    .line 41
    .line 42
    move-result-object v2

    .line 43
    const/4 v3, 0x1

    .line 44
    invoke-virtual {v2, v3}, Ljava/util/Calendar;->get(I)I

    .line 45
    .line 46
    .line 47
    move-result v2

    .line 48
    if-ne v2, v1, :cond_0

    .line 49
    .line 50
    const v2, 0x7f1207dd

    .line 51
    .line 52
    .line 53
    invoke-virtual {p2, v2}, Landroid/content/Context;->getString(I)Ljava/lang/String;

    .line 54
    .line 55
    .line 56
    move-result-object p2

    .line 57
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 58
    .line 59
    .line 60
    move-result-object v2

    .line 61
    filled-new-array {v2}, [Ljava/lang/Object;

    .line 62
    .line 63
    .line 64
    move-result-object v2

    .line 65
    invoke-static {p2, v2}, Ljava/lang/String;->format(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    .line 66
    .line 67
    .line 68
    move-result-object p2

    .line 69
    goto :goto_0

    .line 70
    :cond_0
    const v2, 0x7f1207de

    .line 71
    .line 72
    .line 73
    invoke-virtual {p2, v2}, Landroid/content/Context;->getString(I)Ljava/lang/String;

    .line 74
    .line 75
    .line 76
    move-result-object p2

    .line 77
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 78
    .line 79
    .line 80
    move-result-object v2

    .line 81
    filled-new-array {v2}, [Ljava/lang/Object;

    .line 82
    .line 83
    .line 84
    move-result-object v2

    .line 85
    invoke-static {p2, v2}, Ljava/lang/String;->format(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    .line 86
    .line 87
    .line 88
    move-result-object p2

    .line 89
    :goto_0
    invoke-virtual {p1, p2}, Landroid/view/View;->setContentDescription(Ljava/lang/CharSequence;)V

    .line 90
    .line 91
    .line 92
    iget-object p2, v0, Lcom/google/android/material/datepicker/u;->j:Lcom/google/android/material/datepicker/d;

    .line 93
    .line 94
    invoke-static {}, Lcom/google/android/material/datepicker/n0;->f()Ljava/util/Calendar;

    .line 95
    .line 96
    .line 97
    move-result-object v2

    .line 98
    invoke-virtual {v2, v3}, Ljava/util/Calendar;->get(I)I

    .line 99
    .line 100
    .line 101
    move-result v4

    .line 102
    if-ne v4, v1, :cond_1

    .line 103
    .line 104
    iget-object v4, p2, Lcom/google/android/material/datepicker/d;->f:Ljava/lang/Object;

    .line 105
    .line 106
    :goto_1
    check-cast v4, Lca/j;

    .line 107
    .line 108
    goto :goto_2

    .line 109
    :cond_1
    iget-object v4, p2, Lcom/google/android/material/datepicker/d;->d:Ljava/lang/Object;

    .line 110
    .line 111
    goto :goto_1

    .line 112
    :goto_2
    iget-object v0, v0, Lcom/google/android/material/datepicker/u;->f:Lcom/google/android/material/datepicker/i;

    .line 113
    .line 114
    invoke-interface {v0}, Lcom/google/android/material/datepicker/i;->l0()Ljava/util/ArrayList;

    .line 115
    .line 116
    .line 117
    move-result-object v0

    .line 118
    invoke-virtual {v0}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 119
    .line 120
    .line 121
    move-result-object v0

    .line 122
    :cond_2
    :goto_3
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 123
    .line 124
    .line 125
    move-result v5

    .line 126
    if-eqz v5, :cond_3

    .line 127
    .line 128
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 129
    .line 130
    .line 131
    move-result-object v5

    .line 132
    check-cast v5, Ljava/lang/Long;

    .line 133
    .line 134
    invoke-virtual {v5}, Ljava/lang/Long;->longValue()J

    .line 135
    .line 136
    .line 137
    move-result-wide v5

    .line 138
    invoke-virtual {v2, v5, v6}, Ljava/util/Calendar;->setTimeInMillis(J)V

    .line 139
    .line 140
    .line 141
    invoke-virtual {v2, v3}, Ljava/util/Calendar;->get(I)I

    .line 142
    .line 143
    .line 144
    move-result v5

    .line 145
    if-ne v5, v1, :cond_2

    .line 146
    .line 147
    iget-object v4, p2, Lcom/google/android/material/datepicker/d;->e:Ljava/lang/Object;

    .line 148
    .line 149
    check-cast v4, Lca/j;

    .line 150
    .line 151
    goto :goto_3

    .line 152
    :cond_3
    invoke-virtual {v4, p1}, Lca/j;->p(Landroid/widget/TextView;)V

    .line 153
    .line 154
    .line 155
    iget-object p2, p2, Lcom/google/android/material/datepicker/d;->e:Ljava/lang/Object;

    .line 156
    .line 157
    check-cast p2, Lca/j;

    .line 158
    .line 159
    if-ne v4, p2, :cond_4

    .line 160
    .line 161
    goto :goto_4

    .line 162
    :cond_4
    const/4 v3, 0x0

    .line 163
    :goto_4
    invoke-virtual {p1, v3}, Landroid/widget/TextView;->setSelected(Z)V

    .line 164
    .line 165
    .line 166
    new-instance p2, Lcom/google/android/material/datepicker/o0;

    .line 167
    .line 168
    invoke-direct {p2, p0, v1}, Lcom/google/android/material/datepicker/o0;-><init>(Lcom/google/android/material/datepicker/q0;I)V

    .line 169
    .line 170
    .line 171
    invoke-virtual {p1, p2}, Landroid/view/View;->setOnClickListener(Landroid/view/View$OnClickListener;)V

    .line 172
    .line 173
    .line 174
    return-void
.end method

.method public final d(Landroid/view/ViewGroup;)Lka/v0;
    .locals 2

    .line 1
    invoke-virtual {p1}, Landroid/view/View;->getContext()Landroid/content/Context;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    invoke-static {p0}, Landroid/view/LayoutInflater;->from(Landroid/content/Context;)Landroid/view/LayoutInflater;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    const v0, 0x7f0d02cd

    .line 10
    .line 11
    .line 12
    const/4 v1, 0x0

    .line 13
    invoke-virtual {p0, v0, p1, v1}, Landroid/view/LayoutInflater;->inflate(ILandroid/view/ViewGroup;Z)Landroid/view/View;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    check-cast p0, Landroid/widget/TextView;

    .line 18
    .line 19
    new-instance p1, Lcom/google/android/material/datepicker/p0;

    .line 20
    .line 21
    invoke-direct {p1, p0}, Lcom/google/android/material/datepicker/p0;-><init>(Landroid/widget/TextView;)V

    .line 22
    .line 23
    .line 24
    return-object p1
.end method
