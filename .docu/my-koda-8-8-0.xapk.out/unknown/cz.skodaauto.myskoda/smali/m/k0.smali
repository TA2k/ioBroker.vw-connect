.class public final Lm/k0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Landroid/widget/AdapterView$OnItemClickListener;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Object;I)V
    .locals 0

    .line 1
    iput p2, p0, Lm/k0;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lm/k0;->e:Ljava/lang/Object;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final onItemClick(Landroid/widget/AdapterView;Landroid/view/View;IJ)V
    .locals 9

    .line 1
    iget p1, p0, Lm/k0;->d:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lm/k0;->e:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast p0, Lzq/r;

    .line 9
    .line 10
    iget-object p1, p0, Lzq/r;->h:Lm/z1;

    .line 11
    .line 12
    const/4 v0, 0x0

    .line 13
    if-gez p3, :cond_1

    .line 14
    .line 15
    iget-object v1, p1, Lm/z1;->C:Lm/z;

    .line 16
    .line 17
    invoke-virtual {v1}, Landroid/widget/PopupWindow;->isShowing()Z

    .line 18
    .line 19
    .line 20
    move-result v1

    .line 21
    if-nez v1, :cond_0

    .line 22
    .line 23
    move-object v1, v0

    .line 24
    goto :goto_0

    .line 25
    :cond_0
    iget-object v1, p1, Lm/z1;->f:Lm/m1;

    .line 26
    .line 27
    invoke-virtual {v1}, Landroid/widget/AdapterView;->getSelectedItem()Ljava/lang/Object;

    .line 28
    .line 29
    .line 30
    move-result-object v1

    .line 31
    goto :goto_0

    .line 32
    :cond_1
    invoke-virtual {p0}, Landroid/widget/AutoCompleteTextView;->getAdapter()Landroid/widget/ListAdapter;

    .line 33
    .line 34
    .line 35
    move-result-object v1

    .line 36
    invoke-interface {v1, p3}, Landroid/widget/Adapter;->getItem(I)Ljava/lang/Object;

    .line 37
    .line 38
    .line 39
    move-result-object v1

    .line 40
    :goto_0
    invoke-static {p0, v1}, Lzq/r;->a(Lzq/r;Ljava/lang/Object;)Ljava/lang/CharSequence;

    .line 41
    .line 42
    .line 43
    move-result-object v1

    .line 44
    const/4 v2, 0x0

    .line 45
    invoke-virtual {p0, v1, v2}, Landroid/widget/AutoCompleteTextView;->setText(Ljava/lang/CharSequence;Z)V

    .line 46
    .line 47
    .line 48
    invoke-virtual {p0}, Landroid/widget/AutoCompleteTextView;->getOnItemClickListener()Landroid/widget/AdapterView$OnItemClickListener;

    .line 49
    .line 50
    .line 51
    move-result-object v3

    .line 52
    if-eqz v3, :cond_7

    .line 53
    .line 54
    if-eqz p2, :cond_3

    .line 55
    .line 56
    if-gez p3, :cond_2

    .line 57
    .line 58
    goto :goto_2

    .line 59
    :cond_2
    :goto_1
    move-object v5, p2

    .line 60
    move v6, p3

    .line 61
    move-wide v7, p4

    .line 62
    goto :goto_6

    .line 63
    :cond_3
    :goto_2
    iget-object p0, p1, Lm/z1;->C:Lm/z;

    .line 64
    .line 65
    invoke-virtual {p0}, Landroid/widget/PopupWindow;->isShowing()Z

    .line 66
    .line 67
    .line 68
    move-result p0

    .line 69
    if-nez p0, :cond_4

    .line 70
    .line 71
    move-object p2, v0

    .line 72
    goto :goto_3

    .line 73
    :cond_4
    iget-object p0, p1, Lm/z1;->f:Lm/m1;

    .line 74
    .line 75
    invoke-virtual {p0}, Landroid/widget/AdapterView;->getSelectedView()Landroid/view/View;

    .line 76
    .line 77
    .line 78
    move-result-object p0

    .line 79
    move-object p2, p0

    .line 80
    :goto_3
    iget-object p0, p1, Lm/z1;->C:Lm/z;

    .line 81
    .line 82
    invoke-virtual {p0}, Landroid/widget/PopupWindow;->isShowing()Z

    .line 83
    .line 84
    .line 85
    move-result p0

    .line 86
    if-nez p0, :cond_5

    .line 87
    .line 88
    const/4 p0, -0x1

    .line 89
    :goto_4
    move p3, p0

    .line 90
    goto :goto_5

    .line 91
    :cond_5
    iget-object p0, p1, Lm/z1;->f:Lm/m1;

    .line 92
    .line 93
    invoke-virtual {p0}, Landroid/widget/AdapterView;->getSelectedItemPosition()I

    .line 94
    .line 95
    .line 96
    move-result p0

    .line 97
    goto :goto_4

    .line 98
    :goto_5
    iget-object p0, p1, Lm/z1;->C:Lm/z;

    .line 99
    .line 100
    invoke-virtual {p0}, Landroid/widget/PopupWindow;->isShowing()Z

    .line 101
    .line 102
    .line 103
    move-result p0

    .line 104
    if-nez p0, :cond_6

    .line 105
    .line 106
    const-wide/high16 p4, -0x8000000000000000L

    .line 107
    .line 108
    goto :goto_1

    .line 109
    :cond_6
    iget-object p0, p1, Lm/z1;->f:Lm/m1;

    .line 110
    .line 111
    invoke-virtual {p0}, Landroid/widget/AdapterView;->getSelectedItemId()J

    .line 112
    .line 113
    .line 114
    move-result-wide p4

    .line 115
    goto :goto_1

    .line 116
    :goto_6
    iget-object v4, p1, Lm/z1;->f:Lm/m1;

    .line 117
    .line 118
    invoke-interface/range {v3 .. v8}, Landroid/widget/AdapterView$OnItemClickListener;->onItemClick(Landroid/widget/AdapterView;Landroid/view/View;IJ)V

    .line 119
    .line 120
    .line 121
    :cond_7
    invoke-virtual {p1}, Lm/z1;->dismiss()V

    .line 122
    .line 123
    .line 124
    return-void

    .line 125
    :pswitch_0
    iget-object p0, p0, Lm/k0;->e:Ljava/lang/Object;

    .line 126
    .line 127
    check-cast p0, Lm/m0;

    .line 128
    .line 129
    iget-object p1, p0, Lm/m0;->H:Lm/p0;

    .line 130
    .line 131
    invoke-virtual {p1, p3}, Landroid/widget/AdapterView;->setSelection(I)V

    .line 132
    .line 133
    .line 134
    invoke-virtual {p1}, Landroid/widget/AdapterView;->getOnItemClickListener()Landroid/widget/AdapterView$OnItemClickListener;

    .line 135
    .line 136
    .line 137
    move-result-object p4

    .line 138
    if-eqz p4, :cond_8

    .line 139
    .line 140
    iget-object p4, p0, Lm/m0;->E:Lm/j0;

    .line 141
    .line 142
    invoke-virtual {p4, p3}, Lm/j0;->getItemId(I)J

    .line 143
    .line 144
    .line 145
    move-result-wide p4

    .line 146
    invoke-virtual {p1, p2, p3, p4, p5}, Landroid/widget/AdapterView;->performItemClick(Landroid/view/View;IJ)Z

    .line 147
    .line 148
    .line 149
    :cond_8
    invoke-virtual {p0}, Lm/z1;->dismiss()V

    .line 150
    .line 151
    .line 152
    return-void

    .line 153
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
