.class public final Lw4/c;
.super Lkotlin/jvm/internal/n;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic f:I

.field public final synthetic g:Lw4/o;

.field public final synthetic h:Lv3/h0;


# direct methods
.method public synthetic constructor <init>(Lw4/o;Lv3/h0;I)V
    .locals 0

    .line 1
    iput p3, p0, Lw4/c;->f:I

    .line 2
    .line 3
    iput-object p1, p0, Lw4/c;->g:Lw4/o;

    .line 4
    .line 5
    iput-object p2, p0, Lw4/c;->h:Lv3/h0;

    .line 6
    .line 7
    const/4 p1, 0x1

    .line 8
    invoke-direct {p0, p1}, Lkotlin/jvm/internal/n;-><init>(I)V

    .line 9
    .line 10
    .line 11
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 9

    .line 1
    iget v0, p0, Lw4/c;->f:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Lt3/y;

    .line 7
    .line 8
    iget-object v0, p0, Lw4/c;->h:Lv3/h0;

    .line 9
    .line 10
    iget-object p0, p0, Lw4/c;->g:Lw4/o;

    .line 11
    .line 12
    invoke-static {p0, v0}, Lw4/i;->d(Lw4/o;Lv3/h0;)V

    .line 13
    .line 14
    .line 15
    iget-object v0, p0, Lw4/g;->f:Lv3/o1;

    .line 16
    .line 17
    check-cast v0, Lw3/t;

    .line 18
    .line 19
    const/4 v1, 0x1

    .line 20
    iput-boolean v1, v0, Lw3/t;->D:Z

    .line 21
    .line 22
    iget-object v0, p0, Lw4/g;->q:[I

    .line 23
    .line 24
    const/4 v2, 0x0

    .line 25
    aget v3, v0, v2

    .line 26
    .line 27
    aget v4, v0, v1

    .line 28
    .line 29
    invoke-virtual {p0}, Lw4/g;->getView()Landroid/view/View;

    .line 30
    .line 31
    .line 32
    move-result-object v5

    .line 33
    invoke-virtual {v5, v0}, Landroid/view/View;->getLocationOnScreen([I)V

    .line 34
    .line 35
    .line 36
    iget-wide v5, p0, Lw4/g;->r:J

    .line 37
    .line 38
    invoke-interface {p1}, Lt3/y;->h()J

    .line 39
    .line 40
    .line 41
    move-result-wide v7

    .line 42
    iput-wide v7, p0, Lw4/g;->r:J

    .line 43
    .line 44
    iget-object p1, p0, Lw4/g;->s:Ld6/w1;

    .line 45
    .line 46
    if-eqz p1, :cond_1

    .line 47
    .line 48
    aget v2, v0, v2

    .line 49
    .line 50
    if-ne v3, v2, :cond_0

    .line 51
    .line 52
    aget v0, v0, v1

    .line 53
    .line 54
    if-ne v4, v0, :cond_0

    .line 55
    .line 56
    invoke-static {v5, v6, v7, v8}, Lt4/l;->a(JJ)Z

    .line 57
    .line 58
    .line 59
    move-result v0

    .line 60
    if-nez v0, :cond_1

    .line 61
    .line 62
    :cond_0
    invoke-virtual {p0, p1}, Lw4/g;->m(Ld6/w1;)Ld6/w1;

    .line 63
    .line 64
    .line 65
    move-result-object p1

    .line 66
    invoke-virtual {p1}, Ld6/w1;->g()Landroid/view/WindowInsets;

    .line 67
    .line 68
    .line 69
    move-result-object p1

    .line 70
    if-eqz p1, :cond_1

    .line 71
    .line 72
    invoke-virtual {p0}, Lw4/g;->getView()Landroid/view/View;

    .line 73
    .line 74
    .line 75
    move-result-object p0

    .line 76
    invoke-virtual {p0, p1}, Landroid/view/View;->dispatchApplyWindowInsets(Landroid/view/WindowInsets;)Landroid/view/WindowInsets;

    .line 77
    .line 78
    .line 79
    :cond_1
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 80
    .line 81
    return-object p0

    .line 82
    :pswitch_0
    check-cast p1, Lt3/d1;

    .line 83
    .line 84
    iget-object p1, p0, Lw4/c;->g:Lw4/o;

    .line 85
    .line 86
    iget-object p0, p0, Lw4/c;->h:Lv3/h0;

    .line 87
    .line 88
    invoke-static {p1, p0}, Lw4/i;->d(Lw4/o;Lv3/h0;)V

    .line 89
    .line 90
    .line 91
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 92
    .line 93
    return-object p0

    .line 94
    :pswitch_1
    check-cast p1, Lv3/o1;

    .line 95
    .line 96
    instance-of v0, p1, Lw3/t;

    .line 97
    .line 98
    if-eqz v0, :cond_2

    .line 99
    .line 100
    check-cast p1, Lw3/t;

    .line 101
    .line 102
    goto :goto_0

    .line 103
    :cond_2
    const/4 p1, 0x0

    .line 104
    :goto_0
    iget-object v0, p0, Lw4/c;->g:Lw4/o;

    .line 105
    .line 106
    if-eqz p1, :cond_3

    .line 107
    .line 108
    invoke-virtual {p1}, Lw3/t;->getAndroidViewsHandler$ui_release()Lw3/t0;

    .line 109
    .line 110
    .line 111
    move-result-object v1

    .line 112
    invoke-virtual {v1}, Lw3/t0;->getHolderToLayoutNode()Ljava/util/HashMap;

    .line 113
    .line 114
    .line 115
    move-result-object v1

    .line 116
    iget-object p0, p0, Lw4/c;->h:Lv3/h0;

    .line 117
    .line 118
    invoke-interface {v1, v0, p0}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 119
    .line 120
    .line 121
    invoke-virtual {p1}, Lw3/t;->getAndroidViewsHandler$ui_release()Lw3/t0;

    .line 122
    .line 123
    .line 124
    move-result-object v1

    .line 125
    invoke-virtual {v1, v0}, Landroid/view/ViewGroup;->addView(Landroid/view/View;)V

    .line 126
    .line 127
    .line 128
    invoke-virtual {p1}, Lw3/t;->getAndroidViewsHandler$ui_release()Lw3/t0;

    .line 129
    .line 130
    .line 131
    move-result-object v1

    .line 132
    invoke-virtual {v1}, Lw3/t0;->getLayoutNodeToHolder()Ljava/util/HashMap;

    .line 133
    .line 134
    .line 135
    move-result-object v1

    .line 136
    invoke-interface {v1, p0, v0}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 137
    .line 138
    .line 139
    const/4 v1, 0x1

    .line 140
    invoke-virtual {v0, v1}, Landroid/view/View;->setImportantForAccessibility(I)V

    .line 141
    .line 142
    .line 143
    new-instance v1, Lw3/n;

    .line 144
    .line 145
    invoke-direct {v1, p1, p0, p1}, Lw3/n;-><init>(Lw3/t;Lv3/h0;Lw3/t;)V

    .line 146
    .line 147
    .line 148
    invoke-static {v0, v1}, Ld6/r0;->i(Landroid/view/View;Ld6/b;)V

    .line 149
    .line 150
    .line 151
    :cond_3
    invoke-virtual {v0}, Lw4/g;->getView()Landroid/view/View;

    .line 152
    .line 153
    .line 154
    move-result-object p0

    .line 155
    invoke-virtual {p0}, Landroid/view/View;->getParent()Landroid/view/ViewParent;

    .line 156
    .line 157
    .line 158
    move-result-object p0

    .line 159
    if-eq p0, v0, :cond_4

    .line 160
    .line 161
    invoke-virtual {v0}, Lw4/g;->getView()Landroid/view/View;

    .line 162
    .line 163
    .line 164
    move-result-object p0

    .line 165
    invoke-virtual {v0, p0}, Landroid/view/ViewGroup;->addView(Landroid/view/View;)V

    .line 166
    .line 167
    .line 168
    :cond_4
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 169
    .line 170
    return-object p0

    .line 171
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
