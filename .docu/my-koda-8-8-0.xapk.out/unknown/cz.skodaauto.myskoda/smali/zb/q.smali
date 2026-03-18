.class public final Lzb/q;
.super Lb/t;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final g:Landroid/view/View;

.field public final h:Lzb/n;


# direct methods
.method public constructor <init>(Landroid/view/View;Lay0/a;Ljava/util/UUID;)V
    .locals 5

    .line 1
    const-string v0, "view"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "onBackPress"

    .line 7
    .line 8
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    invoke-virtual {p1}, Landroid/view/View;->getContext()Landroid/content/Context;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    const-string v1, "getContext(...)"

    .line 16
    .line 17
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 18
    .line 19
    .line 20
    const v2, 0x7f13012e

    .line 21
    .line 22
    .line 23
    invoke-direct {p0, v0, v2}, Lb/t;-><init>(Landroid/content/Context;I)V

    .line 24
    .line 25
    .line 26
    iput-object p1, p0, Lzb/q;->g:Landroid/view/View;

    .line 27
    .line 28
    invoke-virtual {p0}, Landroid/app/Dialog;->getWindow()Landroid/view/Window;

    .line 29
    .line 30
    .line 31
    move-result-object v0

    .line 32
    if-eqz v0, :cond_2

    .line 33
    .line 34
    const/4 v2, 0x1

    .line 35
    invoke-virtual {v0, v2}, Landroid/view/Window;->requestFeature(I)Z

    .line 36
    .line 37
    .line 38
    const v2, 0x106000d

    .line 39
    .line 40
    .line 41
    invoke-virtual {v0, v2}, Landroid/view/Window;->setBackgroundDrawableResource(I)V

    .line 42
    .line 43
    .line 44
    const/4 v3, 0x0

    .line 45
    invoke-virtual {v0, v3}, Landroid/view/Window;->setDimAmount(F)V

    .line 46
    .line 47
    .line 48
    const/high16 v3, -0x80000000

    .line 49
    .line 50
    invoke-virtual {v0, v3}, Landroid/view/Window;->addFlags(I)V

    .line 51
    .line 52
    .line 53
    const/16 v4, 0x200

    .line 54
    .line 55
    invoke-virtual {v0, v4}, Landroid/view/Window;->addFlags(I)V

    .line 56
    .line 57
    .line 58
    const/4 v4, -0x1

    .line 59
    invoke-virtual {v0, v4, v4}, Landroid/view/Window;->setLayout(II)V

    .line 60
    .line 61
    .line 62
    invoke-virtual {v0, v2}, Landroid/view/Window;->setBackgroundDrawableResource(I)V

    .line 63
    .line 64
    .line 65
    const/4 v2, 0x0

    .line 66
    invoke-virtual {v0, v2}, Landroid/view/Window;->setStatusBarColor(I)V

    .line 67
    .line 68
    .line 69
    invoke-virtual {v0, v2}, Landroid/view/Window;->setNavigationBarColor(I)V

    .line 70
    .line 71
    .line 72
    invoke-virtual {v0, v3}, Landroid/view/Window;->addFlags(I)V

    .line 73
    .line 74
    .line 75
    invoke-virtual {v0}, Landroid/view/Window;->getDecorView()Landroid/view/View;

    .line 76
    .line 77
    .line 78
    move-result-object v3

    .line 79
    instance-of v4, v3, Landroid/view/ViewGroup;

    .line 80
    .line 81
    if-eqz v4, :cond_0

    .line 82
    .line 83
    check-cast v3, Landroid/view/ViewGroup;

    .line 84
    .line 85
    goto :goto_0

    .line 86
    :cond_0
    const/4 v3, 0x0

    .line 87
    :goto_0
    if-eqz v3, :cond_1

    .line 88
    .line 89
    invoke-static {v3}, Lzb/q;->c(Landroid/view/ViewGroup;)V

    .line 90
    .line 91
    .line 92
    :cond_1
    invoke-virtual {v0, v2}, Landroid/view/Window;->setSoftInputMode(I)V

    .line 93
    .line 94
    .line 95
    invoke-virtual {v0, v2}, Landroid/view/Window;->setNavigationBarContrastEnforced(Z)V

    .line 96
    .line 97
    .line 98
    invoke-static {v0, v2}, Ljp/pf;->b(Landroid/view/Window;Z)V

    .line 99
    .line 100
    .line 101
    invoke-virtual {p0}, Landroid/app/Dialog;->getContext()Landroid/content/Context;

    .line 102
    .line 103
    .line 104
    move-result-object v2

    .line 105
    invoke-static {v2, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 106
    .line 107
    .line 108
    new-instance v1, Lzb/n;

    .line 109
    .line 110
    invoke-direct {v1, v2, p3, v0}, Lzb/n;-><init>(Landroid/content/Context;Ljava/util/UUID;Landroid/view/Window;)V

    .line 111
    .line 112
    .line 113
    iput-object v1, p0, Lzb/q;->h:Lzb/n;

    .line 114
    .line 115
    invoke-static {p1}, Landroidx/lifecycle/v0;->d(Landroid/view/View;)Landroidx/lifecycle/x;

    .line 116
    .line 117
    .line 118
    move-result-object p3

    .line 119
    invoke-static {v1, p3}, Landroidx/lifecycle/v0;->l(Landroid/view/View;Landroidx/lifecycle/x;)V

    .line 120
    .line 121
    .line 122
    invoke-static {p1}, Landroidx/lifecycle/v0;->e(Landroid/view/View;)Landroidx/lifecycle/i1;

    .line 123
    .line 124
    .line 125
    move-result-object p3

    .line 126
    invoke-static {v1, p3}, Landroidx/lifecycle/v0;->m(Landroid/view/View;Landroidx/lifecycle/i1;)V

    .line 127
    .line 128
    .line 129
    invoke-static {p1}, Lkp/w;->b(Landroid/view/View;)Lra/f;

    .line 130
    .line 131
    .line 132
    move-result-object p1

    .line 133
    invoke-static {v1, p1}, Lkp/w;->d(Landroid/view/View;Lra/f;)V

    .line 134
    .line 135
    .line 136
    invoke-virtual {p0, v1}, Lb/t;->setContentView(Landroid/view/View;)V

    .line 137
    .line 138
    .line 139
    iget-object p1, p0, Lb/t;->f:Lb/h0;

    .line 140
    .line 141
    new-instance p3, Lvo0/g;

    .line 142
    .line 143
    const/16 v0, 0x1b

    .line 144
    .line 145
    invoke-direct {p3, p2, v0}, Lvo0/g;-><init>(Lay0/a;I)V

    .line 146
    .line 147
    .line 148
    invoke-static {p1, p0, p3}, Ljp/t1;->e(Lb/h0;Lb/t;Lay0/k;)V

    .line 149
    .line 150
    .line 151
    return-void

    .line 152
    :cond_2
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 153
    .line 154
    const-string p1, "Dialog has no window"

    .line 155
    .line 156
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 157
    .line 158
    .line 159
    throw p0
.end method

.method public static c(Landroid/view/ViewGroup;)V
    .locals 4

    .line 1
    const/4 v0, 0x0

    .line 2
    invoke-virtual {p0, v0}, Landroid/view/ViewGroup;->setClipChildren(Z)V

    .line 3
    .line 4
    .line 5
    instance-of v1, p0, Lzb/n;

    .line 6
    .line 7
    if-eqz v1, :cond_0

    .line 8
    .line 9
    goto :goto_2

    .line 10
    :cond_0
    invoke-virtual {p0}, Landroid/view/ViewGroup;->getChildCount()I

    .line 11
    .line 12
    .line 13
    move-result v1

    .line 14
    :goto_0
    if-ge v0, v1, :cond_3

    .line 15
    .line 16
    invoke-virtual {p0, v0}, Landroid/view/ViewGroup;->getChildAt(I)Landroid/view/View;

    .line 17
    .line 18
    .line 19
    move-result-object v2

    .line 20
    instance-of v3, v2, Landroid/view/ViewGroup;

    .line 21
    .line 22
    if-eqz v3, :cond_1

    .line 23
    .line 24
    check-cast v2, Landroid/view/ViewGroup;

    .line 25
    .line 26
    goto :goto_1

    .line 27
    :cond_1
    const/4 v2, 0x0

    .line 28
    :goto_1
    if-eqz v2, :cond_2

    .line 29
    .line 30
    invoke-static {v2}, Lzb/q;->c(Landroid/view/ViewGroup;)V

    .line 31
    .line 32
    .line 33
    :cond_2
    add-int/lit8 v0, v0, 0x1

    .line 34
    .line 35
    goto :goto_0

    .line 36
    :cond_3
    :goto_2
    return-void
.end method


# virtual methods
.method public final cancel()V
    .locals 0

    .line 1
    return-void
.end method
