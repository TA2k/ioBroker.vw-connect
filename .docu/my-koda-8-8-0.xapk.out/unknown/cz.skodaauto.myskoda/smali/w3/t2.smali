.class public abstract Lw3/t2;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Landroid/view/ViewGroup$LayoutParams;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Landroid/view/ViewGroup$LayoutParams;

    .line 2
    .line 3
    const/4 v1, -0x2

    .line 4
    invoke-direct {v0, v1, v1}, Landroid/view/ViewGroup$LayoutParams;-><init>(II)V

    .line 5
    .line 6
    .line 7
    sput-object v0, Lw3/t2;->a:Landroid/view/ViewGroup$LayoutParams;

    .line 8
    .line 9
    return-void
.end method

.method public static final a(Lw3/a;Ll2/x;Lt2/b;)Lw3/s2;
    .locals 6

    .line 1
    sget-object v0, Lw3/n1;->a:Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    const/4 v2, 0x1

    .line 5
    invoke-virtual {v0, v1, v2}, Ljava/util/concurrent/atomic/AtomicBoolean;->compareAndSet(ZZ)Z

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    const/4 v3, 0x0

    .line 10
    if-eqz v0, :cond_0

    .line 11
    .line 12
    const/4 v0, 0x6

    .line 13
    invoke-static {v2, v0, v3}, Llp/jf;->a(IILxy0/a;)Lxy0/j;

    .line 14
    .line 15
    .line 16
    move-result-object v0

    .line 17
    sget-object v2, Lw3/p0;->o:Llx0/q;

    .line 18
    .line 19
    invoke-virtual {v2}, Llx0/q;->getValue()Ljava/lang/Object;

    .line 20
    .line 21
    .line 22
    move-result-object v2

    .line 23
    check-cast v2, Lpx0/g;

    .line 24
    .line 25
    invoke-static {v2}, Lvy0/e0;->c(Lpx0/g;)Lpw0/a;

    .line 26
    .line 27
    .line 28
    move-result-object v2

    .line 29
    new-instance v4, Ltr0/e;

    .line 30
    .line 31
    const/16 v5, 0x18

    .line 32
    .line 33
    invoke-direct {v4, v0, v3, v5}, Ltr0/e;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 34
    .line 35
    .line 36
    const/4 v5, 0x3

    .line 37
    invoke-static {v2, v3, v3, v4, v5}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 38
    .line 39
    .line 40
    new-instance v2, Lw3/a0;

    .line 41
    .line 42
    const/4 v4, 0x3

    .line 43
    invoke-direct {v2, v0, v4}, Lw3/a0;-><init>(Ljava/lang/Object;I)V

    .line 44
    .line 45
    .line 46
    sget-object v0, Lv2/l;->c:Ljava/lang/Object;

    .line 47
    .line 48
    monitor-enter v0

    .line 49
    :try_start_0
    sget-object v4, Lv2/l;->i:Ljava/lang/Object;

    .line 50
    .line 51
    check-cast v4, Ljava/util/Collection;

    .line 52
    .line 53
    invoke-static {v4, v2}, Lmx0/q;->b0(Ljava/util/Collection;Ljava/lang/Object;)Ljava/util/ArrayList;

    .line 54
    .line 55
    .line 56
    move-result-object v2

    .line 57
    sput-object v2, Lv2/l;->i:Ljava/lang/Object;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 58
    .line 59
    monitor-exit v0

    .line 60
    invoke-static {}, Lv2/l;->a()V

    .line 61
    .line 62
    .line 63
    goto :goto_0

    .line 64
    :catchall_0
    move-exception p0

    .line 65
    monitor-exit v0

    .line 66
    throw p0

    .line 67
    :cond_0
    :goto_0
    invoke-virtual {p0}, Landroid/view/ViewGroup;->getChildCount()I

    .line 68
    .line 69
    .line 70
    move-result v0

    .line 71
    if-lez v0, :cond_2

    .line 72
    .line 73
    invoke-virtual {p0, v1}, Landroid/view/ViewGroup;->getChildAt(I)Landroid/view/View;

    .line 74
    .line 75
    .line 76
    move-result-object v0

    .line 77
    instance-of v1, v0, Lw3/t;

    .line 78
    .line 79
    if-eqz v1, :cond_1

    .line 80
    .line 81
    check-cast v0, Lw3/t;

    .line 82
    .line 83
    goto :goto_2

    .line 84
    :cond_1
    :goto_1
    move-object v0, v3

    .line 85
    goto :goto_2

    .line 86
    :cond_2
    invoke-virtual {p0}, Landroid/view/ViewGroup;->removeAllViews()V

    .line 87
    .line 88
    .line 89
    goto :goto_1

    .line 90
    :goto_2
    if-nez v0, :cond_3

    .line 91
    .line 92
    new-instance v0, Lw3/t;

    .line 93
    .line 94
    invoke-virtual {p0}, Landroid/view/View;->getContext()Landroid/content/Context;

    .line 95
    .line 96
    .line 97
    move-result-object v1

    .line 98
    invoke-virtual {p1}, Ll2/x;->j()Lpx0/g;

    .line 99
    .line 100
    .line 101
    move-result-object v2

    .line 102
    invoke-direct {v0, v1, v2}, Lw3/t;-><init>(Landroid/content/Context;Lpx0/g;)V

    .line 103
    .line 104
    .line 105
    invoke-virtual {v0}, Lw3/t;->getView()Landroid/view/View;

    .line 106
    .line 107
    .line 108
    move-result-object v1

    .line 109
    sget-object v2, Lw3/t2;->a:Landroid/view/ViewGroup$LayoutParams;

    .line 110
    .line 111
    invoke-virtual {p0, v1, v2}, Lw3/a;->addView(Landroid/view/View;Landroid/view/ViewGroup$LayoutParams;)V

    .line 112
    .line 113
    .line 114
    :cond_3
    invoke-virtual {v0}, Lw3/t;->getView()Landroid/view/View;

    .line 115
    .line 116
    .line 117
    move-result-object p0

    .line 118
    const v1, 0x7f0a0313

    .line 119
    .line 120
    .line 121
    invoke-virtual {p0, v1}, Landroid/view/View;->getTag(I)Ljava/lang/Object;

    .line 122
    .line 123
    .line 124
    move-result-object p0

    .line 125
    instance-of v2, p0, Lw3/s2;

    .line 126
    .line 127
    if-eqz v2, :cond_4

    .line 128
    .line 129
    move-object v3, p0

    .line 130
    check-cast v3, Lw3/s2;

    .line 131
    .line 132
    :cond_4
    if-nez v3, :cond_5

    .line 133
    .line 134
    new-instance v3, Lw3/s2;

    .line 135
    .line 136
    new-instance p0, Lv3/d2;

    .line 137
    .line 138
    invoke-virtual {v0}, Lw3/t;->getRoot()Lv3/h0;

    .line 139
    .line 140
    .line 141
    move-result-object v2

    .line 142
    invoke-direct {p0, v2}, Leb/j0;-><init>(Ljava/lang/Object;)V

    .line 143
    .line 144
    .line 145
    new-instance v2, Ll2/a0;

    .line 146
    .line 147
    invoke-direct {v2, p1, p0}, Ll2/a0;-><init>(Ll2/x;Leb/j0;)V

    .line 148
    .line 149
    .line 150
    invoke-direct {v3, v0, v2}, Lw3/s2;-><init>(Lw3/t;Ll2/a0;)V

    .line 151
    .line 152
    .line 153
    invoke-virtual {v0}, Lw3/t;->getView()Landroid/view/View;

    .line 154
    .line 155
    .line 156
    move-result-object p0

    .line 157
    invoke-virtual {p0, v1, v3}, Landroid/view/View;->setTag(ILjava/lang/Object;)V

    .line 158
    .line 159
    .line 160
    :cond_5
    invoke-virtual {v3, p2}, Lw3/s2;->a(Lay0/n;)V

    .line 161
    .line 162
    .line 163
    invoke-virtual {v0}, Lw3/t;->getCoroutineContext()Lpx0/g;

    .line 164
    .line 165
    .line 166
    move-result-object p0

    .line 167
    invoke-virtual {p1}, Ll2/x;->j()Lpx0/g;

    .line 168
    .line 169
    .line 170
    move-result-object p2

    .line 171
    invoke-static {p0, p2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 172
    .line 173
    .line 174
    move-result p0

    .line 175
    if-nez p0, :cond_6

    .line 176
    .line 177
    invoke-virtual {p1}, Ll2/x;->j()Lpx0/g;

    .line 178
    .line 179
    .line 180
    move-result-object p0

    .line 181
    invoke-virtual {v0, p0}, Lw3/t;->setCoroutineContext(Lpx0/g;)V

    .line 182
    .line 183
    .line 184
    :cond_6
    return-object v3
.end method
