.class public final Lw3/o2;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Landroidx/lifecycle/v;


# instance fields
.field public final synthetic d:Lpw0/a;

.field public final synthetic e:Ll2/l1;

.field public final synthetic f:Ll2/y1;

.field public final synthetic g:Lkotlin/jvm/internal/f0;

.field public final synthetic h:Landroid/view/View;


# direct methods
.method public constructor <init>(Lpw0/a;Ll2/l1;Ll2/y1;Lkotlin/jvm/internal/f0;Landroid/view/View;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lw3/o2;->d:Lpw0/a;

    .line 5
    .line 6
    iput-object p2, p0, Lw3/o2;->e:Ll2/l1;

    .line 7
    .line 8
    iput-object p3, p0, Lw3/o2;->f:Ll2/y1;

    .line 9
    .line 10
    iput-object p4, p0, Lw3/o2;->g:Lkotlin/jvm/internal/f0;

    .line 11
    .line 12
    iput-object p5, p0, Lw3/o2;->h:Landroid/view/View;

    .line 13
    .line 14
    return-void
.end method


# virtual methods
.method public final f(Landroidx/lifecycle/x;Landroidx/lifecycle/p;)V
    .locals 11

    .line 1
    sget-object v0, Lw3/n2;->a:[I

    .line 2
    .line 3
    invoke-virtual {p2}, Ljava/lang/Enum;->ordinal()I

    .line 4
    .line 5
    .line 6
    move-result p2

    .line 7
    aget p2, v0, p2

    .line 8
    .line 9
    const/4 v0, 0x0

    .line 10
    const/4 v1, 0x1

    .line 11
    packed-switch p2, :pswitch_data_0

    .line 12
    .line 13
    .line 14
    new-instance p0, La8/r0;

    .line 15
    .line 16
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 17
    .line 18
    .line 19
    throw p0

    .line 20
    :pswitch_0
    iget-object p0, p0, Lw3/o2;->f:Ll2/y1;

    .line 21
    .line 22
    invoke-virtual {p0}, Ll2/y1;->v()V

    .line 23
    .line 24
    .line 25
    return-void

    .line 26
    :pswitch_1
    iget-object p0, p0, Lw3/o2;->f:Ll2/y1;

    .line 27
    .line 28
    iget-object p1, p0, Ll2/y1;->c:Ljava/lang/Object;

    .line 29
    .line 30
    monitor-enter p1

    .line 31
    :try_start_0
    iput-boolean v1, p0, Ll2/y1;->t:Z
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 32
    .line 33
    monitor-exit p1

    .line 34
    return-void

    .line 35
    :catchall_0
    move-exception v0

    .line 36
    move-object p0, v0

    .line 37
    monitor-exit p1

    .line 38
    throw p0

    .line 39
    :pswitch_2
    iget-object p1, p0, Lw3/o2;->e:Ll2/l1;

    .line 40
    .line 41
    const/4 p2, 0x0

    .line 42
    if-eqz p1, :cond_2

    .line 43
    .line 44
    iget-object p1, p1, Ll2/l1;->f:Ljava/lang/Object;

    .line 45
    .line 46
    check-cast p1, La8/b;

    .line 47
    .line 48
    iget-object v2, p1, La8/b;->f:Ljava/lang/Object;

    .line 49
    .line 50
    monitor-enter v2

    .line 51
    :try_start_1
    iget-object v3, p1, La8/b;->f:Ljava/lang/Object;

    .line 52
    .line 53
    monitor-enter v3
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 54
    :try_start_2
    iget-boolean v4, p1, La8/b;->e:Z
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_2

    .line 55
    .line 56
    :try_start_3
    monitor-exit v3
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_1

    .line 57
    if-eqz v4, :cond_0

    .line 58
    .line 59
    monitor-exit v2

    .line 60
    goto :goto_2

    .line 61
    :cond_0
    :try_start_4
    iget-object v3, p1, La8/b;->g:Ljava/lang/Object;

    .line 62
    .line 63
    check-cast v3, Ljava/util/ArrayList;

    .line 64
    .line 65
    iget-object v4, p1, La8/b;->h:Ljava/lang/Object;

    .line 66
    .line 67
    check-cast v4, Ljava/util/ArrayList;

    .line 68
    .line 69
    iput-object v4, p1, La8/b;->g:Ljava/lang/Object;

    .line 70
    .line 71
    iput-object v3, p1, La8/b;->h:Ljava/lang/Object;

    .line 72
    .line 73
    iput-boolean v1, p1, La8/b;->e:Z

    .line 74
    .line 75
    invoke-virtual {v3}, Ljava/util/ArrayList;->size()I

    .line 76
    .line 77
    .line 78
    move-result p1

    .line 79
    move v1, p2

    .line 80
    :goto_0
    if-ge v1, p1, :cond_1

    .line 81
    .line 82
    invoke-virtual {v3, v1}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 83
    .line 84
    .line 85
    move-result-object v4

    .line 86
    check-cast v4, Lkotlin/coroutines/Continuation;

    .line 87
    .line 88
    sget-object v5, Llx0/b0;->a:Llx0/b0;

    .line 89
    .line 90
    invoke-interface {v4, v5}, Lkotlin/coroutines/Continuation;->resumeWith(Ljava/lang/Object;)V

    .line 91
    .line 92
    .line 93
    add-int/lit8 v1, v1, 0x1

    .line 94
    .line 95
    goto :goto_0

    .line 96
    :catchall_1
    move-exception v0

    .line 97
    move-object p0, v0

    .line 98
    goto :goto_1

    .line 99
    :cond_1
    invoke-virtual {v3}, Ljava/util/ArrayList;->clear()V
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_1

    .line 100
    .line 101
    .line 102
    monitor-exit v2

    .line 103
    goto :goto_2

    .line 104
    :catchall_2
    move-exception v0

    .line 105
    move-object p0, v0

    .line 106
    :try_start_5
    monitor-exit v3

    .line 107
    throw p0
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_1

    .line 108
    :goto_1
    monitor-exit v2

    .line 109
    throw p0

    .line 110
    :cond_2
    :goto_2
    iget-object p0, p0, Lw3/o2;->f:Ll2/y1;

    .line 111
    .line 112
    iget-object p1, p0, Ll2/y1;->c:Ljava/lang/Object;

    .line 113
    .line 114
    monitor-enter p1

    .line 115
    :try_start_6
    iget-boolean v1, p0, Ll2/y1;->t:Z

    .line 116
    .line 117
    if-eqz v1, :cond_3

    .line 118
    .line 119
    iput-boolean p2, p0, Ll2/y1;->t:Z

    .line 120
    .line 121
    invoke-virtual {p0}, Ll2/y1;->w()Lvy0/k;

    .line 122
    .line 123
    .line 124
    move-result-object v0
    :try_end_6
    .catchall {:try_start_6 .. :try_end_6} :catchall_3

    .line 125
    goto :goto_3

    .line 126
    :catchall_3
    move-exception v0

    .line 127
    move-object p0, v0

    .line 128
    goto :goto_4

    .line 129
    :cond_3
    :goto_3
    monitor-exit p1

    .line 130
    if-eqz v0, :cond_4

    .line 131
    .line 132
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 133
    .line 134
    check-cast v0, Lvy0/l;

    .line 135
    .line 136
    invoke-virtual {v0, p0}, Lvy0/l;->resumeWith(Ljava/lang/Object;)V

    .line 137
    .line 138
    .line 139
    :cond_4
    :pswitch_3
    return-void

    .line 140
    :goto_4
    monitor-exit p1

    .line 141
    throw p0

    .line 142
    :pswitch_4
    iget-object p2, p0, Lw3/o2;->d:Lpw0/a;

    .line 143
    .line 144
    sget-object v2, Lvy0/c0;->g:Lvy0/c0;

    .line 145
    .line 146
    new-instance v3, La7/k0;

    .line 147
    .line 148
    iget-object v4, p0, Lw3/o2;->g:Lkotlin/jvm/internal/f0;

    .line 149
    .line 150
    iget-object v5, p0, Lw3/o2;->f:Ll2/y1;

    .line 151
    .line 152
    iget-object v8, p0, Lw3/o2;->h:Landroid/view/View;

    .line 153
    .line 154
    const/4 v9, 0x0

    .line 155
    const/16 v10, 0xa

    .line 156
    .line 157
    move-object v7, p0

    .line 158
    move-object v6, p1

    .line 159
    invoke-direct/range {v3 .. v10}, La7/k0;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 160
    .line 161
    .line 162
    invoke-static {p2, v0, v2, v3, v1}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 163
    .line 164
    .line 165
    return-void

    .line 166
    nop

    .line 167
    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_4
        :pswitch_2
        :pswitch_1
        :pswitch_0
        :pswitch_3
        :pswitch_3
        :pswitch_3
    .end packed-switch
.end method
