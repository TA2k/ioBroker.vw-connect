.class public abstract Lh/w;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final synthetic a:I

.field public b:Ljava/lang/Object;

.field public c:Ljava/lang/Object;


# direct methods
.method public constructor <init>(I)V
    .locals 1

    iput p1, p0, Lh/w;->a:I

    sparse-switch p1, :sswitch_data_0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void

    .line 21
    :sswitch_0
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    const/4 p1, 0x2

    .line 22
    new-array p1, p1, [I

    iput-object p1, p0, Lh/w;->c:Ljava/lang/Object;

    return-void

    .line 23
    :sswitch_1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 24
    new-instance p1, Lnz/k;

    const/16 v0, 0x14

    invoke-direct {p1, v0}, Lnz/k;-><init>(I)V

    invoke-static {p1}, Lpm/a;->d(Lay0/a;)Llx0/q;

    move-result-object p1

    iput-object p1, p0, Lh/w;->b:Ljava/lang/Object;

    .line 25
    invoke-virtual {p1}, Llx0/q;->getValue()Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Lx11/a;

    .line 26
    iget-object p1, p1, Lx11/a;->a:Landroidx/lifecycle/c1;

    .line 27
    iput-object p1, p0, Lh/w;->c:Ljava/lang/Object;

    return-void

    nop

    :sswitch_data_0
    .sparse-switch
        0x5 -> :sswitch_1
        0x8 -> :sswitch_0
    .end sparse-switch
.end method

.method public constructor <init>(Landroid/content/Context;)V
    .locals 1

    const/4 v0, 0x2

    iput v0, p0, Lh/w;->a:I

    .line 12
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 13
    iput-object p1, p0, Lh/w;->b:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Landroid/content/Context;Llp/ta;)V
    .locals 1

    const/4 v0, 0x7

    iput v0, p0, Lh/w;->a:I

    .line 18
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 19
    const-string v0, "camera"

    invoke-virtual {p1, v0}, Landroid/content/Context;->getSystemService(Ljava/lang/String;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Landroid/hardware/camera2/CameraManager;

    iput-object p1, p0, Lh/w;->b:Ljava/lang/Object;

    .line 20
    iput-object p2, p0, Lh/w;->c:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Landroid/hardware/camera2/CameraDevice;Llp/sa;)V
    .locals 1

    const/4 v0, 0x6

    iput v0, p0, Lh/w;->a:I

    .line 14
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 15
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 16
    iput-object p1, p0, Lh/w;->b:Ljava/lang/Object;

    .line 17
    iput-object p2, p0, Lh/w;->c:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Lh/z;)V
    .locals 1

    const/4 v0, 0x0

    iput v0, p0, Lh/w;->a:I

    .line 28
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lh/w;->c:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Ljava/lang/String;Landroid/graphics/Rect;Ljava/util/List;Ljava/lang/String;)V
    .locals 2

    const/4 v0, 0x3

    iput v0, p0, Lh/w;->a:I

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lh/w;->b:Ljava/lang/Object;

    new-instance p1, Landroid/graphics/Rect;

    invoke-direct {p1, p2}, Landroid/graphics/Rect;-><init>(Landroid/graphics/Rect;)V

    .line 2
    invoke-interface {p3}, Ljava/util/List;->size()I

    move-result p1

    new-array p1, p1, [Landroid/graphics/Point;

    const/4 p2, 0x0

    .line 3
    :goto_0
    invoke-interface {p3}, Ljava/util/List;->size()I

    move-result v0

    if-ge p2, v0, :cond_0

    new-instance v0, Landroid/graphics/Point;

    .line 4
    invoke-interface {p3, p2}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Landroid/graphics/Point;

    invoke-direct {v0, v1}, Landroid/graphics/Point;-><init>(Landroid/graphics/Point;)V

    aput-object v0, p1, p2

    add-int/lit8 p2, p2, 0x1

    goto :goto_0

    .line 5
    :cond_0
    iput-object p4, p0, Lh/w;->c:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Ljava/lang/String;Ljava/util/List;)V
    .locals 1

    const/4 v0, 0x4

    iput v0, p0, Lh/w;->a:I

    const-string v0, "content"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "parameters"

    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 10
    iput-object p1, p0, Lh/w;->b:Ljava/lang/Object;

    .line 11
    iput-object p2, p0, Lh/w;->c:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Lz81/s;Lz81/c;)V
    .locals 1

    const/16 v0, 0x9

    iput v0, p0, Lh/w;->a:I

    .line 6
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 7
    iput-object p1, p0, Lh/w;->b:Ljava/lang/Object;

    .line 8
    iput-object p2, p0, Lh/w;->c:Ljava/lang/Object;

    return-void
.end method


# virtual methods
.method public c()V
    .locals 2

    .line 1
    iget-object v0, p0, Lh/w;->b:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Lc8/e;

    .line 4
    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    :try_start_0
    iget-object v1, p0, Lh/w;->c:Ljava/lang/Object;

    .line 8
    .line 9
    check-cast v1, Lh/z;

    .line 10
    .line 11
    iget-object v1, v1, Lh/z;->n:Landroid/content/Context;

    .line 12
    .line 13
    invoke-virtual {v1, v0}, Landroid/content/Context;->unregisterReceiver(Landroid/content/BroadcastReceiver;)V
    :try_end_0
    .catch Ljava/lang/IllegalArgumentException; {:try_start_0 .. :try_end_0} :catch_0

    .line 14
    .line 15
    .line 16
    :catch_0
    const/4 v0, 0x0

    .line 17
    iput-object v0, p0, Lh/w;->b:Ljava/lang/Object;

    .line 18
    .line 19
    :cond_0
    return-void
.end method

.method public abstract d()Landroid/content/IntentFilter;
.end method

.method public abstract e(I)[I
.end method

.method public abstract f()I
.end method

.method public g()Ljava/util/Set;
    .locals 0

    .line 1
    sget-object p0, Ljava/util/Collections;->EMPTY_SET:Ljava/util/Set;

    .line 2
    .line 3
    return-object p0
.end method

.method public h(Landroid/view/MenuItem;)Landroid/view/MenuItem;
    .locals 2

    .line 1
    instance-of v0, p1, Lv5/a;

    .line 2
    .line 3
    if-eqz v0, :cond_2

    .line 4
    .line 5
    check-cast p1, Lv5/a;

    .line 6
    .line 7
    iget-object v0, p0, Lh/w;->c:Ljava/lang/Object;

    .line 8
    .line 9
    check-cast v0, Landroidx/collection/a1;

    .line 10
    .line 11
    if-nez v0, :cond_0

    .line 12
    .line 13
    new-instance v0, Landroidx/collection/a1;

    .line 14
    .line 15
    const/4 v1, 0x0

    .line 16
    invoke-direct {v0, v1}, Landroidx/collection/a1;-><init>(I)V

    .line 17
    .line 18
    .line 19
    iput-object v0, p0, Lh/w;->c:Ljava/lang/Object;

    .line 20
    .line 21
    :cond_0
    iget-object v0, p0, Lh/w;->c:Ljava/lang/Object;

    .line 22
    .line 23
    check-cast v0, Landroidx/collection/a1;

    .line 24
    .line 25
    invoke-virtual {v0, p1}, Landroidx/collection/a1;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 26
    .line 27
    .line 28
    move-result-object v0

    .line 29
    check-cast v0, Landroid/view/MenuItem;

    .line 30
    .line 31
    if-nez v0, :cond_1

    .line 32
    .line 33
    new-instance v0, Ll/s;

    .line 34
    .line 35
    iget-object v1, p0, Lh/w;->b:Ljava/lang/Object;

    .line 36
    .line 37
    check-cast v1, Landroid/content/Context;

    .line 38
    .line 39
    invoke-direct {v0, v1, p1}, Ll/s;-><init>(Landroid/content/Context;Lv5/a;)V

    .line 40
    .line 41
    .line 42
    iget-object p0, p0, Lh/w;->c:Ljava/lang/Object;

    .line 43
    .line 44
    check-cast p0, Landroidx/collection/a1;

    .line 45
    .line 46
    invoke-virtual {p0, p1, v0}, Landroidx/collection/a1;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 47
    .line 48
    .line 49
    :cond_1
    return-object v0

    .line 50
    :cond_2
    return-object p1
.end method

.method public i(II)[I
    .locals 1

    .line 1
    if-ltz p1, :cond_1

    .line 2
    .line 3
    if-ltz p2, :cond_1

    .line 4
    .line 5
    if-ne p1, p2, :cond_0

    .line 6
    .line 7
    goto :goto_0

    .line 8
    :cond_0
    iget-object p0, p0, Lh/w;->c:Ljava/lang/Object;

    .line 9
    .line 10
    check-cast p0, [I

    .line 11
    .line 12
    const/4 v0, 0x0

    .line 13
    aput p1, p0, v0

    .line 14
    .line 15
    const/4 p1, 0x1

    .line 16
    aput p2, p0, p1

    .line 17
    .line 18
    return-object p0

    .line 19
    :cond_1
    :goto_0
    const/4 p0, 0x0

    .line 20
    return-object p0
.end method

.method public j()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lh/w;->b:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Ljava/lang/String;

    .line 4
    .line 5
    if-eqz p0, :cond_0

    .line 6
    .line 7
    return-object p0

    .line 8
    :cond_0
    const-string p0, "text"

    .line 9
    .line 10
    invoke-static {p0}, Lkotlin/jvm/internal/m;->n(Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    const/4 p0, 0x0

    .line 14
    throw p0
.end method

.method public abstract k()V
.end method

.method public l(Ljava/lang/String;)Ljava/lang/String;
    .locals 5

    .line 1
    const-string v0, "name"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lh/w;->c:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast p0, Ljava/util/List;

    .line 9
    .line 10
    invoke-static {p0}, Ljp/k1;->h(Ljava/util/List;)I

    .line 11
    .line 12
    .line 13
    move-result v0

    .line 14
    if-ltz v0, :cond_1

    .line 15
    .line 16
    const/4 v1, 0x0

    .line 17
    :goto_0
    invoke-interface {p0, v1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 18
    .line 19
    .line 20
    move-result-object v2

    .line 21
    check-cast v2, Low0/j;

    .line 22
    .line 23
    iget-object v3, v2, Low0/j;->a:Ljava/lang/String;

    .line 24
    .line 25
    const/4 v4, 0x1

    .line 26
    invoke-static {v3, p1, v4}, Lly0/w;->p(Ljava/lang/String;Ljava/lang/String;Z)Z

    .line 27
    .line 28
    .line 29
    move-result v3

    .line 30
    if-eqz v3, :cond_0

    .line 31
    .line 32
    iget-object p0, v2, Low0/j;->b:Ljava/lang/String;

    .line 33
    .line 34
    return-object p0

    .line 35
    :cond_0
    if-eq v1, v0, :cond_1

    .line 36
    .line 37
    add-int/lit8 v1, v1, 0x1

    .line 38
    .line 39
    goto :goto_0

    .line 40
    :cond_1
    const/4 p0, 0x0

    .line 41
    return-object p0
.end method

.method public abstract m(I)[I
.end method

.method public abstract n()V
.end method

.method public abstract o(Lt7/u0;)V
.end method

.method public p()V
    .locals 3

    .line 1
    invoke-virtual {p0}, Lh/w;->c()V

    .line 2
    .line 3
    .line 4
    invoke-virtual {p0}, Lh/w;->d()Landroid/content/IntentFilter;

    .line 5
    .line 6
    .line 7
    move-result-object v0

    .line 8
    invoke-virtual {v0}, Landroid/content/IntentFilter;->countActions()I

    .line 9
    .line 10
    .line 11
    move-result v1

    .line 12
    if-nez v1, :cond_0

    .line 13
    .line 14
    return-void

    .line 15
    :cond_0
    iget-object v1, p0, Lh/w;->b:Ljava/lang/Object;

    .line 16
    .line 17
    check-cast v1, Lc8/e;

    .line 18
    .line 19
    if-nez v1, :cond_1

    .line 20
    .line 21
    new-instance v1, Lc8/e;

    .line 22
    .line 23
    const/4 v2, 0x1

    .line 24
    invoke-direct {v1, p0, v2}, Lc8/e;-><init>(Ljava/lang/Object;I)V

    .line 25
    .line 26
    .line 27
    iput-object v1, p0, Lh/w;->b:Ljava/lang/Object;

    .line 28
    .line 29
    :cond_1
    iget-object v1, p0, Lh/w;->c:Ljava/lang/Object;

    .line 30
    .line 31
    check-cast v1, Lh/z;

    .line 32
    .line 33
    iget-object v1, v1, Lh/z;->n:Landroid/content/Context;

    .line 34
    .line 35
    iget-object p0, p0, Lh/w;->b:Ljava/lang/Object;

    .line 36
    .line 37
    check-cast p0, Lc8/e;

    .line 38
    .line 39
    invoke-virtual {v1, p0, v0}, Landroid/content/Context;->registerReceiver(Landroid/content/BroadcastReceiver;Landroid/content/IntentFilter;)Landroid/content/Intent;

    .line 40
    .line 41
    .line 42
    return-void
.end method

.method public toString()Ljava/lang/String;
    .locals 13

    .line 1
    iget v0, p0, Lh/w;->a:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-super {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    return-object p0

    .line 11
    :pswitch_0
    iget-object v0, p0, Lh/w;->b:Ljava/lang/Object;

    .line 12
    .line 13
    check-cast v0, Ljava/lang/String;

    .line 14
    .line 15
    iget-object p0, p0, Lh/w;->c:Ljava/lang/Object;

    .line 16
    .line 17
    check-cast p0, Ljava/util/List;

    .line 18
    .line 19
    invoke-interface {p0}, Ljava/util/List;->isEmpty()Z

    .line 20
    .line 21
    .line 22
    move-result v1

    .line 23
    if-eqz v1, :cond_0

    .line 24
    .line 25
    goto/16 :goto_a

    .line 26
    .line 27
    :cond_0
    invoke-virtual {v0}, Ljava/lang/String;->length()I

    .line 28
    .line 29
    .line 30
    move-result v1

    .line 31
    move-object v2, p0

    .line 32
    check-cast v2, Ljava/lang/Iterable;

    .line 33
    .line 34
    invoke-interface {v2}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 35
    .line 36
    .line 37
    move-result-object v2

    .line 38
    const/4 v3, 0x0

    .line 39
    move v4, v3

    .line 40
    :goto_0
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    .line 41
    .line 42
    .line 43
    move-result v5

    .line 44
    if-eqz v5, :cond_1

    .line 45
    .line 46
    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 47
    .line 48
    .line 49
    move-result-object v5

    .line 50
    check-cast v5, Low0/j;

    .line 51
    .line 52
    iget-object v6, v5, Low0/j;->a:Ljava/lang/String;

    .line 53
    .line 54
    invoke-virtual {v6}, Ljava/lang/String;->length()I

    .line 55
    .line 56
    .line 57
    move-result v6

    .line 58
    iget-object v5, v5, Low0/j;->b:Ljava/lang/String;

    .line 59
    .line 60
    invoke-virtual {v5}, Ljava/lang/String;->length()I

    .line 61
    .line 62
    .line 63
    move-result v5

    .line 64
    add-int/2addr v5, v6

    .line 65
    add-int/lit8 v5, v5, 0x3

    .line 66
    .line 67
    add-int/2addr v4, v5

    .line 68
    goto :goto_0

    .line 69
    :cond_1
    add-int/2addr v1, v4

    .line 70
    new-instance v2, Ljava/lang/StringBuilder;

    .line 71
    .line 72
    invoke-direct {v2, v1}, Ljava/lang/StringBuilder;-><init>(I)V

    .line 73
    .line 74
    .line 75
    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 76
    .line 77
    .line 78
    invoke-static {p0}, Ljp/k1;->h(Ljava/util/List;)I

    .line 79
    .line 80
    .line 81
    move-result v0

    .line 82
    if-ltz v0, :cond_13

    .line 83
    .line 84
    move v1, v3

    .line 85
    :goto_1
    invoke-interface {p0, v1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 86
    .line 87
    .line 88
    move-result-object v4

    .line 89
    check-cast v4, Low0/j;

    .line 90
    .line 91
    const-string v5, "; "

    .line 92
    .line 93
    invoke-virtual {v2, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 94
    .line 95
    .line 96
    iget-object v5, v4, Low0/j;->a:Ljava/lang/String;

    .line 97
    .line 98
    invoke-virtual {v2, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 99
    .line 100
    .line 101
    const-string v5, "="

    .line 102
    .line 103
    invoke-virtual {v2, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 104
    .line 105
    .line 106
    iget-object v4, v4, Low0/j;->b:Ljava/lang/String;

    .line 107
    .line 108
    sget-object v5, Low0/k;->a:Ljava/util/Set;

    .line 109
    .line 110
    invoke-virtual {v4}, Ljava/lang/String;->length()I

    .line 111
    .line 112
    .line 113
    move-result v5

    .line 114
    const/16 v6, 0x5c

    .line 115
    .line 116
    const/16 v7, 0x22

    .line 117
    .line 118
    if-nez v5, :cond_2

    .line 119
    .line 120
    goto :goto_5

    .line 121
    :cond_2
    invoke-virtual {v4}, Ljava/lang/String;->length()I

    .line 122
    .line 123
    .line 124
    move-result v5

    .line 125
    const/4 v8, 0x2

    .line 126
    if-ge v5, v8, :cond_3

    .line 127
    .line 128
    goto :goto_3

    .line 129
    :cond_3
    invoke-virtual {v4}, Ljava/lang/String;->length()I

    .line 130
    .line 131
    .line 132
    move-result v5

    .line 133
    if-eqz v5, :cond_12

    .line 134
    .line 135
    invoke-virtual {v4, v3}, Ljava/lang/String;->charAt(I)C

    .line 136
    .line 137
    .line 138
    move-result v5

    .line 139
    if-ne v5, v7, :cond_9

    .line 140
    .line 141
    invoke-static {v4}, Lly0/p;->N(Ljava/lang/CharSequence;)C

    .line 142
    .line 143
    .line 144
    move-result v5

    .line 145
    if-eq v5, v7, :cond_4

    .line 146
    .line 147
    goto :goto_3

    .line 148
    :cond_4
    const/4 v5, 0x1

    .line 149
    :cond_5
    const/4 v8, 0x4

    .line 150
    invoke-static {v4, v7, v5, v8}, Lly0/p;->J(Ljava/lang/CharSequence;CII)I

    .line 151
    .line 152
    .line 153
    move-result v5

    .line 154
    invoke-static {v4}, Lly0/p;->F(Ljava/lang/CharSequence;)I

    .line 155
    .line 156
    .line 157
    move-result v8

    .line 158
    if-ne v5, v8, :cond_6

    .line 159
    .line 160
    goto/16 :goto_8

    .line 161
    .line 162
    :cond_6
    add-int/lit8 v8, v5, -0x1

    .line 163
    .line 164
    move v9, v3

    .line 165
    :goto_2
    invoke-virtual {v4, v8}, Ljava/lang/String;->charAt(I)C

    .line 166
    .line 167
    .line 168
    move-result v10

    .line 169
    if-ne v10, v6, :cond_7

    .line 170
    .line 171
    add-int/lit8 v9, v9, 0x1

    .line 172
    .line 173
    add-int/lit8 v8, v8, -0x1

    .line 174
    .line 175
    goto :goto_2

    .line 176
    :cond_7
    rem-int/lit8 v9, v9, 0x2

    .line 177
    .line 178
    if-nez v9, :cond_8

    .line 179
    .line 180
    goto :goto_3

    .line 181
    :cond_8
    add-int/lit8 v5, v5, 0x1

    .line 182
    .line 183
    invoke-virtual {v4}, Ljava/lang/String;->length()I

    .line 184
    .line 185
    .line 186
    move-result v8

    .line 187
    if-lt v5, v8, :cond_5

    .line 188
    .line 189
    goto/16 :goto_8

    .line 190
    .line 191
    :cond_9
    :goto_3
    invoke-virtual {v4}, Ljava/lang/String;->length()I

    .line 192
    .line 193
    .line 194
    move-result v5

    .line 195
    move v8, v3

    .line 196
    :goto_4
    if-ge v8, v5, :cond_11

    .line 197
    .line 198
    invoke-virtual {v4, v8}, Ljava/lang/String;->charAt(I)C

    .line 199
    .line 200
    .line 201
    move-result v9

    .line 202
    sget-object v10, Low0/k;->a:Ljava/util/Set;

    .line 203
    .line 204
    invoke-static {v9}, Ljava/lang/Character;->valueOf(C)Ljava/lang/Character;

    .line 205
    .line 206
    .line 207
    move-result-object v9

    .line 208
    invoke-interface {v10, v9}, Ljava/util/Set;->contains(Ljava/lang/Object;)Z

    .line 209
    .line 210
    .line 211
    move-result v9

    .line 212
    if-eqz v9, :cond_10

    .line 213
    .line 214
    :goto_5
    new-instance v5, Ljava/lang/StringBuilder;

    .line 215
    .line 216
    const-string v8, "\""

    .line 217
    .line 218
    invoke-direct {v5, v8}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 219
    .line 220
    .line 221
    invoke-virtual {v4}, Ljava/lang/String;->length()I

    .line 222
    .line 223
    .line 224
    move-result v9

    .line 225
    move v10, v3

    .line 226
    :goto_6
    if-ge v10, v9, :cond_f

    .line 227
    .line 228
    invoke-virtual {v4, v10}, Ljava/lang/String;->charAt(I)C

    .line 229
    .line 230
    .line 231
    move-result v11

    .line 232
    const/16 v12, 0x9

    .line 233
    .line 234
    if-eq v11, v12, :cond_e

    .line 235
    .line 236
    const/16 v12, 0xa

    .line 237
    .line 238
    if-eq v11, v12, :cond_d

    .line 239
    .line 240
    const/16 v12, 0xd

    .line 241
    .line 242
    if-eq v11, v12, :cond_c

    .line 243
    .line 244
    if-eq v11, v7, :cond_b

    .line 245
    .line 246
    if-eq v11, v6, :cond_a

    .line 247
    .line 248
    invoke-virtual {v5, v11}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 249
    .line 250
    .line 251
    goto :goto_7

    .line 252
    :cond_a
    const-string v11, "\\\\"

    .line 253
    .line 254
    invoke-virtual {v5, v11}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 255
    .line 256
    .line 257
    goto :goto_7

    .line 258
    :cond_b
    const-string v11, "\\\""

    .line 259
    .line 260
    invoke-virtual {v5, v11}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 261
    .line 262
    .line 263
    goto :goto_7

    .line 264
    :cond_c
    const-string v11, "\\r"

    .line 265
    .line 266
    invoke-virtual {v5, v11}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 267
    .line 268
    .line 269
    goto :goto_7

    .line 270
    :cond_d
    const-string v11, "\\n"

    .line 271
    .line 272
    invoke-virtual {v5, v11}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 273
    .line 274
    .line 275
    goto :goto_7

    .line 276
    :cond_e
    const-string v11, "\\t"

    .line 277
    .line 278
    invoke-virtual {v5, v11}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 279
    .line 280
    .line 281
    :goto_7
    add-int/lit8 v10, v10, 0x1

    .line 282
    .line 283
    goto :goto_6

    .line 284
    :cond_f
    invoke-virtual {v5, v8}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 285
    .line 286
    .line 287
    invoke-virtual {v5}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 288
    .line 289
    .line 290
    move-result-object v4

    .line 291
    invoke-virtual {v2, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 292
    .line 293
    .line 294
    goto :goto_9

    .line 295
    :cond_10
    add-int/lit8 v8, v8, 0x1

    .line 296
    .line 297
    goto :goto_4

    .line 298
    :cond_11
    :goto_8
    invoke-virtual {v2, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 299
    .line 300
    .line 301
    :goto_9
    if-eq v1, v0, :cond_13

    .line 302
    .line 303
    add-int/lit8 v1, v1, 0x1

    .line 304
    .line 305
    goto/16 :goto_1

    .line 306
    .line 307
    :cond_12
    new-instance p0, Ljava/util/NoSuchElementException;

    .line 308
    .line 309
    const-string v0, "Char sequence is empty."

    .line 310
    .line 311
    invoke-direct {p0, v0}, Ljava/util/NoSuchElementException;-><init>(Ljava/lang/String;)V

    .line 312
    .line 313
    .line 314
    throw p0

    .line 315
    :cond_13
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 316
    .line 317
    .line 318
    move-result-object v0

    .line 319
    invoke-static {v0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 320
    .line 321
    .line 322
    :goto_a
    return-object v0

    .line 323
    :pswitch_data_0
    .packed-switch 0x4
        :pswitch_0
    .end packed-switch
.end method
