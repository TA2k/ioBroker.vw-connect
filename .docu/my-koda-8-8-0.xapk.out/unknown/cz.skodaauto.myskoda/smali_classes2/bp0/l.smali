.class public final Lbp0/l;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static c(Landroidx/core/app/x;Landroid/content/Context;Ljava/lang/String;Ljava/lang/String;ILap0/a;)V
    .locals 2

    .line 1
    if-eqz p2, :cond_0

    .line 2
    .line 3
    if-eqz p3, :cond_0

    .line 4
    .line 5
    const-string v0, "context"

    .line 6
    .line 7
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    const-string v0, "channelId"

    .line 11
    .line 12
    invoke-static {p5, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 13
    .line 14
    .line 15
    new-instance v0, Landroid/content/Intent;

    .line 16
    .line 17
    const-string v1, "android.intent.action.VIEW"

    .line 18
    .line 19
    invoke-static {p3}, Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;

    .line 20
    .line 21
    .line 22
    move-result-object p3

    .line 23
    invoke-direct {v0, v1, p3}, Landroid/content/Intent;-><init>(Ljava/lang/String;Landroid/net/Uri;)V

    .line 24
    .line 25
    .line 26
    const-string p3, "NOTIFICATION_ID"

    .line 27
    .line 28
    invoke-virtual {v0, p3, p4}, Landroid/content/Intent;->putExtra(Ljava/lang/String;I)Landroid/content/Intent;

    .line 29
    .line 30
    .line 31
    const-string p3, "GROUP"

    .line 32
    .line 33
    iget-object p4, p5, Lap0/a;->d:Ljava/lang/String;

    .line 34
    .line 35
    invoke-virtual {v0, p3, p4}, Landroid/content/Intent;->putExtra(Ljava/lang/String;Ljava/lang/String;)Landroid/content/Intent;

    .line 36
    .line 37
    .line 38
    new-instance p3, Landroidx/core/app/m0;

    .line 39
    .line 40
    invoke-direct {p3, p1}, Landroidx/core/app/m0;-><init>(Landroid/content/Context;)V

    .line 41
    .line 42
    .line 43
    invoke-virtual {p3, v0}, Landroidx/core/app/m0;->c(Landroid/content/Intent;)V

    .line 44
    .line 45
    .line 46
    new-instance p1, Ljava/security/SecureRandom;

    .line 47
    .line 48
    invoke-direct {p1}, Ljava/security/SecureRandom;-><init>()V

    .line 49
    .line 50
    .line 51
    invoke-virtual {p1}, Ljava/util/Random;->nextInt()I

    .line 52
    .line 53
    .line 54
    move-result p1

    .line 55
    invoke-virtual {p3, p1}, Landroidx/core/app/m0;->g(I)Landroid/app/PendingIntent;

    .line 56
    .line 57
    .line 58
    move-result-object p1

    .line 59
    iget-object p0, p0, Landroidx/core/app/x;->b:Ljava/util/ArrayList;

    .line 60
    .line 61
    new-instance p3, Landroidx/core/app/r;

    .line 62
    .line 63
    const/4 p4, 0x0

    .line 64
    invoke-direct {p3, p4, p2, p1}, Landroidx/core/app/r;-><init>(ILjava/lang/CharSequence;Landroid/app/PendingIntent;)V

    .line 65
    .line 66
    .line 67
    invoke-virtual {p0, p3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 68
    .line 69
    .line 70
    :cond_0
    return-void
.end method

.method public static d(Ljp/k1;Landroid/content/Context;)Ljava/lang/String;
    .locals 4

    .line 1
    instance-of v0, p0, Lap0/k;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    check-cast p0, Lap0/k;

    .line 6
    .line 7
    iget-object p0, p0, Lap0/k;->a:Ljava/lang/String;

    .line 8
    .line 9
    return-object p0

    .line 10
    :cond_0
    instance-of v0, p0, Lap0/l;

    .line 11
    .line 12
    if-eqz v0, :cond_3

    .line 13
    .line 14
    invoke-virtual {p1}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    .line 15
    .line 16
    .line 17
    move-result-object v0

    .line 18
    check-cast p0, Lap0/l;

    .line 19
    .line 20
    iget-object v1, p0, Lap0/l;->b:Ljava/util/List;

    .line 21
    .line 22
    iget-object p0, p0, Lap0/l;->a:Ljava/lang/String;

    .line 23
    .line 24
    const-string v2, "string"

    .line 25
    .line 26
    invoke-virtual {p1}, Landroid/content/Context;->getPackageName()Ljava/lang/String;

    .line 27
    .line 28
    .line 29
    move-result-object v3

    .line 30
    invoke-virtual {v0, p0, v2, v3}, Landroid/content/res/Resources;->getIdentifier(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)I

    .line 31
    .line 32
    .line 33
    move-result p0

    .line 34
    if-lez p0, :cond_2

    .line 35
    .line 36
    invoke-interface {v1}, Ljava/util/List;->isEmpty()Z

    .line 37
    .line 38
    .line 39
    move-result v0

    .line 40
    if-eqz v0, :cond_1

    .line 41
    .line 42
    invoke-virtual {p1}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    .line 43
    .line 44
    .line 45
    move-result-object p1

    .line 46
    invoke-virtual {p1, p0}, Landroid/content/res/Resources;->getString(I)Ljava/lang/String;

    .line 47
    .line 48
    .line 49
    move-result-object p0

    .line 50
    return-object p0

    .line 51
    :cond_1
    invoke-virtual {p1}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    .line 52
    .line 53
    .line 54
    move-result-object p1

    .line 55
    check-cast v1, Ljava/util/Collection;

    .line 56
    .line 57
    const/4 v0, 0x0

    .line 58
    new-array v0, v0, [Ljava/lang/String;

    .line 59
    .line 60
    invoke-interface {v1, v0}, Ljava/util/Collection;->toArray([Ljava/lang/Object;)[Ljava/lang/Object;

    .line 61
    .line 62
    .line 63
    move-result-object v0

    .line 64
    check-cast v0, [Ljava/lang/String;

    .line 65
    .line 66
    array-length v1, v0

    .line 67
    invoke-static {v0, v1}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    .line 68
    .line 69
    .line 70
    move-result-object v0

    .line 71
    invoke-virtual {p1, p0, v0}, Landroid/content/res/Resources;->getString(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 72
    .line 73
    .line 74
    move-result-object p0

    .line 75
    return-object p0

    .line 76
    :cond_2
    const/4 p0, 0x0

    .line 77
    return-object p0

    .line 78
    :cond_3
    new-instance p0, La8/r0;

    .line 79
    .line 80
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 81
    .line 82
    .line 83
    throw p0
.end method


# virtual methods
.method public final a(Landroidx/core/app/x;Landroid/content/Context;Ljava/lang/String;Lrx0/c;)Ljava/lang/Object;
    .locals 4

    .line 1
    instance-of v0, p4, Lbp0/j;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p4

    .line 6
    check-cast v0, Lbp0/j;

    .line 7
    .line 8
    iget v1, v0, Lbp0/j;->g:I

    .line 9
    .line 10
    const/high16 v2, -0x80000000

    .line 11
    .line 12
    and-int v3, v1, v2

    .line 13
    .line 14
    if-eqz v3, :cond_0

    .line 15
    .line 16
    sub-int/2addr v1, v2

    .line 17
    iput v1, v0, Lbp0/j;->g:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lbp0/j;

    .line 21
    .line 22
    invoke-direct {v0, p0, p4}, Lbp0/j;-><init>(Lbp0/l;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p0, v0, Lbp0/j;->e:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object p4, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v1, v0, Lbp0/j;->g:I

    .line 30
    .line 31
    const/4 v2, 0x1

    .line 32
    if-eqz v1, :cond_2

    .line 33
    .line 34
    if-ne v1, v2, :cond_1

    .line 35
    .line 36
    iget-object p1, v0, Lbp0/j;->d:Landroidx/core/app/x;

    .line 37
    .line 38
    invoke-static {p0}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 39
    .line 40
    .line 41
    goto :goto_1

    .line 42
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 43
    .line 44
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 45
    .line 46
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 47
    .line 48
    .line 49
    throw p0

    .line 50
    :cond_2
    invoke-static {p0}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 51
    .line 52
    .line 53
    new-instance p0, Lcom/google/android/material/datepicker/d;

    .line 54
    .line 55
    const/4 v1, 0x4

    .line 56
    invoke-direct {p0, p2, v1}, Lcom/google/android/material/datepicker/d;-><init>(Landroid/content/Context;I)V

    .line 57
    .line 58
    .line 59
    invoke-virtual {p0}, Lcom/google/android/material/datepicker/d;->f()Lyl/r;

    .line 60
    .line 61
    .line 62
    move-result-object p0

    .line 63
    new-instance v1, Lmm/d;

    .line 64
    .line 65
    invoke-direct {v1, p2}, Lmm/d;-><init>(Landroid/content/Context;)V

    .line 66
    .line 67
    .line 68
    iput-object p3, v1, Lmm/d;->c:Ljava/lang/Object;

    .line 69
    .line 70
    invoke-virtual {v1}, Lmm/d;->a()Lmm/g;

    .line 71
    .line 72
    .line 73
    move-result-object p2

    .line 74
    iput-object p1, v0, Lbp0/j;->d:Landroidx/core/app/x;

    .line 75
    .line 76
    iput v2, v0, Lbp0/j;->g:I

    .line 77
    .line 78
    invoke-virtual {p0, p2, v0}, Lyl/r;->b(Lmm/g;Lrx0/c;)Ljava/lang/Object;

    .line 79
    .line 80
    .line 81
    move-result-object p0

    .line 82
    if-ne p0, p4, :cond_3

    .line 83
    .line 84
    return-object p4

    .line 85
    :cond_3
    :goto_1
    check-cast p0, Lmm/j;

    .line 86
    .line 87
    invoke-interface {p0}, Lmm/j;->r()Lyl/j;

    .line 88
    .line 89
    .line 90
    move-result-object p0

    .line 91
    if-eqz p0, :cond_6

    .line 92
    .line 93
    invoke-static {p0}, Lyl/m;->i(Lyl/j;)Landroid/graphics/Bitmap;

    .line 94
    .line 95
    .line 96
    move-result-object p0

    .line 97
    const/4 p2, 0x0

    .line 98
    if-nez p0, :cond_4

    .line 99
    .line 100
    move-object p3, p2

    .line 101
    goto :goto_2

    .line 102
    :cond_4
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 103
    .line 104
    .line 105
    new-instance p3, Landroidx/core/graphics/drawable/IconCompat;

    .line 106
    .line 107
    invoke-direct {p3, v2}, Landroidx/core/graphics/drawable/IconCompat;-><init>(I)V

    .line 108
    .line 109
    .line 110
    iput-object p0, p3, Landroidx/core/graphics/drawable/IconCompat;->b:Ljava/lang/Object;

    .line 111
    .line 112
    :goto_2
    iput-object p3, p1, Landroidx/core/app/x;->h:Landroidx/core/graphics/drawable/IconCompat;

    .line 113
    .line 114
    new-instance p3, Landroidx/core/app/u;

    .line 115
    .line 116
    invoke-direct {p3}, Landroidx/core/app/a0;-><init>()V

    .line 117
    .line 118
    .line 119
    if-nez p0, :cond_5

    .line 120
    .line 121
    move-object p4, p2

    .line 122
    goto :goto_3

    .line 123
    :cond_5
    new-instance p4, Landroidx/core/graphics/drawable/IconCompat;

    .line 124
    .line 125
    invoke-direct {p4, v2}, Landroidx/core/graphics/drawable/IconCompat;-><init>(I)V

    .line 126
    .line 127
    .line 128
    iput-object p0, p4, Landroidx/core/graphics/drawable/IconCompat;->b:Ljava/lang/Object;

    .line 129
    .line 130
    :goto_3
    iput-object p4, p3, Landroidx/core/app/u;->e:Landroidx/core/graphics/drawable/IconCompat;

    .line 131
    .line 132
    iput-object p2, p3, Landroidx/core/app/u;->f:Landroidx/core/graphics/drawable/IconCompat;

    .line 133
    .line 134
    iput-boolean v2, p3, Landroidx/core/app/u;->g:Z

    .line 135
    .line 136
    invoke-virtual {p1, p3}, Landroidx/core/app/x;->f(Landroidx/core/app/a0;)V

    .line 137
    .line 138
    .line 139
    :cond_6
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 140
    .line 141
    return-object p0
.end method

.method public final b(Landroid/content/Context;Lap0/c;ILap0/a;Landroidx/core/app/x;Lrx0/c;)Ljava/lang/Object;
    .locals 11

    .line 1
    move-object/from16 v0, p5

    .line 2
    .line 3
    move-object/from16 v1, p6

    .line 4
    .line 5
    instance-of v2, v1, Lbp0/k;

    .line 6
    .line 7
    if-eqz v2, :cond_0

    .line 8
    .line 9
    move-object v2, v1

    .line 10
    check-cast v2, Lbp0/k;

    .line 11
    .line 12
    iget v3, v2, Lbp0/k;->g:I

    .line 13
    .line 14
    const/high16 v4, -0x80000000

    .line 15
    .line 16
    and-int v5, v3, v4

    .line 17
    .line 18
    if-eqz v5, :cond_0

    .line 19
    .line 20
    sub-int/2addr v3, v4

    .line 21
    iput v3, v2, Lbp0/k;->g:I

    .line 22
    .line 23
    :goto_0
    move-object v6, v2

    .line 24
    goto :goto_1

    .line 25
    :cond_0
    new-instance v2, Lbp0/k;

    .line 26
    .line 27
    invoke-direct {v2, p0, v1}, Lbp0/k;-><init>(Lbp0/l;Lrx0/c;)V

    .line 28
    .line 29
    .line 30
    goto :goto_0

    .line 31
    :goto_1
    iget-object v1, v6, Lbp0/k;->e:Ljava/lang/Object;

    .line 32
    .line 33
    sget-object v7, Lqx0/a;->d:Lqx0/a;

    .line 34
    .line 35
    iget v2, v6, Lbp0/k;->g:I

    .line 36
    .line 37
    const/4 v8, 0x1

    .line 38
    if-eqz v2, :cond_2

    .line 39
    .line 40
    if-ne v2, v8, :cond_1

    .line 41
    .line 42
    iget-object p0, v6, Lbp0/k;->d:Landroidx/core/app/x;

    .line 43
    .line 44
    invoke-static {v1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 45
    .line 46
    .line 47
    goto/16 :goto_9

    .line 48
    .line 49
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 50
    .line 51
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 52
    .line 53
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 54
    .line 55
    .line 56
    throw p0

    .line 57
    :cond_2
    invoke-static {v1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 58
    .line 59
    .line 60
    iget-object v1, p2, Lap0/c;->a:Ljp/k1;

    .line 61
    .line 62
    iget-object v2, p2, Lap0/c;->e:Lap0/g;

    .line 63
    .line 64
    iget-object v3, p2, Lap0/c;->b:Ljp/k1;

    .line 65
    .line 66
    invoke-static {v1, p1}, Lbp0/l;->d(Ljp/k1;Landroid/content/Context;)Ljava/lang/String;

    .line 67
    .line 68
    .line 69
    move-result-object v1

    .line 70
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 71
    .line 72
    .line 73
    invoke-static {v1}, Landroidx/core/app/x;->b(Ljava/lang/CharSequence;)Ljava/lang/CharSequence;

    .line 74
    .line 75
    .line 76
    move-result-object v1

    .line 77
    iput-object v1, v0, Landroidx/core/app/x;->e:Ljava/lang/CharSequence;

    .line 78
    .line 79
    invoke-static {v3, p1}, Lbp0/l;->d(Ljp/k1;Landroid/content/Context;)Ljava/lang/String;

    .line 80
    .line 81
    .line 82
    move-result-object v1

    .line 83
    invoke-static {v1}, Landroidx/core/app/x;->b(Ljava/lang/CharSequence;)Ljava/lang/CharSequence;

    .line 84
    .line 85
    .line 86
    move-result-object v1

    .line 87
    iput-object v1, v0, Landroidx/core/app/x;->f:Ljava/lang/CharSequence;

    .line 88
    .line 89
    const/4 v1, 0x0

    .line 90
    iput-boolean v1, v0, Landroidx/core/app/x;->n:Z

    .line 91
    .line 92
    const/16 v4, 0x10

    .line 93
    .line 94
    invoke-virtual {v0, v4, v8}, Landroidx/core/app/x;->d(IZ)V

    .line 95
    .line 96
    .line 97
    invoke-static {}, Ljava/time/Instant;->now()Ljava/time/Instant;

    .line 98
    .line 99
    .line 100
    move-result-object v4

    .line 101
    invoke-virtual {v4}, Ljava/time/Instant;->toEpochMilli()J

    .line 102
    .line 103
    .line 104
    move-result-wide v4

    .line 105
    iget-object v9, v0, Landroidx/core/app/x;->y:Landroid/app/Notification;

    .line 106
    .line 107
    iput-wide v4, v9, Landroid/app/Notification;->when:J

    .line 108
    .line 109
    iput-boolean v8, v0, Landroidx/core/app/x;->k:Z

    .line 110
    .line 111
    iput-boolean v1, v0, Landroidx/core/app/x;->o:Z

    .line 112
    .line 113
    const/4 v1, 0x2

    .line 114
    iput v1, v0, Landroidx/core/app/x;->w:I

    .line 115
    .line 116
    new-instance v1, Landroidx/core/app/v;

    .line 117
    .line 118
    invoke-direct {v1}, Landroidx/core/app/a0;-><init>()V

    .line 119
    .line 120
    .line 121
    invoke-static {v3, p1}, Lbp0/l;->d(Ljp/k1;Landroid/content/Context;)Ljava/lang/String;

    .line 122
    .line 123
    .line 124
    move-result-object v3

    .line 125
    invoke-static {v3}, Landroidx/core/app/x;->b(Ljava/lang/CharSequence;)Ljava/lang/CharSequence;

    .line 126
    .line 127
    .line 128
    move-result-object v3

    .line 129
    iput-object v3, v1, Landroidx/core/app/v;->e:Ljava/lang/CharSequence;

    .line 130
    .line 131
    invoke-virtual {v0, v1}, Landroidx/core/app/x;->f(Landroidx/core/app/a0;)V

    .line 132
    .line 133
    .line 134
    iget-object v9, p2, Lap0/c;->f:Lap0/g;

    .line 135
    .line 136
    const/4 v10, 0x0

    .line 137
    if-eqz v2, :cond_3

    .line 138
    .line 139
    iget-object v1, v2, Lap0/g;->a:Ljp/k1;

    .line 140
    .line 141
    invoke-static {v1, p1}, Lbp0/l;->d(Ljp/k1;Landroid/content/Context;)Ljava/lang/String;

    .line 142
    .line 143
    .line 144
    move-result-object v1

    .line 145
    goto :goto_2

    .line 146
    :cond_3
    move-object v1, v10

    .line 147
    :goto_2
    if-eqz v2, :cond_4

    .line 148
    .line 149
    iget-object v2, v2, Lap0/g;->b:Ljava/lang/String;

    .line 150
    .line 151
    move-object v3, v2

    .line 152
    :goto_3
    move v4, p3

    .line 153
    move-object v5, p4

    .line 154
    move-object v2, v1

    .line 155
    move-object v1, p1

    .line 156
    goto :goto_4

    .line 157
    :cond_4
    move-object v3, v10

    .line 158
    goto :goto_3

    .line 159
    :goto_4
    invoke-static/range {v0 .. v5}, Lbp0/l;->c(Landroidx/core/app/x;Landroid/content/Context;Ljava/lang/String;Ljava/lang/String;ILap0/a;)V

    .line 160
    .line 161
    .line 162
    if-eqz v9, :cond_5

    .line 163
    .line 164
    iget-object v0, v9, Lap0/g;->a:Ljp/k1;

    .line 165
    .line 166
    invoke-static {v0, p1}, Lbp0/l;->d(Ljp/k1;Landroid/content/Context;)Ljava/lang/String;

    .line 167
    .line 168
    .line 169
    move-result-object v0

    .line 170
    move-object v2, v0

    .line 171
    goto :goto_5

    .line 172
    :cond_5
    move-object v2, v10

    .line 173
    :goto_5
    if-eqz v9, :cond_6

    .line 174
    .line 175
    iget-object v0, v9, Lap0/g;->b:Ljava/lang/String;

    .line 176
    .line 177
    move-object v3, v0

    .line 178
    :goto_6
    move-object v1, p1

    .line 179
    move v4, p3

    .line 180
    move-object v5, p4

    .line 181
    move-object/from16 v0, p5

    .line 182
    .line 183
    goto :goto_7

    .line 184
    :cond_6
    move-object v3, v10

    .line 185
    goto :goto_6

    .line 186
    :goto_7
    invoke-static/range {v0 .. v5}, Lbp0/l;->c(Landroidx/core/app/x;Landroid/content/Context;Ljava/lang/String;Ljava/lang/String;ILap0/a;)V

    .line 187
    .line 188
    .line 189
    iget-object p2, p2, Lap0/c;->g:Ljava/lang/String;

    .line 190
    .line 191
    if-eqz p2, :cond_8

    .line 192
    .line 193
    invoke-virtual {p2}, Ljava/lang/String;->length()I

    .line 194
    .line 195
    .line 196
    move-result p3

    .line 197
    if-nez p3, :cond_7

    .line 198
    .line 199
    goto :goto_8

    .line 200
    :cond_7
    move-object v10, p2

    .line 201
    :cond_8
    :goto_8
    if-eqz v10, :cond_9

    .line 202
    .line 203
    iput-object v0, v6, Lbp0/k;->d:Landroidx/core/app/x;

    .line 204
    .line 205
    iput v8, v6, Lbp0/k;->g:I

    .line 206
    .line 207
    invoke-virtual {p0, v0, p1, v10, v6}, Lbp0/l;->a(Landroidx/core/app/x;Landroid/content/Context;Ljava/lang/String;Lrx0/c;)Ljava/lang/Object;

    .line 208
    .line 209
    .line 210
    move-result-object p0

    .line 211
    if-ne p0, v7, :cond_9

    .line 212
    .line 213
    return-object v7

    .line 214
    :cond_9
    move-object p0, v0

    .line 215
    :goto_9
    const-string p1, "with(...)"

    .line 216
    .line 217
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 218
    .line 219
    .line 220
    return-object p0
.end method
