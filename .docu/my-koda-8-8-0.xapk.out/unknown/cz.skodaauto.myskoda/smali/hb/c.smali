.class public final Lhb/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lfb/g;


# static fields
.field public static final i:Ljava/lang/String;


# instance fields
.field public final d:Landroid/content/Context;

.field public final e:Landroid/app/job/JobScheduler;

.field public final f:Lhb/b;

.field public final g:Landroidx/work/impl/WorkDatabase;

.field public final h:Leb/b;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    const-string v0, "SystemJobScheduler"

    .line 2
    .line 3
    invoke-static {v0}, Leb/w;->f(Ljava/lang/String;)Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    sput-object v0, Lhb/c;->i:Ljava/lang/String;

    .line 8
    .line 9
    return-void
.end method

.method public constructor <init>(Landroid/content/Context;Landroidx/work/impl/WorkDatabase;Leb/b;)V
    .locals 4

    .line 1
    invoke-static {p1}, Lhb/a;->b(Landroid/content/Context;)Landroid/app/job/JobScheduler;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    new-instance v1, Lhb/b;

    .line 6
    .line 7
    iget-object v2, p3, Leb/b;->d:Leb/j;

    .line 8
    .line 9
    iget-boolean v3, p3, Leb/b;->l:Z

    .line 10
    .line 11
    invoke-direct {v1, p1, v2, v3}, Lhb/b;-><init>(Landroid/content/Context;Leb/j;Z)V

    .line 12
    .line 13
    .line 14
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 15
    .line 16
    .line 17
    iput-object p1, p0, Lhb/c;->d:Landroid/content/Context;

    .line 18
    .line 19
    iput-object v0, p0, Lhb/c;->e:Landroid/app/job/JobScheduler;

    .line 20
    .line 21
    iput-object v1, p0, Lhb/c;->f:Lhb/b;

    .line 22
    .line 23
    iput-object p2, p0, Lhb/c;->g:Landroidx/work/impl/WorkDatabase;

    .line 24
    .line 25
    iput-object p3, p0, Lhb/c;->h:Leb/b;

    .line 26
    .line 27
    return-void
.end method

.method public static b(Landroid/app/job/JobScheduler;I)V
    .locals 3

    .line 1
    :try_start_0
    invoke-virtual {p0, p1}, Landroid/app/job/JobScheduler;->cancel(I)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 2
    .line 3
    .line 4
    return-void

    .line 5
    :catchall_0
    move-exception p0

    .line 6
    invoke-static {}, Leb/w;->d()Leb/w;

    .line 7
    .line 8
    .line 9
    move-result-object v0

    .line 10
    invoke-static {}, Ljava/util/Locale;->getDefault()Ljava/util/Locale;

    .line 11
    .line 12
    .line 13
    move-result-object v1

    .line 14
    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 15
    .line 16
    .line 17
    move-result-object p1

    .line 18
    filled-new-array {p1}, [Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p1

    .line 22
    const-string v2, "Exception while trying to cancel job (%d)"

    .line 23
    .line 24
    invoke-static {v1, v2, p1}, Ljava/lang/String;->format(Ljava/util/Locale;Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    .line 25
    .line 26
    .line 27
    move-result-object p1

    .line 28
    sget-object v1, Lhb/c;->i:Ljava/lang/String;

    .line 29
    .line 30
    invoke-virtual {v0, v1, p1, p0}, Leb/w;->c(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 31
    .line 32
    .line 33
    return-void
.end method

.method public static d(Landroid/content/Context;Landroid/app/job/JobScheduler;)Ljava/util/ArrayList;
    .locals 3

    .line 1
    invoke-static {p1}, Lhb/a;->a(Landroid/app/job/JobScheduler;)Ljava/util/List;

    .line 2
    .line 3
    .line 4
    move-result-object p1

    .line 5
    if-nez p1, :cond_0

    .line 6
    .line 7
    const/4 p0, 0x0

    .line 8
    return-object p0

    .line 9
    :cond_0
    new-instance v0, Ljava/util/ArrayList;

    .line 10
    .line 11
    invoke-interface {p1}, Ljava/util/List;->size()I

    .line 12
    .line 13
    .line 14
    move-result v1

    .line 15
    invoke-direct {v0, v1}, Ljava/util/ArrayList;-><init>(I)V

    .line 16
    .line 17
    .line 18
    new-instance v1, Landroid/content/ComponentName;

    .line 19
    .line 20
    const-class v2, Landroidx/work/impl/background/systemjob/SystemJobService;

    .line 21
    .line 22
    invoke-direct {v1, p0, v2}, Landroid/content/ComponentName;-><init>(Landroid/content/Context;Ljava/lang/Class;)V

    .line 23
    .line 24
    .line 25
    invoke-interface {p1}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 26
    .line 27
    .line 28
    move-result-object p0

    .line 29
    :cond_1
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 30
    .line 31
    .line 32
    move-result p1

    .line 33
    if-eqz p1, :cond_2

    .line 34
    .line 35
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 36
    .line 37
    .line 38
    move-result-object p1

    .line 39
    check-cast p1, Landroid/app/job/JobInfo;

    .line 40
    .line 41
    invoke-virtual {p1}, Landroid/app/job/JobInfo;->getService()Landroid/content/ComponentName;

    .line 42
    .line 43
    .line 44
    move-result-object v2

    .line 45
    invoke-virtual {v1, v2}, Landroid/content/ComponentName;->equals(Ljava/lang/Object;)Z

    .line 46
    .line 47
    .line 48
    move-result v2

    .line 49
    if-eqz v2, :cond_1

    .line 50
    .line 51
    invoke-virtual {v0, p1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 52
    .line 53
    .line 54
    goto :goto_0

    .line 55
    :cond_2
    return-object v0
.end method

.method public static f(Landroid/app/job/JobInfo;)Lmb/i;
    .locals 3

    .line 1
    const-string v0, "EXTRA_WORK_SPEC_ID"

    .line 2
    .line 3
    invoke-virtual {p0}, Landroid/app/job/JobInfo;->getExtras()Landroid/os/PersistableBundle;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    if-eqz p0, :cond_0

    .line 8
    .line 9
    :try_start_0
    invoke-virtual {p0, v0}, Landroid/os/BaseBundle;->containsKey(Ljava/lang/String;)Z

    .line 10
    .line 11
    .line 12
    move-result v1

    .line 13
    if-eqz v1, :cond_0

    .line 14
    .line 15
    const-string v1, "EXTRA_WORK_SPEC_GENERATION"

    .line 16
    .line 17
    const/4 v2, 0x0

    .line 18
    invoke-virtual {p0, v1, v2}, Landroid/os/BaseBundle;->getInt(Ljava/lang/String;I)I

    .line 19
    .line 20
    .line 21
    move-result v1

    .line 22
    new-instance v2, Lmb/i;

    .line 23
    .line 24
    invoke-virtual {p0, v0}, Landroid/os/BaseBundle;->getString(Ljava/lang/String;)Ljava/lang/String;

    .line 25
    .line 26
    .line 27
    move-result-object p0

    .line 28
    invoke-direct {v2, p0, v1}, Lmb/i;-><init>(Ljava/lang/String;I)V
    :try_end_0
    .catch Ljava/lang/NullPointerException; {:try_start_0 .. :try_end_0} :catch_0

    .line 29
    .line 30
    .line 31
    return-object v2

    .line 32
    :catch_0
    :cond_0
    const/4 p0, 0x0

    .line 33
    return-object p0
.end method


# virtual methods
.method public final varargs a([Lmb/o;)V
    .locals 13

    .line 1
    iget-object v0, p0, Lhb/c;->h:Leb/b;

    .line 2
    .line 3
    new-instance v1, Lhu/q;

    .line 4
    .line 5
    iget-object v2, p0, Lhb/c;->g:Landroidx/work/impl/WorkDatabase;

    .line 6
    .line 7
    invoke-direct {v1, v2}, Lhu/q;-><init>(Landroidx/work/impl/WorkDatabase;)V

    .line 8
    .line 9
    .line 10
    array-length v3, p1

    .line 11
    const/4 v4, 0x0

    .line 12
    move v5, v4

    .line 13
    :goto_0
    if-ge v5, v3, :cond_4

    .line 14
    .line 15
    aget-object v6, p1, v5

    .line 16
    .line 17
    invoke-virtual {v2}, Lla/u;->c()V

    .line 18
    .line 19
    .line 20
    :try_start_0
    invoke-virtual {v2}, Landroidx/work/impl/WorkDatabase;->x()Lmb/s;

    .line 21
    .line 22
    .line 23
    move-result-object v7

    .line 24
    iget-object v8, v6, Lmb/o;->a:Ljava/lang/String;

    .line 25
    .line 26
    invoke-virtual {v7, v8}, Lmb/s;->e(Ljava/lang/String;)Lmb/o;

    .line 27
    .line 28
    .line 29
    move-result-object v7
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 30
    const-string v9, "Skipping scheduling "

    .line 31
    .line 32
    sget-object v10, Lhb/c;->i:Ljava/lang/String;

    .line 33
    .line 34
    if-nez v7, :cond_0

    .line 35
    .line 36
    :try_start_1
    invoke-static {}, Leb/w;->d()Leb/w;

    .line 37
    .line 38
    .line 39
    move-result-object v6

    .line 40
    new-instance v7, Ljava/lang/StringBuilder;

    .line 41
    .line 42
    invoke-direct {v7}, Ljava/lang/StringBuilder;-><init>()V

    .line 43
    .line 44
    .line 45
    invoke-virtual {v7, v9}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 46
    .line 47
    .line 48
    invoke-virtual {v7, v8}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 49
    .line 50
    .line 51
    const-string v8, " because it\'s no longer in the DB"

    .line 52
    .line 53
    invoke-virtual {v7, v8}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 54
    .line 55
    .line 56
    invoke-virtual {v7}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 57
    .line 58
    .line 59
    move-result-object v7

    .line 60
    invoke-virtual {v6, v10, v7}, Leb/w;->g(Ljava/lang/String;Ljava/lang/String;)V

    .line 61
    .line 62
    .line 63
    invoke-virtual {v2}, Lla/u;->q()V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 64
    .line 65
    .line 66
    :goto_1
    invoke-virtual {v2}, Lla/u;->g()V

    .line 67
    .line 68
    .line 69
    goto/16 :goto_3

    .line 70
    .line 71
    :catchall_0
    move-exception p0

    .line 72
    goto/16 :goto_4

    .line 73
    .line 74
    :cond_0
    :try_start_2
    iget-object v7, v7, Lmb/o;->b:Leb/h0;

    .line 75
    .line 76
    sget-object v11, Leb/h0;->d:Leb/h0;

    .line 77
    .line 78
    if-eq v7, v11, :cond_1

    .line 79
    .line 80
    invoke-static {}, Leb/w;->d()Leb/w;

    .line 81
    .line 82
    .line 83
    move-result-object v6

    .line 84
    new-instance v7, Ljava/lang/StringBuilder;

    .line 85
    .line 86
    invoke-direct {v7}, Ljava/lang/StringBuilder;-><init>()V

    .line 87
    .line 88
    .line 89
    invoke-virtual {v7, v9}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 90
    .line 91
    .line 92
    invoke-virtual {v7, v8}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 93
    .line 94
    .line 95
    const-string v8, " because it is no longer enqueued"

    .line 96
    .line 97
    invoke-virtual {v7, v8}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 98
    .line 99
    .line 100
    invoke-virtual {v7}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 101
    .line 102
    .line 103
    move-result-object v7

    .line 104
    invoke-virtual {v6, v10, v7}, Leb/w;->g(Ljava/lang/String;Ljava/lang/String;)V

    .line 105
    .line 106
    .line 107
    invoke-virtual {v2}, Lla/u;->q()V

    .line 108
    .line 109
    .line 110
    goto :goto_1

    .line 111
    :cond_1
    invoke-static {v6}, Ljp/y0;->c(Lmb/o;)Lmb/i;

    .line 112
    .line 113
    .line 114
    move-result-object v7

    .line 115
    invoke-virtual {v2}, Landroidx/work/impl/WorkDatabase;->u()Lmb/h;

    .line 116
    .line 117
    .line 118
    move-result-object v8

    .line 119
    invoke-virtual {v8, v7}, Lmb/h;->a(Lmb/i;)Lmb/f;

    .line 120
    .line 121
    .line 122
    move-result-object v8

    .line 123
    if-eqz v8, :cond_2

    .line 124
    .line 125
    iget v9, v8, Lmb/f;->c:I

    .line 126
    .line 127
    goto :goto_2

    .line 128
    :cond_2
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 129
    .line 130
    .line 131
    iget v9, v0, Leb/b;->i:I

    .line 132
    .line 133
    iget-object v10, v1, Lhu/q;->e:Ljava/lang/Object;

    .line 134
    .line 135
    check-cast v10, Landroidx/work/impl/WorkDatabase;

    .line 136
    .line 137
    new-instance v11, Lnb/c;

    .line 138
    .line 139
    invoke-direct {v11, v1, v9}, Lnb/c;-><init>(Lhu/q;I)V

    .line 140
    .line 141
    .line 142
    invoke-virtual {v10}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 143
    .line 144
    .line 145
    new-instance v9, Lh50/q0;

    .line 146
    .line 147
    const/16 v12, 0x17

    .line 148
    .line 149
    invoke-direct {v9, v11, v12}, Lh50/q0;-><init>(Ljava/lang/Object;I)V

    .line 150
    .line 151
    .line 152
    invoke-virtual {v10, v9}, Lla/u;->p(Lay0/a;)Ljava/lang/Object;

    .line 153
    .line 154
    .line 155
    move-result-object v9

    .line 156
    const-string v10, "runInTransaction(...)"

    .line 157
    .line 158
    invoke-static {v9, v10}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 159
    .line 160
    .line 161
    check-cast v9, Ljava/lang/Number;

    .line 162
    .line 163
    invoke-virtual {v9}, Ljava/lang/Number;->intValue()I

    .line 164
    .line 165
    .line 166
    move-result v9

    .line 167
    :goto_2
    if-nez v8, :cond_3

    .line 168
    .line 169
    new-instance v8, Lmb/f;

    .line 170
    .line 171
    iget-object v10, v7, Lmb/i;->a:Ljava/lang/String;

    .line 172
    .line 173
    iget v7, v7, Lmb/i;->b:I

    .line 174
    .line 175
    invoke-direct {v8, v10, v7, v9}, Lmb/f;-><init>(Ljava/lang/String;II)V

    .line 176
    .line 177
    .line 178
    invoke-virtual {v2}, Landroidx/work/impl/WorkDatabase;->u()Lmb/h;

    .line 179
    .line 180
    .line 181
    move-result-object v7

    .line 182
    invoke-virtual {v7}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 183
    .line 184
    .line 185
    iget-object v10, v7, Lmb/h;->a:Lla/u;

    .line 186
    .line 187
    new-instance v11, Ll2/v1;

    .line 188
    .line 189
    const/4 v12, 0x7

    .line 190
    invoke-direct {v11, v12, v7, v8}, Ll2/v1;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 191
    .line 192
    .line 193
    const/4 v7, 0x1

    .line 194
    invoke-static {v10, v4, v7, v11}, Ljp/ue;->f(Lla/u;ZZLay0/k;)Ljava/lang/Object;

    .line 195
    .line 196
    .line 197
    :cond_3
    invoke-virtual {p0, v6, v9}, Lhb/c;->g(Lmb/o;I)V

    .line 198
    .line 199
    .line 200
    invoke-virtual {v2}, Lla/u;->q()V
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 201
    .line 202
    .line 203
    goto/16 :goto_1

    .line 204
    .line 205
    :goto_3
    add-int/lit8 v5, v5, 0x1

    .line 206
    .line 207
    goto/16 :goto_0

    .line 208
    .line 209
    :goto_4
    invoke-virtual {v2}, Lla/u;->g()V

    .line 210
    .line 211
    .line 212
    throw p0

    .line 213
    :cond_4
    return-void
.end method

.method public final c(Ljava/lang/String;)V
    .locals 5

    .line 1
    iget-object v0, p0, Lhb/c;->d:Landroid/content/Context;

    .line 2
    .line 3
    iget-object v1, p0, Lhb/c;->e:Landroid/app/job/JobScheduler;

    .line 4
    .line 5
    invoke-static {v0, v1}, Lhb/c;->d(Landroid/content/Context;Landroid/app/job/JobScheduler;)Ljava/util/ArrayList;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    if-nez v0, :cond_0

    .line 10
    .line 11
    const/4 v0, 0x0

    .line 12
    goto :goto_1

    .line 13
    :cond_0
    new-instance v2, Ljava/util/ArrayList;

    .line 14
    .line 15
    const/4 v3, 0x2

    .line 16
    invoke-direct {v2, v3}, Ljava/util/ArrayList;-><init>(I)V

    .line 17
    .line 18
    .line 19
    invoke-virtual {v0}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 20
    .line 21
    .line 22
    move-result-object v0

    .line 23
    :cond_1
    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 24
    .line 25
    .line 26
    move-result v3

    .line 27
    if-eqz v3, :cond_2

    .line 28
    .line 29
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 30
    .line 31
    .line 32
    move-result-object v3

    .line 33
    check-cast v3, Landroid/app/job/JobInfo;

    .line 34
    .line 35
    invoke-static {v3}, Lhb/c;->f(Landroid/app/job/JobInfo;)Lmb/i;

    .line 36
    .line 37
    .line 38
    move-result-object v4

    .line 39
    if-eqz v4, :cond_1

    .line 40
    .line 41
    iget-object v4, v4, Lmb/i;->a:Ljava/lang/String;

    .line 42
    .line 43
    invoke-virtual {p1, v4}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 44
    .line 45
    .line 46
    move-result v4

    .line 47
    if-eqz v4, :cond_1

    .line 48
    .line 49
    invoke-virtual {v3}, Landroid/app/job/JobInfo;->getId()I

    .line 50
    .line 51
    .line 52
    move-result v3

    .line 53
    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 54
    .line 55
    .line 56
    move-result-object v3

    .line 57
    invoke-virtual {v2, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 58
    .line 59
    .line 60
    goto :goto_0

    .line 61
    :cond_2
    move-object v0, v2

    .line 62
    :goto_1
    if-eqz v0, :cond_4

    .line 63
    .line 64
    invoke-virtual {v0}, Ljava/util/ArrayList;->isEmpty()Z

    .line 65
    .line 66
    .line 67
    move-result v2

    .line 68
    if-nez v2, :cond_4

    .line 69
    .line 70
    invoke-virtual {v0}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 71
    .line 72
    .line 73
    move-result-object v0

    .line 74
    :goto_2
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 75
    .line 76
    .line 77
    move-result v2

    .line 78
    if-eqz v2, :cond_3

    .line 79
    .line 80
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 81
    .line 82
    .line 83
    move-result-object v2

    .line 84
    check-cast v2, Ljava/lang/Integer;

    .line 85
    .line 86
    invoke-virtual {v2}, Ljava/lang/Integer;->intValue()I

    .line 87
    .line 88
    .line 89
    move-result v2

    .line 90
    invoke-static {v1, v2}, Lhb/c;->b(Landroid/app/job/JobScheduler;I)V

    .line 91
    .line 92
    .line 93
    goto :goto_2

    .line 94
    :cond_3
    iget-object p0, p0, Lhb/c;->g:Landroidx/work/impl/WorkDatabase;

    .line 95
    .line 96
    invoke-virtual {p0}, Landroidx/work/impl/WorkDatabase;->u()Lmb/h;

    .line 97
    .line 98
    .line 99
    move-result-object p0

    .line 100
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 101
    .line 102
    .line 103
    const-string v0, "workSpecId"

    .line 104
    .line 105
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 106
    .line 107
    .line 108
    iget-object p0, p0, Lmb/h;->a:Lla/u;

    .line 109
    .line 110
    new-instance v0, Lif0/d;

    .line 111
    .line 112
    const/16 v1, 0xe

    .line 113
    .line 114
    invoke-direct {v0, p1, v1}, Lif0/d;-><init>(Ljava/lang/String;I)V

    .line 115
    .line 116
    .line 117
    const/4 p1, 0x0

    .line 118
    const/4 v1, 0x1

    .line 119
    invoke-static {p0, p1, v1, v0}, Ljp/ue;->f(Lla/u;ZZLay0/k;)Ljava/lang/Object;

    .line 120
    .line 121
    .line 122
    :cond_4
    return-void
.end method

.method public final e()Z
    .locals 0

    .line 1
    const/4 p0, 0x1

    .line 2
    return p0
.end method

.method public final g(Lmb/o;I)V
    .locals 12

    .line 1
    iget-object v0, p0, Lhb/c;->f:Lhb/b;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 4
    .line 5
    .line 6
    iget-object v1, p1, Lmb/o;->j:Leb/e;

    .line 7
    .line 8
    new-instance v2, Landroid/os/PersistableBundle;

    .line 9
    .line 10
    invoke-direct {v2}, Landroid/os/PersistableBundle;-><init>()V

    .line 11
    .line 12
    .line 13
    iget-object v3, p1, Lmb/o;->a:Ljava/lang/String;

    .line 14
    .line 15
    const-string v4, "EXTRA_WORK_SPEC_ID"

    .line 16
    .line 17
    invoke-virtual {v2, v4, v3}, Landroid/os/BaseBundle;->putString(Ljava/lang/String;Ljava/lang/String;)V

    .line 18
    .line 19
    .line 20
    const-string v4, "EXTRA_WORK_SPEC_GENERATION"

    .line 21
    .line 22
    iget v5, p1, Lmb/o;->t:I

    .line 23
    .line 24
    invoke-virtual {v2, v4, v5}, Landroid/os/BaseBundle;->putInt(Ljava/lang/String;I)V

    .line 25
    .line 26
    .line 27
    const-string v4, "EXTRA_IS_PERIODIC"

    .line 28
    .line 29
    invoke-virtual {p1}, Lmb/o;->b()Z

    .line 30
    .line 31
    .line 32
    move-result v5

    .line 33
    invoke-virtual {v2, v4, v5}, Landroid/os/BaseBundle;->putBoolean(Ljava/lang/String;Z)V

    .line 34
    .line 35
    .line 36
    new-instance v4, Landroid/app/job/JobInfo$Builder;

    .line 37
    .line 38
    iget-object v5, v0, Lhb/b;->a:Landroid/content/ComponentName;

    .line 39
    .line 40
    invoke-direct {v4, p2, v5}, Landroid/app/job/JobInfo$Builder;-><init>(ILandroid/content/ComponentName;)V

    .line 41
    .line 42
    .line 43
    iget-boolean v5, v1, Leb/e;->c:Z

    .line 44
    .line 45
    invoke-virtual {v4, v5}, Landroid/app/job/JobInfo$Builder;->setRequiresCharging(Z)Landroid/app/job/JobInfo$Builder;

    .line 46
    .line 47
    .line 48
    move-result-object v4

    .line 49
    iget-boolean v5, v1, Leb/e;->d:Z

    .line 50
    .line 51
    invoke-virtual {v4, v5}, Landroid/app/job/JobInfo$Builder;->setRequiresDeviceIdle(Z)Landroid/app/job/JobInfo$Builder;

    .line 52
    .line 53
    .line 54
    move-result-object v4

    .line 55
    invoke-virtual {v4, v2}, Landroid/app/job/JobInfo$Builder;->setExtras(Landroid/os/PersistableBundle;)Landroid/app/job/JobInfo$Builder;

    .line 56
    .line 57
    .line 58
    move-result-object v2

    .line 59
    invoke-virtual {v1}, Leb/e;->a()Landroid/net/NetworkRequest;

    .line 60
    .line 61
    .line 62
    move-result-object v4

    .line 63
    sget v6, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 64
    .line 65
    const/4 v7, 0x0

    .line 66
    const/4 v8, 0x1

    .line 67
    if-eqz v4, :cond_0

    .line 68
    .line 69
    const-string v6, "builder"

    .line 70
    .line 71
    invoke-static {v2, v6}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 72
    .line 73
    .line 74
    invoke-virtual {v2, v4}, Landroid/app/job/JobInfo$Builder;->setRequiredNetwork(Landroid/net/NetworkRequest;)Landroid/app/job/JobInfo$Builder;

    .line 75
    .line 76
    .line 77
    goto :goto_1

    .line 78
    :cond_0
    iget-object v4, v1, Leb/e;->a:Leb/x;

    .line 79
    .line 80
    const/16 v9, 0x1e

    .line 81
    .line 82
    if-lt v6, v9, :cond_1

    .line 83
    .line 84
    sget-object v6, Leb/x;->i:Leb/x;

    .line 85
    .line 86
    if-ne v4, v6, :cond_1

    .line 87
    .line 88
    new-instance v4, Landroid/net/NetworkRequest$Builder;

    .line 89
    .line 90
    invoke-direct {v4}, Landroid/net/NetworkRequest$Builder;-><init>()V

    .line 91
    .line 92
    .line 93
    const/16 v6, 0x19

    .line 94
    .line 95
    invoke-virtual {v4, v6}, Landroid/net/NetworkRequest$Builder;->addCapability(I)Landroid/net/NetworkRequest$Builder;

    .line 96
    .line 97
    .line 98
    move-result-object v4

    .line 99
    invoke-virtual {v4}, Landroid/net/NetworkRequest$Builder;->build()Landroid/net/NetworkRequest;

    .line 100
    .line 101
    .line 102
    move-result-object v4

    .line 103
    invoke-virtual {v2, v4}, Landroid/app/job/JobInfo$Builder;->setRequiredNetwork(Landroid/net/NetworkRequest;)Landroid/app/job/JobInfo$Builder;

    .line 104
    .line 105
    .line 106
    goto :goto_1

    .line 107
    :cond_1
    invoke-virtual {v4}, Ljava/lang/Enum;->ordinal()I

    .line 108
    .line 109
    .line 110
    move-result v6

    .line 111
    if-eqz v6, :cond_3

    .line 112
    .line 113
    if-eq v6, v8, :cond_2

    .line 114
    .line 115
    const/4 v9, 0x2

    .line 116
    if-eq v6, v9, :cond_4

    .line 117
    .line 118
    const/4 v9, 0x3

    .line 119
    if-eq v6, v9, :cond_4

    .line 120
    .line 121
    const/4 v9, 0x4

    .line 122
    if-eq v6, v9, :cond_4

    .line 123
    .line 124
    invoke-static {}, Leb/w;->d()Leb/w;

    .line 125
    .line 126
    .line 127
    move-result-object v6

    .line 128
    sget-object v9, Lhb/b;->d:Ljava/lang/String;

    .line 129
    .line 130
    new-instance v10, Ljava/lang/StringBuilder;

    .line 131
    .line 132
    const-string v11, "API version too low. Cannot convert network type value "

    .line 133
    .line 134
    invoke-direct {v10, v11}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 135
    .line 136
    .line 137
    invoke-virtual {v10, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 138
    .line 139
    .line 140
    invoke-virtual {v10}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 141
    .line 142
    .line 143
    move-result-object v4

    .line 144
    invoke-virtual {v6, v9, v4}, Leb/w;->a(Ljava/lang/String;Ljava/lang/String;)V

    .line 145
    .line 146
    .line 147
    :cond_2
    move v9, v8

    .line 148
    goto :goto_0

    .line 149
    :cond_3
    move v9, v7

    .line 150
    :cond_4
    :goto_0
    invoke-virtual {v2, v9}, Landroid/app/job/JobInfo$Builder;->setRequiredNetworkType(I)Landroid/app/job/JobInfo$Builder;

    .line 151
    .line 152
    .line 153
    :goto_1
    if-nez v5, :cond_6

    .line 154
    .line 155
    iget-object v4, p1, Lmb/o;->l:Leb/a;

    .line 156
    .line 157
    sget-object v5, Leb/a;->e:Leb/a;

    .line 158
    .line 159
    if-ne v4, v5, :cond_5

    .line 160
    .line 161
    move v4, v7

    .line 162
    goto :goto_2

    .line 163
    :cond_5
    move v4, v8

    .line 164
    :goto_2
    iget-wide v5, p1, Lmb/o;->m:J

    .line 165
    .line 166
    invoke-virtual {v2, v5, v6, v4}, Landroid/app/job/JobInfo$Builder;->setBackoffCriteria(JI)Landroid/app/job/JobInfo$Builder;

    .line 167
    .line 168
    .line 169
    :cond_6
    invoke-virtual {p1}, Lmb/o;->a()J

    .line 170
    .line 171
    .line 172
    move-result-wide v4

    .line 173
    iget-object v6, v0, Lhb/b;->b:Leb/j;

    .line 174
    .line 175
    invoke-virtual {v6}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 176
    .line 177
    .line 178
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    .line 179
    .line 180
    .line 181
    move-result-wide v9

    .line 182
    sub-long/2addr v4, v9

    .line 183
    const-wide/16 v9, 0x0

    .line 184
    .line 185
    invoke-static {v4, v5, v9, v10}, Ljava/lang/Math;->max(JJ)J

    .line 186
    .line 187
    .line 188
    move-result-wide v4

    .line 189
    cmp-long v6, v4, v9

    .line 190
    .line 191
    if-lez v6, :cond_7

    .line 192
    .line 193
    invoke-virtual {v2, v4, v5}, Landroid/app/job/JobInfo$Builder;->setMinimumLatency(J)Landroid/app/job/JobInfo$Builder;

    .line 194
    .line 195
    .line 196
    goto :goto_3

    .line 197
    :cond_7
    iget-boolean v4, p1, Lmb/o;->q:Z

    .line 198
    .line 199
    if-nez v4, :cond_8

    .line 200
    .line 201
    iget-boolean v0, v0, Lhb/b;->c:Z

    .line 202
    .line 203
    if-eqz v0, :cond_8

    .line 204
    .line 205
    invoke-virtual {v2, v8}, Landroid/app/job/JobInfo$Builder;->setImportantWhileForeground(Z)Landroid/app/job/JobInfo$Builder;

    .line 206
    .line 207
    .line 208
    :cond_8
    :goto_3
    invoke-virtual {v1}, Leb/e;->b()Z

    .line 209
    .line 210
    .line 211
    move-result v0

    .line 212
    if-eqz v0, :cond_a

    .line 213
    .line 214
    iget-object v0, v1, Leb/e;->i:Ljava/util/Set;

    .line 215
    .line 216
    invoke-interface {v0}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 217
    .line 218
    .line 219
    move-result-object v0

    .line 220
    :goto_4
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 221
    .line 222
    .line 223
    move-result v4

    .line 224
    if-eqz v4, :cond_9

    .line 225
    .line 226
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 227
    .line 228
    .line 229
    move-result-object v4

    .line 230
    check-cast v4, Leb/d;

    .line 231
    .line 232
    iget-boolean v5, v4, Leb/d;->b:Z

    .line 233
    .line 234
    new-instance v9, Landroid/app/job/JobInfo$TriggerContentUri;

    .line 235
    .line 236
    iget-object v4, v4, Leb/d;->a:Landroid/net/Uri;

    .line 237
    .line 238
    invoke-direct {v9, v4, v5}, Landroid/app/job/JobInfo$TriggerContentUri;-><init>(Landroid/net/Uri;I)V

    .line 239
    .line 240
    .line 241
    invoke-virtual {v2, v9}, Landroid/app/job/JobInfo$Builder;->addTriggerContentUri(Landroid/app/job/JobInfo$TriggerContentUri;)Landroid/app/job/JobInfo$Builder;

    .line 242
    .line 243
    .line 244
    goto :goto_4

    .line 245
    :cond_9
    iget-wide v4, v1, Leb/e;->g:J

    .line 246
    .line 247
    invoke-virtual {v2, v4, v5}, Landroid/app/job/JobInfo$Builder;->setTriggerContentUpdateDelay(J)Landroid/app/job/JobInfo$Builder;

    .line 248
    .line 249
    .line 250
    iget-wide v4, v1, Leb/e;->h:J

    .line 251
    .line 252
    invoke-virtual {v2, v4, v5}, Landroid/app/job/JobInfo$Builder;->setTriggerContentMaxDelay(J)Landroid/app/job/JobInfo$Builder;

    .line 253
    .line 254
    .line 255
    :cond_a
    invoke-virtual {v2, v7}, Landroid/app/job/JobInfo$Builder;->setPersisted(Z)Landroid/app/job/JobInfo$Builder;

    .line 256
    .line 257
    .line 258
    sget v0, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 259
    .line 260
    iget-boolean v4, v1, Leb/e;->e:Z

    .line 261
    .line 262
    invoke-virtual {v2, v4}, Landroid/app/job/JobInfo$Builder;->setRequiresBatteryNotLow(Z)Landroid/app/job/JobInfo$Builder;

    .line 263
    .line 264
    .line 265
    iget-boolean v1, v1, Leb/e;->f:Z

    .line 266
    .line 267
    invoke-virtual {v2, v1}, Landroid/app/job/JobInfo$Builder;->setRequiresStorageNotLow(Z)Landroid/app/job/JobInfo$Builder;

    .line 268
    .line 269
    .line 270
    iget v1, p1, Lmb/o;->k:I

    .line 271
    .line 272
    if-lez v1, :cond_b

    .line 273
    .line 274
    move v1, v8

    .line 275
    goto :goto_5

    .line 276
    :cond_b
    move v1, v7

    .line 277
    :goto_5
    if-lez v6, :cond_c

    .line 278
    .line 279
    move v4, v8

    .line 280
    goto :goto_6

    .line 281
    :cond_c
    move v4, v7

    .line 282
    :goto_6
    const/16 v5, 0x1f

    .line 283
    .line 284
    if-lt v0, v5, :cond_d

    .line 285
    .line 286
    iget-boolean v6, p1, Lmb/o;->q:Z

    .line 287
    .line 288
    if-eqz v6, :cond_d

    .line 289
    .line 290
    if-nez v1, :cond_d

    .line 291
    .line 292
    if-nez v4, :cond_d

    .line 293
    .line 294
    invoke-static {v2}, Lh4/b;->p(Landroid/app/job/JobInfo$Builder;)V

    .line 295
    .line 296
    .line 297
    :cond_d
    const/16 v1, 0x23

    .line 298
    .line 299
    if-lt v0, v1, :cond_e

    .line 300
    .line 301
    iget-object v0, p1, Lmb/o;->x:Ljava/lang/String;

    .line 302
    .line 303
    if-eqz v0, :cond_e

    .line 304
    .line 305
    invoke-static {v2, v0}, Lf8/a;->d(Landroid/app/job/JobInfo$Builder;Ljava/lang/String;)V

    .line 306
    .line 307
    .line 308
    :cond_e
    invoke-virtual {v2}, Landroid/app/job/JobInfo$Builder;->build()Landroid/app/job/JobInfo;

    .line 309
    .line 310
    .line 311
    move-result-object v0

    .line 312
    invoke-static {}, Leb/w;->d()Leb/w;

    .line 313
    .line 314
    .line 315
    move-result-object v1

    .line 316
    new-instance v2, Ljava/lang/StringBuilder;

    .line 317
    .line 318
    const-string v4, "Scheduling work ID "

    .line 319
    .line 320
    invoke-direct {v2, v4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 321
    .line 322
    .line 323
    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 324
    .line 325
    .line 326
    const-string v4, "Job ID "

    .line 327
    .line 328
    invoke-virtual {v2, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 329
    .line 330
    .line 331
    invoke-virtual {v2, p2}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 332
    .line 333
    .line 334
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 335
    .line 336
    .line 337
    move-result-object v2

    .line 338
    sget-object v4, Lhb/c;->i:Ljava/lang/String;

    .line 339
    .line 340
    invoke-virtual {v1, v4, v2}, Leb/w;->a(Ljava/lang/String;Ljava/lang/String;)V

    .line 341
    .line 342
    .line 343
    :try_start_0
    iget-object v1, p0, Lhb/c;->e:Landroid/app/job/JobScheduler;

    .line 344
    .line 345
    invoke-virtual {v1, v0}, Landroid/app/job/JobScheduler;->schedule(Landroid/app/job/JobInfo;)I

    .line 346
    .line 347
    .line 348
    move-result v0

    .line 349
    if-nez v0, :cond_f

    .line 350
    .line 351
    invoke-static {}, Leb/w;->d()Leb/w;

    .line 352
    .line 353
    .line 354
    move-result-object v0

    .line 355
    new-instance v1, Ljava/lang/StringBuilder;

    .line 356
    .line 357
    invoke-direct {v1}, Ljava/lang/StringBuilder;-><init>()V

    .line 358
    .line 359
    .line 360
    const-string v2, "Unable to schedule work ID "

    .line 361
    .line 362
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 363
    .line 364
    .line 365
    invoke-virtual {v1, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 366
    .line 367
    .line 368
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 369
    .line 370
    .line 371
    move-result-object v1

    .line 372
    invoke-virtual {v0, v4, v1}, Leb/w;->g(Ljava/lang/String;Ljava/lang/String;)V

    .line 373
    .line 374
    .line 375
    iget-boolean v0, p1, Lmb/o;->q:Z

    .line 376
    .line 377
    if-eqz v0, :cond_f

    .line 378
    .line 379
    iget-object v0, p1, Lmb/o;->r:Leb/e0;

    .line 380
    .line 381
    sget-object v1, Leb/e0;->d:Leb/e0;

    .line 382
    .line 383
    if-ne v0, v1, :cond_f

    .line 384
    .line 385
    iput-boolean v7, p1, Lmb/o;->q:Z

    .line 386
    .line 387
    new-instance v0, Ljava/lang/StringBuilder;

    .line 388
    .line 389
    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    .line 390
    .line 391
    .line 392
    const-string v1, "Scheduling a non-expedited job (work ID "

    .line 393
    .line 394
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 395
    .line 396
    .line 397
    invoke-virtual {v0, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 398
    .line 399
    .line 400
    const-string v1, ")"

    .line 401
    .line 402
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 403
    .line 404
    .line 405
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 406
    .line 407
    .line 408
    move-result-object v0

    .line 409
    invoke-static {}, Leb/w;->d()Leb/w;

    .line 410
    .line 411
    .line 412
    move-result-object v1

    .line 413
    invoke-virtual {v1, v4, v0}, Leb/w;->a(Ljava/lang/String;Ljava/lang/String;)V

    .line 414
    .line 415
    .line 416
    invoke-virtual {p0, p1, p2}, Lhb/c;->g(Lmb/o;I)V
    :try_end_0
    .catch Ljava/lang/IllegalStateException; {:try_start_0 .. :try_end_0} :catch_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 417
    .line 418
    .line 419
    return-void

    .line 420
    :catchall_0
    move-exception v0

    .line 421
    move-object p0, v0

    .line 422
    goto :goto_7

    .line 423
    :catch_0
    move-exception v0

    .line 424
    move-object p1, v0

    .line 425
    goto :goto_8

    .line 426
    :cond_f
    return-void

    .line 427
    :goto_7
    invoke-static {}, Leb/w;->d()Leb/w;

    .line 428
    .line 429
    .line 430
    move-result-object p2

    .line 431
    new-instance v0, Ljava/lang/StringBuilder;

    .line 432
    .line 433
    const-string v1, "Unable to schedule "

    .line 434
    .line 435
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 436
    .line 437
    .line 438
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 439
    .line 440
    .line 441
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 442
    .line 443
    .line 444
    move-result-object p1

    .line 445
    invoke-virtual {p2, v4, p1, p0}, Leb/w;->c(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 446
    .line 447
    .line 448
    return-void

    .line 449
    :goto_8
    sget-object p2, Lhb/a;->a:Ljava/lang/String;

    .line 450
    .line 451
    const-string p2, "context"

    .line 452
    .line 453
    iget-object v0, p0, Lhb/c;->d:Landroid/content/Context;

    .line 454
    .line 455
    invoke-static {v0, p2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 456
    .line 457
    .line 458
    const-string p2, "workDatabase"

    .line 459
    .line 460
    iget-object v1, p0, Lhb/c;->g:Landroidx/work/impl/WorkDatabase;

    .line 461
    .line 462
    invoke-static {v1, p2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 463
    .line 464
    .line 465
    const-string p2, "configuration"

    .line 466
    .line 467
    iget-object p0, p0, Lhb/c;->h:Leb/b;

    .line 468
    .line 469
    invoke-static {p0, p2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 470
    .line 471
    .line 472
    sget p2, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 473
    .line 474
    if-lt p2, v5, :cond_10

    .line 475
    .line 476
    const/16 v2, 0x96

    .line 477
    .line 478
    goto :goto_9

    .line 479
    :cond_10
    const/16 v2, 0x64

    .line 480
    .line 481
    :goto_9
    invoke-virtual {v1}, Landroidx/work/impl/WorkDatabase;->x()Lmb/s;

    .line 482
    .line 483
    .line 484
    move-result-object v1

    .line 485
    iget-object v1, v1, Lmb/s;->a:Lla/u;

    .line 486
    .line 487
    new-instance v3, Lm40/e;

    .line 488
    .line 489
    const/16 v5, 0xc

    .line 490
    .line 491
    invoke-direct {v3, v5}, Lm40/e;-><init>(I)V

    .line 492
    .line 493
    .line 494
    invoke-static {v1, v8, v7, v3}, Ljp/ue;->f(Lla/u;ZZLay0/k;)Ljava/lang/Object;

    .line 495
    .line 496
    .line 497
    move-result-object v1

    .line 498
    check-cast v1, Ljava/util/List;

    .line 499
    .line 500
    invoke-interface {v1}, Ljava/util/List;->size()I

    .line 501
    .line 502
    .line 503
    move-result v1

    .line 504
    const/16 v3, 0x22

    .line 505
    .line 506
    const-string v5, "<faulty JobScheduler failed to getPendingJobs>"

    .line 507
    .line 508
    if-lt p2, v3, :cond_15

    .line 509
    .line 510
    invoke-static {v0}, Lhb/a;->b(Landroid/content/Context;)Landroid/app/job/JobScheduler;

    .line 511
    .line 512
    .line 513
    move-result-object p2

    .line 514
    invoke-static {p2}, Lhb/a;->a(Landroid/app/job/JobScheduler;)Ljava/util/List;

    .line 515
    .line 516
    .line 517
    move-result-object v3

    .line 518
    if-eqz v3, :cond_17

    .line 519
    .line 520
    invoke-static {v0, p2}, Lhb/c;->d(Landroid/content/Context;Landroid/app/job/JobScheduler;)Ljava/util/ArrayList;

    .line 521
    .line 522
    .line 523
    move-result-object p2

    .line 524
    if-eqz p2, :cond_11

    .line 525
    .line 526
    invoke-interface {v3}, Ljava/util/List;->size()I

    .line 527
    .line 528
    .line 529
    move-result v5

    .line 530
    invoke-virtual {p2}, Ljava/util/ArrayList;->size()I

    .line 531
    .line 532
    .line 533
    move-result p2

    .line 534
    sub-int/2addr v5, p2

    .line 535
    goto :goto_a

    .line 536
    :cond_11
    move v5, v7

    .line 537
    :goto_a
    const/4 p2, 0x0

    .line 538
    if-nez v5, :cond_12

    .line 539
    .line 540
    move-object v5, p2

    .line 541
    goto :goto_b

    .line 542
    :cond_12
    const-string v6, " of which are not owned by WorkManager"

    .line 543
    .line 544
    invoke-static {v5, v6}, Lp3/m;->e(ILjava/lang/String;)Ljava/lang/String;

    .line 545
    .line 546
    .line 547
    move-result-object v5

    .line 548
    :goto_b
    const-string v6, "jobscheduler"

    .line 549
    .line 550
    invoke-virtual {v0, v6}, Landroid/content/Context;->getSystemService(Ljava/lang/String;)Ljava/lang/Object;

    .line 551
    .line 552
    .line 553
    move-result-object v6

    .line 554
    const-string v8, "null cannot be cast to non-null type android.app.job.JobScheduler"

    .line 555
    .line 556
    invoke-static {v6, v8}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 557
    .line 558
    .line 559
    check-cast v6, Landroid/app/job/JobScheduler;

    .line 560
    .line 561
    invoke-static {v0, v6}, Lhb/c;->d(Landroid/content/Context;Landroid/app/job/JobScheduler;)Ljava/util/ArrayList;

    .line 562
    .line 563
    .line 564
    move-result-object v0

    .line 565
    if-eqz v0, :cond_13

    .line 566
    .line 567
    invoke-virtual {v0}, Ljava/util/ArrayList;->size()I

    .line 568
    .line 569
    .line 570
    move-result v7

    .line 571
    :cond_13
    if-nez v7, :cond_14

    .line 572
    .line 573
    goto :goto_c

    .line 574
    :cond_14
    const-string p2, " from WorkManager in the default namespace"

    .line 575
    .line 576
    invoke-static {v7, p2}, Lp3/m;->e(ILjava/lang/String;)Ljava/lang/String;

    .line 577
    .line 578
    .line 579
    move-result-object p2

    .line 580
    :goto_c
    new-instance v0, Ljava/lang/StringBuilder;

    .line 581
    .line 582
    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    .line 583
    .line 584
    .line 585
    invoke-interface {v3}, Ljava/util/List;->size()I

    .line 586
    .line 587
    .line 588
    move-result v3

    .line 589
    invoke-virtual {v0, v3}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 590
    .line 591
    .line 592
    const-string v3, " jobs in \"androidx.work.systemjobscheduler\" namespace"

    .line 593
    .line 594
    invoke-virtual {v0, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 595
    .line 596
    .line 597
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 598
    .line 599
    .line 600
    move-result-object v0

    .line 601
    filled-new-array {v0, v5, p2}, [Ljava/lang/String;

    .line 602
    .line 603
    .line 604
    move-result-object p2

    .line 605
    invoke-static {p2}, Lmx0/n;->t([Ljava/lang/Object;)Ljava/util/List;

    .line 606
    .line 607
    .line 608
    move-result-object v5

    .line 609
    const/4 v9, 0x0

    .line 610
    const/16 v10, 0x3e

    .line 611
    .line 612
    const-string v6, ",\n"

    .line 613
    .line 614
    const/4 v7, 0x0

    .line 615
    const/4 v8, 0x0

    .line 616
    invoke-static/range {v5 .. v10}, Lmx0/q;->R(Ljava/lang/Iterable;Ljava/lang/CharSequence;Ljava/lang/String;Ljava/lang/String;Lay0/k;I)Ljava/lang/String;

    .line 617
    .line 618
    .line 619
    move-result-object v5

    .line 620
    goto :goto_d

    .line 621
    :cond_15
    invoke-static {v0}, Lhb/a;->b(Landroid/content/Context;)Landroid/app/job/JobScheduler;

    .line 622
    .line 623
    .line 624
    move-result-object p2

    .line 625
    invoke-static {v0, p2}, Lhb/c;->d(Landroid/content/Context;Landroid/app/job/JobScheduler;)Ljava/util/ArrayList;

    .line 626
    .line 627
    .line 628
    move-result-object p2

    .line 629
    if-nez p2, :cond_16

    .line 630
    .line 631
    goto :goto_d

    .line 632
    :cond_16
    new-instance v0, Ljava/lang/StringBuilder;

    .line 633
    .line 634
    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    .line 635
    .line 636
    .line 637
    invoke-virtual {p2}, Ljava/util/ArrayList;->size()I

    .line 638
    .line 639
    .line 640
    move-result p2

    .line 641
    invoke-virtual {v0, p2}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 642
    .line 643
    .line 644
    const-string p2, " jobs from WorkManager"

    .line 645
    .line 646
    invoke-virtual {v0, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 647
    .line 648
    .line 649
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 650
    .line 651
    .line 652
    move-result-object v5

    .line 653
    :cond_17
    :goto_d
    const-string p2, " job limit exceeded.\nIn JobScheduler there are "

    .line 654
    .line 655
    const-string v0, ".\nThere are "

    .line 656
    .line 657
    const-string v3, "JobScheduler "

    .line 658
    .line 659
    invoke-static {v3, v2, p2, v5, v0}, Lf2/m0;->o(Ljava/lang/String;ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 660
    .line 661
    .line 662
    move-result-object p2

    .line 663
    invoke-virtual {p2, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 664
    .line 665
    .line 666
    const-string v0, " jobs tracked by WorkManager\'s database;\nthe Configuration limit is "

    .line 667
    .line 668
    invoke-virtual {p2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 669
    .line 670
    .line 671
    iget p0, p0, Leb/b;->k:I

    .line 672
    .line 673
    const/16 v0, 0x2e

    .line 674
    .line 675
    invoke-static {p2, p0, v0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->m(Ljava/lang/StringBuilder;IC)Ljava/lang/String;

    .line 676
    .line 677
    .line 678
    move-result-object p0

    .line 679
    invoke-static {}, Leb/w;->d()Leb/w;

    .line 680
    .line 681
    .line 682
    move-result-object p2

    .line 683
    invoke-virtual {p2, v4, p0}, Leb/w;->b(Ljava/lang/String;Ljava/lang/String;)V

    .line 684
    .line 685
    .line 686
    new-instance p2, Ljava/lang/IllegalStateException;

    .line 687
    .line 688
    invoke-direct {p2, p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 689
    .line 690
    .line 691
    throw p2
.end method
