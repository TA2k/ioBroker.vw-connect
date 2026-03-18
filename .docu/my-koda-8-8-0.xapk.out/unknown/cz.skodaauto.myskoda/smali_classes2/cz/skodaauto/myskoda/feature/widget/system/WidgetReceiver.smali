.class public final Lcz/skodaauto/myskoda/feature/widget/system/WidgetReceiver;
.super La7/z0;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ly11/a;


# annotations
.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\u0010\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0003\u0008\u0001\u0018\u00002\u00020\u00012\u00020\u0002B\u0007\u00a2\u0006\u0004\u0008\u0003\u0010\u0004\u00a8\u0006\u0005"
    }
    d2 = {
        "Lcz/skodaauto/myskoda/feature/widget/system/WidgetReceiver;",
        "Ly11/a;",
        "La7/z0;",
        "<init>",
        "()V",
        "widget_release"
    }
    k = 0x1
    mv = {
        0x2,
        0x2,
        0x0
    }
    xi = 0x30
.end annotation


# static fields
.field public static final g:Ljava/time/Duration;


# instance fields
.field public final e:Ljava/lang/Object;

.field public final f:Lza0/q;


# direct methods
.method static constructor <clinit>()V
    .locals 4

    .line 1
    sget v0, Lmy0/c;->g:I

    .line 2
    .line 3
    const/16 v0, 0x1f

    .line 4
    .line 5
    sget-object v1, Lmy0/e;->i:Lmy0/e;

    .line 6
    .line 7
    invoke-static {v0, v1}, Lmy0/h;->s(ILmy0/e;)J

    .line 8
    .line 9
    .line 10
    move-result-wide v0

    .line 11
    sget-object v2, Lmy0/e;->h:Lmy0/e;

    .line 12
    .line 13
    invoke-static {v0, v1, v2}, Lmy0/c;->n(JLmy0/e;)J

    .line 14
    .line 15
    .line 16
    move-result-wide v2

    .line 17
    invoke-static {v0, v1}, Lmy0/c;->f(J)I

    .line 18
    .line 19
    .line 20
    move-result v0

    .line 21
    int-to-long v0, v0

    .line 22
    invoke-static {v2, v3, v0, v1}, Ljava/time/Duration;->ofSeconds(JJ)Ljava/time/Duration;

    .line 23
    .line 24
    .line 25
    move-result-object v0

    .line 26
    const-string v1, "toComponents-impl(...)"

    .line 27
    .line 28
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 29
    .line 30
    .line 31
    sput-object v0, Lcz/skodaauto/myskoda/feature/widget/system/WidgetReceiver;->g:Ljava/time/Duration;

    .line 32
    .line 33
    return-void
.end method

.method public constructor <init>()V
    .locals 3

    .line 1
    invoke-direct {p0}, La7/z0;-><init>()V

    .line 2
    .line 3
    .line 4
    sget-object v0, Llx0/j;->d:Llx0/j;

    .line 5
    .line 6
    new-instance v1, Lbp0/h;

    .line 7
    .line 8
    const/16 v2, 0x12

    .line 9
    .line 10
    invoke-direct {v1, p0, v2}, Lbp0/h;-><init>(Ly11/a;I)V

    .line 11
    .line 12
    .line 13
    invoke-static {v0, v1}, Lpm/a;->c(Llx0/j;Lay0/a;)Llx0/i;

    .line 14
    .line 15
    .line 16
    move-result-object v0

    .line 17
    iput-object v0, p0, Lcz/skodaauto/myskoda/feature/widget/system/WidgetReceiver;->e:Ljava/lang/Object;

    .line 18
    .line 19
    new-instance v0, Lza0/q;

    .line 20
    .line 21
    invoke-direct {v0}, Lza0/q;-><init>()V

    .line 22
    .line 23
    .line 24
    iput-object v0, p0, Lcz/skodaauto/myskoda/feature/widget/system/WidgetReceiver;->f:Lza0/q;

    .line 25
    .line 26
    return-void
.end method


# virtual methods
.method public final bridge b()Landroidx/lifecycle/c1;
    .locals 0

    .line 1
    invoke-static {}, Llp/qf;->a()Landroidx/lifecycle/c1;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public final onDisabled(Landroid/content/Context;)V
    .locals 4

    .line 1
    const-string v0, "context"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    sget-object v0, Lge0/a;->d:Lge0/a;

    .line 7
    .line 8
    new-instance v1, Lyj0/c;

    .line 9
    .line 10
    const/4 v2, 0x6

    .line 11
    const/4 v3, 0x0

    .line 12
    invoke-direct {v1, p0, v3, v2}, Lyj0/c;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 13
    .line 14
    .line 15
    const/4 p0, 0x3

    .line 16
    invoke-static {v0, v3, v3, v1, p0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 17
    .line 18
    .line 19
    invoke-static {p1}, Lfb/u;->f(Landroid/content/Context;)Lfb/u;

    .line 20
    .line 21
    .line 22
    move-result-object p0

    .line 23
    iget-object p1, p0, Lfb/u;->b:Leb/b;

    .line 24
    .line 25
    iget-object p1, p1, Leb/b;->m:Leb/j;

    .line 26
    .line 27
    const-string v0, "CancelWorkByName_"

    .line 28
    .line 29
    const-string v1, "widget_worker"

    .line 30
    .line 31
    invoke-virtual {v0, v1}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 32
    .line 33
    .line 34
    move-result-object v0

    .line 35
    iget-object v1, p0, Lfb/u;->d:Lob/a;

    .line 36
    .line 37
    iget-object v1, v1, Lob/a;->a:Lla/a0;

    .line 38
    .line 39
    const-string v2, "getSerialTaskExecutor(...)"

    .line 40
    .line 41
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 42
    .line 43
    .line 44
    new-instance v2, Lfb/t;

    .line 45
    .line 46
    const/4 v3, 0x1

    .line 47
    invoke-direct {v2, p0, v3}, Lfb/t;-><init>(Lfb/u;I)V

    .line 48
    .line 49
    .line 50
    invoke-static {p1, v0, v1, v2}, Lkp/e6;->b(Leb/j;Ljava/lang/String;Ljava/util/concurrent/Executor;Lay0/a;)Leb/c0;

    .line 51
    .line 52
    .line 53
    return-void
.end method

.method public final onUpdate(Landroid/content/Context;Landroid/appwidget/AppWidgetManager;[I)V
    .locals 19

    .line 1
    const-string v0, "context"

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    invoke-static {v1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    const-string v0, "appWidgetManager"

    .line 9
    .line 10
    move-object/from16 v2, p2

    .line 11
    .line 12
    invoke-static {v2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 13
    .line 14
    .line 15
    const-string v0, "appWidgetIds"

    .line 16
    .line 17
    move-object/from16 v3, p3

    .line 18
    .line 19
    invoke-static {v3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 20
    .line 21
    .line 22
    invoke-super/range {p0 .. p3}, La7/z0;->onUpdate(Landroid/content/Context;Landroid/appwidget/AppWidgetManager;[I)V

    .line 23
    .line 24
    .line 25
    invoke-static {v1}, Lfb/u;->f(Landroid/content/Context;)Lfb/u;

    .line 26
    .line 27
    .line 28
    move-result-object v2

    .line 29
    new-instance v0, Lnb/d;

    .line 30
    .line 31
    sget-object v0, Leb/x;->d:Leb/x;

    .line 32
    .line 33
    new-instance v0, Ljava/util/LinkedHashSet;

    .line 34
    .line 35
    invoke-direct {v0}, Ljava/util/LinkedHashSet;-><init>()V

    .line 36
    .line 37
    .line 38
    sget-object v5, Leb/x;->e:Leb/x;

    .line 39
    .line 40
    new-instance v4, Lnb/d;

    .line 41
    .line 42
    const/4 v1, 0x0

    .line 43
    invoke-direct {v4, v1}, Lnb/d;-><init>(Landroid/net/NetworkRequest;)V

    .line 44
    .line 45
    .line 46
    invoke-static {v0}, Lmx0/q;->C0(Ljava/lang/Iterable;)Ljava/util/Set;

    .line 47
    .line 48
    .line 49
    move-result-object v14

    .line 50
    new-instance v3, Leb/e;

    .line 51
    .line 52
    const/4 v6, 0x0

    .line 53
    const/4 v7, 0x0

    .line 54
    const/4 v8, 0x0

    .line 55
    const/4 v9, 0x0

    .line 56
    const-wide/16 v10, -0x1

    .line 57
    .line 58
    move-wide v12, v10

    .line 59
    invoke-direct/range {v3 .. v14}, Leb/e;-><init>(Lnb/d;Leb/x;ZZZZJJLjava/util/Set;)V

    .line 60
    .line 61
    .line 62
    new-instance v0, Leb/y;

    .line 63
    .line 64
    const-string v1, "repeatInterval"

    .line 65
    .line 66
    sget-object v4, Lcz/skodaauto/myskoda/feature/widget/system/WidgetReceiver;->g:Ljava/time/Duration;

    .line 67
    .line 68
    invoke-static {v4, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 69
    .line 70
    .line 71
    const/4 v1, 0x1

    .line 72
    const-class v5, Lcz/skodaauto/myskoda/feature/widget/system/LocalWidgetWorker;

    .line 73
    .line 74
    invoke-direct {v0, v1, v5}, Leb/y;-><init>(ILjava/lang/Class;)V

    .line 75
    .line 76
    .line 77
    iget-object v1, v0, Leb/j0;->f:Ljava/lang/Object;

    .line 78
    .line 79
    check-cast v1, Lmb/o;

    .line 80
    .line 81
    invoke-virtual {v4}, Ljava/time/Duration;->toMillis()J

    .line 82
    .line 83
    .line 84
    move-result-wide v4

    .line 85
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 86
    .line 87
    .line 88
    sget-object v6, Lmb/o;->z:Ljava/lang/String;

    .line 89
    .line 90
    const-wide/32 v7, 0xdbba0

    .line 91
    .line 92
    .line 93
    cmp-long v9, v4, v7

    .line 94
    .line 95
    const-string v10, "Interval duration lesser than minimum allowed value; Changed to 900000"

    .line 96
    .line 97
    if-gez v9, :cond_0

    .line 98
    .line 99
    invoke-static {}, Leb/w;->d()Leb/w;

    .line 100
    .line 101
    .line 102
    move-result-object v11

    .line 103
    invoke-virtual {v11, v6, v10}, Leb/w;->g(Ljava/lang/String;Ljava/lang/String;)V

    .line 104
    .line 105
    .line 106
    :cond_0
    if-gez v9, :cond_1

    .line 107
    .line 108
    move-wide v11, v7

    .line 109
    goto :goto_0

    .line 110
    :cond_1
    move-wide v11, v4

    .line 111
    :goto_0
    if-gez v9, :cond_2

    .line 112
    .line 113
    move-wide v13, v7

    .line 114
    goto :goto_1

    .line 115
    :cond_2
    move-wide v13, v4

    .line 116
    :goto_1
    cmp-long v4, v11, v7

    .line 117
    .line 118
    if-gez v4, :cond_3

    .line 119
    .line 120
    invoke-static {}, Leb/w;->d()Leb/w;

    .line 121
    .line 122
    .line 123
    move-result-object v5

    .line 124
    invoke-virtual {v5, v6, v10}, Leb/w;->g(Ljava/lang/String;Ljava/lang/String;)V

    .line 125
    .line 126
    .line 127
    :cond_3
    if-gez v4, :cond_4

    .line 128
    .line 129
    goto :goto_2

    .line 130
    :cond_4
    move-wide v7, v11

    .line 131
    :goto_2
    iput-wide v7, v1, Lmb/o;->h:J

    .line 132
    .line 133
    const-wide/32 v4, 0x493e0

    .line 134
    .line 135
    .line 136
    cmp-long v4, v13, v4

    .line 137
    .line 138
    if-gez v4, :cond_5

    .line 139
    .line 140
    invoke-static {}, Leb/w;->d()Leb/w;

    .line 141
    .line 142
    .line 143
    move-result-object v4

    .line 144
    const-string v5, "Flex duration lesser than minimum allowed value; Changed to 300000"

    .line 145
    .line 146
    invoke-virtual {v4, v6, v5}, Leb/w;->g(Ljava/lang/String;Ljava/lang/String;)V

    .line 147
    .line 148
    .line 149
    :cond_5
    iget-wide v4, v1, Lmb/o;->h:J

    .line 150
    .line 151
    cmp-long v4, v13, v4

    .line 152
    .line 153
    if-lez v4, :cond_6

    .line 154
    .line 155
    invoke-static {}, Leb/w;->d()Leb/w;

    .line 156
    .line 157
    .line 158
    move-result-object v4

    .line 159
    new-instance v5, Ljava/lang/StringBuilder;

    .line 160
    .line 161
    const-string v7, "Flex duration greater than interval duration; Changed to "

    .line 162
    .line 163
    invoke-direct {v5, v7}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 164
    .line 165
    .line 166
    invoke-virtual {v5, v11, v12}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    .line 167
    .line 168
    .line 169
    invoke-virtual {v5}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 170
    .line 171
    .line 172
    move-result-object v5

    .line 173
    invoke-virtual {v4, v6, v5}, Leb/w;->g(Ljava/lang/String;Ljava/lang/String;)V

    .line 174
    .line 175
    .line 176
    :cond_6
    const-wide/32 v15, 0x493e0

    .line 177
    .line 178
    .line 179
    iget-wide v4, v1, Lmb/o;->h:J

    .line 180
    .line 181
    move-wide/from16 v17, v4

    .line 182
    .line 183
    invoke-static/range {v13 .. v18}, Lkp/r9;->g(JJJ)J

    .line 184
    .line 185
    .line 186
    move-result-wide v4

    .line 187
    iput-wide v4, v1, Lmb/o;->i:J

    .line 188
    .line 189
    iget-object v1, v0, Leb/j0;->f:Ljava/lang/Object;

    .line 190
    .line 191
    check-cast v1, Lmb/o;

    .line 192
    .line 193
    iput-object v3, v1, Lmb/o;->j:Leb/e;

    .line 194
    .line 195
    invoke-virtual {v0}, Leb/j0;->h()Leb/k0;

    .line 196
    .line 197
    .line 198
    move-result-object v0

    .line 199
    check-cast v0, Leb/f0;

    .line 200
    .line 201
    sget-object v1, Leb/l;->d:[Leb/l;

    .line 202
    .line 203
    sget-object v4, Leb/m;->e:Leb/m;

    .line 204
    .line 205
    new-instance v1, Lfb/o;

    .line 206
    .line 207
    invoke-static {v0}, Ljava/util/Collections;->singletonList(Ljava/lang/Object;)Ljava/util/List;

    .line 208
    .line 209
    .line 210
    move-result-object v5

    .line 211
    const/4 v6, 0x0

    .line 212
    const-string v3, "widget_worker"

    .line 213
    .line 214
    invoke-direct/range {v1 .. v6}, Lfb/o;-><init>(Lfb/u;Ljava/lang/String;Leb/m;Ljava/util/List;I)V

    .line 215
    .line 216
    .line 217
    invoke-virtual {v1}, Lfb/o;->d()Leb/c0;

    .line 218
    .line 219
    .line 220
    return-void
.end method
