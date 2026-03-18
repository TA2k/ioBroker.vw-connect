.class public final La7/b1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Landroid/widget/RemoteViewsService$RemoteViewsFactory;


# instance fields
.field public final a:Landroidx/glance/appwidget/GlanceRemoteViewsService;

.field public final b:I

.field public final c:I

.field public final d:Ljava/lang/String;


# direct methods
.method public constructor <init>(Landroidx/glance/appwidget/GlanceRemoteViewsService;IILjava/lang/String;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, La7/b1;->a:Landroidx/glance/appwidget/GlanceRemoteViewsService;

    .line 5
    .line 6
    iput p2, p0, La7/b1;->b:I

    .line 7
    .line 8
    iput p3, p0, La7/b1;->c:I

    .line 9
    .line 10
    iput-object p4, p0, La7/b1;->d:Ljava/lang/String;

    .line 11
    .line 12
    return-void
.end method

.method public static final a(La7/b1;La7/c;Lrx0/c;)Ljava/lang/Object;
    .locals 12

    .line 1
    instance-of v0, p2, La7/a1;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p2

    .line 6
    check-cast v0, La7/a1;

    .line 7
    .line 8
    iget v1, v0, La7/a1;->g:I

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
    iput v1, v0, La7/a1;->g:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, La7/a1;

    .line 21
    .line 22
    invoke-direct {v0, p0, p2}, La7/a1;-><init>(La7/b1;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p2, v0, La7/a1;->e:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, La7/a1;->g:I

    .line 30
    .line 31
    sget-object v3, Llx0/b0;->a:Llx0/b0;

    .line 32
    .line 33
    const/4 v4, 0x3

    .line 34
    const/4 v5, 0x1

    .line 35
    const/4 v11, 0x0

    .line 36
    if-eqz v2, :cond_4

    .line 37
    .line 38
    if-eq v2, v5, :cond_3

    .line 39
    .line 40
    const/4 p0, 0x2

    .line 41
    if-eq v2, p0, :cond_2

    .line 42
    .line 43
    if-ne v2, v4, :cond_1

    .line 44
    .line 45
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 46
    .line 47
    .line 48
    return-object v3

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
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 58
    .line 59
    .line 60
    check-cast p2, Lvy0/i1;

    .line 61
    .line 62
    move-object p1, p2

    .line 63
    goto/16 :goto_4

    .line 64
    .line 65
    :cond_3
    iget-object p0, v0, La7/a1;->d:La7/b1;

    .line 66
    .line 67
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 68
    .line 69
    .line 70
    goto :goto_2

    .line 71
    :cond_4
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 72
    .line 73
    .line 74
    iget-object p2, p0, La7/b1;->a:Landroidx/glance/appwidget/GlanceRemoteViewsService;

    .line 75
    .line 76
    invoke-static {p2}, Landroid/appwidget/AppWidgetManager;->getInstance(Landroid/content/Context;)Landroid/appwidget/AppWidgetManager;

    .line 77
    .line 78
    .line 79
    move-result-object p2

    .line 80
    iget v2, p0, La7/b1;->b:I

    .line 81
    .line 82
    invoke-virtual {p2, v2}, Landroid/appwidget/AppWidgetManager;->getAppWidgetInfo(I)Landroid/appwidget/AppWidgetProviderInfo;

    .line 83
    .line 84
    .line 85
    move-result-object p2

    .line 86
    if-eqz p2, :cond_5

    .line 87
    .line 88
    iget-object p2, p2, Landroid/appwidget/AppWidgetProviderInfo;->provider:Landroid/content/ComponentName;

    .line 89
    .line 90
    if-eqz p2, :cond_5

    .line 91
    .line 92
    invoke-virtual {p2}, Landroid/content/ComponentName;->getClassName()Ljava/lang/String;

    .line 93
    .line 94
    .line 95
    move-result-object p2

    .line 96
    if-eqz p2, :cond_5

    .line 97
    .line 98
    invoke-static {p2}, Ljava/lang/Class;->forName(Ljava/lang/String;)Ljava/lang/Class;

    .line 99
    .line 100
    .line 101
    move-result-object p2

    .line 102
    invoke-virtual {p2, v11}, Ljava/lang/Class;->getDeclaredConstructor([Ljava/lang/Class;)Ljava/lang/reflect/Constructor;

    .line 103
    .line 104
    .line 105
    move-result-object p2

    .line 106
    invoke-virtual {p2, v11}, Ljava/lang/reflect/Constructor;->newInstance([Ljava/lang/Object;)Ljava/lang/Object;

    .line 107
    .line 108
    .line 109
    move-result-object p2

    .line 110
    const-string v2, "null cannot be cast to non-null type androidx.glance.appwidget.GlanceAppWidgetReceiver"

    .line 111
    .line 112
    invoke-static {p2, v2}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 113
    .line 114
    .line 115
    check-cast p2, La7/z0;

    .line 116
    .line 117
    check-cast p2, Lcz/skodaauto/myskoda/feature/widget/system/WidgetReceiver;

    .line 118
    .line 119
    iget-object p2, p2, Lcz/skodaauto/myskoda/feature/widget/system/WidgetReceiver;->f:Lza0/q;

    .line 120
    .line 121
    move-object v10, p2

    .line 122
    goto :goto_1

    .line 123
    :cond_5
    move-object v10, v11

    .line 124
    :goto_1
    if-eqz v10, :cond_7

    .line 125
    .line 126
    sget-object p2, Lh7/n;->a:Lh7/m;

    .line 127
    .line 128
    new-instance v6, La7/k;

    .line 129
    .line 130
    const/4 v7, 0x3

    .line 131
    move-object v8, p0

    .line 132
    move-object v9, p1

    .line 133
    invoke-direct/range {v6 .. v11}, La7/k;-><init>(ILjava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 134
    .line 135
    .line 136
    iput-object v8, v0, La7/a1;->d:La7/b1;

    .line 137
    .line 138
    iput v5, v0, La7/a1;->g:I

    .line 139
    .line 140
    invoke-virtual {p2, v6, v0}, Lh7/m;->a(Lay0/n;Lrx0/c;)Ljava/lang/Object;

    .line 141
    .line 142
    .line 143
    move-result-object p2

    .line 144
    if-ne p2, v1, :cond_6

    .line 145
    .line 146
    goto :goto_5

    .line 147
    :cond_6
    move-object p0, v8

    .line 148
    :goto_2
    move-object p1, p2

    .line 149
    check-cast p1, Lvy0/i1;

    .line 150
    .line 151
    if-nez p1, :cond_8

    .line 152
    .line 153
    goto :goto_3

    .line 154
    :cond_7
    move-object v8, p0

    .line 155
    :goto_3
    sget-object p1, Landroidx/glance/appwidget/UnmanagedSessionReceiver;->a:La7/a0;

    .line 156
    .line 157
    iget p0, p0, La7/b1;->b:I

    .line 158
    .line 159
    invoke-static {p0}, La7/a0;->a(I)V

    .line 160
    .line 161
    .line 162
    move-object p1, v11

    .line 163
    :cond_8
    :goto_4
    if-eqz p1, :cond_9

    .line 164
    .line 165
    iput-object v11, v0, La7/a1;->d:La7/b1;

    .line 166
    .line 167
    iput v4, v0, La7/a1;->g:I

    .line 168
    .line 169
    invoke-interface {p1, v0}, Lvy0/i1;->l(Lrx0/c;)Ljava/lang/Object;

    .line 170
    .line 171
    .line 172
    move-result-object p0

    .line 173
    if-ne p0, v1, :cond_9

    .line 174
    .line 175
    :goto_5
    return-object v1

    .line 176
    :cond_9
    return-object v3
.end method


# virtual methods
.method public final b()La7/n1;
    .locals 4

    .line 1
    sget-object v0, Landroidx/glance/appwidget/GlanceRemoteViewsService;->d:La7/o1;

    .line 2
    .line 3
    iget v0, p0, La7/b1;->b:I

    .line 4
    .line 5
    iget v1, p0, La7/b1;->c:I

    .line 6
    .line 7
    iget-object p0, p0, La7/b1;->d:Ljava/lang/String;

    .line 8
    .line 9
    sget-object v2, Landroidx/glance/appwidget/GlanceRemoteViewsService;->d:La7/o1;

    .line 10
    .line 11
    monitor-enter v2

    .line 12
    :try_start_0
    iget-object v3, v2, La7/o1;->a:Ljava/util/LinkedHashMap;

    .line 13
    .line 14
    invoke-static {v0, v1, p0}, La7/o1;->a(IILjava/lang/String;)Ljava/lang/String;

    .line 15
    .line 16
    .line 17
    move-result-object p0

    .line 18
    invoke-virtual {v3, p0}, Ljava/util/LinkedHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    check-cast p0, La7/n1;

    .line 23
    .line 24
    if-nez p0, :cond_0

    .line 25
    .line 26
    sget-object p0, La7/n1;->d:La7/n1;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 27
    .line 28
    :cond_0
    monitor-exit v2

    .line 29
    return-object p0

    .line 30
    :catchall_0
    move-exception p0

    .line 31
    monitor-exit v2

    .line 32
    throw p0
.end method

.method public final getCount()I
    .locals 0

    .line 1
    invoke-virtual {p0}, La7/b1;->b()La7/n1;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    iget-object p0, p0, La7/n1;->a:[J

    .line 6
    .line 7
    array-length p0, p0

    .line 8
    return p0
.end method

.method public final getItemId(I)J
    .locals 0

    .line 1
    :try_start_0
    invoke-virtual {p0}, La7/b1;->b()La7/n1;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    iget-object p0, p0, La7/n1;->a:[J

    .line 6
    .line 7
    aget-wide p0, p0, p1
    :try_end_0
    .catch Ljava/lang/ArrayIndexOutOfBoundsException; {:try_start_0 .. :try_end_0} :catch_0

    .line 8
    .line 9
    return-wide p0

    .line 10
    :catch_0
    const-wide/16 p0, -0x1

    .line 11
    .line 12
    return-wide p0
.end method

.method public final bridge synthetic getLoadingView()Landroid/widget/RemoteViews;
    .locals 0

    .line 1
    const/4 p0, 0x0

    .line 2
    return-object p0
.end method

.method public final getViewAt(I)Landroid/widget/RemoteViews;
    .locals 1

    .line 1
    :try_start_0
    invoke-virtual {p0}, La7/b1;->b()La7/n1;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    iget-object v0, v0, La7/n1;->b:[Landroid/widget/RemoteViews;

    .line 6
    .line 7
    aget-object p0, v0, p1
    :try_end_0
    .catch Ljava/lang/ArrayIndexOutOfBoundsException; {:try_start_0 .. :try_end_0} :catch_0

    .line 8
    .line 9
    return-object p0

    .line 10
    :catch_0
    new-instance p1, Landroid/widget/RemoteViews;

    .line 11
    .line 12
    iget-object p0, p0, La7/b1;->a:Landroidx/glance/appwidget/GlanceRemoteViewsService;

    .line 13
    .line 14
    invoke-virtual {p0}, Landroid/content/Context;->getPackageName()Ljava/lang/String;

    .line 15
    .line 16
    .line 17
    move-result-object p0

    .line 18
    const v0, 0x7f0d01e9

    .line 19
    .line 20
    .line 21
    invoke-direct {p1, p0, v0}, Landroid/widget/RemoteViews;-><init>(Ljava/lang/String;I)V

    .line 22
    .line 23
    .line 24
    return-object p1
.end method

.method public final getViewTypeCount()I
    .locals 0

    .line 1
    invoke-virtual {p0}, La7/b1;->b()La7/n1;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    iget p0, p0, La7/n1;->c:I

    .line 6
    .line 7
    return p0
.end method

.method public final hasStableIds()Z
    .locals 0

    .line 1
    invoke-virtual {p0}, La7/b1;->b()La7/n1;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 6
    .line 7
    .line 8
    const/4 p0, 0x0

    .line 9
    return p0
.end method

.method public final onCreate()V
    .locals 0

    .line 1
    return-void
.end method

.method public final onDataSetChanged()V
    .locals 3

    .line 1
    new-instance v0, La50/a;

    .line 2
    .line 3
    const/4 v1, 0x2

    .line 4
    const/4 v2, 0x0

    .line 5
    invoke-direct {v0, p0, v2, v1}, La50/a;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 6
    .line 7
    .line 8
    invoke-static {v0}, Lvy0/e0;->L(Lay0/n;)Ljava/lang/Object;

    .line 9
    .line 10
    .line 11
    return-void
.end method

.method public final onDestroy()V
    .locals 4

    .line 1
    sget-object v0, Landroidx/glance/appwidget/GlanceRemoteViewsService;->d:La7/o1;

    .line 2
    .line 3
    iget v0, p0, La7/b1;->b:I

    .line 4
    .line 5
    iget v1, p0, La7/b1;->c:I

    .line 6
    .line 7
    iget-object p0, p0, La7/b1;->d:Ljava/lang/String;

    .line 8
    .line 9
    sget-object v2, Landroidx/glance/appwidget/GlanceRemoteViewsService;->d:La7/o1;

    .line 10
    .line 11
    monitor-enter v2

    .line 12
    :try_start_0
    iget-object v3, v2, La7/o1;->a:Ljava/util/LinkedHashMap;

    .line 13
    .line 14
    invoke-static {v0, v1, p0}, La7/o1;->a(IILjava/lang/String;)Ljava/lang/String;

    .line 15
    .line 16
    .line 17
    move-result-object p0

    .line 18
    invoke-interface {v3, p0}, Ljava/util/Map;->remove(Ljava/lang/Object;)Ljava/lang/Object;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 19
    .line 20
    .line 21
    monitor-exit v2

    .line 22
    return-void

    .line 23
    :catchall_0
    move-exception p0

    .line 24
    monitor-exit v2

    .line 25
    throw p0
.end method
