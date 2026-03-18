.class public final Lm/h2;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final f:Landroid/graphics/PorterDuff$Mode;

.field public static g:Lm/h2;

.field public static final h:Lm/g2;


# instance fields
.field public a:Ljava/util/WeakHashMap;

.field public final b:Ljava/util/WeakHashMap;

.field public c:Landroid/util/TypedValue;

.field public d:Z

.field public e:Lu/x0;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    sget-object v0, Landroid/graphics/PorterDuff$Mode;->SRC_IN:Landroid/graphics/PorterDuff$Mode;

    .line 2
    .line 3
    sput-object v0, Lm/h2;->f:Landroid/graphics/PorterDuff$Mode;

    .line 4
    .line 5
    new-instance v0, Lm/g2;

    .line 6
    .line 7
    const/4 v1, 0x6

    .line 8
    invoke-direct {v0, v1}, Lm/g2;-><init>(I)V

    .line 9
    .line 10
    .line 11
    sput-object v0, Lm/h2;->h:Lm/g2;

    .line 12
    .line 13
    return-void
.end method

.method public constructor <init>()V
    .locals 2

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Ljava/util/WeakHashMap;

    .line 5
    .line 6
    const/4 v1, 0x0

    .line 7
    invoke-direct {v0, v1}, Ljava/util/WeakHashMap;-><init>(I)V

    .line 8
    .line 9
    .line 10
    iput-object v0, p0, Lm/h2;->b:Ljava/util/WeakHashMap;

    .line 11
    .line 12
    return-void
.end method

.method public static declared-synchronized b()Lm/h2;
    .locals 2

    .line 1
    const-class v0, Lm/h2;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    sget-object v1, Lm/h2;->g:Lm/h2;

    .line 5
    .line 6
    if-nez v1, :cond_0

    .line 7
    .line 8
    new-instance v1, Lm/h2;

    .line 9
    .line 10
    invoke-direct {v1}, Lm/h2;-><init>()V

    .line 11
    .line 12
    .line 13
    sput-object v1, Lm/h2;->g:Lm/h2;

    .line 14
    .line 15
    goto :goto_0

    .line 16
    :catchall_0
    move-exception v1

    .line 17
    goto :goto_1

    .line 18
    :cond_0
    :goto_0
    sget-object v1, Lm/h2;->g:Lm/h2;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 19
    .line 20
    monitor-exit v0

    .line 21
    return-object v1

    .line 22
    :goto_1
    :try_start_1
    monitor-exit v0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 23
    throw v1
.end method

.method public static declared-synchronized e(ILandroid/graphics/PorterDuff$Mode;)Landroid/graphics/PorterDuffColorFilter;
    .locals 4

    .line 1
    const-class v0, Lm/h2;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    sget-object v1, Lm/h2;->h:Lm/g2;

    .line 5
    .line 6
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 7
    .line 8
    .line 9
    const/16 v2, 0x1f

    .line 10
    .line 11
    add-int v3, v2, p0

    .line 12
    .line 13
    mul-int/2addr v3, v2

    .line 14
    invoke-virtual {p1}, Ljava/lang/Object;->hashCode()I

    .line 15
    .line 16
    .line 17
    move-result v2

    .line 18
    add-int/2addr v2, v3

    .line 19
    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 20
    .line 21
    .line 22
    move-result-object v2

    .line 23
    invoke-virtual {v1, v2}, Landroidx/collection/w;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 24
    .line 25
    .line 26
    move-result-object v2

    .line 27
    check-cast v2, Landroid/graphics/PorterDuffColorFilter;

    .line 28
    .line 29
    if-nez v2, :cond_0

    .line 30
    .line 31
    new-instance v2, Landroid/graphics/PorterDuffColorFilter;

    .line 32
    .line 33
    invoke-direct {v2, p0, p1}, Landroid/graphics/PorterDuffColorFilter;-><init>(ILandroid/graphics/PorterDuff$Mode;)V

    .line 34
    .line 35
    .line 36
    invoke-virtual {p1}, Ljava/lang/Object;->hashCode()I

    .line 37
    .line 38
    .line 39
    move-result p0

    .line 40
    add-int/2addr p0, v3

    .line 41
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 42
    .line 43
    .line 44
    move-result-object p0

    .line 45
    invoke-virtual {v1, p0, v2}, Landroidx/collection/w;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 46
    .line 47
    .line 48
    move-result-object p0

    .line 49
    check-cast p0, Landroid/graphics/PorterDuffColorFilter;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 50
    .line 51
    goto :goto_0

    .line 52
    :catchall_0
    move-exception p0

    .line 53
    goto :goto_1

    .line 54
    :cond_0
    :goto_0
    monitor-exit v0

    .line 55
    return-object v2

    .line 56
    :goto_1
    :try_start_1
    monitor-exit v0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 57
    throw p0
.end method


# virtual methods
.method public final a(Landroid/content/Context;I)Landroid/graphics/drawable/Drawable;
    .locals 6

    .line 1
    iget-object v0, p0, Lm/h2;->c:Landroid/util/TypedValue;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    new-instance v0, Landroid/util/TypedValue;

    .line 6
    .line 7
    invoke-direct {v0}, Landroid/util/TypedValue;-><init>()V

    .line 8
    .line 9
    .line 10
    iput-object v0, p0, Lm/h2;->c:Landroid/util/TypedValue;

    .line 11
    .line 12
    :cond_0
    iget-object v0, p0, Lm/h2;->c:Landroid/util/TypedValue;

    .line 13
    .line 14
    invoke-virtual {p1}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    .line 15
    .line 16
    .line 17
    move-result-object v1

    .line 18
    const/4 v2, 0x1

    .line 19
    invoke-virtual {v1, p2, v0, v2}, Landroid/content/res/Resources;->getValue(ILandroid/util/TypedValue;Z)V

    .line 20
    .line 21
    .line 22
    iget v1, v0, Landroid/util/TypedValue;->assetCookie:I

    .line 23
    .line 24
    int-to-long v1, v1

    .line 25
    const/16 v3, 0x20

    .line 26
    .line 27
    shl-long/2addr v1, v3

    .line 28
    iget v3, v0, Landroid/util/TypedValue;->data:I

    .line 29
    .line 30
    int-to-long v3, v3

    .line 31
    or-long/2addr v1, v3

    .line 32
    monitor-enter p0

    .line 33
    :try_start_0
    iget-object v3, p0, Lm/h2;->b:Ljava/util/WeakHashMap;

    .line 34
    .line 35
    invoke-virtual {v3, p1}, Ljava/util/WeakHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 36
    .line 37
    .line 38
    move-result-object v3

    .line 39
    check-cast v3, Landroidx/collection/u;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 40
    .line 41
    const/4 v4, 0x0

    .line 42
    if-nez v3, :cond_1

    .line 43
    .line 44
    monitor-exit p0

    .line 45
    goto :goto_0

    .line 46
    :cond_1
    :try_start_1
    invoke-virtual {v3, v1, v2}, Landroidx/collection/u;->b(J)Ljava/lang/Object;

    .line 47
    .line 48
    .line 49
    move-result-object v5

    .line 50
    check-cast v5, Ljava/lang/ref/WeakReference;

    .line 51
    .line 52
    if-eqz v5, :cond_3

    .line 53
    .line 54
    invoke-virtual {v5}, Ljava/lang/ref/Reference;->get()Ljava/lang/Object;

    .line 55
    .line 56
    .line 57
    move-result-object v5

    .line 58
    check-cast v5, Landroid/graphics/drawable/Drawable$ConstantState;

    .line 59
    .line 60
    if-eqz v5, :cond_2

    .line 61
    .line 62
    invoke-virtual {p1}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    .line 63
    .line 64
    .line 65
    move-result-object v3

    .line 66
    invoke-virtual {v5, v3}, Landroid/graphics/drawable/Drawable$ConstantState;->newDrawable(Landroid/content/res/Resources;)Landroid/graphics/drawable/Drawable;

    .line 67
    .line 68
    .line 69
    move-result-object v4
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 70
    monitor-exit p0

    .line 71
    goto :goto_0

    .line 72
    :catchall_0
    move-exception p1

    .line 73
    goto/16 :goto_5

    .line 74
    .line 75
    :cond_2
    :try_start_2
    invoke-virtual {v3, v1, v2}, Landroidx/collection/u;->f(J)V
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 76
    .line 77
    .line 78
    :cond_3
    monitor-exit p0

    .line 79
    :goto_0
    if-eqz v4, :cond_4

    .line 80
    .line 81
    return-object v4

    .line 82
    :cond_4
    iget-object v3, p0, Lm/h2;->e:Lu/x0;

    .line 83
    .line 84
    const/4 v4, 0x0

    .line 85
    if-nez v3, :cond_5

    .line 86
    .line 87
    goto :goto_1

    .line 88
    :cond_5
    const v3, 0x7f08004c

    .line 89
    .line 90
    .line 91
    if-ne p2, v3, :cond_6

    .line 92
    .line 93
    new-instance v4, Landroid/graphics/drawable/LayerDrawable;

    .line 94
    .line 95
    const p2, 0x7f08004b

    .line 96
    .line 97
    .line 98
    invoke-virtual {p0, p1, p2}, Lm/h2;->c(Landroid/content/Context;I)Landroid/graphics/drawable/Drawable;

    .line 99
    .line 100
    .line 101
    move-result-object p2

    .line 102
    const v3, 0x7f08004d

    .line 103
    .line 104
    .line 105
    invoke-virtual {p0, p1, v3}, Lm/h2;->c(Landroid/content/Context;I)Landroid/graphics/drawable/Drawable;

    .line 106
    .line 107
    .line 108
    move-result-object v3

    .line 109
    filled-new-array {p2, v3}, [Landroid/graphics/drawable/Drawable;

    .line 110
    .line 111
    .line 112
    move-result-object p2

    .line 113
    invoke-direct {v4, p2}, Landroid/graphics/drawable/LayerDrawable;-><init>([Landroid/graphics/drawable/Drawable;)V

    .line 114
    .line 115
    .line 116
    goto :goto_1

    .line 117
    :cond_6
    const v3, 0x7f08006f

    .line 118
    .line 119
    .line 120
    if-ne p2, v3, :cond_7

    .line 121
    .line 122
    const p2, 0x7f07003b

    .line 123
    .line 124
    .line 125
    invoke-static {p0, p1, p2}, Lu/x0;->g(Lm/h2;Landroid/content/Context;I)Landroid/graphics/drawable/LayerDrawable;

    .line 126
    .line 127
    .line 128
    move-result-object v4

    .line 129
    goto :goto_1

    .line 130
    :cond_7
    const v3, 0x7f08006e

    .line 131
    .line 132
    .line 133
    if-ne p2, v3, :cond_8

    .line 134
    .line 135
    const p2, 0x7f07003c

    .line 136
    .line 137
    .line 138
    invoke-static {p0, p1, p2}, Lu/x0;->g(Lm/h2;Landroid/content/Context;I)Landroid/graphics/drawable/LayerDrawable;

    .line 139
    .line 140
    .line 141
    move-result-object v4

    .line 142
    goto :goto_1

    .line 143
    :cond_8
    const v3, 0x7f080070

    .line 144
    .line 145
    .line 146
    if-ne p2, v3, :cond_9

    .line 147
    .line 148
    const p2, 0x7f07003d

    .line 149
    .line 150
    .line 151
    invoke-static {p0, p1, p2}, Lu/x0;->g(Lm/h2;Landroid/content/Context;I)Landroid/graphics/drawable/LayerDrawable;

    .line 152
    .line 153
    .line 154
    move-result-object v4

    .line 155
    :cond_9
    :goto_1
    if-eqz v4, :cond_c

    .line 156
    .line 157
    iget p2, v0, Landroid/util/TypedValue;->changingConfigurations:I

    .line 158
    .line 159
    invoke-virtual {v4, p2}, Landroid/graphics/drawable/Drawable;->setChangingConfigurations(I)V

    .line 160
    .line 161
    .line 162
    monitor-enter p0

    .line 163
    :try_start_3
    invoke-virtual {v4}, Landroid/graphics/drawable/Drawable;->getConstantState()Landroid/graphics/drawable/Drawable$ConstantState;

    .line 164
    .line 165
    .line 166
    move-result-object p2

    .line 167
    if-eqz p2, :cond_b

    .line 168
    .line 169
    iget-object v0, p0, Lm/h2;->b:Ljava/util/WeakHashMap;

    .line 170
    .line 171
    invoke-virtual {v0, p1}, Ljava/util/WeakHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 172
    .line 173
    .line 174
    move-result-object v0

    .line 175
    check-cast v0, Landroidx/collection/u;

    .line 176
    .line 177
    if-nez v0, :cond_a

    .line 178
    .line 179
    new-instance v0, Landroidx/collection/u;

    .line 180
    .line 181
    const/4 v3, 0x0

    .line 182
    invoke-direct {v0, v3}, Landroidx/collection/u;-><init>(Ljava/lang/Object;)V

    .line 183
    .line 184
    .line 185
    iget-object v3, p0, Lm/h2;->b:Ljava/util/WeakHashMap;

    .line 186
    .line 187
    invoke-virtual {v3, p1, v0}, Ljava/util/WeakHashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 188
    .line 189
    .line 190
    goto :goto_2

    .line 191
    :catchall_1
    move-exception p1

    .line 192
    goto :goto_4

    .line 193
    :cond_a
    :goto_2
    new-instance p1, Ljava/lang/ref/WeakReference;

    .line 194
    .line 195
    invoke-direct {p1, p2}, Ljava/lang/ref/WeakReference;-><init>(Ljava/lang/Object;)V

    .line 196
    .line 197
    .line 198
    invoke-virtual {v0, v1, v2, p1}, Landroidx/collection/u;->e(JLjava/lang/Object;)V
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_1

    .line 199
    .line 200
    .line 201
    monitor-exit p0

    .line 202
    goto :goto_3

    .line 203
    :cond_b
    monitor-exit p0

    .line 204
    :goto_3
    return-object v4

    .line 205
    :goto_4
    :try_start_4
    monitor-exit p0
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_1

    .line 206
    throw p1

    .line 207
    :cond_c
    return-object v4

    .line 208
    :goto_5
    :try_start_5
    monitor-exit p0
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_0

    .line 209
    throw p1
.end method

.method public final declared-synchronized c(Landroid/content/Context;I)Landroid/graphics/drawable/Drawable;
    .locals 1

    .line 1
    monitor-enter p0

    .line 2
    const/4 v0, 0x0

    .line 3
    :try_start_0
    invoke-virtual {p0, p1, p2, v0}, Lm/h2;->d(Landroid/content/Context;IZ)Landroid/graphics/drawable/Drawable;

    .line 4
    .line 5
    .line 6
    move-result-object p1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 7
    monitor-exit p0

    .line 8
    return-object p1

    .line 9
    :catchall_0
    move-exception p1

    .line 10
    :try_start_1
    monitor-exit p0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 11
    throw p1
.end method

.method public final declared-synchronized d(Landroid/content/Context;IZ)Landroid/graphics/drawable/Drawable;
    .locals 2

    .line 1
    monitor-enter p0

    .line 2
    :try_start_0
    iget-boolean v0, p0, Lm/h2;->d:Z

    .line 3
    .line 4
    if-eqz v0, :cond_0

    .line 5
    .line 6
    goto :goto_0

    .line 7
    :cond_0
    const/4 v0, 0x1

    .line 8
    iput-boolean v0, p0, Lm/h2;->d:Z

    .line 9
    .line 10
    const v0, 0x7f08008a

    .line 11
    .line 12
    .line 13
    invoke-virtual {p0, p1, v0}, Lm/h2;->c(Landroid/content/Context;I)Landroid/graphics/drawable/Drawable;

    .line 14
    .line 15
    .line 16
    move-result-object v0

    .line 17
    if-eqz v0, :cond_5

    .line 18
    .line 19
    instance-of v1, v0, Lcb/p;

    .line 20
    .line 21
    if-nez v1, :cond_1

    .line 22
    .line 23
    const-string v1, "android.graphics.drawable.VectorDrawable"

    .line 24
    .line 25
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 26
    .line 27
    .line 28
    move-result-object v0

    .line 29
    invoke-virtual {v0}, Ljava/lang/Class;->getName()Ljava/lang/String;

    .line 30
    .line 31
    .line 32
    move-result-object v0

    .line 33
    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 34
    .line 35
    .line 36
    move-result v0

    .line 37
    if-eqz v0, :cond_5

    .line 38
    .line 39
    :cond_1
    :goto_0
    invoke-virtual {p0, p1, p2}, Lm/h2;->a(Landroid/content/Context;I)Landroid/graphics/drawable/Drawable;

    .line 40
    .line 41
    .line 42
    move-result-object v0

    .line 43
    if-nez v0, :cond_2

    .line 44
    .line 45
    invoke-virtual {p1, p2}, Landroid/content/Context;->getDrawable(I)Landroid/graphics/drawable/Drawable;

    .line 46
    .line 47
    .line 48
    move-result-object v0

    .line 49
    goto :goto_1

    .line 50
    :catchall_0
    move-exception p1

    .line 51
    goto :goto_2

    .line 52
    :cond_2
    :goto_1
    if-eqz v0, :cond_3

    .line 53
    .line 54
    invoke-virtual {p0, p1, p2, p3, v0}, Lm/h2;->g(Landroid/content/Context;IZLandroid/graphics/drawable/Drawable;)Landroid/graphics/drawable/Drawable;

    .line 55
    .line 56
    .line 57
    move-result-object v0

    .line 58
    :cond_3
    if-eqz v0, :cond_4

    .line 59
    .line 60
    invoke-static {v0}, Lm/g1;->a(Landroid/graphics/drawable/Drawable;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 61
    .line 62
    .line 63
    :cond_4
    monitor-exit p0

    .line 64
    return-object v0

    .line 65
    :cond_5
    const/4 p1, 0x0

    .line 66
    :try_start_1
    iput-boolean p1, p0, Lm/h2;->d:Z

    .line 67
    .line 68
    new-instance p1, Ljava/lang/IllegalStateException;

    .line 69
    .line 70
    const-string p2, "This app has been built with an incorrect configuration. Please configure your build for VectorDrawableCompat."

    .line 71
    .line 72
    invoke-direct {p1, p2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 73
    .line 74
    .line 75
    throw p1

    .line 76
    :goto_2
    monitor-exit p0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 77
    throw p1
.end method

.method public final declared-synchronized f(Landroid/content/Context;I)Landroid/content/res/ColorStateList;
    .locals 3

    .line 1
    monitor-enter p0

    .line 2
    :try_start_0
    iget-object v0, p0, Lm/h2;->a:Ljava/util/WeakHashMap;

    .line 3
    .line 4
    const/4 v1, 0x0

    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    invoke-virtual {v0, p1}, Ljava/util/WeakHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    check-cast v0, Landroidx/collection/b1;

    .line 12
    .line 13
    if-eqz v0, :cond_0

    .line 14
    .line 15
    invoke-virtual {v0, p2}, Landroidx/collection/b1;->c(I)Ljava/lang/Object;

    .line 16
    .line 17
    .line 18
    move-result-object v0

    .line 19
    check-cast v0, Landroid/content/res/ColorStateList;

    .line 20
    .line 21
    goto :goto_0

    .line 22
    :cond_0
    move-object v0, v1

    .line 23
    :goto_0
    if-nez v0, :cond_5

    .line 24
    .line 25
    iget-object v0, p0, Lm/h2;->e:Lu/x0;

    .line 26
    .line 27
    if-nez v0, :cond_1

    .line 28
    .line 29
    goto :goto_1

    .line 30
    :cond_1
    invoke-virtual {v0, p1, p2}, Lu/x0;->i(Landroid/content/Context;I)Landroid/content/res/ColorStateList;

    .line 31
    .line 32
    .line 33
    move-result-object v1

    .line 34
    :goto_1
    if-eqz v1, :cond_4

    .line 35
    .line 36
    iget-object v0, p0, Lm/h2;->a:Ljava/util/WeakHashMap;

    .line 37
    .line 38
    if-nez v0, :cond_2

    .line 39
    .line 40
    new-instance v0, Ljava/util/WeakHashMap;

    .line 41
    .line 42
    invoke-direct {v0}, Ljava/util/WeakHashMap;-><init>()V

    .line 43
    .line 44
    .line 45
    iput-object v0, p0, Lm/h2;->a:Ljava/util/WeakHashMap;

    .line 46
    .line 47
    :cond_2
    iget-object v0, p0, Lm/h2;->a:Ljava/util/WeakHashMap;

    .line 48
    .line 49
    invoke-virtual {v0, p1}, Ljava/util/WeakHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 50
    .line 51
    .line 52
    move-result-object v0

    .line 53
    check-cast v0, Landroidx/collection/b1;

    .line 54
    .line 55
    if-nez v0, :cond_3

    .line 56
    .line 57
    new-instance v0, Landroidx/collection/b1;

    .line 58
    .line 59
    const/4 v2, 0x0

    .line 60
    invoke-direct {v0, v2}, Landroidx/collection/b1;-><init>(I)V

    .line 61
    .line 62
    .line 63
    iget-object v2, p0, Lm/h2;->a:Ljava/util/WeakHashMap;

    .line 64
    .line 65
    invoke-virtual {v2, p1, v0}, Ljava/util/WeakHashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 66
    .line 67
    .line 68
    :cond_3
    invoke-virtual {v0, p2, v1}, Landroidx/collection/b1;->a(ILjava/lang/Object;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 69
    .line 70
    .line 71
    :cond_4
    move-object v0, v1

    .line 72
    goto :goto_2

    .line 73
    :catchall_0
    move-exception p1

    .line 74
    goto :goto_3

    .line 75
    :cond_5
    :goto_2
    monitor-exit p0

    .line 76
    return-object v0

    .line 77
    :goto_3
    :try_start_1
    monitor-exit p0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 78
    throw p1
.end method

.method public final g(Landroid/content/Context;IZLandroid/graphics/drawable/Drawable;)Landroid/graphics/drawable/Drawable;
    .locals 7

    .line 1
    invoke-virtual {p0, p1, p2}, Lm/h2;->f(Landroid/content/Context;I)Landroid/content/res/ColorStateList;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    const/4 v1, 0x0

    .line 6
    if-eqz v0, :cond_3

    .line 7
    .line 8
    invoke-virtual {p4}, Landroid/graphics/drawable/Drawable;->mutate()Landroid/graphics/drawable/Drawable;

    .line 9
    .line 10
    .line 11
    move-result-object p1

    .line 12
    invoke-virtual {p1, v0}, Landroid/graphics/drawable/Drawable;->setTintList(Landroid/content/res/ColorStateList;)V

    .line 13
    .line 14
    .line 15
    iget-object p0, p0, Lm/h2;->e:Lu/x0;

    .line 16
    .line 17
    if-nez p0, :cond_0

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    const p0, 0x7f08007d

    .line 21
    .line 22
    .line 23
    if-ne p2, p0, :cond_1

    .line 24
    .line 25
    sget-object v1, Landroid/graphics/PorterDuff$Mode;->MULTIPLY:Landroid/graphics/PorterDuff$Mode;

    .line 26
    .line 27
    :cond_1
    :goto_0
    if-eqz v1, :cond_2

    .line 28
    .line 29
    invoke-virtual {p1, v1}, Landroid/graphics/drawable/Drawable;->setTintMode(Landroid/graphics/PorterDuff$Mode;)V

    .line 30
    .line 31
    .line 32
    :cond_2
    return-object p1

    .line 33
    :cond_3
    iget-object v0, p0, Lm/h2;->e:Lu/x0;

    .line 34
    .line 35
    if-eqz v0, :cond_6

    .line 36
    .line 37
    const v0, 0x7f080078

    .line 38
    .line 39
    .line 40
    const v2, 0x102000d

    .line 41
    .line 42
    .line 43
    const v3, 0x102000f

    .line 44
    .line 45
    .line 46
    const/high16 v4, 0x1020000

    .line 47
    .line 48
    const v5, 0x7f04011d

    .line 49
    .line 50
    .line 51
    const v6, 0x7f04011f

    .line 52
    .line 53
    .line 54
    if-ne p2, v0, :cond_4

    .line 55
    .line 56
    move-object p0, p4

    .line 57
    check-cast p0, Landroid/graphics/drawable/LayerDrawable;

    .line 58
    .line 59
    invoke-virtual {p0, v4}, Landroid/graphics/drawable/LayerDrawable;->findDrawableByLayerId(I)Landroid/graphics/drawable/Drawable;

    .line 60
    .line 61
    .line 62
    move-result-object p2

    .line 63
    invoke-static {p1, v6}, Lm/m2;->c(Landroid/content/Context;I)I

    .line 64
    .line 65
    .line 66
    move-result p3

    .line 67
    sget-object v0, Lm/s;->b:Landroid/graphics/PorterDuff$Mode;

    .line 68
    .line 69
    invoke-static {p2, p3, v0}, Lu/x0;->o(Landroid/graphics/drawable/Drawable;ILandroid/graphics/PorterDuff$Mode;)V

    .line 70
    .line 71
    .line 72
    invoke-virtual {p0, v3}, Landroid/graphics/drawable/LayerDrawable;->findDrawableByLayerId(I)Landroid/graphics/drawable/Drawable;

    .line 73
    .line 74
    .line 75
    move-result-object p2

    .line 76
    invoke-static {p1, v6}, Lm/m2;->c(Landroid/content/Context;I)I

    .line 77
    .line 78
    .line 79
    move-result p3

    .line 80
    invoke-static {p2, p3, v0}, Lu/x0;->o(Landroid/graphics/drawable/Drawable;ILandroid/graphics/PorterDuff$Mode;)V

    .line 81
    .line 82
    .line 83
    invoke-virtual {p0, v2}, Landroid/graphics/drawable/LayerDrawable;->findDrawableByLayerId(I)Landroid/graphics/drawable/Drawable;

    .line 84
    .line 85
    .line 86
    move-result-object p0

    .line 87
    invoke-static {p1, v5}, Lm/m2;->c(Landroid/content/Context;I)I

    .line 88
    .line 89
    .line 90
    move-result p1

    .line 91
    invoke-static {p0, p1, v0}, Lu/x0;->o(Landroid/graphics/drawable/Drawable;ILandroid/graphics/PorterDuff$Mode;)V

    .line 92
    .line 93
    .line 94
    return-object p4

    .line 95
    :cond_4
    const v0, 0x7f08006f

    .line 96
    .line 97
    .line 98
    if-eq p2, v0, :cond_5

    .line 99
    .line 100
    const v0, 0x7f08006e

    .line 101
    .line 102
    .line 103
    if-eq p2, v0, :cond_5

    .line 104
    .line 105
    const v0, 0x7f080070

    .line 106
    .line 107
    .line 108
    if-ne p2, v0, :cond_6

    .line 109
    .line 110
    :cond_5
    move-object p0, p4

    .line 111
    check-cast p0, Landroid/graphics/drawable/LayerDrawable;

    .line 112
    .line 113
    invoke-virtual {p0, v4}, Landroid/graphics/drawable/LayerDrawable;->findDrawableByLayerId(I)Landroid/graphics/drawable/Drawable;

    .line 114
    .line 115
    .line 116
    move-result-object p2

    .line 117
    invoke-static {p1, v6}, Lm/m2;->b(Landroid/content/Context;I)I

    .line 118
    .line 119
    .line 120
    move-result p3

    .line 121
    sget-object v0, Lm/s;->b:Landroid/graphics/PorterDuff$Mode;

    .line 122
    .line 123
    invoke-static {p2, p3, v0}, Lu/x0;->o(Landroid/graphics/drawable/Drawable;ILandroid/graphics/PorterDuff$Mode;)V

    .line 124
    .line 125
    .line 126
    invoke-virtual {p0, v3}, Landroid/graphics/drawable/LayerDrawable;->findDrawableByLayerId(I)Landroid/graphics/drawable/Drawable;

    .line 127
    .line 128
    .line 129
    move-result-object p2

    .line 130
    invoke-static {p1, v5}, Lm/m2;->c(Landroid/content/Context;I)I

    .line 131
    .line 132
    .line 133
    move-result p3

    .line 134
    invoke-static {p2, p3, v0}, Lu/x0;->o(Landroid/graphics/drawable/Drawable;ILandroid/graphics/PorterDuff$Mode;)V

    .line 135
    .line 136
    .line 137
    invoke-virtual {p0, v2}, Landroid/graphics/drawable/LayerDrawable;->findDrawableByLayerId(I)Landroid/graphics/drawable/Drawable;

    .line 138
    .line 139
    .line 140
    move-result-object p0

    .line 141
    invoke-static {p1, v5}, Lm/m2;->c(Landroid/content/Context;I)I

    .line 142
    .line 143
    .line 144
    move-result p1

    .line 145
    invoke-static {p0, p1, v0}, Lu/x0;->o(Landroid/graphics/drawable/Drawable;ILandroid/graphics/PorterDuff$Mode;)V

    .line 146
    .line 147
    .line 148
    return-object p4

    .line 149
    :cond_6
    iget-object p0, p0, Lm/h2;->e:Lu/x0;

    .line 150
    .line 151
    const/4 v0, 0x0

    .line 152
    if-eqz p0, :cond_d

    .line 153
    .line 154
    sget-object v2, Lm/s;->b:Landroid/graphics/PorterDuff$Mode;

    .line 155
    .line 156
    iget-object v3, p0, Lu/x0;->a:Ljava/lang/Object;

    .line 157
    .line 158
    check-cast v3, [I

    .line 159
    .line 160
    invoke-static {p2, v3}, Lu/x0;->b(I[I)Z

    .line 161
    .line 162
    .line 163
    move-result v3

    .line 164
    const/4 v4, 0x1

    .line 165
    const/4 v5, -0x1

    .line 166
    if-eqz v3, :cond_7

    .line 167
    .line 168
    const p0, 0x7f04011f

    .line 169
    .line 170
    .line 171
    :goto_1
    move v3, v4

    .line 172
    :goto_2
    move p2, v5

    .line 173
    goto :goto_4

    .line 174
    :cond_7
    iget-object v3, p0, Lu/x0;->c:Ljava/lang/Object;

    .line 175
    .line 176
    check-cast v3, [I

    .line 177
    .line 178
    invoke-static {p2, v3}, Lu/x0;->b(I[I)Z

    .line 179
    .line 180
    .line 181
    move-result v3

    .line 182
    if-eqz v3, :cond_8

    .line 183
    .line 184
    const p0, 0x7f04011d

    .line 185
    .line 186
    .line 187
    goto :goto_1

    .line 188
    :cond_8
    iget-object p0, p0, Lu/x0;->d:Ljava/lang/Object;

    .line 189
    .line 190
    check-cast p0, [I

    .line 191
    .line 192
    invoke-static {p2, p0}, Lu/x0;->b(I[I)Z

    .line 193
    .line 194
    .line 195
    move-result p0

    .line 196
    const v3, 0x1010031

    .line 197
    .line 198
    .line 199
    if-eqz p0, :cond_9

    .line 200
    .line 201
    sget-object v2, Landroid/graphics/PorterDuff$Mode;->MULTIPLY:Landroid/graphics/PorterDuff$Mode;

    .line 202
    .line 203
    :goto_3
    move p0, v3

    .line 204
    goto :goto_1

    .line 205
    :cond_9
    const p0, 0x7f080061

    .line 206
    .line 207
    .line 208
    if-ne p2, p0, :cond_a

    .line 209
    .line 210
    const p0, 0x42233333    # 40.8f

    .line 211
    .line 212
    .line 213
    invoke-static {p0}, Ljava/lang/Math;->round(F)I

    .line 214
    .line 215
    .line 216
    move-result p0

    .line 217
    const p2, 0x1010030

    .line 218
    .line 219
    .line 220
    move v3, p2

    .line 221
    move p2, p0

    .line 222
    move p0, v3

    .line 223
    move v3, v4

    .line 224
    goto :goto_4

    .line 225
    :cond_a
    const p0, 0x7f08004f

    .line 226
    .line 227
    .line 228
    if-ne p2, p0, :cond_b

    .line 229
    .line 230
    goto :goto_3

    .line 231
    :cond_b
    move p0, v0

    .line 232
    move v3, p0

    .line 233
    goto :goto_2

    .line 234
    :goto_4
    if-eqz v3, :cond_d

    .line 235
    .line 236
    invoke-virtual {p4}, Landroid/graphics/drawable/Drawable;->mutate()Landroid/graphics/drawable/Drawable;

    .line 237
    .line 238
    .line 239
    move-result-object v0

    .line 240
    invoke-static {p1, p0}, Lm/m2;->c(Landroid/content/Context;I)I

    .line 241
    .line 242
    .line 243
    move-result p0

    .line 244
    invoke-static {p0, v2}, Lm/s;->c(ILandroid/graphics/PorterDuff$Mode;)Landroid/graphics/PorterDuffColorFilter;

    .line 245
    .line 246
    .line 247
    move-result-object p0

    .line 248
    invoke-virtual {v0, p0}, Landroid/graphics/drawable/Drawable;->setColorFilter(Landroid/graphics/ColorFilter;)V

    .line 249
    .line 250
    .line 251
    if-eq p2, v5, :cond_c

    .line 252
    .line 253
    invoke-virtual {v0, p2}, Landroid/graphics/drawable/Drawable;->setAlpha(I)V

    .line 254
    .line 255
    .line 256
    :cond_c
    move v0, v4

    .line 257
    :cond_d
    if-nez v0, :cond_e

    .line 258
    .line 259
    if-eqz p3, :cond_e

    .line 260
    .line 261
    return-object v1

    .line 262
    :cond_e
    return-object p4
.end method
