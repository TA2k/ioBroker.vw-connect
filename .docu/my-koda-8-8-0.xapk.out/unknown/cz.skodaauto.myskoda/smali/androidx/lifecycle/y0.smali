.class public final Landroidx/lifecycle/y0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Landroidx/lifecycle/e1;


# instance fields
.field public final a:Landroid/app/Application;

.field public final b:Landroidx/lifecycle/d1;

.field public final c:Landroid/os/Bundle;

.field public final d:Landroidx/lifecycle/r;

.field public final e:Lra/d;


# direct methods
.method public constructor <init>()V
    .locals 2

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    new-instance v0, Landroidx/lifecycle/d1;

    const/4 v1, 0x0

    .line 3
    invoke-direct {v0, v1}, Landroidx/lifecycle/d1;-><init>(Landroid/app/Application;)V

    .line 4
    iput-object v0, p0, Landroidx/lifecycle/y0;->b:Landroidx/lifecycle/d1;

    return-void
.end method

.method public constructor <init>(Landroid/app/Application;Lra/f;Landroid/os/Bundle;)V
    .locals 1

    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    invoke-interface {p2}, Lra/f;->getSavedStateRegistry()Lra/d;

    move-result-object v0

    iput-object v0, p0, Landroidx/lifecycle/y0;->e:Lra/d;

    .line 7
    invoke-interface {p2}, Landroidx/lifecycle/x;->getLifecycle()Landroidx/lifecycle/r;

    move-result-object p2

    iput-object p2, p0, Landroidx/lifecycle/y0;->d:Landroidx/lifecycle/r;

    .line 8
    iput-object p3, p0, Landroidx/lifecycle/y0;->c:Landroid/os/Bundle;

    .line 9
    iput-object p1, p0, Landroidx/lifecycle/y0;->a:Landroid/app/Application;

    if-eqz p1, :cond_1

    .line 10
    sget-object p2, Landroidx/lifecycle/d1;->c:Landroidx/lifecycle/d1;

    if-nez p2, :cond_0

    .line 11
    new-instance p2, Landroidx/lifecycle/d1;

    .line 12
    invoke-direct {p2, p1}, Landroidx/lifecycle/d1;-><init>(Landroid/app/Application;)V

    .line 13
    sput-object p2, Landroidx/lifecycle/d1;->c:Landroidx/lifecycle/d1;

    .line 14
    :cond_0
    sget-object p1, Landroidx/lifecycle/d1;->c:Landroidx/lifecycle/d1;

    .line 15
    invoke-static {p1}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    goto :goto_0

    .line 16
    :cond_1
    new-instance p1, Landroidx/lifecycle/d1;

    const/4 p2, 0x0

    .line 17
    invoke-direct {p1, p2}, Landroidx/lifecycle/d1;-><init>(Landroid/app/Application;)V

    .line 18
    :goto_0
    iput-object p1, p0, Landroidx/lifecycle/y0;->b:Landroidx/lifecycle/d1;

    return-void
.end method


# virtual methods
.method public final a(Lhy0/d;Lp7/e;)Landroidx/lifecycle/b1;
    .locals 1

    .line 1
    const-string v0, "modelClass"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-static {p1}, Ljp/p1;->c(Lhy0/d;)Ljava/lang/Class;

    .line 7
    .line 8
    .line 9
    move-result-object p1

    .line 10
    invoke-virtual {p0, p1, p2}, Landroidx/lifecycle/y0;->c(Ljava/lang/Class;Lp7/e;)Landroidx/lifecycle/b1;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    return-object p0
.end method

.method public final b(Ljava/lang/Class;)Landroidx/lifecycle/b1;
    .locals 1

    .line 1
    invoke-virtual {p1}, Ljava/lang/Class;->getCanonicalName()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    invoke-virtual {p0, p1, v0}, Landroidx/lifecycle/y0;->d(Ljava/lang/Class;Ljava/lang/String;)Landroidx/lifecycle/b1;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    return-object p0

    .line 12
    :cond_0
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 13
    .line 14
    const-string p1, "Local and anonymous classes can not be ViewModels"

    .line 15
    .line 16
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 17
    .line 18
    .line 19
    throw p0
.end method

.method public final c(Ljava/lang/Class;Lp7/e;)Landroidx/lifecycle/b1;
    .locals 3

    .line 1
    iget-object v0, p2, Lp7/c;->a:Ljava/util/LinkedHashMap;

    .line 2
    .line 3
    sget-object v1, Landroidx/lifecycle/g1;->b:Lwe0/b;

    .line 4
    .line 5
    invoke-virtual {v0, v1}, Ljava/util/LinkedHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 6
    .line 7
    .line 8
    move-result-object v1

    .line 9
    check-cast v1, Ljava/lang/String;

    .line 10
    .line 11
    if-eqz v1, :cond_5

    .line 12
    .line 13
    sget-object v2, Landroidx/lifecycle/v0;->a:Lmb/e;

    .line 14
    .line 15
    invoke-virtual {v0, v2}, Ljava/util/LinkedHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 16
    .line 17
    .line 18
    move-result-object v2

    .line 19
    if-eqz v2, :cond_3

    .line 20
    .line 21
    sget-object v2, Landroidx/lifecycle/v0;->b:Lnm0/b;

    .line 22
    .line 23
    invoke-virtual {v0, v2}, Ljava/util/LinkedHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 24
    .line 25
    .line 26
    move-result-object v2

    .line 27
    if-eqz v2, :cond_3

    .line 28
    .line 29
    sget-object v1, Landroidx/lifecycle/d1;->d:Lrb0/a;

    .line 30
    .line 31
    invoke-virtual {v0, v1}, Ljava/util/LinkedHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    move-result-object v0

    .line 35
    check-cast v0, Landroid/app/Application;

    .line 36
    .line 37
    const-class v1, Landroidx/lifecycle/a;

    .line 38
    .line 39
    invoke-virtual {v1, p1}, Ljava/lang/Class;->isAssignableFrom(Ljava/lang/Class;)Z

    .line 40
    .line 41
    .line 42
    move-result v1

    .line 43
    if-eqz v1, :cond_0

    .line 44
    .line 45
    if-eqz v0, :cond_0

    .line 46
    .line 47
    sget-object v2, Landroidx/lifecycle/z0;->a:Ljava/util/List;

    .line 48
    .line 49
    invoke-static {p1, v2}, Landroidx/lifecycle/z0;->a(Ljava/lang/Class;Ljava/util/List;)Ljava/lang/reflect/Constructor;

    .line 50
    .line 51
    .line 52
    move-result-object v2

    .line 53
    goto :goto_0

    .line 54
    :cond_0
    sget-object v2, Landroidx/lifecycle/z0;->b:Ljava/util/List;

    .line 55
    .line 56
    invoke-static {p1, v2}, Landroidx/lifecycle/z0;->a(Ljava/lang/Class;Ljava/util/List;)Ljava/lang/reflect/Constructor;

    .line 57
    .line 58
    .line 59
    move-result-object v2

    .line 60
    :goto_0
    if-nez v2, :cond_1

    .line 61
    .line 62
    iget-object p0, p0, Landroidx/lifecycle/y0;->b:Landroidx/lifecycle/d1;

    .line 63
    .line 64
    invoke-virtual {p0, p1, p2}, Landroidx/lifecycle/d1;->c(Ljava/lang/Class;Lp7/e;)Landroidx/lifecycle/b1;

    .line 65
    .line 66
    .line 67
    move-result-object p0

    .line 68
    return-object p0

    .line 69
    :cond_1
    if-eqz v1, :cond_2

    .line 70
    .line 71
    if-eqz v0, :cond_2

    .line 72
    .line 73
    invoke-static {p2}, Landroidx/lifecycle/v0;->b(Lp7/c;)Landroidx/lifecycle/s0;

    .line 74
    .line 75
    .line 76
    move-result-object p0

    .line 77
    filled-new-array {v0, p0}, [Ljava/lang/Object;

    .line 78
    .line 79
    .line 80
    move-result-object p0

    .line 81
    invoke-static {p1, v2, p0}, Landroidx/lifecycle/z0;->b(Ljava/lang/Class;Ljava/lang/reflect/Constructor;[Ljava/lang/Object;)Landroidx/lifecycle/b1;

    .line 82
    .line 83
    .line 84
    move-result-object p0

    .line 85
    return-object p0

    .line 86
    :cond_2
    invoke-static {p2}, Landroidx/lifecycle/v0;->b(Lp7/c;)Landroidx/lifecycle/s0;

    .line 87
    .line 88
    .line 89
    move-result-object p0

    .line 90
    filled-new-array {p0}, [Ljava/lang/Object;

    .line 91
    .line 92
    .line 93
    move-result-object p0

    .line 94
    invoke-static {p1, v2, p0}, Landroidx/lifecycle/z0;->b(Ljava/lang/Class;Ljava/lang/reflect/Constructor;[Ljava/lang/Object;)Landroidx/lifecycle/b1;

    .line 95
    .line 96
    .line 97
    move-result-object p0

    .line 98
    return-object p0

    .line 99
    :cond_3
    iget-object p2, p0, Landroidx/lifecycle/y0;->d:Landroidx/lifecycle/r;

    .line 100
    .line 101
    if-eqz p2, :cond_4

    .line 102
    .line 103
    invoke-virtual {p0, p1, v1}, Landroidx/lifecycle/y0;->d(Ljava/lang/Class;Ljava/lang/String;)Landroidx/lifecycle/b1;

    .line 104
    .line 105
    .line 106
    move-result-object p0

    .line 107
    return-object p0

    .line 108
    :cond_4
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 109
    .line 110
    const-string p1, "SAVED_STATE_REGISTRY_OWNER_KEY andVIEW_MODEL_STORE_OWNER_KEY must be provided in the creation extras tosuccessfully create a ViewModel."

    .line 111
    .line 112
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 113
    .line 114
    .line 115
    throw p0

    .line 116
    :cond_5
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 117
    .line 118
    const-string p1, "VIEW_MODEL_KEY must always be provided by ViewModelProvider"

    .line 119
    .line 120
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 121
    .line 122
    .line 123
    throw p0
.end method

.method public final d(Ljava/lang/Class;Ljava/lang/String;)Landroidx/lifecycle/b1;
    .locals 9

    .line 1
    iget-object v0, p0, Landroidx/lifecycle/y0;->d:Landroidx/lifecycle/r;

    .line 2
    .line 3
    if-eqz v0, :cond_a

    .line 4
    .line 5
    const-class v1, Landroidx/lifecycle/a;

    .line 6
    .line 7
    invoke-virtual {v1, p1}, Ljava/lang/Class;->isAssignableFrom(Ljava/lang/Class;)Z

    .line 8
    .line 9
    .line 10
    move-result v1

    .line 11
    iget-object v2, p0, Landroidx/lifecycle/y0;->a:Landroid/app/Application;

    .line 12
    .line 13
    if-eqz v1, :cond_0

    .line 14
    .line 15
    if-eqz v2, :cond_0

    .line 16
    .line 17
    sget-object v3, Landroidx/lifecycle/z0;->a:Ljava/util/List;

    .line 18
    .line 19
    invoke-static {p1, v3}, Landroidx/lifecycle/z0;->a(Ljava/lang/Class;Ljava/util/List;)Ljava/lang/reflect/Constructor;

    .line 20
    .line 21
    .line 22
    move-result-object v3

    .line 23
    goto :goto_0

    .line 24
    :cond_0
    sget-object v3, Landroidx/lifecycle/z0;->b:Ljava/util/List;

    .line 25
    .line 26
    invoke-static {p1, v3}, Landroidx/lifecycle/z0;->a(Ljava/lang/Class;Ljava/util/List;)Ljava/lang/reflect/Constructor;

    .line 27
    .line 28
    .line 29
    move-result-object v3

    .line 30
    :goto_0
    if-nez v3, :cond_3

    .line 31
    .line 32
    if-eqz v2, :cond_1

    .line 33
    .line 34
    iget-object p0, p0, Landroidx/lifecycle/y0;->b:Landroidx/lifecycle/d1;

    .line 35
    .line 36
    invoke-virtual {p0, p1}, Landroidx/lifecycle/d1;->b(Ljava/lang/Class;)Landroidx/lifecycle/b1;

    .line 37
    .line 38
    .line 39
    move-result-object p0

    .line 40
    return-object p0

    .line 41
    :cond_1
    sget-object p0, Landroidx/lifecycle/f1;->a:Landroidx/lifecycle/f1;

    .line 42
    .line 43
    if-nez p0, :cond_2

    .line 44
    .line 45
    new-instance p0, Landroidx/lifecycle/f1;

    .line 46
    .line 47
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 48
    .line 49
    .line 50
    sput-object p0, Landroidx/lifecycle/f1;->a:Landroidx/lifecycle/f1;

    .line 51
    .line 52
    :cond_2
    sget-object p0, Landroidx/lifecycle/f1;->a:Landroidx/lifecycle/f1;

    .line 53
    .line 54
    invoke-static {p0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 55
    .line 56
    .line 57
    invoke-static {p1}, Lkp/n;->a(Ljava/lang/Class;)Landroidx/lifecycle/b1;

    .line 58
    .line 59
    .line 60
    move-result-object p0

    .line 61
    return-object p0

    .line 62
    :cond_3
    iget-object v4, p0, Landroidx/lifecycle/y0;->e:Lra/d;

    .line 63
    .line 64
    invoke-static {v4}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 65
    .line 66
    .line 67
    invoke-virtual {v4, p2}, Lra/d;->a(Ljava/lang/String;)Landroid/os/Bundle;

    .line 68
    .line 69
    .line 70
    move-result-object v5

    .line 71
    if-nez v5, :cond_4

    .line 72
    .line 73
    iget-object v5, p0, Landroidx/lifecycle/y0;->c:Landroid/os/Bundle;

    .line 74
    .line 75
    :cond_4
    if-nez v5, :cond_5

    .line 76
    .line 77
    new-instance p0, Landroidx/lifecycle/s0;

    .line 78
    .line 79
    invoke-direct {p0}, Landroidx/lifecycle/s0;-><init>()V

    .line 80
    .line 81
    .line 82
    goto :goto_2

    .line 83
    :cond_5
    const-class p0, Landroidx/lifecycle/s0;

    .line 84
    .line 85
    invoke-virtual {p0}, Ljava/lang/Class;->getClassLoader()Ljava/lang/ClassLoader;

    .line 86
    .line 87
    .line 88
    move-result-object p0

    .line 89
    invoke-static {p0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 90
    .line 91
    .line 92
    invoke-virtual {v5, p0}, Landroid/os/Bundle;->setClassLoader(Ljava/lang/ClassLoader;)V

    .line 93
    .line 94
    .line 95
    invoke-virtual {v5}, Landroid/os/BaseBundle;->size()I

    .line 96
    .line 97
    .line 98
    move-result p0

    .line 99
    new-instance v6, Lnx0/f;

    .line 100
    .line 101
    invoke-direct {v6, p0}, Lnx0/f;-><init>(I)V

    .line 102
    .line 103
    .line 104
    invoke-virtual {v5}, Landroid/os/BaseBundle;->keySet()Ljava/util/Set;

    .line 105
    .line 106
    .line 107
    move-result-object p0

    .line 108
    invoke-interface {p0}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 109
    .line 110
    .line 111
    move-result-object p0

    .line 112
    :goto_1
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 113
    .line 114
    .line 115
    move-result v7

    .line 116
    if-eqz v7, :cond_6

    .line 117
    .line 118
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 119
    .line 120
    .line 121
    move-result-object v7

    .line 122
    check-cast v7, Ljava/lang/String;

    .line 123
    .line 124
    invoke-static {v7}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 125
    .line 126
    .line 127
    invoke-virtual {v5, v7}, Landroid/os/BaseBundle;->get(Ljava/lang/String;)Ljava/lang/Object;

    .line 128
    .line 129
    .line 130
    move-result-object v8

    .line 131
    invoke-virtual {v6, v7, v8}, Lnx0/f;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 132
    .line 133
    .line 134
    goto :goto_1

    .line 135
    :cond_6
    invoke-virtual {v6}, Lnx0/f;->b()Lnx0/f;

    .line 136
    .line 137
    .line 138
    move-result-object p0

    .line 139
    new-instance v5, Landroidx/lifecycle/s0;

    .line 140
    .line 141
    invoke-direct {v5, p0}, Landroidx/lifecycle/s0;-><init>(Lnx0/f;)V

    .line 142
    .line 143
    .line 144
    move-object p0, v5

    .line 145
    :goto_2
    new-instance v5, Landroidx/lifecycle/t0;

    .line 146
    .line 147
    invoke-direct {v5, p2, p0}, Landroidx/lifecycle/t0;-><init>(Ljava/lang/String;Landroidx/lifecycle/s0;)V

    .line 148
    .line 149
    .line 150
    invoke-virtual {v5, v0, v4}, Landroidx/lifecycle/t0;->a(Landroidx/lifecycle/r;Lra/d;)V

    .line 151
    .line 152
    .line 153
    invoke-virtual {v0}, Landroidx/lifecycle/r;->b()Landroidx/lifecycle/q;

    .line 154
    .line 155
    .line 156
    move-result-object p2

    .line 157
    sget-object v6, Landroidx/lifecycle/q;->e:Landroidx/lifecycle/q;

    .line 158
    .line 159
    if-eq p2, v6, :cond_8

    .line 160
    .line 161
    sget-object v6, Landroidx/lifecycle/q;->g:Landroidx/lifecycle/q;

    .line 162
    .line 163
    invoke-virtual {p2, v6}, Ljava/lang/Enum;->compareTo(Ljava/lang/Enum;)I

    .line 164
    .line 165
    .line 166
    move-result p2

    .line 167
    if-ltz p2, :cond_7

    .line 168
    .line 169
    goto :goto_3

    .line 170
    :cond_7
    new-instance p2, Landroidx/lifecycle/h;

    .line 171
    .line 172
    invoke-direct {p2, v0, v4}, Landroidx/lifecycle/h;-><init>(Landroidx/lifecycle/r;Lra/d;)V

    .line 173
    .line 174
    .line 175
    invoke-virtual {v0, p2}, Landroidx/lifecycle/r;->a(Landroidx/lifecycle/w;)V

    .line 176
    .line 177
    .line 178
    goto :goto_4

    .line 179
    :cond_8
    :goto_3
    invoke-virtual {v4}, Lra/d;->d()V

    .line 180
    .line 181
    .line 182
    :goto_4
    if-eqz v1, :cond_9

    .line 183
    .line 184
    if-eqz v2, :cond_9

    .line 185
    .line 186
    filled-new-array {v2, p0}, [Ljava/lang/Object;

    .line 187
    .line 188
    .line 189
    move-result-object p0

    .line 190
    invoke-static {p1, v3, p0}, Landroidx/lifecycle/z0;->b(Ljava/lang/Class;Ljava/lang/reflect/Constructor;[Ljava/lang/Object;)Landroidx/lifecycle/b1;

    .line 191
    .line 192
    .line 193
    move-result-object p0

    .line 194
    goto :goto_5

    .line 195
    :cond_9
    filled-new-array {p0}, [Ljava/lang/Object;

    .line 196
    .line 197
    .line 198
    move-result-object p0

    .line 199
    invoke-static {p1, v3, p0}, Landroidx/lifecycle/z0;->b(Ljava/lang/Class;Ljava/lang/reflect/Constructor;[Ljava/lang/Object;)Landroidx/lifecycle/b1;

    .line 200
    .line 201
    .line 202
    move-result-object p0

    .line 203
    :goto_5
    const-string p1, "androidx.lifecycle.savedstate.vm.tag"

    .line 204
    .line 205
    invoke-virtual {p0, p1, v5}, Landroidx/lifecycle/b1;->addCloseable(Ljava/lang/String;Ljava/lang/AutoCloseable;)V

    .line 206
    .line 207
    .line 208
    return-object p0

    .line 209
    :cond_a
    new-instance p0, Ljava/lang/UnsupportedOperationException;

    .line 210
    .line 211
    const-string p1, "SavedStateViewModelFactory constructed with empty constructor supports only calls to create(modelClass: Class<T>, extras: CreationExtras)."

    .line 212
    .line 213
    invoke-direct {p0, p1}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    .line 214
    .line 215
    .line 216
    throw p0
.end method
