.class public abstract Lz9/u;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final synthetic h:I


# instance fields
.field public final d:Ljava/lang/String;

.field public final e:Lca/j;

.field public f:Lz9/v;

.field public final g:Landroidx/collection/b1;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Ljava/util/LinkedHashMap;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/util/LinkedHashMap;-><init>()V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public constructor <init>(Lz9/j0;)V
    .locals 1

    .line 1
    const-string v0, "navigator"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    sget-object v0, Lz9/k0;->b:Ljava/util/LinkedHashMap;

    .line 7
    .line 8
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 9
    .line 10
    .line 11
    move-result-object p1

    .line 12
    invoke-static {p1}, Ljp/s0;->a(Ljava/lang/Class;)Ljava/lang/String;

    .line 13
    .line 14
    .line 15
    move-result-object p1

    .line 16
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 17
    .line 18
    .line 19
    iput-object p1, p0, Lz9/u;->d:Ljava/lang/String;

    .line 20
    .line 21
    new-instance p1, Lca/j;

    .line 22
    .line 23
    invoke-direct {p1}, Ljava/lang/Object;-><init>()V

    .line 24
    .line 25
    .line 26
    iput-object p0, p1, Lca/j;->b:Ljava/lang/Object;

    .line 27
    .line 28
    new-instance v0, Ljava/util/ArrayList;

    .line 29
    .line 30
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 31
    .line 32
    .line 33
    iput-object v0, p1, Lca/j;->c:Ljava/lang/Object;

    .line 34
    .line 35
    new-instance v0, Ljava/util/LinkedHashMap;

    .line 36
    .line 37
    invoke-direct {v0}, Ljava/util/LinkedHashMap;-><init>()V

    .line 38
    .line 39
    .line 40
    iput-object v0, p1, Lca/j;->d:Ljava/lang/Object;

    .line 41
    .line 42
    iput-object p1, p0, Lz9/u;->e:Lca/j;

    .line 43
    .line 44
    new-instance p1, Landroidx/collection/b1;

    .line 45
    .line 46
    const/4 v0, 0x0

    .line 47
    invoke-direct {p1, v0}, Landroidx/collection/b1;-><init>(I)V

    .line 48
    .line 49
    .line 50
    iput-object p1, p0, Lz9/u;->g:Landroidx/collection/b1;

    .line 51
    .line 52
    return-void
.end method


# virtual methods
.method public final c(Lz9/r;)V
    .locals 3

    .line 1
    const-string v0, "navDeepLink"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lz9/u;->e:Lca/j;

    .line 7
    .line 8
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 9
    .line 10
    .line 11
    iget-object v0, p0, Lca/j;->d:Ljava/lang/Object;

    .line 12
    .line 13
    check-cast v0, Ljava/util/LinkedHashMap;

    .line 14
    .line 15
    new-instance v1, Lca/h;

    .line 16
    .line 17
    const/4 v2, 0x0

    .line 18
    invoke-direct {v1, p1, v2}, Lca/h;-><init>(Lz9/r;I)V

    .line 19
    .line 20
    .line 21
    invoke-static {v0, v1}, Ljb0/b;->e(Ljava/util/Map;Lay0/k;)Ljava/util/ArrayList;

    .line 22
    .line 23
    .line 24
    move-result-object v0

    .line 25
    invoke-virtual {v0}, Ljava/util/ArrayList;->isEmpty()Z

    .line 26
    .line 27
    .line 28
    move-result v1

    .line 29
    if-eqz v1, :cond_0

    .line 30
    .line 31
    iget-object p0, p0, Lca/j;->c:Ljava/lang/Object;

    .line 32
    .line 33
    check-cast p0, Ljava/util/ArrayList;

    .line 34
    .line 35
    invoke-virtual {p0, p1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 36
    .line 37
    .line 38
    return-void

    .line 39
    :cond_0
    new-instance v1, Ljava/lang/StringBuilder;

    .line 40
    .line 41
    const-string v2, "Deep link "

    .line 42
    .line 43
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 44
    .line 45
    .line 46
    iget-object p1, p1, Lz9/r;->a:Ljava/lang/String;

    .line 47
    .line 48
    invoke-virtual {v1, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 49
    .line 50
    .line 51
    const-string p1, " can\'t be used to open destination "

    .line 52
    .line 53
    invoke-virtual {v1, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 54
    .line 55
    .line 56
    iget-object p0, p0, Lca/j;->b:Ljava/lang/Object;

    .line 57
    .line 58
    check-cast p0, Lz9/u;

    .line 59
    .line 60
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 61
    .line 62
    .line 63
    const-string p0, ".\nFollowing required arguments are missing: "

    .line 64
    .line 65
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 66
    .line 67
    .line 68
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 69
    .line 70
    .line 71
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 72
    .line 73
    .line 74
    move-result-object p0

    .line 75
    new-instance p1, Ljava/lang/IllegalArgumentException;

    .line 76
    .line 77
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 78
    .line 79
    .line 80
    move-result-object p0

    .line 81
    invoke-direct {p1, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 82
    .line 83
    .line 84
    throw p1
.end method

.method public final e(Landroid/os/Bundle;)Landroid/os/Bundle;
    .locals 5

    .line 1
    iget-object p0, p0, Lz9/u;->e:Lca/j;

    .line 2
    .line 3
    iget-object p0, p0, Lca/j;->d:Ljava/lang/Object;

    .line 4
    .line 5
    check-cast p0, Ljava/util/LinkedHashMap;

    .line 6
    .line 7
    if-nez p1, :cond_0

    .line 8
    .line 9
    invoke-interface {p0}, Ljava/util/Map;->isEmpty()Z

    .line 10
    .line 11
    .line 12
    move-result v0

    .line 13
    if-eqz v0, :cond_0

    .line 14
    .line 15
    const/4 p0, 0x0

    .line 16
    return-object p0

    .line 17
    :cond_0
    const/4 v0, 0x0

    .line 18
    new-array v1, v0, [Llx0/l;

    .line 19
    .line 20
    invoke-static {v1, v0}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    .line 21
    .line 22
    .line 23
    move-result-object v0

    .line 24
    check-cast v0, [Llx0/l;

    .line 25
    .line 26
    invoke-static {v0}, Llp/xf;->a([Llx0/l;)Landroid/os/Bundle;

    .line 27
    .line 28
    .line 29
    move-result-object v0

    .line 30
    invoke-virtual {p0}, Ljava/util/LinkedHashMap;->entrySet()Ljava/util/Set;

    .line 31
    .line 32
    .line 33
    move-result-object v1

    .line 34
    invoke-interface {v1}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 35
    .line 36
    .line 37
    move-result-object v1

    .line 38
    :goto_0
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 39
    .line 40
    .line 41
    move-result v2

    .line 42
    const-string v3, "name"

    .line 43
    .line 44
    if-eqz v2, :cond_1

    .line 45
    .line 46
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 47
    .line 48
    .line 49
    move-result-object v2

    .line 50
    check-cast v2, Ljava/util/Map$Entry;

    .line 51
    .line 52
    invoke-interface {v2}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 53
    .line 54
    .line 55
    move-result-object v4

    .line 56
    check-cast v4, Ljava/lang/String;

    .line 57
    .line 58
    invoke-interface {v2}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 59
    .line 60
    .line 61
    move-result-object v2

    .line 62
    check-cast v2, Lz9/i;

    .line 63
    .line 64
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 65
    .line 66
    .line 67
    invoke-static {v4, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 68
    .line 69
    .line 70
    goto :goto_0

    .line 71
    :cond_1
    if-eqz p1, :cond_5

    .line 72
    .line 73
    invoke-virtual {v0, p1}, Landroid/os/Bundle;->putAll(Landroid/os/Bundle;)V

    .line 74
    .line 75
    .line 76
    invoke-virtual {p0}, Ljava/util/LinkedHashMap;->entrySet()Ljava/util/Set;

    .line 77
    .line 78
    .line 79
    move-result-object p0

    .line 80
    invoke-interface {p0}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 81
    .line 82
    .line 83
    move-result-object p0

    .line 84
    :cond_2
    :goto_1
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 85
    .line 86
    .line 87
    move-result p1

    .line 88
    if-eqz p1, :cond_5

    .line 89
    .line 90
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 91
    .line 92
    .line 93
    move-result-object p1

    .line 94
    check-cast p1, Ljava/util/Map$Entry;

    .line 95
    .line 96
    invoke-interface {p1}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 97
    .line 98
    .line 99
    move-result-object v1

    .line 100
    check-cast v1, Ljava/lang/String;

    .line 101
    .line 102
    invoke-interface {p1}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 103
    .line 104
    .line 105
    move-result-object p1

    .line 106
    check-cast p1, Lz9/i;

    .line 107
    .line 108
    iget-boolean v2, p1, Lz9/i;->d:Z

    .line 109
    .line 110
    iget-object v4, p1, Lz9/i;->a:Lz9/g0;

    .line 111
    .line 112
    if-nez v2, :cond_2

    .line 113
    .line 114
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 115
    .line 116
    .line 117
    iget-boolean p1, p1, Lz9/i;->b:Z

    .line 118
    .line 119
    if-nez p1, :cond_3

    .line 120
    .line 121
    invoke-virtual {v0, v1}, Landroid/os/BaseBundle;->containsKey(Ljava/lang/String;)Z

    .line 122
    .line 123
    .line 124
    move-result p1

    .line 125
    if-eqz p1, :cond_3

    .line 126
    .line 127
    invoke-static {v1, v0}, Lkp/t;->j(Ljava/lang/String;Landroid/os/Bundle;)Z

    .line 128
    .line 129
    .line 130
    move-result p1

    .line 131
    if-nez p1, :cond_4

    .line 132
    .line 133
    :cond_3
    :try_start_0
    invoke-virtual {v4, v1, v0}, Lz9/g0;->a(Ljava/lang/String;Landroid/os/Bundle;)Ljava/lang/Object;
    :try_end_0
    .catch Ljava/lang/IllegalStateException; {:try_start_0 .. :try_end_0} :catch_0

    .line 134
    .line 135
    .line 136
    goto :goto_1

    .line 137
    :catch_0
    :cond_4
    const-string p0, "Wrong argument type for \'"

    .line 138
    .line 139
    const-string p1, "\' in argument savedState. "

    .line 140
    .line 141
    invoke-static {p0, v1, p1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->q(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 142
    .line 143
    .line 144
    move-result-object p0

    .line 145
    invoke-virtual {v4}, Lz9/g0;->b()Ljava/lang/String;

    .line 146
    .line 147
    .line 148
    move-result-object p1

    .line 149
    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 150
    .line 151
    .line 152
    const-string p1, " expected."

    .line 153
    .line 154
    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 155
    .line 156
    .line 157
    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 158
    .line 159
    .line 160
    move-result-object p0

    .line 161
    new-instance p1, Ljava/lang/IllegalArgumentException;

    .line 162
    .line 163
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 164
    .line 165
    .line 166
    move-result-object p0

    .line 167
    invoke-direct {p1, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 168
    .line 169
    .line 170
    throw p1

    .line 171
    :cond_5
    return-object v0
.end method

.method public equals(Ljava/lang/Object;)Z
    .locals 10

    .line 1
    const/4 v0, 0x1

    .line 2
    if-ne p0, p1, :cond_0

    .line 3
    .line 4
    goto/16 :goto_4

    .line 5
    .line 6
    :cond_0
    const/4 v1, 0x0

    .line 7
    if-eqz p1, :cond_7

    .line 8
    .line 9
    instance-of v2, p1, Lz9/u;

    .line 10
    .line 11
    if-nez v2, :cond_1

    .line 12
    .line 13
    goto/16 :goto_5

    .line 14
    .line 15
    :cond_1
    iget-object v2, p0, Lz9/u;->e:Lca/j;

    .line 16
    .line 17
    iget-object v3, v2, Lca/j;->c:Ljava/lang/Object;

    .line 18
    .line 19
    check-cast v3, Ljava/util/ArrayList;

    .line 20
    .line 21
    check-cast p1, Lz9/u;

    .line 22
    .line 23
    iget-object v4, p1, Lz9/u;->g:Landroidx/collection/b1;

    .line 24
    .line 25
    iget-object v5, p1, Lz9/u;->e:Lca/j;

    .line 26
    .line 27
    iget-object v6, v5, Lca/j;->c:Ljava/lang/Object;

    .line 28
    .line 29
    check-cast v6, Ljava/util/ArrayList;

    .line 30
    .line 31
    invoke-static {v3, v6}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 32
    .line 33
    .line 34
    move-result v3

    .line 35
    iget-object v6, p0, Lz9/u;->g:Landroidx/collection/b1;

    .line 36
    .line 37
    invoke-virtual {v6}, Landroidx/collection/b1;->f()I

    .line 38
    .line 39
    .line 40
    move-result v7

    .line 41
    invoke-virtual {v4}, Landroidx/collection/b1;->f()I

    .line 42
    .line 43
    .line 44
    move-result v8

    .line 45
    if-ne v7, v8, :cond_4

    .line 46
    .line 47
    new-instance v7, Landroidx/collection/c1;

    .line 48
    .line 49
    invoke-direct {v7, v6}, Landroidx/collection/c1;-><init>(Landroidx/collection/b1;)V

    .line 50
    .line 51
    .line 52
    invoke-static {v7}, Lky0/l;->b(Ljava/util/Iterator;)Lky0/j;

    .line 53
    .line 54
    .line 55
    move-result-object v7

    .line 56
    check-cast v7, Lky0/a;

    .line 57
    .line 58
    invoke-virtual {v7}, Lky0/a;->iterator()Ljava/util/Iterator;

    .line 59
    .line 60
    .line 61
    move-result-object v7

    .line 62
    :cond_2
    invoke-interface {v7}, Ljava/util/Iterator;->hasNext()Z

    .line 63
    .line 64
    .line 65
    move-result v8

    .line 66
    if-eqz v8, :cond_3

    .line 67
    .line 68
    invoke-interface {v7}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 69
    .line 70
    .line 71
    move-result-object v8

    .line 72
    check-cast v8, Ljava/lang/Number;

    .line 73
    .line 74
    invoke-virtual {v8}, Ljava/lang/Number;->intValue()I

    .line 75
    .line 76
    .line 77
    move-result v8

    .line 78
    invoke-virtual {v6, v8}, Landroidx/collection/b1;->c(I)Ljava/lang/Object;

    .line 79
    .line 80
    .line 81
    move-result-object v9

    .line 82
    invoke-virtual {v4, v8}, Landroidx/collection/b1;->c(I)Ljava/lang/Object;

    .line 83
    .line 84
    .line 85
    move-result-object v8

    .line 86
    invoke-static {v9, v8}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 87
    .line 88
    .line 89
    move-result v8

    .line 90
    if-nez v8, :cond_2

    .line 91
    .line 92
    goto :goto_0

    .line 93
    :cond_3
    move v4, v0

    .line 94
    goto :goto_1

    .line 95
    :cond_4
    :goto_0
    move v4, v1

    .line 96
    :goto_1
    invoke-virtual {p0}, Lz9/u;->i()Ljava/util/Map;

    .line 97
    .line 98
    .line 99
    move-result-object v6

    .line 100
    invoke-interface {v6}, Ljava/util/Map;->size()I

    .line 101
    .line 102
    .line 103
    move-result v6

    .line 104
    invoke-virtual {p1}, Lz9/u;->i()Ljava/util/Map;

    .line 105
    .line 106
    .line 107
    move-result-object v7

    .line 108
    invoke-interface {v7}, Ljava/util/Map;->size()I

    .line 109
    .line 110
    .line 111
    move-result v7

    .line 112
    if-ne v6, v7, :cond_6

    .line 113
    .line 114
    invoke-virtual {p0}, Lz9/u;->i()Ljava/util/Map;

    .line 115
    .line 116
    .line 117
    move-result-object p0

    .line 118
    invoke-interface {p0}, Ljava/util/Map;->entrySet()Ljava/util/Set;

    .line 119
    .line 120
    .line 121
    move-result-object p0

    .line 122
    check-cast p0, Ljava/lang/Iterable;

    .line 123
    .line 124
    invoke-static {p0}, Lmx0/q;->z(Ljava/lang/Iterable;)Lky0/m;

    .line 125
    .line 126
    .line 127
    move-result-object p0

    .line 128
    iget-object p0, p0, Lky0/m;->b:Ljava/lang/Object;

    .line 129
    .line 130
    check-cast p0, Ljava/lang/Iterable;

    .line 131
    .line 132
    invoke-interface {p0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 133
    .line 134
    .line 135
    move-result-object p0

    .line 136
    :goto_2
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 137
    .line 138
    .line 139
    move-result v6

    .line 140
    if-eqz v6, :cond_5

    .line 141
    .line 142
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 143
    .line 144
    .line 145
    move-result-object v6

    .line 146
    check-cast v6, Ljava/util/Map$Entry;

    .line 147
    .line 148
    invoke-virtual {p1}, Lz9/u;->i()Ljava/util/Map;

    .line 149
    .line 150
    .line 151
    move-result-object v7

    .line 152
    invoke-interface {v6}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 153
    .line 154
    .line 155
    move-result-object v8

    .line 156
    invoke-interface {v7, v8}, Ljava/util/Map;->containsKey(Ljava/lang/Object;)Z

    .line 157
    .line 158
    .line 159
    move-result v7

    .line 160
    if-eqz v7, :cond_6

    .line 161
    .line 162
    invoke-virtual {p1}, Lz9/u;->i()Ljava/util/Map;

    .line 163
    .line 164
    .line 165
    move-result-object v7

    .line 166
    invoke-interface {v6}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 167
    .line 168
    .line 169
    move-result-object v8

    .line 170
    invoke-interface {v7, v8}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 171
    .line 172
    .line 173
    move-result-object v7

    .line 174
    invoke-interface {v6}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 175
    .line 176
    .line 177
    move-result-object v6

    .line 178
    invoke-static {v7, v6}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 179
    .line 180
    .line 181
    move-result v6

    .line 182
    if-eqz v6, :cond_6

    .line 183
    .line 184
    goto :goto_2

    .line 185
    :cond_5
    move p0, v0

    .line 186
    goto :goto_3

    .line 187
    :cond_6
    move p0, v1

    .line 188
    :goto_3
    iget p1, v2, Lca/j;->a:I

    .line 189
    .line 190
    iget v6, v5, Lca/j;->a:I

    .line 191
    .line 192
    if-ne p1, v6, :cond_7

    .line 193
    .line 194
    iget-object p1, v2, Lca/j;->e:Ljava/lang/Object;

    .line 195
    .line 196
    check-cast p1, Ljava/lang/String;

    .line 197
    .line 198
    iget-object v2, v5, Lca/j;->e:Ljava/lang/Object;

    .line 199
    .line 200
    check-cast v2, Ljava/lang/String;

    .line 201
    .line 202
    invoke-static {p1, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 203
    .line 204
    .line 205
    move-result p1

    .line 206
    if-eqz p1, :cond_7

    .line 207
    .line 208
    if-eqz v3, :cond_7

    .line 209
    .line 210
    if-eqz v4, :cond_7

    .line 211
    .line 212
    if-eqz p0, :cond_7

    .line 213
    .line 214
    :goto_4
    return v0

    .line 215
    :cond_7
    :goto_5
    return v1
.end method

.method public final g(Lz9/u;)[I
    .locals 5

    .line 1
    new-instance v0, Lmx0/l;

    .line 2
    .line 3
    invoke-direct {v0}, Lmx0/l;-><init>()V

    .line 4
    .line 5
    .line 6
    :goto_0
    iget-object v1, p0, Lz9/u;->e:Lca/j;

    .line 7
    .line 8
    iget-object v2, p0, Lz9/u;->f:Lz9/v;

    .line 9
    .line 10
    if-eqz p1, :cond_0

    .line 11
    .line 12
    iget-object v3, p1, Lz9/u;->f:Lz9/v;

    .line 13
    .line 14
    goto :goto_1

    .line 15
    :cond_0
    const/4 v3, 0x0

    .line 16
    :goto_1
    if-eqz v3, :cond_1

    .line 17
    .line 18
    iget-object v3, p1, Lz9/u;->f:Lz9/v;

    .line 19
    .line 20
    invoke-static {v3}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 21
    .line 22
    .line 23
    iget v4, v1, Lca/j;->a:I

    .line 24
    .line 25
    iget-object v3, v3, Lz9/v;->i:Lca/m;

    .line 26
    .line 27
    invoke-virtual {v3, v4}, Lca/m;->d(I)Lz9/u;

    .line 28
    .line 29
    .line 30
    move-result-object v3

    .line 31
    if-ne v3, p0, :cond_1

    .line 32
    .line 33
    invoke-virtual {v0, p0}, Lmx0/l;->addFirst(Ljava/lang/Object;)V

    .line 34
    .line 35
    .line 36
    goto :goto_2

    .line 37
    :cond_1
    if-eqz v2, :cond_2

    .line 38
    .line 39
    iget-object v3, v2, Lz9/v;->i:Lca/m;

    .line 40
    .line 41
    iget v3, v3, Lca/m;->d:I

    .line 42
    .line 43
    iget v1, v1, Lca/j;->a:I

    .line 44
    .line 45
    if-eq v3, v1, :cond_3

    .line 46
    .line 47
    :cond_2
    invoke-virtual {v0, p0}, Lmx0/l;->addFirst(Ljava/lang/Object;)V

    .line 48
    .line 49
    .line 50
    :cond_3
    invoke-static {v2, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 51
    .line 52
    .line 53
    move-result p0

    .line 54
    if-eqz p0, :cond_4

    .line 55
    .line 56
    goto :goto_2

    .line 57
    :cond_4
    if-nez v2, :cond_6

    .line 58
    .line 59
    :goto_2
    invoke-static {v0}, Lmx0/q;->x0(Ljava/lang/Iterable;)Ljava/util/List;

    .line 60
    .line 61
    .line 62
    move-result-object p0

    .line 63
    check-cast p0, Ljava/lang/Iterable;

    .line 64
    .line 65
    new-instance p1, Ljava/util/ArrayList;

    .line 66
    .line 67
    const/16 v0, 0xa

    .line 68
    .line 69
    invoke-static {p0, v0}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 70
    .line 71
    .line 72
    move-result v0

    .line 73
    invoke-direct {p1, v0}, Ljava/util/ArrayList;-><init>(I)V

    .line 74
    .line 75
    .line 76
    invoke-interface {p0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 77
    .line 78
    .line 79
    move-result-object p0

    .line 80
    :goto_3
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 81
    .line 82
    .line 83
    move-result v0

    .line 84
    if-eqz v0, :cond_5

    .line 85
    .line 86
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 87
    .line 88
    .line 89
    move-result-object v0

    .line 90
    check-cast v0, Lz9/u;

    .line 91
    .line 92
    iget-object v0, v0, Lz9/u;->e:Lca/j;

    .line 93
    .line 94
    iget v0, v0, Lca/j;->a:I

    .line 95
    .line 96
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 97
    .line 98
    .line 99
    move-result-object v0

    .line 100
    invoke-interface {p1, v0}, Ljava/util/Collection;->add(Ljava/lang/Object;)Z

    .line 101
    .line 102
    .line 103
    goto :goto_3

    .line 104
    :cond_5
    invoke-static {p1}, Lmx0/q;->w0(Ljava/util/Collection;)[I

    .line 105
    .line 106
    .line 107
    move-result-object p0

    .line 108
    return-object p0

    .line 109
    :cond_6
    move-object p0, v2

    .line 110
    goto :goto_0
.end method

.method public hashCode()I
    .locals 6

    .line 1
    iget-object v0, p0, Lz9/u;->e:Lca/j;

    .line 2
    .line 3
    iget v1, v0, Lca/j;->a:I

    .line 4
    .line 5
    const/16 v2, 0x1f

    .line 6
    .line 7
    mul-int/2addr v1, v2

    .line 8
    iget-object v3, v0, Lca/j;->e:Ljava/lang/Object;

    .line 9
    .line 10
    check-cast v3, Ljava/lang/String;

    .line 11
    .line 12
    const/4 v4, 0x0

    .line 13
    if-eqz v3, :cond_0

    .line 14
    .line 15
    invoke-virtual {v3}, Ljava/lang/Object;->hashCode()I

    .line 16
    .line 17
    .line 18
    move-result v3

    .line 19
    goto :goto_0

    .line 20
    :cond_0
    move v3, v4

    .line 21
    :goto_0
    add-int/2addr v1, v3

    .line 22
    iget-object v0, v0, Lca/j;->c:Ljava/lang/Object;

    .line 23
    .line 24
    check-cast v0, Ljava/util/ArrayList;

    .line 25
    .line 26
    invoke-virtual {v0}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 27
    .line 28
    .line 29
    move-result-object v0

    .line 30
    :goto_1
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 31
    .line 32
    .line 33
    move-result v3

    .line 34
    if-eqz v3, :cond_1

    .line 35
    .line 36
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 37
    .line 38
    .line 39
    move-result-object v3

    .line 40
    check-cast v3, Lz9/r;

    .line 41
    .line 42
    mul-int/lit8 v1, v1, 0x1f

    .line 43
    .line 44
    iget-object v3, v3, Lz9/r;->a:Ljava/lang/String;

    .line 45
    .line 46
    invoke-virtual {v3}, Ljava/lang/Object;->hashCode()I

    .line 47
    .line 48
    .line 49
    move-result v3

    .line 50
    add-int/2addr v3, v1

    .line 51
    mul-int/lit16 v1, v3, 0x3c1

    .line 52
    .line 53
    goto :goto_1

    .line 54
    :cond_1
    const-string v0, "<this>"

    .line 55
    .line 56
    iget-object v3, p0, Lz9/u;->g:Landroidx/collection/b1;

    .line 57
    .line 58
    invoke-static {v3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 59
    .line 60
    .line 61
    invoke-virtual {v3}, Landroidx/collection/b1;->f()I

    .line 62
    .line 63
    .line 64
    move-result v0

    .line 65
    if-lez v0, :cond_2

    .line 66
    .line 67
    const/4 v0, 0x1

    .line 68
    goto :goto_2

    .line 69
    :cond_2
    move v0, v4

    .line 70
    :goto_2
    if-nez v0, :cond_5

    .line 71
    .line 72
    invoke-virtual {p0}, Lz9/u;->i()Ljava/util/Map;

    .line 73
    .line 74
    .line 75
    move-result-object v0

    .line 76
    invoke-interface {v0}, Ljava/util/Map;->keySet()Ljava/util/Set;

    .line 77
    .line 78
    .line 79
    move-result-object v0

    .line 80
    check-cast v0, Ljava/lang/Iterable;

    .line 81
    .line 82
    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 83
    .line 84
    .line 85
    move-result-object v0

    .line 86
    :goto_3
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 87
    .line 88
    .line 89
    move-result v3

    .line 90
    if-eqz v3, :cond_4

    .line 91
    .line 92
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 93
    .line 94
    .line 95
    move-result-object v3

    .line 96
    check-cast v3, Ljava/lang/String;

    .line 97
    .line 98
    mul-int/lit8 v1, v1, 0x1f

    .line 99
    .line 100
    invoke-static {v1, v2, v3}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->d(IILjava/lang/String;)I

    .line 101
    .line 102
    .line 103
    move-result v1

    .line 104
    invoke-virtual {p0}, Lz9/u;->i()Ljava/util/Map;

    .line 105
    .line 106
    .line 107
    move-result-object v5

    .line 108
    invoke-interface {v5, v3}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 109
    .line 110
    .line 111
    move-result-object v3

    .line 112
    if-eqz v3, :cond_3

    .line 113
    .line 114
    invoke-virtual {v3}, Ljava/lang/Object;->hashCode()I

    .line 115
    .line 116
    .line 117
    move-result v3

    .line 118
    goto :goto_4

    .line 119
    :cond_3
    move v3, v4

    .line 120
    :goto_4
    add-int/2addr v1, v3

    .line 121
    goto :goto_3

    .line 122
    :cond_4
    return v1

    .line 123
    :cond_5
    invoke-virtual {v3, v4}, Landroidx/collection/b1;->h(I)Ljava/lang/Object;

    .line 124
    .line 125
    .line 126
    move-result-object p0

    .line 127
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 128
    .line 129
    .line 130
    new-instance p0, Ljava/lang/ClassCastException;

    .line 131
    .line 132
    invoke-direct {p0}, Ljava/lang/ClassCastException;-><init>()V

    .line 133
    .line 134
    .line 135
    throw p0
.end method

.method public final i()Ljava/util/Map;
    .locals 0

    .line 1
    iget-object p0, p0, Lz9/u;->e:Lca/j;

    .line 2
    .line 3
    iget-object p0, p0, Lca/j;->d:Ljava/lang/Object;

    .line 4
    .line 5
    check-cast p0, Ljava/util/LinkedHashMap;

    .line 6
    .line 7
    invoke-static {p0}, Lmx0/x;->u(Ljava/util/Map;)Ljava/util/Map;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    return-object p0
.end method

.method public final k(Ljava/lang/String;Landroid/os/Bundle;)Z
    .locals 5

    .line 1
    const-string v0, "route"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lz9/u;->e:Lca/j;

    .line 7
    .line 8
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 9
    .line 10
    .line 11
    iget-object v0, p0, Lca/j;->e:Ljava/lang/Object;

    .line 12
    .line 13
    check-cast v0, Ljava/lang/String;

    .line 14
    .line 15
    invoke-static {v0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 16
    .line 17
    .line 18
    move-result v0

    .line 19
    if-eqz v0, :cond_0

    .line 20
    .line 21
    goto/16 :goto_4

    .line 22
    .line 23
    :cond_0
    invoke-virtual {p0, p1}, Lca/j;->h(Ljava/lang/String;)Lz9/t;

    .line 24
    .line 25
    .line 26
    move-result-object p1

    .line 27
    iget-object p0, p0, Lca/j;->b:Ljava/lang/Object;

    .line 28
    .line 29
    check-cast p0, Lz9/u;

    .line 30
    .line 31
    const/4 v0, 0x0

    .line 32
    if-eqz p1, :cond_1

    .line 33
    .line 34
    iget-object v1, p1, Lz9/t;->d:Lz9/u;

    .line 35
    .line 36
    goto :goto_0

    .line 37
    :cond_1
    move-object v1, v0

    .line 38
    :goto_0
    invoke-virtual {p0, v1}, Lz9/u;->equals(Ljava/lang/Object;)Z

    .line 39
    .line 40
    .line 41
    move-result p0

    .line 42
    if-nez p0, :cond_2

    .line 43
    .line 44
    goto :goto_5

    .line 45
    :cond_2
    iget-object p0, p1, Lz9/t;->e:Landroid/os/Bundle;

    .line 46
    .line 47
    if-eqz p2, :cond_a

    .line 48
    .line 49
    if-nez p0, :cond_3

    .line 50
    .line 51
    goto :goto_5

    .line 52
    :cond_3
    invoke-virtual {p0}, Landroid/os/BaseBundle;->keySet()Ljava/util/Set;

    .line 53
    .line 54
    .line 55
    move-result-object v1

    .line 56
    const-string v2, "keySet(...)"

    .line 57
    .line 58
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 59
    .line 60
    .line 61
    check-cast v1, Ljava/lang/Iterable;

    .line 62
    .line 63
    invoke-interface {v1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 64
    .line 65
    .line 66
    move-result-object v1

    .line 67
    :cond_4
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 68
    .line 69
    .line 70
    move-result v2

    .line 71
    if-eqz v2, :cond_9

    .line 72
    .line 73
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 74
    .line 75
    .line 76
    move-result-object v2

    .line 77
    check-cast v2, Ljava/lang/String;

    .line 78
    .line 79
    invoke-static {v2}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 80
    .line 81
    .line 82
    invoke-virtual {p2, v2}, Landroid/os/BaseBundle;->containsKey(Ljava/lang/String;)Z

    .line 83
    .line 84
    .line 85
    move-result v3

    .line 86
    if-nez v3, :cond_5

    .line 87
    .line 88
    goto :goto_5

    .line 89
    :cond_5
    iget-object v3, p1, Lz9/t;->d:Lz9/u;

    .line 90
    .line 91
    invoke-virtual {v3}, Lz9/u;->i()Ljava/util/Map;

    .line 92
    .line 93
    .line 94
    move-result-object v3

    .line 95
    invoke-interface {v3, v2}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 96
    .line 97
    .line 98
    move-result-object v3

    .line 99
    check-cast v3, Lz9/i;

    .line 100
    .line 101
    if-eqz v3, :cond_6

    .line 102
    .line 103
    iget-object v3, v3, Lz9/i;->a:Lz9/g0;

    .line 104
    .line 105
    goto :goto_1

    .line 106
    :cond_6
    move-object v3, v0

    .line 107
    :goto_1
    if-eqz v3, :cond_7

    .line 108
    .line 109
    invoke-virtual {v3, v2, p0}, Lz9/g0;->a(Ljava/lang/String;Landroid/os/Bundle;)Ljava/lang/Object;

    .line 110
    .line 111
    .line 112
    move-result-object v4

    .line 113
    goto :goto_2

    .line 114
    :cond_7
    move-object v4, v0

    .line 115
    :goto_2
    if-eqz v3, :cond_8

    .line 116
    .line 117
    invoke-virtual {v3, v2, p2}, Lz9/g0;->a(Ljava/lang/String;Landroid/os/Bundle;)Ljava/lang/Object;

    .line 118
    .line 119
    .line 120
    move-result-object v2

    .line 121
    goto :goto_3

    .line 122
    :cond_8
    move-object v2, v0

    .line 123
    :goto_3
    if-eqz v3, :cond_4

    .line 124
    .line 125
    invoke-virtual {v3, v4, v2}, Lz9/g0;->g(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 126
    .line 127
    .line 128
    move-result v2

    .line 129
    if-nez v2, :cond_4

    .line 130
    .line 131
    goto :goto_5

    .line 132
    :cond_9
    :goto_4
    const/4 p0, 0x1

    .line 133
    return p0

    .line 134
    :cond_a
    :goto_5
    const/4 p0, 0x0

    .line 135
    return p0
.end method

.method public m(Lrn/i;)Lz9/t;
    .locals 18

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    iget-object v0, v0, Lz9/u;->e:Lca/j;

    .line 6
    .line 7
    iget-object v2, v0, Lca/j;->d:Ljava/lang/Object;

    .line 8
    .line 9
    check-cast v2, Ljava/util/LinkedHashMap;

    .line 10
    .line 11
    iget-object v3, v1, Lrn/i;->f:Ljava/lang/Object;

    .line 12
    .line 13
    check-cast v3, Landroid/net/Uri;

    .line 14
    .line 15
    iget-object v4, v0, Lca/j;->c:Ljava/lang/Object;

    .line 16
    .line 17
    check-cast v4, Ljava/util/ArrayList;

    .line 18
    .line 19
    invoke-virtual {v4}, Ljava/util/ArrayList;->isEmpty()Z

    .line 20
    .line 21
    .line 22
    move-result v5

    .line 23
    const/4 v6, 0x0

    .line 24
    if-eqz v5, :cond_0

    .line 25
    .line 26
    return-object v6

    .line 27
    :cond_0
    invoke-virtual {v4}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 28
    .line 29
    .line 30
    move-result-object v4

    .line 31
    move-object v5, v6

    .line 32
    :cond_1
    :goto_0
    invoke-interface {v4}, Ljava/util/Iterator;->hasNext()Z

    .line 33
    .line 34
    .line 35
    move-result v7

    .line 36
    if-eqz v7, :cond_c

    .line 37
    .line 38
    invoke-interface {v4}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 39
    .line 40
    .line 41
    move-result-object v7

    .line 42
    check-cast v7, Lz9/r;

    .line 43
    .line 44
    invoke-virtual {v7}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 45
    .line 46
    .line 47
    iget-object v8, v7, Lz9/r;->d:Llx0/q;

    .line 48
    .line 49
    invoke-virtual {v8}, Llx0/q;->getValue()Ljava/lang/Object;

    .line 50
    .line 51
    .line 52
    move-result-object v9

    .line 53
    check-cast v9, Lly0/n;

    .line 54
    .line 55
    const/4 v10, 0x1

    .line 56
    const/4 v11, 0x0

    .line 57
    if-nez v9, :cond_2

    .line 58
    .line 59
    move v9, v10

    .line 60
    goto :goto_1

    .line 61
    :cond_2
    if-nez v3, :cond_3

    .line 62
    .line 63
    move v9, v11

    .line 64
    goto :goto_1

    .line 65
    :cond_3
    invoke-virtual {v8}, Llx0/q;->getValue()Ljava/lang/Object;

    .line 66
    .line 67
    .line 68
    move-result-object v9

    .line 69
    check-cast v9, Lly0/n;

    .line 70
    .line 71
    invoke-static {v9}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 72
    .line 73
    .line 74
    invoke-virtual {v3}, Landroid/net/Uri;->toString()Ljava/lang/String;

    .line 75
    .line 76
    .line 77
    move-result-object v12

    .line 78
    invoke-virtual {v9, v12}, Lly0/n;->d(Ljava/lang/CharSequence;)Z

    .line 79
    .line 80
    .line 81
    move-result v9

    .line 82
    :goto_1
    if-eqz v9, :cond_1

    .line 83
    .line 84
    if-eqz v3, :cond_4

    .line 85
    .line 86
    invoke-virtual {v7, v3, v2}, Lz9/r;->d(Landroid/net/Uri;Ljava/util/LinkedHashMap;)Landroid/os/Bundle;

    .line 87
    .line 88
    .line 89
    move-result-object v9

    .line 90
    move-object v14, v9

    .line 91
    goto :goto_2

    .line 92
    :cond_4
    move-object v14, v6

    .line 93
    :goto_2
    invoke-virtual {v7, v3}, Lz9/r;->b(Landroid/net/Uri;)I

    .line 94
    .line 95
    .line 96
    move-result v16

    .line 97
    iget-object v9, v1, Lrn/i;->e:Ljava/lang/Object;

    .line 98
    .line 99
    check-cast v9, Ljava/lang/String;

    .line 100
    .line 101
    if-eqz v9, :cond_5

    .line 102
    .line 103
    invoke-virtual {v9, v6}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 104
    .line 105
    .line 106
    move-result v9

    .line 107
    if-eqz v9, :cond_5

    .line 108
    .line 109
    move/from16 v17, v10

    .line 110
    .line 111
    goto :goto_3

    .line 112
    :cond_5
    move/from16 v17, v11

    .line 113
    .line 114
    :goto_3
    if-nez v14, :cond_a

    .line 115
    .line 116
    if-nez v17, :cond_6

    .line 117
    .line 118
    goto :goto_0

    .line 119
    :cond_6
    const-string v9, "arguments"

    .line 120
    .line 121
    invoke-static {v2, v9}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 122
    .line 123
    .line 124
    new-array v9, v11, [Llx0/l;

    .line 125
    .line 126
    invoke-static {v9, v11}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    .line 127
    .line 128
    .line 129
    move-result-object v9

    .line 130
    check-cast v9, [Llx0/l;

    .line 131
    .line 132
    invoke-static {v9}, Llp/xf;->a([Llx0/l;)Landroid/os/Bundle;

    .line 133
    .line 134
    .line 135
    move-result-object v9

    .line 136
    if-nez v3, :cond_7

    .line 137
    .line 138
    goto :goto_4

    .line 139
    :cond_7
    invoke-virtual {v8}, Llx0/q;->getValue()Ljava/lang/Object;

    .line 140
    .line 141
    .line 142
    move-result-object v8

    .line 143
    check-cast v8, Lly0/n;

    .line 144
    .line 145
    if-eqz v8, :cond_9

    .line 146
    .line 147
    invoke-virtual {v3}, Landroid/net/Uri;->toString()Ljava/lang/String;

    .line 148
    .line 149
    .line 150
    move-result-object v10

    .line 151
    invoke-virtual {v8, v10}, Lly0/n;->c(Ljava/lang/String;)Lly0/l;

    .line 152
    .line 153
    .line 154
    move-result-object v8

    .line 155
    if-nez v8, :cond_8

    .line 156
    .line 157
    goto :goto_4

    .line 158
    :cond_8
    invoke-virtual {v7, v8, v9, v2}, Lz9/r;->e(Lly0/l;Landroid/os/Bundle;Ljava/util/Map;)Z

    .line 159
    .line 160
    .line 161
    iget-object v8, v7, Lz9/r;->e:Llx0/q;

    .line 162
    .line 163
    invoke-virtual {v8}, Llx0/q;->getValue()Ljava/lang/Object;

    .line 164
    .line 165
    .line 166
    move-result-object v8

    .line 167
    check-cast v8, Ljava/lang/Boolean;

    .line 168
    .line 169
    invoke-virtual {v8}, Ljava/lang/Boolean;->booleanValue()Z

    .line 170
    .line 171
    .line 172
    move-result v8

    .line 173
    if-eqz v8, :cond_9

    .line 174
    .line 175
    invoke-virtual {v7, v3, v9, v2}, Lz9/r;->f(Landroid/net/Uri;Landroid/os/Bundle;Ljava/util/Map;)Z

    .line 176
    .line 177
    .line 178
    :cond_9
    :goto_4
    new-instance v8, Lca/i;

    .line 179
    .line 180
    const/4 v10, 0x0

    .line 181
    invoke-direct {v8, v10, v9}, Lca/i;-><init>(ILandroid/os/Bundle;)V

    .line 182
    .line 183
    .line 184
    invoke-static {v2, v8}, Ljb0/b;->e(Ljava/util/Map;Lay0/k;)Ljava/util/ArrayList;

    .line 185
    .line 186
    .line 187
    move-result-object v8

    .line 188
    invoke-virtual {v8}, Ljava/util/ArrayList;->isEmpty()Z

    .line 189
    .line 190
    .line 191
    move-result v8

    .line 192
    if-eqz v8, :cond_1

    .line 193
    .line 194
    :cond_a
    new-instance v12, Lz9/t;

    .line 195
    .line 196
    iget-object v8, v0, Lca/j;->b:Ljava/lang/Object;

    .line 197
    .line 198
    move-object v13, v8

    .line 199
    check-cast v13, Lz9/u;

    .line 200
    .line 201
    iget-boolean v15, v7, Lz9/r;->l:Z

    .line 202
    .line 203
    invoke-direct/range {v12 .. v17}, Lz9/t;-><init>(Lz9/u;Landroid/os/Bundle;ZIZ)V

    .line 204
    .line 205
    .line 206
    if-eqz v5, :cond_b

    .line 207
    .line 208
    invoke-virtual {v12, v5}, Lz9/t;->a(Lz9/t;)I

    .line 209
    .line 210
    .line 211
    move-result v7

    .line 212
    if-lez v7, :cond_1

    .line 213
    .line 214
    :cond_b
    move-object v5, v12

    .line 215
    goto/16 :goto_0

    .line 216
    .line 217
    :cond_c
    return-object v5
.end method

.method public toString()Ljava/lang/String;
    .locals 2

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 7
    .line 8
    .line 9
    move-result-object v1

    .line 10
    invoke-virtual {v1}, Ljava/lang/Class;->getSimpleName()Ljava/lang/String;

    .line 11
    .line 12
    .line 13
    move-result-object v1

    .line 14
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 15
    .line 16
    .line 17
    const-string v1, "(0x"

    .line 18
    .line 19
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 20
    .line 21
    .line 22
    iget-object p0, p0, Lz9/u;->e:Lca/j;

    .line 23
    .line 24
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 25
    .line 26
    .line 27
    iget v1, p0, Lca/j;->a:I

    .line 28
    .line 29
    invoke-static {v1}, Ljava/lang/Integer;->toHexString(I)Ljava/lang/String;

    .line 30
    .line 31
    .line 32
    move-result-object v1

    .line 33
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 34
    .line 35
    .line 36
    const-string v1, ")"

    .line 37
    .line 38
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 39
    .line 40
    .line 41
    iget-object v1, p0, Lca/j;->e:Ljava/lang/Object;

    .line 42
    .line 43
    check-cast v1, Ljava/lang/String;

    .line 44
    .line 45
    if-eqz v1, :cond_1

    .line 46
    .line 47
    invoke-static {v1}, Lly0/p;->M(Ljava/lang/CharSequence;)Z

    .line 48
    .line 49
    .line 50
    move-result v1

    .line 51
    if-eqz v1, :cond_0

    .line 52
    .line 53
    goto :goto_0

    .line 54
    :cond_0
    const-string v1, " route="

    .line 55
    .line 56
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 57
    .line 58
    .line 59
    iget-object p0, p0, Lca/j;->e:Ljava/lang/Object;

    .line 60
    .line 61
    check-cast p0, Ljava/lang/String;

    .line 62
    .line 63
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 64
    .line 65
    .line 66
    :cond_1
    :goto_0
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 67
    .line 68
    .line 69
    move-result-object p0

    .line 70
    const-string v0, "toString(...)"

    .line 71
    .line 72
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 73
    .line 74
    .line 75
    return-object p0
.end method
