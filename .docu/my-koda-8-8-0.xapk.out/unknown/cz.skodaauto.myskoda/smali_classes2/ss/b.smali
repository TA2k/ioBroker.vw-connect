.class public final Lss/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lju/b;
.implements Lkx0/a;
.implements Ltn/b;


# instance fields
.field public final synthetic d:I

.field public e:Ljava/lang/Object;

.field public f:Ljava/lang/Object;

.field public g:Ljava/lang/Object;

.field public h:Ljava/lang/Object;

.field public i:Ljava/lang/Object;

.field public j:Ljava/lang/Object;

.field public k:Ljava/lang/Object;


# direct methods
.method public constructor <init>()V
    .locals 4

    const/4 v0, 0x1

    iput v0, p0, Lss/b;->d:I

    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    new-instance v0, Ljava/util/concurrent/atomic/AtomicBoolean;

    invoke-direct {v0}, Ljava/util/concurrent/atomic/AtomicBoolean;-><init>()V

    iput-object v0, p0, Lss/b;->e:Ljava/lang/Object;

    const/4 v0, 0x0

    iput-object v0, p0, Lss/b;->f:Ljava/lang/Object;

    new-instance v1, Ljava/util/HashMap;

    const/16 v2, 0x10

    const/high16 v3, 0x3f800000    # 1.0f

    .line 4
    invoke-direct {v1, v2, v3}, Ljava/util/HashMap;-><init>(IF)V

    iput-object v1, p0, Lss/b;->g:Ljava/lang/Object;

    new-instance v1, Ljava/util/HashMap;

    .line 5
    invoke-direct {v1, v2, v3}, Ljava/util/HashMap;-><init>(IF)V

    iput-object v1, p0, Lss/b;->h:Ljava/lang/Object;

    new-instance v1, Ljava/util/HashMap;

    .line 6
    invoke-direct {v1, v2, v3}, Ljava/util/HashMap;-><init>(IF)V

    iput-object v1, p0, Lss/b;->i:Ljava/lang/Object;

    new-instance v1, Ljava/util/HashMap;

    .line 7
    invoke-direct {v1, v2, v3}, Ljava/util/HashMap;-><init>(IF)V

    iput-object v1, p0, Lss/b;->j:Ljava/lang/Object;

    iput-object v0, p0, Lss/b;->k:Ljava/lang/Object;

    return-void
.end method

.method public synthetic constructor <init>(I)V
    .locals 0

    .line 1
    iput p1, p0, Lss/b;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public constructor <init>(Landroid/content/Context;)V
    .locals 4

    const/4 v0, 0x0

    iput v0, p0, Lss/b;->d:I

    .line 8
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 9
    sget-object v0, Ljs/c;->b:Ljs/c;

    .line 10
    invoke-virtual {v0, p1}, Ljs/c;->d(Landroid/content/Context;)Lps/c2;

    move-result-object v0

    check-cast v0, Lps/z0;

    .line 11
    iget-object v0, v0, Lps/z0;->a:Ljava/lang/String;

    .line 12
    iput-object v0, p0, Lss/b;->e:Ljava/lang/Object;

    .line 13
    invoke-virtual {p1}, Landroid/content/Context;->getFilesDir()Ljava/io/File;

    move-result-object p1

    iput-object p1, p0, Lss/b;->f:Ljava/lang/Object;

    .line 14
    invoke-virtual {v0}, Ljava/lang/String;->isEmpty()Z

    move-result v1

    if-nez v1, :cond_1

    .line 15
    new-instance v1, Ljava/lang/StringBuilder;

    const-string v2, ".crashlytics.v3"

    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    sget-object v2, Ljava/io/File;->separator:Ljava/lang/String;

    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 16
    invoke-virtual {v0}, Ljava/lang/String;->length()I

    move-result v2

    const/16 v3, 0x28

    if-le v2, v3, :cond_0

    .line 17
    invoke-static {v0}, Lms/f;->h(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v0

    goto :goto_0

    .line 18
    :cond_0
    const-string v2, "[^a-zA-Z0-9.]"

    const-string v3, "_"

    invoke-virtual {v0, v2, v3}, Ljava/lang/String;->replaceAll(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v0

    .line 19
    :goto_0
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    goto :goto_1

    .line 20
    :cond_1
    const-string v0, ".com.google.firebase.crashlytics.files.v1"

    .line 21
    :goto_1
    new-instance v1, Ljava/io/File;

    invoke-direct {v1, p1, v0}, Ljava/io/File;-><init>(Ljava/io/File;Ljava/lang/String;)V

    invoke-static {v1}, Lss/b;->k(Ljava/io/File;)V

    iput-object v1, p0, Lss/b;->g:Ljava/lang/Object;

    .line 22
    new-instance p1, Ljava/io/File;

    const-string v0, "open-sessions"

    invoke-direct {p1, v1, v0}, Ljava/io/File;-><init>(Ljava/io/File;Ljava/lang/String;)V

    invoke-static {p1}, Lss/b;->k(Ljava/io/File;)V

    iput-object p1, p0, Lss/b;->h:Ljava/lang/Object;

    .line 23
    new-instance p1, Ljava/io/File;

    const-string v0, "reports"

    invoke-direct {p1, v1, v0}, Ljava/io/File;-><init>(Ljava/io/File;Ljava/lang/String;)V

    invoke-static {p1}, Lss/b;->k(Ljava/io/File;)V

    iput-object p1, p0, Lss/b;->i:Ljava/lang/Object;

    .line 24
    new-instance p1, Ljava/io/File;

    const-string v0, "priority-reports"

    invoke-direct {p1, v1, v0}, Ljava/io/File;-><init>(Ljava/io/File;Ljava/lang/String;)V

    invoke-static {p1}, Lss/b;->k(Ljava/io/File;)V

    iput-object p1, p0, Lss/b;->j:Ljava/lang/Object;

    .line 25
    new-instance p1, Ljava/io/File;

    const-string v0, "native-reports"

    invoke-direct {p1, v1, v0}, Ljava/io/File;-><init>(Ljava/io/File;Ljava/lang/String;)V

    invoke-static {p1}, Lss/b;->k(Ljava/io/File;)V

    iput-object p1, p0, Lss/b;->k:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Landroid/content/Context;Leb/b;Lob/a;Llb/a;Landroidx/work/impl/WorkDatabase;Lmb/o;Ljava/util/ArrayList;)V
    .locals 1

    const/4 v0, 0x2

    iput v0, p0, Lss/b;->d:I

    const-string v0, "context"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "foregroundProcessor"

    invoke-static {p4, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 43
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 44
    iput-object p2, p0, Lss/b;->e:Ljava/lang/Object;

    .line 45
    iput-object p3, p0, Lss/b;->f:Ljava/lang/Object;

    .line 46
    iput-object p4, p0, Lss/b;->g:Ljava/lang/Object;

    .line 47
    iput-object p5, p0, Lss/b;->h:Ljava/lang/Object;

    .line 48
    iput-object p6, p0, Lss/b;->i:Ljava/lang/Object;

    .line 49
    iput-object p7, p0, Lss/b;->j:Ljava/lang/Object;

    .line 50
    invoke-virtual {p1}, Landroid/content/Context;->getApplicationContext()Landroid/content/Context;

    move-result-object p1

    const-string p2, "getApplicationContext(...)"

    invoke-static {p1, p2}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    iput-object p1, p0, Lss/b;->k:Ljava/lang/Object;

    .line 51
    new-instance p0, Lc2/k;

    const/4 p1, 0x4

    invoke-direct {p0, p1}, Lc2/k;-><init>(I)V

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V
    .locals 0

    .line 2
    iput p8, p0, Lss/b;->d:I

    iput-object p1, p0, Lss/b;->e:Ljava/lang/Object;

    iput-object p2, p0, Lss/b;->f:Ljava/lang/Object;

    iput-object p3, p0, Lss/b;->g:Ljava/lang/Object;

    iput-object p4, p0, Lss/b;->h:Ljava/lang/Object;

    iput-object p5, p0, Lss/b;->i:Ljava/lang/Object;

    iput-object p6, p0, Lss/b;->j:Ljava/lang/Object;

    iput-object p7, p0, Lss/b;->k:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public constructor <init>(Ljava/lang/String;Lss/b;Lns/d;)V
    .locals 3

    const/16 v0, 0x9

    iput v0, p0, Lss/b;->d:I

    .line 26
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 27
    new-instance v0, La8/b;

    const/4 v1, 0x0

    invoke-direct {v0, p0, v1}, La8/b;-><init>(Lss/b;Z)V

    iput-object v0, p0, Lss/b;->h:Ljava/lang/Object;

    .line 28
    new-instance v0, La8/b;

    const/4 v2, 0x1

    invoke-direct {v0, p0, v2}, La8/b;-><init>(Lss/b;Z)V

    iput-object v0, p0, Lss/b;->i:Ljava/lang/Object;

    .line 29
    new-instance v0, Lh01/v;

    invoke-direct {v0}, Lh01/v;-><init>()V

    iput-object v0, p0, Lss/b;->j:Ljava/lang/Object;

    .line 30
    new-instance v0, Ljava/util/concurrent/atomic/AtomicMarkableReference;

    const/4 v2, 0x0

    invoke-direct {v0, v2, v1}, Ljava/util/concurrent/atomic/AtomicMarkableReference;-><init>(Ljava/lang/Object;Z)V

    iput-object v0, p0, Lss/b;->k:Ljava/lang/Object;

    .line 31
    iput-object p1, p0, Lss/b;->e:Ljava/lang/Object;

    .line 32
    new-instance p1, Los/h;

    invoke-direct {p1, p2}, Los/h;-><init>(Lss/b;)V

    iput-object p1, p0, Lss/b;->f:Ljava/lang/Object;

    .line 33
    iput-object p3, p0, Lss/b;->g:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Low0/f0;Low0/s;Low0/o;Lrw0/d;Lvy0/i1;Lvw0/d;)V
    .locals 1

    const/4 v0, 0x7

    iput v0, p0, Lss/b;->d:I

    const-string v0, "method"

    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "executionContext"

    invoke-static {p5, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "attributes"

    invoke-static {p6, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 34
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 35
    iput-object p1, p0, Lss/b;->e:Ljava/lang/Object;

    .line 36
    iput-object p2, p0, Lss/b;->f:Ljava/lang/Object;

    .line 37
    iput-object p3, p0, Lss/b;->g:Ljava/lang/Object;

    .line 38
    iput-object p4, p0, Lss/b;->h:Ljava/lang/Object;

    .line 39
    iput-object p5, p0, Lss/b;->i:Ljava/lang/Object;

    .line 40
    iput-object p6, p0, Lss/b;->j:Ljava/lang/Object;

    .line 41
    sget-object p1, Lcw0/g;->a:Lvw0/a;

    .line 42
    invoke-virtual {p6, p1}, Lvw0/d;->d(Lvw0/a;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Ljava/util/Map;

    if-eqz p1, :cond_0

    invoke-interface {p1}, Ljava/util/Map;->keySet()Ljava/util/Set;

    move-result-object p1

    if-nez p1, :cond_1

    :cond_0
    sget-object p1, Lmx0/u;->d:Lmx0/u;

    :cond_1
    iput-object p1, p0, Lss/b;->k:Ljava/lang/Object;

    return-void
.end method

.method public static a(Lps/p0;Los/f;Lss/b;Ljava/util/Map;)Lps/p0;
    .locals 10

    .line 1
    const-string v0, "FirebaseCrashlytics"

    .line 2
    .line 3
    invoke-virtual {p0}, Lps/p0;->a()Lps/o0;

    .line 4
    .line 5
    .line 6
    move-result-object v1

    .line 7
    iget-object p1, p1, Los/f;->e:Ljava/lang/Object;

    .line 8
    .line 9
    check-cast p1, Los/d;

    .line 10
    .line 11
    invoke-interface {p1}, Los/d;->c()Ljava/lang/String;

    .line 12
    .line 13
    .line 14
    move-result-object p1

    .line 15
    const/4 v2, 0x0

    .line 16
    if-eqz p1, :cond_0

    .line 17
    .line 18
    new-instance v3, Lps/c1;

    .line 19
    .line 20
    invoke-direct {v3, p1}, Lps/c1;-><init>(Ljava/lang/String;)V

    .line 21
    .line 22
    .line 23
    iput-object v3, v1, Lps/o0;->e:Lps/f2;

    .line 24
    .line 25
    goto :goto_0

    .line 26
    :cond_0
    const-string p1, "No log data to include with this event."

    .line 27
    .line 28
    const/4 v3, 0x2

    .line 29
    invoke-static {v0, v3}, Landroid/util/Log;->isLoggable(Ljava/lang/String;I)Z

    .line 30
    .line 31
    .line 32
    move-result v3

    .line 33
    if-eqz v3, :cond_1

    .line 34
    .line 35
    invoke-static {v0, p1, v2}, Landroid/util/Log;->v(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 36
    .line 37
    .line 38
    :cond_1
    :goto_0
    iget-object p1, p2, Lss/b;->h:Ljava/lang/Object;

    .line 39
    .line 40
    check-cast p1, La8/b;

    .line 41
    .line 42
    invoke-interface {p3}, Ljava/util/Map;->isEmpty()Z

    .line 43
    .line 44
    .line 45
    move-result v3

    .line 46
    if-eqz v3, :cond_2

    .line 47
    .line 48
    iget-object p1, p1, La8/b;->f:Ljava/lang/Object;

    .line 49
    .line 50
    check-cast p1, Ljava/util/concurrent/atomic/AtomicMarkableReference;

    .line 51
    .line 52
    invoke-virtual {p1}, Ljava/util/concurrent/atomic/AtomicMarkableReference;->getReference()Ljava/lang/Object;

    .line 53
    .line 54
    .line 55
    move-result-object p1

    .line 56
    move-object v3, p1

    .line 57
    check-cast v3, Los/e;

    .line 58
    .line 59
    monitor-enter v3

    .line 60
    :try_start_0
    new-instance p1, Ljava/util/HashMap;

    .line 61
    .line 62
    iget-object p3, v3, Los/e;->a:Ljava/util/HashMap;

    .line 63
    .line 64
    invoke-direct {p1, p3}, Ljava/util/HashMap;-><init>(Ljava/util/Map;)V

    .line 65
    .line 66
    .line 67
    invoke-static {p1}, Ljava/util/Collections;->unmodifiableMap(Ljava/util/Map;)Ljava/util/Map;

    .line 68
    .line 69
    .line 70
    move-result-object p1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 71
    monitor-exit v3

    .line 72
    goto/16 :goto_3

    .line 73
    .line 74
    :catchall_0
    move-exception v0

    .line 75
    move-object p0, v0

    .line 76
    :try_start_1
    monitor-exit v3
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 77
    throw p0

    .line 78
    :cond_2
    iget-object p1, p1, La8/b;->f:Ljava/lang/Object;

    .line 79
    .line 80
    check-cast p1, Ljava/util/concurrent/atomic/AtomicMarkableReference;

    .line 81
    .line 82
    invoke-virtual {p1}, Ljava/util/concurrent/atomic/AtomicMarkableReference;->getReference()Ljava/lang/Object;

    .line 83
    .line 84
    .line 85
    move-result-object p1

    .line 86
    check-cast p1, Los/e;

    .line 87
    .line 88
    monitor-enter p1

    .line 89
    :try_start_2
    new-instance v3, Ljava/util/HashMap;

    .line 90
    .line 91
    iget-object v4, p1, Los/e;->a:Ljava/util/HashMap;

    .line 92
    .line 93
    invoke-direct {v3, v4}, Ljava/util/HashMap;-><init>(Ljava/util/Map;)V

    .line 94
    .line 95
    .line 96
    invoke-static {v3}, Ljava/util/Collections;->unmodifiableMap(Ljava/util/Map;)Ljava/util/Map;

    .line 97
    .line 98
    .line 99
    move-result-object v3
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_2

    .line 100
    monitor-exit p1

    .line 101
    new-instance p1, Ljava/util/HashMap;

    .line 102
    .line 103
    invoke-direct {p1, v3}, Ljava/util/HashMap;-><init>(Ljava/util/Map;)V

    .line 104
    .line 105
    .line 106
    invoke-interface {p3}, Ljava/util/Map;->entrySet()Ljava/util/Set;

    .line 107
    .line 108
    .line 109
    move-result-object p3

    .line 110
    invoke-interface {p3}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 111
    .line 112
    .line 113
    move-result-object p3

    .line 114
    const/4 v3, 0x0

    .line 115
    :goto_1
    invoke-interface {p3}, Ljava/util/Iterator;->hasNext()Z

    .line 116
    .line 117
    .line 118
    move-result v4

    .line 119
    if-eqz v4, :cond_5

    .line 120
    .line 121
    invoke-interface {p3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 122
    .line 123
    .line 124
    move-result-object v4

    .line 125
    check-cast v4, Ljava/util/Map$Entry;

    .line 126
    .line 127
    invoke-interface {v4}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 128
    .line 129
    .line 130
    move-result-object v5

    .line 131
    check-cast v5, Ljava/lang/String;

    .line 132
    .line 133
    const/16 v6, 0x400

    .line 134
    .line 135
    invoke-static {v6, v5}, Los/e;->a(ILjava/lang/String;)Ljava/lang/String;

    .line 136
    .line 137
    .line 138
    move-result-object v5

    .line 139
    invoke-virtual {p1}, Ljava/util/HashMap;->size()I

    .line 140
    .line 141
    .line 142
    move-result v7

    .line 143
    const/16 v8, 0x40

    .line 144
    .line 145
    if-lt v7, v8, :cond_4

    .line 146
    .line 147
    invoke-virtual {p1, v5}, Ljava/util/HashMap;->containsKey(Ljava/lang/Object;)Z

    .line 148
    .line 149
    .line 150
    move-result v7

    .line 151
    if-eqz v7, :cond_3

    .line 152
    .line 153
    goto :goto_2

    .line 154
    :cond_3
    add-int/lit8 v3, v3, 0x1

    .line 155
    .line 156
    goto :goto_1

    .line 157
    :cond_4
    :goto_2
    invoke-interface {v4}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 158
    .line 159
    .line 160
    move-result-object v4

    .line 161
    check-cast v4, Ljava/lang/String;

    .line 162
    .line 163
    invoke-static {v6, v4}, Los/e;->a(ILjava/lang/String;)Ljava/lang/String;

    .line 164
    .line 165
    .line 166
    move-result-object v4

    .line 167
    invoke-virtual {p1, v5, v4}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 168
    .line 169
    .line 170
    goto :goto_1

    .line 171
    :cond_5
    if-lez v3, :cond_6

    .line 172
    .line 173
    new-instance p3, Ljava/lang/StringBuilder;

    .line 174
    .line 175
    const-string v4, "Ignored "

    .line 176
    .line 177
    invoke-direct {p3, v4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 178
    .line 179
    .line 180
    invoke-virtual {p3, v3}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 181
    .line 182
    .line 183
    const-string v3, " keys when adding event specific keys. Maximum allowable: 1024"

    .line 184
    .line 185
    invoke-virtual {p3, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 186
    .line 187
    .line 188
    invoke-virtual {p3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 189
    .line 190
    .line 191
    move-result-object p3

    .line 192
    invoke-static {v0, p3, v2}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 193
    .line 194
    .line 195
    :cond_6
    invoke-static {p1}, Ljava/util/Collections;->unmodifiableMap(Ljava/util/Map;)Ljava/util/Map;

    .line 196
    .line 197
    .line 198
    move-result-object p1

    .line 199
    :goto_3
    invoke-static {p1}, Lss/b;->i(Ljava/util/Map;)Ljava/util/List;

    .line 200
    .line 201
    .line 202
    move-result-object v4

    .line 203
    iget-object p1, p2, Lss/b;->i:Ljava/lang/Object;

    .line 204
    .line 205
    check-cast p1, La8/b;

    .line 206
    .line 207
    iget-object p1, p1, La8/b;->f:Ljava/lang/Object;

    .line 208
    .line 209
    check-cast p1, Ljava/util/concurrent/atomic/AtomicMarkableReference;

    .line 210
    .line 211
    invoke-virtual {p1}, Ljava/util/concurrent/atomic/AtomicMarkableReference;->getReference()Ljava/lang/Object;

    .line 212
    .line 213
    .line 214
    move-result-object p1

    .line 215
    move-object p2, p1

    .line 216
    check-cast p2, Los/e;

    .line 217
    .line 218
    monitor-enter p2

    .line 219
    :try_start_3
    new-instance p1, Ljava/util/HashMap;

    .line 220
    .line 221
    iget-object p3, p2, Los/e;->a:Ljava/util/HashMap;

    .line 222
    .line 223
    invoke-direct {p1, p3}, Ljava/util/HashMap;-><init>(Ljava/util/Map;)V

    .line 224
    .line 225
    .line 226
    invoke-static {p1}, Ljava/util/Collections;->unmodifiableMap(Ljava/util/Map;)Ljava/util/Map;

    .line 227
    .line 228
    .line 229
    move-result-object p1
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_1

    .line 230
    monitor-exit p2

    .line 231
    invoke-static {p1}, Lss/b;->i(Ljava/util/Map;)Ljava/util/List;

    .line 232
    .line 233
    .line 234
    move-result-object v5

    .line 235
    invoke-interface {v4}, Ljava/util/List;->isEmpty()Z

    .line 236
    .line 237
    .line 238
    move-result p1

    .line 239
    if-eqz p1, :cond_7

    .line 240
    .line 241
    invoke-interface {v5}, Ljava/util/List;->isEmpty()Z

    .line 242
    .line 243
    .line 244
    move-result p1

    .line 245
    if-nez p1, :cond_8

    .line 246
    .line 247
    :cond_7
    iget-object p0, p0, Lps/p0;->c:Lps/d2;

    .line 248
    .line 249
    check-cast p0, Lps/q0;

    .line 250
    .line 251
    iget-object v3, p0, Lps/q0;->a:Lps/r0;

    .line 252
    .line 253
    iget-object v6, p0, Lps/q0;->d:Ljava/lang/Boolean;

    .line 254
    .line 255
    iget-object v7, p0, Lps/q0;->e:Lps/c2;

    .line 256
    .line 257
    iget-object v8, p0, Lps/q0;->f:Ljava/util/List;

    .line 258
    .line 259
    iget v9, p0, Lps/q0;->g:I

    .line 260
    .line 261
    new-instance v2, Lps/q0;

    .line 262
    .line 263
    invoke-direct/range {v2 .. v9}, Lps/q0;-><init>(Lps/r0;Ljava/util/List;Ljava/util/List;Ljava/lang/Boolean;Lps/c2;Ljava/util/List;I)V

    .line 264
    .line 265
    .line 266
    iput-object v2, v1, Lps/o0;->c:Lps/d2;

    .line 267
    .line 268
    :cond_8
    invoke-virtual {v1}, Lps/o0;->a()Lps/p0;

    .line 269
    .line 270
    .line 271
    move-result-object p0

    .line 272
    return-object p0

    .line 273
    :catchall_1
    move-exception v0

    .line 274
    move-object p0, v0

    .line 275
    :try_start_4
    monitor-exit p2
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_1

    .line 276
    throw p0

    .line 277
    :catchall_2
    move-exception v0

    .line 278
    move-object p0, v0

    .line 279
    :try_start_5
    monitor-exit p1
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_2

    .line 280
    throw p0
.end method

.method public static b(Lps/p0;Lss/b;)Lps/j2;
    .locals 7

    .line 1
    iget-object p1, p1, Lss/b;->j:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p1, Lh01/v;

    .line 4
    .line 5
    invoke-virtual {p1}, Lh01/v;->a()Ljava/util/List;

    .line 6
    .line 7
    .line 8
    move-result-object p1

    .line 9
    new-instance v0, Ljava/util/ArrayList;

    .line 10
    .line 11
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 12
    .line 13
    .line 14
    const/4 v1, 0x0

    .line 15
    :goto_0
    invoke-interface {p1}, Ljava/util/List;->size()I

    .line 16
    .line 17
    .line 18
    move-result v2

    .line 19
    if-ge v1, v2, :cond_4

    .line 20
    .line 21
    invoke-interface {p1, v1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 22
    .line 23
    .line 24
    move-result-object v2

    .line 25
    check-cast v2, Los/n;

    .line 26
    .line 27
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 28
    .line 29
    .line 30
    new-instance v3, Lps/d1;

    .line 31
    .line 32
    invoke-direct {v3}, Ljava/lang/Object;-><init>()V

    .line 33
    .line 34
    .line 35
    check-cast v2, Los/b;

    .line 36
    .line 37
    iget-object v4, v2, Los/b;->e:Ljava/lang/String;

    .line 38
    .line 39
    if-eqz v4, :cond_3

    .line 40
    .line 41
    iget-object v5, v2, Los/b;->b:Ljava/lang/String;

    .line 42
    .line 43
    if-eqz v5, :cond_2

    .line 44
    .line 45
    new-instance v6, Lps/f1;

    .line 46
    .line 47
    invoke-direct {v6, v5, v4}, Lps/f1;-><init>(Ljava/lang/String;Ljava/lang/String;)V

    .line 48
    .line 49
    .line 50
    iput-object v6, v3, Lps/d1;->a:Lps/f1;

    .line 51
    .line 52
    iget-object v4, v2, Los/b;->c:Ljava/lang/String;

    .line 53
    .line 54
    if-eqz v4, :cond_1

    .line 55
    .line 56
    iput-object v4, v3, Lps/d1;->b:Ljava/lang/String;

    .line 57
    .line 58
    iget-object v4, v2, Los/b;->d:Ljava/lang/String;

    .line 59
    .line 60
    if-eqz v4, :cond_0

    .line 61
    .line 62
    iput-object v4, v3, Lps/d1;->c:Ljava/lang/String;

    .line 63
    .line 64
    iget-wide v4, v2, Los/b;->f:J

    .line 65
    .line 66
    iput-wide v4, v3, Lps/d1;->d:J

    .line 67
    .line 68
    iget-byte v2, v3, Lps/d1;->e:B

    .line 69
    .line 70
    or-int/lit8 v2, v2, 0x1

    .line 71
    .line 72
    int-to-byte v2, v2

    .line 73
    iput-byte v2, v3, Lps/d1;->e:B

    .line 74
    .line 75
    invoke-virtual {v3}, Lps/d1;->a()Lps/e1;

    .line 76
    .line 77
    .line 78
    move-result-object v2

    .line 79
    invoke-virtual {v0, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 80
    .line 81
    .line 82
    add-int/lit8 v1, v1, 0x1

    .line 83
    .line 84
    goto :goto_0

    .line 85
    :cond_0
    new-instance p0, Ljava/lang/NullPointerException;

    .line 86
    .line 87
    const-string p1, "Null parameterValue"

    .line 88
    .line 89
    invoke-direct {p0, p1}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    .line 90
    .line 91
    .line 92
    throw p0

    .line 93
    :cond_1
    new-instance p0, Ljava/lang/NullPointerException;

    .line 94
    .line 95
    const-string p1, "Null parameterKey"

    .line 96
    .line 97
    invoke-direct {p0, p1}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    .line 98
    .line 99
    .line 100
    throw p0

    .line 101
    :cond_2
    new-instance p0, Ljava/lang/NullPointerException;

    .line 102
    .line 103
    const-string p1, "Null rolloutId"

    .line 104
    .line 105
    invoke-direct {p0, p1}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    .line 106
    .line 107
    .line 108
    throw p0

    .line 109
    :cond_3
    new-instance p0, Ljava/lang/NullPointerException;

    .line 110
    .line 111
    const-string p1, "Null variantId"

    .line 112
    .line 113
    invoke-direct {p0, p1}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    .line 114
    .line 115
    .line 116
    throw p0

    .line 117
    :cond_4
    invoke-virtual {v0}, Ljava/util/ArrayList;->isEmpty()Z

    .line 118
    .line 119
    .line 120
    move-result p1

    .line 121
    if-eqz p1, :cond_5

    .line 122
    .line 123
    return-object p0

    .line 124
    :cond_5
    invoke-virtual {p0}, Lps/p0;->a()Lps/o0;

    .line 125
    .line 126
    .line 127
    move-result-object p0

    .line 128
    new-instance p1, Lps/g1;

    .line 129
    .line 130
    invoke-direct {p1, v0}, Lps/g1;-><init>(Ljava/util/List;)V

    .line 131
    .line 132
    .line 133
    iput-object p1, p0, Lps/o0;->f:Lps/i2;

    .line 134
    .line 135
    invoke-virtual {p0}, Lps/o0;->a()Lps/p0;

    .line 136
    .line 137
    .line 138
    move-result-object p0

    .line 139
    return-object p0
.end method

.method public static e(Ljava/io/InputStream;)Ljava/lang/String;
    .locals 4

    .line 1
    new-instance v0, Ljava/io/BufferedInputStream;

    .line 2
    .line 3
    invoke-direct {v0, p0}, Ljava/io/BufferedInputStream;-><init>(Ljava/io/InputStream;)V

    .line 4
    .line 5
    .line 6
    :try_start_0
    new-instance p0, Ljava/io/ByteArrayOutputStream;

    .line 7
    .line 8
    invoke-direct {p0}, Ljava/io/ByteArrayOutputStream;-><init>()V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_1

    .line 9
    .line 10
    .line 11
    const/16 v1, 0x2000

    .line 12
    .line 13
    :try_start_1
    new-array v1, v1, [B

    .line 14
    .line 15
    :goto_0
    invoke-virtual {v0, v1}, Ljava/io/InputStream;->read([B)I

    .line 16
    .line 17
    .line 18
    move-result v2

    .line 19
    const/4 v3, -0x1

    .line 20
    if-eq v2, v3, :cond_0

    .line 21
    .line 22
    const/4 v3, 0x0

    .line 23
    invoke-virtual {p0, v1, v3, v2}, Ljava/io/ByteArrayOutputStream;->write([BII)V

    .line 24
    .line 25
    .line 26
    goto :goto_0

    .line 27
    :catchall_0
    move-exception v1

    .line 28
    goto :goto_1

    .line 29
    :cond_0
    sget-object v1, Ljava/nio/charset/StandardCharsets;->UTF_8:Ljava/nio/charset/Charset;

    .line 30
    .line 31
    invoke-virtual {v1}, Ljava/nio/charset/Charset;->name()Ljava/lang/String;

    .line 32
    .line 33
    .line 34
    move-result-object v1

    .line 35
    invoke-virtual {p0, v1}, Ljava/io/ByteArrayOutputStream;->toString(Ljava/lang/String;)Ljava/lang/String;

    .line 36
    .line 37
    .line 38
    move-result-object v1
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 39
    :try_start_2
    invoke-virtual {p0}, Ljava/io/ByteArrayOutputStream;->close()V
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_1

    .line 40
    .line 41
    .line 42
    invoke-virtual {v0}, Ljava/io/BufferedInputStream;->close()V

    .line 43
    .line 44
    .line 45
    return-object v1

    .line 46
    :catchall_1
    move-exception p0

    .line 47
    goto :goto_3

    .line 48
    :goto_1
    :try_start_3
    invoke-virtual {p0}, Ljava/io/ByteArrayOutputStream;->close()V
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_2

    .line 49
    .line 50
    .line 51
    goto :goto_2

    .line 52
    :catchall_2
    move-exception p0

    .line 53
    :try_start_4
    invoke-virtual {v1, p0}, Ljava/lang/Throwable;->addSuppressed(Ljava/lang/Throwable;)V

    .line 54
    .line 55
    .line 56
    :goto_2
    throw v1
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_1

    .line 57
    :goto_3
    :try_start_5
    invoke-virtual {v0}, Ljava/io/BufferedInputStream;->close()V
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_3

    .line 58
    .line 59
    .line 60
    goto :goto_4

    .line 61
    :catchall_3
    move-exception v0

    .line 62
    invoke-virtual {p0, v0}, Ljava/lang/Throwable;->addSuppressed(Ljava/lang/Throwable;)V

    .line 63
    .line 64
    .line 65
    :goto_4
    throw p0
.end method

.method public static f(Landroid/content/Context;Lms/u;Lss/b;Lcom/google/android/material/datepicker/d;Los/f;Lss/b;Lvp/y1;Lqn/s;Lb81/d;Lms/i;Lns/d;)Lss/b;
    .locals 9

    .line 1
    new-instance v0, Lms/q;

    .line 2
    .line 3
    move-object v1, p0

    .line 4
    move-object v2, p1

    .line 5
    move-object v3, p3

    .line 6
    move-object v4, p6

    .line 7
    move-object/from16 v5, p7

    .line 8
    .line 9
    invoke-direct/range {v0 .. v5}, Lms/q;-><init>(Landroid/content/Context;Lms/u;Lcom/google/android/material/datepicker/d;Lvp/y1;Lqn/s;)V

    .line 10
    .line 11
    .line 12
    new-instance v2, Lss/a;

    .line 13
    .line 14
    move-object/from16 p3, p9

    .line 15
    .line 16
    invoke-direct {v2, p2, v5, p3}, Lss/a;-><init>(Lss/b;Lqn/s;Lms/i;)V

    .line 17
    .line 18
    .line 19
    sget-object p2, Lts/a;->b:Lqs/a;

    .line 20
    .line 21
    invoke-static {p0}, Lrn/r;->b(Landroid/content/Context;)V

    .line 22
    .line 23
    .line 24
    invoke-static {}, Lrn/r;->a()Lrn/r;

    .line 25
    .line 26
    .line 27
    move-result-object p0

    .line 28
    new-instance p2, Lpn/a;

    .line 29
    .line 30
    sget-object p3, Lts/a;->c:Ljava/lang/String;

    .line 31
    .line 32
    sget-object p6, Lts/a;->d:Ljava/lang/String;

    .line 33
    .line 34
    invoke-direct {p2, p3, p6}, Lpn/a;-><init>(Ljava/lang/String;Ljava/lang/String;)V

    .line 35
    .line 36
    .line 37
    invoke-virtual {p0, p2}, Lrn/r;->c(Lrn/l;)Lrn/p;

    .line 38
    .line 39
    .line 40
    move-result-object p0

    .line 41
    new-instance p2, Lon/c;

    .line 42
    .line 43
    const-string p3, "json"

    .line 44
    .line 45
    invoke-direct {p2, p3}, Lon/c;-><init>(Ljava/lang/String;)V

    .line 46
    .line 47
    .line 48
    sget-object p3, Lts/a;->e:Lt0/c;

    .line 49
    .line 50
    const-string p6, "FIREBASE_CRASHLYTICS_REPORT"

    .line 51
    .line 52
    invoke-virtual {p0, p6, p2, p3}, Lrn/p;->a(Ljava/lang/String;Lon/c;Lon/e;)Lrn/q;

    .line 53
    .line 54
    .line 55
    move-result-object p0

    .line 56
    new-instance p2, Lts/b;

    .line 57
    .line 58
    invoke-virtual {v5}, Lqn/s;->b()Lus/a;

    .line 59
    .line 60
    .line 61
    move-result-object p3

    .line 62
    move-object/from16 p6, p8

    .line 63
    .line 64
    invoke-direct {p2, p0, p3, p6}, Lts/b;-><init>(Lrn/q;Lus/a;Lb81/d;)V

    .line 65
    .line 66
    .line 67
    new-instance v3, Lts/a;

    .line 68
    .line 69
    invoke-direct {v3, p2}, Lts/a;-><init>(Lts/b;)V

    .line 70
    .line 71
    .line 72
    move-object v1, v0

    .line 73
    new-instance v0, Lss/b;

    .line 74
    .line 75
    const/16 v8, 0x8

    .line 76
    .line 77
    move-object v6, p1

    .line 78
    move-object v4, p4

    .line 79
    move-object v5, p5

    .line 80
    move-object/from16 v7, p10

    .line 81
    .line 82
    invoke-direct/range {v0 .. v8}, Lss/b;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 83
    .line 84
    .line 85
    return-object v0
.end method

.method public static i(Ljava/util/Map;)Ljava/util/List;
    .locals 4

    .line 1
    new-instance v0, Ljava/util/ArrayList;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 4
    .line 5
    .line 6
    invoke-interface {p0}, Ljava/util/Map;->size()I

    .line 7
    .line 8
    .line 9
    move-result v1

    .line 10
    invoke-virtual {v0, v1}, Ljava/util/ArrayList;->ensureCapacity(I)V

    .line 11
    .line 12
    .line 13
    invoke-interface {p0}, Ljava/util/Map;->entrySet()Ljava/util/Set;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    invoke-interface {p0}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 18
    .line 19
    .line 20
    move-result-object p0

    .line 21
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 22
    .line 23
    .line 24
    move-result v1

    .line 25
    if-eqz v1, :cond_2

    .line 26
    .line 27
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 28
    .line 29
    .line 30
    move-result-object v1

    .line 31
    check-cast v1, Ljava/util/Map$Entry;

    .line 32
    .line 33
    invoke-interface {v1}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 34
    .line 35
    .line 36
    move-result-object v2

    .line 37
    check-cast v2, Ljava/lang/String;

    .line 38
    .line 39
    if-eqz v2, :cond_1

    .line 40
    .line 41
    invoke-interface {v1}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 42
    .line 43
    .line 44
    move-result-object v1

    .line 45
    check-cast v1, Ljava/lang/String;

    .line 46
    .line 47
    if-eqz v1, :cond_0

    .line 48
    .line 49
    new-instance v3, Lps/f0;

    .line 50
    .line 51
    invoke-direct {v3, v2, v1}, Lps/f0;-><init>(Ljava/lang/String;Ljava/lang/String;)V

    .line 52
    .line 53
    .line 54
    invoke-virtual {v0, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 55
    .line 56
    .line 57
    goto :goto_0

    .line 58
    :cond_0
    new-instance p0, Ljava/lang/NullPointerException;

    .line 59
    .line 60
    const-string v0, "Null value"

    .line 61
    .line 62
    invoke-direct {p0, v0}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    .line 63
    .line 64
    .line 65
    throw p0

    .line 66
    :cond_1
    new-instance p0, Ljava/lang/NullPointerException;

    .line 67
    .line 68
    const-string v0, "Null key"

    .line 69
    .line 70
    invoke-direct {p0, v0}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    .line 71
    .line 72
    .line 73
    throw p0

    .line 74
    :cond_2
    new-instance p0, Lcom/salesforce/marketingcloud/analytics/piwama/m;

    .line 75
    .line 76
    const/16 v1, 0x11

    .line 77
    .line 78
    invoke-direct {p0, v1}, Lcom/salesforce/marketingcloud/analytics/piwama/m;-><init>(I)V

    .line 79
    .line 80
    .line 81
    invoke-static {v0, p0}, Ljava/util/Collections;->sort(Ljava/util/List;Ljava/util/Comparator;)V

    .line 82
    .line 83
    .line 84
    invoke-static {v0}, Ljava/util/Collections;->unmodifiableList(Ljava/util/List;)Ljava/util/List;

    .line 85
    .line 86
    .line 87
    move-result-object p0

    .line 88
    return-object p0
.end method

.method public static declared-synchronized k(Ljava/io/File;)V
    .locals 6

    .line 1
    const-string v0, "Could not create Crashlytics-specific directory: "

    .line 2
    .line 3
    const-string v1, "Unexpected non-directory file: "

    .line 4
    .line 5
    const-class v2, Lss/b;

    .line 6
    .line 7
    monitor-enter v2

    .line 8
    :try_start_0
    invoke-virtual {p0}, Ljava/io/File;->exists()Z

    .line 9
    .line 10
    .line 11
    move-result v3

    .line 12
    const/4 v4, 0x0

    .line 13
    if-eqz v3, :cond_2

    .line 14
    .line 15
    invoke-virtual {p0}, Ljava/io/File;->isDirectory()Z

    .line 16
    .line 17
    .line 18
    move-result v3
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 19
    if-eqz v3, :cond_0

    .line 20
    .line 21
    monitor-exit v2

    .line 22
    return-void

    .line 23
    :cond_0
    :try_start_1
    new-instance v3, Ljava/lang/StringBuilder;

    .line 24
    .line 25
    invoke-direct {v3, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 26
    .line 27
    .line 28
    invoke-virtual {v3, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 29
    .line 30
    .line 31
    const-string v1, "; deleting file and creating new directory."

    .line 32
    .line 33
    invoke-virtual {v3, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 34
    .line 35
    .line 36
    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 37
    .line 38
    .line 39
    move-result-object v1

    .line 40
    const-string v3, "FirebaseCrashlytics"

    .line 41
    .line 42
    const/4 v5, 0x3

    .line 43
    invoke-static {v3, v5}, Landroid/util/Log;->isLoggable(Ljava/lang/String;I)Z

    .line 44
    .line 45
    .line 46
    move-result v3

    .line 47
    if-eqz v3, :cond_1

    .line 48
    .line 49
    const-string v3, "FirebaseCrashlytics"

    .line 50
    .line 51
    invoke-static {v3, v1, v4}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 52
    .line 53
    .line 54
    :cond_1
    invoke-virtual {p0}, Ljava/io/File;->delete()Z

    .line 55
    .line 56
    .line 57
    goto :goto_0

    .line 58
    :catchall_0
    move-exception p0

    .line 59
    goto :goto_1

    .line 60
    :cond_2
    :goto_0
    invoke-virtual {p0}, Ljava/io/File;->mkdirs()Z

    .line 61
    .line 62
    .line 63
    move-result v1

    .line 64
    if-nez v1, :cond_3

    .line 65
    .line 66
    new-instance v1, Ljava/lang/StringBuilder;

    .line 67
    .line 68
    invoke-direct {v1, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 69
    .line 70
    .line 71
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 72
    .line 73
    .line 74
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 75
    .line 76
    .line 77
    move-result-object p0

    .line 78
    const-string v0, "FirebaseCrashlytics"

    .line 79
    .line 80
    invoke-static {v0, p0, v4}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 81
    .line 82
    .line 83
    :cond_3
    monitor-exit v2

    .line 84
    return-void

    .line 85
    :goto_1
    :try_start_2
    monitor-exit v2
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 86
    throw p0
.end method

.method public static l(Ljava/io/File;)Z
    .locals 4

    .line 1
    invoke-virtual {p0}, Ljava/io/File;->listFiles()[Ljava/io/File;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    array-length v1, v0

    .line 8
    const/4 v2, 0x0

    .line 9
    :goto_0
    if-ge v2, v1, :cond_0

    .line 10
    .line 11
    aget-object v3, v0, v2

    .line 12
    .line 13
    invoke-static {v3}, Lss/b;->l(Ljava/io/File;)Z

    .line 14
    .line 15
    .line 16
    add-int/lit8 v2, v2, 0x1

    .line 17
    .line 18
    goto :goto_0

    .line 19
    :cond_0
    invoke-virtual {p0}, Ljava/io/File;->delete()Z

    .line 20
    .line 21
    .line 22
    move-result p0

    .line 23
    return p0
.end method

.method public static m([Ljava/lang/Object;)Ljava/util/List;
    .locals 0

    .line 1
    if-nez p0, :cond_0

    .line 2
    .line 3
    sget-object p0, Ljava/util/Collections;->EMPTY_LIST:Ljava/util/List;

    .line 4
    .line 5
    return-object p0

    .line 6
    :cond_0
    invoke-static {p0}, Ljava/util/Arrays;->asList([Ljava/lang/Object;)Ljava/util/List;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    return-object p0
.end method


# virtual methods
.method public c()Lh0/k;
    .locals 10

    .line 1
    iget-object v0, p0, Lss/b;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Landroid/util/Size;

    .line 4
    .line 5
    if-nez v0, :cond_0

    .line 6
    .line 7
    const-string v0, " resolution"

    .line 8
    .line 9
    goto :goto_0

    .line 10
    :cond_0
    const-string v0, ""

    .line 11
    .line 12
    :goto_0
    iget-object v1, p0, Lss/b;->f:Ljava/lang/Object;

    .line 13
    .line 14
    check-cast v1, Landroid/util/Size;

    .line 15
    .line 16
    if-nez v1, :cond_1

    .line 17
    .line 18
    const-string v1, " originalConfiguredResolution"

    .line 19
    .line 20
    invoke-virtual {v0, v1}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 21
    .line 22
    .line 23
    move-result-object v0

    .line 24
    :cond_1
    iget-object v1, p0, Lss/b;->g:Ljava/lang/Object;

    .line 25
    .line 26
    check-cast v1, Lb0/y;

    .line 27
    .line 28
    if-nez v1, :cond_2

    .line 29
    .line 30
    const-string v1, " dynamicRange"

    .line 31
    .line 32
    invoke-static {v0, v1}, Lf2/m0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 33
    .line 34
    .line 35
    move-result-object v0

    .line 36
    :cond_2
    iget-object v1, p0, Lss/b;->h:Ljava/lang/Object;

    .line 37
    .line 38
    check-cast v1, Ljava/lang/Integer;

    .line 39
    .line 40
    if-nez v1, :cond_3

    .line 41
    .line 42
    const-string v1, " sessionType"

    .line 43
    .line 44
    invoke-static {v0, v1}, Lf2/m0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 45
    .line 46
    .line 47
    move-result-object v0

    .line 48
    :cond_3
    iget-object v1, p0, Lss/b;->i:Ljava/lang/Object;

    .line 49
    .line 50
    check-cast v1, Landroid/util/Range;

    .line 51
    .line 52
    if-nez v1, :cond_4

    .line 53
    .line 54
    const-string v1, " expectedFrameRateRange"

    .line 55
    .line 56
    invoke-static {v0, v1}, Lf2/m0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 57
    .line 58
    .line 59
    move-result-object v0

    .line 60
    :cond_4
    iget-object v1, p0, Lss/b;->k:Ljava/lang/Object;

    .line 61
    .line 62
    check-cast v1, Ljava/lang/Boolean;

    .line 63
    .line 64
    if-nez v1, :cond_5

    .line 65
    .line 66
    const-string v1, " zslDisabled"

    .line 67
    .line 68
    invoke-static {v0, v1}, Lf2/m0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 69
    .line 70
    .line 71
    move-result-object v0

    .line 72
    :cond_5
    invoke-virtual {v0}, Ljava/lang/String;->isEmpty()Z

    .line 73
    .line 74
    .line 75
    move-result v1

    .line 76
    if-eqz v1, :cond_6

    .line 77
    .line 78
    new-instance v2, Lh0/k;

    .line 79
    .line 80
    iget-object v0, p0, Lss/b;->e:Ljava/lang/Object;

    .line 81
    .line 82
    move-object v3, v0

    .line 83
    check-cast v3, Landroid/util/Size;

    .line 84
    .line 85
    iget-object v0, p0, Lss/b;->f:Ljava/lang/Object;

    .line 86
    .line 87
    move-object v4, v0

    .line 88
    check-cast v4, Landroid/util/Size;

    .line 89
    .line 90
    iget-object v0, p0, Lss/b;->g:Ljava/lang/Object;

    .line 91
    .line 92
    move-object v5, v0

    .line 93
    check-cast v5, Lb0/y;

    .line 94
    .line 95
    iget-object v0, p0, Lss/b;->h:Ljava/lang/Object;

    .line 96
    .line 97
    check-cast v0, Ljava/lang/Integer;

    .line 98
    .line 99
    invoke-virtual {v0}, Ljava/lang/Integer;->intValue()I

    .line 100
    .line 101
    .line 102
    move-result v6

    .line 103
    iget-object v0, p0, Lss/b;->i:Ljava/lang/Object;

    .line 104
    .line 105
    move-object v7, v0

    .line 106
    check-cast v7, Landroid/util/Range;

    .line 107
    .line 108
    iget-object v0, p0, Lss/b;->j:Ljava/lang/Object;

    .line 109
    .line 110
    move-object v8, v0

    .line 111
    check-cast v8, Lh0/q0;

    .line 112
    .line 113
    iget-object p0, p0, Lss/b;->k:Ljava/lang/Object;

    .line 114
    .line 115
    check-cast p0, Ljava/lang/Boolean;

    .line 116
    .line 117
    invoke-virtual {p0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 118
    .line 119
    .line 120
    move-result v9

    .line 121
    invoke-direct/range {v2 .. v9}, Lh0/k;-><init>(Landroid/util/Size;Landroid/util/Size;Lb0/y;ILandroid/util/Range;Lh0/q0;Z)V

    .line 122
    .line 123
    .line 124
    return-object v2

    .line 125
    :cond_6
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 126
    .line 127
    const-string v1, "Missing required properties:"

    .line 128
    .line 129
    invoke-virtual {v1, v0}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 130
    .line 131
    .line 132
    move-result-object v0

    .line 133
    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 134
    .line 135
    .line 136
    throw p0
.end method

.method public d(Ljava/lang/String;)V
    .locals 1

    .line 1
    new-instance v0, Ljava/io/File;

    .line 2
    .line 3
    iget-object p0, p0, Lss/b;->f:Ljava/lang/Object;

    .line 4
    .line 5
    check-cast p0, Ljava/io/File;

    .line 6
    .line 7
    invoke-direct {v0, p0, p1}, Ljava/io/File;-><init>(Ljava/io/File;Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    invoke-virtual {v0}, Ljava/io/File;->exists()Z

    .line 11
    .line 12
    .line 13
    move-result p0

    .line 14
    if-eqz p0, :cond_0

    .line 15
    .line 16
    invoke-static {v0}, Lss/b;->l(Ljava/io/File;)Z

    .line 17
    .line 18
    .line 19
    move-result p0

    .line 20
    if-eqz p0, :cond_0

    .line 21
    .line 22
    new-instance p0, Ljava/lang/StringBuilder;

    .line 23
    .line 24
    const-string p1, "Deleted previous Crashlytics file system: "

    .line 25
    .line 26
    invoke-direct {p0, p1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 27
    .line 28
    .line 29
    invoke-virtual {v0}, Ljava/io/File;->getPath()Ljava/lang/String;

    .line 30
    .line 31
    .line 32
    move-result-object p1

    .line 33
    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 34
    .line 35
    .line 36
    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 37
    .line 38
    .line 39
    move-result-object p0

    .line 40
    const/4 p1, 0x3

    .line 41
    const-string v0, "FirebaseCrashlytics"

    .line 42
    .line 43
    invoke-static {v0, p1}, Landroid/util/Log;->isLoggable(Ljava/lang/String;I)Z

    .line 44
    .line 45
    .line 46
    move-result p1

    .line 47
    if-eqz p1, :cond_0

    .line 48
    .line 49
    const/4 p1, 0x0

    .line 50
    invoke-static {v0, p0, p1}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 51
    .line 52
    .line 53
    :cond_0
    return-void
.end method

.method public g()Ljava/lang/Object;
    .locals 1

    .line 1
    iget-object p0, p0, Lss/b;->j:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Lvw0/d;

    .line 4
    .line 5
    sget-object v0, Lcw0/g;->a:Lvw0/a;

    .line 6
    .line 7
    invoke-virtual {p0, v0}, Lvw0/d;->d(Lvw0/a;)Ljava/lang/Object;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    check-cast p0, Ljava/util/Map;

    .line 12
    .line 13
    if-eqz p0, :cond_0

    .line 14
    .line 15
    sget-object v0, Lfw0/x0;->a:Lfw0/x0;

    .line 16
    .line 17
    invoke-interface {p0, v0}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 18
    .line 19
    .line 20
    move-result-object p0

    .line 21
    return-object p0

    .line 22
    :cond_0
    const/4 p0, 0x0

    .line 23
    return-object p0
.end method

.method public get()Ljava/lang/Object;
    .locals 9

    .line 1
    iget v0, p0, Lss/b;->d:I

    .line 2
    .line 3
    sparse-switch v0, :sswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lss/b;->e:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast v0, Lkx0/a;

    .line 9
    .line 10
    invoke-interface {v0}, Lkx0/a;->get()Ljava/lang/Object;

    .line 11
    .line 12
    .line 13
    move-result-object v0

    .line 14
    check-cast v0, Landroid/content/Context;

    .line 15
    .line 16
    iget-object v1, p0, Lss/b;->f:Ljava/lang/Object;

    .line 17
    .line 18
    check-cast v1, Lkx0/a;

    .line 19
    .line 20
    invoke-interface {v1}, Lkx0/a;->get()Ljava/lang/Object;

    .line 21
    .line 22
    .line 23
    move-result-object v1

    .line 24
    check-cast v1, Lsn/d;

    .line 25
    .line 26
    iget-object v2, p0, Lss/b;->g:Ljava/lang/Object;

    .line 27
    .line 28
    check-cast v2, Lkx0/a;

    .line 29
    .line 30
    invoke-interface {v2}, Lkx0/a;->get()Ljava/lang/Object;

    .line 31
    .line 32
    .line 33
    move-result-object v2

    .line 34
    check-cast v2, Lyn/d;

    .line 35
    .line 36
    iget-object v3, p0, Lss/b;->h:Ljava/lang/Object;

    .line 37
    .line 38
    check-cast v3, Lrn/i;

    .line 39
    .line 40
    invoke-virtual {v3}, Lrn/i;->get()Ljava/lang/Object;

    .line 41
    .line 42
    .line 43
    move-result-object v3

    .line 44
    check-cast v3, Lrn/i;

    .line 45
    .line 46
    iget-object v4, p0, Lss/b;->i:Ljava/lang/Object;

    .line 47
    .line 48
    check-cast v4, Lkx0/a;

    .line 49
    .line 50
    invoke-interface {v4}, Lkx0/a;->get()Ljava/lang/Object;

    .line 51
    .line 52
    .line 53
    move-result-object v4

    .line 54
    check-cast v4, Ljava/util/concurrent/Executor;

    .line 55
    .line 56
    iget-object v5, p0, Lss/b;->j:Ljava/lang/Object;

    .line 57
    .line 58
    check-cast v5, Lkx0/a;

    .line 59
    .line 60
    invoke-interface {v5}, Lkx0/a;->get()Ljava/lang/Object;

    .line 61
    .line 62
    .line 63
    move-result-object v5

    .line 64
    check-cast v5, Lzn/c;

    .line 65
    .line 66
    new-instance v6, La61/a;

    .line 67
    .line 68
    const/4 v7, 0x2

    .line 69
    invoke-direct {v6, v7}, La61/a;-><init>(I)V

    .line 70
    .line 71
    .line 72
    new-instance v7, Lwq/f;

    .line 73
    .line 74
    const/4 v8, 0x1

    .line 75
    invoke-direct {v7, v8}, Lwq/f;-><init>(I)V

    .line 76
    .line 77
    .line 78
    iget-object p0, p0, Lss/b;->k:Ljava/lang/Object;

    .line 79
    .line 80
    check-cast p0, Lkx0/a;

    .line 81
    .line 82
    invoke-interface {p0}, Lkx0/a;->get()Ljava/lang/Object;

    .line 83
    .line 84
    .line 85
    move-result-object p0

    .line 86
    check-cast p0, Lyn/c;

    .line 87
    .line 88
    new-instance v8, Lqn/s;

    .line 89
    .line 90
    invoke-direct {v8}, Ljava/lang/Object;-><init>()V

    .line 91
    .line 92
    .line 93
    iput-object v0, v8, Lqn/s;->a:Ljava/lang/Object;

    .line 94
    .line 95
    iput-object v1, v8, Lqn/s;->b:Ljava/lang/Object;

    .line 96
    .line 97
    iput-object v2, v8, Lqn/s;->c:Ljava/lang/Object;

    .line 98
    .line 99
    iput-object v3, v8, Lqn/s;->d:Ljava/lang/Object;

    .line 100
    .line 101
    iput-object v4, v8, Lqn/s;->e:Ljava/lang/Object;

    .line 102
    .line 103
    iput-object v5, v8, Lqn/s;->f:Ljava/lang/Object;

    .line 104
    .line 105
    iput-object v6, v8, Lqn/s;->g:Ljava/lang/Object;

    .line 106
    .line 107
    iput-object v7, v8, Lqn/s;->h:Ljava/lang/Object;

    .line 108
    .line 109
    iput-object p0, v8, Lqn/s;->i:Ljava/lang/Object;

    .line 110
    .line 111
    return-object v8

    .line 112
    :sswitch_0
    iget-object v0, p0, Lss/b;->e:Ljava/lang/Object;

    .line 113
    .line 114
    check-cast v0, Lrt/a;

    .line 115
    .line 116
    invoke-virtual {v0}, Lrt/a;->get()Ljava/lang/Object;

    .line 117
    .line 118
    .line 119
    move-result-object v0

    .line 120
    move-object v2, v0

    .line 121
    check-cast v2, Lsr/f;

    .line 122
    .line 123
    iget-object v0, p0, Lss/b;->f:Ljava/lang/Object;

    .line 124
    .line 125
    check-cast v0, Lj1/a;

    .line 126
    .line 127
    invoke-virtual {v0}, Lj1/a;->get()Ljava/lang/Object;

    .line 128
    .line 129
    .line 130
    move-result-object v0

    .line 131
    move-object v3, v0

    .line 132
    check-cast v3, Lgt/b;

    .line 133
    .line 134
    iget-object v0, p0, Lss/b;->g:Ljava/lang/Object;

    .line 135
    .line 136
    check-cast v0, Lpv/g;

    .line 137
    .line 138
    invoke-virtual {v0}, Lpv/g;->get()Ljava/lang/Object;

    .line 139
    .line 140
    .line 141
    move-result-object v0

    .line 142
    move-object v4, v0

    .line 143
    check-cast v4, Lht/d;

    .line 144
    .line 145
    iget-object v0, p0, Lss/b;->h:Ljava/lang/Object;

    .line 146
    .line 147
    check-cast v0, Lrt/a;

    .line 148
    .line 149
    invoke-virtual {v0}, Lrt/a;->get()Ljava/lang/Object;

    .line 150
    .line 151
    .line 152
    move-result-object v0

    .line 153
    move-object v5, v0

    .line 154
    check-cast v5, Lgt/b;

    .line 155
    .line 156
    iget-object v0, p0, Lss/b;->i:Ljava/lang/Object;

    .line 157
    .line 158
    check-cast v0, Ldv/a;

    .line 159
    .line 160
    invoke-virtual {v0}, Ldv/a;->get()Ljava/lang/Object;

    .line 161
    .line 162
    .line 163
    move-result-object v0

    .line 164
    move-object v6, v0

    .line 165
    check-cast v6, Lcom/google/firebase/perf/config/RemoteConfigManager;

    .line 166
    .line 167
    iget-object v0, p0, Lss/b;->j:Ljava/lang/Object;

    .line 168
    .line 169
    check-cast v0, La61/a;

    .line 170
    .line 171
    invoke-virtual {v0}, La61/a;->get()Ljava/lang/Object;

    .line 172
    .line 173
    .line 174
    move-result-object v0

    .line 175
    move-object v7, v0

    .line 176
    check-cast v7, Lqt/a;

    .line 177
    .line 178
    iget-object p0, p0, Lss/b;->k:Ljava/lang/Object;

    .line 179
    .line 180
    check-cast p0, Let/d;

    .line 181
    .line 182
    invoke-virtual {p0}, Let/d;->get()Ljava/lang/Object;

    .line 183
    .line 184
    .line 185
    move-result-object p0

    .line 186
    move-object v8, p0

    .line 187
    check-cast v8, Lcom/google/firebase/perf/session/SessionManager;

    .line 188
    .line 189
    new-instance v1, Lot/b;

    .line 190
    .line 191
    invoke-direct/range {v1 .. v8}, Lot/b;-><init>(Lsr/f;Lgt/b;Lht/d;Lgt/b;Lcom/google/firebase/perf/config/RemoteConfigManager;Lqt/a;Lcom/google/firebase/perf/session/SessionManager;)V

    .line 192
    .line 193
    .line 194
    return-object v1

    .line 195
    :sswitch_1
    iget-object v0, p0, Lss/b;->e:Ljava/lang/Object;

    .line 196
    .line 197
    check-cast v0, Lkx0/a;

    .line 198
    .line 199
    invoke-interface {v0}, Lkx0/a;->get()Ljava/lang/Object;

    .line 200
    .line 201
    .line 202
    move-result-object v0

    .line 203
    move-object v2, v0

    .line 204
    check-cast v2, Lku/j;

    .line 205
    .line 206
    iget-object v0, p0, Lss/b;->f:Ljava/lang/Object;

    .line 207
    .line 208
    check-cast v0, Lkx0/a;

    .line 209
    .line 210
    invoke-interface {v0}, Lkx0/a;->get()Ljava/lang/Object;

    .line 211
    .line 212
    .line 213
    move-result-object v0

    .line 214
    move-object v3, v0

    .line 215
    check-cast v3, Lhu/p0;

    .line 216
    .line 217
    iget-object v0, p0, Lss/b;->g:Ljava/lang/Object;

    .line 218
    .line 219
    check-cast v0, Lkx0/a;

    .line 220
    .line 221
    invoke-interface {v0}, Lkx0/a;->get()Ljava/lang/Object;

    .line 222
    .line 223
    .line 224
    move-result-object v0

    .line 225
    move-object v4, v0

    .line 226
    check-cast v4, Lhu/m0;

    .line 227
    .line 228
    iget-object v0, p0, Lss/b;->h:Ljava/lang/Object;

    .line 229
    .line 230
    check-cast v0, Lkx0/a;

    .line 231
    .line 232
    invoke-interface {v0}, Lkx0/a;->get()Ljava/lang/Object;

    .line 233
    .line 234
    .line 235
    move-result-object v0

    .line 236
    move-object v5, v0

    .line 237
    check-cast v5, Lhu/a1;

    .line 238
    .line 239
    iget-object v0, p0, Lss/b;->i:Ljava/lang/Object;

    .line 240
    .line 241
    check-cast v0, Lkx0/a;

    .line 242
    .line 243
    invoke-interface {v0}, Lkx0/a;->get()Ljava/lang/Object;

    .line 244
    .line 245
    .line 246
    move-result-object v0

    .line 247
    move-object v6, v0

    .line 248
    check-cast v6, Lm6/g;

    .line 249
    .line 250
    iget-object v0, p0, Lss/b;->j:Ljava/lang/Object;

    .line 251
    .line 252
    check-cast v0, Lju/c;

    .line 253
    .line 254
    invoke-interface {v0}, Lkx0/a;->get()Ljava/lang/Object;

    .line 255
    .line 256
    .line 257
    move-result-object v0

    .line 258
    move-object v7, v0

    .line 259
    check-cast v7, Lhu/a0;

    .line 260
    .line 261
    iget-object p0, p0, Lss/b;->k:Ljava/lang/Object;

    .line 262
    .line 263
    check-cast p0, Lkx0/a;

    .line 264
    .line 265
    invoke-interface {p0}, Lkx0/a;->get()Ljava/lang/Object;

    .line 266
    .line 267
    .line 268
    move-result-object p0

    .line 269
    move-object v8, p0

    .line 270
    check-cast v8, Lpx0/g;

    .line 271
    .line 272
    new-instance v1, Lhu/w0;

    .line 273
    .line 274
    invoke-direct/range {v1 .. v8}, Lhu/w0;-><init>(Lku/j;Lhu/p0;Lhu/m0;Lhu/a1;Lm6/g;Lhu/a0;Lpx0/g;)V

    .line 275
    .line 276
    .line 277
    return-object v1

    .line 278
    nop

    .line 279
    :sswitch_data_0
    .sparse-switch
        0x5 -> :sswitch_1
        0xa -> :sswitch_0
    .end sparse-switch
.end method

.method public h(Ljava/lang/String;Ljava/lang/String;)Ljava/io/File;
    .locals 2

    .line 1
    new-instance v0, Ljava/io/File;

    .line 2
    .line 3
    new-instance v1, Ljava/io/File;

    .line 4
    .line 5
    iget-object p0, p0, Lss/b;->h:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast p0, Ljava/io/File;

    .line 8
    .line 9
    invoke-direct {v1, p0, p1}, Ljava/io/File;-><init>(Ljava/io/File;Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    invoke-virtual {v1}, Ljava/io/File;->mkdirs()Z

    .line 13
    .line 14
    .line 15
    invoke-direct {v0, v1, p2}, Ljava/io/File;-><init>(Ljava/io/File;Ljava/lang/String;)V

    .line 16
    .line 17
    .line 18
    return-object v0
.end method

.method public j(Ljava/lang/Throwable;Ljava/lang/Thread;Ljava/lang/String;Los/c;Z)V
    .locals 30

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p3

    .line 4
    .line 5
    move-object/from16 v2, p4

    .line 6
    .line 7
    const-string v3, "crash"

    .line 8
    .line 9
    invoke-virtual {v1, v3}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 10
    .line 11
    .line 12
    move-result v3

    .line 13
    iget-object v4, v0, Lss/b;->e:Ljava/lang/Object;

    .line 14
    .line 15
    check-cast v4, Lms/q;

    .line 16
    .line 17
    iget-wide v5, v2, Los/c;->b:J

    .line 18
    .line 19
    iget-object v7, v4, Lms/q;->a:Landroid/content/Context;

    .line 20
    .line 21
    invoke-virtual {v7}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    .line 22
    .line 23
    .line 24
    move-result-object v8

    .line 25
    invoke-virtual {v8}, Landroid/content/res/Resources;->getConfiguration()Landroid/content/res/Configuration;

    .line 26
    .line 27
    .line 28
    move-result-object v8

    .line 29
    iget v8, v8, Landroid/content/res/Configuration;->orientation:I

    .line 30
    .line 31
    iget-object v9, v4, Lms/q;->d:Lvp/y1;

    .line 32
    .line 33
    new-instance v10, Ljava/util/Stack;

    .line 34
    .line 35
    invoke-direct {v10}, Ljava/util/Stack;-><init>()V

    .line 36
    .line 37
    .line 38
    move-object/from16 v11, p1

    .line 39
    .line 40
    :goto_0
    if-eqz v11, :cond_0

    .line 41
    .line 42
    invoke-virtual {v10, v11}, Ljava/util/Stack;->push(Ljava/lang/Object;)Ljava/lang/Object;

    .line 43
    .line 44
    .line 45
    invoke-virtual {v11}, Ljava/lang/Throwable;->getCause()Ljava/lang/Throwable;

    .line 46
    .line 47
    .line 48
    move-result-object v11

    .line 49
    goto :goto_0

    .line 50
    :cond_0
    const/4 v11, 0x0

    .line 51
    move-object/from16 v16, v11

    .line 52
    .line 53
    :goto_1
    invoke-virtual {v10}, Ljava/util/AbstractCollection;->isEmpty()Z

    .line 54
    .line 55
    .line 56
    move-result v12

    .line 57
    if-nez v12, :cond_1

    .line 58
    .line 59
    invoke-virtual {v10}, Ljava/util/Stack;->pop()Ljava/lang/Object;

    .line 60
    .line 61
    .line 62
    move-result-object v12

    .line 63
    check-cast v12, Ljava/lang/Throwable;

    .line 64
    .line 65
    move-object v13, v12

    .line 66
    new-instance v12, Lun/a;

    .line 67
    .line 68
    move-object v14, v13

    .line 69
    invoke-virtual {v14}, Ljava/lang/Throwable;->getLocalizedMessage()Ljava/lang/String;

    .line 70
    .line 71
    .line 72
    move-result-object v13

    .line 73
    invoke-virtual {v14}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 74
    .line 75
    .line 76
    move-result-object v15

    .line 77
    invoke-virtual {v15}, Ljava/lang/Class;->getName()Ljava/lang/String;

    .line 78
    .line 79
    .line 80
    move-result-object v15

    .line 81
    invoke-virtual {v14}, Ljava/lang/Throwable;->getStackTrace()[Ljava/lang/StackTraceElement;

    .line 82
    .line 83
    .line 84
    move-result-object v14

    .line 85
    invoke-virtual {v9, v14}, Lvp/y1;->o([Ljava/lang/StackTraceElement;)[Ljava/lang/StackTraceElement;

    .line 86
    .line 87
    .line 88
    move-result-object v14

    .line 89
    const/16 v17, 0x3

    .line 90
    .line 91
    move-object/from16 v29, v15

    .line 92
    .line 93
    move-object v15, v14

    .line 94
    move-object/from16 v14, v29

    .line 95
    .line 96
    invoke-direct/range {v12 .. v17}, Lun/a;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 97
    .line 98
    .line 99
    move-object/from16 v16, v12

    .line 100
    .line 101
    goto :goto_1

    .line 102
    :cond_1
    move-object/from16 v12, v16

    .line 103
    .line 104
    new-instance v10, Lps/o0;

    .line 105
    .line 106
    invoke-direct {v10}, Ljava/lang/Object;-><init>()V

    .line 107
    .line 108
    .line 109
    iput-object v1, v10, Lps/o0;->b:Ljava/lang/String;

    .line 110
    .line 111
    iput-wide v5, v10, Lps/o0;->a:J

    .line 112
    .line 113
    iget-byte v1, v10, Lps/o0;->g:B

    .line 114
    .line 115
    const/4 v5, 0x1

    .line 116
    or-int/2addr v1, v5

    .line 117
    int-to-byte v1, v1

    .line 118
    iput-byte v1, v10, Lps/o0;->g:B

    .line 119
    .line 120
    sget-object v1, Ljs/c;->b:Ljs/c;

    .line 121
    .line 122
    invoke-virtual {v1, v7}, Ljs/c;->d(Landroid/content/Context;)Lps/c2;

    .line 123
    .line 124
    .line 125
    move-result-object v14

    .line 126
    move-object v1, v14

    .line 127
    check-cast v1, Lps/z0;

    .line 128
    .line 129
    iget v1, v1, Lps/z0;->c:I

    .line 130
    .line 131
    if-lez v1, :cond_3

    .line 132
    .line 133
    const/16 v11, 0x64

    .line 134
    .line 135
    if-eq v1, v11, :cond_2

    .line 136
    .line 137
    move v1, v5

    .line 138
    goto :goto_2

    .line 139
    :cond_2
    const/4 v1, 0x0

    .line 140
    :goto_2
    invoke-static {v1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 141
    .line 142
    .line 143
    move-result-object v11

    .line 144
    :cond_3
    move-object v13, v11

    .line 145
    invoke-static {v7}, Ljs/c;->c(Landroid/content/Context;)Ljava/util/ArrayList;

    .line 146
    .line 147
    .line 148
    move-result-object v15

    .line 149
    int-to-byte v1, v5

    .line 150
    new-instance v7, Ljava/util/ArrayList;

    .line 151
    .line 152
    invoke-direct {v7}, Ljava/util/ArrayList;-><init>()V

    .line 153
    .line 154
    .line 155
    iget-object v11, v12, Lun/a;->f:Ljava/lang/Object;

    .line 156
    .line 157
    check-cast v11, [Ljava/lang/StackTraceElement;

    .line 158
    .line 159
    invoke-virtual/range {p2 .. p2}, Ljava/lang/Thread;->getName()Ljava/lang/String;

    .line 160
    .line 161
    .line 162
    move-result-object v6

    .line 163
    move/from16 v16, v8

    .line 164
    .line 165
    const-string v8, "Null name"

    .line 166
    .line 167
    if-eqz v6, :cond_11

    .line 168
    .line 169
    move-object/from16 v17, v10

    .line 170
    .line 171
    int-to-byte v10, v5

    .line 172
    const/4 v5, 0x4

    .line 173
    invoke-static {v11, v5}, Lms/q;->d([Ljava/lang/StackTraceElement;I)Ljava/util/List;

    .line 174
    .line 175
    .line 176
    move-result-object v11

    .line 177
    const-string v5, "Null frames"

    .line 178
    .line 179
    if-eqz v11, :cond_10

    .line 180
    .line 181
    move-object/from16 v19, v13

    .line 182
    .line 183
    const-string v13, " importance"

    .line 184
    .line 185
    move-object/from16 v20, v14

    .line 186
    .line 187
    const-string v14, "Missing required properties:"

    .line 188
    .line 189
    move-object/from16 v21, v15

    .line 190
    .line 191
    const/4 v15, 0x1

    .line 192
    if-ne v10, v15, :cond_e

    .line 193
    .line 194
    new-instance v15, Lps/v0;

    .line 195
    .line 196
    move/from16 v22, v3

    .line 197
    .line 198
    const/4 v3, 0x4

    .line 199
    invoke-direct {v15, v3, v6, v11}, Lps/v0;-><init>(ILjava/lang/String;Ljava/util/List;)V

    .line 200
    .line 201
    .line 202
    invoke-virtual {v7, v15}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 203
    .line 204
    .line 205
    if-eqz p5, :cond_9

    .line 206
    .line 207
    invoke-static {}, Ljava/lang/Thread;->getAllStackTraces()Ljava/util/Map;

    .line 208
    .line 209
    .line 210
    move-result-object v3

    .line 211
    invoke-interface {v3}, Ljava/util/Map;->entrySet()Ljava/util/Set;

    .line 212
    .line 213
    .line 214
    move-result-object v3

    .line 215
    invoke-interface {v3}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 216
    .line 217
    .line 218
    move-result-object v3

    .line 219
    :goto_3
    invoke-interface {v3}, Ljava/util/Iterator;->hasNext()Z

    .line 220
    .line 221
    .line 222
    move-result v6

    .line 223
    if-eqz v6, :cond_9

    .line 224
    .line 225
    invoke-interface {v3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 226
    .line 227
    .line 228
    move-result-object v6

    .line 229
    check-cast v6, Ljava/util/Map$Entry;

    .line 230
    .line 231
    invoke-interface {v6}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 232
    .line 233
    .line 234
    move-result-object v11

    .line 235
    check-cast v11, Ljava/lang/Thread;

    .line 236
    .line 237
    move-object/from16 v15, p2

    .line 238
    .line 239
    invoke-virtual {v11, v15}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 240
    .line 241
    .line 242
    move-result v18

    .line 243
    if-nez v18, :cond_8

    .line 244
    .line 245
    invoke-interface {v6}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 246
    .line 247
    .line 248
    move-result-object v6

    .line 249
    check-cast v6, [Ljava/lang/StackTraceElement;

    .line 250
    .line 251
    invoke-virtual {v9, v6}, Lvp/y1;->o([Ljava/lang/StackTraceElement;)[Ljava/lang/StackTraceElement;

    .line 252
    .line 253
    .line 254
    move-result-object v6

    .line 255
    invoke-virtual {v11}, Ljava/lang/Thread;->getName()Ljava/lang/String;

    .line 256
    .line 257
    .line 258
    move-result-object v11

    .line 259
    if-eqz v11, :cond_7

    .line 260
    .line 261
    move-object/from16 v18, v3

    .line 262
    .line 263
    const/4 v3, 0x0

    .line 264
    invoke-static {v6, v3}, Lms/q;->d([Ljava/lang/StackTraceElement;I)Ljava/util/List;

    .line 265
    .line 266
    .line 267
    move-result-object v6

    .line 268
    if-eqz v6, :cond_6

    .line 269
    .line 270
    const/4 v3, 0x1

    .line 271
    if-ne v10, v3, :cond_4

    .line 272
    .line 273
    new-instance v3, Lps/v0;

    .line 274
    .line 275
    move-object/from16 v23, v9

    .line 276
    .line 277
    const/4 v9, 0x0

    .line 278
    invoke-direct {v3, v9, v11, v6}, Lps/v0;-><init>(ILjava/lang/String;Ljava/util/List;)V

    .line 279
    .line 280
    .line 281
    invoke-virtual {v7, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 282
    .line 283
    .line 284
    goto :goto_4

    .line 285
    :cond_4
    new-instance v0, Ljava/lang/StringBuilder;

    .line 286
    .line 287
    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    .line 288
    .line 289
    .line 290
    if-nez v10, :cond_5

    .line 291
    .line 292
    invoke-virtual {v0, v13}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 293
    .line 294
    .line 295
    :cond_5
    new-instance v1, Ljava/lang/IllegalStateException;

    .line 296
    .line 297
    invoke-static {v14, v0}, Lkx/a;->j(Ljava/lang/String;Ljava/lang/StringBuilder;)Ljava/lang/String;

    .line 298
    .line 299
    .line 300
    move-result-object v0

    .line 301
    invoke-direct {v1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 302
    .line 303
    .line 304
    throw v1

    .line 305
    :cond_6
    new-instance v0, Ljava/lang/NullPointerException;

    .line 306
    .line 307
    invoke-direct {v0, v5}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    .line 308
    .line 309
    .line 310
    throw v0

    .line 311
    :cond_7
    new-instance v0, Ljava/lang/NullPointerException;

    .line 312
    .line 313
    invoke-direct {v0, v8}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    .line 314
    .line 315
    .line 316
    throw v0

    .line 317
    :cond_8
    move-object/from16 v18, v3

    .line 318
    .line 319
    move-object/from16 v23, v9

    .line 320
    .line 321
    :goto_4
    move-object/from16 v3, v18

    .line 322
    .line 323
    move-object/from16 v9, v23

    .line 324
    .line 325
    goto :goto_3

    .line 326
    :cond_9
    invoke-static {v7}, Ljava/util/Collections;->unmodifiableList(Ljava/util/List;)Ljava/util/List;

    .line 327
    .line 328
    .line 329
    move-result-object v24

    .line 330
    const/4 v3, 0x0

    .line 331
    invoke-static {v12, v3}, Lms/q;->c(Lun/a;I)Lps/t0;

    .line 332
    .line 333
    .line 334
    move-result-object v25

    .line 335
    invoke-static {}, Lms/q;->e()Lps/u0;

    .line 336
    .line 337
    .line 338
    move-result-object v27

    .line 339
    invoke-virtual {v4}, Lms/q;->a()Ljava/util/List;

    .line 340
    .line 341
    .line 342
    move-result-object v28

    .line 343
    if-eqz v28, :cond_d

    .line 344
    .line 345
    new-instance v10, Lps/r0;

    .line 346
    .line 347
    const/16 v26, 0x0

    .line 348
    .line 349
    move-object/from16 v23, v10

    .line 350
    .line 351
    invoke-direct/range {v23 .. v28}, Lps/r0;-><init>(Ljava/util/List;Lps/t0;Lps/p1;Lps/u0;Ljava/util/List;)V

    .line 352
    .line 353
    .line 354
    const/4 v15, 0x1

    .line 355
    if-ne v1, v15, :cond_b

    .line 356
    .line 357
    new-instance v9, Lps/q0;

    .line 358
    .line 359
    const/4 v11, 0x0

    .line 360
    const/4 v12, 0x0

    .line 361
    move-object/from16 v1, v17

    .line 362
    .line 363
    move-object/from16 v13, v19

    .line 364
    .line 365
    move-object/from16 v14, v20

    .line 366
    .line 367
    move-object/from16 v15, v21

    .line 368
    .line 369
    invoke-direct/range {v9 .. v16}, Lps/q0;-><init>(Lps/r0;Ljava/util/List;Ljava/util/List;Ljava/lang/Boolean;Lps/c2;Ljava/util/List;I)V

    .line 370
    .line 371
    .line 372
    move/from16 v3, v16

    .line 373
    .line 374
    iput-object v9, v1, Lps/o0;->c:Lps/d2;

    .line 375
    .line 376
    invoke-virtual {v4, v3}, Lms/q;->b(I)Lps/b1;

    .line 377
    .line 378
    .line 379
    move-result-object v3

    .line 380
    iput-object v3, v1, Lps/o0;->d:Lps/e2;

    .line 381
    .line 382
    invoke-virtual {v1}, Lps/o0;->a()Lps/p0;

    .line 383
    .line 384
    .line 385
    move-result-object v1

    .line 386
    iget-object v3, v2, Los/c;->c:Ljava/util/Map;

    .line 387
    .line 388
    iget-object v4, v0, Lss/b;->h:Ljava/lang/Object;

    .line 389
    .line 390
    check-cast v4, Los/f;

    .line 391
    .line 392
    iget-object v5, v0, Lss/b;->i:Ljava/lang/Object;

    .line 393
    .line 394
    check-cast v5, Lss/b;

    .line 395
    .line 396
    invoke-static {v1, v4, v5, v3}, Lss/b;->a(Lps/p0;Los/f;Lss/b;Ljava/util/Map;)Lps/p0;

    .line 397
    .line 398
    .line 399
    move-result-object v1

    .line 400
    invoke-static {v1, v5}, Lss/b;->b(Lps/p0;Lss/b;)Lps/j2;

    .line 401
    .line 402
    .line 403
    move-result-object v1

    .line 404
    if-nez p5, :cond_a

    .line 405
    .line 406
    iget-object v3, v0, Lss/b;->k:Ljava/lang/Object;

    .line 407
    .line 408
    check-cast v3, Lns/d;

    .line 409
    .line 410
    iget-object v3, v3, Lns/d;->b:Lns/b;

    .line 411
    .line 412
    new-instance v4, La8/c0;

    .line 413
    .line 414
    move/from16 v5, v22

    .line 415
    .line 416
    invoke-direct {v4, v0, v1, v2, v5}, La8/c0;-><init>(Lss/b;Lps/j2;Los/c;Z)V

    .line 417
    .line 418
    .line 419
    invoke-virtual {v3, v4}, Lns/b;->a(Ljava/lang/Runnable;)Laq/t;

    .line 420
    .line 421
    .line 422
    return-void

    .line 423
    :cond_a
    move/from16 v5, v22

    .line 424
    .line 425
    iget-object v0, v0, Lss/b;->f:Ljava/lang/Object;

    .line 426
    .line 427
    check-cast v0, Lss/a;

    .line 428
    .line 429
    iget-object v2, v2, Los/c;->a:Ljava/lang/String;

    .line 430
    .line 431
    invoke-virtual {v0, v1, v2, v5}, Lss/a;->d(Lps/j2;Ljava/lang/String;Z)V

    .line 432
    .line 433
    .line 434
    return-void

    .line 435
    :cond_b
    new-instance v0, Ljava/lang/StringBuilder;

    .line 436
    .line 437
    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    .line 438
    .line 439
    .line 440
    if-nez v1, :cond_c

    .line 441
    .line 442
    const-string v1, " uiOrientation"

    .line 443
    .line 444
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 445
    .line 446
    .line 447
    :cond_c
    new-instance v1, Ljava/lang/IllegalStateException;

    .line 448
    .line 449
    invoke-static {v14, v0}, Lkx/a;->j(Ljava/lang/String;Ljava/lang/StringBuilder;)Ljava/lang/String;

    .line 450
    .line 451
    .line 452
    move-result-object v0

    .line 453
    invoke-direct {v1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 454
    .line 455
    .line 456
    throw v1

    .line 457
    :cond_d
    new-instance v0, Ljava/lang/NullPointerException;

    .line 458
    .line 459
    const-string v1, "Null binaries"

    .line 460
    .line 461
    invoke-direct {v0, v1}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    .line 462
    .line 463
    .line 464
    throw v0

    .line 465
    :cond_e
    new-instance v0, Ljava/lang/StringBuilder;

    .line 466
    .line 467
    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    .line 468
    .line 469
    .line 470
    if-nez v10, :cond_f

    .line 471
    .line 472
    invoke-virtual {v0, v13}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 473
    .line 474
    .line 475
    :cond_f
    new-instance v1, Ljava/lang/IllegalStateException;

    .line 476
    .line 477
    invoke-static {v14, v0}, Lkx/a;->j(Ljava/lang/String;Ljava/lang/StringBuilder;)Ljava/lang/String;

    .line 478
    .line 479
    .line 480
    move-result-object v0

    .line 481
    invoke-direct {v1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 482
    .line 483
    .line 484
    throw v1

    .line 485
    :cond_10
    new-instance v0, Ljava/lang/NullPointerException;

    .line 486
    .line 487
    invoke-direct {v0, v5}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    .line 488
    .line 489
    .line 490
    throw v0

    .line 491
    :cond_11
    new-instance v0, Ljava/lang/NullPointerException;

    .line 492
    .line 493
    invoke-direct {v0, v8}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    .line 494
    .line 495
    .line 496
    throw v0
.end method

.method public n(Ljava/util/concurrent/Executor;Ljava/lang/String;)Laq/t;
    .locals 16

    .line 1
    move-object/from16 v1, p0

    .line 2
    .line 3
    move-object/from16 v2, p2

    .line 4
    .line 5
    iget-object v0, v1, Lss/b;->f:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast v0, Lss/a;

    .line 8
    .line 9
    invoke-virtual {v0}, Lss/a;->b()Ljava/util/ArrayList;

    .line 10
    .line 11
    .line 12
    move-result-object v0

    .line 13
    new-instance v3, Ljava/util/ArrayList;

    .line 14
    .line 15
    invoke-direct {v3}, Ljava/util/ArrayList;-><init>()V

    .line 16
    .line 17
    .line 18
    invoke-virtual {v0}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 19
    .line 20
    .line 21
    move-result-object v4

    .line 22
    :goto_0
    invoke-interface {v4}, Ljava/util/Iterator;->hasNext()Z

    .line 23
    .line 24
    .line 25
    move-result v0

    .line 26
    if-eqz v0, :cond_0

    .line 27
    .line 28
    invoke-interface {v4}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 29
    .line 30
    .line 31
    move-result-object v0

    .line 32
    move-object v5, v0

    .line 33
    check-cast v5, Ljava/io/File;

    .line 34
    .line 35
    :try_start_0
    sget-object v0, Lss/a;->g:Lqs/a;

    .line 36
    .line 37
    invoke-static {v5}, Lss/a;->e(Ljava/io/File;)Ljava/lang/String;

    .line 38
    .line 39
    .line 40
    move-result-object v6

    .line 41
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 42
    .line 43
    .line 44
    invoke-static {v6}, Lqs/a;->i(Ljava/lang/String;)Lps/b0;

    .line 45
    .line 46
    .line 47
    move-result-object v0

    .line 48
    invoke-virtual {v5}, Ljava/io/File;->getName()Ljava/lang/String;

    .line 49
    .line 50
    .line 51
    move-result-object v6

    .line 52
    new-instance v7, Lms/a;

    .line 53
    .line 54
    invoke-direct {v7, v0, v6, v5}, Lms/a;-><init>(Lps/b0;Ljava/lang/String;Ljava/io/File;)V

    .line 55
    .line 56
    .line 57
    invoke-virtual {v3, v7}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z
    :try_end_0
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_0

    .line 58
    .line 59
    .line 60
    goto :goto_0

    .line 61
    :catch_0
    move-exception v0

    .line 62
    new-instance v6, Ljava/lang/StringBuilder;

    .line 63
    .line 64
    const-string v7, "Could not load report file "

    .line 65
    .line 66
    invoke-direct {v6, v7}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 67
    .line 68
    .line 69
    invoke-virtual {v6, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 70
    .line 71
    .line 72
    const-string v7, "; deleting"

    .line 73
    .line 74
    invoke-virtual {v6, v7}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 75
    .line 76
    .line 77
    invoke-virtual {v6}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 78
    .line 79
    .line 80
    move-result-object v6

    .line 81
    const-string v7, "FirebaseCrashlytics"

    .line 82
    .line 83
    invoke-static {v7, v6, v0}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 84
    .line 85
    .line 86
    invoke-virtual {v5}, Ljava/io/File;->delete()Z

    .line 87
    .line 88
    .line 89
    goto :goto_0

    .line 90
    :cond_0
    new-instance v0, Ljava/util/ArrayList;

    .line 91
    .line 92
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 93
    .line 94
    .line 95
    invoke-virtual {v3}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 96
    .line 97
    .line 98
    move-result-object v3

    .line 99
    :goto_1
    invoke-interface {v3}, Ljava/util/Iterator;->hasNext()Z

    .line 100
    .line 101
    .line 102
    move-result v4

    .line 103
    if-eqz v4, :cond_9

    .line 104
    .line 105
    invoke-interface {v3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 106
    .line 107
    .line 108
    move-result-object v4

    .line 109
    check-cast v4, Lms/a;

    .line 110
    .line 111
    if-eqz v2, :cond_2

    .line 112
    .line 113
    iget-object v5, v4, Lms/a;->b:Ljava/lang/String;

    .line 114
    .line 115
    invoke-virtual {v2, v5}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 116
    .line 117
    .line 118
    move-result v5

    .line 119
    if-eqz v5, :cond_1

    .line 120
    .line 121
    goto :goto_2

    .line 122
    :cond_1
    move-object/from16 v6, p1

    .line 123
    .line 124
    goto :goto_1

    .line 125
    :cond_2
    :goto_2
    iget-object v5, v1, Lss/b;->g:Ljava/lang/Object;

    .line 126
    .line 127
    check-cast v5, Lts/a;

    .line 128
    .line 129
    iget-object v6, v4, Lms/a;->a:Lps/b0;

    .line 130
    .line 131
    iget-object v7, v6, Lps/b0;->f:Ljava/lang/String;

    .line 132
    .line 133
    const/4 v8, 0x1

    .line 134
    if-eqz v7, :cond_4

    .line 135
    .line 136
    iget-object v6, v6, Lps/b0;->g:Ljava/lang/String;

    .line 137
    .line 138
    if-nez v6, :cond_3

    .line 139
    .line 140
    goto :goto_3

    .line 141
    :cond_3
    move-object v12, v4

    .line 142
    goto :goto_4

    .line 143
    :cond_4
    :goto_3
    iget-object v6, v1, Lss/b;->j:Ljava/lang/Object;

    .line 144
    .line 145
    check-cast v6, Lms/u;

    .line 146
    .line 147
    invoke-virtual {v6, v8}, Lms/u;->b(Z)Lms/t;

    .line 148
    .line 149
    .line 150
    move-result-object v6

    .line 151
    iget-object v7, v4, Lms/a;->a:Lps/b0;

    .line 152
    .line 153
    iget-object v9, v6, Lms/t;->a:Ljava/lang/String;

    .line 154
    .line 155
    invoke-virtual {v7}, Lps/b0;->a()Lps/a0;

    .line 156
    .line 157
    .line 158
    move-result-object v7

    .line 159
    iput-object v9, v7, Lps/a0;->e:Ljava/lang/String;

    .line 160
    .line 161
    invoke-virtual {v7}, Lps/a0;->a()Lps/b0;

    .line 162
    .line 163
    .line 164
    move-result-object v7

    .line 165
    iget-object v6, v6, Lms/t;->b:Ljava/lang/String;

    .line 166
    .line 167
    invoke-virtual {v7}, Lps/b0;->a()Lps/a0;

    .line 168
    .line 169
    .line 170
    move-result-object v7

    .line 171
    iput-object v6, v7, Lps/a0;->f:Ljava/lang/String;

    .line 172
    .line 173
    invoke-virtual {v7}, Lps/a0;->a()Lps/b0;

    .line 174
    .line 175
    .line 176
    move-result-object v6

    .line 177
    iget-object v7, v4, Lms/a;->b:Ljava/lang/String;

    .line 178
    .line 179
    iget-object v4, v4, Lms/a;->c:Ljava/io/File;

    .line 180
    .line 181
    new-instance v9, Lms/a;

    .line 182
    .line 183
    invoke-direct {v9, v6, v7, v4}, Lms/a;-><init>(Lps/b0;Ljava/lang/String;Ljava/io/File;)V

    .line 184
    .line 185
    .line 186
    move-object v12, v9

    .line 187
    :goto_4
    if-eqz v2, :cond_5

    .line 188
    .line 189
    goto :goto_5

    .line 190
    :cond_5
    const/4 v8, 0x0

    .line 191
    :goto_5
    iget-object v11, v5, Lts/a;->a:Lts/b;

    .line 192
    .line 193
    const-string v4, "Dropping report due to queue being full: "

    .line 194
    .line 195
    const-string v5, "Closing task for report: "

    .line 196
    .line 197
    const-string v6, "Queue size: "

    .line 198
    .line 199
    const-string v7, "Enqueueing report: "

    .line 200
    .line 201
    iget-object v9, v11, Lts/b;->f:Ljava/util/concurrent/ArrayBlockingQueue;

    .line 202
    .line 203
    monitor-enter v9

    .line 204
    :try_start_1
    new-instance v14, Laq/k;

    .line 205
    .line 206
    invoke-direct {v14}, Laq/k;-><init>()V

    .line 207
    .line 208
    .line 209
    if-eqz v8, :cond_8

    .line 210
    .line 211
    iget-object v8, v11, Lts/b;->i:Lb81/d;

    .line 212
    .line 213
    iget-object v8, v8, Lb81/d;->e:Ljava/lang/Object;

    .line 214
    .line 215
    check-cast v8, Ljava/util/concurrent/atomic/AtomicInteger;

    .line 216
    .line 217
    invoke-virtual {v8}, Ljava/util/concurrent/atomic/AtomicInteger;->getAndIncrement()I

    .line 218
    .line 219
    .line 220
    iget-object v8, v11, Lts/b;->f:Ljava/util/concurrent/ArrayBlockingQueue;

    .line 221
    .line 222
    invoke-virtual {v8}, Ljava/util/concurrent/ArrayBlockingQueue;->size()I

    .line 223
    .line 224
    .line 225
    move-result v8

    .line 226
    iget v10, v11, Lts/b;->e:I

    .line 227
    .line 228
    if-ge v8, v10, :cond_6

    .line 229
    .line 230
    sget-object v4, Ljs/c;->a:Ljs/c;

    .line 231
    .line 232
    new-instance v8, Ljava/lang/StringBuilder;

    .line 233
    .line 234
    invoke-direct {v8, v7}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 235
    .line 236
    .line 237
    iget-object v7, v12, Lms/a;->b:Ljava/lang/String;

    .line 238
    .line 239
    invoke-virtual {v8, v7}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 240
    .line 241
    .line 242
    invoke-virtual {v8}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 243
    .line 244
    .line 245
    move-result-object v7

    .line 246
    invoke-virtual {v4, v7}, Ljs/c;->b(Ljava/lang/String;)V

    .line 247
    .line 248
    .line 249
    new-instance v7, Ljava/lang/StringBuilder;

    .line 250
    .line 251
    invoke-direct {v7, v6}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 252
    .line 253
    .line 254
    iget-object v6, v11, Lts/b;->f:Ljava/util/concurrent/ArrayBlockingQueue;

    .line 255
    .line 256
    invoke-virtual {v6}, Ljava/util/concurrent/ArrayBlockingQueue;->size()I

    .line 257
    .line 258
    .line 259
    move-result v6

    .line 260
    invoke-virtual {v7, v6}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 261
    .line 262
    .line 263
    invoke-virtual {v7}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 264
    .line 265
    .line 266
    move-result-object v6

    .line 267
    invoke-virtual {v4, v6}, Ljs/c;->b(Ljava/lang/String;)V

    .line 268
    .line 269
    .line 270
    iget-object v6, v11, Lts/b;->g:Ljava/util/concurrent/ThreadPoolExecutor;

    .line 271
    .line 272
    new-instance v10, Lio/i;

    .line 273
    .line 274
    const/4 v15, 0x3

    .line 275
    const/4 v13, 0x0

    .line 276
    invoke-direct/range {v10 .. v15}, Lio/i;-><init>(Ljava/lang/Object;Ljava/lang/Object;ZLjava/lang/Object;I)V

    .line 277
    .line 278
    .line 279
    invoke-virtual {v6, v10}, Ljava/util/concurrent/ThreadPoolExecutor;->execute(Ljava/lang/Runnable;)V

    .line 280
    .line 281
    .line 282
    new-instance v6, Ljava/lang/StringBuilder;

    .line 283
    .line 284
    invoke-direct {v6, v5}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 285
    .line 286
    .line 287
    iget-object v5, v12, Lms/a;->b:Ljava/lang/String;

    .line 288
    .line 289
    invoke-virtual {v6, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 290
    .line 291
    .line 292
    invoke-virtual {v6}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 293
    .line 294
    .line 295
    move-result-object v5

    .line 296
    invoke-virtual {v4, v5}, Ljs/c;->b(Ljava/lang/String;)V

    .line 297
    .line 298
    .line 299
    invoke-virtual {v14, v12}, Laq/k;->d(Ljava/lang/Object;)V

    .line 300
    .line 301
    .line 302
    monitor-exit v9

    .line 303
    goto :goto_6

    .line 304
    :catchall_0
    move-exception v0

    .line 305
    goto :goto_7

    .line 306
    :cond_6
    invoke-virtual {v11}, Lts/b;->a()I

    .line 307
    .line 308
    .line 309
    new-instance v5, Ljava/lang/StringBuilder;

    .line 310
    .line 311
    invoke-direct {v5, v4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 312
    .line 313
    .line 314
    iget-object v4, v12, Lms/a;->b:Ljava/lang/String;

    .line 315
    .line 316
    invoke-virtual {v5, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 317
    .line 318
    .line 319
    invoke-virtual {v5}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 320
    .line 321
    .line 322
    move-result-object v4

    .line 323
    const-string v5, "FirebaseCrashlytics"

    .line 324
    .line 325
    const/4 v6, 0x3

    .line 326
    invoke-static {v5, v6}, Landroid/util/Log;->isLoggable(Ljava/lang/String;I)Z

    .line 327
    .line 328
    .line 329
    move-result v5

    .line 330
    if-eqz v5, :cond_7

    .line 331
    .line 332
    const-string v5, "FirebaseCrashlytics"

    .line 333
    .line 334
    const/4 v6, 0x0

    .line 335
    invoke-static {v5, v4, v6}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 336
    .line 337
    .line 338
    :cond_7
    iget-object v4, v11, Lts/b;->i:Lb81/d;

    .line 339
    .line 340
    iget-object v4, v4, Lb81/d;->f:Ljava/lang/Object;

    .line 341
    .line 342
    check-cast v4, Ljava/util/concurrent/atomic/AtomicInteger;

    .line 343
    .line 344
    invoke-virtual {v4}, Ljava/util/concurrent/atomic/AtomicInteger;->getAndIncrement()I

    .line 345
    .line 346
    .line 347
    invoke-virtual {v14, v12}, Laq/k;->d(Ljava/lang/Object;)V

    .line 348
    .line 349
    .line 350
    monitor-exit v9

    .line 351
    goto :goto_6

    .line 352
    :cond_8
    invoke-virtual {v11, v12, v14}, Lts/b;->b(Lms/a;Laq/k;)V

    .line 353
    .line 354
    .line 355
    monitor-exit v9
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 356
    :goto_6
    iget-object v4, v14, Laq/k;->a:Laq/t;

    .line 357
    .line 358
    new-instance v5, Lj9/d;

    .line 359
    .line 360
    invoke-direct {v5, v1}, Lj9/d;-><init>(Lss/b;)V

    .line 361
    .line 362
    .line 363
    move-object/from16 v6, p1

    .line 364
    .line 365
    invoke-virtual {v4, v6, v5}, Laq/t;->m(Ljava/util/concurrent/Executor;Laq/b;)Laq/t;

    .line 366
    .line 367
    .line 368
    move-result-object v4

    .line 369
    invoke-virtual {v0, v4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 370
    .line 371
    .line 372
    goto/16 :goto_1

    .line 373
    .line 374
    :goto_7
    :try_start_2
    monitor-exit v9
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 375
    throw v0

    .line 376
    :cond_9
    invoke-static {v0}, Ljp/l1;->f(Ljava/util/List;)Laq/t;

    .line 377
    .line 378
    .line 379
    move-result-object v0

    .line 380
    return-object v0
.end method

.method public o(Lx41/t;)V
    .locals 2

    .line 1
    const-string v0, "error"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    new-instance v0, Lg70/g;

    .line 7
    .line 8
    const/4 v1, 0x1

    .line 9
    invoke-direct {v0, p1, v1}, Lg70/g;-><init>(Lx41/t;I)V

    .line 10
    .line 11
    .line 12
    const/4 v1, 0x0

    .line 13
    invoke-static {v1, p0, v0}, Llp/nd;->m(Ljava/lang/String;Ljava/lang/Object;Lay0/a;)Lkj0/f;

    .line 14
    .line 15
    .line 16
    sput-object v1, Lh70/m;->b:Lw81/c;

    .line 17
    .line 18
    iget-object p0, p0, Lss/b;->g:Ljava/lang/Object;

    .line 19
    .line 20
    check-cast p0, Lay0/k;

    .line 21
    .line 22
    invoke-interface {p0, p1}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 23
    .line 24
    .line 25
    return-void
.end method

.method public toString()Ljava/lang/String;
    .locals 2

    .line 1
    iget v0, p0, Lss/b;->d:I

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
    new-instance v0, Ljava/lang/StringBuilder;

    .line 12
    .line 13
    const-string v1, "HttpRequestData(url="

    .line 14
    .line 15
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 16
    .line 17
    .line 18
    iget-object v1, p0, Lss/b;->e:Ljava/lang/Object;

    .line 19
    .line 20
    check-cast v1, Low0/f0;

    .line 21
    .line 22
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 23
    .line 24
    .line 25
    const-string v1, ", method="

    .line 26
    .line 27
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 28
    .line 29
    .line 30
    iget-object p0, p0, Lss/b;->f:Ljava/lang/Object;

    .line 31
    .line 32
    check-cast p0, Low0/s;

    .line 33
    .line 34
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 35
    .line 36
    .line 37
    const/16 p0, 0x29

    .line 38
    .line 39
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 40
    .line 41
    .line 42
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 43
    .line 44
    .line 45
    move-result-object p0

    .line 46
    return-object p0

    .line 47
    :pswitch_data_0
    .packed-switch 0x7
        :pswitch_0
    .end packed-switch
.end method
