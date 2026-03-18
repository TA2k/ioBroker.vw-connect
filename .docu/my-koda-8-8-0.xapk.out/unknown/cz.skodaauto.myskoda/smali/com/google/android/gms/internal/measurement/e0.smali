.class public final Lcom/google/android/gms/internal/measurement/e0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Lcom/google/firebase/messaging/w;

.field public b:Lcom/google/firebase/messaging/w;

.field public final c:Lgw0/c;

.field public final d:Lcom/google/android/gms/internal/measurement/u;


# direct methods
.method public constructor <init>()V
    .locals 4

    .line 1
    new-instance v0, Lcom/google/firebase/messaging/w;

    .line 2
    .line 3
    const/4 v1, 0x6

    .line 4
    invoke-direct {v0, v1}, Lcom/google/firebase/messaging/w;-><init>(I)V

    .line 5
    .line 6
    .line 7
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 8
    .line 9
    .line 10
    iput-object v0, p0, Lcom/google/android/gms/internal/measurement/e0;->a:Lcom/google/firebase/messaging/w;

    .line 11
    .line 12
    iget-object v1, v0, Lcom/google/firebase/messaging/w;->f:Ljava/lang/Object;

    .line 13
    .line 14
    check-cast v1, Lcom/google/firebase/messaging/w;

    .line 15
    .line 16
    invoke-virtual {v1}, Lcom/google/firebase/messaging/w;->z()Lcom/google/firebase/messaging/w;

    .line 17
    .line 18
    .line 19
    move-result-object v1

    .line 20
    iput-object v1, p0, Lcom/google/android/gms/internal/measurement/e0;->b:Lcom/google/firebase/messaging/w;

    .line 21
    .line 22
    new-instance v1, Lgw0/c;

    .line 23
    .line 24
    const/16 v2, 0x8

    .line 25
    .line 26
    invoke-direct {v1, v2}, Lgw0/c;-><init>(I)V

    .line 27
    .line 28
    .line 29
    iput-object v1, p0, Lcom/google/android/gms/internal/measurement/e0;->c:Lgw0/c;

    .line 30
    .line 31
    new-instance v1, Lcom/google/android/gms/internal/measurement/u;

    .line 32
    .line 33
    const/4 v2, 0x3

    .line 34
    invoke-direct {v1, v2}, Lcom/google/android/gms/internal/measurement/u;-><init>(I)V

    .line 35
    .line 36
    .line 37
    iput-object v1, p0, Lcom/google/android/gms/internal/measurement/e0;->d:Lcom/google/android/gms/internal/measurement/u;

    .line 38
    .line 39
    new-instance v1, Lcom/google/android/gms/internal/measurement/a;

    .line 40
    .line 41
    const/4 v2, 0x1

    .line 42
    invoke-direct {v1, p0, v2}, Lcom/google/android/gms/internal/measurement/a;-><init>(Lcom/google/android/gms/internal/measurement/e0;I)V

    .line 43
    .line 44
    .line 45
    iget-object v0, v0, Lcom/google/firebase/messaging/w;->h:Ljava/lang/Object;

    .line 46
    .line 47
    check-cast v0, Lcom/google/android/gms/internal/measurement/a6;

    .line 48
    .line 49
    iget-object v2, v0, Lcom/google/android/gms/internal/measurement/a6;->a:Ljava/lang/Object;

    .line 50
    .line 51
    check-cast v2, Ljava/util/HashMap;

    .line 52
    .line 53
    const-string v3, "internal.registerCallback"

    .line 54
    .line 55
    invoke-virtual {v2, v3, v1}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 56
    .line 57
    .line 58
    new-instance v1, Lcom/google/android/gms/internal/measurement/a;

    .line 59
    .line 60
    const/4 v2, 0x0

    .line 61
    invoke-direct {v1, p0, v2}, Lcom/google/android/gms/internal/measurement/a;-><init>(Lcom/google/android/gms/internal/measurement/e0;I)V

    .line 62
    .line 63
    .line 64
    iget-object p0, v0, Lcom/google/android/gms/internal/measurement/a6;->a:Ljava/lang/Object;

    .line 65
    .line 66
    check-cast p0, Ljava/util/HashMap;

    .line 67
    .line 68
    const-string v0, "internal.eventLogger"

    .line 69
    .line 70
    invoke-virtual {p0, v0, v1}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 71
    .line 72
    .line 73
    return-void
.end method


# virtual methods
.method public final a(Lcom/google/android/gms/internal/measurement/b;)Z
    .locals 5

    .line 1
    iget-object v0, p0, Lcom/google/android/gms/internal/measurement/e0;->c:Lgw0/c;

    .line 2
    .line 3
    :try_start_0
    iput-object p1, v0, Lgw0/c;->e:Ljava/lang/Object;

    .line 4
    .line 5
    invoke-virtual {p1}, Lcom/google/android/gms/internal/measurement/b;->a()Lcom/google/android/gms/internal/measurement/b;

    .line 6
    .line 7
    .line 8
    move-result-object p1

    .line 9
    iput-object p1, v0, Lgw0/c;->f:Ljava/lang/Object;

    .line 10
    .line 11
    iget-object p1, v0, Lgw0/c;->g:Ljava/lang/Object;

    .line 12
    .line 13
    check-cast p1, Ljava/util/ArrayList;

    .line 14
    .line 15
    invoke-virtual {p1}, Ljava/util/ArrayList;->clear()V

    .line 16
    .line 17
    .line 18
    iget-object p1, p0, Lcom/google/android/gms/internal/measurement/e0;->a:Lcom/google/firebase/messaging/w;

    .line 19
    .line 20
    iget-object p1, p1, Lcom/google/firebase/messaging/w;->g:Ljava/lang/Object;

    .line 21
    .line 22
    check-cast p1, Lcom/google/firebase/messaging/w;

    .line 23
    .line 24
    const-string v1, "runtime.counter"

    .line 25
    .line 26
    new-instance v2, Lcom/google/android/gms/internal/measurement/h;

    .line 27
    .line 28
    const-wide/16 v3, 0x0

    .line 29
    .line 30
    invoke-static {v3, v4}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 31
    .line 32
    .line 33
    move-result-object v3

    .line 34
    invoke-direct {v2, v3}, Lcom/google/android/gms/internal/measurement/h;-><init>(Ljava/lang/Double;)V

    .line 35
    .line 36
    .line 37
    invoke-virtual {p1, v1, v2}, Lcom/google/firebase/messaging/w;->B(Ljava/lang/String;Lcom/google/android/gms/internal/measurement/o;)V

    .line 38
    .line 39
    .line 40
    iget-object p1, p0, Lcom/google/android/gms/internal/measurement/e0;->d:Lcom/google/android/gms/internal/measurement/u;

    .line 41
    .line 42
    iget-object p0, p0, Lcom/google/android/gms/internal/measurement/e0;->b:Lcom/google/firebase/messaging/w;

    .line 43
    .line 44
    invoke-virtual {p0}, Lcom/google/firebase/messaging/w;->z()Lcom/google/firebase/messaging/w;

    .line 45
    .line 46
    .line 47
    move-result-object p0

    .line 48
    invoke-virtual {p1, p0, v0}, Lcom/google/android/gms/internal/measurement/u;->d(Lcom/google/firebase/messaging/w;Lgw0/c;)V

    .line 49
    .line 50
    .line 51
    iget-object p0, v0, Lgw0/c;->f:Ljava/lang/Object;

    .line 52
    .line 53
    check-cast p0, Lcom/google/android/gms/internal/measurement/b;

    .line 54
    .line 55
    iget-object p1, v0, Lgw0/c;->e:Ljava/lang/Object;

    .line 56
    .line 57
    check-cast p1, Lcom/google/android/gms/internal/measurement/b;

    .line 58
    .line 59
    invoke-virtual {p0, p1}, Lcom/google/android/gms/internal/measurement/b;->equals(Ljava/lang/Object;)Z

    .line 60
    .line 61
    .line 62
    move-result p0

    .line 63
    if-eqz p0, :cond_1

    .line 64
    .line 65
    iget-object p0, v0, Lgw0/c;->g:Ljava/lang/Object;

    .line 66
    .line 67
    check-cast p0, Ljava/util/ArrayList;

    .line 68
    .line 69
    invoke-virtual {p0}, Ljava/util/ArrayList;->isEmpty()Z

    .line 70
    .line 71
    .line 72
    move-result p0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 73
    if-nez p0, :cond_0

    .line 74
    .line 75
    goto :goto_0

    .line 76
    :cond_0
    const/4 p0, 0x0

    .line 77
    return p0

    .line 78
    :cond_1
    :goto_0
    const/4 p0, 0x1

    .line 79
    return p0

    .line 80
    :catchall_0
    move-exception p0

    .line 81
    new-instance p1, Lcom/google/android/gms/internal/measurement/q0;

    .line 82
    .line 83
    invoke-direct {p1, p0}, Ljava/lang/Exception;-><init>(Ljava/lang/Throwable;)V

    .line 84
    .line 85
    .line 86
    throw p1
.end method

.method public final b(Lcom/google/android/gms/internal/measurement/v3;)V
    .locals 8

    .line 1
    :try_start_0
    iget-object v0, p0, Lcom/google/android/gms/internal/measurement/e0;->a:Lcom/google/firebase/messaging/w;

    .line 2
    .line 3
    iget-object v1, v0, Lcom/google/firebase/messaging/w;->f:Ljava/lang/Object;

    .line 4
    .line 5
    check-cast v1, Lcom/google/firebase/messaging/w;

    .line 6
    .line 7
    invoke-virtual {v1}, Lcom/google/firebase/messaging/w;->z()Lcom/google/firebase/messaging/w;

    .line 8
    .line 9
    .line 10
    move-result-object v1

    .line 11
    iput-object v1, p0, Lcom/google/android/gms/internal/measurement/e0;->b:Lcom/google/firebase/messaging/w;

    .line 12
    .line 13
    invoke-virtual {p1}, Lcom/google/android/gms/internal/measurement/v3;->p()Ljava/util/List;

    .line 14
    .line 15
    .line 16
    move-result-object v1

    .line 17
    iget-object v2, p0, Lcom/google/android/gms/internal/measurement/e0;->b:Lcom/google/firebase/messaging/w;

    .line 18
    .line 19
    const/4 v3, 0x0

    .line 20
    new-array v3, v3, [Lcom/google/android/gms/internal/measurement/w3;

    .line 21
    .line 22
    invoke-interface {v1, v3}, Ljava/util/List;->toArray([Ljava/lang/Object;)[Ljava/lang/Object;

    .line 23
    .line 24
    .line 25
    move-result-object v1

    .line 26
    check-cast v1, [Lcom/google/android/gms/internal/measurement/w3;

    .line 27
    .line 28
    invoke-virtual {v0, v2, v1}, Lcom/google/firebase/messaging/w;->w(Lcom/google/firebase/messaging/w;[Lcom/google/android/gms/internal/measurement/w3;)Lcom/google/android/gms/internal/measurement/o;

    .line 29
    .line 30
    .line 31
    move-result-object v1

    .line 32
    instance-of v1, v1, Lcom/google/android/gms/internal/measurement/g;

    .line 33
    .line 34
    if-nez v1, :cond_6

    .line 35
    .line 36
    invoke-virtual {p1}, Lcom/google/android/gms/internal/measurement/v3;->q()Lcom/google/android/gms/internal/measurement/t3;

    .line 37
    .line 38
    .line 39
    move-result-object p1

    .line 40
    invoke-virtual {p1}, Lcom/google/android/gms/internal/measurement/t3;->p()Ljava/util/List;

    .line 41
    .line 42
    .line 43
    move-result-object p1

    .line 44
    invoke-interface {p1}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 45
    .line 46
    .line 47
    move-result-object p1

    .line 48
    :cond_0
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 49
    .line 50
    .line 51
    move-result v1

    .line 52
    if-eqz v1, :cond_5

    .line 53
    .line 54
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 55
    .line 56
    .line 57
    move-result-object v1

    .line 58
    check-cast v1, Lcom/google/android/gms/internal/measurement/u3;

    .line 59
    .line 60
    invoke-virtual {v1}, Lcom/google/android/gms/internal/measurement/u3;->q()Ljava/util/List;

    .line 61
    .line 62
    .line 63
    move-result-object v2

    .line 64
    invoke-virtual {v1}, Lcom/google/android/gms/internal/measurement/u3;->p()Ljava/lang/String;

    .line 65
    .line 66
    .line 67
    move-result-object v1

    .line 68
    invoke-interface {v2}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 69
    .line 70
    .line 71
    move-result-object v2

    .line 72
    :goto_0
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    .line 73
    .line 74
    .line 75
    move-result v3

    .line 76
    if-eqz v3, :cond_0

    .line 77
    .line 78
    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 79
    .line 80
    .line 81
    move-result-object v3

    .line 82
    check-cast v3, Lcom/google/android/gms/internal/measurement/w3;

    .line 83
    .line 84
    iget-object v4, p0, Lcom/google/android/gms/internal/measurement/e0;->b:Lcom/google/firebase/messaging/w;

    .line 85
    .line 86
    filled-new-array {v3}, [Lcom/google/android/gms/internal/measurement/w3;

    .line 87
    .line 88
    .line 89
    move-result-object v3

    .line 90
    invoke-virtual {v0, v4, v3}, Lcom/google/firebase/messaging/w;->w(Lcom/google/firebase/messaging/w;[Lcom/google/android/gms/internal/measurement/w3;)Lcom/google/android/gms/internal/measurement/o;

    .line 91
    .line 92
    .line 93
    move-result-object v3

    .line 94
    instance-of v4, v3, Lcom/google/android/gms/internal/measurement/l;

    .line 95
    .line 96
    if-eqz v4, :cond_4

    .line 97
    .line 98
    const-string v4, "Rule function is undefined: "

    .line 99
    .line 100
    iget-object v5, p0, Lcom/google/android/gms/internal/measurement/e0;->b:Lcom/google/firebase/messaging/w;

    .line 101
    .line 102
    const-string v6, "Invalid function name: "

    .line 103
    .line 104
    invoke-virtual {v5, v1}, Lcom/google/firebase/messaging/w;->A(Ljava/lang/String;)Z

    .line 105
    .line 106
    .line 107
    move-result v7

    .line 108
    if-nez v7, :cond_1

    .line 109
    .line 110
    const/4 v5, 0x0

    .line 111
    goto :goto_1

    .line 112
    :cond_1
    invoke-virtual {v5, v1}, Lcom/google/firebase/messaging/w;->E(Ljava/lang/String;)Lcom/google/android/gms/internal/measurement/o;

    .line 113
    .line 114
    .line 115
    move-result-object v5

    .line 116
    instance-of v7, v5, Lcom/google/android/gms/internal/measurement/i;

    .line 117
    .line 118
    if-eqz v7, :cond_3

    .line 119
    .line 120
    check-cast v5, Lcom/google/android/gms/internal/measurement/i;

    .line 121
    .line 122
    :goto_1
    if-eqz v5, :cond_2

    .line 123
    .line 124
    iget-object v4, p0, Lcom/google/android/gms/internal/measurement/e0;->b:Lcom/google/firebase/messaging/w;

    .line 125
    .line 126
    invoke-static {v3}, Ljava/util/Collections;->singletonList(Ljava/lang/Object;)Ljava/util/List;

    .line 127
    .line 128
    .line 129
    move-result-object v3

    .line 130
    invoke-virtual {v5, v4, v3}, Lcom/google/android/gms/internal/measurement/i;->a(Lcom/google/firebase/messaging/w;Ljava/util/List;)Lcom/google/android/gms/internal/measurement/o;

    .line 131
    .line 132
    .line 133
    goto :goto_0

    .line 134
    :cond_2
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 135
    .line 136
    invoke-static {v1}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;

    .line 137
    .line 138
    .line 139
    move-result-object p1

    .line 140
    invoke-virtual {v4, p1}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 141
    .line 142
    .line 143
    move-result-object p1

    .line 144
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 145
    .line 146
    .line 147
    throw p0

    .line 148
    :cond_3
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 149
    .line 150
    invoke-static {v1}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;

    .line 151
    .line 152
    .line 153
    move-result-object p1

    .line 154
    invoke-virtual {v6, p1}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 155
    .line 156
    .line 157
    move-result-object p1

    .line 158
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 159
    .line 160
    .line 161
    throw p0

    .line 162
    :cond_4
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 163
    .line 164
    const-string p1, "Invalid rule definition"

    .line 165
    .line 166
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 167
    .line 168
    .line 169
    throw p0

    .line 170
    :cond_5
    return-void

    .line 171
    :cond_6
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 172
    .line 173
    const-string p1, "Program loading failed"

    .line 174
    .line 175
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 176
    .line 177
    .line 178
    throw p0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 179
    :catchall_0
    move-exception p0

    .line 180
    new-instance p1, Lcom/google/android/gms/internal/measurement/q0;

    .line 181
    .line 182
    invoke-direct {p1, p0}, Ljava/lang/Exception;-><init>(Ljava/lang/Throwable;)V

    .line 183
    .line 184
    .line 185
    throw p1
.end method
