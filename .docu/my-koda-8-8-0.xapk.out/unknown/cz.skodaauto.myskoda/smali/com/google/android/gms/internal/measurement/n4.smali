.class public final Lcom/google/android/gms/internal/measurement/n4;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final g:Ljava/lang/Object;

.field public static volatile h:Lcom/google/android/gms/internal/measurement/d4;

.field public static final i:Ljava/util/concurrent/atomic/AtomicInteger;


# instance fields
.field public final a:Lb6/f;

.field public final b:Ljava/lang/String;

.field public final c:Ljava/lang/Object;

.field public volatile d:I

.field public volatile e:Ljava/lang/Object;

.field public final synthetic f:I


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Ljava/lang/Object;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lcom/google/android/gms/internal/measurement/n4;->g:Ljava/lang/Object;

    .line 7
    .line 8
    new-instance v0, Ljava/util/concurrent/atomic/AtomicReference;

    .line 9
    .line 10
    invoke-direct {v0}, Ljava/util/concurrent/atomic/AtomicReference;-><init>()V

    .line 11
    .line 12
    .line 13
    new-instance v0, Ljava/util/concurrent/atomic/AtomicInteger;

    .line 14
    .line 15
    invoke-direct {v0}, Ljava/util/concurrent/atomic/AtomicInteger;-><init>()V

    .line 16
    .line 17
    .line 18
    sput-object v0, Lcom/google/android/gms/internal/measurement/n4;->i:Ljava/util/concurrent/atomic/AtomicInteger;

    .line 19
    .line 20
    return-void
.end method

.method public synthetic constructor <init>(Lb6/f;Ljava/lang/String;Ljava/lang/Object;I)V
    .locals 0

    .line 1
    iput p4, p0, Lcom/google/android/gms/internal/measurement/n4;->f:I

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    const/4 p4, -0x1

    .line 7
    iput p4, p0, Lcom/google/android/gms/internal/measurement/n4;->d:I

    .line 8
    .line 9
    iget-object p4, p1, Lb6/f;->e:Ljava/lang/Object;

    .line 10
    .line 11
    check-cast p4, Landroid/net/Uri;

    .line 12
    .line 13
    if-eqz p4, :cond_0

    .line 14
    .line 15
    iput-object p1, p0, Lcom/google/android/gms/internal/measurement/n4;->a:Lb6/f;

    .line 16
    .line 17
    iput-object p2, p0, Lcom/google/android/gms/internal/measurement/n4;->b:Ljava/lang/String;

    .line 18
    .line 19
    iput-object p3, p0, Lcom/google/android/gms/internal/measurement/n4;->c:Ljava/lang/Object;

    .line 20
    .line 21
    return-void

    .line 22
    :cond_0
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 23
    .line 24
    const-string p1, "Must pass a valid SharedPreferences file name or ContentProvider URI"

    .line 25
    .line 26
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 27
    .line 28
    .line 29
    throw p0
.end method


# virtual methods
.method public final a(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 3

    .line 1
    iget v0, p0, Lcom/google/android/gms/internal/measurement/n4;->f:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    instance-of p0, p1, Ljava/lang/String;

    .line 7
    .line 8
    if-eqz p0, :cond_0

    .line 9
    .line 10
    check-cast p1, Ljava/lang/String;

    .line 11
    .line 12
    goto :goto_0

    .line 13
    :cond_0
    const/4 p1, 0x0

    .line 14
    :goto_0
    return-object p1

    .line 15
    :pswitch_0
    instance-of v0, p1, Ljava/lang/Double;

    .line 16
    .line 17
    if-eqz v0, :cond_1

    .line 18
    .line 19
    check-cast p1, Ljava/lang/Double;

    .line 20
    .line 21
    goto :goto_1

    .line 22
    :cond_1
    instance-of v0, p1, Ljava/lang/Float;

    .line 23
    .line 24
    if-eqz v0, :cond_2

    .line 25
    .line 26
    check-cast p1, Ljava/lang/Float;

    .line 27
    .line 28
    invoke-virtual {p1}, Ljava/lang/Float;->doubleValue()D

    .line 29
    .line 30
    .line 31
    move-result-wide p0

    .line 32
    invoke-static {p0, p1}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 33
    .line 34
    .line 35
    move-result-object p1

    .line 36
    goto :goto_1

    .line 37
    :cond_2
    instance-of v0, p1, Ljava/lang/String;

    .line 38
    .line 39
    if-eqz v0, :cond_3

    .line 40
    .line 41
    :try_start_0
    move-object v0, p1

    .line 42
    check-cast v0, Ljava/lang/String;

    .line 43
    .line 44
    invoke-static {v0}, Ljava/lang/Double;->parseDouble(Ljava/lang/String;)D

    .line 45
    .line 46
    .line 47
    move-result-wide v0

    .line 48
    invoke-static {v0, v1}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 49
    .line 50
    .line 51
    move-result-object p1
    :try_end_0
    .catch Ljava/lang/NumberFormatException; {:try_start_0 .. :try_end_0} :catch_0

    .line 52
    goto :goto_1

    .line 53
    :catch_0
    :cond_3
    invoke-virtual {p1}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 54
    .line 55
    .line 56
    move-result-object p1

    .line 57
    iget-object p0, p0, Lcom/google/android/gms/internal/measurement/n4;->b:Ljava/lang/String;

    .line 58
    .line 59
    invoke-virtual {p0}, Ljava/lang/String;->length()I

    .line 60
    .line 61
    .line 62
    move-result v0

    .line 63
    add-int/lit8 v0, v0, 0x1b

    .line 64
    .line 65
    invoke-virtual {p1}, Ljava/lang/String;->length()I

    .line 66
    .line 67
    .line 68
    move-result v1

    .line 69
    new-instance v2, Ljava/lang/StringBuilder;

    .line 70
    .line 71
    add-int/2addr v0, v1

    .line 72
    invoke-direct {v2, v0}, Ljava/lang/StringBuilder;-><init>(I)V

    .line 73
    .line 74
    .line 75
    const-string v0, "Invalid double value for "

    .line 76
    .line 77
    const-string v1, ": "

    .line 78
    .line 79
    invoke-static {v2, v0, p0, v1, p1}, Lvj/b;->k(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 80
    .line 81
    .line 82
    move-result-object p0

    .line 83
    const-string p1, "PhenotypeFlag"

    .line 84
    .line 85
    invoke-static {p1, p0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I

    .line 86
    .line 87
    .line 88
    const/4 p1, 0x0

    .line 89
    :goto_1
    return-object p1

    .line 90
    :pswitch_1
    instance-of v0, p1, Ljava/lang/Boolean;

    .line 91
    .line 92
    if-eqz v0, :cond_4

    .line 93
    .line 94
    check-cast p1, Ljava/lang/Boolean;

    .line 95
    .line 96
    goto :goto_2

    .line 97
    :cond_4
    instance-of v0, p1, Ljava/lang/String;

    .line 98
    .line 99
    if-eqz v0, :cond_6

    .line 100
    .line 101
    move-object v0, p1

    .line 102
    check-cast v0, Ljava/lang/String;

    .line 103
    .line 104
    sget-object v1, Lcom/google/android/gms/internal/measurement/y3;->b:Ljava/util/regex/Pattern;

    .line 105
    .line 106
    invoke-virtual {v1, v0}, Ljava/util/regex/Pattern;->matcher(Ljava/lang/CharSequence;)Ljava/util/regex/Matcher;

    .line 107
    .line 108
    .line 109
    move-result-object v1

    .line 110
    invoke-virtual {v1}, Ljava/util/regex/Matcher;->matches()Z

    .line 111
    .line 112
    .line 113
    move-result v1

    .line 114
    if-eqz v1, :cond_5

    .line 115
    .line 116
    sget-object p1, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 117
    .line 118
    goto :goto_2

    .line 119
    :cond_5
    sget-object v1, Lcom/google/android/gms/internal/measurement/y3;->c:Ljava/util/regex/Pattern;

    .line 120
    .line 121
    invoke-virtual {v1, v0}, Ljava/util/regex/Pattern;->matcher(Ljava/lang/CharSequence;)Ljava/util/regex/Matcher;

    .line 122
    .line 123
    .line 124
    move-result-object v0

    .line 125
    invoke-virtual {v0}, Ljava/util/regex/Matcher;->matches()Z

    .line 126
    .line 127
    .line 128
    move-result v0

    .line 129
    if-eqz v0, :cond_6

    .line 130
    .line 131
    sget-object p1, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 132
    .line 133
    goto :goto_2

    .line 134
    :cond_6
    invoke-virtual {p1}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 135
    .line 136
    .line 137
    move-result-object p1

    .line 138
    iget-object p0, p0, Lcom/google/android/gms/internal/measurement/n4;->b:Ljava/lang/String;

    .line 139
    .line 140
    invoke-virtual {p0}, Ljava/lang/String;->length()I

    .line 141
    .line 142
    .line 143
    move-result v0

    .line 144
    add-int/lit8 v0, v0, 0x1c

    .line 145
    .line 146
    invoke-virtual {p1}, Ljava/lang/String;->length()I

    .line 147
    .line 148
    .line 149
    move-result v1

    .line 150
    new-instance v2, Ljava/lang/StringBuilder;

    .line 151
    .line 152
    add-int/2addr v0, v1

    .line 153
    invoke-direct {v2, v0}, Ljava/lang/StringBuilder;-><init>(I)V

    .line 154
    .line 155
    .line 156
    const-string v0, "Invalid boolean value for "

    .line 157
    .line 158
    const-string v1, ": "

    .line 159
    .line 160
    invoke-static {v2, v0, p0, v1, p1}, Lvj/b;->k(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 161
    .line 162
    .line 163
    move-result-object p0

    .line 164
    const-string p1, "PhenotypeFlag"

    .line 165
    .line 166
    invoke-static {p1, p0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I

    .line 167
    .line 168
    .line 169
    const/4 p1, 0x0

    .line 170
    :goto_2
    return-object p1

    .line 171
    :pswitch_2
    instance-of v0, p1, Ljava/lang/Long;

    .line 172
    .line 173
    if-eqz v0, :cond_7

    .line 174
    .line 175
    check-cast p1, Ljava/lang/Long;

    .line 176
    .line 177
    goto :goto_3

    .line 178
    :cond_7
    instance-of v0, p1, Ljava/lang/String;

    .line 179
    .line 180
    if-eqz v0, :cond_8

    .line 181
    .line 182
    :try_start_1
    move-object v0, p1

    .line 183
    check-cast v0, Ljava/lang/String;

    .line 184
    .line 185
    invoke-static {v0}, Ljava/lang/Long;->parseLong(Ljava/lang/String;)J

    .line 186
    .line 187
    .line 188
    move-result-wide v0

    .line 189
    invoke-static {v0, v1}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 190
    .line 191
    .line 192
    move-result-object p1
    :try_end_1
    .catch Ljava/lang/NumberFormatException; {:try_start_1 .. :try_end_1} :catch_1

    .line 193
    goto :goto_3

    .line 194
    :catch_1
    :cond_8
    invoke-virtual {p1}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 195
    .line 196
    .line 197
    move-result-object p1

    .line 198
    iget-object p0, p0, Lcom/google/android/gms/internal/measurement/n4;->b:Ljava/lang/String;

    .line 199
    .line 200
    invoke-virtual {p0}, Ljava/lang/String;->length()I

    .line 201
    .line 202
    .line 203
    move-result v0

    .line 204
    add-int/lit8 v0, v0, 0x19

    .line 205
    .line 206
    invoke-virtual {p1}, Ljava/lang/String;->length()I

    .line 207
    .line 208
    .line 209
    move-result v1

    .line 210
    new-instance v2, Ljava/lang/StringBuilder;

    .line 211
    .line 212
    add-int/2addr v0, v1

    .line 213
    invoke-direct {v2, v0}, Ljava/lang/StringBuilder;-><init>(I)V

    .line 214
    .line 215
    .line 216
    const-string v0, "Invalid long value for "

    .line 217
    .line 218
    const-string v1, ": "

    .line 219
    .line 220
    invoke-static {v2, v0, p0, v1, p1}, Lvj/b;->k(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 221
    .line 222
    .line 223
    move-result-object p0

    .line 224
    const-string p1, "PhenotypeFlag"

    .line 225
    .line 226
    invoke-static {p1, p0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I

    .line 227
    .line 228
    .line 229
    const/4 p1, 0x0

    .line 230
    :goto_3
    return-object p1

    .line 231
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final b()Ljava/lang/Object;
    .locals 9

    .line 1
    sget-object v0, Lcom/google/android/gms/internal/measurement/n4;->i:Ljava/util/concurrent/atomic/AtomicInteger;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/util/concurrent/atomic/AtomicInteger;->get()I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    iget v1, p0, Lcom/google/android/gms/internal/measurement/n4;->d:I

    .line 8
    .line 9
    if-ge v1, v0, :cond_d

    .line 10
    .line 11
    monitor-enter p0

    .line 12
    :try_start_0
    iget v1, p0, Lcom/google/android/gms/internal/measurement/n4;->d:I

    .line 13
    .line 14
    if-ge v1, v0, :cond_c

    .line 15
    .line 16
    sget-object v1, Lcom/google/android/gms/internal/measurement/n4;->h:Lcom/google/android/gms/internal/measurement/d4;

    .line 17
    .line 18
    sget-object v2, Lgr/a;->d:Lgr/a;

    .line 19
    .line 20
    const/4 v3, 0x0

    .line 21
    if-eqz v1, :cond_2

    .line 22
    .line 23
    iget-object v4, v1, Lcom/google/android/gms/internal/measurement/d4;->b:Lgr/m;

    .line 24
    .line 25
    if-eqz v4, :cond_2

    .line 26
    .line 27
    invoke-interface {v4}, Lgr/m;->get()Ljava/lang/Object;

    .line 28
    .line 29
    .line 30
    move-result-object v2

    .line 31
    check-cast v2, Lgr/g;

    .line 32
    .line 33
    invoke-virtual {v2}, Lgr/g;->b()Z

    .line 34
    .line 35
    .line 36
    move-result v4

    .line 37
    if-eqz v4, :cond_2

    .line 38
    .line 39
    invoke-virtual {v2}, Lgr/g;->a()Ljava/lang/Object;

    .line 40
    .line 41
    .line 42
    move-result-object v4

    .line 43
    check-cast v4, Lcom/google/android/gms/internal/measurement/g4;

    .line 44
    .line 45
    iget-object v5, p0, Lcom/google/android/gms/internal/measurement/n4;->a:Lb6/f;

    .line 46
    .line 47
    iget-object v5, v5, Lb6/f;->e:Ljava/lang/Object;

    .line 48
    .line 49
    check-cast v5, Landroid/net/Uri;

    .line 50
    .line 51
    iget-object v6, p0, Lcom/google/android/gms/internal/measurement/n4;->b:Ljava/lang/String;

    .line 52
    .line 53
    if-eqz v5, :cond_0

    .line 54
    .line 55
    iget-object v4, v4, Lcom/google/android/gms/internal/measurement/g4;->a:Landroidx/collection/a1;

    .line 56
    .line 57
    invoke-virtual {v5}, Landroid/net/Uri;->toString()Ljava/lang/String;

    .line 58
    .line 59
    .line 60
    move-result-object v5

    .line 61
    invoke-virtual {v4, v5}, Landroidx/collection/a1;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 62
    .line 63
    .line 64
    move-result-object v4

    .line 65
    check-cast v4, Landroidx/collection/a1;

    .line 66
    .line 67
    goto :goto_0

    .line 68
    :cond_0
    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 69
    .line 70
    .line 71
    move-object v4, v3

    .line 72
    :goto_0
    if-nez v4, :cond_1

    .line 73
    .line 74
    goto :goto_1

    .line 75
    :cond_1
    const-string v5, ""

    .line 76
    .line 77
    invoke-virtual {v5, v6}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 78
    .line 79
    .line 80
    move-result-object v5

    .line 81
    invoke-virtual {v4, v5}, Landroidx/collection/a1;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 82
    .line 83
    .line 84
    move-result-object v4

    .line 85
    check-cast v4, Ljava/lang/String;

    .line 86
    .line 87
    goto :goto_2

    .line 88
    :catchall_0
    move-exception v0

    .line 89
    goto/16 :goto_9

    .line 90
    .line 91
    :cond_2
    :goto_1
    move-object v4, v3

    .line 92
    :goto_2
    if-eqz v1, :cond_3

    .line 93
    .line 94
    const/4 v5, 0x1

    .line 95
    goto :goto_3

    .line 96
    :cond_3
    const/4 v5, 0x0

    .line 97
    :goto_3
    const-string v6, "Must call PhenotypeFlagInitializer.maybeInit() first"

    .line 98
    .line 99
    invoke-static {v6, v5}, Lkp/i9;->h(Ljava/lang/String;Z)V

    .line 100
    .line 101
    .line 102
    iget-object v5, p0, Lcom/google/android/gms/internal/measurement/n4;->a:Lb6/f;

    .line 103
    .line 104
    iget-object v6, v5, Lb6/f;->e:Ljava/lang/Object;

    .line 105
    .line 106
    check-cast v6, Landroid/net/Uri;

    .line 107
    .line 108
    if-eqz v6, :cond_b

    .line 109
    .line 110
    iget-object v7, v1, Lcom/google/android/gms/internal/measurement/d4;->a:Landroid/content/Context;

    .line 111
    .line 112
    invoke-static {v7, v6}, Lcom/google/android/gms/internal/measurement/l4;->a(Landroid/content/Context;Landroid/net/Uri;)Z

    .line 113
    .line 114
    .line 115
    move-result v7

    .line 116
    if-eqz v7, :cond_4

    .line 117
    .line 118
    iget-object v7, v1, Lcom/google/android/gms/internal/measurement/d4;->a:Landroid/content/Context;

    .line 119
    .line 120
    invoke-virtual {v7}, Landroid/content/Context;->getContentResolver()Landroid/content/ContentResolver;

    .line 121
    .line 122
    .line 123
    move-result-object v7

    .line 124
    sget-object v8, Lcom/google/android/gms/internal/measurement/o4;->d:Lcom/google/android/gms/internal/measurement/o4;

    .line 125
    .line 126
    invoke-static {v7, v6, v8}, Lcom/google/android/gms/internal/measurement/f4;->a(Landroid/content/ContentResolver;Landroid/net/Uri;Ljava/lang/Runnable;)Lcom/google/android/gms/internal/measurement/f4;

    .line 127
    .line 128
    .line 129
    move-result-object v6

    .line 130
    goto :goto_4

    .line 131
    :cond_4
    move-object v6, v3

    .line 132
    :goto_4
    if-eqz v6, :cond_5

    .line 133
    .line 134
    iget-object v7, p0, Lcom/google/android/gms/internal/measurement/n4;->b:Ljava/lang/String;

    .line 135
    .line 136
    invoke-virtual {v6}, Lcom/google/android/gms/internal/measurement/f4;->b()Ljava/util/Map;

    .line 137
    .line 138
    .line 139
    move-result-object v6

    .line 140
    invoke-interface {v6, v7}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 141
    .line 142
    .line 143
    move-result-object v6

    .line 144
    check-cast v6, Ljava/lang/String;

    .line 145
    .line 146
    if-eqz v6, :cond_5

    .line 147
    .line 148
    invoke-virtual {p0, v6}, Lcom/google/android/gms/internal/measurement/n4;->a(Ljava/lang/Object;)Ljava/lang/Object;

    .line 149
    .line 150
    .line 151
    move-result-object v6

    .line 152
    goto :goto_5

    .line 153
    :cond_5
    move-object v6, v3

    .line 154
    :goto_5
    if-eqz v6, :cond_6

    .line 155
    .line 156
    goto :goto_6

    .line 157
    :cond_6
    iget-boolean v5, v5, Lb6/f;->d:Z

    .line 158
    .line 159
    if-nez v5, :cond_7

    .line 160
    .line 161
    iget-object v1, v1, Lcom/google/android/gms/internal/measurement/d4;->a:Landroid/content/Context;

    .line 162
    .line 163
    invoke-static {v1}, Lcom/google/android/gms/internal/measurement/i4;->y(Landroid/content/Context;)Lcom/google/android/gms/internal/measurement/i4;

    .line 164
    .line 165
    .line 166
    move-result-object v1

    .line 167
    iget-object v5, p0, Lcom/google/android/gms/internal/measurement/n4;->b:Ljava/lang/String;

    .line 168
    .line 169
    invoke-virtual {v1, v5}, Lcom/google/android/gms/internal/measurement/i4;->B(Ljava/lang/String;)Ljava/lang/String;

    .line 170
    .line 171
    .line 172
    move-result-object v1

    .line 173
    if-eqz v1, :cond_7

    .line 174
    .line 175
    invoke-virtual {p0, v1}, Lcom/google/android/gms/internal/measurement/n4;->a(Ljava/lang/Object;)Ljava/lang/Object;

    .line 176
    .line 177
    .line 178
    move-result-object v3

    .line 179
    :cond_7
    if-nez v3, :cond_8

    .line 180
    .line 181
    iget-object v6, p0, Lcom/google/android/gms/internal/measurement/n4;->c:Ljava/lang/Object;

    .line 182
    .line 183
    goto :goto_6

    .line 184
    :cond_8
    move-object v6, v3

    .line 185
    :goto_6
    invoke-virtual {v2}, Lgr/g;->b()Z

    .line 186
    .line 187
    .line 188
    move-result v1

    .line 189
    if-eqz v1, :cond_a

    .line 190
    .line 191
    if-nez v4, :cond_9

    .line 192
    .line 193
    iget-object v6, p0, Lcom/google/android/gms/internal/measurement/n4;->c:Ljava/lang/Object;

    .line 194
    .line 195
    goto :goto_7

    .line 196
    :cond_9
    invoke-virtual {p0, v4}, Lcom/google/android/gms/internal/measurement/n4;->a(Ljava/lang/Object;)Ljava/lang/Object;

    .line 197
    .line 198
    .line 199
    move-result-object v6

    .line 200
    :cond_a
    :goto_7
    iput-object v6, p0, Lcom/google/android/gms/internal/measurement/n4;->e:Ljava/lang/Object;

    .line 201
    .line 202
    iput v0, p0, Lcom/google/android/gms/internal/measurement/n4;->d:I

    .line 203
    .line 204
    goto :goto_8

    .line 205
    :cond_b
    iget-object v0, v1, Lcom/google/android/gms/internal/measurement/d4;->a:Landroid/content/Context;

    .line 206
    .line 207
    throw v3

    .line 208
    :cond_c
    :goto_8
    monitor-exit p0

    .line 209
    goto :goto_a

    .line 210
    :goto_9
    monitor-exit p0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 211
    throw v0

    .line 212
    :cond_d
    :goto_a
    iget-object p0, p0, Lcom/google/android/gms/internal/measurement/n4;->e:Ljava/lang/Object;

    .line 213
    .line 214
    return-object p0
.end method
