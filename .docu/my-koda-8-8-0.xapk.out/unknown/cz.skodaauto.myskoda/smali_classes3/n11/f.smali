.class public abstract Ln11/f;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/io/Serializable;


# static fields
.field public static final e:Ln11/n;

.field public static final f:Ljava/util/concurrent/atomic/AtomicReference;

.field public static final g:Ljava/util/concurrent/atomic/AtomicReference;

.field public static final h:Ljava/util/concurrent/atomic/AtomicReference;


# instance fields
.field public final d:Ljava/lang/String;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    sget-object v0, Ln11/n;->i:Ln11/n;

    .line 2
    .line 3
    sput-object v0, Ln11/f;->e:Ln11/n;

    .line 4
    .line 5
    new-instance v0, Ljava/util/concurrent/atomic/AtomicReference;

    .line 6
    .line 7
    invoke-direct {v0}, Ljava/util/concurrent/atomic/AtomicReference;-><init>()V

    .line 8
    .line 9
    .line 10
    sput-object v0, Ln11/f;->f:Ljava/util/concurrent/atomic/AtomicReference;

    .line 11
    .line 12
    new-instance v0, Ljava/util/concurrent/atomic/AtomicReference;

    .line 13
    .line 14
    invoke-direct {v0}, Ljava/util/concurrent/atomic/AtomicReference;-><init>()V

    .line 15
    .line 16
    .line 17
    sput-object v0, Ln11/f;->g:Ljava/util/concurrent/atomic/AtomicReference;

    .line 18
    .line 19
    new-instance v0, Ljava/util/concurrent/atomic/AtomicReference;

    .line 20
    .line 21
    invoke-direct {v0}, Ljava/util/concurrent/atomic/AtomicReference;-><init>()V

    .line 22
    .line 23
    .line 24
    sput-object v0, Ln11/f;->h:Ljava/util/concurrent/atomic/AtomicReference;

    .line 25
    .line 26
    return-void
.end method

.method public constructor <init>(Ljava/lang/String;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    if-eqz p1, :cond_0

    .line 5
    .line 6
    iput-object p1, p0, Ln11/f;->d:Ljava/lang/String;

    .line 7
    .line 8
    return-void

    .line 9
    :cond_0
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 10
    .line 11
    const-string p1, "Id must not be null"

    .line 12
    .line 13
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    throw p0
.end method

.method public static c(Ljava/lang/String;)Ln11/f;
    .locals 4

    .line 1
    if-nez p0, :cond_0

    .line 2
    .line 3
    invoke-static {}, Ln11/f;->e()Ln11/f;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0

    .line 8
    :cond_0
    const-string v0, "UTC"

    .line 9
    .line 10
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 11
    .line 12
    .line 13
    move-result v0

    .line 14
    if-eqz v0, :cond_1

    .line 15
    .line 16
    goto :goto_1

    .line 17
    :cond_1
    invoke-static {}, Ln11/f;->k()Ls11/h;

    .line 18
    .line 19
    .line 20
    move-result-object v0

    .line 21
    invoke-interface {v0, p0}, Ls11/h;->a(Ljava/lang/String;)Ln11/f;

    .line 22
    .line 23
    .line 24
    move-result-object v0

    .line 25
    if-eqz v0, :cond_2

    .line 26
    .line 27
    return-object v0

    .line 28
    :cond_2
    const-string v0, "+"

    .line 29
    .line 30
    invoke-virtual {p0, v0}, Ljava/lang/String;->startsWith(Ljava/lang/String;)Z

    .line 31
    .line 32
    .line 33
    move-result v0

    .line 34
    if-nez v0, :cond_4

    .line 35
    .line 36
    const-string v0, "-"

    .line 37
    .line 38
    invoke-virtual {p0, v0}, Ljava/lang/String;->startsWith(Ljava/lang/String;)Z

    .line 39
    .line 40
    .line 41
    move-result v0

    .line 42
    if-eqz v0, :cond_3

    .line 43
    .line 44
    goto :goto_0

    .line 45
    :cond_3
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 46
    .line 47
    const-string v1, "The datetime zone id \'"

    .line 48
    .line 49
    const-string v2, "\' is not recognised"

    .line 50
    .line 51
    invoke-static {v1, p0, v2}, Lp3/m;->j(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 52
    .line 53
    .line 54
    move-result-object p0

    .line 55
    invoke-direct {v0, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 56
    .line 57
    .line 58
    throw v0

    .line 59
    :cond_4
    :goto_0
    invoke-static {p0}, Ln11/f;->o(Ljava/lang/String;)I

    .line 60
    .line 61
    .line 62
    move-result p0

    .line 63
    int-to-long v0, p0

    .line 64
    const-wide/16 v2, 0x0

    .line 65
    .line 66
    cmp-long v0, v0, v2

    .line 67
    .line 68
    if-nez v0, :cond_5

    .line 69
    .line 70
    goto :goto_1

    .line 71
    :cond_5
    invoke-static {p0}, Ln11/f;->q(I)Ljava/lang/String;

    .line 72
    .line 73
    .line 74
    move-result-object v0

    .line 75
    if-nez p0, :cond_6

    .line 76
    .line 77
    :goto_1
    sget-object p0, Ln11/f;->e:Ln11/n;

    .line 78
    .line 79
    return-object p0

    .line 80
    :cond_6
    new-instance v1, Ls11/g;

    .line 81
    .line 82
    const/4 v2, 0x0

    .line 83
    invoke-direct {v1, v0, v2, p0, p0}, Ls11/g;-><init>(Ljava/lang/String;Ljava/lang/String;II)V

    .line 84
    .line 85
    .line 86
    return-object v1
.end method

.method public static d(Ljava/util/TimeZone;)Ln11/f;
    .locals 8

    .line 1
    if-nez p0, :cond_0

    .line 2
    .line 3
    invoke-static {}, Ln11/f;->e()Ln11/f;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0

    .line 8
    :cond_0
    invoke-virtual {p0}, Ljava/util/TimeZone;->getID()Ljava/lang/String;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    if-eqz p0, :cond_c

    .line 13
    .line 14
    const-string v0, "UTC"

    .line 15
    .line 16
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 17
    .line 18
    .line 19
    move-result v0

    .line 20
    sget-object v1, Ln11/f;->e:Ln11/n;

    .line 21
    .line 22
    if-eqz v0, :cond_1

    .line 23
    .line 24
    goto/16 :goto_2

    .line 25
    .line 26
    :cond_1
    sget-object v0, Ln11/e;->a:Ljava/util/Map;

    .line 27
    .line 28
    invoke-interface {v0, p0}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 29
    .line 30
    .line 31
    move-result-object v0

    .line 32
    check-cast v0, Ljava/lang/String;

    .line 33
    .line 34
    invoke-static {}, Ln11/f;->k()Ls11/h;

    .line 35
    .line 36
    .line 37
    move-result-object v2

    .line 38
    const/4 v3, 0x0

    .line 39
    if-eqz v0, :cond_2

    .line 40
    .line 41
    invoke-interface {v2, v0}, Ls11/h;->a(Ljava/lang/String;)Ln11/f;

    .line 42
    .line 43
    .line 44
    move-result-object v4

    .line 45
    goto :goto_0

    .line 46
    :cond_2
    move-object v4, v3

    .line 47
    :goto_0
    if-nez v4, :cond_3

    .line 48
    .line 49
    invoke-interface {v2, p0}, Ls11/h;->a(Ljava/lang/String;)Ln11/f;

    .line 50
    .line 51
    .line 52
    move-result-object v4

    .line 53
    :cond_3
    if-eqz v4, :cond_4

    .line 54
    .line 55
    return-object v4

    .line 56
    :cond_4
    if-nez v0, :cond_b

    .line 57
    .line 58
    const-string v0, "GMT+"

    .line 59
    .line 60
    invoke-virtual {p0, v0}, Ljava/lang/String;->startsWith(Ljava/lang/String;)Z

    .line 61
    .line 62
    .line 63
    move-result v0

    .line 64
    if-nez v0, :cond_5

    .line 65
    .line 66
    const-string v0, "GMT-"

    .line 67
    .line 68
    invoke-virtual {p0, v0}, Ljava/lang/String;->startsWith(Ljava/lang/String;)Z

    .line 69
    .line 70
    .line 71
    move-result v0

    .line 72
    if-eqz v0, :cond_b

    .line 73
    .line 74
    :cond_5
    const/4 v0, 0x3

    .line 75
    invoke-virtual {p0, v0}, Ljava/lang/String;->substring(I)Ljava/lang/String;

    .line 76
    .line 77
    .line 78
    move-result-object p0

    .line 79
    invoke-virtual {p0}, Ljava/lang/String;->length()I

    .line 80
    .line 81
    .line 82
    move-result v0

    .line 83
    const/4 v2, 0x2

    .line 84
    if-le v0, v2, :cond_8

    .line 85
    .line 86
    const/4 v0, 0x1

    .line 87
    invoke-virtual {p0, v0}, Ljava/lang/String;->charAt(I)C

    .line 88
    .line 89
    .line 90
    move-result v0

    .line 91
    const/16 v2, 0x39

    .line 92
    .line 93
    if-le v0, v2, :cond_8

    .line 94
    .line 95
    invoke-static {v0}, Ljava/lang/Character;->isDigit(C)Z

    .line 96
    .line 97
    .line 98
    move-result v0

    .line 99
    if-eqz v0, :cond_8

    .line 100
    .line 101
    new-instance v0, Ljava/lang/StringBuilder;

    .line 102
    .line 103
    invoke-direct {v0, p0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 104
    .line 105
    .line 106
    const/4 p0, 0x0

    .line 107
    :goto_1
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->length()I

    .line 108
    .line 109
    .line 110
    move-result v2

    .line 111
    if-ge p0, v2, :cond_7

    .line 112
    .line 113
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->charAt(I)C

    .line 114
    .line 115
    .line 116
    move-result v2

    .line 117
    const/16 v4, 0xa

    .line 118
    .line 119
    invoke-static {v2, v4}, Ljava/lang/Character;->digit(CI)I

    .line 120
    .line 121
    .line 122
    move-result v2

    .line 123
    if-ltz v2, :cond_6

    .line 124
    .line 125
    add-int/lit8 v2, v2, 0x30

    .line 126
    .line 127
    int-to-char v2, v2

    .line 128
    invoke-virtual {v0, p0, v2}, Ljava/lang/StringBuilder;->setCharAt(IC)V

    .line 129
    .line 130
    .line 131
    :cond_6
    add-int/lit8 p0, p0, 0x1

    .line 132
    .line 133
    goto :goto_1

    .line 134
    :cond_7
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 135
    .line 136
    .line 137
    move-result-object p0

    .line 138
    :cond_8
    invoke-static {p0}, Ln11/f;->o(Ljava/lang/String;)I

    .line 139
    .line 140
    .line 141
    move-result p0

    .line 142
    int-to-long v4, p0

    .line 143
    const-wide/16 v6, 0x0

    .line 144
    .line 145
    cmp-long v0, v4, v6

    .line 146
    .line 147
    if-nez v0, :cond_9

    .line 148
    .line 149
    :goto_2
    return-object v1

    .line 150
    :cond_9
    invoke-static {p0}, Ln11/f;->q(I)Ljava/lang/String;

    .line 151
    .line 152
    .line 153
    move-result-object v0

    .line 154
    if-nez p0, :cond_a

    .line 155
    .line 156
    return-object v1

    .line 157
    :cond_a
    new-instance v1, Ls11/g;

    .line 158
    .line 159
    invoke-direct {v1, v0, v3, p0, p0}, Ls11/g;-><init>(Ljava/lang/String;Ljava/lang/String;II)V

    .line 160
    .line 161
    .line 162
    return-object v1

    .line 163
    :cond_b
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 164
    .line 165
    const-string v1, "The datetime zone id \'"

    .line 166
    .line 167
    const-string v2, "\' is not recognised"

    .line 168
    .line 169
    invoke-static {v1, p0, v2}, Lp3/m;->j(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 170
    .line 171
    .line 172
    move-result-object p0

    .line 173
    invoke-direct {v0, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 174
    .line 175
    .line 176
    throw v0

    .line 177
    :cond_c
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 178
    .line 179
    const-string v0, "The TimeZone id must not be null"

    .line 180
    .line 181
    invoke-direct {p0, v0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 182
    .line 183
    .line 184
    throw p0
.end method

.method public static e()Ln11/f;
    .locals 3

    .line 1
    sget-object v0, Ln11/f;->h:Ljava/util/concurrent/atomic/AtomicReference;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/util/concurrent/atomic/AtomicReference;->get()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v1

    .line 7
    check-cast v1, Ln11/f;

    .line 8
    .line 9
    if-nez v1, :cond_5

    .line 10
    .line 11
    :try_start_0
    const-string v2, "user.timezone"

    .line 12
    .line 13
    invoke-static {v2}, Ljava/lang/System;->getProperty(Ljava/lang/String;)Ljava/lang/String;

    .line 14
    .line 15
    .line 16
    move-result-object v2

    .line 17
    if-eqz v2, :cond_0

    .line 18
    .line 19
    invoke-static {v2}, Ln11/f;->c(Ljava/lang/String;)Ln11/f;

    .line 20
    .line 21
    .line 22
    move-result-object v1
    :try_end_0
    .catch Ljava/lang/RuntimeException; {:try_start_0 .. :try_end_0} :catch_0

    .line 23
    :catch_0
    :cond_0
    if-nez v1, :cond_1

    .line 24
    .line 25
    :try_start_1
    invoke-static {}, Ljava/util/TimeZone;->getDefault()Ljava/util/TimeZone;

    .line 26
    .line 27
    .line 28
    move-result-object v2

    .line 29
    invoke-static {v2}, Ln11/f;->d(Ljava/util/TimeZone;)Ln11/f;

    .line 30
    .line 31
    .line 32
    move-result-object v1
    :try_end_1
    .catch Ljava/lang/IllegalArgumentException; {:try_start_1 .. :try_end_1} :catch_1

    .line 33
    :catch_1
    :cond_1
    if-nez v1, :cond_2

    .line 34
    .line 35
    sget-object v1, Ln11/f;->e:Ln11/n;

    .line 36
    .line 37
    :cond_2
    move-object v2, v1

    .line 38
    :cond_3
    const/4 v1, 0x0

    .line 39
    invoke-virtual {v0, v1, v2}, Ljava/util/concurrent/atomic/AtomicReference;->compareAndSet(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 40
    .line 41
    .line 42
    move-result v1

    .line 43
    if-eqz v1, :cond_4

    .line 44
    .line 45
    goto :goto_0

    .line 46
    :cond_4
    invoke-virtual {v0}, Ljava/util/concurrent/atomic/AtomicReference;->get()Ljava/lang/Object;

    .line 47
    .line 48
    .line 49
    move-result-object v1

    .line 50
    if-eqz v1, :cond_3

    .line 51
    .line 52
    invoke-virtual {v0}, Ljava/util/concurrent/atomic/AtomicReference;->get()Ljava/lang/Object;

    .line 53
    .line 54
    .line 55
    move-result-object v0

    .line 56
    move-object v2, v0

    .line 57
    check-cast v2, Ln11/f;

    .line 58
    .line 59
    :goto_0
    return-object v2

    .line 60
    :cond_5
    return-object v1
.end method

.method public static h()Ls11/f;
    .locals 4

    .line 1
    sget-object v0, Ln11/f;->g:Ljava/util/concurrent/atomic/AtomicReference;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/util/concurrent/atomic/AtomicReference;->get()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v1

    .line 7
    check-cast v1, Ls11/f;

    .line 8
    .line 9
    if-nez v1, :cond_4

    .line 10
    .line 11
    const/4 v2, 0x0

    .line 12
    :try_start_0
    const-string v1, "org.joda.time.DateTimeZone.NameProvider"

    .line 13
    .line 14
    invoke-static {v1}, Ljava/lang/System;->getProperty(Ljava/lang/String;)Ljava/lang/String;

    .line 15
    .line 16
    .line 17
    move-result-object v1
    :try_end_0
    .catch Ljava/lang/SecurityException; {:try_start_0 .. :try_end_0} :catch_1

    .line 18
    if-eqz v1, :cond_0

    .line 19
    .line 20
    :try_start_1
    invoke-static {v1}, Ljava/lang/Class;->forName(Ljava/lang/String;)Ljava/lang/Class;

    .line 21
    .line 22
    .line 23
    move-result-object v1

    .line 24
    invoke-virtual {v1}, Ljava/lang/Class;->newInstance()Ljava/lang/Object;

    .line 25
    .line 26
    .line 27
    move-result-object v1

    .line 28
    check-cast v1, Ls11/f;
    :try_end_1
    .catch Ljava/lang/Exception; {:try_start_1 .. :try_end_1} :catch_0

    .line 29
    .line 30
    goto :goto_0

    .line 31
    :catch_0
    move-exception v1

    .line 32
    :try_start_2
    new-instance v3, Ljava/lang/RuntimeException;

    .line 33
    .line 34
    invoke-direct {v3, v1}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/Throwable;)V

    .line 35
    .line 36
    .line 37
    throw v3
    :try_end_2
    .catch Ljava/lang/SecurityException; {:try_start_2 .. :try_end_2} :catch_1

    .line 38
    :catch_1
    :cond_0
    move-object v1, v2

    .line 39
    :goto_0
    if-nez v1, :cond_1

    .line 40
    .line 41
    new-instance v1, Ls11/f;

    .line 42
    .line 43
    invoke-direct {v1}, Ljava/lang/Object;-><init>()V

    .line 44
    .line 45
    .line 46
    invoke-static {}, Ls11/f;->a()Ljava/util/HashMap;

    .line 47
    .line 48
    .line 49
    move-result-object v3

    .line 50
    iput-object v3, v1, Ls11/f;->a:Ljava/util/HashMap;

    .line 51
    .line 52
    invoke-static {}, Ls11/f;->a()Ljava/util/HashMap;

    .line 53
    .line 54
    .line 55
    move-result-object v3

    .line 56
    iput-object v3, v1, Ls11/f;->b:Ljava/util/HashMap;

    .line 57
    .line 58
    :cond_1
    move-object v3, v1

    .line 59
    :cond_2
    invoke-virtual {v0, v2, v3}, Ljava/util/concurrent/atomic/AtomicReference;->compareAndSet(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 60
    .line 61
    .line 62
    move-result v1

    .line 63
    if-eqz v1, :cond_3

    .line 64
    .line 65
    goto :goto_1

    .line 66
    :cond_3
    invoke-virtual {v0}, Ljava/util/concurrent/atomic/AtomicReference;->get()Ljava/lang/Object;

    .line 67
    .line 68
    .line 69
    move-result-object v1

    .line 70
    if-eqz v1, :cond_2

    .line 71
    .line 72
    invoke-virtual {v0}, Ljava/util/concurrent/atomic/AtomicReference;->get()Ljava/lang/Object;

    .line 73
    .line 74
    .line 75
    move-result-object v0

    .line 76
    move-object v3, v0

    .line 77
    check-cast v3, Ls11/f;

    .line 78
    .line 79
    :goto_1
    return-object v3

    .line 80
    :cond_4
    return-object v1
.end method

.method public static k()Ls11/h;
    .locals 4

    .line 1
    sget-object v0, Ln11/f;->f:Ljava/util/concurrent/atomic/AtomicReference;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/util/concurrent/atomic/AtomicReference;->get()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v1

    .line 7
    check-cast v1, Ls11/h;

    .line 8
    .line 9
    if-nez v1, :cond_4

    .line 10
    .line 11
    :try_start_0
    const-string v1, "org.joda.time.DateTimeZone.Provider"

    .line 12
    .line 13
    invoke-static {v1}, Ljava/lang/System;->getProperty(Ljava/lang/String;)Ljava/lang/String;

    .line 14
    .line 15
    .line 16
    move-result-object v1
    :try_end_0
    .catch Ljava/lang/SecurityException; {:try_start_0 .. :try_end_0} :catch_1

    .line 17
    if-eqz v1, :cond_0

    .line 18
    .line 19
    :try_start_1
    invoke-static {v1}, Ljava/lang/Class;->forName(Ljava/lang/String;)Ljava/lang/Class;

    .line 20
    .line 21
    .line 22
    move-result-object v1

    .line 23
    invoke-virtual {v1}, Ljava/lang/Class;->newInstance()Ljava/lang/Object;

    .line 24
    .line 25
    .line 26
    move-result-object v1

    .line 27
    check-cast v1, Ls11/h;

    .line 28
    .line 29
    invoke-static {v1}, Ln11/f;->r(Ls11/h;)V
    :try_end_1
    .catch Ljava/lang/Exception; {:try_start_1 .. :try_end_1} :catch_0

    .line 30
    .line 31
    .line 32
    :goto_0
    move-object v2, v1

    .line 33
    goto :goto_1

    .line 34
    :catch_0
    move-exception v1

    .line 35
    :try_start_2
    new-instance v2, Ljava/lang/RuntimeException;

    .line 36
    .line 37
    invoke-direct {v2, v1}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/Throwable;)V

    .line 38
    .line 39
    .line 40
    throw v2
    :try_end_2
    .catch Ljava/lang/SecurityException; {:try_start_2 .. :try_end_2} :catch_1

    .line 41
    :catch_1
    :cond_0
    :try_start_3
    const-string v1, "org.joda.time.DateTimeZone.Folder"

    .line 42
    .line 43
    invoke-static {v1}, Ljava/lang/System;->getProperty(Ljava/lang/String;)Ljava/lang/String;

    .line 44
    .line 45
    .line 46
    move-result-object v1
    :try_end_3
    .catch Ljava/lang/SecurityException; {:try_start_3 .. :try_end_3} :catch_3

    .line 47
    if-eqz v1, :cond_1

    .line 48
    .line 49
    :try_start_4
    new-instance v2, Ls11/k;

    .line 50
    .line 51
    new-instance v3, Ljava/io/File;

    .line 52
    .line 53
    invoke-direct {v3, v1}, Ljava/io/File;-><init>(Ljava/lang/String;)V

    .line 54
    .line 55
    .line 56
    invoke-direct {v2, v3}, Ls11/k;-><init>(Ljava/io/File;)V

    .line 57
    .line 58
    .line 59
    invoke-static {v2}, Ln11/f;->r(Ls11/h;)V
    :try_end_4
    .catch Ljava/lang/Exception; {:try_start_4 .. :try_end_4} :catch_2

    .line 60
    .line 61
    .line 62
    goto :goto_1

    .line 63
    :catch_2
    move-exception v1

    .line 64
    :try_start_5
    new-instance v2, Ljava/lang/RuntimeException;

    .line 65
    .line 66
    invoke-direct {v2, v1}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/Throwable;)V

    .line 67
    .line 68
    .line 69
    throw v2
    :try_end_5
    .catch Ljava/lang/SecurityException; {:try_start_5 .. :try_end_5} :catch_3

    .line 70
    :catch_3
    :cond_1
    :try_start_6
    new-instance v1, Ls11/k;

    .line 71
    .line 72
    invoke-direct {v1}, Ls11/k;-><init>()V

    .line 73
    .line 74
    .line 75
    invoke-static {v1}, Ln11/f;->r(Ls11/h;)V
    :try_end_6
    .catch Ljava/lang/Exception; {:try_start_6 .. :try_end_6} :catch_4

    .line 76
    .line 77
    .line 78
    goto :goto_0

    .line 79
    :catch_4
    move-exception v1

    .line 80
    invoke-virtual {v1}, Ljava/lang/Throwable;->printStackTrace()V

    .line 81
    .line 82
    .line 83
    new-instance v1, Ls11/i;

    .line 84
    .line 85
    invoke-direct {v1}, Ljava/lang/Object;-><init>()V

    .line 86
    .line 87
    .line 88
    goto :goto_0

    .line 89
    :cond_2
    :goto_1
    const/4 v1, 0x0

    .line 90
    invoke-virtual {v0, v1, v2}, Ljava/util/concurrent/atomic/AtomicReference;->compareAndSet(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 91
    .line 92
    .line 93
    move-result v1

    .line 94
    if-eqz v1, :cond_3

    .line 95
    .line 96
    goto :goto_2

    .line 97
    :cond_3
    invoke-virtual {v0}, Ljava/util/concurrent/atomic/AtomicReference;->get()Ljava/lang/Object;

    .line 98
    .line 99
    .line 100
    move-result-object v1

    .line 101
    if-eqz v1, :cond_2

    .line 102
    .line 103
    invoke-virtual {v0}, Ljava/util/concurrent/atomic/AtomicReference;->get()Ljava/lang/Object;

    .line 104
    .line 105
    .line 106
    move-result-object v0

    .line 107
    move-object v2, v0

    .line 108
    check-cast v2, Ls11/h;

    .line 109
    .line 110
    :goto_2
    return-object v2

    .line 111
    :cond_4
    return-object v1
.end method

.method public static o(Ljava/lang/String;)I
    .locals 3

    .line 1
    sget-object v0, Ln11/e;->b:Lr11/b;

    .line 2
    .line 3
    iget-object v1, v0, Lr11/b;->b:Lr11/w;

    .line 4
    .line 5
    if-eqz v1, :cond_2

    .line 6
    .line 7
    iget-object v2, v0, Lr11/b;->c:Ljp/u1;

    .line 8
    .line 9
    invoke-virtual {v0, v2}, Lr11/b;->d(Ljp/u1;)Ljp/u1;

    .line 10
    .line 11
    .line 12
    move-result-object v0

    .line 13
    new-instance v2, Lr11/s;

    .line 14
    .line 15
    invoke-direct {v2, v0}, Lr11/s;-><init>(Ljp/u1;)V

    .line 16
    .line 17
    .line 18
    const/4 v0, 0x0

    .line 19
    invoke-interface {v1, v2, p0, v0}, Lr11/w;->d(Lr11/s;Ljava/lang/CharSequence;I)I

    .line 20
    .line 21
    .line 22
    move-result v0

    .line 23
    if-ltz v0, :cond_0

    .line 24
    .line 25
    invoke-virtual {p0}, Ljava/lang/String;->length()I

    .line 26
    .line 27
    .line 28
    move-result v1

    .line 29
    if-lt v0, v1, :cond_1

    .line 30
    .line 31
    invoke-virtual {v2, p0}, Lr11/s;->b(Ljava/lang/CharSequence;)J

    .line 32
    .line 33
    .line 34
    move-result-wide v0

    .line 35
    long-to-int p0, v0

    .line 36
    neg-int p0, p0

    .line 37
    return p0

    .line 38
    :cond_0
    not-int v0, v0

    .line 39
    :cond_1
    new-instance v1, Ljava/lang/IllegalArgumentException;

    .line 40
    .line 41
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 42
    .line 43
    .line 44
    move-result-object p0

    .line 45
    invoke-static {v0, p0}, Lr11/u;->c(ILjava/lang/String;)Ljava/lang/String;

    .line 46
    .line 47
    .line 48
    move-result-object p0

    .line 49
    invoke-direct {v1, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 50
    .line 51
    .line 52
    throw v1

    .line 53
    :cond_2
    new-instance p0, Ljava/lang/UnsupportedOperationException;

    .line 54
    .line 55
    const-string v0, "Parsing not supported"

    .line 56
    .line 57
    invoke-direct {p0, v0}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    .line 58
    .line 59
    .line 60
    throw p0
.end method

.method public static q(I)Ljava/lang/String;
    .locals 5

    .line 1
    new-instance v0, Ljava/lang/StringBuffer;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/StringBuffer;-><init>()V

    .line 4
    .line 5
    .line 6
    if-ltz p0, :cond_0

    .line 7
    .line 8
    const/16 v1, 0x2b

    .line 9
    .line 10
    invoke-virtual {v0, v1}, Ljava/lang/StringBuffer;->append(C)Ljava/lang/StringBuffer;

    .line 11
    .line 12
    .line 13
    goto :goto_0

    .line 14
    :cond_0
    const/16 v1, 0x2d

    .line 15
    .line 16
    invoke-virtual {v0, v1}, Ljava/lang/StringBuffer;->append(C)Ljava/lang/StringBuffer;

    .line 17
    .line 18
    .line 19
    neg-int p0, p0

    .line 20
    :goto_0
    const v1, 0x36ee80

    .line 21
    .line 22
    .line 23
    div-int v2, p0, v1

    .line 24
    .line 25
    const/4 v3, 0x2

    .line 26
    :try_start_0
    invoke-static {v0, v2, v3}, Lr11/u;->a(Ljava/lang/Appendable;II)V
    :try_end_0
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_0

    .line 27
    .line 28
    .line 29
    :catch_0
    mul-int/2addr v2, v1

    .line 30
    sub-int/2addr p0, v2

    .line 31
    const v1, 0xea60

    .line 32
    .line 33
    .line 34
    div-int v2, p0, v1

    .line 35
    .line 36
    const/16 v4, 0x3a

    .line 37
    .line 38
    invoke-virtual {v0, v4}, Ljava/lang/StringBuffer;->append(C)Ljava/lang/StringBuffer;

    .line 39
    .line 40
    .line 41
    :try_start_1
    invoke-static {v0, v2, v3}, Lr11/u;->a(Ljava/lang/Appendable;II)V
    :try_end_1
    .catch Ljava/io/IOException; {:try_start_1 .. :try_end_1} :catch_1

    .line 42
    .line 43
    .line 44
    :catch_1
    mul-int/2addr v2, v1

    .line 45
    sub-int/2addr p0, v2

    .line 46
    if-nez p0, :cond_1

    .line 47
    .line 48
    invoke-virtual {v0}, Ljava/lang/StringBuffer;->toString()Ljava/lang/String;

    .line 49
    .line 50
    .line 51
    move-result-object p0

    .line 52
    return-object p0

    .line 53
    :cond_1
    div-int/lit16 v1, p0, 0x3e8

    .line 54
    .line 55
    invoke-virtual {v0, v4}, Ljava/lang/StringBuffer;->append(C)Ljava/lang/StringBuffer;

    .line 56
    .line 57
    .line 58
    :try_start_2
    invoke-static {v0, v1, v3}, Lr11/u;->a(Ljava/lang/Appendable;II)V
    :try_end_2
    .catch Ljava/io/IOException; {:try_start_2 .. :try_end_2} :catch_2

    .line 59
    .line 60
    .line 61
    :catch_2
    mul-int/lit16 v1, v1, 0x3e8

    .line 62
    .line 63
    sub-int/2addr p0, v1

    .line 64
    if-nez p0, :cond_2

    .line 65
    .line 66
    invoke-virtual {v0}, Ljava/lang/StringBuffer;->toString()Ljava/lang/String;

    .line 67
    .line 68
    .line 69
    move-result-object p0

    .line 70
    return-object p0

    .line 71
    :cond_2
    const/16 v1, 0x2e

    .line 72
    .line 73
    invoke-virtual {v0, v1}, Ljava/lang/StringBuffer;->append(C)Ljava/lang/StringBuffer;

    .line 74
    .line 75
    .line 76
    const/4 v1, 0x3

    .line 77
    :try_start_3
    invoke-static {v0, p0, v1}, Lr11/u;->a(Ljava/lang/Appendable;II)V
    :try_end_3
    .catch Ljava/io/IOException; {:try_start_3 .. :try_end_3} :catch_3

    .line 78
    .line 79
    .line 80
    :catch_3
    invoke-virtual {v0}, Ljava/lang/StringBuffer;->toString()Ljava/lang/String;

    .line 81
    .line 82
    .line 83
    move-result-object p0

    .line 84
    return-object p0
.end method

.method public static r(Ls11/h;)V
    .locals 2

    .line 1
    invoke-interface {p0}, Ls11/h;->b()Ljava/util/Set;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    if-eqz v0, :cond_2

    .line 6
    .line 7
    invoke-interface {v0}, Ljava/util/Set;->size()I

    .line 8
    .line 9
    .line 10
    move-result v1

    .line 11
    if-eqz v1, :cond_2

    .line 12
    .line 13
    const-string v1, "UTC"

    .line 14
    .line 15
    invoke-interface {v0, v1}, Ljava/util/Set;->contains(Ljava/lang/Object;)Z

    .line 16
    .line 17
    .line 18
    move-result v0

    .line 19
    if-eqz v0, :cond_1

    .line 20
    .line 21
    invoke-interface {p0, v1}, Ls11/h;->a(Ljava/lang/String;)Ln11/f;

    .line 22
    .line 23
    .line 24
    move-result-object p0

    .line 25
    sget-object v0, Ln11/f;->e:Ln11/n;

    .line 26
    .line 27
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 28
    .line 29
    .line 30
    instance-of p0, p0, Ln11/n;

    .line 31
    .line 32
    if-eqz p0, :cond_0

    .line 33
    .line 34
    return-void

    .line 35
    :cond_0
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 36
    .line 37
    const-string v0, "Invalid UTC zone provided"

    .line 38
    .line 39
    invoke-direct {p0, v0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 40
    .line 41
    .line 42
    throw p0

    .line 43
    :cond_1
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 44
    .line 45
    const-string v0, "The provider doesn\'t support UTC"

    .line 46
    .line 47
    invoke-direct {p0, v0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 48
    .line 49
    .line 50
    throw p0

    .line 51
    :cond_2
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 52
    .line 53
    const-string v0, "The provider doesn\'t have any available ids"

    .line 54
    .line 55
    invoke-direct {p0, v0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 56
    .line 57
    .line 58
    throw p0
.end method


# virtual methods
.method public final a(JJ)J
    .locals 8

    .line 1
    invoke-virtual {p0, p3, p4}, Ln11/f;->i(J)I

    .line 2
    .line 3
    .line 4
    move-result p3

    .line 5
    int-to-long v0, p3

    .line 6
    sub-long v0, p1, v0

    .line 7
    .line 8
    invoke-virtual {p0, v0, v1}, Ln11/f;->i(J)I

    .line 9
    .line 10
    .line 11
    move-result p4

    .line 12
    if-ne p4, p3, :cond_0

    .line 13
    .line 14
    return-wide v0

    .line 15
    :cond_0
    invoke-virtual {p0, p1, p2}, Ln11/f;->i(J)I

    .line 16
    .line 17
    .line 18
    move-result p3

    .line 19
    int-to-long v0, p3

    .line 20
    sub-long v0, p1, v0

    .line 21
    .line 22
    invoke-virtual {p0, v0, v1}, Ln11/f;->i(J)I

    .line 23
    .line 24
    .line 25
    move-result p4

    .line 26
    if-eq p3, p4, :cond_3

    .line 27
    .line 28
    if-gez p3, :cond_3

    .line 29
    .line 30
    invoke-virtual {p0, v0, v1}, Ln11/f;->n(J)J

    .line 31
    .line 32
    .line 33
    move-result-wide v2

    .line 34
    cmp-long v0, v2, v0

    .line 35
    .line 36
    const-wide v4, 0x7fffffffffffffffL

    .line 37
    .line 38
    .line 39
    .line 40
    .line 41
    if-nez v0, :cond_1

    .line 42
    .line 43
    move-wide v2, v4

    .line 44
    :cond_1
    int-to-long v0, p4

    .line 45
    sub-long v0, p1, v0

    .line 46
    .line 47
    invoke-virtual {p0, v0, v1}, Ln11/f;->n(J)J

    .line 48
    .line 49
    .line 50
    move-result-wide v6

    .line 51
    cmp-long p0, v6, v0

    .line 52
    .line 53
    if-nez p0, :cond_2

    .line 54
    .line 55
    goto :goto_0

    .line 56
    :cond_2
    move-wide v4, v6

    .line 57
    :goto_0
    cmp-long p0, v2, v4

    .line 58
    .line 59
    if-eqz p0, :cond_3

    .line 60
    .line 61
    goto :goto_1

    .line 62
    :cond_3
    move p3, p4

    .line 63
    :goto_1
    int-to-long p3, p3

    .line 64
    sub-long v0, p1, p3

    .line 65
    .line 66
    xor-long v2, p1, v0

    .line 67
    .line 68
    const-wide/16 v4, 0x0

    .line 69
    .line 70
    cmp-long p0, v2, v4

    .line 71
    .line 72
    if-gez p0, :cond_5

    .line 73
    .line 74
    xor-long p0, p1, p3

    .line 75
    .line 76
    cmp-long p0, p0, v4

    .line 77
    .line 78
    if-ltz p0, :cond_4

    .line 79
    .line 80
    goto :goto_2

    .line 81
    :cond_4
    new-instance p0, Ljava/lang/ArithmeticException;

    .line 82
    .line 83
    const-string p1, "Subtracting time zone offset caused overflow"

    .line 84
    .line 85
    invoke-direct {p0, p1}, Ljava/lang/ArithmeticException;-><init>(Ljava/lang/String;)V

    .line 86
    .line 87
    .line 88
    throw p0

    .line 89
    :cond_5
    :goto_2
    return-wide v0
.end method

.method public final b(J)J
    .locals 8

    .line 1
    invoke-virtual {p0, p1, p2}, Ln11/f;->i(J)I

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    int-to-long v0, p0

    .line 6
    add-long v2, p1, v0

    .line 7
    .line 8
    xor-long v4, p1, v2

    .line 9
    .line 10
    const-wide/16 v6, 0x0

    .line 11
    .line 12
    cmp-long p0, v4, v6

    .line 13
    .line 14
    if-gez p0, :cond_1

    .line 15
    .line 16
    xor-long p0, p1, v0

    .line 17
    .line 18
    cmp-long p0, p0, v6

    .line 19
    .line 20
    if-gez p0, :cond_0

    .line 21
    .line 22
    goto :goto_0

    .line 23
    :cond_0
    new-instance p0, Ljava/lang/ArithmeticException;

    .line 24
    .line 25
    const-string p1, "Adding time zone offset caused overflow"

    .line 26
    .line 27
    invoke-direct {p0, p1}, Ljava/lang/ArithmeticException;-><init>(Ljava/lang/String;)V

    .line 28
    .line 29
    .line 30
    throw p0

    .line 31
    :cond_1
    :goto_0
    return-wide v2
.end method

.method public abstract equals(Ljava/lang/Object;)Z
.end method

.method public final f(Ln11/f;J)J
    .locals 2

    .line 1
    if-nez p1, :cond_0

    .line 2
    .line 3
    invoke-static {}, Ln11/f;->e()Ln11/f;

    .line 4
    .line 5
    .line 6
    move-result-object p1

    .line 7
    :cond_0
    if-ne p1, p0, :cond_1

    .line 8
    .line 9
    return-wide p2

    .line 10
    :cond_1
    invoke-virtual {p0, p2, p3}, Ln11/f;->b(J)J

    .line 11
    .line 12
    .line 13
    move-result-wide v0

    .line 14
    invoke-virtual {p1, v0, v1, p2, p3}, Ln11/f;->a(JJ)J

    .line 15
    .line 16
    .line 17
    move-result-wide p0

    .line 18
    return-wide p0
.end method

.method public abstract g(J)Ljava/lang/String;
.end method

.method public hashCode()I
    .locals 0

    .line 1
    iget-object p0, p0, Ln11/f;->d:Ljava/lang/String;

    .line 2
    .line 3
    invoke-virtual {p0}, Ljava/lang/String;->hashCode()I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    add-int/lit8 p0, p0, 0x39

    .line 8
    .line 9
    return p0
.end method

.method public abstract i(J)I
.end method

.method public j(J)I
    .locals 8

    .line 1
    invoke-virtual {p0, p1, p2}, Ln11/f;->i(J)I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    int-to-long v1, v0

    .line 6
    sub-long v1, p1, v1

    .line 7
    .line 8
    invoke-virtual {p0, v1, v2}, Ln11/f;->i(J)I

    .line 9
    .line 10
    .line 11
    move-result v3

    .line 12
    if-eq v0, v3, :cond_2

    .line 13
    .line 14
    sub-int v4, v0, v3

    .line 15
    .line 16
    if-gez v4, :cond_3

    .line 17
    .line 18
    invoke-virtual {p0, v1, v2}, Ln11/f;->n(J)J

    .line 19
    .line 20
    .line 21
    move-result-wide v4

    .line 22
    cmp-long v1, v4, v1

    .line 23
    .line 24
    const-wide v6, 0x7fffffffffffffffL

    .line 25
    .line 26
    .line 27
    .line 28
    .line 29
    if-nez v1, :cond_0

    .line 30
    .line 31
    move-wide v4, v6

    .line 32
    :cond_0
    int-to-long v1, v3

    .line 33
    sub-long/2addr p1, v1

    .line 34
    invoke-virtual {p0, p1, p2}, Ln11/f;->n(J)J

    .line 35
    .line 36
    .line 37
    move-result-wide v1

    .line 38
    cmp-long p0, v1, p1

    .line 39
    .line 40
    if-nez p0, :cond_1

    .line 41
    .line 42
    goto :goto_0

    .line 43
    :cond_1
    move-wide v6, v1

    .line 44
    :goto_0
    cmp-long p0, v4, v6

    .line 45
    .line 46
    if-eqz p0, :cond_3

    .line 47
    .line 48
    return v0

    .line 49
    :cond_2
    if-ltz v0, :cond_3

    .line 50
    .line 51
    invoke-virtual {p0, v1, v2}, Ln11/f;->p(J)J

    .line 52
    .line 53
    .line 54
    move-result-wide p1

    .line 55
    cmp-long v4, p1, v1

    .line 56
    .line 57
    if-gez v4, :cond_3

    .line 58
    .line 59
    invoke-virtual {p0, p1, p2}, Ln11/f;->i(J)I

    .line 60
    .line 61
    .line 62
    move-result p0

    .line 63
    sub-int v0, p0, v0

    .line 64
    .line 65
    sub-long/2addr v1, p1

    .line 66
    int-to-long p1, v0

    .line 67
    cmp-long p1, v1, p1

    .line 68
    .line 69
    if-gtz p1, :cond_3

    .line 70
    .line 71
    return p0

    .line 72
    :cond_3
    return v3
.end method

.method public abstract l(J)I
.end method

.method public abstract m()Z
.end method

.method public abstract n(J)J
.end method

.method public abstract p(J)J
.end method

.method public final toString()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Ln11/f;->d:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method
