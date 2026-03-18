.class public final synthetic Lc1/y;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lc1/w;
.implements Lc9/g;
.implements Laq/b;
.implements Ldt/a;
.implements Lon/e;
.implements Lcom/google/gson/internal/m;
.implements Laq/i;
.implements Lf3/j;


# instance fields
.field public final synthetic d:I


# direct methods
.method public synthetic constructor <init>(I)V
    .locals 0

    .line 1
    iput p1, p0, Lc1/y;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Lin/z1;)V
    .locals 0

    .line 2
    const/4 p1, 0x5

    iput p1, p0, Lc1/y;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public a()Ljava/lang/Object;
    .locals 1

    .line 1
    iget p0, p0, Lc1/y;->d:I

    .line 2
    .line 3
    packed-switch p0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance p0, Ljava/util/ArrayDeque;

    .line 7
    .line 8
    invoke-direct {p0}, Ljava/util/ArrayDeque;-><init>()V

    .line 9
    .line 10
    .line 11
    return-object p0

    .line 12
    :pswitch_0
    new-instance p0, Ljava/util/TreeSet;

    .line 13
    .line 14
    invoke-direct {p0}, Ljava/util/TreeSet;-><init>()V

    .line 15
    .line 16
    .line 17
    return-object p0

    .line 18
    :pswitch_1
    new-instance p0, Ljava/util/LinkedHashSet;

    .line 19
    .line 20
    invoke-direct {p0}, Ljava/util/LinkedHashSet;-><init>()V

    .line 21
    .line 22
    .line 23
    return-object p0

    .line 24
    :pswitch_2
    new-instance p0, Ljava/util/ArrayList;

    .line 25
    .line 26
    invoke-direct {p0}, Ljava/util/ArrayList;-><init>()V

    .line 27
    .line 28
    .line 29
    return-object p0

    .line 30
    :pswitch_3
    new-instance p0, Ljava/util/concurrent/ConcurrentSkipListMap;

    .line 31
    .line 32
    invoke-direct {p0}, Ljava/util/concurrent/ConcurrentSkipListMap;-><init>()V

    .line 33
    .line 34
    .line 35
    return-object p0

    .line 36
    :pswitch_4
    new-instance p0, Ljava/util/concurrent/ConcurrentHashMap;

    .line 37
    .line 38
    invoke-direct {p0}, Ljava/util/concurrent/ConcurrentHashMap;-><init>()V

    .line 39
    .line 40
    .line 41
    return-object p0

    .line 42
    :pswitch_5
    new-instance p0, Ljava/util/TreeMap;

    .line 43
    .line 44
    invoke-direct {p0}, Ljava/util/TreeMap;-><init>()V

    .line 45
    .line 46
    .line 47
    return-object p0

    .line 48
    :pswitch_6
    new-instance p0, Ljava/util/LinkedHashMap;

    .line 49
    .line 50
    invoke-direct {p0}, Ljava/util/LinkedHashMap;-><init>()V

    .line 51
    .line 52
    .line 53
    return-object p0

    .line 54
    :pswitch_7
    new-instance p0, Lcom/google/gson/internal/l;

    .line 55
    .line 56
    const/4 v0, 0x1

    .line 57
    invoke-direct {p0, v0}, Lcom/google/gson/internal/l;-><init>(Z)V

    .line 58
    .line 59
    .line 60
    return-object p0

    .line 61
    :pswitch_data_0
    .packed-switch 0x7
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public apply(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    check-cast p1, Lnt/e;

    .line 2
    .line 3
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 4
    .line 5
    .line 6
    sget-object p0, Lcom/google/firebase/messaging/s;->a:Lgw0/c;

    .line 7
    .line 8
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 9
    .line 10
    .line 11
    new-instance v0, Ljava/io/ByteArrayOutputStream;

    .line 12
    .line 13
    invoke-direct {v0}, Ljava/io/ByteArrayOutputStream;-><init>()V

    .line 14
    .line 15
    .line 16
    :try_start_0
    invoke-virtual {p0, p1, v0}, Lgw0/c;->e(Ljava/lang/Object;Ljava/io/ByteArrayOutputStream;)V
    :try_end_0
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_0

    .line 17
    .line 18
    .line 19
    :catch_0
    invoke-virtual {v0}, Ljava/io/ByteArrayOutputStream;->toByteArray()[B

    .line 20
    .line 21
    .line 22
    move-result-object p0

    .line 23
    return-object p0
.end method

.method public b(F)F
    .locals 0

    .line 1
    return p1
.end method

.method public d(IIIII)Z
    .locals 0

    .line 1
    const/4 p0, 0x0

    .line 2
    return p0
.end method

.method public g(Ljava/lang/Object;)Laq/t;
    .locals 6

    .line 1
    iget p0, p0, Lc1/y;->d:I

    .line 2
    .line 3
    const/4 v0, 0x0

    .line 4
    packed-switch p0, :pswitch_data_0

    .line 5
    .line 6
    .line 7
    check-cast p1, Las/a;

    .line 8
    .line 9
    invoke-static {p1}, Lno/c0;->h(Ljava/lang/Object;)V

    .line 10
    .line 11
    .line 12
    iget-object v3, p1, Las/a;->a:Ljava/lang/String;

    .line 13
    .line 14
    :try_start_0
    iget-object p0, p1, Las/a;->b:Ljava/lang/String;

    .line 15
    .line 16
    const-string p1, "s"

    .line 17
    .line 18
    const-string v0, ""

    .line 19
    .line 20
    invoke-virtual {p0, p1, v0}, Ljava/lang/String;->replace(Ljava/lang/CharSequence;Ljava/lang/CharSequence;)Ljava/lang/String;

    .line 21
    .line 22
    .line 23
    move-result-object p0

    .line 24
    invoke-static {p0}, Ljava/lang/Double;->parseDouble(Ljava/lang/String;)D

    .line 25
    .line 26
    .line 27
    move-result-wide p0
    :try_end_0
    .catch Ljava/lang/NumberFormatException; {:try_start_0 .. :try_end_0} :catch_0

    .line 28
    const-wide v0, 0x408f400000000000L    # 1000.0

    .line 29
    .line 30
    .line 31
    .line 32
    .line 33
    mul-double/2addr p0, v0

    .line 34
    double-to-long p0, p0

    .line 35
    :goto_0
    move-wide v1, p0

    .line 36
    goto :goto_1

    .line 37
    :catch_0
    invoke-static {v3}, Ljp/db;->b(Ljava/lang/String;)Ljava/util/Map;

    .line 38
    .line 39
    .line 40
    move-result-object p0

    .line 41
    const-string p1, "iat"

    .line 42
    .line 43
    invoke-static {p1, p0}, Las/b;->c(Ljava/lang/String;Ljava/util/Map;)J

    .line 44
    .line 45
    .line 46
    move-result-wide v0

    .line 47
    const-string p1, "exp"

    .line 48
    .line 49
    invoke-static {p1, p0}, Las/b;->c(Ljava/lang/String;Ljava/util/Map;)J

    .line 50
    .line 51
    .line 52
    move-result-wide p0

    .line 53
    sub-long/2addr p0, v0

    .line 54
    const-wide/16 v0, 0x3e8

    .line 55
    .line 56
    mul-long/2addr p0, v0

    .line 57
    goto :goto_0

    .line 58
    :goto_1
    new-instance v0, Las/b;

    .line 59
    .line 60
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    .line 61
    .line 62
    .line 63
    move-result-wide v4

    .line 64
    invoke-direct/range {v0 .. v5}, Las/b;-><init>(JLjava/lang/String;J)V

    .line 65
    .line 66
    .line 67
    invoke-static {v0}, Ljp/l1;->e(Ljava/lang/Object;)Laq/t;

    .line 68
    .line 69
    .line 70
    move-result-object p0

    .line 71
    return-object p0

    .line 72
    :pswitch_0
    check-cast p1, Ldu/h;

    .line 73
    .line 74
    invoke-static {v0}, Ljp/l1;->e(Ljava/lang/Object;)Laq/t;

    .line 75
    .line 76
    .line 77
    move-result-object p0

    .line 78
    return-object p0

    .line 79
    :pswitch_1
    check-cast p1, Ldu/e;

    .line 80
    .line 81
    invoke-static {v0}, Ljp/l1;->e(Ljava/lang/Object;)Laq/t;

    .line 82
    .line 83
    .line 84
    move-result-object p0

    .line 85
    return-object p0

    .line 86
    :pswitch_2
    check-cast p1, Ldu/h;

    .line 87
    .line 88
    invoke-static {v0}, Ljp/l1;->e(Ljava/lang/Object;)Laq/t;

    .line 89
    .line 90
    .line 91
    move-result-object p0

    .line 92
    return-object p0

    .line 93
    :pswitch_data_0
    .packed-switch 0x10
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public h(D)D
    .locals 10

    .line 1
    iget p0, p0, Lc1/y;->d:I

    .line 2
    .line 3
    const-wide/16 v0, 0x0

    .line 4
    .line 5
    const-wide v2, 0x3fb3d0722149b580L    # 0.07739938080495357

    .line 6
    .line 7
    .line 8
    .line 9
    .line 10
    const-wide v4, 0x3faab1232f514a03L    # 0.05213270142180095

    .line 11
    .line 12
    .line 13
    .line 14
    .line 15
    const-wide v6, 0x3fee54edcd0aeb60L    # 0.9478672985781991

    .line 16
    .line 17
    .line 18
    .line 19
    .line 20
    packed-switch p0, :pswitch_data_0

    .line 21
    .line 22
    .line 23
    sget-object p0, Lf3/e;->a:[F

    .line 24
    .line 25
    sget-object p0, Lf3/e;->c:Lf3/s;

    .line 26
    .line 27
    invoke-static {p0, p1, p2}, Lf3/e;->b(Lf3/s;D)D

    .line 28
    .line 29
    .line 30
    move-result-wide p0

    .line 31
    return-wide p0

    .line 32
    :pswitch_0
    cmpg-double p0, p1, v0

    .line 33
    .line 34
    if-gez p0, :cond_0

    .line 35
    .line 36
    neg-double v0, p1

    .line 37
    goto :goto_0

    .line 38
    :cond_0
    move-wide v0, p1

    .line 39
    :goto_0
    const-wide v8, 0x3fa4b5dcc63f1412L    # 0.04045

    .line 40
    .line 41
    .line 42
    .line 43
    .line 44
    cmpl-double p0, v0, v8

    .line 45
    .line 46
    if-ltz p0, :cond_1

    .line 47
    .line 48
    mul-double/2addr v6, v0

    .line 49
    add-double/2addr v6, v4

    .line 50
    const-wide v0, 0x4003333333333333L    # 2.4

    .line 51
    .line 52
    .line 53
    .line 54
    .line 55
    invoke-static {v6, v7, v0, v1}, Ljava/lang/Math;->pow(DD)D

    .line 56
    .line 57
    .line 58
    move-result-wide v0

    .line 59
    goto :goto_1

    .line 60
    :cond_1
    mul-double/2addr v0, v2

    .line 61
    :goto_1
    invoke-static {v0, v1, p1, p2}, Ljava/lang/Math;->copySign(DD)D

    .line 62
    .line 63
    .line 64
    move-result-wide p0

    .line 65
    return-wide p0

    .line 66
    :pswitch_1
    cmpg-double p0, p1, v0

    .line 67
    .line 68
    if-gez p0, :cond_2

    .line 69
    .line 70
    neg-double v0, p1

    .line 71
    goto :goto_2

    .line 72
    :cond_2
    move-wide v0, p1

    .line 73
    :goto_2
    const-wide v8, 0x3f69a5c61c57a063L    # 0.0031308049535603718

    .line 74
    .line 75
    .line 76
    .line 77
    .line 78
    cmpl-double p0, v0, v8

    .line 79
    .line 80
    if-ltz p0, :cond_3

    .line 81
    .line 82
    const-wide v2, 0x3fdaaaaaaaaaaaabL    # 0.4166666666666667

    .line 83
    .line 84
    .line 85
    .line 86
    .line 87
    invoke-static {v0, v1, v2, v3}, Ljava/lang/Math;->pow(DD)D

    .line 88
    .line 89
    .line 90
    move-result-wide v0

    .line 91
    sub-double/2addr v0, v4

    .line 92
    div-double/2addr v0, v6

    .line 93
    goto :goto_3

    .line 94
    :cond_3
    div-double/2addr v0, v2

    .line 95
    :goto_3
    invoke-static {v0, v1, p1, p2}, Ljava/lang/Math;->copySign(DD)D

    .line 96
    .line 97
    .line 98
    move-result-wide p0

    .line 99
    return-wide p0

    .line 100
    nop

    .line 101
    :pswitch_data_0
    .packed-switch 0x1b
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public w(Laq/j;)Ljava/lang/Object;
    .locals 3

    .line 1
    iget p0, p0, Lc1/y;->d:I

    .line 2
    .line 3
    packed-switch p0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    const-class p0, Ljava/io/IOException;

    .line 7
    .line 8
    check-cast p1, Laq/t;

    .line 9
    .line 10
    iget-object v0, p1, Laq/t;->a:Ljava/lang/Object;

    .line 11
    .line 12
    monitor-enter v0

    .line 13
    :try_start_0
    iget-boolean v1, p1, Laq/t;->c:Z

    .line 14
    .line 15
    const-string v2, "Task is not yet complete"

    .line 16
    .line 17
    invoke-static {v2, v1}, Lno/c0;->j(Ljava/lang/String;Z)V

    .line 18
    .line 19
    .line 20
    iget-boolean v1, p1, Laq/t;->d:Z

    .line 21
    .line 22
    if-nez v1, :cond_7

    .line 23
    .line 24
    iget-object v1, p1, Laq/t;->f:Ljava/lang/Exception;

    .line 25
    .line 26
    invoke-virtual {p0, v1}, Ljava/lang/Class;->isInstance(Ljava/lang/Object;)Z

    .line 27
    .line 28
    .line 29
    move-result v1

    .line 30
    if-nez v1, :cond_6

    .line 31
    .line 32
    iget-object p0, p1, Laq/t;->f:Ljava/lang/Exception;

    .line 33
    .line 34
    if-nez p0, :cond_5

    .line 35
    .line 36
    iget-object p0, p1, Laq/t;->e:Ljava/lang/Object;

    .line 37
    .line 38
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 39
    check-cast p0, Landroid/os/Bundle;

    .line 40
    .line 41
    const-string p1, "SERVICE_NOT_AVAILABLE"

    .line 42
    .line 43
    if-eqz p0, :cond_4

    .line 44
    .line 45
    const-string v0, "registration_id"

    .line 46
    .line 47
    invoke-virtual {p0, v0}, Landroid/os/BaseBundle;->getString(Ljava/lang/String;)Ljava/lang/String;

    .line 48
    .line 49
    .line 50
    move-result-object v0

    .line 51
    if-eqz v0, :cond_0

    .line 52
    .line 53
    goto :goto_0

    .line 54
    :cond_0
    const-string v0, "unregistered"

    .line 55
    .line 56
    invoke-virtual {p0, v0}, Landroid/os/BaseBundle;->getString(Ljava/lang/String;)Ljava/lang/String;

    .line 57
    .line 58
    .line 59
    move-result-object v0

    .line 60
    if-eqz v0, :cond_1

    .line 61
    .line 62
    :goto_0
    return-object v0

    .line 63
    :cond_1
    const-string v0, "error"

    .line 64
    .line 65
    invoke-virtual {p0, v0}, Landroid/os/BaseBundle;->getString(Ljava/lang/String;)Ljava/lang/String;

    .line 66
    .line 67
    .line 68
    move-result-object v0

    .line 69
    const-string v1, "RST"

    .line 70
    .line 71
    invoke-virtual {v1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 72
    .line 73
    .line 74
    move-result v1

    .line 75
    if-nez v1, :cond_3

    .line 76
    .line 77
    if-eqz v0, :cond_2

    .line 78
    .line 79
    new-instance p0, Ljava/io/IOException;

    .line 80
    .line 81
    invoke-direct {p0, v0}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    .line 82
    .line 83
    .line 84
    throw p0

    .line 85
    :cond_2
    const-string v0, "FirebaseMessaging"

    .line 86
    .line 87
    new-instance v1, Ljava/lang/StringBuilder;

    .line 88
    .line 89
    const-string v2, "Unexpected response: "

    .line 90
    .line 91
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 92
    .line 93
    .line 94
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 95
    .line 96
    .line 97
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 98
    .line 99
    .line 100
    move-result-object p0

    .line 101
    new-instance v1, Ljava/lang/Throwable;

    .line 102
    .line 103
    invoke-direct {v1}, Ljava/lang/Throwable;-><init>()V

    .line 104
    .line 105
    .line 106
    invoke-static {v0, p0, v1}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 107
    .line 108
    .line 109
    new-instance p0, Ljava/io/IOException;

    .line 110
    .line 111
    invoke-direct {p0, p1}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    .line 112
    .line 113
    .line 114
    throw p0

    .line 115
    :cond_3
    new-instance p0, Ljava/io/IOException;

    .line 116
    .line 117
    const-string p1, "INSTANCE_ID_RESET"

    .line 118
    .line 119
    invoke-direct {p0, p1}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    .line 120
    .line 121
    .line 122
    throw p0

    .line 123
    :cond_4
    new-instance p0, Ljava/io/IOException;

    .line 124
    .line 125
    invoke-direct {p0, p1}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    .line 126
    .line 127
    .line 128
    throw p0

    .line 129
    :catchall_0
    move-exception p0

    .line 130
    goto :goto_1

    .line 131
    :cond_5
    :try_start_1
    new-instance p1, Laq/h;

    .line 132
    .line 133
    invoke-direct {p1, p0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/Throwable;)V

    .line 134
    .line 135
    .line 136
    throw p1

    .line 137
    :cond_6
    iget-object p1, p1, Laq/t;->f:Ljava/lang/Exception;

    .line 138
    .line 139
    invoke-virtual {p0, p1}, Ljava/lang/Class;->cast(Ljava/lang/Object;)Ljava/lang/Object;

    .line 140
    .line 141
    .line 142
    move-result-object p0

    .line 143
    check-cast p0, Ljava/lang/Throwable;

    .line 144
    .line 145
    throw p0

    .line 146
    :cond_7
    new-instance p0, Ljava/util/concurrent/CancellationException;

    .line 147
    .line 148
    const-string p1, "Task is already canceled."

    .line 149
    .line 150
    invoke-direct {p0, p1}, Ljava/util/concurrent/CancellationException;-><init>(Ljava/lang/String;)V

    .line 151
    .line 152
    .line 153
    throw p0

    .line 154
    :goto_1
    monitor-exit v0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 155
    throw p0

    .line 156
    :pswitch_0
    const/4 p0, -0x1

    .line 157
    :goto_2
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 158
    .line 159
    .line 160
    move-result-object p0

    .line 161
    return-object p0

    .line 162
    :pswitch_1
    const/16 p0, 0x193

    .line 163
    .line 164
    goto :goto_2

    :pswitch_data_0
    .packed-switch 0x2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
