.class public final Lp6/e;
.super Landroidx/datastore/preferences/protobuf/x;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field private static final DEFAULT_INSTANCE:Lp6/e;

.field private static volatile PARSER:Landroidx/datastore/preferences/protobuf/v0; = null
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Landroidx/datastore/preferences/protobuf/v0;"
        }
    .end annotation
.end field

.field public static final PREFERENCES_FIELD_NUMBER:I = 0x1


# instance fields
.field private preferences_:Landroidx/datastore/preferences/protobuf/m0;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Landroidx/datastore/preferences/protobuf/m0;"
        }
    .end annotation
.end field


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lp6/e;

    .line 2
    .line 3
    invoke-direct {v0}, Lp6/e;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lp6/e;->DEFAULT_INSTANCE:Lp6/e;

    .line 7
    .line 8
    const-class v1, Lp6/e;

    .line 9
    .line 10
    invoke-static {v1, v0}, Landroidx/datastore/preferences/protobuf/x;->j(Ljava/lang/Class;Landroidx/datastore/preferences/protobuf/x;)V

    .line 11
    .line 12
    .line 13
    return-void
.end method

.method public constructor <init>()V
    .locals 1

    .line 1
    invoke-direct {p0}, Landroidx/datastore/preferences/protobuf/x;-><init>()V

    .line 2
    .line 3
    .line 4
    sget-object v0, Landroidx/datastore/preferences/protobuf/m0;->e:Landroidx/datastore/preferences/protobuf/m0;

    .line 5
    .line 6
    iput-object v0, p0, Lp6/e;->preferences_:Landroidx/datastore/preferences/protobuf/m0;

    .line 7
    .line 8
    return-void
.end method

.method public static l(Lp6/e;)Landroidx/datastore/preferences/protobuf/m0;
    .locals 2

    .line 1
    iget-object v0, p0, Lp6/e;->preferences_:Landroidx/datastore/preferences/protobuf/m0;

    .line 2
    .line 3
    iget-boolean v1, v0, Landroidx/datastore/preferences/protobuf/m0;->d:Z

    .line 4
    .line 5
    if-nez v1, :cond_0

    .line 6
    .line 7
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/m0;->b()Landroidx/datastore/preferences/protobuf/m0;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    iput-object v0, p0, Lp6/e;->preferences_:Landroidx/datastore/preferences/protobuf/m0;

    .line 12
    .line 13
    :cond_0
    iget-object p0, p0, Lp6/e;->preferences_:Landroidx/datastore/preferences/protobuf/m0;

    .line 14
    .line 15
    return-object p0
.end method

.method public static n()Lp6/c;
    .locals 2

    .line 1
    sget-object v0, Lp6/e;->DEFAULT_INSTANCE:Lp6/e;

    .line 2
    .line 3
    const/4 v1, 0x5

    .line 4
    invoke-virtual {v0, v1}, Lp6/e;->c(I)Ljava/lang/Object;

    .line 5
    .line 6
    .line 7
    move-result-object v0

    .line 8
    check-cast v0, Landroidx/datastore/preferences/protobuf/v;

    .line 9
    .line 10
    check-cast v0, Lp6/c;

    .line 11
    .line 12
    return-object v0
.end method

.method public static o(Ljava/io/FileInputStream;)Lp6/e;
    .locals 4

    .line 1
    sget-object v0, Lp6/e;->DEFAULT_INSTANCE:Lp6/e;

    .line 2
    .line 3
    new-instance v1, Landroidx/datastore/preferences/protobuf/j;

    .line 4
    .line 5
    invoke-direct {v1, p0}, Landroidx/datastore/preferences/protobuf/j;-><init>(Ljava/io/FileInputStream;)V

    .line 6
    .line 7
    .line 8
    invoke-static {}, Landroidx/datastore/preferences/protobuf/o;->a()Landroidx/datastore/preferences/protobuf/o;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    invoke-virtual {v0}, Landroidx/datastore/preferences/protobuf/x;->i()Landroidx/datastore/preferences/protobuf/x;

    .line 13
    .line 14
    .line 15
    move-result-object v0

    .line 16
    :try_start_0
    sget-object v2, Landroidx/datastore/preferences/protobuf/x0;->c:Landroidx/datastore/preferences/protobuf/x0;

    .line 17
    .line 18
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 19
    .line 20
    .line 21
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 22
    .line 23
    .line 24
    move-result-object v3

    .line 25
    invoke-virtual {v2, v3}, Landroidx/datastore/preferences/protobuf/x0;->a(Ljava/lang/Class;)Landroidx/datastore/preferences/protobuf/a1;

    .line 26
    .line 27
    .line 28
    move-result-object v2

    .line 29
    iget-object v3, v1, Landroidx/datastore/preferences/protobuf/k;->e:Ljava/lang/Object;

    .line 30
    .line 31
    check-cast v3, Landroidx/collection/h;

    .line 32
    .line 33
    if-eqz v3, :cond_0

    .line 34
    .line 35
    goto :goto_0

    .line 36
    :cond_0
    new-instance v3, Landroidx/collection/h;

    .line 37
    .line 38
    invoke-direct {v3, v1}, Landroidx/collection/h;-><init>(Landroidx/datastore/preferences/protobuf/k;)V

    .line 39
    .line 40
    .line 41
    :goto_0
    invoke-interface {v2, v0, v3, p0}, Landroidx/datastore/preferences/protobuf/a1;->i(Ljava/lang/Object;Landroidx/collection/h;Landroidx/datastore/preferences/protobuf/o;)V

    .line 42
    .line 43
    .line 44
    invoke-interface {v2, v0}, Landroidx/datastore/preferences/protobuf/a1;->a(Ljava/lang/Object;)V
    :try_end_0
    .catch Landroidx/datastore/preferences/protobuf/c0; {:try_start_0 .. :try_end_0} :catch_3
    .catch Landroidx/datastore/preferences/protobuf/g1; {:try_start_0 .. :try_end_0} :catch_2
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_1
    .catch Ljava/lang/RuntimeException; {:try_start_0 .. :try_end_0} :catch_0

    .line 45
    .line 46
    .line 47
    const/4 p0, 0x1

    .line 48
    invoke-static {v0, p0}, Landroidx/datastore/preferences/protobuf/x;->f(Landroidx/datastore/preferences/protobuf/x;Z)Z

    .line 49
    .line 50
    .line 51
    move-result p0

    .line 52
    if-eqz p0, :cond_1

    .line 53
    .line 54
    check-cast v0, Lp6/e;

    .line 55
    .line 56
    return-object v0

    .line 57
    :cond_1
    new-instance p0, Landroidx/datastore/preferences/protobuf/g1;

    .line 58
    .line 59
    invoke-direct {p0}, Landroidx/datastore/preferences/protobuf/g1;-><init>()V

    .line 60
    .line 61
    .line 62
    new-instance v0, Landroidx/datastore/preferences/protobuf/c0;

    .line 63
    .line 64
    invoke-virtual {p0}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    .line 65
    .line 66
    .line 67
    move-result-object p0

    .line 68
    invoke-direct {v0, p0}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    .line 69
    .line 70
    .line 71
    throw v0

    .line 72
    :catch_0
    move-exception p0

    .line 73
    invoke-virtual {p0}, Ljava/lang/Throwable;->getCause()Ljava/lang/Throwable;

    .line 74
    .line 75
    .line 76
    move-result-object v0

    .line 77
    instance-of v0, v0, Landroidx/datastore/preferences/protobuf/c0;

    .line 78
    .line 79
    if-eqz v0, :cond_2

    .line 80
    .line 81
    invoke-virtual {p0}, Ljava/lang/Throwable;->getCause()Ljava/lang/Throwable;

    .line 82
    .line 83
    .line 84
    move-result-object p0

    .line 85
    check-cast p0, Landroidx/datastore/preferences/protobuf/c0;

    .line 86
    .line 87
    throw p0

    .line 88
    :cond_2
    throw p0

    .line 89
    :catch_1
    move-exception p0

    .line 90
    invoke-virtual {p0}, Ljava/lang/Throwable;->getCause()Ljava/lang/Throwable;

    .line 91
    .line 92
    .line 93
    move-result-object v0

    .line 94
    instance-of v0, v0, Landroidx/datastore/preferences/protobuf/c0;

    .line 95
    .line 96
    if-eqz v0, :cond_3

    .line 97
    .line 98
    invoke-virtual {p0}, Ljava/lang/Throwable;->getCause()Ljava/lang/Throwable;

    .line 99
    .line 100
    .line 101
    move-result-object p0

    .line 102
    check-cast p0, Landroidx/datastore/preferences/protobuf/c0;

    .line 103
    .line 104
    throw p0

    .line 105
    :cond_3
    new-instance v0, Landroidx/datastore/preferences/protobuf/c0;

    .line 106
    .line 107
    invoke-virtual {p0}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    .line 108
    .line 109
    .line 110
    move-result-object v1

    .line 111
    invoke-direct {v0, v1, p0}, Ljava/io/IOException;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 112
    .line 113
    .line 114
    throw v0

    .line 115
    :catch_2
    move-exception p0

    .line 116
    new-instance v0, Landroidx/datastore/preferences/protobuf/c0;

    .line 117
    .line 118
    invoke-virtual {p0}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    .line 119
    .line 120
    .line 121
    move-result-object p0

    .line 122
    invoke-direct {v0, p0}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    .line 123
    .line 124
    .line 125
    throw v0

    .line 126
    :catch_3
    move-exception p0

    .line 127
    iget-boolean v0, p0, Landroidx/datastore/preferences/protobuf/c0;->d:Z

    .line 128
    .line 129
    if-eqz v0, :cond_4

    .line 130
    .line 131
    new-instance v0, Landroidx/datastore/preferences/protobuf/c0;

    .line 132
    .line 133
    invoke-virtual {p0}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    .line 134
    .line 135
    .line 136
    move-result-object v1

    .line 137
    invoke-direct {v0, v1, p0}, Ljava/io/IOException;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 138
    .line 139
    .line 140
    move-object p0, v0

    .line 141
    :cond_4
    throw p0
.end method


# virtual methods
.method public final c(I)Ljava/lang/Object;
    .locals 2

    .line 1
    invoke-static {p1}, Lu/w;->o(I)I

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    packed-switch p0, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    new-instance p0, Ljava/lang/UnsupportedOperationException;

    .line 9
    .line 10
    invoke-direct {p0}, Ljava/lang/UnsupportedOperationException;-><init>()V

    .line 11
    .line 12
    .line 13
    throw p0

    .line 14
    :pswitch_0
    sget-object p0, Lp6/e;->PARSER:Landroidx/datastore/preferences/protobuf/v0;

    .line 15
    .line 16
    if-nez p0, :cond_1

    .line 17
    .line 18
    const-class p1, Lp6/e;

    .line 19
    .line 20
    monitor-enter p1

    .line 21
    :try_start_0
    sget-object p0, Lp6/e;->PARSER:Landroidx/datastore/preferences/protobuf/v0;

    .line 22
    .line 23
    if-nez p0, :cond_0

    .line 24
    .line 25
    new-instance p0, Landroidx/datastore/preferences/protobuf/w;

    .line 26
    .line 27
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 28
    .line 29
    .line 30
    sput-object p0, Lp6/e;->PARSER:Landroidx/datastore/preferences/protobuf/v0;

    .line 31
    .line 32
    goto :goto_0

    .line 33
    :catchall_0
    move-exception p0

    .line 34
    goto :goto_1

    .line 35
    :cond_0
    :goto_0
    monitor-exit p1

    .line 36
    return-object p0

    .line 37
    :goto_1
    monitor-exit p1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 38
    throw p0

    .line 39
    :cond_1
    return-object p0

    .line 40
    :pswitch_1
    sget-object p0, Lp6/e;->DEFAULT_INSTANCE:Lp6/e;

    .line 41
    .line 42
    return-object p0

    .line 43
    :pswitch_2
    new-instance p0, Lp6/c;

    .line 44
    .line 45
    sget-object p1, Lp6/e;->DEFAULT_INSTANCE:Lp6/e;

    .line 46
    .line 47
    invoke-direct {p0, p1}, Landroidx/datastore/preferences/protobuf/v;-><init>(Landroidx/datastore/preferences/protobuf/x;)V

    .line 48
    .line 49
    .line 50
    return-object p0

    .line 51
    :pswitch_3
    new-instance p0, Lp6/e;

    .line 52
    .line 53
    invoke-direct {p0}, Lp6/e;-><init>()V

    .line 54
    .line 55
    .line 56
    return-object p0

    .line 57
    :pswitch_4
    const-string p0, "preferences_"

    .line 58
    .line 59
    sget-object p1, Lp6/d;->a:Landroidx/datastore/preferences/protobuf/l0;

    .line 60
    .line 61
    filled-new-array {p0, p1}, [Ljava/lang/Object;

    .line 62
    .line 63
    .line 64
    move-result-object p0

    .line 65
    const-string p1, "\u0001\u0001\u0000\u0000\u0001\u0001\u0001\u0001\u0000\u0000\u00012"

    .line 66
    .line 67
    sget-object v0, Lp6/e;->DEFAULT_INSTANCE:Lp6/e;

    .line 68
    .line 69
    new-instance v1, Landroidx/datastore/preferences/protobuf/z0;

    .line 70
    .line 71
    invoke-direct {v1, v0, p1, p0}, Landroidx/datastore/preferences/protobuf/z0;-><init>(Landroidx/datastore/preferences/protobuf/x;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 72
    .line 73
    .line 74
    return-object v1

    .line 75
    :pswitch_5
    const/4 p0, 0x0

    .line 76
    return-object p0

    .line 77
    :pswitch_6
    const/4 p0, 0x1

    .line 78
    invoke-static {p0}, Ljava/lang/Byte;->valueOf(B)Ljava/lang/Byte;

    .line 79
    .line 80
    .line 81
    move-result-object p0

    .line 82
    return-object p0

    .line 83
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final m()Ljava/util/Map;
    .locals 0

    .line 1
    iget-object p0, p0, Lp6/e;->preferences_:Landroidx/datastore/preferences/protobuf/m0;

    .line 2
    .line 3
    invoke-static {p0}, Ljava/util/Collections;->unmodifiableMap(Ljava/util/Map;)Ljava/util/Map;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method
