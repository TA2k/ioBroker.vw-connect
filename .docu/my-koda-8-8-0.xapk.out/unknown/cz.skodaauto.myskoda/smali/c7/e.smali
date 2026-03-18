.class public final Lc7/e;
.super Landroidx/glance/appwidget/protobuf/u;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field private static final DEFAULT_INSTANCE:Lc7/e;

.field public static final LAYOUT_FIELD_NUMBER:I = 0x1

.field public static final NEXT_INDEX_FIELD_NUMBER:I = 0x2

.field private static volatile PARSER:Landroidx/glance/appwidget/protobuf/r0;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Landroidx/glance/appwidget/protobuf/r0;"
        }
    .end annotation
.end field


# instance fields
.field private layout_:Landroidx/glance/appwidget/protobuf/x;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Landroidx/glance/appwidget/protobuf/x;"
        }
    .end annotation
.end field

.field private nextIndex_:I


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lc7/e;

    .line 2
    .line 3
    invoke-direct {v0}, Lc7/e;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lc7/e;->DEFAULT_INSTANCE:Lc7/e;

    .line 7
    .line 8
    const-class v1, Lc7/e;

    .line 9
    .line 10
    invoke-static {v1, v0}, Landroidx/glance/appwidget/protobuf/u;->i(Ljava/lang/Class;Landroidx/glance/appwidget/protobuf/u;)V

    .line 11
    .line 12
    .line 13
    return-void
.end method

.method public constructor <init>()V
    .locals 1

    .line 1
    invoke-direct {p0}, Landroidx/glance/appwidget/protobuf/u;-><init>()V

    .line 2
    .line 3
    .line 4
    sget-object v0, Landroidx/glance/appwidget/protobuf/t0;->g:Landroidx/glance/appwidget/protobuf/t0;

    .line 5
    .line 6
    iput-object v0, p0, Lc7/e;->layout_:Landroidx/glance/appwidget/protobuf/x;

    .line 7
    .line 8
    return-void
.end method

.method public static k(Lc7/e;Lc7/g;)V
    .locals 2

    .line 1
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 2
    .line 3
    .line 4
    iget-object v0, p0, Lc7/e;->layout_:Landroidx/glance/appwidget/protobuf/x;

    .line 5
    .line 6
    move-object v1, v0

    .line 7
    check-cast v1, Landroidx/glance/appwidget/protobuf/b;

    .line 8
    .line 9
    iget-boolean v1, v1, Landroidx/glance/appwidget/protobuf/b;->d:Z

    .line 10
    .line 11
    if-nez v1, :cond_1

    .line 12
    .line 13
    invoke-interface {v0}, Ljava/util/List;->size()I

    .line 14
    .line 15
    .line 16
    move-result v1

    .line 17
    if-nez v1, :cond_0

    .line 18
    .line 19
    const/16 v1, 0xa

    .line 20
    .line 21
    goto :goto_0

    .line 22
    :cond_0
    mul-int/lit8 v1, v1, 0x2

    .line 23
    .line 24
    :goto_0
    check-cast v0, Landroidx/glance/appwidget/protobuf/t0;

    .line 25
    .line 26
    invoke-virtual {v0, v1}, Landroidx/glance/appwidget/protobuf/t0;->g(I)Landroidx/glance/appwidget/protobuf/t0;

    .line 27
    .line 28
    .line 29
    move-result-object v0

    .line 30
    iput-object v0, p0, Lc7/e;->layout_:Landroidx/glance/appwidget/protobuf/x;

    .line 31
    .line 32
    :cond_1
    iget-object p0, p0, Lc7/e;->layout_:Landroidx/glance/appwidget/protobuf/x;

    .line 33
    .line 34
    invoke-interface {p0, p1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 35
    .line 36
    .line 37
    return-void
.end method

.method public static l(Lc7/e;)V
    .locals 1

    .line 1
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 2
    .line 3
    .line 4
    sget-object v0, Landroidx/glance/appwidget/protobuf/t0;->g:Landroidx/glance/appwidget/protobuf/t0;

    .line 5
    .line 6
    iput-object v0, p0, Lc7/e;->layout_:Landroidx/glance/appwidget/protobuf/x;

    .line 7
    .line 8
    return-void
.end method

.method public static m(Lc7/e;I)V
    .locals 0

    .line 1
    iput p1, p0, Lc7/e;->nextIndex_:I

    .line 2
    .line 3
    return-void
.end method

.method public static n()Lc7/e;
    .locals 1

    .line 1
    sget-object v0, Lc7/e;->DEFAULT_INSTANCE:Lc7/e;

    .line 2
    .line 3
    return-object v0
.end method

.method public static q(Ljava/io/FileInputStream;)Lc7/e;
    .locals 5

    .line 1
    sget-object v0, Lc7/e;->DEFAULT_INSTANCE:Lc7/e;

    .line 2
    .line 3
    new-instance v1, Landroidx/glance/appwidget/protobuf/i;

    .line 4
    .line 5
    invoke-direct {v1, p0}, Landroidx/glance/appwidget/protobuf/i;-><init>(Ljava/io/FileInputStream;)V

    .line 6
    .line 7
    .line 8
    invoke-static {}, Landroidx/glance/appwidget/protobuf/m;->a()Landroidx/glance/appwidget/protobuf/m;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    invoke-virtual {v0}, Landroidx/glance/appwidget/protobuf/u;->h()Landroidx/glance/appwidget/protobuf/u;

    .line 13
    .line 14
    .line 15
    move-result-object v0

    .line 16
    :try_start_0
    sget-object v2, Landroidx/glance/appwidget/protobuf/s0;->c:Landroidx/glance/appwidget/protobuf/s0;

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
    invoke-virtual {v2, v3}, Landroidx/glance/appwidget/protobuf/s0;->a(Ljava/lang/Class;)Landroidx/glance/appwidget/protobuf/v0;

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
    const/4 v4, 0x0

    .line 39
    invoke-direct {v3, v1, v4}, Landroidx/collection/h;-><init>(Landroidx/datastore/preferences/protobuf/k;B)V

    .line 40
    .line 41
    .line 42
    :goto_0
    invoke-interface {v2, v0, v3, p0}, Landroidx/glance/appwidget/protobuf/v0;->h(Ljava/lang/Object;Landroidx/collection/h;Landroidx/glance/appwidget/protobuf/m;)V

    .line 43
    .line 44
    .line 45
    invoke-interface {v2, v0}, Landroidx/glance/appwidget/protobuf/v0;->a(Ljava/lang/Object;)V
    :try_end_0
    .catch Landroidx/glance/appwidget/protobuf/a0; {:try_start_0 .. :try_end_0} :catch_3
    .catch Landroidx/glance/appwidget/protobuf/x0; {:try_start_0 .. :try_end_0} :catch_2
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_1
    .catch Ljava/lang/RuntimeException; {:try_start_0 .. :try_end_0} :catch_0

    .line 46
    .line 47
    .line 48
    const/4 p0, 0x1

    .line 49
    invoke-static {v0, p0}, Landroidx/glance/appwidget/protobuf/u;->e(Landroidx/glance/appwidget/protobuf/u;Z)Z

    .line 50
    .line 51
    .line 52
    move-result p0

    .line 53
    if-eqz p0, :cond_1

    .line 54
    .line 55
    check-cast v0, Lc7/e;

    .line 56
    .line 57
    return-object v0

    .line 58
    :cond_1
    new-instance p0, Landroidx/glance/appwidget/protobuf/x0;

    .line 59
    .line 60
    invoke-direct {p0}, Landroidx/glance/appwidget/protobuf/x0;-><init>()V

    .line 61
    .line 62
    .line 63
    new-instance v0, Landroidx/glance/appwidget/protobuf/a0;

    .line 64
    .line 65
    invoke-virtual {p0}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    .line 66
    .line 67
    .line 68
    move-result-object p0

    .line 69
    invoke-direct {v0, p0}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    .line 70
    .line 71
    .line 72
    throw v0

    .line 73
    :catch_0
    move-exception p0

    .line 74
    invoke-virtual {p0}, Ljava/lang/Throwable;->getCause()Ljava/lang/Throwable;

    .line 75
    .line 76
    .line 77
    move-result-object v0

    .line 78
    instance-of v0, v0, Landroidx/glance/appwidget/protobuf/a0;

    .line 79
    .line 80
    if-eqz v0, :cond_2

    .line 81
    .line 82
    invoke-virtual {p0}, Ljava/lang/Throwable;->getCause()Ljava/lang/Throwable;

    .line 83
    .line 84
    .line 85
    move-result-object p0

    .line 86
    check-cast p0, Landroidx/glance/appwidget/protobuf/a0;

    .line 87
    .line 88
    throw p0

    .line 89
    :cond_2
    throw p0

    .line 90
    :catch_1
    move-exception p0

    .line 91
    invoke-virtual {p0}, Ljava/lang/Throwable;->getCause()Ljava/lang/Throwable;

    .line 92
    .line 93
    .line 94
    move-result-object v0

    .line 95
    instance-of v0, v0, Landroidx/glance/appwidget/protobuf/a0;

    .line 96
    .line 97
    if-eqz v0, :cond_3

    .line 98
    .line 99
    invoke-virtual {p0}, Ljava/lang/Throwable;->getCause()Ljava/lang/Throwable;

    .line 100
    .line 101
    .line 102
    move-result-object p0

    .line 103
    check-cast p0, Landroidx/glance/appwidget/protobuf/a0;

    .line 104
    .line 105
    throw p0

    .line 106
    :cond_3
    new-instance v0, Landroidx/glance/appwidget/protobuf/a0;

    .line 107
    .line 108
    invoke-virtual {p0}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    .line 109
    .line 110
    .line 111
    move-result-object v1

    .line 112
    invoke-direct {v0, v1, p0}, Ljava/io/IOException;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 113
    .line 114
    .line 115
    throw v0

    .line 116
    :catch_2
    move-exception p0

    .line 117
    new-instance v0, Landroidx/glance/appwidget/protobuf/a0;

    .line 118
    .line 119
    invoke-virtual {p0}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    .line 120
    .line 121
    .line 122
    move-result-object p0

    .line 123
    invoke-direct {v0, p0}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    .line 124
    .line 125
    .line 126
    throw v0

    .line 127
    :catch_3
    move-exception p0

    .line 128
    iget-boolean v0, p0, Landroidx/glance/appwidget/protobuf/a0;->d:Z

    .line 129
    .line 130
    if-eqz v0, :cond_4

    .line 131
    .line 132
    new-instance v0, Landroidx/glance/appwidget/protobuf/a0;

    .line 133
    .line 134
    invoke-virtual {p0}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    .line 135
    .line 136
    .line 137
    move-result-object v1

    .line 138
    invoke-direct {v0, v1, p0}, Ljava/io/IOException;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 139
    .line 140
    .line 141
    move-object p0, v0

    .line 142
    :cond_4
    throw p0
.end method


# virtual methods
.method public final b(I)Ljava/lang/Object;
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
    sget-object p0, Lc7/e;->PARSER:Landroidx/glance/appwidget/protobuf/r0;

    .line 15
    .line 16
    if-nez p0, :cond_1

    .line 17
    .line 18
    const-class p1, Lc7/e;

    .line 19
    .line 20
    monitor-enter p1

    .line 21
    :try_start_0
    sget-object p0, Lc7/e;->PARSER:Landroidx/glance/appwidget/protobuf/r0;

    .line 22
    .line 23
    if-nez p0, :cond_0

    .line 24
    .line 25
    new-instance p0, Landroidx/glance/appwidget/protobuf/t;

    .line 26
    .line 27
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 28
    .line 29
    .line 30
    sput-object p0, Lc7/e;->PARSER:Landroidx/glance/appwidget/protobuf/r0;

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
    sget-object p0, Lc7/e;->DEFAULT_INSTANCE:Lc7/e;

    .line 41
    .line 42
    return-object p0

    .line 43
    :pswitch_2
    new-instance p0, Lc7/d;

    .line 44
    .line 45
    sget-object p1, Lc7/e;->DEFAULT_INSTANCE:Lc7/e;

    .line 46
    .line 47
    invoke-direct {p0, p1}, Landroidx/glance/appwidget/protobuf/s;-><init>(Landroidx/glance/appwidget/protobuf/u;)V

    .line 48
    .line 49
    .line 50
    return-object p0

    .line 51
    :pswitch_3
    new-instance p0, Lc7/e;

    .line 52
    .line 53
    invoke-direct {p0}, Lc7/e;-><init>()V

    .line 54
    .line 55
    .line 56
    return-object p0

    .line 57
    :pswitch_4
    const-string p0, "layout_"

    .line 58
    .line 59
    const-class p1, Lc7/g;

    .line 60
    .line 61
    const-string v0, "nextIndex_"

    .line 62
    .line 63
    filled-new-array {p0, p1, v0}, [Ljava/lang/Object;

    .line 64
    .line 65
    .line 66
    move-result-object p0

    .line 67
    const-string p1, "\u0000\u0002\u0000\u0000\u0001\u0002\u0002\u0000\u0001\u0000\u0001\u001b\u0002\u0004"

    .line 68
    .line 69
    sget-object v0, Lc7/e;->DEFAULT_INSTANCE:Lc7/e;

    .line 70
    .line 71
    new-instance v1, Landroidx/glance/appwidget/protobuf/u0;

    .line 72
    .line 73
    invoke-direct {v1, v0, p1, p0}, Landroidx/glance/appwidget/protobuf/u0;-><init>(Landroidx/glance/appwidget/protobuf/u;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 74
    .line 75
    .line 76
    return-object v1

    .line 77
    :pswitch_5
    const/4 p0, 0x0

    .line 78
    return-object p0

    .line 79
    :pswitch_6
    const/4 p0, 0x1

    .line 80
    invoke-static {p0}, Ljava/lang/Byte;->valueOf(B)Ljava/lang/Byte;

    .line 81
    .line 82
    .line 83
    move-result-object p0

    .line 84
    return-object p0

    .line 85
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

.method public final o()Landroidx/glance/appwidget/protobuf/x;
    .locals 0

    .line 1
    iget-object p0, p0, Lc7/e;->layout_:Landroidx/glance/appwidget/protobuf/x;

    .line 2
    .line 3
    return-object p0
.end method

.method public final p()I
    .locals 0

    .line 1
    iget p0, p0, Lc7/e;->nextIndex_:I

    .line 2
    .line 3
    return p0
.end method
