.class public abstract Lcom/google/crypto/tink/shaded/protobuf/x;
.super Lcom/google/crypto/tink/shaded/protobuf/a;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field private static defaultInstanceMap:Ljava/util/Map;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/Map<",
            "Ljava/lang/Object;",
            "Lcom/google/crypto/tink/shaded/protobuf/x;",
            ">;"
        }
    .end annotation
.end field


# instance fields
.field protected memoizedSerializedSize:I

.field protected unknownFields:Lcom/google/crypto/tink/shaded/protobuf/c1;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Ljava/util/concurrent/ConcurrentHashMap;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/util/concurrent/ConcurrentHashMap;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lcom/google/crypto/tink/shaded/protobuf/x;->defaultInstanceMap:Ljava/util/Map;

    .line 7
    .line 8
    return-void
.end method

.method public constructor <init>()V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    const/4 v0, 0x0

    .line 5
    iput v0, p0, Lcom/google/crypto/tink/shaded/protobuf/a;->memoizedHashCode:I

    .line 6
    .line 7
    sget-object v0, Lcom/google/crypto/tink/shaded/protobuf/c1;->f:Lcom/google/crypto/tink/shaded/protobuf/c1;

    .line 8
    .line 9
    iput-object v0, p0, Lcom/google/crypto/tink/shaded/protobuf/x;->unknownFields:Lcom/google/crypto/tink/shaded/protobuf/c1;

    .line 10
    .line 11
    const/4 v0, -0x1

    .line 12
    iput v0, p0, Lcom/google/crypto/tink/shaded/protobuf/x;->memoizedSerializedSize:I

    .line 13
    .line 14
    return-void
.end method

.method public static g(Ljava/lang/Class;)Lcom/google/crypto/tink/shaded/protobuf/x;
    .locals 3

    .line 1
    sget-object v0, Lcom/google/crypto/tink/shaded/protobuf/x;->defaultInstanceMap:Ljava/util/Map;

    .line 2
    .line 3
    invoke-interface {v0, p0}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, Lcom/google/crypto/tink/shaded/protobuf/x;

    .line 8
    .line 9
    if-nez v0, :cond_0

    .line 10
    .line 11
    :try_start_0
    invoke-virtual {p0}, Ljava/lang/Class;->getName()Ljava/lang/String;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    invoke-virtual {p0}, Ljava/lang/Class;->getClassLoader()Ljava/lang/ClassLoader;

    .line 16
    .line 17
    .line 18
    move-result-object v1

    .line 19
    const/4 v2, 0x1

    .line 20
    invoke-static {v0, v2, v1}, Ljava/lang/Class;->forName(Ljava/lang/String;ZLjava/lang/ClassLoader;)Ljava/lang/Class;
    :try_end_0
    .catch Ljava/lang/ClassNotFoundException; {:try_start_0 .. :try_end_0} :catch_0

    .line 21
    .line 22
    .line 23
    sget-object v0, Lcom/google/crypto/tink/shaded/protobuf/x;->defaultInstanceMap:Ljava/util/Map;

    .line 24
    .line 25
    invoke-interface {v0, p0}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 26
    .line 27
    .line 28
    move-result-object v0

    .line 29
    check-cast v0, Lcom/google/crypto/tink/shaded/protobuf/x;

    .line 30
    .line 31
    goto :goto_0

    .line 32
    :catch_0
    move-exception p0

    .line 33
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 34
    .line 35
    const-string v1, "Class initialization cannot fail."

    .line 36
    .line 37
    invoke-direct {v0, v1, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 38
    .line 39
    .line 40
    throw v0

    .line 41
    :cond_0
    :goto_0
    if-nez v0, :cond_2

    .line 42
    .line 43
    invoke-static {p0}, Lcom/google/crypto/tink/shaded/protobuf/l1;->a(Ljava/lang/Class;)Ljava/lang/Object;

    .line 44
    .line 45
    .line 46
    move-result-object v0

    .line 47
    check-cast v0, Lcom/google/crypto/tink/shaded/protobuf/x;

    .line 48
    .line 49
    const/4 v1, 0x6

    .line 50
    invoke-virtual {v0, v1}, Lcom/google/crypto/tink/shaded/protobuf/x;->f(I)Ljava/lang/Object;

    .line 51
    .line 52
    .line 53
    move-result-object v0

    .line 54
    check-cast v0, Lcom/google/crypto/tink/shaded/protobuf/x;

    .line 55
    .line 56
    if-eqz v0, :cond_1

    .line 57
    .line 58
    sget-object v1, Lcom/google/crypto/tink/shaded/protobuf/x;->defaultInstanceMap:Ljava/util/Map;

    .line 59
    .line 60
    invoke-interface {v1, p0, v0}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 61
    .line 62
    .line 63
    return-object v0

    .line 64
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 65
    .line 66
    invoke-direct {p0}, Ljava/lang/IllegalStateException;-><init>()V

    .line 67
    .line 68
    .line 69
    throw p0

    .line 70
    :cond_2
    return-object v0
.end method

.method public static varargs h(Ljava/lang/reflect/Method;Lcom/google/crypto/tink/shaded/protobuf/x;[Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    .line 1
    :try_start_0
    invoke-virtual {p0, p1, p2}, Ljava/lang/reflect/Method;->invoke(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;

    .line 2
    .line 3
    .line 4
    move-result-object p0
    :try_end_0
    .catch Ljava/lang/IllegalAccessException; {:try_start_0 .. :try_end_0} :catch_1
    .catch Ljava/lang/reflect/InvocationTargetException; {:try_start_0 .. :try_end_0} :catch_0

    .line 5
    return-object p0

    .line 6
    :catch_0
    move-exception p0

    .line 7
    invoke-virtual {p0}, Ljava/lang/reflect/InvocationTargetException;->getCause()Ljava/lang/Throwable;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    instance-of p1, p0, Ljava/lang/RuntimeException;

    .line 12
    .line 13
    if-nez p1, :cond_1

    .line 14
    .line 15
    instance-of p1, p0, Ljava/lang/Error;

    .line 16
    .line 17
    if-eqz p1, :cond_0

    .line 18
    .line 19
    check-cast p0, Ljava/lang/Error;

    .line 20
    .line 21
    throw p0

    .line 22
    :cond_0
    new-instance p1, Ljava/lang/RuntimeException;

    .line 23
    .line 24
    const-string p2, "Unexpected exception thrown by generated accessor method."

    .line 25
    .line 26
    invoke-direct {p1, p2, p0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 27
    .line 28
    .line 29
    throw p1

    .line 30
    :cond_1
    check-cast p0, Ljava/lang/RuntimeException;

    .line 31
    .line 32
    throw p0

    .line 33
    :catch_1
    move-exception p0

    .line 34
    new-instance p1, Ljava/lang/RuntimeException;

    .line 35
    .line 36
    const-string p2, "Couldn\'t use Java reflection to implement protocol message reflection."

    .line 37
    .line 38
    invoke-direct {p1, p2, p0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 39
    .line 40
    .line 41
    throw p1
.end method

.method public static j(Lcom/google/crypto/tink/shaded/protobuf/x;Lcom/google/crypto/tink/shaded/protobuf/i;Lcom/google/crypto/tink/shaded/protobuf/p;)Lcom/google/crypto/tink/shaded/protobuf/x;
    .locals 4

    .line 1
    check-cast p1, Lcom/google/crypto/tink/shaded/protobuf/h;

    .line 2
    .line 3
    iget-object v0, p1, Lcom/google/crypto/tink/shaded/protobuf/h;->g:[B

    .line 4
    .line 5
    invoke-virtual {p1}, Lcom/google/crypto/tink/shaded/protobuf/h;->m()I

    .line 6
    .line 7
    .line 8
    move-result v1

    .line 9
    invoke-virtual {p1}, Lcom/google/crypto/tink/shaded/protobuf/h;->size()I

    .line 10
    .line 11
    .line 12
    move-result p1

    .line 13
    new-instance v2, Lcom/google/crypto/tink/shaded/protobuf/j;

    .line 14
    .line 15
    const/4 v3, 0x1

    .line 16
    invoke-direct {v2, v0, v1, p1, v3}, Lcom/google/crypto/tink/shaded/protobuf/j;-><init>([BIIZ)V

    .line 17
    .line 18
    .line 19
    :try_start_0
    invoke-virtual {v2, p1}, Lcom/google/crypto/tink/shaded/protobuf/j;->e(I)I
    :try_end_0
    .catch Lcom/google/crypto/tink/shaded/protobuf/d0; {:try_start_0 .. :try_end_0} :catch_2

    .line 20
    .line 21
    .line 22
    const/4 p1, 0x4

    .line 23
    invoke-virtual {p0, p1}, Lcom/google/crypto/tink/shaded/protobuf/x;->f(I)Ljava/lang/Object;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    check-cast p0, Lcom/google/crypto/tink/shaded/protobuf/x;

    .line 28
    .line 29
    :try_start_1
    sget-object p1, Lcom/google/crypto/tink/shaded/protobuf/x0;->c:Lcom/google/crypto/tink/shaded/protobuf/x0;

    .line 30
    .line 31
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 32
    .line 33
    .line 34
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 35
    .line 36
    .line 37
    move-result-object v0

    .line 38
    invoke-virtual {p1, v0}, Lcom/google/crypto/tink/shaded/protobuf/x0;->a(Ljava/lang/Class;)Lcom/google/crypto/tink/shaded/protobuf/a1;

    .line 39
    .line 40
    .line 41
    move-result-object p1

    .line 42
    iget-object v0, v2, Lcom/google/crypto/tink/shaded/protobuf/j;->b:Landroidx/collection/h;

    .line 43
    .line 44
    if-eqz v0, :cond_0

    .line 45
    .line 46
    goto :goto_0

    .line 47
    :cond_0
    new-instance v0, Landroidx/collection/h;

    .line 48
    .line 49
    invoke-direct {v0, v2}, Landroidx/collection/h;-><init>(Lcom/google/crypto/tink/shaded/protobuf/j;)V

    .line 50
    .line 51
    .line 52
    :goto_0
    invoke-interface {p1, p0, v0, p2}, Lcom/google/crypto/tink/shaded/protobuf/a1;->f(Ljava/lang/Object;Landroidx/collection/h;Lcom/google/crypto/tink/shaded/protobuf/p;)V

    .line 53
    .line 54
    .line 55
    invoke-interface {p1, p0}, Lcom/google/crypto/tink/shaded/protobuf/a1;->a(Ljava/lang/Object;)V
    :try_end_1
    .catch Ljava/io/IOException; {:try_start_1 .. :try_end_1} :catch_1
    .catch Ljava/lang/RuntimeException; {:try_start_1 .. :try_end_1} :catch_0

    .line 56
    .line 57
    .line 58
    iget p1, v2, Lcom/google/crypto/tink/shaded/protobuf/j;->h:I

    .line 59
    .line 60
    if-nez p1, :cond_2

    .line 61
    .line 62
    invoke-virtual {p0}, Lcom/google/crypto/tink/shaded/protobuf/x;->i()Z

    .line 63
    .line 64
    .line 65
    move-result p1

    .line 66
    if-eqz p1, :cond_1

    .line 67
    .line 68
    return-object p0

    .line 69
    :cond_1
    new-instance p0, La8/r0;

    .line 70
    .line 71
    invoke-direct {p0}, La8/r0;-><init>()V

    .line 72
    .line 73
    .line 74
    new-instance p1, Lcom/google/crypto/tink/shaded/protobuf/d0;

    .line 75
    .line 76
    invoke-virtual {p0}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    .line 77
    .line 78
    .line 79
    move-result-object p0

    .line 80
    invoke-direct {p1, p0}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    .line 81
    .line 82
    .line 83
    throw p1

    .line 84
    :cond_2
    new-instance p0, Lcom/google/crypto/tink/shaded/protobuf/d0;

    .line 85
    .line 86
    const-string p1, "Protocol message end-group tag did not match expected tag."

    .line 87
    .line 88
    invoke-direct {p0, p1}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    .line 89
    .line 90
    .line 91
    throw p0

    .line 92
    :catch_0
    move-exception p0

    .line 93
    invoke-virtual {p0}, Ljava/lang/Throwable;->getCause()Ljava/lang/Throwable;

    .line 94
    .line 95
    .line 96
    move-result-object p1

    .line 97
    instance-of p1, p1, Lcom/google/crypto/tink/shaded/protobuf/d0;

    .line 98
    .line 99
    if-eqz p1, :cond_3

    .line 100
    .line 101
    invoke-virtual {p0}, Ljava/lang/Throwable;->getCause()Ljava/lang/Throwable;

    .line 102
    .line 103
    .line 104
    move-result-object p0

    .line 105
    check-cast p0, Lcom/google/crypto/tink/shaded/protobuf/d0;

    .line 106
    .line 107
    throw p0

    .line 108
    :cond_3
    throw p0

    .line 109
    :catch_1
    move-exception p0

    .line 110
    invoke-virtual {p0}, Ljava/lang/Throwable;->getCause()Ljava/lang/Throwable;

    .line 111
    .line 112
    .line 113
    move-result-object p1

    .line 114
    instance-of p1, p1, Lcom/google/crypto/tink/shaded/protobuf/d0;

    .line 115
    .line 116
    if-eqz p1, :cond_4

    .line 117
    .line 118
    invoke-virtual {p0}, Ljava/lang/Throwable;->getCause()Ljava/lang/Throwable;

    .line 119
    .line 120
    .line 121
    move-result-object p0

    .line 122
    check-cast p0, Lcom/google/crypto/tink/shaded/protobuf/d0;

    .line 123
    .line 124
    throw p0

    .line 125
    :cond_4
    new-instance p1, Lcom/google/crypto/tink/shaded/protobuf/d0;

    .line 126
    .line 127
    invoke-virtual {p0}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    .line 128
    .line 129
    .line 130
    move-result-object p0

    .line 131
    invoke-direct {p1, p0}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    .line 132
    .line 133
    .line 134
    throw p1

    .line 135
    :catch_2
    move-exception p0

    .line 136
    new-instance p1, Ljava/lang/IllegalArgumentException;

    .line 137
    .line 138
    invoke-direct {p1, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/Throwable;)V

    .line 139
    .line 140
    .line 141
    throw p1
.end method

.method public static k(Lcom/google/crypto/tink/shaded/protobuf/x;[BLcom/google/crypto/tink/shaded/protobuf/p;)Lcom/google/crypto/tink/shaded/protobuf/x;
    .locals 6

    .line 1
    array-length v4, p1

    .line 2
    const/4 v0, 0x4

    .line 3
    invoke-virtual {p0, v0}, Lcom/google/crypto/tink/shaded/protobuf/x;->f(I)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    move-object v1, p0

    .line 8
    check-cast v1, Lcom/google/crypto/tink/shaded/protobuf/x;

    .line 9
    .line 10
    :try_start_0
    sget-object p0, Lcom/google/crypto/tink/shaded/protobuf/x0;->c:Lcom/google/crypto/tink/shaded/protobuf/x0;

    .line 11
    .line 12
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 13
    .line 14
    .line 15
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 16
    .line 17
    .line 18
    move-result-object v0

    .line 19
    invoke-virtual {p0, v0}, Lcom/google/crypto/tink/shaded/protobuf/x0;->a(Ljava/lang/Class;)Lcom/google/crypto/tink/shaded/protobuf/a1;

    .line 20
    .line 21
    .line 22
    move-result-object v0

    .line 23
    new-instance v5, Lcom/google/crypto/tink/shaded/protobuf/d;

    .line 24
    .line 25
    invoke-direct {v5}, Ljava/lang/Object;-><init>()V

    .line 26
    .line 27
    .line 28
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 29
    .line 30
    .line 31
    const/4 v3, 0x0

    .line 32
    move-object v2, p1

    .line 33
    invoke-interface/range {v0 .. v5}, Lcom/google/crypto/tink/shaded/protobuf/a1;->e(Ljava/lang/Object;[BIILcom/google/crypto/tink/shaded/protobuf/d;)V

    .line 34
    .line 35
    .line 36
    invoke-interface {v0, v1}, Lcom/google/crypto/tink/shaded/protobuf/a1;->a(Ljava/lang/Object;)V

    .line 37
    .line 38
    .line 39
    iget p0, v1, Lcom/google/crypto/tink/shaded/protobuf/a;->memoizedHashCode:I
    :try_end_0
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_1
    .catch Ljava/lang/IndexOutOfBoundsException; {:try_start_0 .. :try_end_0} :catch_0

    .line 40
    .line 41
    if-nez p0, :cond_1

    .line 42
    .line 43
    invoke-virtual {v1}, Lcom/google/crypto/tink/shaded/protobuf/x;->i()Z

    .line 44
    .line 45
    .line 46
    move-result p0

    .line 47
    if-eqz p0, :cond_0

    .line 48
    .line 49
    return-object v1

    .line 50
    :cond_0
    new-instance p0, La8/r0;

    .line 51
    .line 52
    invoke-direct {p0}, La8/r0;-><init>()V

    .line 53
    .line 54
    .line 55
    new-instance p1, Lcom/google/crypto/tink/shaded/protobuf/d0;

    .line 56
    .line 57
    invoke-virtual {p0}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    .line 58
    .line 59
    .line 60
    move-result-object p0

    .line 61
    invoke-direct {p1, p0}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    .line 62
    .line 63
    .line 64
    throw p1

    .line 65
    :cond_1
    :try_start_1
    new-instance p0, Ljava/lang/RuntimeException;

    .line 66
    .line 67
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 68
    .line 69
    .line 70
    throw p0
    :try_end_1
    .catch Ljava/io/IOException; {:try_start_1 .. :try_end_1} :catch_1
    .catch Ljava/lang/IndexOutOfBoundsException; {:try_start_1 .. :try_end_1} :catch_0

    .line 71
    :catch_0
    invoke-static {}, Lcom/google/crypto/tink/shaded/protobuf/d0;->f()Lcom/google/crypto/tink/shaded/protobuf/d0;

    .line 72
    .line 73
    .line 74
    move-result-object p0

    .line 75
    throw p0

    .line 76
    :catch_1
    move-exception v0

    .line 77
    move-object p0, v0

    .line 78
    invoke-virtual {p0}, Ljava/lang/Throwable;->getCause()Ljava/lang/Throwable;

    .line 79
    .line 80
    .line 81
    move-result-object p1

    .line 82
    instance-of p1, p1, Lcom/google/crypto/tink/shaded/protobuf/d0;

    .line 83
    .line 84
    if-eqz p1, :cond_2

    .line 85
    .line 86
    invoke-virtual {p0}, Ljava/lang/Throwable;->getCause()Ljava/lang/Throwable;

    .line 87
    .line 88
    .line 89
    move-result-object p0

    .line 90
    check-cast p0, Lcom/google/crypto/tink/shaded/protobuf/d0;

    .line 91
    .line 92
    throw p0

    .line 93
    :cond_2
    new-instance p1, Lcom/google/crypto/tink/shaded/protobuf/d0;

    .line 94
    .line 95
    invoke-virtual {p0}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    .line 96
    .line 97
    .line 98
    move-result-object p0

    .line 99
    invoke-direct {p1, p0}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    .line 100
    .line 101
    .line 102
    throw p1
.end method

.method public static l(Ljava/lang/Class;Lcom/google/crypto/tink/shaded/protobuf/x;)V
    .locals 1

    .line 1
    sget-object v0, Lcom/google/crypto/tink/shaded/protobuf/x;->defaultInstanceMap:Ljava/util/Map;

    .line 2
    .line 3
    invoke-interface {v0, p0, p1}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final a()I
    .locals 2

    .line 1
    iget v0, p0, Lcom/google/crypto/tink/shaded/protobuf/x;->memoizedSerializedSize:I

    .line 2
    .line 3
    const/4 v1, -0x1

    .line 4
    if-ne v0, v1, :cond_0

    .line 5
    .line 6
    sget-object v0, Lcom/google/crypto/tink/shaded/protobuf/x0;->c:Lcom/google/crypto/tink/shaded/protobuf/x0;

    .line 7
    .line 8
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 9
    .line 10
    .line 11
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 12
    .line 13
    .line 14
    move-result-object v1

    .line 15
    invoke-virtual {v0, v1}, Lcom/google/crypto/tink/shaded/protobuf/x0;->a(Ljava/lang/Class;)Lcom/google/crypto/tink/shaded/protobuf/a1;

    .line 16
    .line 17
    .line 18
    move-result-object v0

    .line 19
    invoke-interface {v0, p0}, Lcom/google/crypto/tink/shaded/protobuf/a1;->i(Lcom/google/crypto/tink/shaded/protobuf/a;)I

    .line 20
    .line 21
    .line 22
    move-result v0

    .line 23
    iput v0, p0, Lcom/google/crypto/tink/shaded/protobuf/x;->memoizedSerializedSize:I

    .line 24
    .line 25
    :cond_0
    iget p0, p0, Lcom/google/crypto/tink/shaded/protobuf/x;->memoizedSerializedSize:I

    .line 26
    .line 27
    return p0
.end method

.method public final d(Lcom/google/crypto/tink/shaded/protobuf/k;)V
    .locals 2

    .line 1
    sget-object v0, Lcom/google/crypto/tink/shaded/protobuf/x0;->c:Lcom/google/crypto/tink/shaded/protobuf/x0;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 7
    .line 8
    .line 9
    move-result-object v1

    .line 10
    invoke-virtual {v0, v1}, Lcom/google/crypto/tink/shaded/protobuf/x0;->a(Ljava/lang/Class;)Lcom/google/crypto/tink/shaded/protobuf/a1;

    .line 11
    .line 12
    .line 13
    move-result-object v0

    .line 14
    iget-object v1, p1, Lcom/google/crypto/tink/shaded/protobuf/k;->a:Lcom/google/crypto/tink/shaded/protobuf/m;

    .line 15
    .line 16
    if-eqz v1, :cond_0

    .line 17
    .line 18
    goto :goto_0

    .line 19
    :cond_0
    new-instance v1, Lcom/google/crypto/tink/shaded/protobuf/m;

    .line 20
    .line 21
    invoke-direct {v1, p1}, Lcom/google/crypto/tink/shaded/protobuf/m;-><init>(Lcom/google/crypto/tink/shaded/protobuf/k;)V

    .line 22
    .line 23
    .line 24
    :goto_0
    invoke-interface {v0, p0, v1}, Lcom/google/crypto/tink/shaded/protobuf/a1;->d(Ljava/lang/Object;Lcom/google/crypto/tink/shaded/protobuf/m;)V

    .line 25
    .line 26
    .line 27
    return-void
.end method

.method public final e()Lcom/google/crypto/tink/shaded/protobuf/v;
    .locals 1

    .line 1
    const/4 v0, 0x5

    .line 2
    invoke-virtual {p0, v0}, Lcom/google/crypto/tink/shaded/protobuf/x;->f(I)Ljava/lang/Object;

    .line 3
    .line 4
    .line 5
    move-result-object p0

    .line 6
    check-cast p0, Lcom/google/crypto/tink/shaded/protobuf/v;

    .line 7
    .line 8
    return-object p0
.end method

.method public final equals(Ljava/lang/Object;)Z
    .locals 2

    .line 1
    if-ne p0, p1, :cond_0

    .line 2
    .line 3
    const/4 p0, 0x1

    .line 4
    return p0

    .line 5
    :cond_0
    const/4 v0, 0x6

    .line 6
    invoke-virtual {p0, v0}, Lcom/google/crypto/tink/shaded/protobuf/x;->f(I)Ljava/lang/Object;

    .line 7
    .line 8
    .line 9
    move-result-object v0

    .line 10
    check-cast v0, Lcom/google/crypto/tink/shaded/protobuf/x;

    .line 11
    .line 12
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 13
    .line 14
    .line 15
    move-result-object v0

    .line 16
    invoke-virtual {v0, p1}, Ljava/lang/Class;->isInstance(Ljava/lang/Object;)Z

    .line 17
    .line 18
    .line 19
    move-result v0

    .line 20
    if-nez v0, :cond_1

    .line 21
    .line 22
    const/4 p0, 0x0

    .line 23
    return p0

    .line 24
    :cond_1
    sget-object v0, Lcom/google/crypto/tink/shaded/protobuf/x0;->c:Lcom/google/crypto/tink/shaded/protobuf/x0;

    .line 25
    .line 26
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 27
    .line 28
    .line 29
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 30
    .line 31
    .line 32
    move-result-object v1

    .line 33
    invoke-virtual {v0, v1}, Lcom/google/crypto/tink/shaded/protobuf/x0;->a(Ljava/lang/Class;)Lcom/google/crypto/tink/shaded/protobuf/a1;

    .line 34
    .line 35
    .line 36
    move-result-object v0

    .line 37
    check-cast p1, Lcom/google/crypto/tink/shaded/protobuf/x;

    .line 38
    .line 39
    invoke-interface {v0, p0, p1}, Lcom/google/crypto/tink/shaded/protobuf/a1;->g(Lcom/google/crypto/tink/shaded/protobuf/x;Lcom/google/crypto/tink/shaded/protobuf/x;)Z

    .line 40
    .line 41
    .line 42
    move-result p0

    .line 43
    return p0
.end method

.method public abstract f(I)Ljava/lang/Object;
.end method

.method public final hashCode()I
    .locals 2

    .line 1
    iget v0, p0, Lcom/google/crypto/tink/shaded/protobuf/a;->memoizedHashCode:I

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    return v0

    .line 6
    :cond_0
    sget-object v0, Lcom/google/crypto/tink/shaded/protobuf/x0;->c:Lcom/google/crypto/tink/shaded/protobuf/x0;

    .line 7
    .line 8
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 9
    .line 10
    .line 11
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 12
    .line 13
    .line 14
    move-result-object v1

    .line 15
    invoke-virtual {v0, v1}, Lcom/google/crypto/tink/shaded/protobuf/x0;->a(Ljava/lang/Class;)Lcom/google/crypto/tink/shaded/protobuf/a1;

    .line 16
    .line 17
    .line 18
    move-result-object v0

    .line 19
    invoke-interface {v0, p0}, Lcom/google/crypto/tink/shaded/protobuf/a1;->h(Lcom/google/crypto/tink/shaded/protobuf/x;)I

    .line 20
    .line 21
    .line 22
    move-result v0

    .line 23
    iput v0, p0, Lcom/google/crypto/tink/shaded/protobuf/a;->memoizedHashCode:I

    .line 24
    .line 25
    return v0
.end method

.method public final i()Z
    .locals 2

    .line 1
    const/4 v0, 0x1

    .line 2
    invoke-virtual {p0, v0}, Lcom/google/crypto/tink/shaded/protobuf/x;->f(I)Ljava/lang/Object;

    .line 3
    .line 4
    .line 5
    move-result-object v1

    .line 6
    check-cast v1, Ljava/lang/Byte;

    .line 7
    .line 8
    invoke-virtual {v1}, Ljava/lang/Byte;->byteValue()B

    .line 9
    .line 10
    .line 11
    move-result v1

    .line 12
    if-ne v1, v0, :cond_0

    .line 13
    .line 14
    return v0

    .line 15
    :cond_0
    if-nez v1, :cond_1

    .line 16
    .line 17
    const/4 p0, 0x0

    .line 18
    return p0

    .line 19
    :cond_1
    sget-object v0, Lcom/google/crypto/tink/shaded/protobuf/x0;->c:Lcom/google/crypto/tink/shaded/protobuf/x0;

    .line 20
    .line 21
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 22
    .line 23
    .line 24
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 25
    .line 26
    .line 27
    move-result-object v1

    .line 28
    invoke-virtual {v0, v1}, Lcom/google/crypto/tink/shaded/protobuf/x0;->a(Ljava/lang/Class;)Lcom/google/crypto/tink/shaded/protobuf/a1;

    .line 29
    .line 30
    .line 31
    move-result-object v0

    .line 32
    invoke-interface {v0, p0}, Lcom/google/crypto/tink/shaded/protobuf/a1;->b(Ljava/lang/Object;)Z

    .line 33
    .line 34
    .line 35
    move-result v0

    .line 36
    const/4 v1, 0x2

    .line 37
    invoke-virtual {p0, v1}, Lcom/google/crypto/tink/shaded/protobuf/x;->f(I)Ljava/lang/Object;

    .line 38
    .line 39
    .line 40
    return v0
.end method

.method public final toString()Ljava/lang/String;
    .locals 3

    .line 1
    invoke-super {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    new-instance v1, Ljava/lang/StringBuilder;

    .line 6
    .line 7
    invoke-direct {v1}, Ljava/lang/StringBuilder;-><init>()V

    .line 8
    .line 9
    .line 10
    const-string v2, "# "

    .line 11
    .line 12
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 13
    .line 14
    .line 15
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    const/4 v0, 0x0

    .line 19
    invoke-static {p0, v1, v0}, Lcom/google/crypto/tink/shaded/protobuf/q0;->y(Lcom/google/crypto/tink/shaded/protobuf/x;Ljava/lang/StringBuilder;I)V

    .line 20
    .line 21
    .line 22
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 23
    .line 24
    .line 25
    move-result-object p0

    .line 26
    return-object p0
.end method
