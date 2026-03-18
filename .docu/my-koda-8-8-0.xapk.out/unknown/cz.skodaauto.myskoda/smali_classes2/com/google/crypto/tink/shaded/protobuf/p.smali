.class public final Lcom/google/crypto/tink/shaded/protobuf/p;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static volatile a:Lcom/google/crypto/tink/shaded/protobuf/p;

.field public static final b:Lcom/google/crypto/tink/shaded/protobuf/p;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lcom/google/crypto/tink/shaded/protobuf/p;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sget-object v1, Ljava/util/Collections;->EMPTY_MAP:Ljava/util/Map;

    .line 7
    .line 8
    sput-object v0, Lcom/google/crypto/tink/shaded/protobuf/p;->b:Lcom/google/crypto/tink/shaded/protobuf/p;

    .line 9
    .line 10
    return-void
.end method

.method public static a()Lcom/google/crypto/tink/shaded/protobuf/p;
    .locals 4

    .line 1
    sget-object v0, Lcom/google/crypto/tink/shaded/protobuf/p;->a:Lcom/google/crypto/tink/shaded/protobuf/p;

    .line 2
    .line 3
    if-nez v0, :cond_3

    .line 4
    .line 5
    const-class v1, Lcom/google/crypto/tink/shaded/protobuf/p;

    .line 6
    .line 7
    monitor-enter v1

    .line 8
    :try_start_0
    sget-object v0, Lcom/google/crypto/tink/shaded/protobuf/p;->a:Lcom/google/crypto/tink/shaded/protobuf/p;

    .line 9
    .line 10
    if-nez v0, :cond_2

    .line 11
    .line 12
    const-string v0, "getEmptyRegistry"

    .line 13
    .line 14
    sget-object v2, Lcom/google/crypto/tink/shaded/protobuf/o;->a:Ljava/lang/Class;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 15
    .line 16
    const/4 v3, 0x0

    .line 17
    if-nez v2, :cond_0

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    :try_start_1
    invoke-virtual {v2, v0, v3}, Ljava/lang/Class;->getDeclaredMethod(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;

    .line 21
    .line 22
    .line 23
    move-result-object v0

    .line 24
    invoke-virtual {v0, v3, v3}, Ljava/lang/reflect/Method;->invoke(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;

    .line 25
    .line 26
    .line 27
    move-result-object v0

    .line 28
    check-cast v0, Lcom/google/crypto/tink/shaded/protobuf/p;
    :try_end_1
    .catch Ljava/lang/Exception; {:try_start_1 .. :try_end_1} :catch_0
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 29
    .line 30
    move-object v3, v0

    .line 31
    :catch_0
    :goto_0
    if-eqz v3, :cond_1

    .line 32
    .line 33
    move-object v0, v3

    .line 34
    goto :goto_1

    .line 35
    :cond_1
    :try_start_2
    sget-object v0, Lcom/google/crypto/tink/shaded/protobuf/p;->b:Lcom/google/crypto/tink/shaded/protobuf/p;

    .line 36
    .line 37
    :goto_1
    sput-object v0, Lcom/google/crypto/tink/shaded/protobuf/p;->a:Lcom/google/crypto/tink/shaded/protobuf/p;

    .line 38
    .line 39
    goto :goto_2

    .line 40
    :catchall_0
    move-exception v0

    .line 41
    goto :goto_3

    .line 42
    :cond_2
    :goto_2
    monitor-exit v1

    .line 43
    return-object v0

    .line 44
    :goto_3
    monitor-exit v1
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 45
    throw v0

    .line 46
    :cond_3
    return-object v0
.end method
