.class public final Lqr/y;
.super Lcom/google/crypto/tink/shaded/protobuf/x;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field private static final DEFAULT_INSTANCE:Lqr/y;

.field public static final KEY_FIELD_NUMBER:I = 0x2

.field private static volatile PARSER:Lcom/google/crypto/tink/shaded/protobuf/v0; = null
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lcom/google/crypto/tink/shaded/protobuf/v0;"
        }
    .end annotation
.end field

.field public static final PRIMARY_KEY_ID_FIELD_NUMBER:I = 0x1


# instance fields
.field private key_:Lcom/google/crypto/tink/shaded/protobuf/a0;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lcom/google/crypto/tink/shaded/protobuf/a0;"
        }
    .end annotation
.end field

.field private primaryKeyId_:I


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lqr/y;

    .line 2
    .line 3
    invoke-direct {v0}, Lqr/y;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lqr/y;->DEFAULT_INSTANCE:Lqr/y;

    .line 7
    .line 8
    const-class v1, Lqr/y;

    .line 9
    .line 10
    invoke-static {v1, v0}, Lcom/google/crypto/tink/shaded/protobuf/x;->l(Ljava/lang/Class;Lcom/google/crypto/tink/shaded/protobuf/x;)V

    .line 11
    .line 12
    .line 13
    return-void
.end method

.method public constructor <init>()V
    .locals 1

    .line 1
    invoke-direct {p0}, Lcom/google/crypto/tink/shaded/protobuf/x;-><init>()V

    .line 2
    .line 3
    .line 4
    sget-object v0, Lcom/google/crypto/tink/shaded/protobuf/y0;->g:Lcom/google/crypto/tink/shaded/protobuf/y0;

    .line 5
    .line 6
    iput-object v0, p0, Lqr/y;->key_:Lcom/google/crypto/tink/shaded/protobuf/a0;

    .line 7
    .line 8
    return-void
.end method

.method public static m(Lqr/y;I)V
    .locals 0

    .line 1
    iput p1, p0, Lqr/y;->primaryKeyId_:I

    .line 2
    .line 3
    return-void
.end method

.method public static n(Lqr/y;Lqr/x;)V
    .locals 2

    .line 1
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 2
    .line 3
    .line 4
    iget-object v0, p0, Lqr/y;->key_:Lcom/google/crypto/tink/shaded/protobuf/a0;

    .line 5
    .line 6
    move-object v1, v0

    .line 7
    check-cast v1, Lcom/google/crypto/tink/shaded/protobuf/b;

    .line 8
    .line 9
    iget-boolean v1, v1, Lcom/google/crypto/tink/shaded/protobuf/b;->d:Z

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
    invoke-interface {v0, v1}, Lcom/google/crypto/tink/shaded/protobuf/a0;->a(I)Lcom/google/crypto/tink/shaded/protobuf/a0;

    .line 25
    .line 26
    .line 27
    move-result-object v0

    .line 28
    iput-object v0, p0, Lqr/y;->key_:Lcom/google/crypto/tink/shaded/protobuf/a0;

    .line 29
    .line 30
    :cond_1
    iget-object p0, p0, Lqr/y;->key_:Lcom/google/crypto/tink/shaded/protobuf/a0;

    .line 31
    .line 32
    invoke-interface {p0, p1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 33
    .line 34
    .line 35
    return-void
.end method

.method public static s()Lqr/v;
    .locals 1

    .line 1
    sget-object v0, Lqr/y;->DEFAULT_INSTANCE:Lqr/y;

    .line 2
    .line 3
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/x;->e()Lcom/google/crypto/tink/shaded/protobuf/v;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, Lqr/v;

    .line 8
    .line 9
    return-object v0
.end method

.method public static t([BLcom/google/crypto/tink/shaded/protobuf/p;)Lqr/y;
    .locals 1

    .line 1
    sget-object v0, Lqr/y;->DEFAULT_INSTANCE:Lqr/y;

    .line 2
    .line 3
    invoke-static {v0, p0, p1}, Lcom/google/crypto/tink/shaded/protobuf/x;->k(Lcom/google/crypto/tink/shaded/protobuf/x;[BLcom/google/crypto/tink/shaded/protobuf/p;)Lcom/google/crypto/tink/shaded/protobuf/x;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lqr/y;

    .line 8
    .line 9
    return-object p0
.end method


# virtual methods
.method public final f(I)Ljava/lang/Object;
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
    sget-object p0, Lqr/y;->PARSER:Lcom/google/crypto/tink/shaded/protobuf/v0;

    .line 15
    .line 16
    if-nez p0, :cond_1

    .line 17
    .line 18
    const-class p1, Lqr/y;

    .line 19
    .line 20
    monitor-enter p1

    .line 21
    :try_start_0
    sget-object p0, Lqr/y;->PARSER:Lcom/google/crypto/tink/shaded/protobuf/v0;

    .line 22
    .line 23
    if-nez p0, :cond_0

    .line 24
    .line 25
    new-instance p0, Lcom/google/crypto/tink/shaded/protobuf/w;

    .line 26
    .line 27
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 28
    .line 29
    .line 30
    sput-object p0, Lqr/y;->PARSER:Lcom/google/crypto/tink/shaded/protobuf/v0;

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
    sget-object p0, Lqr/y;->DEFAULT_INSTANCE:Lqr/y;

    .line 41
    .line 42
    return-object p0

    .line 43
    :pswitch_2
    new-instance p0, Lqr/v;

    .line 44
    .line 45
    sget-object p1, Lqr/y;->DEFAULT_INSTANCE:Lqr/y;

    .line 46
    .line 47
    invoke-direct {p0, p1}, Lcom/google/crypto/tink/shaded/protobuf/v;-><init>(Lcom/google/crypto/tink/shaded/protobuf/x;)V

    .line 48
    .line 49
    .line 50
    return-object p0

    .line 51
    :pswitch_3
    new-instance p0, Lqr/y;

    .line 52
    .line 53
    invoke-direct {p0}, Lqr/y;-><init>()V

    .line 54
    .line 55
    .line 56
    return-object p0

    .line 57
    :pswitch_4
    const-string p0, "primaryKeyId_"

    .line 58
    .line 59
    const-string p1, "key_"

    .line 60
    .line 61
    const-class v0, Lqr/x;

    .line 62
    .line 63
    filled-new-array {p0, p1, v0}, [Ljava/lang/Object;

    .line 64
    .line 65
    .line 66
    move-result-object p0

    .line 67
    const-string p1, "\u0000\u0002\u0000\u0000\u0001\u0002\u0002\u0000\u0001\u0000\u0001\u000b\u0002\u001b"

    .line 68
    .line 69
    sget-object v0, Lqr/y;->DEFAULT_INSTANCE:Lqr/y;

    .line 70
    .line 71
    new-instance v1, Lcom/google/crypto/tink/shaded/protobuf/z0;

    .line 72
    .line 73
    invoke-direct {v1, v0, p1, p0}, Lcom/google/crypto/tink/shaded/protobuf/z0;-><init>(Lcom/google/crypto/tink/shaded/protobuf/a;Ljava/lang/String;[Ljava/lang/Object;)V

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

.method public final o(I)Lqr/x;
    .locals 0

    .line 1
    iget-object p0, p0, Lqr/y;->key_:Lcom/google/crypto/tink/shaded/protobuf/a0;

    .line 2
    .line 3
    invoke-interface {p0, p1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lqr/x;

    .line 8
    .line 9
    return-object p0
.end method

.method public final p()I
    .locals 0

    .line 1
    iget-object p0, p0, Lqr/y;->key_:Lcom/google/crypto/tink/shaded/protobuf/a0;

    .line 2
    .line 3
    invoke-interface {p0}, Ljava/util/List;->size()I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public final q()Ljava/util/List;
    .locals 0

    .line 1
    iget-object p0, p0, Lqr/y;->key_:Lcom/google/crypto/tink/shaded/protobuf/a0;

    .line 2
    .line 3
    return-object p0
.end method

.method public final r()I
    .locals 0

    .line 1
    iget p0, p0, Lqr/y;->primaryKeyId_:I

    .line 2
    .line 3
    return p0
.end method
