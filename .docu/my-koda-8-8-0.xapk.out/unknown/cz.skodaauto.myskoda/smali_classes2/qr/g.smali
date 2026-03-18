.class public final Lqr/g;
.super Lcom/google/crypto/tink/shaded/protobuf/x;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field private static final DEFAULT_INSTANCE:Lqr/g;

.field public static final ENCRYPTED_KEYSET_FIELD_NUMBER:I = 0x2

.field public static final KEYSET_INFO_FIELD_NUMBER:I = 0x3

.field private static volatile PARSER:Lcom/google/crypto/tink/shaded/protobuf/v0;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lcom/google/crypto/tink/shaded/protobuf/v0;"
        }
    .end annotation
.end field


# instance fields
.field private encryptedKeyset_:Lcom/google/crypto/tink/shaded/protobuf/i;

.field private keysetInfo_:Lqr/c0;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lqr/g;

    .line 2
    .line 3
    invoke-direct {v0}, Lqr/g;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lqr/g;->DEFAULT_INSTANCE:Lqr/g;

    .line 7
    .line 8
    const-class v1, Lqr/g;

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
    sget-object v0, Lcom/google/crypto/tink/shaded/protobuf/i;->e:Lcom/google/crypto/tink/shaded/protobuf/h;

    .line 5
    .line 6
    iput-object v0, p0, Lqr/g;->encryptedKeyset_:Lcom/google/crypto/tink/shaded/protobuf/i;

    .line 7
    .line 8
    return-void
.end method

.method public static m(Lqr/g;Lcom/google/crypto/tink/shaded/protobuf/h;)V
    .locals 0

    .line 1
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lqr/g;->encryptedKeyset_:Lcom/google/crypto/tink/shaded/protobuf/i;

    .line 5
    .line 6
    return-void
.end method

.method public static n(Lqr/g;Lqr/c0;)V
    .locals 0

    .line 1
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lqr/g;->keysetInfo_:Lqr/c0;

    .line 5
    .line 6
    return-void
.end method

.method public static p()Lqr/f;
    .locals 1

    .line 1
    sget-object v0, Lqr/g;->DEFAULT_INSTANCE:Lqr/g;

    .line 2
    .line 3
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/x;->e()Lcom/google/crypto/tink/shaded/protobuf/v;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, Lqr/f;

    .line 8
    .line 9
    return-object v0
.end method

.method public static q([BLcom/google/crypto/tink/shaded/protobuf/p;)Lqr/g;
    .locals 1

    .line 1
    sget-object v0, Lqr/g;->DEFAULT_INSTANCE:Lqr/g;

    .line 2
    .line 3
    invoke-static {v0, p0, p1}, Lcom/google/crypto/tink/shaded/protobuf/x;->k(Lcom/google/crypto/tink/shaded/protobuf/x;[BLcom/google/crypto/tink/shaded/protobuf/p;)Lcom/google/crypto/tink/shaded/protobuf/x;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lqr/g;

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
    sget-object p0, Lqr/g;->PARSER:Lcom/google/crypto/tink/shaded/protobuf/v0;

    .line 15
    .line 16
    if-nez p0, :cond_1

    .line 17
    .line 18
    const-class p1, Lqr/g;

    .line 19
    .line 20
    monitor-enter p1

    .line 21
    :try_start_0
    sget-object p0, Lqr/g;->PARSER:Lcom/google/crypto/tink/shaded/protobuf/v0;

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
    sput-object p0, Lqr/g;->PARSER:Lcom/google/crypto/tink/shaded/protobuf/v0;

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
    sget-object p0, Lqr/g;->DEFAULT_INSTANCE:Lqr/g;

    .line 41
    .line 42
    return-object p0

    .line 43
    :pswitch_2
    new-instance p0, Lqr/f;

    .line 44
    .line 45
    sget-object p1, Lqr/g;->DEFAULT_INSTANCE:Lqr/g;

    .line 46
    .line 47
    invoke-direct {p0, p1}, Lcom/google/crypto/tink/shaded/protobuf/v;-><init>(Lcom/google/crypto/tink/shaded/protobuf/x;)V

    .line 48
    .line 49
    .line 50
    return-object p0

    .line 51
    :pswitch_3
    new-instance p0, Lqr/g;

    .line 52
    .line 53
    invoke-direct {p0}, Lqr/g;-><init>()V

    .line 54
    .line 55
    .line 56
    return-object p0

    .line 57
    :pswitch_4
    const-string p0, "encryptedKeyset_"

    .line 58
    .line 59
    const-string p1, "keysetInfo_"

    .line 60
    .line 61
    filled-new-array {p0, p1}, [Ljava/lang/Object;

    .line 62
    .line 63
    .line 64
    move-result-object p0

    .line 65
    const-string p1, "\u0000\u0002\u0000\u0000\u0002\u0003\u0002\u0000\u0000\u0000\u0002\n\u0003\t"

    .line 66
    .line 67
    sget-object v0, Lqr/g;->DEFAULT_INSTANCE:Lqr/g;

    .line 68
    .line 69
    new-instance v1, Lcom/google/crypto/tink/shaded/protobuf/z0;

    .line 70
    .line 71
    invoke-direct {v1, v0, p1, p0}, Lcom/google/crypto/tink/shaded/protobuf/z0;-><init>(Lcom/google/crypto/tink/shaded/protobuf/a;Ljava/lang/String;[Ljava/lang/Object;)V

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

.method public final o()Lcom/google/crypto/tink/shaded/protobuf/i;
    .locals 0

    .line 1
    iget-object p0, p0, Lqr/g;->encryptedKeyset_:Lcom/google/crypto/tink/shaded/protobuf/i;

    .line 2
    .line 3
    return-object p0
.end method
