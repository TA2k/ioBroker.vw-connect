.class public final Lqr/x;
.super Lcom/google/crypto/tink/shaded/protobuf/x;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field private static final DEFAULT_INSTANCE:Lqr/x;

.field public static final KEY_DATA_FIELD_NUMBER:I = 0x1

.field public static final KEY_ID_FIELD_NUMBER:I = 0x3

.field public static final OUTPUT_PREFIX_TYPE_FIELD_NUMBER:I = 0x4

.field private static volatile PARSER:Lcom/google/crypto/tink/shaded/protobuf/v0; = null
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lcom/google/crypto/tink/shaded/protobuf/v0;"
        }
    .end annotation
.end field

.field public static final STATUS_FIELD_NUMBER:I = 0x2


# instance fields
.field private keyData_:Lqr/q;

.field private keyId_:I

.field private outputPrefixType_:I

.field private status_:I


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lqr/x;

    .line 2
    .line 3
    invoke-direct {v0}, Lcom/google/crypto/tink/shaded/protobuf/x;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lqr/x;->DEFAULT_INSTANCE:Lqr/x;

    .line 7
    .line 8
    const-class v1, Lqr/x;

    .line 9
    .line 10
    invoke-static {v1, v0}, Lcom/google/crypto/tink/shaded/protobuf/x;->l(Ljava/lang/Class;Lcom/google/crypto/tink/shaded/protobuf/x;)V

    .line 11
    .line 12
    .line 13
    return-void
.end method

.method public static m(Lqr/x;Lqr/q;)V
    .locals 0

    .line 1
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lqr/x;->keyData_:Lqr/q;

    .line 5
    .line 6
    return-void
.end method

.method public static n(Lqr/x;Lqr/d0;)V
    .locals 0

    .line 1
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 2
    .line 3
    .line 4
    invoke-virtual {p1}, Lqr/d0;->getNumber()I

    .line 5
    .line 6
    .line 7
    move-result p1

    .line 8
    iput p1, p0, Lqr/x;->outputPrefixType_:I

    .line 9
    .line 10
    return-void
.end method

.method public static o(Lqr/x;)V
    .locals 1

    .line 1
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 2
    .line 3
    .line 4
    sget-object v0, Lqr/r;->f:Lqr/r;

    .line 5
    .line 6
    invoke-virtual {v0}, Lqr/r;->getNumber()I

    .line 7
    .line 8
    .line 9
    move-result v0

    .line 10
    iput v0, p0, Lqr/x;->status_:I

    .line 11
    .line 12
    return-void
.end method

.method public static p(Lqr/x;I)V
    .locals 0

    .line 1
    iput p1, p0, Lqr/x;->keyId_:I

    .line 2
    .line 3
    return-void
.end method

.method public static v()Lqr/w;
    .locals 1

    .line 1
    sget-object v0, Lqr/x;->DEFAULT_INSTANCE:Lqr/x;

    .line 2
    .line 3
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/x;->e()Lcom/google/crypto/tink/shaded/protobuf/v;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, Lqr/w;

    .line 8
    .line 9
    return-object v0
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
    sget-object p0, Lqr/x;->PARSER:Lcom/google/crypto/tink/shaded/protobuf/v0;

    .line 15
    .line 16
    if-nez p0, :cond_1

    .line 17
    .line 18
    const-class p1, Lqr/x;

    .line 19
    .line 20
    monitor-enter p1

    .line 21
    :try_start_0
    sget-object p0, Lqr/x;->PARSER:Lcom/google/crypto/tink/shaded/protobuf/v0;

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
    sput-object p0, Lqr/x;->PARSER:Lcom/google/crypto/tink/shaded/protobuf/v0;

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
    sget-object p0, Lqr/x;->DEFAULT_INSTANCE:Lqr/x;

    .line 41
    .line 42
    return-object p0

    .line 43
    :pswitch_2
    new-instance p0, Lqr/w;

    .line 44
    .line 45
    sget-object p1, Lqr/x;->DEFAULT_INSTANCE:Lqr/x;

    .line 46
    .line 47
    invoke-direct {p0, p1}, Lcom/google/crypto/tink/shaded/protobuf/v;-><init>(Lcom/google/crypto/tink/shaded/protobuf/x;)V

    .line 48
    .line 49
    .line 50
    return-object p0

    .line 51
    :pswitch_3
    new-instance p0, Lqr/x;

    .line 52
    .line 53
    invoke-direct {p0}, Lcom/google/crypto/tink/shaded/protobuf/x;-><init>()V

    .line 54
    .line 55
    .line 56
    return-object p0

    .line 57
    :pswitch_4
    const-string p0, "keyData_"

    .line 58
    .line 59
    const-string p1, "status_"

    .line 60
    .line 61
    const-string v0, "keyId_"

    .line 62
    .line 63
    const-string v1, "outputPrefixType_"

    .line 64
    .line 65
    filled-new-array {p0, p1, v0, v1}, [Ljava/lang/Object;

    .line 66
    .line 67
    .line 68
    move-result-object p0

    .line 69
    const-string p1, "\u0000\u0004\u0000\u0000\u0001\u0004\u0004\u0000\u0000\u0000\u0001\t\u0002\u000c\u0003\u000b\u0004\u000c"

    .line 70
    .line 71
    sget-object v0, Lqr/x;->DEFAULT_INSTANCE:Lqr/x;

    .line 72
    .line 73
    new-instance v1, Lcom/google/crypto/tink/shaded/protobuf/z0;

    .line 74
    .line 75
    invoke-direct {v1, v0, p1, p0}, Lcom/google/crypto/tink/shaded/protobuf/z0;-><init>(Lcom/google/crypto/tink/shaded/protobuf/a;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 76
    .line 77
    .line 78
    return-object v1

    .line 79
    :pswitch_5
    const/4 p0, 0x0

    .line 80
    return-object p0

    .line 81
    :pswitch_6
    const/4 p0, 0x1

    .line 82
    invoke-static {p0}, Ljava/lang/Byte;->valueOf(B)Ljava/lang/Byte;

    .line 83
    .line 84
    .line 85
    move-result-object p0

    .line 86
    return-object p0

    .line 87
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

.method public final q()Lqr/q;
    .locals 0

    .line 1
    iget-object p0, p0, Lqr/x;->keyData_:Lqr/q;

    .line 2
    .line 3
    if-nez p0, :cond_0

    .line 4
    .line 5
    invoke-static {}, Lqr/q;->p()Lqr/q;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    :cond_0
    return-object p0
.end method

.method public final r()I
    .locals 0

    .line 1
    iget p0, p0, Lqr/x;->keyId_:I

    .line 2
    .line 3
    return p0
.end method

.method public final s()Lqr/d0;
    .locals 0

    .line 1
    iget p0, p0, Lqr/x;->outputPrefixType_:I

    .line 2
    .line 3
    invoke-static {p0}, Lqr/d0;->a(I)Lqr/d0;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    if-nez p0, :cond_0

    .line 8
    .line 9
    sget-object p0, Lqr/d0;->j:Lqr/d0;

    .line 10
    .line 11
    :cond_0
    return-object p0
.end method

.method public final t()Lqr/r;
    .locals 1

    .line 1
    iget p0, p0, Lqr/x;->status_:I

    .line 2
    .line 3
    if-eqz p0, :cond_3

    .line 4
    .line 5
    const/4 v0, 0x1

    .line 6
    if-eq p0, v0, :cond_2

    .line 7
    .line 8
    const/4 v0, 0x2

    .line 9
    if-eq p0, v0, :cond_1

    .line 10
    .line 11
    const/4 v0, 0x3

    .line 12
    if-eq p0, v0, :cond_0

    .line 13
    .line 14
    const/4 p0, 0x0

    .line 15
    goto :goto_0

    .line 16
    :cond_0
    sget-object p0, Lqr/r;->h:Lqr/r;

    .line 17
    .line 18
    goto :goto_0

    .line 19
    :cond_1
    sget-object p0, Lqr/r;->g:Lqr/r;

    .line 20
    .line 21
    goto :goto_0

    .line 22
    :cond_2
    sget-object p0, Lqr/r;->f:Lqr/r;

    .line 23
    .line 24
    goto :goto_0

    .line 25
    :cond_3
    sget-object p0, Lqr/r;->e:Lqr/r;

    .line 26
    .line 27
    :goto_0
    if-nez p0, :cond_4

    .line 28
    .line 29
    sget-object p0, Lqr/r;->i:Lqr/r;

    .line 30
    .line 31
    :cond_4
    return-object p0
.end method

.method public final u()Z
    .locals 0

    .line 1
    iget-object p0, p0, Lqr/x;->keyData_:Lqr/q;

    .line 2
    .line 3
    if-eqz p0, :cond_0

    .line 4
    .line 5
    const/4 p0, 0x1

    .line 6
    return p0

    .line 7
    :cond_0
    const/4 p0, 0x0

    .line 8
    return p0
.end method
