.class public final Lau/w;
.super Lcom/google/protobuf/p;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field private static final DEFAULT_INSTANCE:Lau/w;

.field private static volatile PARSER:Lcom/google/protobuf/r0; = null
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lcom/google/protobuf/r0;"
        }
    .end annotation
.end field

.field public static final SESSION_ID_FIELD_NUMBER:I = 0x1

.field public static final SESSION_VERBOSITY_FIELD_NUMBER:I = 0x2

.field private static final sessionVerbosity_converter_:Lcom/google/protobuf/s;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lcom/google/protobuf/s;"
        }
    .end annotation
.end field


# instance fields
.field private bitField0_:I

.field private sessionId_:Ljava/lang/String;

.field private sessionVerbosity_:Lcom/google/protobuf/r;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lau/h;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lau/w;->sessionVerbosity_converter_:Lcom/google/protobuf/s;

    .line 7
    .line 8
    new-instance v0, Lau/w;

    .line 9
    .line 10
    invoke-direct {v0}, Lau/w;-><init>()V

    .line 11
    .line 12
    .line 13
    sput-object v0, Lau/w;->DEFAULT_INSTANCE:Lau/w;

    .line 14
    .line 15
    const-class v1, Lau/w;

    .line 16
    .line 17
    invoke-static {v1, v0}, Lcom/google/protobuf/p;->q(Ljava/lang/Class;Lcom/google/protobuf/p;)V

    .line 18
    .line 19
    .line 20
    return-void
.end method

.method public constructor <init>()V
    .locals 1

    .line 1
    invoke-direct {p0}, Lcom/google/protobuf/p;-><init>()V

    .line 2
    .line 3
    .line 4
    const-string v0, ""

    .line 5
    .line 6
    iput-object v0, p0, Lau/w;->sessionId_:Ljava/lang/String;

    .line 7
    .line 8
    sget-object v0, Lcom/google/protobuf/q;->g:Lcom/google/protobuf/q;

    .line 9
    .line 10
    iput-object v0, p0, Lau/w;->sessionVerbosity_:Lcom/google/protobuf/r;

    .line 11
    .line 12
    return-void
.end method

.method public static s(Lau/w;Ljava/lang/String;)V
    .locals 1

    .line 1
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 2
    .line 3
    .line 4
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 5
    .line 6
    .line 7
    iget v0, p0, Lau/w;->bitField0_:I

    .line 8
    .line 9
    or-int/lit8 v0, v0, 0x1

    .line 10
    .line 11
    iput v0, p0, Lau/w;->bitField0_:I

    .line 12
    .line 13
    iput-object p1, p0, Lau/w;->sessionId_:Ljava/lang/String;

    .line 14
    .line 15
    return-void
.end method

.method public static t(Lau/w;)V
    .locals 5

    .line 1
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 2
    .line 3
    .line 4
    iget-object v0, p0, Lau/w;->sessionVerbosity_:Lcom/google/protobuf/r;

    .line 5
    .line 6
    move-object v1, v0

    .line 7
    check-cast v1, Lcom/google/protobuf/b;

    .line 8
    .line 9
    iget-boolean v1, v1, Lcom/google/protobuf/b;->d:Z

    .line 10
    .line 11
    const/4 v2, 0x2

    .line 12
    if-nez v1, :cond_2

    .line 13
    .line 14
    invoke-interface {v0}, Ljava/util/List;->size()I

    .line 15
    .line 16
    .line 17
    move-result v1

    .line 18
    if-nez v1, :cond_0

    .line 19
    .line 20
    const/16 v1, 0xa

    .line 21
    .line 22
    goto :goto_0

    .line 23
    :cond_0
    mul-int/2addr v1, v2

    .line 24
    :goto_0
    check-cast v0, Lcom/google/protobuf/q;

    .line 25
    .line 26
    iget v3, v0, Lcom/google/protobuf/q;->f:I

    .line 27
    .line 28
    if-lt v1, v3, :cond_1

    .line 29
    .line 30
    new-instance v3, Lcom/google/protobuf/q;

    .line 31
    .line 32
    iget-object v4, v0, Lcom/google/protobuf/q;->e:[I

    .line 33
    .line 34
    invoke-static {v4, v1}, Ljava/util/Arrays;->copyOf([II)[I

    .line 35
    .line 36
    .line 37
    move-result-object v1

    .line 38
    iget v0, v0, Lcom/google/protobuf/q;->f:I

    .line 39
    .line 40
    const/4 v4, 0x1

    .line 41
    invoke-direct {v3, v1, v0, v4}, Lcom/google/protobuf/q;-><init>([IIZ)V

    .line 42
    .line 43
    .line 44
    iput-object v3, p0, Lau/w;->sessionVerbosity_:Lcom/google/protobuf/r;

    .line 45
    .line 46
    goto :goto_1

    .line 47
    :cond_1
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 48
    .line 49
    invoke-direct {p0}, Ljava/lang/IllegalArgumentException;-><init>()V

    .line 50
    .line 51
    .line 52
    throw p0

    .line 53
    :cond_2
    :goto_1
    iget-object p0, p0, Lau/w;->sessionVerbosity_:Lcom/google/protobuf/r;

    .line 54
    .line 55
    invoke-static {v2}, Lu/w;->o(I)I

    .line 56
    .line 57
    .line 58
    move-result v0

    .line 59
    check-cast p0, Lcom/google/protobuf/q;

    .line 60
    .line 61
    invoke-virtual {p0, v0}, Lcom/google/protobuf/q;->e(I)V

    .line 62
    .line 63
    .line 64
    return-void
.end method

.method public static w()Lau/v;
    .locals 1

    .line 1
    sget-object v0, Lau/w;->DEFAULT_INSTANCE:Lau/w;

    .line 2
    .line 3
    invoke-virtual {v0}, Lcom/google/protobuf/p;->j()Lcom/google/protobuf/n;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, Lau/v;

    .line 8
    .line 9
    return-object v0
.end method


# virtual methods
.method public final k(I)Ljava/lang/Object;
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
    sget-object p0, Lau/w;->PARSER:Lcom/google/protobuf/r0;

    .line 15
    .line 16
    if-nez p0, :cond_1

    .line 17
    .line 18
    const-class p1, Lau/w;

    .line 19
    .line 20
    monitor-enter p1

    .line 21
    :try_start_0
    sget-object p0, Lau/w;->PARSER:Lcom/google/protobuf/r0;

    .line 22
    .line 23
    if-nez p0, :cond_0

    .line 24
    .line 25
    new-instance p0, Lcom/google/protobuf/o;

    .line 26
    .line 27
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 28
    .line 29
    .line 30
    sput-object p0, Lau/w;->PARSER:Lcom/google/protobuf/r0;

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
    sget-object p0, Lau/w;->DEFAULT_INSTANCE:Lau/w;

    .line 41
    .line 42
    return-object p0

    .line 43
    :pswitch_2
    new-instance p0, Lau/v;

    .line 44
    .line 45
    sget-object p1, Lau/w;->DEFAULT_INSTANCE:Lau/w;

    .line 46
    .line 47
    invoke-direct {p0, p1}, Lcom/google/protobuf/n;-><init>(Lcom/google/protobuf/p;)V

    .line 48
    .line 49
    .line 50
    return-object p0

    .line 51
    :pswitch_3
    new-instance p0, Lau/w;

    .line 52
    .line 53
    invoke-direct {p0}, Lau/w;-><init>()V

    .line 54
    .line 55
    .line 56
    return-object p0

    .line 57
    :pswitch_4
    const-string p0, "bitField0_"

    .line 58
    .line 59
    const-string p1, "sessionId_"

    .line 60
    .line 61
    const-string v0, "sessionVerbosity_"

    .line 62
    .line 63
    sget-object v1, Lau/h;->d:Lau/h;

    .line 64
    .line 65
    filled-new-array {p0, p1, v0, v1}, [Ljava/lang/Object;

    .line 66
    .line 67
    .line 68
    move-result-object p0

    .line 69
    const-string p1, "\u0001\u0002\u0000\u0001\u0001\u0002\u0002\u0000\u0001\u0000\u0001\u1008\u0000\u0002\u081e"

    .line 70
    .line 71
    sget-object v0, Lau/w;->DEFAULT_INSTANCE:Lau/w;

    .line 72
    .line 73
    new-instance v1, Lcom/google/protobuf/v0;

    .line 74
    .line 75
    invoke-direct {v1, v0, p1, p0}, Lcom/google/protobuf/v0;-><init>(Lcom/google/protobuf/a;Ljava/lang/String;[Ljava/lang/Object;)V

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

.method public final u()I
    .locals 2

    .line 1
    iget-object p0, p0, Lau/w;->sessionVerbosity_:Lcom/google/protobuf/r;

    .line 2
    .line 3
    check-cast p0, Lcom/google/protobuf/q;

    .line 4
    .line 5
    const/4 v0, 0x0

    .line 6
    invoke-virtual {p0, v0}, Lcom/google/protobuf/q;->i(I)I

    .line 7
    .line 8
    .line 9
    move-result p0

    .line 10
    const/4 v1, 0x1

    .line 11
    if-eqz p0, :cond_1

    .line 12
    .line 13
    if-eq p0, v1, :cond_0

    .line 14
    .line 15
    goto :goto_0

    .line 16
    :cond_0
    const/4 v0, 0x2

    .line 17
    goto :goto_0

    .line 18
    :cond_1
    move v0, v1

    .line 19
    :goto_0
    if-nez v0, :cond_2

    .line 20
    .line 21
    return v1

    .line 22
    :cond_2
    return v0
.end method

.method public final v()I
    .locals 0

    .line 1
    iget-object p0, p0, Lau/w;->sessionVerbosity_:Lcom/google/protobuf/r;

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
