.class public final Lau/a0;
.super Lcom/google/protobuf/p;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final CLIENT_START_TIME_US_FIELD_NUMBER:I = 0x4

.field public static final COUNTERS_FIELD_NUMBER:I = 0x6

.field public static final CUSTOM_ATTRIBUTES_FIELD_NUMBER:I = 0x8

.field private static final DEFAULT_INSTANCE:Lau/a0;

.field public static final DURATION_US_FIELD_NUMBER:I = 0x5

.field public static final IS_AUTO_FIELD_NUMBER:I = 0x2

.field public static final NAME_FIELD_NUMBER:I = 0x1

.field private static volatile PARSER:Lcom/google/protobuf/r0; = null
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lcom/google/protobuf/r0;"
        }
    .end annotation
.end field

.field public static final PERF_SESSIONS_FIELD_NUMBER:I = 0x9

.field public static final SUBTRACES_FIELD_NUMBER:I = 0x7


# instance fields
.field private bitField0_:I

.field private clientStartTimeUs_:J

.field private counters_:Lcom/google/protobuf/i0;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lcom/google/protobuf/i0;"
        }
    .end annotation
.end field

.field private customAttributes_:Lcom/google/protobuf/i0;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lcom/google/protobuf/i0;"
        }
    .end annotation
.end field

.field private durationUs_:J

.field private isAuto_:Z

.field private name_:Ljava/lang/String;

.field private perfSessions_:Lcom/google/protobuf/t;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lcom/google/protobuf/t;"
        }
    .end annotation
.end field

.field private subtraces_:Lcom/google/protobuf/t;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lcom/google/protobuf/t;"
        }
    .end annotation
.end field


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lau/a0;

    .line 2
    .line 3
    invoke-direct {v0}, Lau/a0;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lau/a0;->DEFAULT_INSTANCE:Lau/a0;

    .line 7
    .line 8
    const-class v1, Lau/a0;

    .line 9
    .line 10
    invoke-static {v1, v0}, Lcom/google/protobuf/p;->q(Ljava/lang/Class;Lcom/google/protobuf/p;)V

    .line 11
    .line 12
    .line 13
    return-void
.end method

.method public constructor <init>()V
    .locals 1

    .line 1
    invoke-direct {p0}, Lcom/google/protobuf/p;-><init>()V

    .line 2
    .line 3
    .line 4
    sget-object v0, Lcom/google/protobuf/i0;->e:Lcom/google/protobuf/i0;

    .line 5
    .line 6
    iput-object v0, p0, Lau/a0;->counters_:Lcom/google/protobuf/i0;

    .line 7
    .line 8
    iput-object v0, p0, Lau/a0;->customAttributes_:Lcom/google/protobuf/i0;

    .line 9
    .line 10
    const-string v0, ""

    .line 11
    .line 12
    iput-object v0, p0, Lau/a0;->name_:Ljava/lang/String;

    .line 13
    .line 14
    sget-object v0, Lcom/google/protobuf/u0;->g:Lcom/google/protobuf/u0;

    .line 15
    .line 16
    iput-object v0, p0, Lau/a0;->subtraces_:Lcom/google/protobuf/t;

    .line 17
    .line 18
    iput-object v0, p0, Lau/a0;->perfSessions_:Lcom/google/protobuf/t;

    .line 19
    .line 20
    return-void
.end method

.method public static A(Lau/a0;J)V
    .locals 1

    .line 1
    iget v0, p0, Lau/a0;->bitField0_:I

    .line 2
    .line 3
    or-int/lit8 v0, v0, 0x8

    .line 4
    .line 5
    iput v0, p0, Lau/a0;->bitField0_:I

    .line 6
    .line 7
    iput-wide p1, p0, Lau/a0;->durationUs_:J

    .line 8
    .line 9
    return-void
.end method

.method public static F()Lau/a0;
    .locals 1

    .line 1
    sget-object v0, Lau/a0;->DEFAULT_INSTANCE:Lau/a0;

    .line 2
    .line 3
    return-object v0
.end method

.method public static L()Lau/x;
    .locals 1

    .line 1
    sget-object v0, Lau/a0;->DEFAULT_INSTANCE:Lau/a0;

    .line 2
    .line 3
    invoke-virtual {v0}, Lcom/google/protobuf/p;->j()Lcom/google/protobuf/n;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, Lau/x;

    .line 8
    .line 9
    return-object v0
.end method

.method public static s(Lau/a0;Ljava/lang/String;)V
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
    iget v0, p0, Lau/a0;->bitField0_:I

    .line 8
    .line 9
    or-int/lit8 v0, v0, 0x1

    .line 10
    .line 11
    iput v0, p0, Lau/a0;->bitField0_:I

    .line 12
    .line 13
    iput-object p1, p0, Lau/a0;->name_:Ljava/lang/String;

    .line 14
    .line 15
    return-void
.end method

.method public static t(Lau/a0;)Lcom/google/protobuf/i0;
    .locals 2

    .line 1
    iget-object v0, p0, Lau/a0;->counters_:Lcom/google/protobuf/i0;

    .line 2
    .line 3
    iget-boolean v1, v0, Lcom/google/protobuf/i0;->d:Z

    .line 4
    .line 5
    if-nez v1, :cond_0

    .line 6
    .line 7
    invoke-virtual {v0}, Lcom/google/protobuf/i0;->c()Lcom/google/protobuf/i0;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    iput-object v0, p0, Lau/a0;->counters_:Lcom/google/protobuf/i0;

    .line 12
    .line 13
    :cond_0
    iget-object p0, p0, Lau/a0;->counters_:Lcom/google/protobuf/i0;

    .line 14
    .line 15
    return-object p0
.end method

.method public static u(Lau/a0;Lau/a0;)V
    .locals 2

    .line 1
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 2
    .line 3
    .line 4
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 5
    .line 6
    .line 7
    iget-object v0, p0, Lau/a0;->subtraces_:Lcom/google/protobuf/t;

    .line 8
    .line 9
    move-object v1, v0

    .line 10
    check-cast v1, Lcom/google/protobuf/b;

    .line 11
    .line 12
    iget-boolean v1, v1, Lcom/google/protobuf/b;->d:Z

    .line 13
    .line 14
    if-nez v1, :cond_0

    .line 15
    .line 16
    invoke-static {v0}, Lcom/google/protobuf/p;->p(Lcom/google/protobuf/t;)Lcom/google/protobuf/t;

    .line 17
    .line 18
    .line 19
    move-result-object v0

    .line 20
    iput-object v0, p0, Lau/a0;->subtraces_:Lcom/google/protobuf/t;

    .line 21
    .line 22
    :cond_0
    iget-object p0, p0, Lau/a0;->subtraces_:Lcom/google/protobuf/t;

    .line 23
    .line 24
    invoke-interface {p0, p1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 25
    .line 26
    .line 27
    return-void
.end method

.method public static v(Lau/a0;Ljava/util/ArrayList;)V
    .locals 2

    .line 1
    iget-object v0, p0, Lau/a0;->subtraces_:Lcom/google/protobuf/t;

    .line 2
    .line 3
    move-object v1, v0

    .line 4
    check-cast v1, Lcom/google/protobuf/b;

    .line 5
    .line 6
    iget-boolean v1, v1, Lcom/google/protobuf/b;->d:Z

    .line 7
    .line 8
    if-nez v1, :cond_0

    .line 9
    .line 10
    invoke-static {v0}, Lcom/google/protobuf/p;->p(Lcom/google/protobuf/t;)Lcom/google/protobuf/t;

    .line 11
    .line 12
    .line 13
    move-result-object v0

    .line 14
    iput-object v0, p0, Lau/a0;->subtraces_:Lcom/google/protobuf/t;

    .line 15
    .line 16
    :cond_0
    iget-object p0, p0, Lau/a0;->subtraces_:Lcom/google/protobuf/t;

    .line 17
    .line 18
    invoke-static {p1, p0}, Lcom/google/protobuf/a;->g(Ljava/lang/Iterable;Ljava/util/List;)V

    .line 19
    .line 20
    .line 21
    return-void
.end method

.method public static w(Lau/a0;)Lcom/google/protobuf/i0;
    .locals 2

    .line 1
    iget-object v0, p0, Lau/a0;->customAttributes_:Lcom/google/protobuf/i0;

    .line 2
    .line 3
    iget-boolean v1, v0, Lcom/google/protobuf/i0;->d:Z

    .line 4
    .line 5
    if-nez v1, :cond_0

    .line 6
    .line 7
    invoke-virtual {v0}, Lcom/google/protobuf/i0;->c()Lcom/google/protobuf/i0;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    iput-object v0, p0, Lau/a0;->customAttributes_:Lcom/google/protobuf/i0;

    .line 12
    .line 13
    :cond_0
    iget-object p0, p0, Lau/a0;->customAttributes_:Lcom/google/protobuf/i0;

    .line 14
    .line 15
    return-object p0
.end method

.method public static x(Lau/a0;Lau/w;)V
    .locals 2

    .line 1
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 2
    .line 3
    .line 4
    iget-object v0, p0, Lau/a0;->perfSessions_:Lcom/google/protobuf/t;

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
    if-nez v1, :cond_0

    .line 12
    .line 13
    invoke-static {v0}, Lcom/google/protobuf/p;->p(Lcom/google/protobuf/t;)Lcom/google/protobuf/t;

    .line 14
    .line 15
    .line 16
    move-result-object v0

    .line 17
    iput-object v0, p0, Lau/a0;->perfSessions_:Lcom/google/protobuf/t;

    .line 18
    .line 19
    :cond_0
    iget-object p0, p0, Lau/a0;->perfSessions_:Lcom/google/protobuf/t;

    .line 20
    .line 21
    invoke-interface {p0, p1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 22
    .line 23
    .line 24
    return-void
.end method

.method public static y(Lau/a0;Ljava/util/List;)V
    .locals 2

    .line 1
    iget-object v0, p0, Lau/a0;->perfSessions_:Lcom/google/protobuf/t;

    .line 2
    .line 3
    move-object v1, v0

    .line 4
    check-cast v1, Lcom/google/protobuf/b;

    .line 5
    .line 6
    iget-boolean v1, v1, Lcom/google/protobuf/b;->d:Z

    .line 7
    .line 8
    if-nez v1, :cond_0

    .line 9
    .line 10
    invoke-static {v0}, Lcom/google/protobuf/p;->p(Lcom/google/protobuf/t;)Lcom/google/protobuf/t;

    .line 11
    .line 12
    .line 13
    move-result-object v0

    .line 14
    iput-object v0, p0, Lau/a0;->perfSessions_:Lcom/google/protobuf/t;

    .line 15
    .line 16
    :cond_0
    iget-object p0, p0, Lau/a0;->perfSessions_:Lcom/google/protobuf/t;

    .line 17
    .line 18
    invoke-static {p1, p0}, Lcom/google/protobuf/a;->g(Ljava/lang/Iterable;Ljava/util/List;)V

    .line 19
    .line 20
    .line 21
    return-void
.end method

.method public static z(Lau/a0;J)V
    .locals 1

    .line 1
    iget v0, p0, Lau/a0;->bitField0_:I

    .line 2
    .line 3
    or-int/lit8 v0, v0, 0x4

    .line 4
    .line 5
    iput v0, p0, Lau/a0;->bitField0_:I

    .line 6
    .line 7
    iput-wide p1, p0, Lau/a0;->clientStartTimeUs_:J

    .line 8
    .line 9
    return-void
.end method


# virtual methods
.method public final B()Z
    .locals 1

    .line 1
    const-string v0, "Hosting_activity"

    .line 2
    .line 3
    iget-object p0, p0, Lau/a0;->customAttributes_:Lcom/google/protobuf/i0;

    .line 4
    .line 5
    invoke-virtual {p0, v0}, Ljava/util/AbstractMap;->containsKey(Ljava/lang/Object;)Z

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    return p0
.end method

.method public final C()I
    .locals 0

    .line 1
    iget-object p0, p0, Lau/a0;->counters_:Lcom/google/protobuf/i0;

    .line 2
    .line 3
    invoke-virtual {p0}, Ljava/util/AbstractMap;->size()I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public final D()Ljava/util/Map;
    .locals 0

    .line 1
    iget-object p0, p0, Lau/a0;->counters_:Lcom/google/protobuf/i0;

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

.method public final E()Ljava/util/Map;
    .locals 0

    .line 1
    iget-object p0, p0, Lau/a0;->customAttributes_:Lcom/google/protobuf/i0;

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

.method public final G()J
    .locals 2

    .line 1
    iget-wide v0, p0, Lau/a0;->durationUs_:J

    .line 2
    .line 3
    return-wide v0
.end method

.method public final H()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lau/a0;->name_:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final I()Lcom/google/protobuf/t;
    .locals 0

    .line 1
    iget-object p0, p0, Lau/a0;->perfSessions_:Lcom/google/protobuf/t;

    .line 2
    .line 3
    return-object p0
.end method

.method public final J()Lcom/google/protobuf/t;
    .locals 0

    .line 1
    iget-object p0, p0, Lau/a0;->subtraces_:Lcom/google/protobuf/t;

    .line 2
    .line 3
    return-object p0
.end method

.method public final K()Z
    .locals 0

    .line 1
    iget p0, p0, Lau/a0;->bitField0_:I

    .line 2
    .line 3
    and-int/lit8 p0, p0, 0x4

    .line 4
    .line 5
    if-eqz p0, :cond_0

    .line 6
    .line 7
    const/4 p0, 0x1

    .line 8
    return p0

    .line 9
    :cond_0
    const/4 p0, 0x0

    .line 10
    return p0
.end method

.method public final k(I)Ljava/lang/Object;
    .locals 13

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
    sget-object p0, Lau/a0;->PARSER:Lcom/google/protobuf/r0;

    .line 15
    .line 16
    if-nez p0, :cond_1

    .line 17
    .line 18
    const-class p1, Lau/a0;

    .line 19
    .line 20
    monitor-enter p1

    .line 21
    :try_start_0
    sget-object p0, Lau/a0;->PARSER:Lcom/google/protobuf/r0;

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
    sput-object p0, Lau/a0;->PARSER:Lcom/google/protobuf/r0;

    .line 31
    .line 32
    goto :goto_0

    .line 33
    :catchall_0
    move-exception v0

    .line 34
    move-object p0, v0

    .line 35
    goto :goto_1

    .line 36
    :cond_0
    :goto_0
    monitor-exit p1

    .line 37
    return-object p0

    .line 38
    :goto_1
    monitor-exit p1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 39
    throw p0

    .line 40
    :cond_1
    return-object p0

    .line 41
    :pswitch_1
    sget-object p0, Lau/a0;->DEFAULT_INSTANCE:Lau/a0;

    .line 42
    .line 43
    return-object p0

    .line 44
    :pswitch_2
    new-instance p0, Lau/x;

    .line 45
    .line 46
    sget-object p1, Lau/a0;->DEFAULT_INSTANCE:Lau/a0;

    .line 47
    .line 48
    invoke-direct {p0, p1}, Lcom/google/protobuf/n;-><init>(Lcom/google/protobuf/p;)V

    .line 49
    .line 50
    .line 51
    return-object p0

    .line 52
    :pswitch_3
    new-instance p0, Lau/a0;

    .line 53
    .line 54
    invoke-direct {p0}, Lau/a0;-><init>()V

    .line 55
    .line 56
    .line 57
    return-object p0

    .line 58
    :pswitch_4
    const-string v0, "bitField0_"

    .line 59
    .line 60
    const-string v1, "name_"

    .line 61
    .line 62
    const-string v2, "isAuto_"

    .line 63
    .line 64
    const-string v3, "clientStartTimeUs_"

    .line 65
    .line 66
    const-string v4, "durationUs_"

    .line 67
    .line 68
    const-string v5, "counters_"

    .line 69
    .line 70
    sget-object v6, Lau/y;->a:Lcom/google/protobuf/h0;

    .line 71
    .line 72
    const-string v7, "subtraces_"

    .line 73
    .line 74
    const-class v8, Lau/a0;

    .line 75
    .line 76
    const-string v9, "customAttributes_"

    .line 77
    .line 78
    sget-object v10, Lau/z;->a:Lcom/google/protobuf/h0;

    .line 79
    .line 80
    const-string v11, "perfSessions_"

    .line 81
    .line 82
    const-class v12, Lau/w;

    .line 83
    .line 84
    filled-new-array/range {v0 .. v12}, [Ljava/lang/Object;

    .line 85
    .line 86
    .line 87
    move-result-object p0

    .line 88
    const-string p1, "\u0001\u0008\u0000\u0001\u0001\t\u0008\u0002\u0002\u0000\u0001\u1008\u0000\u0002\u1007\u0001\u0004\u1002\u0002\u0005\u1002\u0003\u00062\u0007\u001b\u00082\t\u001b"

    .line 89
    .line 90
    sget-object v0, Lau/a0;->DEFAULT_INSTANCE:Lau/a0;

    .line 91
    .line 92
    new-instance v1, Lcom/google/protobuf/v0;

    .line 93
    .line 94
    invoke-direct {v1, v0, p1, p0}, Lcom/google/protobuf/v0;-><init>(Lcom/google/protobuf/a;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 95
    .line 96
    .line 97
    return-object v1

    .line 98
    :pswitch_5
    const/4 p0, 0x0

    .line 99
    return-object p0

    .line 100
    :pswitch_6
    const/4 p0, 0x1

    .line 101
    invoke-static {p0}, Ljava/lang/Byte;->valueOf(B)Ljava/lang/Byte;

    .line 102
    .line 103
    .line 104
    move-result-object p0

    .line 105
    return-object p0

    .line 106
    nop

    .line 107
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
