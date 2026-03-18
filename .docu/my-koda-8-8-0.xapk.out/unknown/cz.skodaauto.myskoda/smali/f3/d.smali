.class public final synthetic Lf3/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lf3/j;
.implements Lgs/f;
.implements Lgt/a;
.implements Lgr/e;
.implements Lw7/f;
.implements Lc9/g;
.implements Lgs/e;
.implements Lon/e;
.implements Lp/a;
.implements Lo8/r;
.implements Lio/opentelemetry/instrumentation/api/semconv/network/internal/AddressAndPortExtractor;
.implements Laq/f;


# instance fields
.field public final synthetic d:I


# direct methods
.method public synthetic constructor <init>(I)V
    .locals 0

    .line 1
    iput p1, p0, Lf3/d;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Lhu/l;)V
    .locals 0

    .line 2
    const/16 p1, 0x13

    iput p1, p0, Lf3/d;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public a(Lcom/google/firebase/components/ComponentRegistrar;)Ljava/util/List;
    .locals 0

    .line 1
    invoke-interface {p1}, Lcom/google/firebase/components/ComponentRegistrar;->getComponents()Ljava/util/List;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public accept(Ljava/lang/Object;)V
    .locals 0

    .line 1
    check-cast p1, Lh8/w0;

    .line 2
    .line 3
    iget-object p0, p1, Lh8/w0;->b:Ld8/i;

    .line 4
    .line 5
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 6
    .line 7
    .line 8
    return-void
.end method

.method public apply(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget p0, p0, Lf3/d;->d:I

    .line 2
    .line 3
    sparse-switch p0, :sswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Li9/q;

    .line 7
    .line 8
    return-object p1

    .line 9
    :sswitch_0
    check-cast p1, Ll9/a;

    .line 10
    .line 11
    iget-wide p0, p1, Ll9/a;->c:J

    .line 12
    .line 13
    invoke-static {p0, p1}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    return-object p0

    .line 18
    :sswitch_1
    check-cast p1, Ll9/a;

    .line 19
    .line 20
    iget-wide p0, p1, Ll9/a;->b:J

    .line 21
    .line 22
    invoke-static {p0, p1}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 23
    .line 24
    .line 25
    move-result-object p0

    .line 26
    return-object p0

    .line 27
    :sswitch_2
    return-object p1

    .line 28
    :sswitch_3
    check-cast p1, Lhu/k0;

    .line 29
    .line 30
    sget-object p0, Lhu/l0;->b:Lbu/c;

    .line 31
    .line 32
    invoke-virtual {p0, p1}, Lbu/c;->l(Ljava/lang/Object;)Ljava/lang/String;

    .line 33
    .line 34
    .line 35
    move-result-object p0

    .line 36
    const-string v0, "encode(...)"

    .line 37
    .line 38
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 39
    .line 40
    .line 41
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 42
    .line 43
    .line 44
    sget-object p1, Lhu/m;->e:Lhu/m;

    .line 45
    .line 46
    const-string p1, "Session Event Type: SESSION_START"

    .line 47
    .line 48
    const-string v0, "FirebaseSessions"

    .line 49
    .line 50
    invoke-static {v0, p1}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    .line 51
    .line 52
    .line 53
    sget-object p1, Lly0/a;->a:Ljava/nio/charset/Charset;

    .line 54
    .line 55
    invoke-virtual {p0, p1}, Ljava/lang/String;->getBytes(Ljava/nio/charset/Charset;)[B

    .line 56
    .line 57
    .line 58
    move-result-object p0

    .line 59
    const-string p1, "getBytes(...)"

    .line 60
    .line 61
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 62
    .line 63
    .line 64
    return-object p0

    .line 65
    :sswitch_4
    check-cast p1, Lt7/q0;

    .line 66
    .line 67
    iget p0, p1, Lt7/q0;->c:I

    .line 68
    .line 69
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 70
    .line 71
    .line 72
    move-result-object p0

    .line 73
    return-object p0

    .line 74
    :sswitch_5
    check-cast p1, Lh8/z;

    .line 75
    .line 76
    invoke-interface {p1}, Lh8/z;->n()Lh8/e1;

    .line 77
    .line 78
    .line 79
    move-result-object p0

    .line 80
    iget-object p0, p0, Lh8/e1;->b:Lhr/x0;

    .line 81
    .line 82
    new-instance p1, Lf3/d;

    .line 83
    .line 84
    const/16 v0, 0xc

    .line 85
    .line 86
    invoke-direct {p1, v0}, Lf3/d;-><init>(I)V

    .line 87
    .line 88
    .line 89
    invoke-static {p0, p1}, Lhr/q;->s(Ljava/util/List;Lgr/e;)Ljava/util/AbstractList;

    .line 90
    .line 91
    .line 92
    move-result-object p0

    .line 93
    invoke-static {p0}, Lhr/h0;->p(Ljava/util/Collection;)Lhr/h0;

    .line 94
    .line 95
    .line 96
    move-result-object p0

    .line 97
    return-object p0

    .line 98
    :sswitch_6
    check-cast p1, Lo8/o;

    .line 99
    .line 100
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 101
    .line 102
    .line 103
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 104
    .line 105
    .line 106
    move-result-object p0

    .line 107
    invoke-virtual {p0}, Ljava/lang/Class;->getSimpleName()Ljava/lang/String;

    .line 108
    .line 109
    .line 110
    move-result-object p0

    .line 111
    return-object p0

    .line 112
    nop

    .line 113
    :sswitch_data_0
    .sparse-switch
        0x9 -> :sswitch_6
        0xa -> :sswitch_5
        0xc -> :sswitch_4
        0x13 -> :sswitch_3
        0x17 -> :sswitch_2
        0x18 -> :sswitch_1
        0x19 -> :sswitch_0
    .end sparse-switch
.end method

.method public b(Lgt/b;)V
    .locals 0

    .line 1
    return-void
.end method

.method public d(IIIII)Z
    .locals 2

    .line 1
    const/16 p0, 0x43

    .line 2
    .line 3
    const/4 v0, 0x2

    .line 4
    const/16 v1, 0x4d

    .line 5
    .line 6
    if-ne p2, p0, :cond_0

    .line 7
    .line 8
    const/16 p0, 0x4f

    .line 9
    .line 10
    if-ne p3, p0, :cond_0

    .line 11
    .line 12
    if-ne p4, v1, :cond_0

    .line 13
    .line 14
    if-eq p5, v1, :cond_1

    .line 15
    .line 16
    if-eq p1, v0, :cond_1

    .line 17
    .line 18
    :cond_0
    if-ne p2, v1, :cond_2

    .line 19
    .line 20
    const/16 p0, 0x4c

    .line 21
    .line 22
    if-ne p3, p0, :cond_2

    .line 23
    .line 24
    if-ne p4, p0, :cond_2

    .line 25
    .line 26
    const/16 p0, 0x54

    .line 27
    .line 28
    if-eq p5, p0, :cond_1

    .line 29
    .line 30
    if-ne p1, v0, :cond_2

    .line 31
    .line 32
    :cond_1
    const/4 p0, 0x1

    .line 33
    return p0

    .line 34
    :cond_2
    const/4 p0, 0x0

    .line 35
    return p0
.end method

.method public e(Lin/z1;)Ljava/lang/Object;
    .locals 0

    .line 1
    iget p0, p0, Lf3/d;->d:I

    .line 2
    .line 3
    packed-switch p0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    :pswitch_0
    invoke-static {p1}, Lcom/google/firebase/sessions/FirebaseSessionsRegistrar;->a(Lin/z1;)Lhu/p;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    return-object p0

    .line 11
    :pswitch_1
    invoke-static {p1}, Lcom/google/firebase/sessions/FirebaseSessionsRegistrar;->b(Lin/z1;)Lhu/n;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    return-object p0

    .line 16
    :pswitch_2
    invoke-static {p1}, Lcom/google/firebase/installations/FirebaseInstallationsRegistrar;->a(Lin/z1;)Lht/d;

    .line 17
    .line 18
    .line 19
    move-result-object p0

    .line 20
    return-object p0

    .line 21
    :pswitch_3
    sget-object p0, Lcom/google/firebase/concurrent/ExecutorsRegistrar;->a:Lgs/o;

    .line 22
    .line 23
    sget-object p0, Lhs/l;->d:Lhs/l;

    .line 24
    .line 25
    return-object p0

    .line 26
    :pswitch_4
    sget-object p0, Lcom/google/firebase/concurrent/ExecutorsRegistrar;->b:Lgs/o;

    .line 27
    .line 28
    invoke-virtual {p0}, Lgs/o;->get()Ljava/lang/Object;

    .line 29
    .line 30
    .line 31
    move-result-object p0

    .line 32
    check-cast p0, Ljava/util/concurrent/ScheduledExecutorService;

    .line 33
    .line 34
    return-object p0

    .line 35
    :pswitch_5
    sget-object p0, Lcom/google/firebase/concurrent/ExecutorsRegistrar;->c:Lgs/o;

    .line 36
    .line 37
    invoke-virtual {p0}, Lgs/o;->get()Ljava/lang/Object;

    .line 38
    .line 39
    .line 40
    move-result-object p0

    .line 41
    check-cast p0, Ljava/util/concurrent/ScheduledExecutorService;

    .line 42
    .line 43
    return-object p0

    .line 44
    :pswitch_6
    sget-object p0, Lcom/google/firebase/concurrent/ExecutorsRegistrar;->a:Lgs/o;

    .line 45
    .line 46
    invoke-virtual {p0}, Lgs/o;->get()Ljava/lang/Object;

    .line 47
    .line 48
    .line 49
    move-result-object p0

    .line 50
    check-cast p0, Ljava/util/concurrent/ScheduledExecutorService;

    .line 51
    .line 52
    return-object p0

    .line 53
    :pswitch_data_0
    .packed-switch 0xe
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_0
        :pswitch_0
        :pswitch_1
    .end packed-switch
.end method

.method public extract(Lio/opentelemetry/instrumentation/api/semconv/network/internal/AddressAndPortExtractor$AddressPortSink;Ljava/lang/Object;)V
    .locals 0

    .line 1
    invoke-static {p1, p2}, Lio/opentelemetry/instrumentation/api/semconv/network/internal/AddressAndPortExtractor;->f(Lio/opentelemetry/instrumentation/api/semconv/network/internal/AddressAndPortExtractor$AddressPortSink;Ljava/lang/Object;)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public g()[Lo8/o;
    .locals 2

    .line 1
    new-instance p0, Li9/m;

    .line 2
    .line 3
    sget-object v0, Ll9/h;->k1:Lwq/f;

    .line 4
    .line 5
    const/16 v1, 0x10

    .line 6
    .line 7
    invoke-direct {p0, v0, v1}, Li9/m;-><init>(Ll9/h;I)V

    .line 8
    .line 9
    .line 10
    const/4 v0, 0x1

    .line 11
    new-array v0, v0, [Lo8/o;

    .line 12
    .line 13
    const/4 v1, 0x0

    .line 14
    aput-object p0, v0, v1

    .line 15
    .line 16
    return-object v0
.end method

.method public h(D)D
    .locals 0

    .line 1
    iget p0, p0, Lf3/d;->d:I

    .line 2
    .line 3
    packed-switch p0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    return-wide p1

    .line 7
    :pswitch_0
    sget-object p0, Lf3/e;->a:[F

    .line 8
    .line 9
    sget-object p0, Lf3/e;->d:Lf3/s;

    .line 10
    .line 11
    invoke-static {p0, p1, p2}, Lf3/e;->c(Lf3/s;D)D

    .line 12
    .line 13
    .line 14
    move-result-wide p0

    .line 15
    return-wide p0

    .line 16
    :pswitch_1
    sget-object p0, Lf3/e;->a:[F

    .line 17
    .line 18
    sget-object p0, Lf3/e;->d:Lf3/s;

    .line 19
    .line 20
    invoke-static {p0, p1, p2}, Lf3/e;->d(Lf3/s;D)D

    .line 21
    .line 22
    .line 23
    move-result-wide p0

    .line 24
    return-wide p0

    .line 25
    :pswitch_2
    sget-object p0, Lf3/e;->a:[F

    .line 26
    .line 27
    sget-object p0, Lf3/e;->c:Lf3/s;

    .line 28
    .line 29
    invoke-static {p0, p1, p2}, Lf3/e;->a(Lf3/s;D)D

    .line 30
    .line 31
    .line 32
    move-result-wide p0

    .line 33
    return-wide p0

    .line 34
    nop

    .line 35
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public onFailure(Ljava/lang/Exception;)V
    .locals 1

    .line 1
    const-string p0, "Error fetching settings."

    .line 2
    .line 3
    const-string v0, "FirebaseCrashlytics"

    .line 4
    .line 5
    invoke-static {v0, p0, p1}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 6
    .line 7
    .line 8
    return-void
.end method
