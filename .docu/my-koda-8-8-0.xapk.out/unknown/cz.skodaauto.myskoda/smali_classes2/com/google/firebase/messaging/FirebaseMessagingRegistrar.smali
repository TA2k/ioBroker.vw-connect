.class public Lcom/google/firebase/messaging/FirebaseMessagingRegistrar;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lcom/google/firebase/components/ComponentRegistrar;


# annotations
.annotation build Landroidx/annotation/Keep;
.end annotation


# static fields
.field private static final LIBRARY_NAME:Ljava/lang/String; = "fire-fcm"


# direct methods
.method public constructor <init>()V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static synthetic a(Lgs/s;Lin/z1;)Lcom/google/firebase/messaging/FirebaseMessaging;
    .locals 0

    .line 1
    invoke-static {p0, p1}, Lcom/google/firebase/messaging/FirebaseMessagingRegistrar;->lambda$getComponents$0(Lgs/s;Lgs/c;)Lcom/google/firebase/messaging/FirebaseMessaging;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method private static synthetic lambda$getComponents$0(Lgs/s;Lgs/c;)Lcom/google/firebase/messaging/FirebaseMessaging;
    .locals 7

    .line 1
    new-instance v0, Lcom/google/firebase/messaging/FirebaseMessaging;

    .line 2
    .line 3
    const-class v1, Lsr/f;

    .line 4
    .line 5
    invoke-interface {p1, v1}, Lgs/c;->a(Ljava/lang/Class;)Ljava/lang/Object;

    .line 6
    .line 7
    .line 8
    move-result-object v1

    .line 9
    check-cast v1, Lsr/f;

    .line 10
    .line 11
    const-class v2, Lft/a;

    .line 12
    .line 13
    invoke-interface {p1, v2}, Lgs/c;->a(Ljava/lang/Class;)Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    move-result-object v2

    .line 17
    if-nez v2, :cond_0

    .line 18
    .line 19
    const-class v2, Lbu/b;

    .line 20
    .line 21
    invoke-interface {p1, v2}, Lgs/c;->f(Ljava/lang/Class;)Lgt/b;

    .line 22
    .line 23
    .line 24
    move-result-object v2

    .line 25
    const-class v3, Let/f;

    .line 26
    .line 27
    invoke-interface {p1, v3}, Lgs/c;->f(Ljava/lang/Class;)Lgt/b;

    .line 28
    .line 29
    .line 30
    move-result-object v3

    .line 31
    const-class v4, Lht/d;

    .line 32
    .line 33
    invoke-interface {p1, v4}, Lgs/c;->a(Ljava/lang/Class;)Ljava/lang/Object;

    .line 34
    .line 35
    .line 36
    move-result-object v4

    .line 37
    check-cast v4, Lht/d;

    .line 38
    .line 39
    invoke-interface {p1, p0}, Lgs/c;->e(Lgs/s;)Lgt/b;

    .line 40
    .line 41
    .line 42
    move-result-object v5

    .line 43
    const-class p0, Ldt/c;

    .line 44
    .line 45
    invoke-interface {p1, p0}, Lgs/c;->a(Ljava/lang/Class;)Ljava/lang/Object;

    .line 46
    .line 47
    .line 48
    move-result-object p0

    .line 49
    move-object v6, p0

    .line 50
    check-cast v6, Ldt/c;

    .line 51
    .line 52
    invoke-direct/range {v0 .. v6}, Lcom/google/firebase/messaging/FirebaseMessaging;-><init>(Lsr/f;Lgt/b;Lgt/b;Lht/d;Lgt/b;Ldt/c;)V

    .line 53
    .line 54
    .line 55
    return-object v0

    .line 56
    :cond_0
    new-instance p0, Ljava/lang/ClassCastException;

    .line 57
    .line 58
    invoke-direct {p0}, Ljava/lang/ClassCastException;-><init>()V

    .line 59
    .line 60
    .line 61
    throw p0
.end method


# virtual methods
.method public getComponents()Ljava/util/List;
    .locals 5
    .annotation build Landroidx/annotation/Keep;
    .end annotation

    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/List<",
            "Lgs/b;",
            ">;"
        }
    .end annotation

    .line 1
    new-instance p0, Lgs/s;

    .line 2
    .line 3
    const-class v0, Lxs/b;

    .line 4
    .line 5
    const-class v1, Lon/f;

    .line 6
    .line 7
    invoke-direct {p0, v0, v1}, Lgs/s;-><init>(Ljava/lang/Class;Ljava/lang/Class;)V

    .line 8
    .line 9
    .line 10
    const-class v0, Lcom/google/firebase/messaging/FirebaseMessaging;

    .line 11
    .line 12
    invoke-static {v0}, Lgs/b;->b(Ljava/lang/Class;)Lgs/a;

    .line 13
    .line 14
    .line 15
    move-result-object v0

    .line 16
    const-string v1, "fire-fcm"

    .line 17
    .line 18
    iput-object v1, v0, Lgs/a;->a:Ljava/lang/String;

    .line 19
    .line 20
    const-class v2, Lsr/f;

    .line 21
    .line 22
    invoke-static {v2}, Lgs/k;->c(Ljava/lang/Class;)Lgs/k;

    .line 23
    .line 24
    .line 25
    move-result-object v2

    .line 26
    invoke-virtual {v0, v2}, Lgs/a;->a(Lgs/k;)V

    .line 27
    .line 28
    .line 29
    new-instance v2, Lgs/k;

    .line 30
    .line 31
    const/4 v3, 0x0

    .line 32
    const-class v4, Lft/a;

    .line 33
    .line 34
    invoke-direct {v2, v3, v3, v4}, Lgs/k;-><init>(IILjava/lang/Class;)V

    .line 35
    .line 36
    .line 37
    invoke-virtual {v0, v2}, Lgs/a;->a(Lgs/k;)V

    .line 38
    .line 39
    .line 40
    const-class v2, Lbu/b;

    .line 41
    .line 42
    invoke-static {v2}, Lgs/k;->a(Ljava/lang/Class;)Lgs/k;

    .line 43
    .line 44
    .line 45
    move-result-object v2

    .line 46
    invoke-virtual {v0, v2}, Lgs/a;->a(Lgs/k;)V

    .line 47
    .line 48
    .line 49
    const-class v2, Let/f;

    .line 50
    .line 51
    invoke-static {v2}, Lgs/k;->a(Ljava/lang/Class;)Lgs/k;

    .line 52
    .line 53
    .line 54
    move-result-object v2

    .line 55
    invoke-virtual {v0, v2}, Lgs/a;->a(Lgs/k;)V

    .line 56
    .line 57
    .line 58
    const-class v2, Lht/d;

    .line 59
    .line 60
    invoke-static {v2}, Lgs/k;->c(Ljava/lang/Class;)Lgs/k;

    .line 61
    .line 62
    .line 63
    move-result-object v2

    .line 64
    invoke-virtual {v0, v2}, Lgs/a;->a(Lgs/k;)V

    .line 65
    .line 66
    .line 67
    new-instance v2, Lgs/k;

    .line 68
    .line 69
    const/4 v4, 0x1

    .line 70
    invoke-direct {v2, p0, v3, v4}, Lgs/k;-><init>(Lgs/s;II)V

    .line 71
    .line 72
    .line 73
    invoke-virtual {v0, v2}, Lgs/a;->a(Lgs/k;)V

    .line 74
    .line 75
    .line 76
    const-class v2, Ldt/c;

    .line 77
    .line 78
    invoke-static {v2}, Lgs/k;->c(Ljava/lang/Class;)Lgs/k;

    .line 79
    .line 80
    .line 81
    move-result-object v2

    .line 82
    invoke-virtual {v0, v2}, Lgs/a;->a(Lgs/k;)V

    .line 83
    .line 84
    .line 85
    new-instance v2, Lcom/google/firebase/messaging/p;

    .line 86
    .line 87
    invoke-direct {v2, p0, v3}, Lcom/google/firebase/messaging/p;-><init>(Lgs/s;I)V

    .line 88
    .line 89
    .line 90
    iput-object v2, v0, Lgs/a;->f:Lgs/e;

    .line 91
    .line 92
    invoke-virtual {v0, v4}, Lgs/a;->c(I)V

    .line 93
    .line 94
    .line 95
    invoke-virtual {v0}, Lgs/a;->b()Lgs/b;

    .line 96
    .line 97
    .line 98
    move-result-object p0

    .line 99
    const-string v0, "25.0.1"

    .line 100
    .line 101
    invoke-static {v1, v0}, Ljp/gb;->a(Ljava/lang/String;Ljava/lang/String;)Lgs/b;

    .line 102
    .line 103
    .line 104
    move-result-object v0

    .line 105
    filled-new-array {p0, v0}, [Lgs/b;

    .line 106
    .line 107
    .line 108
    move-result-object p0

    .line 109
    invoke-static {p0}, Ljava/util/Arrays;->asList([Ljava/lang/Object;)Ljava/util/List;

    .line 110
    .line 111
    .line 112
    move-result-object p0

    .line 113
    return-object p0
.end method
