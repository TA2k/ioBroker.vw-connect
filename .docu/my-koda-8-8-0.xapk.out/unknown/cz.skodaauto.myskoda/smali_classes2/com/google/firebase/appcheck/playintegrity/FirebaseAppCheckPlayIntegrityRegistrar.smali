.class public Lcom/google/firebase/appcheck/playintegrity/FirebaseAppCheckPlayIntegrityRegistrar;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lcom/google/firebase/components/ComponentRegistrar;


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


# virtual methods
.method public final getComponents()Ljava/util/List;
    .locals 6

    .line 1
    new-instance p0, Lgs/s;

    .line 2
    .line 3
    const-class v0, Lyr/c;

    .line 4
    .line 5
    const-class v1, Ljava/util/concurrent/Executor;

    .line 6
    .line 7
    invoke-direct {p0, v0, v1}, Lgs/s;-><init>(Ljava/lang/Class;Ljava/lang/Class;)V

    .line 8
    .line 9
    .line 10
    new-instance v0, Lgs/s;

    .line 11
    .line 12
    const-class v2, Lyr/b;

    .line 13
    .line 14
    invoke-direct {v0, v2, v1}, Lgs/s;-><init>(Ljava/lang/Class;Ljava/lang/Class;)V

    .line 15
    .line 16
    .line 17
    const-class v1, Les/d;

    .line 18
    .line 19
    invoke-static {v1}, Lgs/b;->b(Ljava/lang/Class;)Lgs/a;

    .line 20
    .line 21
    .line 22
    move-result-object v1

    .line 23
    const-string v2, "fire-app-check-play-integrity"

    .line 24
    .line 25
    iput-object v2, v1, Lgs/a;->a:Ljava/lang/String;

    .line 26
    .line 27
    const-class v3, Lsr/f;

    .line 28
    .line 29
    invoke-static {v3}, Lgs/k;->c(Ljava/lang/Class;)Lgs/k;

    .line 30
    .line 31
    .line 32
    move-result-object v3

    .line 33
    invoke-virtual {v1, v3}, Lgs/a;->a(Lgs/k;)V

    .line 34
    .line 35
    .line 36
    new-instance v3, Lgs/k;

    .line 37
    .line 38
    const/4 v4, 0x1

    .line 39
    const/4 v5, 0x0

    .line 40
    invoke-direct {v3, p0, v4, v5}, Lgs/k;-><init>(Lgs/s;II)V

    .line 41
    .line 42
    .line 43
    invoke-virtual {v1, v3}, Lgs/a;->a(Lgs/k;)V

    .line 44
    .line 45
    .line 46
    new-instance v3, Lgs/k;

    .line 47
    .line 48
    invoke-direct {v3, v0, v4, v5}, Lgs/k;-><init>(Lgs/s;II)V

    .line 49
    .line 50
    .line 51
    invoke-virtual {v1, v3}, Lgs/a;->a(Lgs/k;)V

    .line 52
    .line 53
    .line 54
    new-instance v3, La0/h;

    .line 55
    .line 56
    const/16 v4, 0x9

    .line 57
    .line 58
    invoke-direct {v3, v4, p0, v0}, La0/h;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 59
    .line 60
    .line 61
    iput-object v3, v1, Lgs/a;->f:Lgs/e;

    .line 62
    .line 63
    invoke-virtual {v1}, Lgs/a;->b()Lgs/b;

    .line 64
    .line 65
    .line 66
    move-result-object p0

    .line 67
    const-string v0, "19.0.1"

    .line 68
    .line 69
    invoke-static {v2, v0}, Ljp/gb;->a(Ljava/lang/String;Ljava/lang/String;)Lgs/b;

    .line 70
    .line 71
    .line 72
    move-result-object v0

    .line 73
    filled-new-array {p0, v0}, [Lgs/b;

    .line 74
    .line 75
    .line 76
    move-result-object p0

    .line 77
    invoke-static {p0}, Ljava/util/Arrays;->asList([Ljava/lang/Object;)Ljava/util/List;

    .line 78
    .line 79
    .line 80
    move-result-object p0

    .line 81
    return-object p0
.end method
