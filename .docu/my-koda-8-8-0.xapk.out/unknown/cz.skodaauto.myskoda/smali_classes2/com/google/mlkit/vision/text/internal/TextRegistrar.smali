.class public Lcom/google/mlkit/vision/text/internal/TextRegistrar;
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
    .locals 3

    .line 1
    const-class p0, Lpv/f;

    .line 2
    .line 3
    invoke-static {p0}, Lgs/b;->b(Ljava/lang/Class;)Lgs/a;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    const-class v1, Lfv/f;

    .line 8
    .line 9
    invoke-static {v1}, Lgs/k;->c(Ljava/lang/Class;)Lgs/k;

    .line 10
    .line 11
    .line 12
    move-result-object v1

    .line 13
    invoke-virtual {v0, v1}, Lgs/a;->a(Lgs/k;)V

    .line 14
    .line 15
    .line 16
    new-instance v1, Let/d;

    .line 17
    .line 18
    const/16 v2, 0xc

    .line 19
    .line 20
    invoke-direct {v1, v2}, Let/d;-><init>(I)V

    .line 21
    .line 22
    .line 23
    iput-object v1, v0, Lgs/a;->f:Lgs/e;

    .line 24
    .line 25
    invoke-virtual {v0}, Lgs/a;->b()Lgs/b;

    .line 26
    .line 27
    .line 28
    move-result-object v0

    .line 29
    const-class v1, Lpv/e;

    .line 30
    .line 31
    invoke-static {v1}, Lgs/b;->b(Ljava/lang/Class;)Lgs/a;

    .line 32
    .line 33
    .line 34
    move-result-object v1

    .line 35
    invoke-static {p0}, Lgs/k;->c(Ljava/lang/Class;)Lgs/k;

    .line 36
    .line 37
    .line 38
    move-result-object p0

    .line 39
    invoke-virtual {v1, p0}, Lgs/a;->a(Lgs/k;)V

    .line 40
    .line 41
    .line 42
    const-class p0, Lfv/d;

    .line 43
    .line 44
    invoke-static {p0}, Lgs/k;->c(Ljava/lang/Class;)Lgs/k;

    .line 45
    .line 46
    .line 47
    move-result-object p0

    .line 48
    invoke-virtual {v1, p0}, Lgs/a;->a(Lgs/k;)V

    .line 49
    .line 50
    .line 51
    new-instance p0, Lfv/b;

    .line 52
    .line 53
    invoke-direct {p0, v2}, Lfv/b;-><init>(I)V

    .line 54
    .line 55
    .line 56
    iput-object p0, v1, Lgs/a;->f:Lgs/e;

    .line 57
    .line 58
    invoke-virtual {v1}, Lgs/a;->b()Lgs/b;

    .line 59
    .line 60
    .line 61
    move-result-object p0

    .line 62
    filled-new-array {v0, p0}, [Ljava/lang/Object;

    .line 63
    .line 64
    .line 65
    move-result-object p0

    .line 66
    const/4 v0, 0x0

    .line 67
    :goto_0
    const/4 v1, 0x2

    .line 68
    if-ge v0, v1, :cond_1

    .line 69
    .line 70
    sget-object v1, Llp/o;->e:Llp/m;

    .line 71
    .line 72
    aget-object v1, p0, v0

    .line 73
    .line 74
    if-eqz v1, :cond_0

    .line 75
    .line 76
    add-int/lit8 v0, v0, 0x1

    .line 77
    .line 78
    goto :goto_0

    .line 79
    :cond_0
    new-instance p0, Ljava/lang/NullPointerException;

    .line 80
    .line 81
    const-string v1, "at index "

    .line 82
    .line 83
    invoke-static {v0, v1}, Lkx/a;->h(ILjava/lang/String;)Ljava/lang/String;

    .line 84
    .line 85
    .line 86
    move-result-object v0

    .line 87
    invoke-direct {p0, v0}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    .line 88
    .line 89
    .line 90
    throw p0

    .line 91
    :cond_1
    invoke-static {v1, p0}, Llp/o;->m(I[Ljava/lang/Object;)Llp/u;

    .line 92
    .line 93
    .line 94
    move-result-object p0

    .line 95
    return-object p0
.end method
