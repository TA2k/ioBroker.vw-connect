.class public Lcom/google/mlkit/vision/barcode/internal/BarcodeRegistrar;
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
    .locals 4

    .line 1
    const-class p0, Llv/d;

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
    move-result-object v2

    .line 13
    invoke-virtual {v0, v2}, Lgs/a;->a(Lgs/k;)V

    .line 14
    .line 15
    .line 16
    new-instance v2, Let/d;

    .line 17
    .line 18
    const/16 v3, 0x9

    .line 19
    .line 20
    invoke-direct {v2, v3}, Let/d;-><init>(I)V

    .line 21
    .line 22
    .line 23
    iput-object v2, v0, Lgs/a;->f:Lgs/e;

    .line 24
    .line 25
    invoke-virtual {v0}, Lgs/a;->b()Lgs/b;

    .line 26
    .line 27
    .line 28
    move-result-object v0

    .line 29
    const-class v2, Llv/b;

    .line 30
    .line 31
    invoke-static {v2}, Lgs/b;->b(Ljava/lang/Class;)Lgs/a;

    .line 32
    .line 33
    .line 34
    move-result-object v2

    .line 35
    invoke-static {p0}, Lgs/k;->c(Ljava/lang/Class;)Lgs/k;

    .line 36
    .line 37
    .line 38
    move-result-object p0

    .line 39
    invoke-virtual {v2, p0}, Lgs/a;->a(Lgs/k;)V

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
    invoke-virtual {v2, p0}, Lgs/a;->a(Lgs/k;)V

    .line 49
    .line 50
    .line 51
    invoke-static {v1}, Lgs/k;->c(Ljava/lang/Class;)Lgs/k;

    .line 52
    .line 53
    .line 54
    move-result-object p0

    .line 55
    invoke-virtual {v2, p0}, Lgs/a;->a(Lgs/k;)V

    .line 56
    .line 57
    .line 58
    new-instance p0, Lfv/b;

    .line 59
    .line 60
    invoke-direct {p0, v3}, Lfv/b;-><init>(I)V

    .line 61
    .line 62
    .line 63
    iput-object p0, v2, Lgs/a;->f:Lgs/e;

    .line 64
    .line 65
    invoke-virtual {v2}, Lgs/a;->b()Lgs/b;

    .line 66
    .line 67
    .line 68
    move-result-object p0

    .line 69
    sget-object v1, Ljp/y;->e:Ljp/w;

    .line 70
    .line 71
    filled-new-array {v0, p0}, [Ljava/lang/Object;

    .line 72
    .line 73
    .line 74
    move-result-object p0

    .line 75
    const/4 v0, 0x0

    .line 76
    :goto_0
    const/4 v1, 0x2

    .line 77
    if-ge v0, v1, :cond_1

    .line 78
    .line 79
    aget-object v1, p0, v0

    .line 80
    .line 81
    if-eqz v1, :cond_0

    .line 82
    .line 83
    add-int/lit8 v0, v0, 0x1

    .line 84
    .line 85
    goto :goto_0

    .line 86
    :cond_0
    new-instance p0, Ljava/lang/NullPointerException;

    .line 87
    .line 88
    const-string v1, "at index "

    .line 89
    .line 90
    invoke-static {v0, v1}, Lkx/a;->h(ILjava/lang/String;)Ljava/lang/String;

    .line 91
    .line 92
    .line 93
    move-result-object v0

    .line 94
    invoke-direct {p0, v0}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    .line 95
    .line 96
    .line 97
    throw p0

    .line 98
    :cond_1
    new-instance v0, Ljp/c0;

    .line 99
    .line 100
    invoke-direct {v0, p0, v1}, Ljp/c0;-><init>([Ljava/lang/Object;I)V

    .line 101
    .line 102
    .line 103
    return-object v0
.end method
