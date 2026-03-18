.class public final Llv/d;
.super Lap0/o;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final f:Lfv/f;


# direct methods
.method public constructor <init>(Lfv/f;)V
    .locals 1

    .line 1
    const/4 v0, 0x4

    .line 2
    invoke-direct {p0, v0}, Lap0/o;-><init>(I)V

    .line 3
    .line 4
    .line 5
    iput-object p1, p0, Llv/d;->f:Lfv/f;

    .line 6
    .line 7
    return-void
.end method


# virtual methods
.method public final t(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 4

    .line 1
    check-cast p1, Lhv/b;

    .line 2
    .line 3
    iget-object p0, p0, Llv/d;->f:Lfv/f;

    .line 4
    .line 5
    invoke-virtual {p0}, Lfv/f;->b()Landroid/content/Context;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    const/4 v1, 0x1

    .line 10
    invoke-static {}, Llv/a;->c()Z

    .line 11
    .line 12
    .line 13
    move-result v2

    .line 14
    if-eq v1, v2, :cond_0

    .line 15
    .line 16
    const-string v1, "play-services-mlkit-barcode-scanning"

    .line 17
    .line 18
    goto :goto_0

    .line 19
    :cond_0
    const-string v1, "barcode-scanning"

    .line 20
    .line 21
    :goto_0
    invoke-static {v1}, Ljp/yg;->l(Ljava/lang/String;)Ljp/vg;

    .line 22
    .line 23
    .line 24
    move-result-object v1

    .line 25
    sget-object v2, Llv/g;->h:Ljp/c0;

    .line 26
    .line 27
    const-string v2, "com.google.mlkit.dynamite.barcode"

    .line 28
    .line 29
    invoke-static {v0, v2}, Lzo/d;->a(Landroid/content/Context;Ljava/lang/String;)I

    .line 30
    .line 31
    .line 32
    move-result v2

    .line 33
    if-lez v2, :cond_1

    .line 34
    .line 35
    goto :goto_1

    .line 36
    :cond_1
    sget-object v2, Ljo/f;->b:Ljo/f;

    .line 37
    .line 38
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 39
    .line 40
    .line 41
    invoke-static {v0}, Ljo/f;->a(Landroid/content/Context;)I

    .line 42
    .line 43
    .line 44
    move-result v2

    .line 45
    const v3, 0xc306c20

    .line 46
    .line 47
    .line 48
    if-lt v2, v3, :cond_2

    .line 49
    .line 50
    :goto_1
    new-instance v2, Llv/g;

    .line 51
    .line 52
    invoke-direct {v2, v0, p1, v1}, Llv/g;-><init>(Landroid/content/Context;Lhv/b;Ljp/vg;)V

    .line 53
    .line 54
    .line 55
    goto :goto_2

    .line 56
    :cond_2
    new-instance v2, Lvv0/d;

    .line 57
    .line 58
    invoke-direct {v2}, Ljava/lang/Object;-><init>()V

    .line 59
    .line 60
    .line 61
    new-instance v3, Ljp/b;

    .line 62
    .line 63
    invoke-direct {v3}, Ljava/lang/Object;-><init>()V

    .line 64
    .line 65
    .line 66
    iput-object v3, v2, Lvv0/d;->c:Ljava/lang/Object;

    .line 67
    .line 68
    iput-object v0, v2, Lvv0/d;->b:Ljava/lang/Object;

    .line 69
    .line 70
    iget v0, p1, Lhv/b;->a:I

    .line 71
    .line 72
    iput v0, v3, Ljp/b;->d:I

    .line 73
    .line 74
    iput-object v1, v2, Lvv0/d;->d:Ljava/lang/Object;

    .line 75
    .line 76
    :goto_2
    new-instance v0, Llv/e;

    .line 77
    .line 78
    invoke-direct {v0, p0, p1, v2, v1}, Llv/e;-><init>(Lfv/f;Lhv/b;Llv/f;Ljp/vg;)V

    .line 79
    .line 80
    .line 81
    return-object v0
.end method
