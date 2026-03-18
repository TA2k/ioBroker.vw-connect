.class public Lcom/google/mlkit/vision/common/internal/VisionCommonRegistrar;
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
    const-class p0, Lnv/d;

    .line 2
    .line 3
    invoke-static {p0}, Lgs/b;->b(Ljava/lang/Class;)Lgs/a;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    new-instance v0, Lgs/k;

    .line 8
    .line 9
    const/4 v1, 0x2

    .line 10
    const/4 v2, 0x0

    .line 11
    const-class v3, Lnv/c;

    .line 12
    .line 13
    invoke-direct {v0, v1, v2, v3}, Lgs/k;-><init>(IILjava/lang/Class;)V

    .line 14
    .line 15
    .line 16
    invoke-virtual {p0, v0}, Lgs/a;->a(Lgs/k;)V

    .line 17
    .line 18
    .line 19
    sget-object v0, Lnv/d;->e:Lnv/d;

    .line 20
    .line 21
    iput-object v0, p0, Lgs/a;->f:Lgs/e;

    .line 22
    .line 23
    invoke-virtual {p0}, Lgs/a;->b()Lgs/b;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    filled-new-array {p0}, [Ljava/lang/Object;

    .line 28
    .line 29
    .line 30
    move-result-object p0

    .line 31
    :goto_0
    const/4 v0, 0x1

    .line 32
    if-ge v2, v0, :cond_1

    .line 33
    .line 34
    sget-object v0, Lkp/sa;->e:Lkp/qa;

    .line 35
    .line 36
    aget-object v0, p0, v2

    .line 37
    .line 38
    if-eqz v0, :cond_0

    .line 39
    .line 40
    add-int/lit8 v2, v2, 0x1

    .line 41
    .line 42
    goto :goto_0

    .line 43
    :cond_0
    new-instance p0, Ljava/lang/NullPointerException;

    .line 44
    .line 45
    const-string v0, "at index "

    .line 46
    .line 47
    invoke-static {v2, v0}, Lkx/a;->h(ILjava/lang/String;)Ljava/lang/String;

    .line 48
    .line 49
    .line 50
    move-result-object v0

    .line 51
    invoke-direct {p0, v0}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    .line 52
    .line 53
    .line 54
    throw p0

    .line 55
    :cond_1
    sget-object v1, Lkp/sa;->e:Lkp/qa;

    .line 56
    .line 57
    new-instance v1, Lkp/ua;

    .line 58
    .line 59
    invoke-direct {v1, p0, v0}, Lkp/ua;-><init>([Ljava/lang/Object;I)V

    .line 60
    .line 61
    .line 62
    return-object v1
.end method
