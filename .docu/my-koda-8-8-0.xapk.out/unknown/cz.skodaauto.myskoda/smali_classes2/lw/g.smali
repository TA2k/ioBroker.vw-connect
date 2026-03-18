.class public final Llw/g;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final synthetic f:[Lhy0/z;


# instance fields
.field public final a:Ljava/util/ArrayList;

.field public final b:Llw/k;

.field public final c:Llw/k;

.field public final d:Llw/k;

.field public final e:Llw/k;


# direct methods
.method static constructor <clinit>()V
    .locals 8

    .line 1
    new-instance v0, Lkotlin/jvm/internal/r;

    .line 2
    .line 3
    const-class v1, Llw/g;

    .line 4
    .line 5
    const-string v2, "startAxis"

    .line 6
    .line 7
    const-string v3, "getStartAxis()Lcom/patrykandpatrick/vico/core/cartesian/axis/Axis;"

    .line 8
    .line 9
    const/4 v4, 0x0

    .line 10
    invoke-direct {v0, v1, v2, v3, v4}, Lkotlin/jvm/internal/r;-><init>(Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;I)V

    .line 11
    .line 12
    .line 13
    sget-object v2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 14
    .line 15
    invoke-virtual {v2, v0}, Lkotlin/jvm/internal/h0;->mutableProperty1(Lkotlin/jvm/internal/q;)Lhy0/l;

    .line 16
    .line 17
    .line 18
    move-result-object v0

    .line 19
    const-string v3, "topAxis"

    .line 20
    .line 21
    const-string v5, "getTopAxis()Lcom/patrykandpatrick/vico/core/cartesian/axis/Axis;"

    .line 22
    .line 23
    invoke-static {v1, v3, v5, v4, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->f(Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;ILkotlin/jvm/internal/h0;)Lhy0/l;

    .line 24
    .line 25
    .line 26
    move-result-object v3

    .line 27
    const-string v5, "endAxis"

    .line 28
    .line 29
    const-string v6, "getEndAxis()Lcom/patrykandpatrick/vico/core/cartesian/axis/Axis;"

    .line 30
    .line 31
    invoke-static {v1, v5, v6, v4, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->f(Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;ILkotlin/jvm/internal/h0;)Lhy0/l;

    .line 32
    .line 33
    .line 34
    move-result-object v5

    .line 35
    const-string v6, "bottomAxis"

    .line 36
    .line 37
    const-string v7, "getBottomAxis()Lcom/patrykandpatrick/vico/core/cartesian/axis/Axis;"

    .line 38
    .line 39
    invoke-static {v1, v6, v7, v4, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->f(Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;ILkotlin/jvm/internal/h0;)Lhy0/l;

    .line 40
    .line 41
    .line 42
    move-result-object v1

    .line 43
    const/4 v2, 0x4

    .line 44
    new-array v2, v2, [Lhy0/z;

    .line 45
    .line 46
    aput-object v0, v2, v4

    .line 47
    .line 48
    const/4 v0, 0x1

    .line 49
    aput-object v3, v2, v0

    .line 50
    .line 51
    const/4 v0, 0x2

    .line 52
    aput-object v5, v2, v0

    .line 53
    .line 54
    const/4 v0, 0x3

    .line 55
    aput-object v1, v2, v0

    .line 56
    .line 57
    sput-object v2, Llw/g;->f:[Lhy0/z;

    .line 58
    .line 59
    return-void
.end method

.method public constructor <init>()V
    .locals 2

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Ljava/util/ArrayList;

    .line 5
    .line 6
    const/4 v1, 0x4

    .line 7
    invoke-direct {v0, v1}, Ljava/util/ArrayList;-><init>(I)V

    .line 8
    .line 9
    .line 10
    iput-object v0, p0, Llw/g;->a:Ljava/util/ArrayList;

    .line 11
    .line 12
    new-instance v0, Llw/k;

    .line 13
    .line 14
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 15
    .line 16
    .line 17
    iput-object v0, p0, Llw/g;->b:Llw/k;

    .line 18
    .line 19
    new-instance v0, Llw/k;

    .line 20
    .line 21
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 22
    .line 23
    .line 24
    iput-object v0, p0, Llw/g;->c:Llw/k;

    .line 25
    .line 26
    new-instance v0, Llw/k;

    .line 27
    .line 28
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 29
    .line 30
    .line 31
    iput-object v0, p0, Llw/g;->d:Llw/k;

    .line 32
    .line 33
    new-instance v0, Llw/k;

    .line 34
    .line 35
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 36
    .line 37
    .line 38
    iput-object v0, p0, Llw/g;->e:Llw/k;

    .line 39
    .line 40
    return-void
.end method


# virtual methods
.method public final a()Llw/i;
    .locals 2

    .line 1
    sget-object v0, Llw/g;->f:[Lhy0/z;

    .line 2
    .line 3
    const/4 v1, 0x3

    .line 4
    aget-object v0, v0, v1

    .line 5
    .line 6
    iget-object v1, p0, Llw/g;->e:Llw/k;

    .line 7
    .line 8
    invoke-virtual {v1, p0, v0}, Llw/k;->getValue(Ljava/lang/Object;Lhy0/z;)Ljava/lang/Object;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    check-cast p0, Llw/i;

    .line 13
    .line 14
    return-object p0
.end method

.method public final b()Llw/i;
    .locals 2

    .line 1
    sget-object v0, Llw/g;->f:[Lhy0/z;

    .line 2
    .line 3
    const/4 v1, 0x2

    .line 4
    aget-object v0, v0, v1

    .line 5
    .line 6
    iget-object v1, p0, Llw/g;->d:Llw/k;

    .line 7
    .line 8
    invoke-virtual {v1, p0, v0}, Llw/k;->getValue(Ljava/lang/Object;Lhy0/z;)Ljava/lang/Object;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    check-cast p0, Llw/i;

    .line 13
    .line 14
    return-object p0
.end method

.method public final c()Llw/i;
    .locals 2

    .line 1
    sget-object v0, Llw/g;->f:[Lhy0/z;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    aget-object v0, v0, v1

    .line 5
    .line 6
    iget-object v1, p0, Llw/g;->b:Llw/k;

    .line 7
    .line 8
    invoke-virtual {v1, p0, v0}, Llw/k;->getValue(Ljava/lang/Object;Lhy0/z;)Ljava/lang/Object;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    check-cast p0, Llw/i;

    .line 13
    .line 14
    return-object p0
.end method

.method public final d()Llw/i;
    .locals 2

    .line 1
    sget-object v0, Llw/g;->f:[Lhy0/z;

    .line 2
    .line 3
    const/4 v1, 0x1

    .line 4
    aget-object v0, v0, v1

    .line 5
    .line 6
    iget-object v1, p0, Llw/g;->c:Llw/k;

    .line 7
    .line 8
    invoke-virtual {v1, p0, v0}, Llw/k;->getValue(Ljava/lang/Object;Lhy0/z;)Ljava/lang/Object;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    check-cast p0, Llw/i;

    .line 13
    .line 14
    return-object p0
.end method
