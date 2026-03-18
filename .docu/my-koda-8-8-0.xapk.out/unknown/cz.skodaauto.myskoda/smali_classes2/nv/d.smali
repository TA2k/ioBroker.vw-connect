.class public final Lnv/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Laq/f;
.implements Lgs/e;


# static fields
.field public static final synthetic d:Lnv/d;

.field public static final synthetic e:Lnv/d;


# direct methods
.method static synthetic constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Lnv/d;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lnv/d;->d:Lnv/d;

    .line 7
    .line 8
    new-instance v0, Lnv/d;

    .line 9
    .line 10
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 11
    .line 12
    .line 13
    sput-object v0, Lnv/d;->e:Lnv/d;

    .line 14
    .line 15
    return-void
.end method

.method public static a(Lmv/a;)Lyo/b;
    .locals 3

    .line 1
    iget v0, p0, Lmv/a;->f:I

    .line 2
    .line 3
    const/4 v1, -0x1

    .line 4
    if-eq v0, v1, :cond_3

    .line 5
    .line 6
    const/16 v1, 0x11

    .line 7
    .line 8
    const/4 v2, 0x0

    .line 9
    if-eq v0, v1, :cond_2

    .line 10
    .line 11
    const/16 v1, 0x23

    .line 12
    .line 13
    if-eq v0, v1, :cond_0

    .line 14
    .line 15
    const v1, 0x32315659

    .line 16
    .line 17
    .line 18
    if-eq v0, v1, :cond_2

    .line 19
    .line 20
    new-instance v0, Lbv/a;

    .line 21
    .line 22
    iget p0, p0, Lmv/a;->f:I

    .line 23
    .line 24
    const-string v1, "Unsupported image format: "

    .line 25
    .line 26
    invoke-static {p0, v1}, Lkx/a;->h(ILjava/lang/String;)Ljava/lang/String;

    .line 27
    .line 28
    .line 29
    move-result-object p0

    .line 30
    const/4 v1, 0x3

    .line 31
    invoke-direct {v0, p0, v1}, Lbv/a;-><init>(Ljava/lang/String;I)V

    .line 32
    .line 33
    .line 34
    throw v0

    .line 35
    :cond_0
    iget-object v0, p0, Lmv/a;->b:Lhu/q;

    .line 36
    .line 37
    if-nez v0, :cond_1

    .line 38
    .line 39
    goto :goto_0

    .line 40
    :cond_1
    iget-object p0, p0, Lmv/a;->b:Lhu/q;

    .line 41
    .line 42
    iget-object p0, p0, Lhu/q;->e:Ljava/lang/Object;

    .line 43
    .line 44
    move-object v2, p0

    .line 45
    check-cast v2, Landroid/media/Image;

    .line 46
    .line 47
    :goto_0
    new-instance p0, Lyo/b;

    .line 48
    .line 49
    invoke-direct {p0, v2}, Lyo/b;-><init>(Ljava/lang/Object;)V

    .line 50
    .line 51
    .line 52
    return-object p0

    .line 53
    :cond_2
    invoke-static {v2}, Lno/c0;->h(Ljava/lang/Object;)V

    .line 54
    .line 55
    .line 56
    throw v2

    .line 57
    :cond_3
    iget-object p0, p0, Lmv/a;->a:Landroid/graphics/Bitmap;

    .line 58
    .line 59
    invoke-static {p0}, Lno/c0;->h(Ljava/lang/Object;)V

    .line 60
    .line 61
    .line 62
    new-instance v0, Lyo/b;

    .line 63
    .line 64
    invoke-direct {v0, p0}, Lyo/b;-><init>(Ljava/lang/Object;)V

    .line 65
    .line 66
    .line 67
    return-object v0
.end method


# virtual methods
.method public e(Lin/z1;)Ljava/lang/Object;
    .locals 1

    .line 1
    const-class p0, Lnv/c;

    .line 2
    .line 3
    invoke-static {p0}, Lgs/s;->a(Ljava/lang/Class;)Lgs/s;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    invoke-virtual {p1, p0}, Lin/z1;->c(Lgs/s;)Ljava/util/Set;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    new-instance p1, Lnv/d;

    .line 12
    .line 13
    invoke-direct {p1}, Ljava/lang/Object;-><init>()V

    .line 14
    .line 15
    .line 16
    new-instance v0, Ljava/util/HashMap;

    .line 17
    .line 18
    invoke-direct {v0}, Ljava/util/HashMap;-><init>()V

    .line 19
    .line 20
    .line 21
    new-instance v0, Ljava/util/HashMap;

    .line 22
    .line 23
    invoke-direct {v0}, Ljava/util/HashMap;-><init>()V

    .line 24
    .line 25
    .line 26
    invoke-interface {p0}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 27
    .line 28
    .line 29
    move-result-object p0

    .line 30
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 31
    .line 32
    .line 33
    move-result v0

    .line 34
    if-nez v0, :cond_0

    .line 35
    .line 36
    return-object p1

    .line 37
    :cond_0
    invoke-static {p0}, Lf2/m0;->e(Ljava/util/Iterator;)Ljava/lang/ClassCastException;

    .line 38
    .line 39
    .line 40
    move-result-object p0

    .line 41
    throw p0
.end method

.method public onFailure(Ljava/lang/Exception;)V
    .locals 2

    .line 1
    sget-object p0, Lnv/b;->h:Lb81/b;

    .line 2
    .line 3
    iget-object v0, p0, Lb81/b;->e:Ljava/lang/Object;

    .line 4
    .line 5
    check-cast v0, Ljava/lang/String;

    .line 6
    .line 7
    const/4 v1, 0x6

    .line 8
    invoke-static {v0, v1}, Landroid/util/Log;->isLoggable(Ljava/lang/String;I)Z

    .line 9
    .line 10
    .line 11
    move-result v0

    .line 12
    if-eqz v0, :cond_0

    .line 13
    .line 14
    const-string v0, "Error preloading model resource"

    .line 15
    .line 16
    invoke-virtual {p0, v0}, Lb81/b;->B(Ljava/lang/String;)Ljava/lang/String;

    .line 17
    .line 18
    .line 19
    move-result-object p0

    .line 20
    const-string v0, "MobileVisionBase"

    .line 21
    .line 22
    invoke-static {v0, p0, p1}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 23
    .line 24
    .line 25
    :cond_0
    return-void
.end method
