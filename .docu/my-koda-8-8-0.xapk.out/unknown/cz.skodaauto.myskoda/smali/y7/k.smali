.class public final Ly7/k;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ly7/g;
.implements Lretrofit2/Converter;


# instance fields
.field public final d:Ljava/lang/Object;

.field public final e:Ljava/lang/Object;


# direct methods
.method public constructor <init>(ILd5/f;)V
    .locals 1

    .line 8
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p2, p0, Ly7/k;->d:Ljava/lang/Object;

    const/4 p2, -0x2

    .line 9
    const-string v0, "start"

    if-eq p1, p2, :cond_3

    const/4 p2, -0x1

    if-eq p1, p2, :cond_2

    if-eqz p1, :cond_1

    const/4 p2, 0x1

    if-eq p1, p2, :cond_0

    .line 10
    const-string p1, "CCL"

    const-string p2, "verticalAnchorIndexToAnchorName: Unknown vertical index"

    invoke-static {p1, p2}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I

    goto :goto_0

    .line 11
    :cond_0
    const-string v0, "right"

    goto :goto_0

    :cond_1
    const-string v0, "left"

    goto :goto_0

    :cond_2
    const-string v0, "end"

    .line 12
    :cond_3
    :goto_0
    iput-object v0, p0, Ly7/k;->e:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Landroid/content/Context;)V
    .locals 2

    .line 4
    new-instance v0, Lc1/m2;

    const/16 v1, 0x9

    invoke-direct {v0, v1}, Lc1/m2;-><init>(I)V

    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    invoke-virtual {p1}, Landroid/content/Context;->getApplicationContext()Landroid/content/Context;

    move-result-object p1

    iput-object p1, p0, Ly7/k;->d:Ljava/lang/Object;

    .line 7
    iput-object v0, p0, Ly7/k;->e:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Lqz0/a;Lt1/j0;)V
    .locals 1

    const-string v0, "serializer"

    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    iput-object p1, p0, Ly7/k;->d:Ljava/lang/Object;

    .line 3
    iput-object p2, p0, Ly7/k;->e:Ljava/lang/Object;

    return-void
.end method

.method public static b(Ly7/k;Lz4/h;FI)V
    .locals 1

    .line 1
    and-int/lit8 p3, p3, 0x2

    .line 2
    .line 3
    const/4 v0, 0x0

    .line 4
    if-eqz p3, :cond_0

    .line 5
    .line 6
    int-to-float p2, v0

    .line 7
    :cond_0
    int-to-float p3, v0

    .line 8
    invoke-virtual {p0, p1, p2, p3}, Ly7/k;->a(Lz4/h;FF)V

    .line 9
    .line 10
    .line 11
    return-void
.end method


# virtual methods
.method public a(Lz4/h;FF)V
    .locals 3

    .line 1
    iget v0, p1, Lz4/h;->b:I

    .line 2
    .line 3
    const/4 v1, -0x2

    .line 4
    const-string v2, "start"

    .line 5
    .line 6
    if-eq v0, v1, :cond_2

    .line 7
    .line 8
    const/4 v1, -0x1

    .line 9
    if-eq v0, v1, :cond_1

    .line 10
    .line 11
    const/4 v1, 0x1

    .line 12
    if-eq v0, v1, :cond_0

    .line 13
    .line 14
    const-string v0, "CCL"

    .line 15
    .line 16
    const-string v1, "verticalAnchorIndexToAnchorName: Unknown vertical index"

    .line 17
    .line 18
    invoke-static {v0, v1}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I

    .line 19
    .line 20
    .line 21
    goto :goto_0

    .line 22
    :cond_0
    const-string v2, "right"

    .line 23
    .line 24
    goto :goto_0

    .line 25
    :cond_1
    const-string v2, "end"

    .line 26
    .line 27
    :cond_2
    :goto_0
    new-instance v0, Ld5/a;

    .line 28
    .line 29
    const/4 v1, 0x0

    .line 30
    new-array v1, v1, [C

    .line 31
    .line 32
    invoke-direct {v0, v1}, Ld5/b;-><init>([C)V

    .line 33
    .line 34
    .line 35
    iget-object p1, p1, Lz4/h;->a:Ljava/lang/Object;

    .line 36
    .line 37
    invoke-virtual {p1}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 38
    .line 39
    .line 40
    move-result-object p1

    .line 41
    invoke-static {p1}, Ld5/h;->o(Ljava/lang/String;)Ld5/h;

    .line 42
    .line 43
    .line 44
    move-result-object p1

    .line 45
    invoke-virtual {v0, p1}, Ld5/b;->o(Ld5/c;)V

    .line 46
    .line 47
    .line 48
    invoke-static {v2}, Ld5/h;->o(Ljava/lang/String;)Ld5/h;

    .line 49
    .line 50
    .line 51
    move-result-object p1

    .line 52
    invoke-virtual {v0, p1}, Ld5/b;->o(Ld5/c;)V

    .line 53
    .line 54
    .line 55
    new-instance p1, Ld5/e;

    .line 56
    .line 57
    invoke-direct {p1, p2}, Ld5/e;-><init>(F)V

    .line 58
    .line 59
    .line 60
    invoke-virtual {v0, p1}, Ld5/b;->o(Ld5/c;)V

    .line 61
    .line 62
    .line 63
    new-instance p1, Ld5/e;

    .line 64
    .line 65
    invoke-direct {p1, p3}, Ld5/e;-><init>(F)V

    .line 66
    .line 67
    .line 68
    invoke-virtual {v0, p1}, Ld5/b;->o(Ld5/c;)V

    .line 69
    .line 70
    .line 71
    iget-object p1, p0, Ly7/k;->d:Ljava/lang/Object;

    .line 72
    .line 73
    check-cast p1, Ld5/f;

    .line 74
    .line 75
    iget-object p0, p0, Ly7/k;->e:Ljava/lang/Object;

    .line 76
    .line 77
    check-cast p0, Ljava/lang/String;

    .line 78
    .line 79
    invoke-virtual {p1, p0, v0}, Ld5/b;->D(Ljava/lang/String;Ld5/c;)V

    .line 80
    .line 81
    .line 82
    return-void
.end method

.method public i()Ly7/h;
    .locals 2

    .line 1
    new-instance v0, Ly7/l;

    .line 2
    .line 3
    iget-object v1, p0, Ly7/k;->d:Ljava/lang/Object;

    .line 4
    .line 5
    check-cast v1, Landroid/content/Context;

    .line 6
    .line 7
    iget-object p0, p0, Ly7/k;->e:Ljava/lang/Object;

    .line 8
    .line 9
    check-cast p0, Lc1/m2;

    .line 10
    .line 11
    invoke-virtual {p0}, Lc1/m2;->i()Ly7/h;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    invoke-direct {v0, v1, p0}, Ly7/l;-><init>(Landroid/content/Context;Ly7/h;)V

    .line 16
    .line 17
    .line 18
    return-object v0
.end method

.method public j(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    .line 1
    check-cast p1, Ld01/v0;

    .line 2
    .line 3
    const-string v0, "value"

    .line 4
    .line 5
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-object v0, p0, Ly7/k;->e:Ljava/lang/Object;

    .line 9
    .line 10
    check-cast v0, Lt1/j0;

    .line 11
    .line 12
    iget-object p0, p0, Ly7/k;->d:Ljava/lang/Object;

    .line 13
    .line 14
    check-cast p0, Lqz0/a;

    .line 15
    .line 16
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 17
    .line 18
    .line 19
    const-string v1, "loader"

    .line 20
    .line 21
    invoke-static {p0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 22
    .line 23
    .line 24
    invoke-virtual {p1}, Ld01/v0;->f()Ljava/lang/String;

    .line 25
    .line 26
    .line 27
    move-result-object p1

    .line 28
    const-string v1, "body.string()"

    .line 29
    .line 30
    invoke-static {p1, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 31
    .line 32
    .line 33
    iget-object v0, v0, Lt1/j0;->e:Ljava/lang/Object;

    .line 34
    .line 35
    check-cast v0, Lqz0/j;

    .line 36
    .line 37
    check-cast v0, Lvz0/d;

    .line 38
    .line 39
    invoke-virtual {v0, p1, p0}, Lvz0/d;->b(Ljava/lang/String;Lqz0/a;)Ljava/lang/Object;

    .line 40
    .line 41
    .line 42
    move-result-object p0

    .line 43
    return-object p0
.end method
