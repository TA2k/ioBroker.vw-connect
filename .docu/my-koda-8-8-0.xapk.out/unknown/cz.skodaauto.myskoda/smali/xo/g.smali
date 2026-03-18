.class public final Lxo/g;
.super Lko/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lko/m;


# static fields
.field public static final n:Lc2/k;


# direct methods
.method static constructor <clinit>()V
    .locals 4

    .line 1
    new-instance v0, Lko/d;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    new-instance v1, Lbp/l;

    .line 7
    .line 8
    const/4 v2, 0x6

    .line 9
    invoke-direct {v1, v2}, Lbp/l;-><init>(I)V

    .line 10
    .line 11
    .line 12
    new-instance v2, Lc2/k;

    .line 13
    .line 14
    const-string v3, "DigitalKeyFramework.API"

    .line 15
    .line 16
    invoke-direct {v2, v3, v1, v0}, Lc2/k;-><init>(Ljava/lang/String;Llp/wd;Lko/d;)V

    .line 17
    .line 18
    .line 19
    sput-object v2, Lxo/g;->n:Lc2/k;

    .line 20
    .line 21
    return-void
.end method


# virtual methods
.method public final a()[Ljo/d;
    .locals 0

    .line 1
    sget-object p0, Lwo/g;->a:Ljo/d;

    .line 2
    .line 3
    filled-new-array {p0}, [Ljo/d;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final f(Ljava/util/List;Lj51/a;)Laq/t;
    .locals 3

    .line 1
    const-string v0, "CONNECTION_STATUS_LISTENER_TYPE"

    .line 2
    .line 3
    iget-object v1, p0, Lko/i;->i:Landroid/os/Looper;

    .line 4
    .line 5
    invoke-static {v1, p2, v0}, Llp/xf;->b(Landroid/os/Looper;Ljava/lang/Object;Ljava/lang/String;)Lis/b;

    .line 6
    .line 7
    .line 8
    move-result-object p2

    .line 9
    new-instance v0, Lxo/c;

    .line 10
    .line 11
    const/4 v1, 0x1

    .line 12
    invoke-direct {v0, p0, p2, v1}, Lxo/c;-><init>(Lxo/g;Lis/b;I)V

    .line 13
    .line 14
    .line 15
    new-instance v1, Lb81/d;

    .line 16
    .line 17
    const/16 v2, 0x1b

    .line 18
    .line 19
    invoke-direct {v1, v2, p1, v0}, Lb81/d;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 20
    .line 21
    .line 22
    new-instance p1, Lt1/j0;

    .line 23
    .line 24
    const/16 v2, 0x13

    .line 25
    .line 26
    invoke-direct {p1, v0, v2}, Lt1/j0;-><init>(Ljava/lang/Object;I)V

    .line 27
    .line 28
    .line 29
    invoke-static {}, Lb81/d;->h()Lf8/d;

    .line 30
    .line 31
    .line 32
    move-result-object v0

    .line 33
    iput-object p2, v0, Lf8/d;->h:Ljava/lang/Object;

    .line 34
    .line 35
    sget-object p2, Lwo/g;->d:Ljo/d;

    .line 36
    .line 37
    filled-new-array {p2}, [Ljo/d;

    .line 38
    .line 39
    .line 40
    move-result-object p2

    .line 41
    iput-object p2, v0, Lf8/d;->i:Ljava/lang/Object;

    .line 42
    .line 43
    iput-object v1, v0, Lf8/d;->f:Ljava/lang/Object;

    .line 44
    .line 45
    iput-object p1, v0, Lf8/d;->g:Ljava/lang/Object;

    .line 46
    .line 47
    const p1, 0x888d

    .line 48
    .line 49
    .line 50
    iput p1, v0, Lf8/d;->d:I

    .line 51
    .line 52
    invoke-virtual {v0}, Lf8/d;->r()Lb81/d;

    .line 53
    .line 54
    .line 55
    move-result-object p1

    .line 56
    invoke-virtual {p0, p1}, Lko/i;->c(Lb81/d;)Laq/t;

    .line 57
    .line 58
    .line 59
    move-result-object p0

    .line 60
    return-object p0
.end method

.method public final g(Ljava/util/List;Lj51/b;)Laq/t;
    .locals 3

    .line 1
    const-string v0, "RKE_STATUS_LISTENER_TYPE"

    .line 2
    .line 3
    iget-object v1, p0, Lko/i;->i:Landroid/os/Looper;

    .line 4
    .line 5
    invoke-static {v1, p2, v0}, Llp/xf;->b(Landroid/os/Looper;Ljava/lang/Object;Ljava/lang/String;)Lis/b;

    .line 6
    .line 7
    .line 8
    move-result-object p2

    .line 9
    new-instance v0, Lxo/c;

    .line 10
    .line 11
    const/4 v1, 0x0

    .line 12
    invoke-direct {v0, p0, p2, v1}, Lxo/c;-><init>(Lxo/g;Lis/b;I)V

    .line 13
    .line 14
    .line 15
    new-instance v1, Lb81/c;

    .line 16
    .line 17
    const/16 v2, 0x1d

    .line 18
    .line 19
    invoke-direct {v1, v2, p1, v0}, Lb81/c;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 20
    .line 21
    .line 22
    new-instance p1, Lpv/g;

    .line 23
    .line 24
    const/16 v2, 0x18

    .line 25
    .line 26
    invoke-direct {p1, v0, v2}, Lpv/g;-><init>(Ljava/lang/Object;I)V

    .line 27
    .line 28
    .line 29
    invoke-static {}, Lb81/d;->h()Lf8/d;

    .line 30
    .line 31
    .line 32
    move-result-object v0

    .line 33
    iput-object p2, v0, Lf8/d;->h:Ljava/lang/Object;

    .line 34
    .line 35
    sget-object p2, Lwo/g;->c:Ljo/d;

    .line 36
    .line 37
    filled-new-array {p2}, [Ljo/d;

    .line 38
    .line 39
    .line 40
    move-result-object p2

    .line 41
    iput-object p2, v0, Lf8/d;->i:Ljava/lang/Object;

    .line 42
    .line 43
    iput-object v1, v0, Lf8/d;->f:Ljava/lang/Object;

    .line 44
    .line 45
    iput-object p1, v0, Lf8/d;->g:Ljava/lang/Object;

    .line 46
    .line 47
    const p1, 0x8889

    .line 48
    .line 49
    .line 50
    iput p1, v0, Lf8/d;->d:I

    .line 51
    .line 52
    invoke-virtual {v0}, Lf8/d;->r()Lb81/d;

    .line 53
    .line 54
    .line 55
    move-result-object p1

    .line 56
    invoke-virtual {p0, p1}, Lko/i;->c(Lb81/d;)Laq/t;

    .line 57
    .line 58
    .line 59
    move-result-object p0

    .line 60
    return-object p0
.end method
