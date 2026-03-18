.class public final Lxv/g;
.super Lkotlin/jvm/internal/n;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# static fields
.field public static final f:Lxv/g;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lxv/g;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, v1}, Lkotlin/jvm/internal/n;-><init>(I)V

    .line 5
    .line 6
    .line 7
    sput-object v0, Lxv/g;->f:Lxv/g;

    .line 8
    .line 9
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 2

    .line 1
    const/4 p0, 0x7

    .line 2
    new-array p0, p0, [Lxv/n;

    .line 3
    .line 4
    sget-object v0, Lxv/e;->d:Lxv/e;

    .line 5
    .line 6
    const/4 v1, 0x0

    .line 7
    aput-object v0, p0, v1

    .line 8
    .line 9
    sget-object v0, Lxv/h;->d:Lxv/h;

    .line 10
    .line 11
    const/4 v1, 0x1

    .line 12
    aput-object v0, p0, v1

    .line 13
    .line 14
    sget-object v0, Lxv/m;->d:Lxv/m;

    .line 15
    .line 16
    const/4 v1, 0x2

    .line 17
    aput-object v0, p0, v1

    .line 18
    .line 19
    sget-object v0, Lxv/j;->d:Lxv/j;

    .line 20
    .line 21
    const/4 v1, 0x3

    .line 22
    aput-object v0, p0, v1

    .line 23
    .line 24
    sget-object v0, Lxv/k;->d:Lxv/k;

    .line 25
    .line 26
    const/4 v1, 0x4

    .line 27
    aput-object v0, p0, v1

    .line 28
    .line 29
    sget-object v0, Lxv/l;->d:Lxv/l;

    .line 30
    .line 31
    const/4 v1, 0x5

    .line 32
    aput-object v0, p0, v1

    .line 33
    .line 34
    sget-object v0, Lxv/f;->d:Lxv/f;

    .line 35
    .line 36
    const/4 v1, 0x6

    .line 37
    aput-object v0, p0, v1

    .line 38
    .line 39
    invoke-static {p0}, Ljp/k1;->j([Ljava/lang/Object;)Ljava/util/List;

    .line 40
    .line 41
    .line 42
    move-result-object p0

    .line 43
    return-object p0
.end method
