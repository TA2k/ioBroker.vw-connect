.class public abstract Lc0/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Le0/a;

    .line 2
    .line 3
    invoke-direct {v0}, Le0/a;-><init>()V

    .line 4
    .line 5
    .line 6
    new-instance v0, Le0/c;

    .line 7
    .line 8
    invoke-direct {v0}, Le0/c;-><init>()V

    .line 9
    .line 10
    .line 11
    new-instance v0, Le0/f;

    .line 12
    .line 13
    sget-object v1, Le0/e;->d:Le0/e;

    .line 14
    .line 15
    invoke-direct {v0}, Le0/f;-><init>()V

    .line 16
    .line 17
    .line 18
    new-instance v0, Le0/d;

    .line 19
    .line 20
    invoke-direct {v0}, Le0/d;-><init>()V

    .line 21
    .line 22
    .line 23
    return-void
.end method

.method public constructor <init>()V
    .locals 2

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, La71/u;

    .line 5
    .line 6
    const/16 v1, 0xe

    .line 7
    .line 8
    invoke-direct {v0, p0, v1}, La71/u;-><init>(Ljava/lang/Object;I)V

    .line 9
    .line 10
    .line 11
    invoke-static {v0}, Lpm/a;->d(Lay0/a;)Llx0/q;

    .line 12
    .line 13
    .line 14
    return-void
.end method


# virtual methods
.method public abstract a()Le0/b;
.end method

.method public b(Lb0/d1;Lh0/z;)Z
    .locals 0

    .line 1
    const/4 p0, 0x1

    .line 2
    return p0
.end method
