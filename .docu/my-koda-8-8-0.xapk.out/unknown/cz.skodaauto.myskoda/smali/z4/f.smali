.class public final Lz4/f;
.super Lz4/o;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final c:Ljava/lang/Object;

.field public final d:Lz4/h;

.field public final e:Lz4/g;

.field public final f:Lz4/h;

.field public final g:Lz4/g;


# direct methods
.method public constructor <init>(Ljava/lang/Object;)V
    .locals 2

    .line 1
    invoke-direct {p0, p1}, Lz4/o;-><init>(Ljava/lang/Object;)V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lz4/f;->c:Ljava/lang/Object;

    .line 5
    .line 6
    new-instance v0, Lz4/h;

    .line 7
    .line 8
    const/4 v1, -0x2

    .line 9
    invoke-direct {v0, p1, v1, p0}, Lz4/h;-><init>(Ljava/lang/Object;ILz4/f;)V

    .line 10
    .line 11
    .line 12
    iput-object v0, p0, Lz4/f;->d:Lz4/h;

    .line 13
    .line 14
    new-instance v0, Lz4/g;

    .line 15
    .line 16
    const/4 v1, 0x0

    .line 17
    invoke-direct {v0, p1, v1, p0}, Lz4/g;-><init>(Ljava/lang/Object;ILz4/f;)V

    .line 18
    .line 19
    .line 20
    iput-object v0, p0, Lz4/f;->e:Lz4/g;

    .line 21
    .line 22
    new-instance v0, Lz4/h;

    .line 23
    .line 24
    const/4 v1, -0x1

    .line 25
    invoke-direct {v0, p1, v1, p0}, Lz4/h;-><init>(Ljava/lang/Object;ILz4/f;)V

    .line 26
    .line 27
    .line 28
    iput-object v0, p0, Lz4/f;->f:Lz4/h;

    .line 29
    .line 30
    new-instance v0, Lz4/g;

    .line 31
    .line 32
    const/4 v1, 0x1

    .line 33
    invoke-direct {v0, p1, v1, p0}, Lz4/g;-><init>(Ljava/lang/Object;ILz4/f;)V

    .line 34
    .line 35
    .line 36
    iput-object v0, p0, Lz4/f;->g:Lz4/g;

    .line 37
    .line 38
    return-void
.end method


# virtual methods
.method public final a()Ljava/lang/Object;
    .locals 0

    .line 1
    iget-object p0, p0, Lz4/f;->c:Ljava/lang/Object;

    .line 2
    .line 3
    return-object p0
.end method
